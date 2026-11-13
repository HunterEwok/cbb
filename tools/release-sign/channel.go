// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// Where the channel's files are: the branch channel on GitHub, the
// releases' files, and the channel file cbb.tools renews.
const (
	channelFiles   = "https://raw.githubusercontent.com/" + defaultRepo + "/" + channelBranch
	releaseFiles   = "https://github.com/" + defaultRepo + "/releases/download"
	renewedChannel = "https://cbb.tools/channel/" + stableChannel + ".json"
)

// When the channel workflow opens an issue: keys.json needs the YubiKey,
// the channel file only fails to be renewed.
const (
	keysDue    = 21 * 24 * time.Hour
	channelDue = 10 * 24 * time.Hour
)

// fetch reads a file from an https:// address, or from a path for the
// tests and by hand.
func fetch(src string) ([]byte, error) {
	if !strings.HasPrefix(src, "https://") {
		return os.ReadFile(src)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cbb")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", src, resp.Status)
	}
	return release.ReadAll(resp.Body)
}

func fetchFile(src string) (release.File, error) {
	var f release.File
	data, err := fetch(src)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("%s: %w", src, err)
	}
	return f, nil
}

// current reads keys.json and the channel file from the branch (or a
// directory) and the release.json the channel file names, and checks them
// under the pinned roots: all of it at now but the channel file's expiry,
// so that a channel file that lapsed can still be renewed.
func current(from, releases string) (keys, ch, rel release.File, c release.Channel, err error) {
	if keys, err = fetchFile(from + "/keys.json"); err != nil {
		return
	}
	if ch, err = fetchFile(from + "/" + stableChannel + ".json"); err != nil {
		return
	}
	if err = json.Unmarshal(ch.Body, &c); err != nil {
		return
	}
	if rel, err = fetchFile(releases + "/v" + c.Release + "/release.json"); err != nil {
		return
	}
	if _, err = release.VerifyKeys(keys, pinnedRoots(), now(), release.Seen{}); err != nil {
		err = fmt.Errorf("keys.json: %w", err)
		return
	}
	_, _, err = release.Check(keys, ch, rel, pinnedRoots(), stableChannel, time.UnixMilli(c.TimeMS), release.Seen{})
	return
}

// extend signs the current channel file again with the channel key, a
// higher number and a new expiry and the same release, and writes it and
// keys.json to a directory: on cbb.tools, from a weekly timer
// (docs/maintaining.md, "Signed releases").
func extend(args []string) error {
	fs := flag.NewFlagSet("extend", flag.ExitOnError)
	key := fs.String("key", "", "the channel key: file:KEY.pem+slh:PQ.pem, its two halves")
	out := fs.String("out", "", "the directory the files go to, served at https://cbb.tools/channel/")
	from := fs.String("from", channelFiles, "where the current keys.json and channel file are")
	releases := fs.String("releases", releaseFiles, "where each release's files are, under vX.Y.Z")
	fs.Parse(args)
	if *key == "" || *out == "" || fs.NArg() != 0 {
		return errors.New("extend needs -key and -out")
	}
	keys, _, rel, c, err := current(*from, *releases)
	if err != nil {
		return fmt.Errorf("the current channel: %w", err)
	}
	k, err := signer(*key)
	if err != nil {
		return err
	}
	pubs, err := k.PublicKeys()
	if err != nil {
		return err
	}
	var ks release.Keys
	json.Unmarshal(keys.Body, &ks)
	halves := map[string]int{}
	for _, key := range ks.Keys {
		if key.Use == release.UseChannel && bytes.Equal(key.Key, pubs[key.Alg]) {
			halves[key.Name]++
		}
	}
	certified := false
	for _, n := range halves {
		certified = certified || n == len(release.Required)
	}
	if !certified {
		return errors.New("keys.json does not certify this channel key; release-sign publish -channel adds it")
	}
	next := c
	next.Seq++
	next.TimeMS = now().UnixMilli()
	next.ExpiresMS = next.TimeMS + channelLife.Milliseconds()
	ch, err := signWith(k, next)
	if err != nil {
		return err
	}
	if _, _, err := release.Check(keys, ch, rel, pinnedRoots(), stableChannel, now(), release.Seen{}); err != nil {
		return fmt.Errorf("the renewed channel file does not check out: %w", err)
	}
	for name, f := range map[string]release.File{"keys.json": keys, stableChannel + ".json": ch} {
		tmp := filepath.Join(*out, "."+name)
		if err := writeFile(tmp, f); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(*out, name)); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "%s.json %d names %s until %s\n", stableChannel, next.Seq, next.Release, expiry(ch))
	return renewEntries(*from, *out, keys, k)
}

// maxTakeStep is how far past the branch's channel file take accepts a
// renewed one: the weekly timer signs one more each time.
const maxTakeStep = 16

// take replaces the channel file in a checkout of the branch channel with
// the one cbb.tools renewed, when that one checks out, names the same
// release and is newer: the channel workflow.
func take(args []string) error {
	fs := flag.NewFlagSet("take", flag.ExitOnError)
	src := fs.String("new", renewedChannel, "the renewed channel file")
	srcEntries := fs.String("new-entries", renewedEntries, "the renewed entry points")
	releases := fs.String("releases", releaseFiles, "where each release's files are, under vX.Y.Z")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("take needs the branch's directory")
	}
	dir := fs.Arg(0)
	keys, _, rel, c, err := current(dir, *releases)
	if err != nil {
		return fmt.Errorf("the branch's channel: %w", err)
	}
	ch, err := fetchFile(*src)
	if err != nil {
		return err
	}
	var n release.Channel
	if err := json.Unmarshal(ch.Body, &n); err != nil {
		return err
	}
	switch {
	case n.Seq <= c.Seq:
		fmt.Fprintf(stdout, "the branch's %s.json %d is the newest\n", stableChannel, c.Seq)
		return takeEntries(dir, *srcEntries)
	case n.Seq > c.Seq+maxTakeStep:
		// extend signs the branch's seq and one more; a file further ahead
		// was not signed from the branch, and would hold every device that
		// took it above the files signed after.
		return fmt.Errorf("the renewed %s.json %d is more than %d past the branch's %d", stableChannel, n.Seq, maxTakeStep, c.Seq)
	case n.Release != c.Release || n.ReleaseSHA256 != c.ReleaseSHA256:
		return fmt.Errorf("the renewed %s.json names %s, the branch's %s: only release-sign publish changes the release", stableChannel, n.Release, c.Release)
	}
	var ks release.Keys
	if err := json.Unmarshal(keys.Body, &ks); err != nil {
		return err
	}
	if _, _, err := release.Check(keys, ch, rel, pinnedRoots(), stableChannel, now(), release.Seen{KeysSeq: ks.Seq, ChannelSeq: c.Seq}); err != nil {
		return fmt.Errorf("the renewed %s.json: %w", stableChannel, err)
	}
	if err := writeFile(filepath.Join(dir, stableChannel+".json"), ch); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "took %s.json %d, valid until %s\n", stableChannel, n.Seq, expiry(ch))
	return takeEntries(dir, *srcEntries)
}

// due prints what in a checkout of the branch channel needs the
// maintainer soon: keys.json within keysDue of its expiry, the channel
// file within channelDue. The channel workflow opens an issue with it.
func due(args []string) error {
	fs := flag.NewFlagSet("due", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("due needs the branch's directory")
	}
	dir := fs.Arg(0)
	for _, c := range []struct {
		name, todo string
		within     time.Duration
	}{
		{"keys.json", "sign it again with a YubiKey: release-sign renew -new-keys", keysDue},
		{stableChannel + ".json", "check the timer on cbb.tools, or sign it by hand: release-sign renew", channelDue},
		{entriesName, "check the timer on cbb.tools, or sign it by hand: release-sign entries", channelDue},
	} {
		f, err := readFile(filepath.Join(dir, c.name))
		if c.name == entriesName && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var b struct {
			ExpiresMS int64 `json:"expires_ms"`
		}
		if err := json.Unmarshal(f.Body, &b); err != nil {
			return err
		}
		left := time.UnixMilli(b.ExpiresMS).Sub(now())
		if left < c.within {
			fmt.Fprintf(stdout, "- `%s` expires on %s, in %d days: %s.\n", c.name,
				time.UnixMilli(b.ExpiresMS).UTC().Format(time.DateOnly), int(left.Hours()/24), c.todo)
		}
	}
	return nil
}
