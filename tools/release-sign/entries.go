// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// entriesName is the signed list of the project's entry points, beside
// keys.json in the channel (docs/protocol.md, section 16, "Entry points").
const entriesName = "entries.json"

// renewedEntries is the list cbb.tools renews with the channel file.
const renewedEntries = "https://cbb.tools/channel/" + entriesName

// entries signs a new list of entry points into a checkout of the branch
// channel: the forwarders and relays of -in, a plain JSON
// {"forwarders": [...], "relays": [...]}, one
// more than the branch's seq, valid for -days. The key is the release key
// or a channel key that keys.json certifies.
func entries(args []string) error {
	fs := flag.NewFlagSet("entries", flag.ExitOnError)
	key := fs.String("key", "", "the signer: the release key or a channel key (file:, piv: or se:)")
	in := fs.String("in", "", "the entry points to sign, a JSON object with forwarders and relays")
	days := fs.Int("days", int(entriesLife.Hours()/24), "how many days the list is valid, at most 100")
	fs.Parse(args)
	if *key == "" || *in == "" || fs.NArg() != 1 {
		return errors.New("entries needs -key, -in and the branch's directory")
	}
	dir := fs.Arg(0)
	keys, err := readFile(filepath.Join(dir, "keys.json"))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var body struct {
		Forwarders []release.EntryForwarder `json:"forwarders"`
		Relays     []release.EntryRelay     `json:"relays"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	var seq uint64 = 1
	if cur, err := readFile(filepath.Join(dir, entriesName)); err == nil {
		var e release.Entries
		if err := json.Unmarshal(cur.Body, &e); err != nil {
			return err
		}
		seq = e.Seq + 1
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	k, err := signer(*key)
	if err != nil {
		return err
	}
	at := now().UnixMilli()
	e := release.Entries{V: 1, Type: release.TypeEntries, Seq: seq, TimeMS: at,
		ExpiresMS: at + (time.Duration(*days) * 24 * time.Hour).Milliseconds(), Forwarders: body.Forwarders, Relays: body.Relays}
	f, err := signWith(k, e)
	if err != nil {
		return err
	}
	if _, _, err := release.CheckEntries(keys, f, pinnedRoots(), now(), release.Seen{}); err != nil {
		return fmt.Errorf("the signed entry points do not check out: %w", err)
	}
	if err := replaceFile(filepath.Join(dir, entriesName), f); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s %d valid until %s\n", entriesName, seq, expiry(f))
	return nil
}

// checkEntriesFile reports whether f checks out under keys at now, or, for
// a renewal, at the time it was signed.
func checkEntriesFile(keys, f release.File, lapsed bool) (release.Entries, error) {
	e, _, err := release.CheckEntries(keys, f, pinnedRoots(), now(), release.Seen{})
	if err != nil && lapsed && errors.Is(err, release.ErrExpired) {
		var b release.Entries
		if json.Unmarshal(f.Body, &b) == nil {
			e, _, err = release.CheckEntries(keys, f, pinnedRoots(), time.UnixMilli(b.TimeMS), release.Seen{})
		}
	}
	return e, err
}

// renewEntries signs the list of entry points at from again with the
// channel key k, one more seq, a new expiry and the same forwarders and
// relays, into
// out: with extend, on cbb.tools. A channel without one has nothing to
// renew.
func renewEntries(from, out string, keys release.File, k crypto.Signer) error {
	f, err := fetchFile(from + "/" + entriesName)
	if err != nil {
		step("%s/%s: %v; nothing to renew", from, entriesName, err)
		return nil
	}
	e, err := checkEntriesFile(keys, f, true)
	if err != nil {
		return fmt.Errorf("%s: %w", entriesName, err)
	}
	e.Seq++
	e.TimeMS = now().UnixMilli()
	e.ExpiresMS = e.TimeMS + entriesLife.Milliseconds()
	n, err := signWith(k, e)
	if err != nil {
		return err
	}
	if _, err := checkEntriesFile(keys, n, false); err != nil {
		return fmt.Errorf("the renewed %s does not check out: %w", entriesName, err)
	}
	if err := replaceFile(filepath.Join(out, entriesName), n); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s %d valid until %s\n", entriesName, e.Seq, expiry(n))
	return nil
}

// takeEntries replaces the list in a checkout of the branch channel with
// the one cbb.tools renewed, when that one checks out, is newer and names
// the same forwarders and relays: only the maintainer changes them.
func takeEntries(dir, src string) error {
	keys, err := readFile(filepath.Join(dir, "keys.json"))
	if err != nil {
		return err
	}
	cur, err := readFile(filepath.Join(dir, entriesName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var c release.Entries
	if err := json.Unmarshal(cur.Body, &c); err != nil {
		return err
	}
	f, err := fetchFile(src)
	if err != nil {
		step("%s: %v", src, err)
		return nil
	}
	n, err := checkEntriesFile(keys, f, false)
	switch {
	case err != nil:
		return fmt.Errorf("the renewed %s: %w", entriesName, err)
	case n.Seq <= c.Seq:
		fmt.Fprintf(stdout, "the branch's %s %d is the newest\n", entriesName, c.Seq)
		return nil
	case n.Seq > c.Seq+maxTakeStep:
		return fmt.Errorf("the renewed %s %d is more than %d past the branch's %d", entriesName, n.Seq, maxTakeStep, c.Seq)
	case !sameForwarders(n.Forwarders, c.Forwarders) || !sameRelays(n.Relays, c.Relays):
		return fmt.Errorf("the renewed %s names other forwarders or relays: only release-sign entries changes them", entriesName)
	}
	if err := writeFile(filepath.Join(dir, entriesName), f); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "took %s %d, valid until %s\n", entriesName, n.Seq, expiry(f))
	return nil
}

func sameForwarders(a, b []release.EntryForwarder) bool {
	return slices.EqualFunc(a, b, func(x, y release.EntryForwarder) bool {
		return x.Name == y.Name && slices.Equal(x.VLESS, y.VLESS)
	})
}

func sameRelays(a, b []release.EntryRelay) bool {
	return slices.EqualFunc(a, b, func(x, y release.EntryRelay) bool {
		return x.Name == y.Name && slices.Equal(x.Endpoints, y.Endpoints)
	})
}

// newestEntries returns the newest list of entry points of the sources
// that checks out under keys; false for none.
func newestEntries(sources []string, keys release.File) (release.File, release.Entries, bool) {
	var best release.File
	var be release.Entries
	found := false
	for _, src := range sources {
		src = strings.TrimSuffix(strings.TrimSpace(src), "/")
		if src == "" {
			continue
		}
		f, err := fetchFile(src + "/" + entriesName)
		if err != nil {
			continue
		}
		e, err := checkEntriesFile(keys, f, false)
		if err != nil {
			step("%s/%s: %v", src, entriesName, err)
			continue
		}
		if !found || e.Seq > be.Seq {
			best, be, found = f, e, true
		}
	}
	return best, be, found
}
