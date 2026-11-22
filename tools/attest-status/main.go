// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command attest-status mirrors Google's revocation list of Android
// attestation certificates as attest-status.json, signed with the status
// key that keys.json certifies (docs/protocol.md, section 17, "Revoked
// attestations"). The mirror runs it once a day:
//
//	attest-status -key status-key.pem[,status-pq.pem] -out DIR [-days 8] [-allow-drop]
//
// DIR holds the published files: it reads the attest-status.json there to
// raise the sequence number, and refuses a list that drops a serial
// number the last one revoked unless -allow-drop, since Google's list only
// grows but for suspensions it lifts. Nothing is written when Google's
// list has not changed and the last file is more than a day from expiry.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/release"
)

// googleURL is Google's list; tests replace it.
var googleURL = "https://android.googleapis.com/attestation/status"

// client fetches the list, giving up after fetchTimeout, so that a server
// that stops answering cannot hold the job that runs this.
var (
	fetchTimeout = 30 * time.Second
	client       = &http.Client{Timeout: fetchTimeout}
)

var now = time.Now

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "attest-status:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("attest-status", flag.ExitOnError)
	keyPath := fs.String("key", "", "the status key's two halves, P-256 and SLH-DSA, in PEM files, comma-separated (or one file with both)")
	out := fs.String("out", "", "the directory of the published files")
	days := fs.Int("days", 8, "days until the list expires, at most 8")
	allowDrop := fs.Bool("allow-drop", false, "take a list that drops serial numbers the last one revoked")
	fs.Parse(args)
	if *keyPath == "" || *out == "" {
		return errors.New("-key and -out are needed")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	revoked, source, err := fetch()
	if err != nil {
		return err
	}
	path := filepath.Join(*out, "attest-status.json")
	t := now()
	next := release.Status{V: 1, Type: release.TypeStatus, Seq: 1, TimeMS: t.UnixMilli(),
		ExpiresMS: t.Add(time.Duration(*days) * 24 * time.Hour).UnixMilli(), SourceMS: source, AndroidRevoked: revoked}
	if last, ok, err := readLast(path); err != nil {
		return err
	} else if ok {
		if !*allowDrop {
			for _, s := range last.AndroidRevoked {
				if _, found := slices.BinarySearchFunc(revoked, s, compareSerials); !found {
					return fmt.Errorf("the list from Google no longer revokes %s; check it and run again with -allow-drop", s)
				}
			}
		}
		if slices.Equal(last.AndroidRevoked, revoked) && last.ExpiresMS-t.UnixMilli() > 24*time.Hour.Milliseconds() {
			return nil
		}
		next.Seq = last.Seq + 1
	}
	f, err := release.Sign(next, key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, data, 0o644)
}

func compareSerials(a, b string) int {
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

// fetch returns the serial numbers Google's list revokes or suspends, in
// order, and when it last changed.
func fetch() ([]string, int64, error) {
	resp, err := client.Get(googleURL)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("the list from Google: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, 0, err
	}
	var list struct {
		Entries map[string]struct {
			Status string `json:"status"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, 0, fmt.Errorf("the list from Google: %w", err)
	}
	if list.Entries == nil {
		return nil, 0, errors.New("the list from Google has no entries")
	}
	var out []string
	for serial, e := range list.Entries {
		// Google counts a suspended certificate as revoked while it is.
		if e.Status != "REVOKED" && e.Status != "SUSPENDED" {
			continue
		}
		n, ok := new(big.Int).SetString(serial, 16)
		if !ok || n.Sign() < 0 {
			return nil, 0, fmt.Errorf("the list from Google names %q, not a serial number", serial)
		}
		out = append(out, n.Text(16))
	}
	release.SortSerials(out)
	out = slices.Compact(out)
	var source int64
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		source = lm.UnixMilli()
	}
	return out, source, nil
}

// readLast returns the body of the last attest-status.json, if there is
// one. It is the mirror's own file, so its signature is not checked.
func readLast(path string) (release.Status, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return release.Status{}, false, nil
	}
	if err != nil {
		return release.Status{}, false, err
	}
	var f release.File
	var s release.Status
	if err := json.Unmarshal(data, &f); err != nil {
		return s, false, fmt.Errorf("%s: %w", path, err)
	}
	if err := json.Unmarshal(f.Body, &s); err != nil {
		return s, false, fmt.Errorf("%s: %w", path, err)
	}
	return s, true, nil
}

// readKey reads the status key's halves from the PEM files paths names,
// comma-separated.
func readKey(paths string) (release.Signer, error) {
	var texts [][]byte
	for _, p := range strings.Split(paths, ",") {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		texts = append(texts, data)
	}
	s, err := release.ParseSigner(texts...)
	for _, t := range texts {
		clear(t)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", paths, err)
	}
	return s, nil
}
