// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command formatfreeze keeps the 0.6 format's vectors (testdata/format/*.json)
// frozen once the owner declares the freeze, so that a later version reads
// exactly what 0.6 wrote:
//
//	formatfreeze -check                     every vector matches the manifest
//	formatfreeze -check -since BASE         and every commit after BASE keeps the rules
//	formatfreeze -write                     write the manifest again (while it is a draft)
//	formatfreeze -write -break "why"        change a frozen vector: one format break
//
// The manifest, testdata/format/FROZEN, names the state ("draft" until the
// freeze, then "frozen"), the number of breaks after the freeze, the last
// break's reason, and each vector's SHA-256. While it is a draft, -write
// rewrites the hashes freely. Once it is frozen:
//
//   - a vector may be added, but a listed one may not change or go away
//     unless the same commit raises "breaks" by one and gives a new reason;
//   - breaks may not pass MaxBreaks (one before 1.0, as the owner allowed);
//     a second break means changing this command, never an accident;
//   - the state may not go back to draft.
//
// -check alone compares the files with the manifest; -since walks the commits
// after BASE with git and checks each commit against its parent, so a break
// cannot hide in a later commit of the same pull request. That the readers
// read and write the vectors the same way is the readers' job: the core's
// tests, testdata/format/check and gen.py writing the same bytes (CI's
// format job runs all of them).
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// MaxBreaks is how many times a frozen vector may change before 1.0.
const MaxBreaks = 1

// Dir is the vectors' directory and Manifest the manifest's name in it.
const (
	Dir      = "testdata/format"
	Manifest = "FROZEN"
)

const header = `# The 0.6 format's frozen vectors (tools/formatfreeze). Written by
# "go run ./tools/formatfreeze -write"; once the state is "frozen", a listed
# vector changes only with "-write -break REASON", which counts a format break.
`

// Frozen is the manifest.
type Frozen struct {
	State  string            // "draft" or "frozen"
	Breaks int               // breaks after the freeze
	Reason string            // the last break's reason, "-" before any
	Hashes map[string]string // file name -> hex SHA-256
}

// Parse reads a manifest.
func Parse(b []byte) (*Frozen, error) {
	f := &Frozen{Hashes: map[string]string{}}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if ok && !strings.HasPrefix(line, "sha256 ") {
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			if seen[key] {
				return nil, fmt.Errorf("line %d: %s twice", n, key)
			}
			seen[key] = true
			switch key {
			case "state":
				if val != "draft" && val != "frozen" {
					return nil, fmt.Errorf("line %d: state %q is neither draft nor frozen", n, val)
				}
				f.State = val
			case "breaks":
				v, err := strconv.Atoi(val)
				if err != nil || v < 0 {
					return nil, fmt.Errorf("line %d: breaks %q", n, val)
				}
				f.Breaks = v
			case "break":
				if val == "" {
					return nil, fmt.Errorf("line %d: an empty break reason", n)
				}
				f.Reason = val
			default:
				return nil, fmt.Errorf("line %d: unknown key %q", n, key)
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "sha256" {
			return nil, fmt.Errorf("line %d: not \"sha256 HASH FILE\"", n)
		}
		if h, err := hex.DecodeString(fields[1]); err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("line %d: bad hash", n)
		}
		name := fields[2]
		if name != filepath.Base(name) || !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("line %d: %q is not a vector file", n, name)
		}
		if _, dup := f.Hashes[name]; dup {
			return nil, fmt.Errorf("line %d: %s twice", n, name)
		}
		f.Hashes[name] = fields[1]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for _, k := range []string{"state", "breaks", "break"} {
		if !seen[k] {
			return nil, fmt.Errorf("no %s line", k)
		}
	}
	if f.State == "draft" && f.Breaks != 0 {
		return nil, errors.New("a draft has no breaks")
	}
	if f.Breaks > MaxBreaks {
		return nil, fmt.Errorf("%d format breaks, at most %d before 1.0", f.Breaks, MaxBreaks)
	}
	return f, nil
}

// Bytes writes the manifest, its files sorted.
func (f *Frozen) Bytes() []byte {
	var b bytes.Buffer
	b.WriteString(header)
	fmt.Fprintf(&b, "state: %s\nbreaks: %d\nbreak: %s\n\n", f.State, f.Breaks, f.Reason)
	names := make([]string, 0, len(f.Hashes))
	for n := range f.Hashes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "sha256 %s %s\n", f.Hashes[n], n)
	}
	return b.Bytes()
}

// Changed lists the vectors of old that new changes or drops.
func Changed(old, new *Frozen) []string {
	var out []string
	for n, h := range old.Hashes {
		if new.Hashes[n] != h {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Step checks one change of the manifest, from a parent's to a child's.
// A nil parent is the manifest's first commit.
func Step(parent, child *Frozen) error {
	if parent == nil {
		if child.State == "frozen" && child.Breaks != 0 {
			return errors.New("a new manifest starts with no breaks")
		}
		return nil
	}
	if parent.State == "frozen" && child.State != "frozen" {
		return errors.New("the frozen format went back to a draft")
	}
	if parent.State == "draft" {
		if child.Breaks != 0 {
			return errors.New("breaks counted before the freeze")
		}
		return nil
	}
	changed := Changed(parent, child)
	switch {
	case len(changed) == 0 && child.Breaks != parent.Breaks:
		return fmt.Errorf("breaks went from %d to %d but no frozen vector changed", parent.Breaks, child.Breaks)
	case len(changed) == 0:
		return nil
	case child.Breaks != parent.Breaks+1:
		return fmt.Errorf("frozen vectors changed (%s) without counting a break: run formatfreeze -write -break REASON",
			strings.Join(changed, ", "))
	case child.Reason == parent.Reason || child.Reason == "-":
		return fmt.Errorf("a format break (%s) needs its own reason", strings.Join(changed, ", "))
	}
	return nil
}

// Hashes reads the vectors in dir.
func Hashes(dir string) (map[string]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		out[filepath.Base(p)] = hex.EncodeToString(h[:])
	}
	return out, nil
}

// Check compares the files with the manifest.
func Check(f *Frozen, files map[string]string) error {
	var errs []string
	for n, h := range f.Hashes {
		got, ok := files[n]
		switch {
		case !ok:
			errs = append(errs, n+" is listed but missing")
		case got != h:
			errs = append(errs, n+" differs from the manifest")
		}
	}
	for n := range files {
		if _, ok := f.Hashes[n]; !ok {
			errs = append(errs, n+" is not in the manifest")
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	how := "run formatfreeze -write"
	if f.State == "frozen" {
		how = "a frozen vector changes only with formatfreeze -write -break REASON"
	}
	return fmt.Errorf("%s (%s)", strings.Join(errs, "; "), how)
}

// Write builds the next manifest from the files.
func Write(old *Frozen, files map[string]string, reason string, freeze bool) (*Frozen, error) {
	next := &Frozen{State: "draft", Reason: "-", Hashes: files}
	if old != nil {
		next.State, next.Breaks, next.Reason = old.State, old.Breaks, old.Reason
	}
	if freeze {
		next.State = "frozen"
	}
	if old == nil || old.State == "draft" {
		if reason != "" {
			return nil, errors.New("nothing is frozen yet: -break counts only after the freeze")
		}
		return next, nil
	}
	changed := Changed(old, next)
	switch {
	case len(changed) > 0 && reason == "":
		return nil, fmt.Errorf("frozen vectors changed (%s): a format break needs -break REASON", strings.Join(changed, ", "))
	case len(changed) == 0 && reason != "":
		return nil, errors.New("-break but no frozen vector changed")
	case len(changed) > 0:
		if old.Breaks+1 > MaxBreaks {
			return nil, fmt.Errorf("the format may break at most %d time(s) before 1.0", MaxBreaks)
		}
		if strings.ContainsAny(reason, "\n\r") || reason == "-" || reason == old.Reason {
			return nil, errors.New("give the break a new reason of one line")
		}
		next.Breaks, next.Reason = old.Breaks+1, reason
	}
	return next, nil
}

func gitShow(rev, path string) ([]byte, bool, error) {
	cmd := exec.Command("git", "show", rev+":"+path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := stderr.String()
		if strings.Contains(msg, "does not exist") || strings.Contains(msg, "exists on disk, but not in") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("git show %s:%s: %v: %s", rev, path, err, msg)
	}
	return out, true, nil
}

func manifestAt(rev string) (*Frozen, error) {
	b, ok, err := gitShow(rev, Dir+"/"+Manifest)
	if err != nil || !ok {
		return nil, err
	}
	f, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rev, err)
	}
	return f, nil
}

// vectorsAt hashes the vectors a commit holds, so a commit cannot change a
// vector and leave the manifest for a later commit.
func vectorsAt(rev string) (map[string]string, error) {
	out, err := exec.Command("git", "ls-tree", "--name-only", rev, Dir+"/").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-tree %s: %v", rev, err)
	}
	files := map[string]string{}
	for _, p := range strings.Fields(string(out)) {
		if filepath.Ext(p) != ".json" {
			continue
		}
		b, _, err := gitShow(rev, p)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		files[filepath.Base(p)] = hex.EncodeToString(h[:])
	}
	return files, nil
}

// Since checks every commit after base (first parents, as a merge brings in
// commits that were checked on their own branch).
func Since(base string) error {
	out, err := exec.Command("git", "rev-list", "--reverse", "--first-parent", base+"..HEAD").Output()
	if err != nil {
		return fmt.Errorf("git rev-list %s..HEAD: %v", base, err)
	}
	for _, rev := range strings.Fields(string(out)) {
		child, err := manifestAt(rev)
		if err != nil {
			return err
		}
		if child == nil {
			continue
		}
		parent, err := manifestAt(rev + "^")
		if err != nil {
			return err
		}
		if err := Step(parent, child); err != nil {
			return fmt.Errorf("commit %.12s: %w", rev, err)
		}
		files, err := vectorsAt(rev)
		if err != nil {
			return err
		}
		if err := Check(child, files); err != nil {
			return fmt.Errorf("commit %.12s: %w", rev, err)
		}
	}
	return nil
}

func main() {
	check := flag.Bool("check", false, "compare the vectors with the manifest")
	since := flag.String("since", "", "with -check: also check every commit after this one")
	write := flag.Bool("write", false, "write the manifest from the vectors")
	reason := flag.String("break", "", "with -write: the reason of a format break")
	freeze := flag.Bool("freeze", false, "with -write: declare the freeze (the owner's decision)")
	flag.Parse()
	if *check == *write {
		fmt.Fprintln(os.Stderr, "formatfreeze: give -check or -write")
		os.Exit(2)
	}
	if err := run(*check, *since, *reason, *freeze); err != nil {
		fmt.Fprintln(os.Stderr, "formatfreeze:", err)
		os.Exit(1)
	}
}

func run(check bool, since, reason string, freeze bool) error {
	path := filepath.Join(Dir, Manifest)
	files, err := Hashes(Dir)
	if err != nil {
		return err
	}
	var old *Frozen
	if b, err := os.ReadFile(path); err == nil {
		if old, err = Parse(b); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if check {
		if old == nil {
			return fmt.Errorf("no %s", path)
		}
		if err := Check(old, files); err != nil {
			return err
		}
		if since != "" {
			return Since(since)
		}
		return nil
	}
	next, err := Write(old, files, reason, freeze)
	if err != nil {
		return err
	}
	return os.WriteFile(path, next.Bytes(), 0o644)
}
