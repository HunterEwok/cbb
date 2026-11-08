// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command pins checks the tool versions that the workflows and build
// scripts write out by hand, which Dependabot does not see (it covers the
// actions, Go modules, crates, Gradle, npm and Swift packages): qemu, zig,
// the ESP32 toolchain, z88dk, the cargo tools CI installs, the pinned
// nightly Rust and so on. For each pin it asks the tool's own registry or
// release page for its latest stable version and prints one line; it
// exits 1 when a pin is behind, when one tool is pinned at two versions,
// or when the pinned nightly Rust is older than -nightly-days, so that the
// weekly run of the pins workflow fails and mails the maintainer. As
// Dependabot's cooldown, a version counts only once it has been out for
// -cooldown days: a release that turns out bad is mostly withdrawn in its
// first days.
//
// Usage:
//
//	go run ./tools/pins [-cooldown 7] [-nightly-days 60]
//
// GH_TOKEN, when set, is sent to GitHub's API, whose limit without a
// token is 60 requests an hour.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// pin is one hand-written version: where it is written and where its
// latest version is published.
type pin struct {
	name string
	// re finds the version in the files; its first group is the version.
	re *regexp.Regexp
	// releases returns the stable versions, written as the pin writes
	// them, each with when it was published.
	releases func(ctx context.Context) ([]release, error)
}

// release is a published version.
type release struct {
	version string
	at      time.Time
}

// files are the files that carry pins.
var files = []string{
	".github/workflows/*.yml",
	"member/packaging/*.sh",
	"packaging/fdroid/*.yml",
}

var pins = []pin{
	{"qemu", regexp.MustCompile(`(?m)^\s+QEMU: "?([0-9][0-9.]*)"?\s*$`), gitlabTag("qemu-project/qemu", "v")},
	{"zig (PyPI ziglang)", regexp.MustCompile(`ziglang==([0-9][^ \s]*)`), pypi("ziglang")},
	{"cargo-zigbuild", regexp.MustCompile(`cargo-zigbuild==([0-9][^ \s]*)`), pypi("cargo-zigbuild")},
	{"zizmor", regexp.MustCompile(`zizmor==([0-9][^ \s]*)`), pypi("zizmor")},
	{"cargo-ndk", regexp.MustCompile(`cargo-ndk@([0-9][^ \s]*)`), crate("cargo-ndk")},
	{"cargo-llvm-cov", regexp.MustCompile(`cargo-llvm-cov@([0-9][^ \s]*)`), crate("cargo-llvm-cov")},
	{"cargo-deny", regexp.MustCompile(`cargo-deny@([0-9][^ \s]*)`), crate("cargo-deny")},
	{"cargo-mutants", regexp.MustCompile(`cargo-mutants@([0-9][^ \s]*)`), crate("cargo-mutants")},
	{"quint", regexp.MustCompile(`@informalsystems/quint@([0-9][^ \s"]*)`), npm("@informalsystems/quint")},
	{"Rust for Xtensa (esp-rs/rust-build)", regexp.MustCompile(`(?m)^\s+ESP_RUST: "?([0-9][0-9.]*)"?\s*$`), githubRelease("esp-rs/rust-build", "v")},
	{"Espressif's QEMU", regexp.MustCompile(`(?m)^\s+ESP_QEMU: "?(esp-develop-[0-9.]+-[0-9]+)"?\s*$`), githubRelease("espressif/qemu", "")},
	{"espflash", regexp.MustCompile(`(?m)^\s+ESPFLASH: "?([0-9][0-9.]*)"?\s*$`), githubRelease("esp-rs/espflash", "v")},
	{"z88dk", regexp.MustCompile(`(?m)^\s+Z88DK: "?([0-9][0-9.]*)"?\s*$`), githubRelease("z88dk/z88dk", "v")},
	{"Rust (F-Droid build)", regexp.MustCompile(`--default-toolchain ([0-9][0-9.]*)`), githubRelease("rust-lang/rust", "")},
	{"rustup (F-Droid build)", regexp.MustCompile(`rustup@([0-9][0-9.]*)`), githubTag("rust-lang/rustup", "")},
}

// nightlyRe finds a pinned nightly Rust.
var nightlyRe = regexp.MustCompile(`nightly-(\d{4}-\d{2}-\d{2})`)

// found is a pin's versions in the files, each with where it is written.
type found map[string][]string

func scan(re *regexp.Regexp, paths []string) (found, error) {
	f := found{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for _, m := range re.FindAllSubmatchIndex(b, -1) {
			v := string(b[m[2]:m[3]])
			line := 1 + strings.Count(string(b[:m[0]]), "\n")
			f[v] = append(f[v], fmt.Sprintf("%s:%d", p, line))
		}
	}
	return f, nil
}

func main() {
	nightlyDays := flag.Int("nightly-days", 60, "the oldest a pinned nightly Rust may be, in days")
	cooldown := flag.Int("cooldown", 7, "the days a new version waits before a pin counts as behind")
	flag.Parse()
	var paths []string
	for _, g := range files {
		m, err := filepath.Glob(g)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pins:", err)
			os.Exit(2)
		}
		paths = append(paths, m...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bad := false
	for _, p := range pins {
		f, err := scan(p.re, paths)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pins:", err)
			os.Exit(2)
		}
		if len(f) == 0 {
			fmt.Printf("FAIL %s: no pin found; the pattern no longer matches the files\n", p.name)
			bad = true
			continue
		}
		rels, err := p.releases(ctx)
		if err == nil && len(rels) == 0 {
			err = errors.New("the registry gave no stable version")
		}
		if err != nil {
			fmt.Printf("FAIL %s: the latest version: %v\n", p.name, err)
			bad = true
			continue
		}
		due, newest := choose(rels, time.Now().Add(-time.Duration(*cooldown)*24*time.Hour))
		latest := newest.version
		for _, v := range sortedKeys(f) {
			where := strings.Join(f[v], ", ")
			switch {
			case len(f) > 1:
				fmt.Printf("FAIL %s: pinned at %d versions; %s at %s (latest %s)\n", p.name, len(f), v, where, latest)
				bad = true
			case due.version != "" && newer(due.version, v):
				fmt.Printf("FAIL %s: %s, behind %s of %s (newest %s; %s)\n", p.name, v, due.version, due.at.Format("2006-01-02"), latest, where)
				bad = true
			case newer(latest, v):
				fmt.Printf("ok   %s: %s; %s came out %s and waits out the cooldown\n", p.name, v, latest, newest.at.Format("2006-01-02"))
			default:
				fmt.Printf("ok   %s: %s, the latest\n", p.name, v)
			}
		}
	}
	f, err := scan(nightlyRe, paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pins:", err)
		os.Exit(2)
	}
	for _, v := range sortedKeys(f) {
		d, err := time.Parse("2006-01-02", v)
		if err != nil {
			continue
		}
		age := int(time.Since(d).Hours() / 24)
		if len(f) > 1 || age > *nightlyDays {
			fmt.Printf("FAIL nightly Rust: nightly-%s is %d days old, of %d pinned (%s)\n", v, age, len(f), strings.Join(f[v], ", "))
			bad = true
		} else {
			fmt.Printf("ok   nightly Rust: nightly-%s, %d days old\n", v, age)
		}
	}
	if bad {
		os.Exit(1)
	}
}

// choose picks due, the newest release published by cutoff, and the
// newest of all.
func choose(rels []release, cutoff time.Time) (due, newest release) {
	for _, r := range rels {
		if newest.version == "" || newer(r.version, newest.version) {
			newest = r
		}
		if !r.at.After(cutoff) && (due.version == "" || newer(r.version, due.version)) {
			due = r
		}
	}
	return due, newest
}

func sortedKeys(f found) []string {
	k := make([]string, 0, len(f))
	for v := range f {
		k = append(k, v)
	}
	sort.Strings(k)
	return k
}

// newer reports whether version a is newer than b: dotted numbers compare
// part by part; anything else is newer when it differs.
func newer(a, b string) bool {
	pa, oka := parts(a)
	pb, okb := parts(b)
	if !oka || !okb {
		return a != b
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func parts(v string) ([]int, bool) {
	var out []int
	for s := range strings.SplitSeq(v, ".") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

var stable = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cbb-pins")
	if strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Accept", "application/vnd.github+json")
		if t := os.Getenv("GH_TOKEN"); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%s: %s: %s", url, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

func pypi(name string) func(context.Context) ([]release, error) {
	return func(ctx context.Context) ([]release, error) {
		var r struct {
			Releases map[string][]struct {
				Uploaded time.Time `json:"upload_time_iso_8601"`
				Yanked   bool      `json:"yanked"`
			} `json:"releases"`
		}
		if err := getJSON(ctx, "https://pypi.org/pypi/"+name+"/json", &r); err != nil {
			return nil, err
		}
		var out []release
		for v, files := range r.Releases {
			if !stable.MatchString(v) || len(files) == 0 || files[0].Yanked {
				continue
			}
			rel := release{version: v, at: files[0].Uploaded}
			for _, f := range files {
				if f.Uploaded.Before(rel.at) {
					rel.at = f.Uploaded
				}
			}
			out = append(out, rel)
		}
		return out, nil
	}
}

func crate(name string) func(context.Context) ([]release, error) {
	return func(ctx context.Context) ([]release, error) {
		var r struct {
			Versions []struct {
				Num     string    `json:"num"`
				Created time.Time `json:"created_at"`
				Yanked  bool      `json:"yanked"`
			} `json:"versions"`
		}
		if err := getJSON(ctx, "https://crates.io/api/v1/crates/"+name, &r); err != nil {
			return nil, err
		}
		var out []release
		for _, v := range r.Versions {
			if stable.MatchString(v.Num) && !v.Yanked {
				out = append(out, release{version: v.Num, at: v.Created})
			}
		}
		return out, nil
	}
}

func npm(name string) func(context.Context) ([]release, error) {
	return func(ctx context.Context) ([]release, error) {
		var r struct {
			Time map[string]time.Time `json:"time"`
		}
		if err := getJSON(ctx, "https://registry.npmjs.org/"+name, &r); err != nil {
			return nil, err
		}
		var out []release
		for v, at := range r.Time {
			if stable.MatchString(v) {
				out = append(out, release{version: v, at: at})
			}
		}
		return out, nil
	}
}

func githubRelease(repo, prefix string) func(context.Context) ([]release, error) {
	return func(ctx context.Context) ([]release, error) {
		var rs []struct {
			Tag        string    `json:"tag_name"`
			Published  time.Time `json:"published_at"`
			Draft      bool      `json:"draft"`
			Prerelease bool      `json:"prerelease"`
		}
		if err := getJSON(ctx, "https://api.github.com/repos/"+repo+"/releases?per_page=30", &rs); err != nil {
			return nil, err
		}
		var out []release
		for _, r := range rs {
			v, ok := strings.CutPrefix(r.Tag, prefix)
			if ok && !r.Draft && !r.Prerelease {
				out = append(out, release{version: v, at: r.Published})
			}
		}
		return out, nil
	}
}

// githubTag reads the stable versions among a repository's tags, for
// projects that publish no GitHub releases; a tag's date is its commit's,
// fetched for the newest few only.
func githubTag(repo, prefix string) func(context.Context) ([]release, error) {
	return func(ctx context.Context) ([]release, error) {
		var tags []struct {
			Name   string `json:"name"`
			Commit struct {
				SHA string `json:"sha"`
			} `json:"commit"`
		}
		if err := getJSON(ctx, "https://api.github.com/repos/"+repo+"/tags?per_page=100", &tags); err != nil {
			return nil, err
		}
		var out []release
		sha := map[string]string{}
		for _, t := range tags {
			if v, ok := strings.CutPrefix(t.Name, prefix); ok && stable.MatchString(v) {
				out = append(out, release{version: v})
				sha[v] = t.Commit.SHA
			}
		}
		sort.Slice(out, func(i, j int) bool { return newer(out[i].version, out[j].version) })
		out = out[:min(len(out), 3)]
		for i := range out {
			var c struct {
				Commit struct {
					Committer struct {
						Date time.Time `json:"date"`
					} `json:"committer"`
				} `json:"commit"`
			}
			if err := getJSON(ctx, "https://api.github.com/repos/"+repo+"/commits/"+sha[out[i].version], &c); err != nil {
				return nil, err
			}
			out[i].at = c.Commit.Committer.Date
		}
		return out, nil
	}
}

func gitlabTag(project, prefix string) func(context.Context) ([]release, error) {
	return func(ctx context.Context) ([]release, error) {
		var tags []struct {
			Name   string `json:"name"`
			Commit struct {
				Committed time.Time `json:"committed_date"`
			} `json:"commit"`
		}
		url := "https://gitlab.com/api/v4/projects/" + strings.ReplaceAll(project, "/", "%2F") + "/repository/tags?per_page=100"
		if err := getJSON(ctx, url, &tags); err != nil {
			return nil, err
		}
		var out []release
		for _, t := range tags {
			if v, ok := strings.CutPrefix(t.Name, prefix); ok && stable.MatchString(v) {
				out = append(out, release{version: v, at: t.Commit.Committed})
			}
		}
		return out, nil
	}
}
