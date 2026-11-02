// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// automated names the suites that run each case of
// docs/testbench-catalogue.md, in part or in full; "ci" is a test that CI
// runs on every pull request instead, such as the tray app's window in a
// headless browser. A test checks that every ID here is in the catalogue
// and that the suites exist.
var automated = map[string][]string{
	// Sync of text.
	"Y1": {"full"}, "Y2": {"full"}, "Y3": {"full"}, "Y4": {"full"}, "Y5": {"full"},
	"Y10": {"full"}, "Y11": {"full"}, "Y30": {"full"},
	// Groups and pairing.
	"G1": {"full"}, "G3": {"smoke", "full"}, "G12": {"away"}, "G23": {"smoke", "full", "fleet"},
	// Modes, installs, the command line.
	"M1": {"full"}, "M5": {"full", "fleet"}, "I16": {"full"},
	"U1": {"check", "smoke"}, "U3": {"full"}, "U4": {"full", "away", "relay", "faults"},
	"U5": {"faults"}, "U6": {"faults"}, "U7": {"faults"}, "U10": {"full"},
	"H6": {"full"}, "K8": {"full"},
	// Away from home.
	"W1": {"away"}, "W10": {"away", "fleet"}, "W13": {"away", "fleet"}, "W14": {"away", "fleet"}, "W15": {"away", "fleet"},
	"W31": {"away", "fleet"}, "W36": {"relay", "fleet"}, "W3": {"fleet"}, "W11": {"fleet"}, "W18": {"fleet"},
	"W19": {"fleet"}, "W20": {"fleet"}, "W32": {"fleet"}, "W33": {"fleet"}, "W34": {"fleet"}, "W35": {"fleet"},
	"W30": {"fleet"}, "W37": {"fleet"}, "W38": {"fleet"}, "W4": {"fleet"}, "W21": {"fleet"}, "W40": {"fleet"},
	// Security.
	"S10": {"full"}, "S11": {"full"}, "S15": {"full"}, "S16": {"full"},
	"S3": {"fleet"}, "S4": {"fleet"}, "S20": {"fleet"}, "S21": {"fleet"}, "S5": {"fleet"}, "S8": {"fleet"},
	// Load and faults.
	"E7": {"faults"}, "E8": {"faults"}, "E11": {"faults"}, "E6": {"fleet"},
	// The fleet of containers.
	"G5": {"fleet"}, "G6": {"fleet"}, "G9": {"fleet"}, "G20": {"fleet"}, "G21": {"fleet"},
	"G22": {"fleet"}, "G26": {"fleet"}, "G30": {"fleet"}, "G42": {"fleet"}, "G43": {"fleet"},
	"Y12": {"fleet"}, "Y16": {"fleet"}, "M3": {"fleet"}, "M6": {"fleet"}, "D15": {"fleet"},
	"D9": {"fleet"}, "O14": {"fleet"}, "E10": {"fleet"},
	"E3": {"fleet"}, "E5": {"fleet"}, "E9": {"fleet"}, "S13": {"fleet"}, "S14": {"fleet"},
	"T1": {"fleet"}, "T2": {"fleet"}, "T6": {"fleet"}, "T7": {"fleet"}, "T9": {"fleet"},
	"T10": {"fleet"}, "T13": {"fleet"}, "T14": {"fleet"}, "G25": {"fleet"}, "G27": {"fleet"},
	"G33": {"fleet"}, "S24": {"fleet"}, "M4": {"fleet"}, "G4": {"fleet"}, "G7": {"fleet"},
	"D2": {"fleet"}, "D4": {"fleet"}, "D5": {"fleet"}, "D11": {"fleet"}, "D6": {"fleet"}, "D7": {"fleet"}, "D8": {"fleet"}, "D12": {"fleet"},
	"I19": {"fleet"}, "U8": {"fleet"}, "U13": {"fleet"}, "Q1": {"fleet"}, "Q4": {"fleet"},
	"Q6": {"fleet"}, "Q7": {"fleet"}, "X2": {"fleet"}, "X3": {"fleet"}, "K12": {"fleet"},
	"Q2": {"fleet"}, "Q5": {"fleet"}, "X1": {"fleet"}, "U2": {"fleet"},
	"O2": {"fleet"}, "O3": {"fleet"}, "O5": {"fleet"}, "Y20": {"fleet"}, "Y21": {"fleet"},
	"Y22": {"fleet"}, "Y23": {"fleet"}, "G34": {"fleet"}, "K9": {"fleet"},
	"Y33": {"fleet"}, "D16": {"fleet"}, "G24": {"fleet"}, "X4": {"fleet"}, "G35": {"fleet"}, "U11": {"fleet"}, "T17": {"fleet"}, "T19": {"fleet"}, "G13": {"fleet"}, "D17": {"fleet"}, "D3": {"fleet"}, "D14": {"fleet"}, "D13": {"fleet"}, "Y15": {"fleet"}, "G16": {"fleet"}, "G40": {"fleet"}, "K3": {"fleet"},
	"E1": {"fleet"}, "E2": {"fleet"}, "E4": {"fleet"}, "O7": {"fleet"}, "O8": {"fleet"},
	"S17": {"fleet"}, "S23": {"fleet"}, "G31": {"fleet"}, "G32": {"fleet"}, "K14": {"fleet"}, "K11": {"fleet"}, "G41": {"fleet"}, "Y6": {"fleet"}, "I3": {"fleet"}, "I8": {"fleet"}, "I9": {"fleet"}, "I10": {"fleet"}, "I11": {"fleet"}, "I12": {"fleet"}, "I2": {"fleet"}, "I4": {"fleet"}, "I6": {"fleet"}, "I7": {"fleet"}, "O9": {"fleet"}, "U9": {"fleet"}, "O6": {"fleet"}, "O15": {"fleet"}, "G17": {"fleet"}, "G8": {"fleet"}, "S22": {"fleet"}, "I1": {"fleet"},
	"I5": {"fleet"}, "I20": {"fleet"}, "S12": {"fleet"}, "I26": {"fleet"}, "G15": {"fleet"}, "S7": {"fleet"}, "S6": {"fleet"}, "H5": {"fleet"},
	"W17": {"fleet"}, "D1": {"fleet"}, "S1": {"fleet"}, "S2": {"fleet"}, "S9": {"fleet"}, "S18": {"fleet"}, "O10": {"fleet"}, "Y34": {"fleet"}, "I25": {"fleet"}, "W2": {"fleet"}, "D10": {"fleet"},
	// The desktops' own clipboards.
	"Y24": {"desktop"}, "Y25": {"desktop"}, "Y31": {"desktop"}, "Y32": {"desktop"},
	"T3": {"desktop"}, "T5": {"desktop"}, "T11": {"desktop"}, "T12": {"desktop"},
	"I21": {"desktop"}, "M2": {"desktop"}, "H2": {"desktop"}, "H3": {"desktop"}, "O13": {"desktop"},
	"Y26": {"desktop"}, "O12": {"desktop"}, "Q3": {"desktop"}, "I18": {"desktop"}, "H7": {"desktop"}, "H8": {"desktop"}, "O1": {"desktop"}, "O4": {"desktop"}, "H1": {"desktop"}, "T15": {"desktop"}, "H4": {"desktop"}, "K13": {"desktop"},
	// CI's tests of the apps' windows: the tray app in a headless browser,
	// XCUITest of the iPhone app and the Mac app, the Android app on Robolectric.
	// The Android app on an emulator in a group with the fleet (the phone suite).
	"A1": {"phone"}, "M7": {"phone"}, "T16": {"phone"}, "Q8": {"phone"}, "A6": {"phone"},
	"A12": {"phone"}, "O11": {"phone"}, "Y35": {"phone"}, "W5": {"phone"}, "W42": {"phone"},
	"W16": {"phone"}, "G14": {"phone"},
	"A2": {"ci"}, "A4": {"ci"}, "A5": {"ci"}, "A8": {"ci"}, "A9": {"ci"}, "A14": {"ci"}, "A15": {"ci"}, "A16": {"ci"}, "U12": {"ci"},
	// CI's OpenWrt job (the apk feed, procd, UCI, fw4, the NTP wait, a
	// sysupgrade's kept files) and the mips tests under qemu, its FreeBSD
	// VM (rc.d, pf, ipfw, OPNsense, pfSense's printed rules, X11 under
	// Xvfb), and the F-Droid build reproduced without Play services, whose
	// screens the Android ScreensTest drives.
	"I23": {"ci"}, "H9": {"ci"}, "H10": {"ci"}, "A10": {"ci"},
	// The Go tests and the interop vectors that refuse the records cbb upgrade gave.
	"G29": {"ci"},
	// The phone kits' tests and the Go tests that read what they sign: the
	// Swift and Kotlin phones admit a Go joiner by its QR code (G10, the fleet's
	// G17 the refusals), a takeover (G28), a computer made an admin (G36), the
	// watch's shared vectors (G38), the attestation and EK chains (K10).
	"G10": {"ci"}, "G28": {"ci"}, "G36": {"ci"}, "G38": {"ci"}, "K10": {"ci"},
	// The published workflow's check of every release (release-check).
	"I22": {"ci"},
	// The time-scaled build.
	"K1": {"time"}, "K2": {"time"}, "K4": {"time"}, "K6": {"time"}, "K7": {"time"}, "Y14": {"time"}, "T8": {"time", "fleet"},
	"Y13": {"time"}, "W39": {"time"}, "W12": {"time"}, "K5": {"time"},
}

// suites lists every suite `testbench` runs, in the order `all` runs them.
var suites = []string{"check", "smoke", "full", "faults", "desktop", "away", "relay", "fleet", "time", "phone"}

// catCase is one case of the catalogue.
type catCase struct {
	ID, Text string
	How      []string // the kinds of section 0.1: real, fleet, time, feed, ui, helper, person
	Needs    []string // what is missing for it, empty when nothing is
	Old      []string // the IDs of testbench-cases.md it replaces
}

// automatic tells whether the case can run without a person.
func (c catCase) automatic() bool {
	for _, h := range c.How {
		if h != "person" {
			return true
		}
	}
	return false
}

// function is one line of docs/testbench-functions.md.
type function struct {
	ID, What string
	Cases    []string
}

var (
	catRowRE  = regexp.MustCompile(`(?m)^\| ([A-Z][0-9]+) \| (.+) \| ([a-z, ]+) \|([^|]*)\|$`)
	funcRowRE = regexp.MustCompile(`(?m)^\| ([A-Z]\.[0-9]+) \| (.+) \| ([^|]*) \|$`)
	oldRE     = regexp.MustCompile(`\[([A-Z][a-z]*[0-9]*(?:, [A-Z][a-z]*[0-9]*)*)\]$`)
	kinds     = map[string]bool{"real": true, "fleet": true, "time": true, "feed": true, "ui": true, "helper": true, "person": true}
)

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" && f != "-" {
			out = append(out, f)
		}
	}
	return out
}

// readCatalogue reads the cases of the catalogue's tables.
func readCatalogue(text string) ([]catCase, error) {
	var out []catCase
	seen := map[string]bool{}
	for _, m := range catRowRE.FindAllStringSubmatch(text, -1) {
		c := catCase{ID: m[1], Text: strings.TrimSpace(m[2]), How: splitList(m[3]), Needs: splitList(m[4])}
		if seen[c.ID] {
			return nil, fmt.Errorf("case %s is listed twice", c.ID)
		}
		seen[c.ID] = true
		for _, h := range c.How {
			if !kinds[h] {
				return nil, fmt.Errorf("case %s: unknown kind %q", c.ID, h)
			}
		}
		if len(c.How) == 0 {
			return nil, fmt.Errorf("case %s says nothing of how it runs", c.ID)
		}
		if o := oldRE.FindStringSubmatch(c.Text); o != nil {
			c.Old = splitList(o[1])
		}
		out = append(out, c)
	}
	return out, nil
}

// readFunctions reads the functions list's tables.
func readFunctions(text string) ([]function, error) {
	var out []function
	seen := map[string]bool{}
	for _, m := range funcRowRE.FindAllStringSubmatch(text, -1) {
		f := function{ID: m[1], What: strings.TrimSpace(m[2]), Cases: splitList(m[3])}
		if seen[f.ID] {
			return nil, fmt.Errorf("function %s is listed twice", f.ID)
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out, nil
}

// loadCatalogue reads both documents from the repository's docs.
func loadCatalogue(docs string) ([]catCase, []function, error) {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(docs, name))
		if err != nil {
			return "", fmt.Errorf("cannot read the catalogue: %w (run from the repository's root, or give -docs)", err)
		}
		// A checkout on Windows may end lines with CR LF.
		return strings.ReplaceAll(string(b), "\r\n", "\n"), nil
	}
	ct, err := read("testbench-catalogue.md")
	if err != nil {
		return nil, nil, err
	}
	ft, err := read("testbench-functions.md")
	if err != nil {
		return nil, nil, err
	}
	cases, err := readCatalogue(ct)
	if err == nil && len(cases) == 0 {
		err = fmt.Errorf("testbench-catalogue.md has no cases")
	}
	if err != nil {
		return nil, nil, err
	}
	funcs, err := readFunctions(ft)
	if err == nil && len(funcs) == 0 {
		err = fmt.Errorf("testbench-functions.md has no functions")
	}
	if err != nil {
		return nil, nil, err
	}
	return cases, funcs, nil
}

// checkCatalogue finds what the two documents and the harness disagree on:
// a function naming a case that is not there, a case no function names, an
// automated case that is missing or claimed by an unknown suite.
func checkCatalogue(cases []catCase, funcs []function) []string {
	byID := map[string]catCase{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	named := map[string]bool{}
	var bad []string
	for _, f := range funcs {
		for _, id := range f.Cases {
			if _, ok := byID[id]; !ok {
				bad = append(bad, fmt.Sprintf("function %s names case %s, which the catalogue does not have", f.ID, id))
			}
			named[id] = true
		}
	}
	for _, c := range cases {
		if !named[c.ID] {
			bad = append(bad, fmt.Sprintf("no function names case %s", c.ID))
		}
	}
	known := map[string]bool{"ci": true}
	for _, s := range suites {
		known[s] = true
	}
	for id, ss := range automated {
		if _, ok := byID[id]; !ok {
			bad = append(bad, fmt.Sprintf("the harness runs case %s, which the catalogue does not have", id))
		}
		for _, s := range ss {
			if !known[s] {
				bad = append(bad, fmt.Sprintf("case %s: unknown suite %q", id, s))
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// tally counts one area's functions or cases.
type tally struct{ all, covered, auto, run int }

func (t *tally) add(o tally) {
	t.all += o.all
	t.covered += o.covered
	t.auto += o.auto
	t.run += o.run
}

// Coverage prints, by area, how many functions have a case, how many of them
// a case that runs without a person, and how many a case the harness runs
// today; then the same for the cases, and what is left.
func Coverage(w io.Writer, docs string) error {
	cases, funcs, err := loadCatalogue(docs)
	if err != nil {
		return err
	}
	if bad := checkCatalogue(cases, funcs); len(bad) > 0 {
		return fmt.Errorf("the catalogue does not hold together:\n  %s", strings.Join(bad, "\n  "))
	}
	byID := map[string]catCase{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	area := func(id string) string { return id[:1] }
	var order []string
	fa, ca := map[string]*tally{}, map[string]*tally{}
	for _, f := range funcs {
		a := area(f.ID)
		if fa[a] == nil {
			fa[a], ca[a] = &tally{}, &tally{}
			order = append(order, a)
		}
		t := tally{all: 1}
		for _, id := range f.Cases {
			c := byID[id]
			t.covered = 1
			if c.automatic() {
				t.auto = 1
			}
			if automated[id] != nil {
				t.run = 1
			}
		}
		fa[a].add(t)
	}
	var uncovered []string
	for _, f := range funcs {
		if len(f.Cases) == 0 {
			uncovered = append(uncovered, f.ID+" "+f.What)
		}
	}
	needs := map[string][]string{}
	var person []string
	for _, c := range cases {
		a := area(c.ID)
		if ca[a] == nil {
			ca[a], fa[a] = &tally{}, &tally{}
			order = append(order, a)
		}
		t := tally{all: 1, covered: 1}
		if c.automatic() {
			t.auto = 1
		} else {
			person = append(person, c.ID)
		}
		if automated[c.ID] != nil {
			t.run = 1
		}
		ca[a].add(t)
		for _, n := range c.Needs {
			needs[n] = append(needs[n], c.ID)
		}
	}
	fmt.Fprintf(w, "%-4s %28s   %s\n", "", "functions", "cases")
	fmt.Fprintf(w, "%-4s %6s %7s %6s %6s   %5s %6s %5s\n", "area", "all", "a case", "auto", "run", "all", "auto", "run")
	var ft, ct tally
	for _, a := range order {
		f, c := fa[a], ca[a]
		ft.add(*f)
		ct.add(*c)
		fmt.Fprintf(w, "%-4s %6d %7d %6d %6d   %5d %6d %5d\n", a, f.all, f.covered, f.auto, f.run, c.all, c.auto, c.run)
	}
	fmt.Fprintf(w, "%-4s %6d %7d %6d %6d   %5d %6d %5d\n", "all", ft.all, ft.covered, ft.auto, ft.run, ct.all, ct.auto, ct.run)
	fmt.Fprintf(w, "\nfunctions with a case %.1f%%, with a case that runs by itself %.1f%%, run by the harness today %.1f%%\n",
		pct(ft.covered, ft.all), pct(ft.auto, ft.all), pct(ft.run, ft.all))
	fmt.Fprintf(w, "cases that run by themselves %.1f%%, run by the harness today %.1f%%\n", pct(ct.auto, ct.all), pct(ct.run, ct.all))
	if len(uncovered) > 0 {
		fmt.Fprintf(w, "\nfunctions without a case:\n  %s\n", strings.Join(uncovered, "\n  "))
	}
	if len(person) > 0 {
		fmt.Fprintf(w, "\nneed a person: %s\n", strings.Join(person, ", "))
	}
	if len(needs) > 0 {
		fmt.Fprintln(w, "\nwaiting for:")
		var ns []string
		for n := range needs {
			ns = append(ns, n)
		}
		sort.Strings(ns)
		for _, n := range ns {
			fmt.Fprintf(w, "  %s: %s\n", n, strings.Join(needs[n], ", "))
		}
	}
	var todo []string
	for _, c := range cases {
		if c.automatic() && len(c.Needs) == 0 && automated[c.ID] == nil {
			todo = append(todo, c.ID)
		}
	}
	if len(todo) > 0 {
		fmt.Fprintf(w, "\nready to automate (%d): %s\n", len(todo), strings.Join(todo, ", "))
	}
	return nil
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// allCoverage prints the coverage after "all", and keeps it beside the
// report.
func allCoverage(stdout, stderr io.Writer, docs, reportDir string) {
	var b strings.Builder
	if err := Coverage(&b, docs); err != nil {
		fmt.Fprintf(stderr, "bench: coverage: %v\n", err)
		return
	}
	fmt.Fprintf(stdout, "\n%s", b.String())
	if reportDir != "" {
		if err := os.WriteFile(filepath.Join(reportDir, "coverage.txt"), []byte(b.String()), 0o600); err != nil {
			fmt.Fprintf(stderr, "bench: %v\n", err)
		}
	}
}
