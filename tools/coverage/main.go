// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command coverage sums up the test coverage CI measures in each part of the
// project and holds it to the floors in floor.json, so it can rise but not
// fall:
//
//	go run ./tools/coverage -go a.out -go b.out -llvm rust-core=core.json \
//	    -llvm swift-kit=kit.json -jacoco kotlin-kit=kit.xml -floor tools/coverage/floor.json
//
// -go takes Go cover profiles (go test -coverprofile, go tool covdata
// textfmt); several are merged, a block counting as covered when any run
// covered it, so the runs on Linux, macOS and Windows, the desktop clipboards
// and the e2e add up. -llvm takes llvm-cov's JSON export (cargo llvm-cov
// --json, swift test --enable-code-coverage), -jacoco a JaCoCo XML report
// (Gradle's jacoco plugin). A part with no input is not measured and not
// checked, as when CI skipped its jobs.
//
// It counts lines in every part, and branches where the input has them
// (JaCoCo always, llvm-cov when the build counted them: Swift, and Rust on
// a nightly compiler with -Zcoverage-options=branch); Go counts statements
// only. A part's branches are the row "PART/branches", in the table and in
// floor.json.
//
// It prints a Markdown table, coverage by kind (for $GITHUB_STEP_SUMMARY
// with -summary), and exits 1 when a row falls more than -slack points
// below its floor. With -target (lines) and -branch-target (branches;
// -core-branch-target for the cores, whose every branch is a decision to
// take or refuse), the coverage the project aims at above the floors, a row
// below it is marked in the table and warned of (a GitHub annotation),
// without failing: the floor is where CI stops, the target where the tests
// are written up to again (plans of 0.6: lines 90, branches 80, a core's
// branches 90).
//
// Below the table are the hard gates, which have no floor and fail at once:
// -audit, every closed audit finding's tests still exist; -rules with
// -vectors, every rule a format reader names with Rule::field is refused by
// some vector (not measured until the 0.6 core's readers are in the tree);
// -mutants, cargo mutants left no survivor tools/mutants/missed.txt does not
// name.
// docs/testing.md, "Coverage", says what each part counts.
package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const module = "github.com/HunterEwok/cbb/"

// goParts are the parts measured from the Go profiles: a file counts in a
// part when its path in the module matches the part's test.
var goParts = []struct {
	name string
	in   func(rel string) bool
}{
	{"go", goProduct},
	{"go-core", func(rel string) bool {
		return goProduct(rel) && slices.Contains([]string{"internal/group", "internal/clip", "internal/hlc"}, path.Dir(rel))
	}},
}

// goProduct tells the service's own code: cmd and internal, without
// copied code and the fakes that only tests use.
func goProduct(rel string) bool {
	if !(strings.HasPrefix(rel, "cmd/") || strings.HasPrefix(rel, "internal/")) {
		return false
	}
	if strings.Contains(rel, "/third_party/") || strings.HasSuffix(rel, "_test.go") {
		return false
	}
	return !slices.Contains(testFakes, path.Dir(rel))
}

// testFakes are the packages that only tests use: servers, devices and
// networks played for them.
var testFakes = []string{
	"internal/attest/attesttest",
	"internal/blekeyboard/bluetest",
	"internal/ei/eitest",
	"internal/relay",
	"internal/testnet",
	"internal/tpmkey/tpmtest",
	"internal/tvremote/androidtv/atvtest",
	"internal/tvremote/appletv/atvtest",
	"internal/vless/vlesstest",
}

// llvmParts says which files of an llvm-cov export count for each part.
var llvmParts = map[string]func(file string) bool{
	"rust-core": func(f string) bool {
		return strings.Contains(f, "/core/src/") && !strings.Contains(f, "/third_party/") && !strings.Contains(f, "/tests/")
	},
	"rust-member": inMember,
	// rust-service is member/src again, measured with Go's tests of the
	// service run against the instrumented cbb as well (the service job).
	"rust-service": inMember,
	"swift-kit": func(f string) bool {
		return strings.Contains(f, "/CBBKit/Sources/")
	},
}

func inMember(f string) bool {
	return strings.Contains(f, "/member/src/") && !strings.Contains(f, "/tests/")
}

type tally struct{ total, covered int }

func (t tally) pct() float64 {
	if t.total == 0 {
		return 0
	}
	return 100 * float64(t.covered) / float64(t.total)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// corePart tells a part whose branches are held to -core-branch-target.
func corePart(part string) bool { return part == "rust-core" || part == "go-core" }

// branchesOf is the row of a part's branches.
func branchesOf(part string) string { return part + "/branches" }

// options are the command's flags.
type options struct {
	goFiles, llvmFiles, jacocoFiles []string
	floorFile                       string
	slack                           float64
	target                          float64 // lines
	branchTarget, coreBranchTarget  float64
	summary                         string
	audit, root                     string // the closed findings, and where their tests' paths start
	rules, vectors                  string // the readers' sources and the format's vectors
	mutants, knownMutants           string // cargo mutants' missed.txt and the known list
}

func main() {
	var o options
	var goFiles, llvmFiles, jacocoFiles multi
	flag.Var(&goFiles, "go", "a Go cover profile (repeatable)")
	flag.Var(&llvmFiles, "llvm", "PART=FILE, llvm-cov's JSON export (repeatable)")
	flag.Var(&jacocoFiles, "jacoco", "PART=FILE, a JaCoCo XML report (repeatable)")
	flag.StringVar(&o.floorFile, "floor", "", "the floors, a JSON object of row (PART or PART/branches) to percent")
	flag.Float64Var(&o.slack, "slack", 1, "how many points a row may fall below its floor")
	flag.Float64Var(&o.target, "target", 0, "the line coverage aimed at above the floors: a part below it is warned of, not failed")
	flag.Float64Var(&o.branchTarget, "branch-target", 0, "the branch coverage aimed at, as -target")
	flag.Float64Var(&o.coreBranchTarget, "core-branch-target", 0, "the branch coverage aimed at in the cores (rust-core, go-core); 0 takes -branch-target")
	flag.StringVar(&o.summary, "summary", "", "also append the table to this file")
	flag.StringVar(&o.audit, "audit", "", "the closed audit findings and their tests (testdata/audit/closed.json): fail when a test is gone")
	flag.StringVar(&o.root, "root", ".", "the repository, where -audit's test paths start")
	flag.StringVar(&o.rules, "rules", "", "the format readers' Rust sources (core/src): with -vectors, fail when a rule named by Rule::field has no refused vector")
	flag.StringVar(&o.vectors, "vectors", "", "the format's vectors (testdata/format)")
	flag.StringVar(&o.mutants, "mutants", "", "cargo mutants' missed.txt: with -known-mutants, fail on a survivor the list does not name")
	flag.StringVar(&o.knownMutants, "known-mutants", "tools/mutants/missed.txt", "the survivors the tests do not catch yet, each with why")
	flag.Parse()
	o.goFiles, o.llvmFiles, o.jacocoFiles = goFiles, llvmFiles, jacocoFiles
	if err := run(o, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "coverage:", err)
		os.Exit(1)
	}
}

// targetOf is the target of a row: lines, branches, or a core's branches.
func (o options) targetOf(row string) float64 {
	part, isBranches := strings.CutSuffix(row, "/branches")
	switch {
	case !isBranches:
		return o.target
	case corePart(part) && o.coreBranchTarget > 0:
		return o.coreBranchTarget
	}
	return o.branchTarget
}

func run(o options, stdout io.Writer) error {
	goFiles, llvmFiles, jacocoFiles, floorFile, summary := o.goFiles, o.llvmFiles, o.jacocoFiles, o.floorFile, o.summary
	parts := map[string]tally{}
	var packages map[string]tally
	if len(goFiles) > 0 {
		blocks := map[string]block{}
		for _, f := range goFiles {
			if err := readGoProfile(f, blocks); err != nil {
				return err
			}
		}
		var goTallies map[string]tally
		goTallies, packages = sumGo(blocks)
		for k, v := range goTallies {
			parts[k] = v
		}
	}
	for _, arg := range llvmFiles {
		part, file, ok := strings.Cut(arg, "=")
		in := llvmParts[part]
		if !ok || in == nil {
			return fmt.Errorf("-llvm %q: want PART=FILE with PART one of %s", arg, keys(llvmParts))
		}
		t, br, err := readLLVM(file, in)
		if err != nil {
			return err
		}
		parts[part] = add(parts[part], t)
		if br.total > 0 {
			parts[branchesOf(part)] = add(parts[branchesOf(part)], br)
		}
	}
	for _, arg := range jacocoFiles {
		part, file, ok := strings.Cut(arg, "=")
		if !ok {
			return fmt.Errorf("-jacoco %q: want PART=FILE", arg)
		}
		t, br, err := readJaCoCo(file)
		if err != nil {
			return err
		}
		parts[part] = add(parts[part], t)
		if br.total > 0 {
			parts[branchesOf(part)] = add(parts[branchesOf(part)], br)
		}
	}
	floors := map[string]float64{}
	if floorFile != "" {
		b, err := os.ReadFile(floorFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &floors); err != nil {
			return fmt.Errorf("%s: %w", floorFile, err)
		}
	}
	text, failed, short := report(parts, packages, floors, o)
	gates, err := runGates(o)
	if err != nil {
		return err
	}
	text += gatesReport(gates)
	for _, g := range gates {
		if g.failed() {
			failed = append(failed, fmt.Sprintf("%s %d/%d", g.name, g.met, g.of))
		}
	}
	fmt.Fprint(stdout, text)
	for _, s := range short {
		fmt.Fprintf(stdout, "::warning title=coverage below the target::%s\n", s)
	}
	if summary != "" {
		f, err := os.OpenFile(summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, err = f.WriteString(text)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("below the floor or a gate: %s", strings.Join(failed, ", "))
	}
	return nil
}

// runGates checks the gates whose inputs are given.
func runGates(o options) ([]gate, error) {
	var gates []gate
	if o.audit != "" {
		g, err := auditGate(o.audit, o.root)
		if err != nil {
			return nil, err
		}
		gates = append(gates, g)
	}
	if o.rules != "" || o.vectors != "" {
		if o.rules == "" || o.vectors == "" {
			return nil, errors.New("-rules and -vectors go together")
		}
		g, err := formatGate(o.rules, o.vectors)
		if err != nil {
			return nil, err
		}
		gates = append(gates, g)
	}
	if o.mutants != "" {
		g, err := mutantsGate(o.mutants, o.knownMutants)
		if err != nil {
			return nil, err
		}
		gates = append(gates, g)
	}
	return gates, nil
}

func add(a, b tally) tally { return tally{a.total + b.total, a.covered + b.covered} }

func keys[V any](m map[string]V) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}

// A block of a Go profile: its statements, and whether any run covered it.
type block struct {
	stmts   int
	covered bool
}

// readGoProfile adds a profile's blocks to blocks, keyed by file and range.
// go test -coverpkg repeats a block once per test binary; the block is
// counted once, covered when any of them covered it.
func readGoProfile(name string, blocks map[string]block) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if line == 1 && strings.HasPrefix(s, "mode:") || s == "" {
			continue
		}
		// file.go:12.3,14.5 2 1
		pos, rest, ok := strings.Cut(s, " ")
		stmtsField, countField, ok2 := strings.Cut(rest, " ")
		if !ok || !ok2 {
			return fmt.Errorf("%s:%d: not a profile line: %q", name, line, s)
		}
		stmts, err1 := strconv.Atoi(stmtsField)
		count, err2 := strconv.ParseInt(countField, 10, 64)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%s:%d: not a profile line: %q", name, line, s)
		}
		b := blocks[pos]
		b.stmts = stmts
		b.covered = b.covered || count > 0
		blocks[pos] = b
	}
	return sc.Err()
}

// sumGo counts the statements of each Go part and of each package of the
// product.
func sumGo(blocks map[string]block) (parts, packages map[string]tally) {
	parts = map[string]tally{}
	packages = map[string]tally{}
	for pos, b := range blocks {
		file, _, _ := strings.Cut(pos, ":")
		rel := strings.TrimPrefix(file, module)
		if rel == file {
			continue
		}
		t := tally{total: b.stmts}
		if b.covered {
			t.covered = b.stmts
		}
		for _, p := range goParts {
			if p.in(rel) {
				parts[p.name] = add(parts[p.name], t)
			}
		}
		if goProduct(rel) {
			packages[path.Dir(rel)] = add(packages[path.Dir(rel)], t)
		}
	}
	return parts, packages
}

// readLLVM sums the lines and the branches of the files of an llvm-cov
// JSON export that in accepts; the branches are none when the build did
// not count them.
func readLLVM(name string, in func(string) bool) (lines, branches tally, err error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return tally{}, tally{}, err
	}
	var export struct {
		Data []struct {
			Files []struct {
				Filename string `json:"filename"`
				Summary  struct {
					Lines    llvmCount `json:"lines"`
					Branches llvmCount `json:"branches"`
				} `json:"summary"`
			} `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &export); err != nil {
		return tally{}, tally{}, fmt.Errorf("%s: %w", name, err)
	}
	for _, d := range export.Data {
		for _, f := range d.Files {
			if in(f.Filename) {
				lines = add(lines, tally{f.Summary.Lines.Count, f.Summary.Lines.Covered})
				branches = add(branches, tally{f.Summary.Branches.Count, f.Summary.Branches.Covered})
			}
		}
	}
	if lines.total == 0 {
		return lines, branches, fmt.Errorf("%s: no file of the part", name)
	}
	return lines, branches, nil
}

type llvmCount struct {
	Count   int `json:"count"`
	Covered int `json:"covered"`
}

// readJaCoCo takes the lines and the branches of a JaCoCo XML report's own
// totals.
func readJaCoCo(name string) (lines, branches tally, err error) {
	f, err := os.Open(name)
	if err != nil {
		return tally{}, tally{}, err
	}
	defer f.Close()
	d := xml.NewDecoder(f)
	d.Strict = false
	depth := 0
	found := false
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			if !found {
				return tally{}, tally{}, fmt.Errorf("%s: no line counter for the report", name)
			}
			return lines, branches, nil
		}
		if err != nil {
			return tally{}, tally{}, fmt.Errorf("%s: %w", name, err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			depth++
			// The report's own counters are its direct children.
			if depth != 2 || e.Name.Local != "counter" {
				continue
			}
			typ := attr(e, "type")
			if typ != "LINE" && typ != "BRANCH" {
				continue
			}
			missed, err1 := strconv.Atoi(attr(e, "missed"))
			covered, err2 := strconv.Atoi(attr(e, "covered"))
			if err1 != nil || err2 != nil {
				return tally{}, tally{}, fmt.Errorf("%s: a bad %s counter", name, strings.ToLower(typ))
			}
			if typ == "LINE" {
				lines, found = tally{missed + covered, covered}, true
			} else {
				branches = tally{missed + covered, covered}
			}
		case xml.EndElement:
			depth--
		}
	}
}

func attr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// report writes the table of parts and, for Go, of packages; failed names
// the parts more than slack points below their floor, short those above it
// but below target (when target is set).
func report(parts, packages map[string]tally, floors map[string]float64, o options) (string, []string, []string) {
	slack := o.slack
	var b strings.Builder
	var failed, short []string
	b.WriteString("## Test coverage by kind\n\n| Part | Kind | Covered | Of | % | Floor | Target | |\n|---|---|---:|---:|---:|---:|---:|---|\n")
	names := make([]string, 0, len(parts))
	for k := range parts {
		names = append(names, k)
	}
	for k := range floors {
		if _, ok := parts[k]; !ok {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		target := o.targetOf(n)
		part, kind := n, "lines"
		if p, ok := strings.CutSuffix(n, "/branches"); ok {
			part, kind = p, "branches"
		}
		t, measured := parts[n]
		floor, hasFloor := floors[n]
		floorText, targetText, verdict := "-", "-", ""
		if hasFloor {
			floorText = fmt.Sprintf("%.1f", floor)
		}
		if target > 0 {
			targetText = fmt.Sprintf("%.0f", target)
		}
		switch {
		case !measured:
			fmt.Fprintf(&b, "| %s | %s | | | not measured | %s | %s | |\n", part, kind, floorText, targetText)
			continue
		case hasFloor && t.pct() < floor-slack:
			verdict = "below the floor"
			failed = append(failed, fmt.Sprintf("%s %.1f%% < %.1f%%", n, t.pct(), floor))
		case target > 0 && t.pct() < target:
			verdict = fmt.Sprintf("below the target of %.0f", target)
			short = append(short, fmt.Sprintf("%s %.1f%% < %.0f%%", n, t.pct(), target))
		case target > 0:
			verdict = "ok"
		case hasFloor && t.pct() >= floor+2:
			verdict = fmt.Sprintf("raise the floor to %.1f", math.Floor(t.pct()*10)/10)
		case hasFloor:
			verdict = "ok"
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %.1f | %s | %s | %s |\n", part, kind, t.covered, t.total, t.pct(), floorText, targetText, verdict)
	}
	if len(packages) > 0 {
		b.WriteString("\n<details><summary>Go packages, least covered first</summary>\n\n| Package | Statements | % |\n|---|---:|---:|\n")
		pkgs := make([]string, 0, len(packages))
		for k := range packages {
			pkgs = append(pkgs, k)
		}
		sort.Slice(pkgs, func(i, j int) bool {
			pi, pj := packages[pkgs[i]].pct(), packages[pkgs[j]].pct()
			if pi != pj {
				return pi < pj
			}
			return pkgs[i] < pkgs[j]
		})
		for _, p := range pkgs {
			fmt.Fprintf(&b, "| %s | %d | %.1f |\n", p, packages[p].total, packages[p].pct())
		}
		b.WriteString("\n</details>\n")
	}
	return b.String(), failed, short
}
