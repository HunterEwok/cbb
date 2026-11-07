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
// It prints a Markdown table (for $GITHUB_STEP_SUMMARY with -summary) and
// exits 1 when a part falls more than -slack points below its floor.
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
		return goProduct(rel) && slices.Contains([]string{"internal/group", "internal/pair", "internal/node", "internal/clip", "internal/hlc"}, path.Dir(rel))
	}},
}

// goProduct tells the service's own code: cmd, internal and mobile, without
// copied code and the fakes that only tests use.
func goProduct(rel string) bool {
	if !(strings.HasPrefix(rel, "cmd/") || strings.HasPrefix(rel, "internal/") || strings.HasPrefix(rel, "mobile/")) {
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
	"rust-lite": func(f string) bool {
		return strings.Contains(f, "/member/src/") && !strings.Contains(f, "/tests/")
	},
	"swift-kit": func(f string) bool {
		return strings.Contains(f, "/CBBKit/Sources/")
	},
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

func main() {
	var goFiles, llvmFiles, jacocoFiles multi
	flag.Var(&goFiles, "go", "a Go cover profile (repeatable)")
	flag.Var(&llvmFiles, "llvm", "PART=FILE, llvm-cov's JSON export (repeatable)")
	flag.Var(&jacocoFiles, "jacoco", "PART=FILE, a JaCoCo XML report (repeatable)")
	floorFile := flag.String("floor", "", "the floors, a JSON object of part to percent")
	slack := flag.Float64("slack", 1, "how many points a part may fall below its floor")
	summary := flag.String("summary", "", "also append the table to this file")
	flag.Parse()
	if err := run(goFiles, llvmFiles, jacocoFiles, *floorFile, *slack, *summary, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "coverage:", err)
		os.Exit(1)
	}
}

func run(goFiles, llvmFiles, jacocoFiles []string, floorFile string, slack float64, summary string, stdout io.Writer) error {
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
		t, err := readLLVM(file, in)
		if err != nil {
			return err
		}
		parts[part] = add(parts[part], t)
	}
	for _, arg := range jacocoFiles {
		part, file, ok := strings.Cut(arg, "=")
		if !ok {
			return fmt.Errorf("-jacoco %q: want PART=FILE", arg)
		}
		t, err := readJaCoCo(file)
		if err != nil {
			return err
		}
		parts[part] = add(parts[part], t)
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
	text, failed := report(parts, packages, floors, slack)
	fmt.Fprint(stdout, text)
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
		return fmt.Errorf("below the floor: %s", strings.Join(failed, ", "))
	}
	return nil
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

// readLLVM sums the lines of the files of an llvm-cov JSON export that in
// accepts.
func readLLVM(name string, in func(string) bool) (tally, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return tally{}, err
	}
	var export struct {
		Data []struct {
			Files []struct {
				Filename string `json:"filename"`
				Summary  struct {
					Lines struct {
						Count   int `json:"count"`
						Covered int `json:"covered"`
					} `json:"lines"`
				} `json:"summary"`
			} `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &export); err != nil {
		return tally{}, fmt.Errorf("%s: %w", name, err)
	}
	var t tally
	for _, d := range export.Data {
		for _, f := range d.Files {
			if in(f.Filename) {
				t = add(t, tally{f.Summary.Lines.Count, f.Summary.Lines.Covered})
			}
		}
	}
	if t.total == 0 {
		return t, fmt.Errorf("%s: no file of the part", name)
	}
	return t, nil
}

// readJaCoCo takes the lines of a JaCoCo XML report's own totals.
func readJaCoCo(name string) (tally, error) {
	f, err := os.Open(name)
	if err != nil {
		return tally{}, err
	}
	defer f.Close()
	d := xml.NewDecoder(f)
	d.Strict = false
	depth := 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return tally{}, fmt.Errorf("%s: no line counter for the report", name)
		}
		if err != nil {
			return tally{}, fmt.Errorf("%s: %w", name, err)
		}
		switch e := tok.(type) {
		case xml.StartElement:
			depth++
			// The report's own counters are its direct children.
			if depth == 2 && e.Name.Local == "counter" && attr(e, "type") == "LINE" {
				missed, err1 := strconv.Atoi(attr(e, "missed"))
				covered, err2 := strconv.Atoi(attr(e, "covered"))
				if err1 != nil || err2 != nil {
					return tally{}, fmt.Errorf("%s: a bad line counter", name)
				}
				return tally{missed + covered, covered}, nil
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
// the parts more than slack points below their floor.
func report(parts, packages map[string]tally, floors map[string]float64, slack float64) (string, []string) {
	var b strings.Builder
	var failed []string
	b.WriteString("## Test coverage\n\n| Part | Covered | Of | % | Floor | |\n|---|---:|---:|---:|---:|---|\n")
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
		t, measured := parts[n]
		floor, hasFloor := floors[n]
		floorText, verdict := "-", ""
		if hasFloor {
			floorText = fmt.Sprintf("%.1f", floor)
		}
		switch {
		case !measured:
			fmt.Fprintf(&b, "| %s | | | not measured | %s | |\n", n, floorText)
			continue
		case hasFloor && t.pct() < floor-slack:
			verdict = "below the floor"
			failed = append(failed, fmt.Sprintf("%s %.1f%% < %.1f%%", n, t.pct(), floor))
		case hasFloor && t.pct() >= floor+2:
			verdict = fmt.Sprintf("raise the floor to %.1f", math.Floor(t.pct()*10)/10)
		case hasFloor:
			verdict = "ok"
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %.1f | %s | %s |\n", n, t.covered, t.total, t.pct(), floorText, verdict)
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
	return b.String(), failed
}
