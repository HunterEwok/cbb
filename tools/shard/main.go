// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command shard splits a Go package's tests into parts of about the same
// length, so that CI's jobs and local containers run the parts at the same
// time (docs/testing.md, "Running tests in parallel"):
//
//	./service.test -test.list . | go run ./tools/shard -n 6 -i 2 -durations tools/shard/service.txt
//
// It reads the test names on standard input, one per line as -test.list
// prints them, and prints the -test.run expression of part -i (1 to -n),
// such as ^(TestA|TestB)$. Each test is in exactly one part, a new test
// included: the parts are filled longest test first, each into the part
// with the least time so far, from the durations file's seconds ("TestName
// 12.3" per line); a test the file does not name counts as the median of
// those it does. Every part is computed from the same names and file, so
// the jobs agree without talking to each other.
//
// With -record FILE it reads a run's go test -v output on standard input
// and writes the durations of its top-level tests to FILE (a skipped
// test's too, which took no time there), sorted by name,
// keeping the file's other tests: what a full run measured becomes the next
// split.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

func main() {
	n := flag.Int("n", 0, "the number of parts")
	i := flag.Int("i", 0, "the part to print, 1 to -n")
	durations := flag.String("durations", "", "the tests' durations, \"TestName seconds\" per line")
	record := flag.String("record", "", "read go test -v output and write the top-level tests' durations to this file")
	flag.Parse()
	if *record != "" {
		if err := recordDurations(os.Stdin, *record); err != nil {
			fmt.Fprintln(os.Stderr, "shard:", err)
			os.Exit(1)
		}
		return
	}
	if *n < 1 || *i < 1 || *i > *n {
		fmt.Fprintln(os.Stderr, "shard: -n must be 1 or more and -i from 1 to -n")
		os.Exit(2)
	}
	known := map[string]float64{}
	if *durations != "" {
		f, err := os.Open(*durations)
		if err != nil {
			fmt.Fprintln(os.Stderr, "shard:", err)
			os.Exit(1)
		}
		known, err = readDurations(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "shard:", *durations+":", err)
			os.Exit(1)
		}
	}
	tests, err := readTests(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shard:", err)
		os.Exit(1)
	}
	if len(tests) == 0 {
		fmt.Fprintln(os.Stderr, "shard: no test names on standard input")
		os.Exit(1)
	}
	fmt.Println(runExpr(split(tests, known, *n)[*i-1]))
}

// testName is a top-level test, benchmark, fuzz test or example as
// -test.list prints it.
var testName = regexp.MustCompile(`^(Test|Benchmark|Fuzz|Example)[A-Za-z0-9_]*$`)

// readTests reads the test names -test.list prints, skipping its other lines
// (go test's "ok" line and empty ones).
func readTests(r io.Reader) ([]string, error) {
	var tests []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if testName.MatchString(name) && !seen[name] {
			seen[name] = true
			tests = append(tests, name)
		}
	}
	return tests, sc.Err()
}

// readDurations reads "TestName seconds" lines; blank lines and lines that
// start with # are skipped.
func readDurations(r io.Reader) (map[string]float64, error) {
	d := map[string]float64{}
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		f := strings.Fields(text)
		if len(f) != 2 || !testName.MatchString(f[0]) {
			return nil, fmt.Errorf("line %d: want \"TestName seconds\", got %q", line, text)
		}
		s, err := strconv.ParseFloat(f[1], 64)
		if err != nil || s < 0 {
			return nil, fmt.Errorf("line %d: %q is not a number of seconds", line, f[1])
		}
		d[f[0]] = s
	}
	return d, sc.Err()
}

// split puts each test into one of n parts: longest first (by name when two
// take as long), each into the part with the least time so far (the first
// such part on a tie). A test without a duration counts as the median of
// the known ones, or 1 s when none is known.
func split(tests []string, known map[string]float64, n int) [][]string {
	var ds []float64
	for _, t := range tests {
		if d, ok := known[t]; ok {
			ds = append(ds, d)
		}
	}
	guess := 1.0
	if len(ds) > 0 {
		slices.Sort(ds)
		guess = ds[len(ds)/2]
	}
	type test struct {
		name string
		d    float64
	}
	all := make([]test, 0, len(tests))
	for _, t := range tests {
		d, ok := known[t]
		if !ok {
			d = guess
		}
		all = append(all, test{t, d})
	}
	sort.Slice(all, func(a, b int) bool {
		if all[a].d != all[b].d {
			return all[a].d > all[b].d
		}
		return all[a].name < all[b].name
	})
	parts := make([][]string, n)
	load := make([]float64, n)
	for _, t := range all {
		p := 0
		for q := 1; q < n; q++ {
			if load[q] < load[p] {
				p = q
			}
		}
		parts[p] = append(parts[p], t.name)
		load[p] += t.d
	}
	for _, p := range parts {
		slices.Sort(p)
	}
	return parts
}

// runExpr is the -test.run expression that matches exactly these top-level
// tests; ^$ matches none, for a part left empty.
func runExpr(tests []string) string {
	if len(tests) == 0 {
		return "^$"
	}
	return "^(" + strings.Join(tests, "|") + ")$"
}

// result is go test -v's line for a finished top-level test; a subtest's
// line is indented.
var result = regexp.MustCompile(`^--- (PASS|FAIL|SKIP): ((?:Test|Benchmark|Fuzz|Example)[A-Za-z0-9_]*) \(([0-9.]+)s\)`)

// recordDurations writes the durations of the top-level tests go test -v
// printed on r into file, merged with the tests file already names.
func recordDurations(r io.Reader, file string) error {
	d := map[string]float64{}
	if f, err := os.Open(file); err == nil {
		d, err = readDurations(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	found := 0
	for sc.Scan() {
		// GitHub's downloaded logs put a time before each line.
		line := sc.Text()
		if k := strings.Index(line, "--- "); k > 0 {
			if stamp := strings.TrimSpace(line[:k]); stamp != "" && !strings.ContainsAny(stamp, " \t") {
				line = line[k:]
			}
		}
		m := result.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s, _ := strconv.ParseFloat(m[3], 64)
		d[m[2]] = s
		found++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("no finished top-level test in the input")
	}
	names := make([]string, 0, len(d))
	for t := range d {
		names = append(names, t)
	}
	slices.Sort(names)
	var b strings.Builder
	b.WriteString("# Seconds each test took in a full run, for tools/shard (go run ./tools/shard -record).\n")
	for _, t := range names {
		fmt.Fprintf(&b, "%s %s\n", t, strconv.FormatFloat(d[t], 'f', 1, 64))
	}
	return os.WriteFile(file, []byte(b.String()), 0o644)
}
