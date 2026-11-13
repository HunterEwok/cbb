// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every test is in exactly one part, whatever the durations, the number of
// parts and the tests the durations file does not know.
func TestEachTestInOnePart(t *testing.T) {
	var tests []string
	known := map[string]float64{}
	for i := range 157 {
		name := fmt.Sprintf("Test%03d", i)
		tests = append(tests, name)
		if i%5 != 0 {
			known[name] = float64((i * 37) % 120)
		}
	}
	for n := 1; n <= 10; n++ {
		seen := map[string]int{}
		for _, p := range split(tests, known, n) {
			re := regexp.MustCompile(runExpr(p))
			for _, name := range tests {
				if re.MatchString(name) {
					seen[name]++
				}
			}
		}
		for _, name := range tests {
			if seen[name] != 1 {
				t.Fatalf("%d parts: %s runs in %d parts", n, name, seen[name])
			}
		}
	}
}

// The parts come out about the same length: no part is longer than the
// mean plus the longest test.
func TestPartsAreBalanced(t *testing.T) {
	known := map[string]float64{"TestLong": 120}
	tests := []string{"TestLong"}
	total := 120.0
	for i := range 100 {
		name := fmt.Sprintf("TestShort%02d", i)
		tests = append(tests, name)
		known[name] = float64(5 + i%20)
		total += known[name]
	}
	parts := split(tests, known, 6)
	for i, p := range parts {
		sum := 0.0
		for _, name := range p {
			sum += known[name]
		}
		if sum > total/6+120 {
			t.Errorf("part %d takes %.0f s, the mean is %.0f s", i+1, sum, total/6)
		}
	}
}

// The split does not depend on the order of the input, so that every job
// computes the same parts.
func TestSplitIgnoresOrder(t *testing.T) {
	tests := []string{"TestA", "TestB", "TestC", "TestD", "TestE"}
	known := map[string]float64{"TestA": 3, "TestB": 3, "TestC": 1, "TestD": 7}
	want := split(tests, known, 2)
	rev := slices.Clone(tests)
	slices.Reverse(rev)
	if got := split(rev, known, 2); !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("reversed input: %v, want %v", got, want)
	}
}

// More parts than tests leave some parts empty, which match nothing.
func TestEmptyPart(t *testing.T) {
	parts := split([]string{"TestOnly"}, nil, 3)
	if runExpr(parts[0]) != "^(TestOnly)$" || runExpr(parts[1]) != "^$" || runExpr(parts[2]) != "^$" {
		t.Fatalf("parts %v", parts)
	}
}

func TestReadTests(t *testing.T) {
	got, err := readTests(strings.NewReader("TestA\nBenchmarkB\nTestA\nok  \tgithub.com/x\t0.1s\n\nExampleC\n"))
	if err != nil || !slices.Equal(got, []string{"TestA", "BenchmarkB", "ExampleC"}) {
		t.Fatalf("readTests: %v, %v", got, err)
	}
}

func TestReadDurationsRefusesBadLines(t *testing.T) {
	for _, in := range []string{"TestA", "TestA x", "TestA -1", "notatest 3", "TestA 1 2"} {
		if _, err := readDurations(strings.NewReader(in)); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
	d, err := readDurations(strings.NewReader("# comment\n\nTestA 1.5\n"))
	if err != nil || d["TestA"] != 1.5 {
		t.Fatalf("readDurations: %v, %v", d, err)
	}
}

// -record takes the top-level tests' lines of go test -v, from a plain run
// or a log GitHub stamped with times, a skipped test's too, skips subtests,
// and
// keeps what the file knew of other tests.
func TestRecord(t *testing.T) {
	file := filepath.Join(t.TempDir(), "d.txt")
	if err := os.WriteFile(file, []byte("TestOld 9.0\nTestA 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := strings.Join([]string{
		"=== RUN   TestA",
		"--- PASS: TestA (12.34s)",
		"    --- PASS: TestA/sub (3.00s)",
		"2026-11-12T08:43:15.3498313Z --- FAIL: TestB (2.50s)",
		"2026-11-12T08:43:15.3498313Z     --- PASS: TestB/x (1.00s)",
		"--- SKIP: TestC (0.00s)",
		"PASS",
	}, "\n")
	if err := recordDurations(strings.NewReader(log), file); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	d, err := readDurations(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{"TestA": 12.3, "TestB": 2.5, "TestOld": 9, "TestC": 0}
	if len(d) != len(want) {
		t.Fatalf("recorded %v, want %v", d, want)
	}
	for k, v := range want {
		if d[k] != v {
			t.Fatalf("recorded %v, want %v", d, want)
		}
	}
	if err := recordDurations(strings.NewReader("PASS\n"), file); err == nil {
		t.Fatal("no error for a log without tests")
	}
}
