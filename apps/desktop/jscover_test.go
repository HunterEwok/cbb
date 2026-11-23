// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

// The coverage of the window's scripts under TestWindow: with
// CBB_JS_COVERAGE naming a file, the browser counts what runs of
// frontend/'s scripts (V8's precise coverage, over the DevTools protocol),
// and the test writes it there as LCOV, for tools/coverage's row js-tray
// (docs/testing.md, "Coverage").

// jsCoverage gathers the lines of frontend/'s scripts that ran, by path,
// over the pages the test loads.
type jsCoverage struct {
	file  string
	lines map[string]map[int]bool // path → code line → ran
}

// v8Coverage is what Profiler.takePreciseCoverage gives.
type v8Coverage struct {
	Result []struct {
		URL       string `json:"url"`
		Functions []struct {
			Ranges []v8Range `json:"ranges"`
		} `json:"functions"`
	} `json:"result"`
}

type v8Range struct {
	Start int `json:"startOffset"`
	End   int `json:"endOffset"`
	Count int `json:"count"`
}

// startJSCoverage starts the counting when CBB_JS_COVERAGE is set, and
// writes what it gathered when the test ends.
func startJSCoverage(t *testing.T, page *cdpPage) *jsCoverage {
	file := os.Getenv("CBB_JS_COVERAGE")
	if file == "" {
		return nil
	}
	page.call(t, "Profiler.enable", nil, nil)
	page.call(t, "Profiler.startPreciseCoverage", map[string]any{"callCount": true, "detailed": true}, nil)
	c := &jsCoverage{file: file, lines: map[string]map[int]bool{}}
	t.Cleanup(func() {
		c.take(t, page)
		if err := c.write(); err != nil {
			t.Errorf("the scripts' coverage: %v", err)
		}
	})
	return c
}

// take adds what ran since the last take: a page that is left takes its
// counts with it.
func (c *jsCoverage) take(t *testing.T, page *cdpPage) {
	if c == nil {
		return
	}
	var cov v8Coverage
	if err := page.do("Profiler.takePreciseCoverage", nil, &cov); err != nil {
		t.Errorf("the scripts' coverage: %v", err)
		return
	}
	for _, s := range cov.Result {
		u, err := url.Parse(s.URL)
		if err != nil || !strings.HasSuffix(u.Path, ".js") || strings.HasPrefix(u.Path, "/wails/") {
			continue
		}
		path := filepath.Join("frontend", filepath.FromSlash(strings.TrimPrefix(u.Path, "/")))
		src, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("the scripts' coverage: %v", err)
			continue
		}
		var ranges []v8Range
		for _, f := range s.Functions {
			ranges = append(ranges, f.Ranges...)
		}
		ran := linesRun(string(src), ranges)
		seen := c.lines[path]
		if seen == nil {
			seen = map[int]bool{}
			c.lines[path] = seen
		}
		for line, r := range ran {
			seen[line] = seen[line] || r
		}
	}
}

// linesRun tells, for each line of code in src (from 1), whether it ran:
// whether the innermost range around its first character counted more
// than nothing. V8's offsets count UTF-16 units. A line of code holds more
// than a comment or closing brackets.
func linesRun(src string, ranges []v8Range) map[int]bool {
	units := utf16.Encode([]rune(src))
	count := make([]int, len(units)+1)
	for i := range count {
		count[i] = -1
	}
	// Wider ranges first, so that the ranges inside them paint over them.
	sort.SliceStable(ranges, func(i, j int) bool { return ranges[i].End-ranges[i].Start > ranges[j].End-ranges[j].Start })
	for _, r := range ranges {
		for k := max(r.Start, 0); k < min(r.End, len(units)); k++ {
			count[k] = r.Count
		}
	}
	out := map[int]bool{}
	offset := 0
	for n, line := range strings.Split(src, "\n") {
		width := len(utf16.Encode([]rune(line)))
		code := strings.TrimSpace(line)
		if code != "" && !strings.HasPrefix(code, "//") && strings.Trim(code, "}]);, ") != "" {
			lead := len(utf16.Encode([]rune(line[:len(line)-len(strings.TrimLeft(line, " \t"))])))
			out[n+1] = count[offset+lead] > 0
		}
		offset += width + 1
	}
	return out
}

// write writes the gathered lines as LCOV, a record for each script.
func (c *jsCoverage) write() error {
	var b strings.Builder
	paths := make([]string, 0, len(c.lines))
	for p := range c.lines {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		lines := make([]int, 0, len(c.lines[p]))
		for l := range c.lines[p] {
			lines = append(lines, l)
		}
		sort.Ints(lines)
		hit := 0
		fmt.Fprintf(&b, "TN:\nSF:apps/desktop/%s\n", filepath.ToSlash(p))
		for _, l := range lines {
			n := 0
			if c.lines[p][l] {
				n, hit = 1, hit+1
			}
			fmt.Fprintf(&b, "DA:%d,%d\n", l, n)
		}
		fmt.Fprintf(&b, "LF:%d\nLH:%d\nend_of_record\n", len(lines), hit)
	}
	return os.WriteFile(c.file, []byte(b.String()), 0o644)
}

// TestLinesRun checks how the ranges V8 counts become lines that ran.
func TestLinesRun(t *testing.T) {
	src := "let a = 1;\n// a comment\nfunction f() {\n  return \"é\";\n}\nif (a) {\n  g();\n}\n"
	fn := strings.Index(src, "function")
	ifBody := strings.Index(src, "{\n  g")
	got := linesRun(src, []v8Range{
		{Start: 0, End: len(utf16.Encode([]rune(src))), Count: 1},
		{Start: fn, End: strings.Index(src, "}\nif") + 1, Count: 0},
		// After the "é", whose UTF-16 offset is one less than its UTF-8 one.
		{Start: ifBody - 1, End: ifBody - 1 + len("{\n  g();\n}"), Count: 3},
	})
	want := map[int]bool{1: true, 3: false, 4: false, 6: true, 7: true}
	if len(got) != len(want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	for l, w := range want {
		if got[l] != w {
			t.Errorf("line %d ran %v, want %v (all: %v)", l, got[l], w, got)
		}
	}
}
