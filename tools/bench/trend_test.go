// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlaky(t *testing.T) {
	r := NewReport("fleet", io.Discard, false)
	results := map[string][]bool{ // case: passed in each run
		"fleet/G5-window": {true, true, true},
		"fleet/W14-hubs":  {true, false, true},
		"fleet/D3-dial":   {false, false, false},
		"fleet/E9-start":  {false, true, false},
	}
	for i := range 3 {
		r.within("run" + string(rune('1'+i)) + "/")
		for name, ok := range results {
			r.Do(name, func() error {
				if ok[i] {
					return nil
				}
				return errors.New("no")
			})
		}
		r.Skip("fleet/T17-tv", "no TV")
	}
	r.within("")
	got := r.Flaky()
	if len(got) != 2 {
		t.Fatalf("flaky: %+v, want E9 and W14", got)
	}
	if got[0] != (Flaky{"fleet/E9-start", 1, 2}) || got[1] != (Flaky{"fleet/W14-hubs", 2, 1}) {
		t.Errorf("flaky: %+v", got)
	}
	// Every failure still fails the run.
	if r.Failed() != 6 {
		t.Errorf("failed %d, want 6", r.Failed())
	}

	dir := t.TempDir()
	var out strings.Builder
	if err := writeFlaky(&out, filepath.Join(dir, "report"), got, 3); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "report", "flaky.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != out.String() || !strings.Contains(out.String(), "fleet/E9-start: failed 2 of 3") {
		t.Errorf("flaky.txt %q, printed %q", b, out.String())
	}
	out.Reset()
	writeFlaky(&out, "", nil, 5)
	if !strings.Contains(out.String(), "no case both passed and failed in 5 runs") {
		t.Errorf("printed %q", out.String())
	}
}

func TestMetricsAndBaseline(t *testing.T) {
	r := NewReport("fleet", io.Discard, false)
	r.Metric("E1/home-p95", "ms", 300)
	r.Metric("E1/home-p95", "ms", 250) // a second run keeps the worst
	r.Metric("E2/rss-after", "KiB", 40000)
	r.Metric("E4/three-50MiB", "s", 30)
	r.Do("fleet/E1-a", func() error { return nil })
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	ms, err := readMetrics(filepath.Join(dir, "metrics.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 || ms[0] != (Metric{"E1/home-p95", "ms", 300}) {
		t.Fatalf("metrics.json: %+v", ms)
	}

	base := []Metric{
		{"E1/home-p95", "ms", 150},     // 300 > 150*1.25+100: worse
		{"E2/rss-after", "KiB", 36000}, // 40000 <= 36000*1.25+4096
		{"E4/three-50MiB", "s", 30},
		{"E10/rss-most", "KiB", 1}, // not measured now: a note
	}
	compareBaseline(r, base, 0.25)
	var failed []string
	for _, c := range r.cases {
		if c.Failure != "" {
			failed = append(failed, c.Name)
		}
	}
	if len(failed) != 1 || failed[0] != "baseline/E1/home-p95" {
		t.Errorf("failed %v, want only baseline/E1/home-p95", failed)
	}

	if err := worse(Metric{"x", "ms", 1}, Metric{"x", "s", 1}, 0.25); err == nil {
		t.Error("a metric whose unit changed compared")
	}
	if _, err := readMetrics(filepath.Join(dir, "none.json")); err == nil {
		t.Error("a missing baseline read")
	}
}

func TestNoMetricsNoFile(t *testing.T) {
	r := NewReport("check", io.Discard, false)
	r.Do("check/a", func() error { return nil })
	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "metrics.json")); !os.IsNotExist(err) {
		t.Errorf("a run without metrics wrote metrics.json: %v", err)
	}
}

func TestRepeatFlag(t *testing.T) {
	var out strings.Builder
	if code := run([]string{"-repeat", "0", "fleet"}, io.Discard, &out); code != 2 || !strings.Contains(out.String(), "-repeat") {
		t.Errorf("-repeat 0: exit %d, %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"-baseline", filepath.Join(t.TempDir(), "none.json"), "fleet"}, io.Discard, &out); code != 2 || !strings.Contains(out.String(), "-baseline") {
		t.Errorf("a missing -baseline: exit %d, %q", code, out.String())
	}
}
