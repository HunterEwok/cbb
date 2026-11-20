// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A run's numbers and its repeated cases (docs/maintainers/testbench.md, "Trends and
// flaky cases"): the load cases record what they measure as metrics, which
// -report writes to metrics.json and -baseline compares with an earlier
// run's; -repeat runs a suite several times and lists the cases that both
// passed and failed.

// Metric is one number a case measured. Lower is better for every metric
// the bench records: times, memory, descriptors.
type Metric struct {
	Name  string  `json:"name"`
	Unit  string  `json:"unit"` // ms, KiB, fds, s or % (of one core)
	Value float64 `json:"value"`
}

// Metric records a number under name; a name measured again in the same
// run (as -repeat does) keeps the worst value.
func (r *Report) Metric(name, unit string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.out, "METRIC %s %.1f %s\n", name, value, unit)
	for i, m := range r.metrics {
		if m.Name == name {
			r.metrics[i].Value = max(m.Value, value)
			return
		}
	}
	r.metrics = append(r.metrics, Metric{Name: name, Unit: unit, Value: value})
}

// Metrics returns the run's metrics sorted by name.
func (r *Report) Metrics() []Metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]Metric(nil), r.metrics...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// writeMetrics writes metrics.json into dir.
func writeMetrics(dir string, ms []Metric) error {
	b, err := json.MarshalIndent(ms, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "metrics.json"), append(b, '\n'), 0o600)
}

// readMetrics reads a metrics.json that an earlier run wrote.
func readMetrics(path string) ([]Metric, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ms []Metric
	if err := json.Unmarshal(b, &ms); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ms, nil
}

// noise is how much a metric of each unit may move between two runs of the
// same build before the fraction counts: a few milliseconds of a 20 ms
// latency are noise, not a regression.
var noise = map[string]float64{"ms": 100, "KiB": 4096, "fds": 4, "s": 2, "%": 1}

// compareBaseline adds a case "baseline/NAME" for every metric of the run
// that the baseline also has: it fails when the run's value is worse than
// the baseline's by more than slack (0.25 is a quarter) and the unit's
// noise. A metric only one of the two has is noted, not failed.
func compareBaseline(r *Report, base []Metric, slack float64) {
	old := map[string]Metric{}
	for _, m := range base {
		old[m.Name] = m
	}
	for _, m := range r.Metrics() {
		b, ok := old[m.Name]
		if !ok {
			r.Note("baseline", m.Name+" is new: nothing to compare it with")
			continue
		}
		delete(old, m.Name)
		r.Do("baseline/"+m.Name, func() error {
			return worse(m, b, slack)
		})
	}
	for name := range old {
		r.Note("baseline", name+" was in the baseline but not measured in this run")
	}
}

// worse returns an error when now is worse than then by more than slack
// and the unit's noise.
func worse(now, then Metric, slack float64) error {
	if now.Unit != then.Unit {
		return fmt.Errorf("%s is in %s now and was in %s", now.Name, now.Unit, then.Unit)
	}
	limit := then.Value*(1+slack) + noise[now.Unit]
	if now.Value > limit {
		return fmt.Errorf("%s is %.1f %s, the baseline %.1f %s, more than %.0f%% worse", now.Name, now.Value, now.Unit, then.Value, then.Unit, slack*100)
	}
	return nil
}

// runPrefix is what -repeat puts before each case's name.
var runPrefix = regexp.MustCompile(`^run[0-9]+/`)

// Flaky is a case that passed in some of a repeated suite's runs and
// failed in others.
type Flaky struct {
	Name           string
	Passed, Failed int
}

// Flaky lists the cases that both passed and failed across the runs of
// -repeat, the most failed first.
func (r *Report) Flaky() []Flaky {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := map[string]*Flaky{}
	var order []string
	for _, c := range r.cases {
		if c.Skipped != "" {
			continue
		}
		name := runPrefix.ReplaceAllString(c.Name, "")
		f := counts[name]
		if f == nil {
			f = &Flaky{Name: name}
			counts[name] = f
			order = append(order, name)
		}
		if c.Failure != "" {
			f.Failed++
		} else {
			f.Passed++
		}
	}
	var out []Flaky
	for _, name := range order {
		if f := counts[name]; f.Passed > 0 && f.Failed > 0 {
			out = append(out, *f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Failed > out[j].Failed })
	return out
}

// writeFlaky prints the flaky cases and, with dir, writes them to
// flaky.txt there. Every one stays a failure of the run: a case that fails
// once in five is a finding, never noise.
func writeFlaky(w io.Writer, dir string, fl []Flaky, runs int) error {
	var b strings.Builder
	if len(fl) == 0 {
		fmt.Fprintf(&b, "no case both passed and failed in %d runs\n", runs)
	} else {
		fmt.Fprintf(&b, "cases that both passed and failed in %d runs (add each to docs/testing.md, \"Flaky tests\"):\n", runs)
		for _, f := range fl {
			fmt.Fprintf(&b, "  %s: failed %d of %d\n", f.Name, f.Failed, f.Passed+f.Failed)
		}
	}
	io.WriteString(w, b.String())
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "flaky.txt"), []byte(b.String()), 0o600)
}
