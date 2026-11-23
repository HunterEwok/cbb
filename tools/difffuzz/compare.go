// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
)

// readVerdicts reads an implementation's verdicts, from one file or from
// several that each read some kinds and skip the others.
func readVerdicts(files string, n int) ([]string, error) {
	var out []string
	for _, f := range strings.Split(files, ",") {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) != n {
			return nil, fmt.Errorf("%s: %d verdicts for %d cases", f, len(lines), n)
		}
		if out == nil {
			out = lines
			continue
		}
		for i, l := range lines {
			if out[i] == "skip" {
				out[i] = l
			} else if l != "skip" {
				return nil, fmt.Errorf("%s:%d: a second verdict", f, i+1)
			}
		}
	}
	return out, nil
}

// compare reads the corpus and each implementation's verdicts (name=files)
// and reports the cases they read differently, max of them in full; it
// returns whether they all agree, leaving out the kinds of reportOnly,
// whose differences it prints all the same.
func compare(w io.Writer, corpus string, impls []string, max int, failures string, reportOnly []string) (bool, error) {
	cases, err := readCorpus(corpus)
	if err != nil {
		return false, err
	}
	names := make([]string, 0, len(impls))
	verdicts := map[string][]string{}
	for _, a := range impls {
		name, files, ok := strings.Cut(a, "=")
		if !ok {
			return false, fmt.Errorf("%q is not name=files", a)
		}
		v, err := readVerdicts(files, len(cases))
		if err != nil {
			return false, err
		}
		names = append(names, name)
		verdicts[name] = v
	}
	type tally struct{ taken, refused, differ int }
	kinds := map[string]*tally{}
	var bad []int
	for i, c := range cases {
		t := kinds[c.Kind]
		if t == nil {
			t = &tally{}
			kinds[c.Kind] = t
		}
		var first string
		differ := false
		for _, n := range names {
			v := verdicts[n][i]
			if v == "skip" {
				continue
			}
			if first == "" {
				first = v
			} else if v != first {
				differ = true
			}
		}
		switch {
		case differ:
			t.differ++
			bad = append(bad, i)
		case first == "refused":
			t.refused++
		case first != "":
			t.taken++
		}
	}
	kindNames := make([]string, 0, len(kinds))
	for k := range kinds {
		kindNames = append(kindNames, k)
	}
	sort.Strings(kindNames)
	fmt.Fprintf(w, "%d cases, read by %s\n", len(cases), strings.Join(names, ", "))
	for _, k := range kindNames {
		t := kinds[k]
		fmt.Fprintf(w, "  %-14s %6d taken %6d refused %6d read differently\n", k, t.taken, t.refused, t.differ)
	}
	for j, i := range bad {
		if j == max {
			fmt.Fprintf(w, "... and %d more\n", len(bad)-max)
			break
		}
		c := cases[i]
		fmt.Fprintf(w, "\ncase %d (%s):\n", i+1, c.Kind)
		fmt.Fprintf(w, "  body %q\n  base64 %s\n", c.Body, b64.EncodeToString(c.Body))
		for _, n := range names {
			fmt.Fprintf(w, "  %-6s %s\n", n, verdicts[n][i])
		}
	}
	if failures != "" && len(bad) > 0 {
		var l []Case
		for _, i := range bad {
			l = append(l, cases[i])
		}
		if err := writeCorpus(failures, l); err != nil {
			return false, err
		}
	}
	failing := 0
	for _, i := range bad {
		if !slices.Contains(reportOnly, cases[i].Kind) {
			failing++
		}
	}
	switch {
	case len(bad) == 0:
		fmt.Fprintln(w, "all implementations read every case alike")
	case failing == 0:
		fmt.Fprintf(w, "only kinds that are reported, not checked (%s), are read differently\n", strings.Join(reportOnly, ", "))
	}
	return failing == 0, nil
}
