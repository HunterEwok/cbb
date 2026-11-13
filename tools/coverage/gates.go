// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The hard gates hold from the first day, with no floor to fall to: every
// closed audit finding has a test, every rule a format reader refuses by
// name has a vector that it refuses, and the mutation runs leave no
// survivor the known list does not name. A gate whose inputs are missing is
// not measured.

// gate is one row of the gates' table.
type gate struct {
	name    string
	met, of int
	missing []string // what fails it, named in the table
	note    string   // why it is not measured
}

func (g gate) failed() bool { return g.note == "" && len(g.missing) > 0 }

// finding is one row of testdata/audit/closed.json: a closed finding's
// opaque id and the tests that hold it closed.
type finding struct {
	ID    string        `json:"id"`
	Tests []findingTest `json:"tests"`
}

type findingTest struct {
	Lang string `json:"lang"`
	File string `json:"file"`
	Name string `json:"name"`
}

// testDecl is how each language declares a test of that name.
var testDecl = map[string]func(name string) *regexp.Regexp{
	"go": func(n string) *regexp.Regexp { return regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(n) + `\(`) },
	"rust": func(n string) *regexp.Regexp {
		return regexp.MustCompile(`\bfn ` + regexp.QuoteMeta(n) + `\s*(<[^>]*>)?\(`)
	},
	"swift": func(n string) *regexp.Regexp { return regexp.MustCompile(`\bfunc ` + regexp.QuoteMeta(n) + `\s*\(`) },
	"kotlin": func(n string) *regexp.Regexp {
		return regexp.MustCompile("\\bfun (" + regexp.QuoteMeta(n) + "|`" + regexp.QuoteMeta(n) + "`)\\s*\\(")
	},
}

// auditGate checks that each closed finding names at least one test and that
// each named test is declared in its file, the paths taken from root.
func auditGate(file, root string) (gate, error) {
	g := gate{name: "closed audit findings with a test"}
	b, err := os.ReadFile(file)
	if err != nil {
		return g, err
	}
	var list []finding
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return g, fmt.Errorf("%s: %w", file, err)
	}
	seen := map[string]bool{}
	sources := map[string]string{}
	for _, f := range list {
		if f.ID == "" || seen[f.ID] {
			return g, fmt.Errorf("%s: an empty or repeated id %q", file, f.ID)
		}
		seen[f.ID] = true
		g.of++
		ok := len(f.Tests) > 0
		for _, t := range f.Tests {
			decl := testDecl[t.Lang]
			if decl == nil {
				return g, fmt.Errorf("%s: %s: unknown lang %q", file, f.ID, t.Lang)
			}
			src, read := sources[t.File]
			if !read {
				b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(t.File)))
				if err == nil {
					src = string(b)
				}
				sources[t.File] = src
			}
			if !decl(t.Name).MatchString(src) {
				ok = false
				g.missing = append(g.missing, fmt.Sprintf("%s: %s %s", f.ID, t.File, t.Name))
			}
		}
		if ok {
			g.met++
		}
	}
	return g, nil
}

var fieldRule = regexp.MustCompile(`Rule::field\("([^"]+)"\)`)

// formatGate checks that each rule a reader in src names with Rule::field is
// the expected refusal of at least one vector in vectors (*.json). Until the
// 0.6 core's readers are in the tree (no Rule::field in src) it is not
// measured.
func formatGate(src, vectors string) (gate, error) {
	g := gate{name: "format rules with a refused vector"}
	rules := map[string]bool{}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".rs") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range fieldRule.FindAllStringSubmatch(string(b), -1) {
			rules[m[1]] = true
		}
		return nil
	})
	if err != nil {
		return g, err
	}
	if len(rules) == 0 {
		g.note = "no reader names a rule yet (the 0.6 core's readers)"
		return g, nil
	}
	files, err := filepath.Glob(filepath.Join(vectors, "*.json"))
	if err != nil {
		return g, err
	}
	if len(files) == 0 {
		g.note = "no vectors in " + vectors
		return g, nil
	}
	refused := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return g, err
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return g, fmt.Errorf("%s: %w", f, err)
		}
		refusals(v, refused)
	}
	for r := range rules {
		g.of++
		if refused[r] {
			g.met++
		} else {
			g.missing = append(g.missing, r)
		}
	}
	sort.Strings(g.missing)
	return g, nil
}

// refusals gathers the rules of the vectors in v that a reader must refuse:
// an object with a rule and a verdict of refuse, or no verdict at all (the
// lists of refusals that do not repeat it).
func refusals(v any, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		if r, ok := x["rule"].(string); ok {
			if verdict, has := x["verdict"]; !has || verdict == "refuse" {
				into[r] = true
			}
		}
		for _, e := range x {
			refusals(e, into)
		}
	case []any:
		for _, e := range x {
			refusals(e, into)
		}
	}
}

var mutantPlace = regexp.MustCompile(`^([^:]+):[0-9]+:[0-9]+: `)

// mutantsGate counts the survivors in missed (cargo mutants' missed.txt)
// that known (tools/mutants/missed.txt) does not name, as check.sh does:
// without line and column, a survivor counted as often as it appears.
func mutantsGate(missed, known string) (gate, error) {
	g := gate{name: "surviving mutants the known list names"}
	m, err := os.ReadFile(missed)
	if err != nil {
		return g, err
	}
	k, err := os.ReadFile(known)
	if err != nil {
		return g, err
	}
	names := map[string]int{}
	for _, l := range strings.Split(string(k), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			names[l]++
		}
	}
	for _, l := range strings.Split(string(m), "\n") {
		if l == "" {
			continue
		}
		l = mutantPlace.ReplaceAllString(l, "$1: ")
		g.of++
		if names[l] > 0 {
			names[l]--
			g.met++
		} else {
			g.missing = append(g.missing, l)
		}
	}
	return g, nil
}

// gatesReport writes the gates' table.
func gatesReport(gates []gate) string {
	if len(gates) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n## Hard gates\n\n| Gate | Met | Of | |\n|---|---:|---:|---|\n")
	for _, g := range gates {
		switch {
		case g.note != "":
			fmt.Fprintf(&b, "| %s | | | not measured: %s |\n", g.name, g.note)
		case g.failed():
			fmt.Fprintf(&b, "| %s | %d | %d | failed: %s |\n", g.name, g.met, g.of, strings.Join(g.missing, "; "))
		default:
			fmt.Fprintf(&b, "| %s | %d | %d | ok |\n", g.name, g.met, g.of)
		}
	}
	return b.String()
}
