// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/HunterEwok/cbb/tools/strings/catalog"
)

// vale is the Vale that -lint runs, by its module and version: go run
// fetches it once, checks it against the Go checksum database and keeps
// it in the build cache.
const vale = "github.com/vale-cli/vale/v3/cmd/vale@v3.28.1"

// lint checks the words of the apps' strings: the termbase's words and
// the same translation for the same English (catalog), then Vale's rules
// (catalog.ValeDir) on every language's texts. It returns the problems.
func lint(src catalog.Source, terms catalog.Terms) ([]string, error) {
	out := append(terms.CheckTerms(src), src.CheckSame()...)
	alerts, err := runVale(src)
	if err != nil {
		return nil, err
	}
	return append(out, alerts...), nil
}

// valeAlert is the part of Vale's JSON output that lint reports.
type valeAlert struct {
	Check    string
	Message  string
	Severity string
	Match    string
	Line     int
}

// runVale writes each language's texts to a file of its own, a string a
// paragraph, runs Vale on them and maps each alert back to its string.
func runVale(src catalog.Source) ([]string, error) {
	dir, err := os.MkdirTemp("", "cbb-strings-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	lines := map[string][]string{} // language's file -> string ID at each line
	var files []string
	for _, l := range append([]string{"en"}, catalog.Languages...) {
		var b strings.Builder
		var at []string
		for _, s := range src {
			text := s.EN
			if l != "en" {
				if s.Fixed {
					continue
				}
				text = s.Texts[l]
			}
			for range strings.Count(text, "\n") + 2 {
				at = append(at, s.ID)
			}
			b.WriteString(text + "\n\n")
		}
		// The canary: Vale must flag it, or its settings did not reach
		// this file and it checked nothing.
		at = append(at, canary)
		b.WriteString(canary + "\n")
		name := filepath.Join(dir, l+".txt")
		if err := os.WriteFile(name, []byte(b.String()), 0o644); err != nil {
			return nil, err
		}
		lines[name] = at
		files = append(files, name)
	}
	config, err := filepath.Abs(filepath.Join(catalog.ValeDir, "vale.ini"))
	if err != nil {
		return nil, err
	}
	args := append([]string{"run", vale, "--config", config, "--output", "JSON", "--no-exit"}, files...)
	cmd := exec.Command("go", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	got, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("vale: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var alerts map[string][]valeAlert
	if err := json.Unmarshal(got, &alerts); err != nil {
		return nil, fmt.Errorf("vale's output: %v: %s", err, bytes.TrimSpace(got))
	}
	var out []string
	sung := map[string]bool{}
	for name, as := range alerts {
		at, ok := lines[name]
		if !ok {
			abs, _ := filepath.Abs(name)
			at = lines[abs]
		}
		l := strings.TrimSuffix(filepath.Base(name), ".txt")
		for _, a := range as {
			id := "?"
			if a.Line >= 1 && a.Line <= len(at) {
				id = at[a.Line-1]
			}
			if id == canary {
				sung[l] = sung[l] || a.Check == "Cbb.Ellipsis"
				continue
			}
			out = append(out, fmt.Sprintf("%s/%s.json: %q: %s (%s)", catalog.Dir, l, id, a.Message, a.Check))
		}
	}
	for _, name := range files {
		l := strings.TrimSuffix(filepath.Base(name), ".txt")
		if !sung[l] {
			return nil, fmt.Errorf("vale did not check %s.txt: see %s", l, filepath.Join(catalog.ValeDir, "vale.ini"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// canary is the last paragraph of every file lint hands Vale, which Vale's
// Cbb.Ellipsis must flag.
const canary = "cbb canary..."
