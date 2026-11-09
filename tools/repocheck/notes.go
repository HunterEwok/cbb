// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// workNote matches a note of work left to do in the code. The words are
// split so that this file does not match itself.
var workNote = regexp.MustCompile(`\b(` + "TO" + `DO|` + "FIX" + `ME)\b`)

// checkWorkNotes reports a note of work left to do outside the code copied
// from other projects: such work belongs in docs/roadmap.md, where it is
// planned and found, and the code cites the item ("roadmap item 37").
func checkWorkNotes(name string, data []byte) []string {
	if strings.Contains(name, "third_party/") || bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	var problems []string
	for i, line := range strings.Split(string(data), "\n") {
		if m := workNote.FindString(line); m != "" {
			problems = append(problems, fmt.Sprintf("%s:%d: a %s note; write the work in docs/roadmap.md and cite its item instead", name, i+1, m))
		}
	}
	return problems
}
