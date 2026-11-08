// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	decisionRow    = regexp.MustCompile(`^\| (D-\d+) \| ([^|]+) \|`)
	decisionStatus = regexp.MustCompile(`^(accepted|replaced by (D-\d+)|partly replaced by (D-\d+))$`)
)

// checkDecisions reports what is wrong with the register of
// docs/decisions.md: a number used twice, a status it does not know, a
// status naming a decision that does not exist, and a replaced decision
// left among the decisions in force or one in force among the replaced.
func checkDecisions(files map[string][]byte) []string {
	const name = "docs/decisions.md"
	data, ok := files[name]
	if !ok {
		return nil
	}
	type row struct {
		line              int
		id, status, ref   string
		replaced, inForce bool
	}
	var rows []row
	seen := map[string]int{}
	var problems []string
	section := ""
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimPrefix(line, "## ")
			continue
		}
		m := decisionRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		r := row{line: i + 1, id: m[1], status: strings.TrimSpace(m[2])}
		if first, ok := seen[r.id]; ok {
			problems = append(problems, fmt.Sprintf("%s:%d: %s is used already on line %d; take the next free number", name, r.line, r.id, first))
		}
		seen[r.id] = r.line
		s := decisionStatus.FindStringSubmatch(r.status)
		if s == nil {
			problems = append(problems, fmt.Sprintf("%s:%d: %s has the status %q; the statuses are accepted, replaced by D-N and partly replaced by D-N", name, r.line, r.id, r.status))
			continue
		}
		r.ref = s[2] + s[3]
		r.replaced = s[2] != ""
		switch section {
		case "Decisions in force":
			r.inForce = true
		case "Replaced decisions":
		default:
			problems = append(problems, fmt.Sprintf("%s:%d: %s is outside the sections \"Decisions in force\" and \"Replaced decisions\"", name, r.line, r.id))
			continue
		}
		if r.replaced && r.inForce {
			problems = append(problems, fmt.Sprintf("%s:%d: %s is %s; move its row to \"Replaced decisions\"", name, r.line, r.id, r.status))
		}
		if !r.replaced && !r.inForce {
			problems = append(problems, fmt.Sprintf("%s:%d: %s is %s; it belongs among the decisions in force", name, r.line, r.id, r.status))
		}
		rows = append(rows, r)
	}
	for _, r := range rows {
		if r.ref == "" {
			continue
		}
		if _, ok := seen[r.ref]; !ok {
			problems = append(problems, fmt.Sprintf("%s:%d: %s names %s, which the register does not have", name, r.line, r.id, r.ref))
		} else if r.ref == r.id {
			problems = append(problems, fmt.Sprintf("%s:%d: %s names itself", name, r.line, r.id))
		}
	}
	return problems
}
