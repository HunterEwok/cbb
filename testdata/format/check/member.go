// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"strconv"
)

// checkMember checks messages5.json, the member connection's own messages
// (format sections 9.2 and 9.3), against the tables the file gives: they
// join the ones messages3.json and wave4.json gave.
func checkMember(dir string) {
	var f struct {
		Tables map[string][]row  `json:"tables"`
		Types  map[string]string `json:"types"`
		Take   []struct {
			Name    string `json:"name"`
			T       uint64 `json:"t"`
			Message string `json:"message"`
		} `json:"take"`
		Refuse []struct {
			Name    string `json:"name"`
			Rule    string `json:"rule"`
			Message string `json:"message"`
		} `json:"refuse"`
	}
	load(dir, "messages5.json", &f)
	for name, rows := range f.Tables {
		if _, dup := msgTables[name]; dup {
			fail("messages5 table %s named twice", name)
		}
		msgTables[name] = rows
	}
	byType := map[uint64]string{}
	for t, name := range f.Types {
		n, err := strconv.ParseUint(t, 10, 64)
		must(err)
		byType[n] = name
	}
	verdict := func(name, hexMsg string) string {
		v, err := strict(unhex(hexMsg))
		if err != nil {
			fail("messages5 %s: %v", name, err)
			return ""
		}
		m, _ := v.(map[any]any)
		t, _ := u(m, 0)
		if byType[t] == "" {
			fail("messages5 %s: type %d", name, t)
			return ""
		}
		if got := checkTable(byType[t], m); got != "" {
			return got
		}
		return "take"
	}
	for _, t := range f.Take {
		if got := verdict(t.Name, t.Message); got != "take" {
			fail("messages5 %s: %q, want take", t.Name, got)
		}
	}
	for _, r := range f.Refuse {
		if got := verdict(r.Name, r.Message); got != r.Rule {
			fail("messages5 %s: %q, want %q", r.Name, got, r.Rule)
		}
	}
	fmt.Printf("%-18s %d checked\n", "messages5.json", len(f.Take)+len(f.Refuse))
}
