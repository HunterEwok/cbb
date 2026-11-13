// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// future.json: a reader of this version, by each optional field's row
// (format 20.5). This file's own reader: a wrong shape refuses; a value out
// of range refuses, reads as absent, keeps its known bits, or makes a
// transport's table unusable (the empty map), as its row says; a needed
// field always refuses. The Rust core checks that its rows equal the file's.

type laterRow struct {
	Table string `json:"table"`
	N     uint64 `json:"n"`
	Later string `json:"later"`
}

type refused struct{ rule string }

// absent is what a field reads as when it is left out.
var absent = &struct{}{}

var laterRows map[string]string

func laterOf(table string, n uint64) string {
	if l, ok := laterRows[table+" "+strconv.FormatUint(n, 10)]; ok {
		return l
	}
	return "refuse"
}

// readTy reads v of type ty as a reader of this version: the value (lists
// cleaned), absent, or a panic of refused.
func readTy(ty, later, rule string, v any) any {
	w := strings.SplitN(ty, " ", 3)
	upTo := func(s string) uint64 {
		_, b, _ := strings.Cut(s, "..")
		hi, _ := strconv.ParseUint(b, 10, 64)
		return hi
	}
	out := func() any {
		if later == "absent" {
			return absent
		}
		panic(refused{rule})
	}
	shape := func(ok bool) {
		if !ok {
			panic(refused{rule})
		}
	}
	switch w[0] {
	case "uint":
		x, ok := v.(uint64)
		shape(ok)
		if mask, isBits := strings.CutPrefix(later, "bits "); isBits {
			m, _ := strconv.ParseUint(mask, 10, 64)
			if x&m == 0 {
				return absent
			}
			return x & m
		}
		if !tyOK(ty, x) {
			return out()
		}
		return x
	case "flag":
		x, ok := v.(uint64)
		shape(ok)
		if x != 1 {
			return out()
		}
		return x
	case "bytes":
		b, ok := v.([]byte)
		shape(ok)
		if !strings.Contains(w[1], "..") {
			shape(tyOK(ty, b))
			return b
		}
		if len(b) == 0 || uint64(len(b)) > upTo(w[1]) {
			return out()
		}
		return b
	case "id":
		b, ok := v.([]byte)
		n, _ := strconv.Atoi(w[1])
		shape(ok && len(b) == n)
		if bytes.Equal(b, make([]byte, n)) {
			return out()
		}
		return b
	case "text":
		t, ok := v.(string)
		shape(ok)
		if len(t) == 0 || uint64(len(t)) > upTo(w[1]) || strings.IndexFunc(t, unicode.IsControl) >= 0 {
			return out()
		}
		return t
	case "addr":
		t, ok := v.(string)
		shape(ok)
		if !addrOK(t) {
			return out()
		}
		return t
	case "key":
		a, ok := v.([]any)
		shape(ok && len(a) == 2)
		alg, ok1 := a[0].(uint64)
		_, ok2 := a[1].([]byte)
		shape(ok1 && ok2)
		if want, _ := strconv.ParseUint(w[1], 10, 64); alg != want {
			return out()
		}
		shape(tyOK(ty, v))
		return v
	case "envelope":
		shape(tyOK(ty, v))
		return v
	case "array", "once", "set":
		a, ok := v.([]any)
		shape(ok)
		if len(a) > 0 {
			// The order and the uniqueness are shape: checked on a list
			// of the right length by the writer's own check.
			probe := w[0] + " 1.." + strconv.Itoa(len(a)) + " of any"
			shape(orderOK(probe, a))
		}
		if uint64(len(a)) > upTo(w[1]) {
			return out()
		}
		el := "refuse"
		if later == "absent" {
			el = "absent"
		}
		inner := strings.TrimPrefix(w[2], "of ")
		kept := []any{}
		for _, e := range a {
			if x := readTy(inner, el, rule, e); x != absent {
				kept = append(kept, x)
			}
		}
		if len(kept) == 0 {
			return out()
		}
		return kept
	case "map":
		m, ok := v.(map[any]any)
		if later == "unusable" {
			shape(ok)
			got, rule := readTable(w[1], v)
			if rule != "" {
				return map[any]any{}
			}
			for k := range m {
				if !listed(w[1], k) {
					return map[any]any{}
				}
			}
			return got
		}
		got, r := readTable(w[1], v)
		if r != "" {
			panic(refused{rule})
		}
		return got
	}
	panic("type " + ty)
}

// orderOK reports whether a list keeps its kind's order: once, each
// element once; set, rising by encoding.
func orderOK(probe string, a []any) bool {
	kind := strings.SplitN(probe, " ", 2)[0]
	es := make([]string, len(a))
	for i, e := range a {
		es[i] = encOf(e)
	}
	for i := range es {
		for j := range i {
			if kind == "once" && es[i] == es[j] {
				return false
			}
		}
		if kind == "set" && i > 0 && es[i-1] >= es[i] {
			return false
		}
	}
	return true
}

func listed(table string, k any) bool {
	n, ok := k.(uint64)
	if !ok {
		return false
	}
	for _, r := range msgTables[table] {
		if r.N == n {
			return true
		}
	}
	return false
}

// readTable reads v against table name as a reader of this version: the
// map read, or the rule that refuses it.
func readTable(name string, v any) (read map[any]any, rule string) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(refused)
			if !ok {
				panic(r)
			}
			read, rule = nil, e.rule
		}
	}()
	m, ok := v.(map[any]any)
	if !ok {
		return nil, name + "/shape"
	}
	out := map[any]any{}
	for k, x := range m {
		n, _ := k.(uint64)
		var row *row
		for i := range msgTables[name] {
			if r := &msgTables[name][i]; listed(name, k) && r.N == n {
				row = r
			}
		}
		if row == nil {
			out[k] = x
			continue
		}
		l := "refuse"
		if !row.Needed {
			l = laterOf(name, row.N)
		}
		if got := readTy(row.Type, l, row.Rule, x); got != absent {
			out[k] = got
		}
	}
	for _, r := range msgTables[name] {
		if _, there := out[r.N]; r.Needed && !there {
			return nil, r.Rule
		}
	}
	if r := betweenRule(name, out); r != "" {
		return nil, r
	}
	return out, ""
}

func checkFuture(dir string) {
	var f struct {
		Rows  []laterRow `json:"rows"`
		Cases []struct {
			Name, Table, Value, Read, Rule string
		} `json:"cases"`
	}
	load(dir, "future.json", &f)
	laterRows = map[string]string{}
	want := 0
	for _, rows := range msgTables {
		for _, r := range rows {
			if !r.Needed {
				want++
			}
		}
	}
	if len(f.Rows) != want {
		fail("future: %d rows for %d optional fields", len(f.Rows), want)
	}
	for _, r := range f.Rows {
		if r.Later != "refuse" && r.Later != "absent" && r.Later != "unusable" && !strings.HasPrefix(r.Later, "bits ") {
			fail("future: row %s %d: %q", r.Table, r.N, r.Later)
		}
		laterRows[r.Table+" "+strconv.FormatUint(r.N, 10)] = r.Later
	}
	for _, c := range f.Cases {
		v, err := strict(unhex(c.Value))
		must(err)
		got, rule := readTable(c.Table, v)
		switch {
		case c.Rule != "" && rule != c.Rule:
			fail("future %s: %q, want %q", c.Name, rule, c.Rule)
		case c.Rule == "" && rule != "":
			fail("future %s: refused %q", c.Name, rule)
		case c.Rule == "" && encOf(got) != string(unhex(c.Read)):
			fail("future %s: read differently", c.Name)
		}
	}
	fmt.Printf("%-18s %d rows, %d cases checked\n", "future.json", len(f.Rows), len(f.Cases))
}
