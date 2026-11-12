// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// The messages wave 3 numbers (messages3.json): each read by the profile,
// then against its table as the file gives it. The tables are data here,
// read by this file's own interpreter; the Rust core checks that its
// tables equal them.

type row struct {
	N      uint64 `json:"n"`
	Rule   string `json:"rule"`
	Type   string `json:"type"`
	Needed bool   `json:"needed"`
}

var msgTables map[string][]row

func encOf(v any) string {
	b, err := em.Marshal(v)
	must(err)
	return string(b)
}

// tyOK reports whether v has type ty, written as the tables write it.
func tyOK(ty string, v any) bool {
	w := strings.SplitN(ty, " ", 3)
	upTo := func(s string) (uint64, uint64) {
		a, b, _ := strings.Cut(s, "..")
		lo, _ := strconv.ParseUint(a, 10, 64)
		hi, _ := strconv.ParseUint(b, 10, 64)
		return lo, hi
	}
	switch w[0] {
	case "uint":
		lo, hi := upTo(w[1])
		x, ok := v.(uint64)
		return ok && lo <= x && x <= hi
	case "flag":
		x, ok := v.(uint64)
		return ok && x == 1
	case "bytes":
		b, ok := v.([]byte)
		if !ok {
			return false
		}
		if strings.Contains(w[1], "..") {
			_, hi := upTo(w[1])
			return len(b) >= 1 && uint64(len(b)) <= hi
		}
		n, _ := strconv.Atoi(w[1])
		return len(b) == n
	case "text":
		s, ok := v.(string)
		_, hi := upTo(w[1])
		if !ok || len(s) == 0 || uint64(len(s)) > hi {
			return false
		}
		for _, r := range s {
			if unicode.IsControl(r) {
				return false
			}
		}
		return true
	case "addr":
		s, ok := v.(string)
		if !ok {
			return false
		}
		ap, err := netip.ParseAddrPort(s)
		return err == nil && ap.Addr().Zone() == "" && !ap.Addr().Is4In6()
	case "key":
		a, ok := v.([]any)
		if !ok || len(a) != 2 {
			return false
		}
		alg, _ := strconv.ParseUint(w[1], 10, 64)
		got, ok1 := a[0].(uint64)
		pub, ok2 := a[1].([]byte)
		if !ok1 || !ok2 || got != alg {
			return false
		}
		switch alg {
		case 1:
			x, _ := elliptic.Unmarshal(elliptic.P256(), pub) //nolint:staticcheck
			return x != nil
		case 3:
			return len(pub) == 32
		}
		return true
	case "envelope":
		a, ok := v.([]any)
		if !ok || (len(a) != 2 && len(a) != 3) {
			return false
		}
		for _, e := range a {
			if _, ok := e.([]byte); !ok {
				return false
			}
		}
		body, err := strict(a[0].([]byte))
		if err != nil {
			return false
		}
		_, ok = body.(map[any]any)
		return ok
	case "array", "once", "set":
		_, hi := upTo(w[1])
		inner := strings.TrimPrefix(w[2], "of ")
		a, ok := v.([]any)
		if !ok || len(a) == 0 || uint64(len(a)) > hi {
			return false
		}
		es := make([]string, len(a))
		for i, e := range a {
			es[i] = encOf(e)
		}
		switch w[0] {
		case "once":
			s := append([]string{}, es...)
			sort.Strings(s)
			for i := 1; i < len(s); i++ {
				if s[i] == s[i-1] {
					return false
				}
			}
		case "set":
			for i := 1; i < len(es); i++ {
				if es[i-1] >= es[i] {
					return false
				}
			}
		}
		for _, e := range a {
			if !tyOK(inner, e) {
				return false
			}
		}
		return true
	case "map":
		return checkTable(w[1], v) == ""
	}
	panic("type " + ty)
}

// checkTable returns the rule v breaks against table name, or "".
func checkTable(name string, v any) string {
	m, ok := v.(map[any]any)
	if !ok {
		return name + "/shape"
	}
	rows, ok := msgTables[name]
	if !ok {
		panic("table " + name)
	}
	for _, r := range rows {
		x, there := m[r.N]
		if !there {
			if r.Needed {
				return r.Rule
			}
			continue
		}
		if !tyOK(r.Type, x) {
			return r.Rule
		}
	}
	return ""
}

func checkMessages(dir string) {
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
		Maps []struct {
			Name  string `json:"name"`
			Table string `json:"table"`
			Value string `json:"value"`
			Rule  string `json:"rule"`
		} `json:"maps"`
		Invitations struct {
			Prefix string `json:"prefix"`
			Take   []struct {
				Name       string `json:"name"`
				Invitation string `json:"invitation"`
				Text       string `json:"text"`
			} `json:"take"`
			Refuse []struct {
				Name       string `json:"name"`
				Rule       string `json:"rule"`
				Invitation string `json:"invitation"`
				Cross      string `json:"cross"`
			} `json:"refuse"`
		} `json:"invitations"`
		Cards signedFile `json:"cards"`
	}
	load(dir, "messages3.json", &f)
	msgTables = f.Tables
	byType := map[uint64]string{}
	for t, name := range f.Types {
		n, err := strconv.ParseUint(t, 10, 64)
		must(err)
		byType[n] = name
	}
	message := func(b []byte) (uint64, string) {
		v, err := strict(b)
		if err != nil {
			return 0, "profile: " + err.Error()
		}
		m, ok := v.(map[any]any)
		t, ok2 := m[uint64(0)].(uint64)
		if !ok || !ok2 {
			return 0, "frame/message"
		}
		if name, ok := byType[t]; ok {
			return t, checkTable(name, m)
		}
		return t, ""
	}
	count, skipped := 0, 0
	for _, t := range f.Take {
		if got, rule := message(unhex(t.Message)); rule != "" || got != t.T {
			fail("messages3 %s: %d %s", t.Name, got, rule)
		}
		count++
	}
	for _, r := range f.Refuse {
		if _, rule := message(unhex(r.Message)); rule != r.Rule {
			fail("messages3 %s: %q, want %q", r.Name, rule, r.Rule)
		}
		count++
	}
	for _, m := range f.Maps {
		v, err := strict(unhex(m.Value))
		if err != nil {
			fail("messages3 %s: %v", m.Name, err)
			continue
		}
		if rule := checkTable(m.Table, v); rule != m.Rule {
			fail("messages3 %s: %q, want %q", m.Name, rule, m.Rule)
		}
		count++
	}
	for _, t := range f.Invitations.Take {
		b := unhex(t.Invitation)
		v, err := strict(b)
		if err != nil || checkTable("invite", v) != "" {
			fail("invitation %s: %v %s", t.Name, err, checkTable("invite", v))
		}
		text, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(t.Text, f.Invitations.Prefix))
		if err != nil || !bytes.Equal(text, b) || !strings.HasPrefix(t.Text, f.Invitations.Prefix) {
			fail("invitation %s: text", t.Name)
		}
		count++
	}
	for _, r := range f.Invitations.Refuse {
		if r.Cross != "" {
			skipped++
			continue
		}
		v, err := strict(unhex(r.Invitation))
		if err != nil {
			fail("invitation %s: %v", r.Name, err)
		} else if rule := checkTable("invite", v); rule != r.Rule {
			fail("invitation %s: %q, want %q", r.Name, rule, r.Rule)
		}
		count++
	}
	// Cards: signed by the operator Key in field 3; their keys a set and
	// their endpoints each once.
	card := func(b []byte) string {
		m, _, err := envelope(b, f.Cards.Label, bySignerKey)
		if err != nil {
			if strings.Contains(err.Error(), "verify") {
				return "sig/verify"
			}
			return err.Error()
		}
		if !tyOK("set 1..4 of key 1", m[uint64(12)]) {
			return "card/keys"
		}
		if !tyOK("once 1..8 of text 1..253", m[uint64(11)]) {
			return "card/endpoints"
		}
		if k, ok := m[uint64(13)].(uint64); !ok || k == 0 || k&^3 != 0 {
			return "card/kinds"
		}
		return ""
	}
	for _, t := range f.Cards.Take {
		if rule := card(unhex(t.Envelope)); rule != "" {
			fail("card %s: %s", t.Name, rule)
		}
		count++
	}
	for _, r := range f.Cards.Refuse {
		if rule := card(unhex(r.Envelope)); rule != r.Rule {
			fail("card %s: %q, want %q", r.Name, rule, r.Rule)
		}
		count++
	}
	fmt.Printf("%-18s %d checked, %d rules between fields left to the implementations\n", "messages3.json", count, skipped)
}
