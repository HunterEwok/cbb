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
		return addrOK(s)
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
	case "age":
		a, ok := v.([]any)
		if !ok || len(a) != 2 {
			return false
		}
		id, ok1 := a[0].([]byte)
		_, ok2 := a[1].(uint64)
		return ok1 && ok2 && len(id) == 32
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
	// The rules between fields of a map: AmneziaWG's junk sizes, and below
	// one age per claim in a Welcome.
	if name == "obfuscation" && m[uint64(2)].(uint64) > m[uint64(3)].(uint64) {
		return "obfuscation/jmax"
	}
	// An offer's endpoint keys each name one of its endpoints, once.
	if keys, ok := m[uint64(9)].([]any); ok && name == "offer" {
		eps, _ := m[uint64(2)].([]any)
		seen := map[string]bool{}
		for _, k := range keys {
			e, _ := k.(map[any]any)[uint64(1)].(string)
			listed := false
			for _, x := range eps {
				listed = listed || x == e
			}
			if !listed || seen[e] {
				return "offer/endpoint-keys"
			}
			seen[e] = true
		}
	}
	// One age per claim in a Welcome: the IDs rise.
	if ages, ok := m[uint64(3)].([]any); ok && name == "welcome" {
		for i := 1; i < len(ages); i++ {
			if bytes.Compare(ages[i-1].([]any)[0].([]byte), ages[i].([]any)[0].([]byte)) >= 0 {
				return "welcome/claim-ages"
			}
		}
	}
	return ""
}

// inviteCross returns the rule between fields an invitation breaks, or "":
// the rules its reader adds to the tables.
func inviteCross(v any) string {
	m := v.(map[any]any)
	zero := func(x any) bool {
		b, ok := x.([]byte)
		return ok && bytes.Equal(b, make([]byte, len(b)))
	}
	if zero(m[uint64(1)]) || zero(m[uint64(2)]) {
		return "invite/shape"
	}
	paths := m[uint64(3)].([]any)
	has := func(p map[any]any, k uint64) bool { _, ok := p[k]; return ok }
	away := false
	for _, x := range paths {
		p := x.(map[any]any)
		kind := p[uint64(1)].(uint64)
		if has(p, 4) != has(p, 5) || zero(p[uint64(4)]) || zero(p[uint64(5)]) {
			return "invite/path"
		}
		if hk, ok := p[uint64(3)].([]any); ok && zero(hk[1]) {
			return "invite/path"
		}
		switch kind {
		case 1:
			if has(p, 2) || has(p, 3) || has(p, 4) || has(p, 5) {
				return "invite/path"
			}
			if has(p, 6) {
				return "invite/obfuscation"
			}
		case 2:
			if !has(p, 2) || !has(p, 3) || !has(p, 4) {
				return "invite/path"
			}
		case 3:
			if !has(p, 2) {
				return "invite/path"
			}
		}
		if kind != 1 {
			away = true
		}
	}
	pr := m[uint64(4)].(map[any]any)
	if g, _ := pr[uint64(4)].(uint64); g == 1 && pr[uint64(1)].(uint64) != 4 {
		return "invite/profile"
	}
	if h, _ := pr[uint64(3)].(uint64); h == 1 && away {
		return "invite/profile"
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
	count := 0
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
		if err != nil || checkTable("invite", v) != "" || inviteCross(v) != "" {
			fail("invitation %s: %v %s", t.Name, err, checkTable("invite", v))
		}
		text, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(t.Text, f.Invitations.Prefix))
		if err != nil || !bytes.Equal(text, b) || !strings.HasPrefix(t.Text, f.Invitations.Prefix) {
			fail("invitation %s: text", t.Name)
		}
		count++
	}
	cross := 0
	for _, r := range f.Invitations.Refuse {
		v, err := strict(unhex(r.Invitation))
		if err != nil {
			fail("invitation %s: %v", r.Name, err)
			continue
		}
		rule := checkTable("invite", v)
		if rule == "" {
			rule = inviteCross(v)
			if r.Cross == "" {
				fail("invitation %s: refused only by a rule between fields, not marked so", r.Name)
			}
			cross++
		}
		if rule != r.Rule {
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
		for _, e := range m[uint64(11)].([]any) {
			if !endpointOK(e.(string)) {
				return "card/endpoints"
			}
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
	fmt.Printf("%-18s %d checked, %d of them by the invitation's rules between fields\n", "messages3.json", count, cross)
}

// addrOK reports whether s is an addr in its one canonical text (RFC 5952
// for IPv6), no zone, not IPv4-mapped, not unspecified, not port 0.
func addrOK(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.String() == s && ap.Addr().Zone() == "" && !ap.Addr().Is4In6() &&
		!ap.Addr().IsUnspecified() && ap.Port() != 0
}

// endpointOK reports whether s is a card's endpoint: an addr, or a
// lower-case DNS name whose last label is neither all digits nor starts
// with 0x, with its port.
func endpointOK(s string) bool {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return addrOK(s) && publicIP(ap.Addr())
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return false
	}
	host, port := s[:i], s[i+1:]
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || strconv.FormatUint(p, 10) != port || host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	last := labels[len(labels)-1]
	if strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "" || last == "localhost" || last == "local" {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' || strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

// publicV4 reports whether an IPv4 address is none of this network, private,
// shared, loopback, link-local, multicast or reserved.
func publicV4(b [4]byte) bool {
	x, y := b[0], b[1]
	return !(x == 0 || x == 10 || x == 127 || x >= 224 || (x == 172 && y >= 16 && y < 32) ||
		(x == 192 && y == 168) || (x == 100 && y >= 64 && y < 128) || (x == 169 && y == 254))
}

// publicIP reports whether a card may name the address: a public IPv4
// address, or an IPv6 address that is not loopback, unspecified, multicast,
// link-local, site-local or unique-local, nor a refused IPv4 address in a
// translated, NAT64 or 6to4 form.
func publicIP(a netip.Addr) bool {
	if a.Is4() {
		return publicV4(a.As4())
	}
	p := a.As16()
	v4 := func(b []byte) bool { return publicV4([4]byte(b)) }
	first := uint16(p[0])<<8 | uint16(p[1])
	switch {
	case a.IsLoopback(), a.IsUnspecified(), a.IsMulticast():
		return false
	case first&0xffc0 == 0xfe80, first&0xffc0 == 0xfec0, first&0xfe00 == 0xfc00:
		return false
	case bytes.Equal(p[:12], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0}) && !v4(p[12:]):
		return false
	case bytes.Equal(p[:12], []byte{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}) && !v4(p[12:]):
		return false
	case first == 0x2002 && !v4(p[2:6]):
		return false
	}
	return true
}
