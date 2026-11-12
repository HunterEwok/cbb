// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"fmt"
	"strconv"
	"unicode/utf8"
)

// The vectors of wave 4 (wave4.json): contents, commands with their orders,
// keys statements a later version wrote, freshness beacons and the
// messages that carry them. Each rule is checked here by this file's own
// reading of the format, never by what the Rust reader decides: the
// signatures by Go's crypto, the fields and the rules between them below,
// the messages against the tables the file gives.

type wave4File struct {
	Labels   map[string]string `json:"labels"`
	Tables   map[string][]row  `json:"tables"`
	Types    map[string]string `json:"types"`
	Contents []struct {
		Name    string `json:"name"`
		Verdict string `json:"verdict"`
		Content string `json:"content"`
	} `json:"contents"`
	Commands []struct {
		Name     string `json:"name"`
		Verdict  string `json:"verdict"`
		Envelope string `json:"envelope"`
	} `json:"commands"`
	Orders []struct {
		Name    string `json:"name"`
		Type    uint64 `json:"type"`
		Verdict string `json:"verdict"`
		Orders  string `json:"orders"`
	} `json:"orders"`
	Held []struct {
		Name     string `json:"name"`
		Verdict  string `json:"verdict"`
		Envelope string `json:"envelope"`
	} `json:"statements_held"`
	Beacons []struct {
		Name     string `json:"name"`
		Verdict  string `json:"verdict"`
		Envelope string `json:"envelope"`
	} `json:"beacons"`
	Messages []struct {
		Name    string `json:"name"`
		T       uint64 `json:"t"`
		Verdict string `json:"verdict"`
		Message string `json:"message"`
		Frame   string `json:"frame"`
	} `json:"messages"`
}

func u(m map[any]any, k uint64) (uint64, bool) {
	x, ok := m[k].(uint64)
	return x, ok
}

func bs(m map[any]any, k uint64, n int) bool {
	b, ok := m[k].([]byte)
	return ok && (n < 0 || len(b) == n)
}

// only reports whether every critical field (below 256) of m is in allowed.
func only(m map[any]any, allowed ...uint64) bool {
	for k := range m {
		n, ok := k.(uint64)
		if !ok {
			return false
		}
		if n >= 256 {
			continue
		}
		found := false
		for _, a := range allowed {
			found = found || a == n
		}
		if !found {
			return false
		}
	}
	return true
}

func oneItem(b []byte) bool {
	_, err := strict(b)
	return err == nil
}

// contentVerdict: section 10.3. "take", "keep" (a type, flag or critical
// field of a later version: passed on, never written), or the rule.
func contentVerdict(b []byte) string {
	v, err := strict(b)
	if err != nil {
		return "cbor"
	}
	c, ok := v.(map[any]any)
	if !ok {
		return "copy/shape"
	}
	t, ok := u(c, 0)
	if !ok {
		return "copy/shape"
	}
	// One padding: none when the content is a step by itself, else the
	// shortest run of zeros that reaches a step.
	if p, there := c[uint64(1)]; !there {
		if !contentStep(len(b)) {
			return "copy/content-pad"
		}
	} else {
		pb, ok := p.([]byte)
		if !ok || bytes.Count(pb, []byte{0}) != len(pb) {
			return "copy/content-pad"
		}
		rest := map[any]any{}
		for k, x := range c {
			if k != uint64(1) {
				rest[k] = x
			}
		}
		again, err := padded(rest, contentStep)
		if err != nil || !bytes.Equal(again, b) {
			return "copy/content-pad"
		}
	}
	if t == 0 {
		return "content/type"
	}
	for _, f := range []struct {
		n    uint64
		rule string
		max  uint64
	}{{2, "content/flags", 1 << 62}, {3, "content/ttl", 4}, {4, "content/via", 2}} {
		x, there := c[f.n]
		if !there {
			continue
		}
		n, ok := x.(uint64)
		if !ok {
			return f.rule
		}
		if n == 0 {
			return "form/default"
		}
		if n > f.max {
			return f.rule
		}
	}
	if x, there := c[uint64(5)]; there {
		s, ok := x.(string)
		if !ok {
			return "content/text"
		}
		if s == "" {
			return "form/default"
		}
	}
	if _, there := c[uint64(7)]; there && !bs(c, 7, -1) {
		return "content/data"
	}
	_, hasText := c[uint64(5)]
	_, hasManifest := c[uint64(6)]
	_, hasData := c[uint64(7)]
	switch t {
	case 1:
		if !hasText {
			return "content/text"
		}
	case 2, 3:
		if r := manifestRule(c[uint64(6)], t); r != "" {
			return r
		}
	case 4:
		d, _ := c[uint64(7)].([]byte)
		if len(d) < 1 || len(d) > 4096 || !oneItem(d) {
			return "content/data"
		}
		if hasText {
			return "content/text"
		}
	}
	known := t <= 4
	if known && hasManifest && t != 2 && t != 3 {
		return "content/manifest"
	}
	if known && hasData && t != 4 {
		return "content/data"
	}
	flags, _ := u(c, 2)
	if !known || flags&^1 != 0 || !only(c, 0, 1, 2, 3, 4, 5, 6, 7) {
		return "keep"
	}
	return "take"
}

// manifestRule: the manifest of a media copy (t 2: every part a media type
// 1..4 without a path) or of files (t 3: every part a path without a
// type); its size the sum of its parts'.
func manifestRule(x any, t uint64) string {
	m, ok := x.(map[any]any)
	if !ok {
		return "content/manifest"
	}
	parts, ok := m[uint64(2)].([]any)
	if !ok || len(parts) == 0 {
		return "content/manifest"
	}
	var sum uint64
	for _, p := range parts {
		pm, ok := p.(map[any]any)
		if !ok || !only(pm, 1, 2, 3, 4, 5) {
			return "content/manifest"
		}
		mt, hasType := u(pm, 1)
		_, hasPath := pm[uint64(2)].(string)
		_, pathThere := pm[uint64(2)]
		_, typeThere := pm[uint64(1)]
		if t == 2 && (!hasType || mt < 1 || mt > 4 || pathThere) {
			return "content/manifest"
		}
		if t == 3 && (!hasPath || typeThere) {
			return "content/manifest"
		}
		size, _ := u(pm, 4)
		sum += size
	}
	total, _ := u(m, 1)
	if sum != total {
		return "content/manifest"
	}
	return ""
}

// commandVerdict: the form of a command (section 6) after its signature.
func commandVerdict(m map[any]any) string {
	if !only(m, 1, 2, 3, 4, 6, 7, 10, 11, 13, 14, 15) {
		return "form/critical"
	}
	t, ok := u(m, 1)
	if !ok || t < 1 || t > 10 {
		return "commands/type"
	}
	if !bs(m, 2, 16) {
		return "commands/group"
	}
	if !bs(m, 3, 32) {
		return "commands/signer"
	}
	if n, ok := u(m, 4); !ok || n < 1 {
		return "commands/n"
	}
	at, ok := u(m, 6)
	if !ok {
		return "commands/time"
	}
	if exp, ok := u(m, 7); !ok || exp <= at || exp-at > 30000 {
		return "commands/expires"
	}
	if !bs(m, 10, 16) {
		return "commands/to"
	}
	if !bs(m, 11, 16) {
		return "commands/id"
	}
	if _, there := m[uint64(13)]; there && !bs(m, 13, 16) {
		return "commands/nonce"
	}
	epoch, hasEpoch := m[uint64(14)]
	if hasEpoch && epoch == uint64(0) {
		return "form/default"
	}
	sealed, hasSealed := m[uint64(15)]
	if hasSealed {
		// a seal is at least X-Wing's ciphertext and the AEAD's tag
		if sb, ok := sealed.([]byte); !ok || len(sb) < 1120+16 {
			return "commands/sealed"
		}
	}
	if hasEpoch != hasSealed {
		return "commands/epoch"
	}
	if hasSealed {
		switch t {
		case 1, 2, 3, 5, 8, 10:
		default:
			return "commands/sealed"
		}
	}
	return "take"
}

func hiddenRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) || (r >= 0x2028 && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

func lowerName(s string) bool {
	if len(s) < 1 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ordersVerdict: the opened orders of a command of type t.
func ordersVerdict(t uint64, b []byte) string {
	v, err := strict(b)
	if err != nil {
		return "cbor"
	}
	o, ok := v.(map[any]any)
	if !ok {
		return "form/critical"
	}
	allowed := map[uint64][]uint64{1: {10}, 2: {10, 11, 12, 13}, 3: {10, 11, 12, 13, 14}, 5: {10}, 8: {10}, 10: {10, 11}}[t]
	if !only(o, allowed...) {
		return "form/critical"
	}
	switch t {
	case 1:
		if mode, _ := u(o, 10); mode == 1 || mode == 2 {
			return "take"
		}
		return "orders/mode"
	case 3:
		way, _ := u(o, 10)
		kind, _ := u(o, 12)
		enter, hasEnter := u(o, 11)
		if (way != 1 && way != 2) || kind < 1 || kind > 3 || (hasEnter && enter != 1) {
			return "orders/paste"
		}
		_, hasText := o[uint64(13)]
		_, hasCopy := o[uint64(14)]
		if kind == 3 {
			if hasText || !bs(o, 14, 16) || way != 1 {
				return "orders/paste"
			}
			return "take"
		}
		txt, ok := o[uint64(13)].(string)
		limit := 1 << 20
		if way == 2 {
			limit = 4096
		}
		if !ok || hasCopy || len(txt) < 1 || len(txt) > limit {
			return "orders/paste"
		}
		return "take"
	case 5:
		a, _ := o[uint64(10)].(string)
		if lowerName(a) {
			return "take"
		}
		return "orders/action"
	case 8:
		x, there := o[uint64(10)]
		if !there {
			return "take"
		}
		if ms, ok := x.(uint64); ok && ms >= 1 && ms <= 30*86400000 {
			return "take"
		}
		return "orders/mute"
	case 10:
		name, ok := o[uint64(10)].(string)
		if !ok || len(name) < 1 || len(name) > 32 || !utf8.ValidString(name) {
			return "orders/device"
		}
		for _, r := range name {
			if hiddenRune(r) {
				return "orders/device"
			}
		}
		if x, there := o[uint64(11)]; there {
			a, ok := x.([]byte)
			if !ok || len(a) < 1 || len(a) > 4096 || !oneItem(a) {
				return "orders/device"
			}
		}
		return "take"
	}
	panic(fmt.Sprintf("orders of type %d", t))
}

// heldVerdict: a keys statement this version does not read whole is held
// (passed on as it is, never used): a type, a critical field or a sealing
// algorithm of a later version. Anything else here is taken or refused.
func heldVerdict(m map[any]any) string {
	if !bs(m, 2, 16) || !bs(m, 3, 32) {
		return "refuse"
	}
	if e, ok := u(m, 4); !ok || e < 1 {
		return "refuse"
	}
	key, ok := m[uint64(10)].([]any)
	if !ok || len(key) != 2 {
		return "refuse"
	}
	alg, ok := key[0].(uint64)
	if !ok {
		return "refuse"
	}
	t, _ := u(m, 1)
	if t != 1 || !only(m, 1, 2, 3, 4, 6, 10) || alg != 2 {
		return "hold"
	}
	if pub, _ := key[1].([]byte); len(pub) != 1216 {
		return "refuse"
	}
	return "take"
}

// beaconVerdict: section 9.4, after the signature.
func beaconVerdict(body []byte, m map[any]any) string {
	if len(body) > 512 {
		return "env/size"
	}
	if !only(m, 1, 2, 3, 4, 6, 10, 11) {
		return "form/critical"
	}
	if t, _ := u(m, 1); t != 1 {
		return "beacons/type"
	}
	if !bs(m, 2, 16) {
		return "beacons/group"
	}
	if !bs(m, 3, 32) {
		return "beacons/signer"
	}
	if n, ok := u(m, 4); !ok || n < 1 {
		return "beacons/n"
	}
	if at, ok := u(m, 6); !ok || at < 1 {
		return "beacons/time"
	}
	if !bs(m, 10, 32) {
		return "beacons/digest"
	}
	if c, ok := u(m, 11); !ok || c < 1 || c > 4096 {
		return "beacons/count"
	}
	return "take"
}

func checkWave4(dir string) {
	var f wave4File
	load(dir, "wave4.json", &f)
	count := 0
	for _, c := range f.Contents {
		if got := contentVerdict(unhex(c.Content)); got != c.Verdict {
			fail("wave4 contents %s: %q, want %q", c.Name, got, c.Verdict)
		}
		count++
	}
	for _, c := range f.Commands {
		m, _, err := envelope(unhex(c.Envelope), f.Labels["command"], bySignerHash)
		if err != nil {
			fail("wave4 commands %s: %v", c.Name, err)
			continue
		}
		if got := commandVerdict(m); got != c.Verdict {
			fail("wave4 commands %s: %q, want %q", c.Name, got, c.Verdict)
		}
		count++
	}
	for _, o := range f.Orders {
		if got := ordersVerdict(o.Type, unhex(o.Orders)); got != o.Verdict {
			fail("wave4 orders %s: %q, want %q", o.Name, got, o.Verdict)
		}
		count++
	}
	for _, h := range f.Held {
		m, _, err := envelope(unhex(h.Envelope), f.Labels["keys"], bySignerHash)
		if err != nil {
			fail("wave4 statements %s: %v", h.Name, err)
			continue
		}
		if got := heldVerdict(m); got != h.Verdict {
			fail("wave4 statements %s: %q, want %q", h.Name, got, h.Verdict)
		}
		count++
	}
	for _, b := range f.Beacons {
		m, body, err := envelope(unhex(b.Envelope), f.Labels["beacon"], bySignerHash)
		if err != nil {
			fail("wave4 beacons %s: %v", b.Name, err)
			continue
		}
		if got := beaconVerdict(body, m); got != b.Verdict {
			fail("wave4 beacons %s: %q, want %q", b.Name, got, b.Verdict)
		}
		count++
	}
	// The messages: their tables join the ones messages3.json gave.
	for name, rows := range f.Tables {
		if _, dup := msgTables[name]; dup {
			fail("wave4 table %s named twice", name)
		}
		msgTables[name] = rows
	}
	byType := map[uint64]string{}
	for t, name := range f.Types {
		n, err := strconv.ParseUint(t, 10, 64)
		must(err)
		byType[n] = name
	}
	for _, msg := range f.Messages {
		v, err := strict(unhex(msg.Message))
		if err != nil {
			fail("wave4 messages %s: %v", msg.Name, err)
			continue
		}
		m, _ := v.(map[any]any)
		if t, _ := u(m, 0); t != msg.T || byType[t] == "" {
			fail("wave4 messages %s: type %d", msg.Name, t)
			continue
		}
		got := checkTable(byType[msg.T], m)
		if got == "" {
			got = "take"
		}
		if got != msg.Verdict {
			fail("wave4 messages %s: %q, want %q", msg.Name, got, msg.Verdict)
		}
		// Its frame: the length, then the message with one run of zeros in
		// field 1, or none, and nothing else changed.
		fr := unhex(msg.Frame)
		if len(fr) < 4 || int(fr[0])<<24|int(fr[1])<<16|int(fr[2])<<8|int(fr[3]) != len(fr)-4 || !onGridSize(len(fr)-4) {
			fail("wave4 messages %s: frame length", msg.Name)
			continue
		}
		fv, err := strict(fr[4:])
		if err != nil {
			fail("wave4 messages %s: frame: %v", msg.Name, err)
			continue
		}
		fm, _ := fv.(map[any]any)
		if p, there := fm[uint64(1)]; there {
			if pb, ok := p.([]byte); !ok || bytes.Count(pb, []byte{0}) != len(pb) {
				fail("wave4 messages %s: frame padding", msg.Name)
			}
			delete(fm, uint64(1))
		}
		if encOf(fm) != string(unhex(msg.Message)) {
			fail("wave4 messages %s: frame carries another message", msg.Name)
		}
		count++
	}
	fmt.Printf("%-18s %d checked\n", "wave4.json", count)
}
