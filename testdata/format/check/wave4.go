// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
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
	} `json:"statements"`
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
	// Each field's row, in field order; a number written as 0 is the
	// default written out.
	for _, f := range []struct {
		n    uint64
		rule string
	}{{2, "content/flags"}, {3, "content/ttl"}, {4, "content/via"}} {
		if x, there := c[f.n]; there {
			n, ok := x.(uint64)
			if !ok {
				return f.rule
			}
			if n == 0 {
				return "form/default"
			}
		}
	}
	if x, there := c[uint64(5)]; there {
		if _, ok := x.(string); !ok {
			return "content/text"
		}
	}
	// A manifest is read by its own rows whatever the type.
	var man *manifest
	if x, there := c[uint64(6)]; there {
		mm, rule := readManifest(x)
		if rule != "" {
			return rule
		}
		man = mm
	}
	if _, there := c[uint64(7)]; there && !bs(c, 7, -1) {
		return "content/data"
	}
	// The rows between fields.
	if ttl, _ := u(c, 3); ttl > 4 {
		return "content/ttl"
	}
	if via, _ := u(c, 4); via > 2 {
		return "content/via"
	}
	text, hasText := c[uint64(5)].(string)
	if hasText && text == "" {
		return "form/default"
	}
	_, hasData := c[uint64(7)]
	switch t {
	case 1:
		if !hasText {
			return "content/text"
		}
	case 2, 3:
		if man == nil || man.files() != (t == 3) || man.validate() != "" || (t == 3 && !man.namesOK()) {
			return "content/manifest"
		}
		if len(text) > 256<<10 {
			return "content/text"
		}
	case 4:
		d, _ := c[uint64(7)].([]byte)
		if len(d) < 1 || len(d) > 4096 || !oneItem(d) {
			return "content/data"
		}
	}
	known := t <= 4
	if known && man != nil && t != 2 && t != 3 {
		return "content/manifest"
	}
	if known && hasData && t != 4 {
		return "content/data"
	}
	if known && t == 4 && hasText {
		return "content/text"
	}
	flags, _ := u(c, 2)
	if !known || flags&^1 != 0 || !only(c, 0, 1, 2, 3, 4, 5, 6, 7) {
		return "keep"
	}
	return "take"
}

// The manifest of media or files (section 10.3, "today's rules").
type manifest struct {
	size  uint64
	parts []part
}

type part struct {
	kind   uint64 // 1 png, 2 jpeg, 3 gif, 4 html; 0 none
	path   string
	dir    bool
	size   uint64
	sha256 []byte
}

func (m *manifest) files() bool { return len(m.parts) > 0 && m.parts[0].path != "" }

// readManifest reads the manifest's rows: 1 size, 2 parts (1 to 10 000
// maps of 1 type 1..4, 2 path, 3 dir 1, 4 size, 5 sha256 of 32 bytes).
func readManifest(x any) (*manifest, string) {
	const bad = "content/manifest"
	const maxInt = 1<<63 - 1
	m, ok := x.(map[any]any)
	if !ok || !only(m, 1, 2) {
		return nil, bad
	}
	out := &manifest{}
	if s, there := m[uint64(1)]; there {
		n, ok := s.(uint64)
		if !ok || n > maxInt {
			return nil, bad
		}
		if n == 0 {
			return nil, "form/default"
		}
		out.size = n
	}
	list, ok := m[uint64(2)].([]any)
	if !ok || len(list) == 0 || len(list) > 10000 {
		return nil, bad
	}
	for _, e := range list {
		pm, ok := e.(map[any]any)
		if !ok || !only(pm, 1, 2, 3, 4, 5) {
			return nil, bad
		}
		var p part
		if x, there := pm[uint64(1)]; there {
			n, ok := x.(uint64)
			if !ok || n < 1 || n > 4 {
				return nil, bad
			}
			p.kind = n
		}
		if x, there := pm[uint64(2)]; there {
			s, ok := x.(string)
			if !ok || s == "" {
				return nil, bad
			}
			p.path = s
		}
		if x, there := pm[uint64(3)]; there {
			if x != uint64(1) {
				return nil, bad
			}
			p.dir = true
		}
		if x, there := pm[uint64(4)]; there {
			n, ok := x.(uint64)
			if !ok || n > maxInt {
				return nil, bad
			}
			if n == 0 {
				return nil, "form/default"
			}
			p.size = n
		}
		if x, there := pm[uint64(5)]; there {
			h, ok := x.([]byte)
			if !ok || len(h) != 32 {
				return nil, bad
			}
			p.sha256 = h
		}
		out.parts = append(out.parts, p)
	}
	return out, ""
}

// validate is today's manifest rules: clipboard data has at most 8 parts,
// each a type once, no folder; files are clean paths, each once as a
// receiver writes it, no file inside a file; every file part has its
// SHA-256 and at most 1 GiB, the sizes add up to the manifest's, and the
// whole is at most 1 GiB.
func (m *manifest) validate() string {
	const bad = "manifest"
	const maxMedia = 1 << 30
	files := m.files()
	if len(m.parts) == 0 || len(m.parts) > 10000 || (!files && len(m.parts) > 8) {
		return bad
	}
	seen := map[string]bool{}
	var sum uint64
	paths := 0
	for _, p := range m.parts {
		var key string
		if files {
			if p.path == "" || p.kind != 0 || !pathOK(p.path) {
				return bad
			}
			paths += len(p.path)
			key = savePath(p.path)
		} else {
			if p.kind == 0 || p.dir {
				return bad
			}
			key = fmt.Sprint(p.kind)
		}
		if seen[key] {
			return bad
		}
		seen[key] = true
		if p.dir {
			if p.size != 0 || p.sha256 != nil {
				return bad
			}
			continue
		}
		if len(p.sha256) != 32 || p.size > maxMedia {
			return bad
		}
		sum += p.size
	}
	if paths > 512<<10 || sum != m.size || sum > maxMedia {
		return bad
	}
	if files {
		kind := map[string]bool{}
		for _, p := range m.parts {
			kind[savePath(p.path)] = p.dir
		}
		for _, p := range m.parts {
			sp := savePath(p.path)
			for i := 0; i < len(sp); i++ {
				if sp[i] != '/' {
					continue
				}
				if dir, there := kind[sp[:i]]; there && !dir {
					return bad
				}
			}
		}
	}
	return ""
}

// bidiRune is Unicode's Bidi_Control: U+061C, U+200E, U+200F, U+202A to
// U+202E, U+2066 to U+2069.
func bidiRune(r rune) bool {
	return r == 0x61c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// nfcKeeps is true when NFC leaves path as it is: no code point NFC
// changes alone (NFC_Quick_Check No, nfcNo), none that composes with the
// one before it (nfcPairs, Hangul by rule), and no mark before one of a
// lower combining class (nfcCCC, the canonical order).
func nfcKeeps(path string) bool {
	changed := func(c rune) bool {
		i := sort.Search(len(nfcNo), func(i int) bool { return nfcNo[i][1] >= c })
		return i < len(nfcNo) && nfcNo[i][0] <= c
	}
	composes := func(a, b rune) bool {
		if a >= 0x1100 && a <= 0x1112 && b >= 0x1161 && b <= 0x1175 {
			return true
		}
		if a >= 0xac00 && a <= 0xd7a3 && (a-0xac00)%28 == 0 && b >= 0x11a8 && b <= 0x11c2 {
			return true
		}
		i := sort.Search(len(nfcPairs), func(i int) bool {
			p := nfcPairs[i]
			return p[0] > a || (p[0] == a && p[1] >= b)
		})
		return i < len(nfcPairs) && nfcPairs[i] == [2]rune{a, b}
	}
	class := func(c rune) rune {
		i := sort.Search(len(nfcCCC), func(i int) bool { return nfcCCC[i][1] >= c })
		if i < len(nfcCCC) && nfcCCC[i][0] <= c {
			return nfcCCC[i][2]
		}
		return 0
	}
	prev := rune(-1)
	for _, c := range path {
		if changed(c) || (prev >= 0 && composes(prev, c)) {
			return false
		}
		if prev >= 0 && class(c) > 0 && class(c) < class(prev) {
			return false
		}
		prev = c
	}
	return true
}

// namesOK is 0.6's rules on the names of files over today's: no device
// name of Windows in any name, no bidirectional control, nothing NFC
// would change, and no two paths one when each character is lowered,
// nor a path inside a file so.
func (m *manifest) namesOK() bool {
	kind := map[string]bool{}
	for _, p := range m.parts {
		for _, name := range strings.Split(p.path, "/") {
			if device(name) {
				return false
			}
		}
		if !nfcKeeps(p.path) {
			return false
		}
		var b strings.Builder
		for _, r := range p.path {
			if bidiRune(r) {
				return false
			}
			b.WriteRune(unicode.ToLower(r))
		}
		key := b.String()
		if _, there := kind[key]; there {
			return false
		}
		kind[key] = p.dir
	}
	for key := range kind {
		for i := 0; i < len(key); i++ {
			if key[i] == '/' {
				if dir, there := kind[key[:i]]; there && !dir {
					return false
				}
			}
		}
	}
	return true
}

// device is a device name of Windows before the first dot, the spaces
// that end it dropped: CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM or LPT and
// one digit or superscript 1, 2, 3; any case of ASCII letters.
func device(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	for _, pre := range []string{"COM", "LPT"} {
		if n, ok := strings.CutPrefix(base, pre); ok {
			switch n {
			case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
				return true
			}
		}
	}
	return false
}

// reserved is the older list a manifest may not hold at all: CON, PRN,
// AUX, NUL, COM1..9, LPT1..9 before the first dot.
func reserved(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) &&
		base[3] >= '1' && base[3] <= '9'
}

func saveName(name string) string {
	if !device(name) {
		return name
	}
	if base, ext, ok := strings.Cut(name, "."); ok {
		return base + "_." + ext
	}
	return name + "_"
}

func savePath(path string) string {
	names := strings.Split(path, "/")
	for i, n := range names {
		names[i] = saveName(n)
	}
	return strings.Join(names, "/")
}

func fileNameOK(name string) bool {
	if name == "" || len(name) > 255 || len(saveName(name)) > 255 || name == "." || name == ".." ||
		strings.ContainsAny(name, "/\\:*?\"<>|") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") ||
		reserved(name) {
		return false
	}
	for _, r := range name {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

func pathOK(path string) bool {
	if path == "" || len(path) > 4096 || len(savePath(path)) > 4096 {
		return false
	}
	for _, n := range strings.Split(path, "/") {
		if !fileNameOK(n) {
			return false
		}
	}
	return true
}

func hasOrders(t uint64) bool {
	switch t {
	case 1, 2, 3, 5, 8, 10:
		return true
	}
	return false
}

// commandVerdict: the form of a command (section 6), its body and map.
func commandVerdict(body []byte, m map[any]any) string {
	if len(body) > 2<<20 {
		return "env/size"
	}
	if !only(m, 1, 2, 3, 4, 6, 7, 10, 11, 13, 14, 15) {
		return "form/critical"
	}
	t, ok := u(m, 1)
	if !ok || t < 1 || t > 10 {
		return "commands/type"
	}
	// paste carries up to 1 MiB of text; every other type 64 KiB
	if limit := 64 << 10; t != 3 && len(body) > limit {
		return "env/size"
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
	if hasEpoch {
		e, ok := epoch.(uint64)
		if ok && e == 0 {
			return "form/default"
		}
		if !ok {
			return "commands/epoch"
		}
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
	if hasSealed && !hasOrders(t) {
		return "commands/sealed"
	}
	return "take"
}

func hiddenRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) || (r >= 0x2028 && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// plainText: 1 to max bytes, nothing hidden.
func plainText(x any, max int) bool {
	s, ok := x.(string)
	if !ok || len(s) < 1 || len(s) > max {
		return false
	}
	for _, r := range s {
		if hiddenRune(r) {
			return false
		}
	}
	return true
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
	allowed, known := map[uint64][]uint64{1: {10}, 2: {10, 11, 12, 13}, 3: {10, 11, 12, 13, 14}, 5: {10}, 8: {10}, 10: {10, 11}}[t]
	if !known {
		return "commands/type"
	}
	if !ok || !only(o, allowed...) {
		return "form/critical"
	}
	switch t {
	case 1:
		if mode, _ := u(o, 10); mode == 1 || mode == 2 {
			return "take"
		}
		return "orders/mode"
	case 2:
		return hubOrders(o)
	case 3:
		way, _ := u(o, 10)
		if way != 1 && way != 2 {
			return "orders/paste"
		}
		if x, there := o[uint64(11)]; there && x != uint64(1) {
			return "orders/paste"
		}
		kind, _ := u(o, 12)
		if kind < 1 || kind > 3 {
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
	return "commands/type"
}

// hubOrders: 13 `off` (flag, alone), or any of 10 the hub to use
// [endpoint, key of 32 bytes], 11 forwarders (1 to 8 texts, each once),
// 12 its clients (a set of 1 to 256 [ID 16, key 32, psk 32]); not empty.
func hubOrders(o map[any]any) string {
	const bad = "orders/hub"
	if x, there := o[uint64(13)]; there {
		if x != uint64(1) || !only(o, 13) {
			return bad
		}
		return "take"
	}
	if x, there := o[uint64(10)]; there {
		a, ok := x.([]any)
		if !ok || len(a) != 2 || !plainText(a[0], 255) {
			return bad
		}
		if k, ok := a[1].([]byte); !ok || len(k) != 32 {
			return bad
		}
	}
	if x, there := o[uint64(11)]; there {
		a, ok := x.([]any)
		if !ok || len(a) == 0 || len(a) > 8 {
			return bad
		}
		once := map[string]bool{}
		for _, e := range a {
			if !plainText(e, 255) || once[e.(string)] {
				return bad
			}
			once[e.(string)] = true
		}
	}
	if x, there := o[uint64(12)]; there {
		a, ok := x.([]any)
		if !ok || len(a) == 0 || len(a) > 256 || !sortedSet(a) {
			return bad
		}
		for _, e := range a {
			c, ok := e.([]any)
			if !ok || len(c) != 3 {
				return bad
			}
			for i, n := range []int{16, 32, 32} {
				if b, ok := c[i].([]byte); !ok || len(b) != n {
					return bad
				}
			}
		}
	}
	if only(o) {
		return bad
	}
	return "take"
}

// statementVerdict: a keys statement (section 5). What every type has is
// read first; a later type, a critical field this version does not define
// or a second signer is held ("hold", passed on as it is, never used), and
// so is a sealing key of a later algorithm; an algorithm this version
// knows that is not X-Wing is refused.
func statementVerdict(body []byte, m map[any]any, sig2 bool) string {
	if len(body) > 2048 {
		return "env/size"
	}
	if t, ok := u(m, 1); !ok || t < 1 {
		return "statements/type"
	}
	if !bs(m, 2, 16) {
		return "statements/group"
	}
	if !bs(m, 3, 32) {
		return "statements/signer"
	}
	if e, ok := u(m, 4); !ok || e < 1 {
		return "statements/epoch"
	}
	if t, _ := u(m, 1); t != 1 || !only(m, 1, 2, 3, 4, 6, 10) || sig2 {
		return "hold"
	}
	if x, there := m[uint64(6)]; there {
		n, ok := x.(uint64)
		if ok && n == 0 {
			return "form/default"
		}
		if !ok {
			return "statements/time"
		}
	}
	x, there := m[uint64(10)]
	if !there {
		return "statements/seal"
	}
	key, ok := x.([]any)
	if !ok || len(key) != 2 {
		return "keys/shape"
	}
	alg, ok1 := key[0].(uint64)
	pub, ok2 := key[1].([]byte)
	if !ok1 || !ok2 {
		return "keys/shape"
	}
	switch alg {
	case 1:
		if px, _ := elliptic.Unmarshal(elliptic.P256(), pub); px == nil { //nolint:staticcheck
			return "keys/es256"
		}
		return "keys/xwing"
	case 2:
		if len(pub) != 1216 {
			return "keys/xwing"
		}
		return "take"
	case 3:
		if len(pub) != 32 {
			return "keys/x25519"
		}
		return "keys/xwing"
	}
	return "hold"
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
		m, body, err := envelope(unhex(c.Envelope), f.Labels["command"], bySignerHash)
		if err != nil {
			fail("wave4 commands %s: %v", c.Name, err)
			continue
		}
		if got := commandVerdict(body, m); got != c.Verdict {
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
		m, body, err := envelope(unhex(h.Envelope), f.Labels["keys"], bySignerHash)
		if err != nil {
			fail("wave4 statements %s: %v", h.Name, err)
			continue
		}
		if got := statementVerdict(body, m, false); got != h.Verdict {
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
	checkMutants(dir, &f)
}

// checkMutants: the vectors mutated field by field (wave4-mutants.json:
// where, what, and the Rust readers' verdict, written by the Rust core's
// test), mutated here the same way and judged by this file's rules. Any
// disagreement, and any panic, fails.
func checkMutants(dir string, f *wave4File) {
	var mf struct {
		Alts     []string `json:"alts"`
		AddValue int      `json:"add_value"`
		Cases    []struct {
			Family  string   `json:"family"`
			Index   int      `json:"index"`
			Path    []uint64 `json:"path"`
			Op      string   `json:"op"`
			Arg     uint64   `json:"arg"`
			Verdict string   `json:"verdict"`
		} `json:"cases"`
	}
	load(dir, "wave4-mutants.json", &mf)
	alts := make([]any, len(mf.Alts))
	for i, a := range mf.Alts {
		v, err := strict(unhex(a))
		must(err)
		alts[i] = v
	}
	input := func(family string, i int) (string, uint64) {
		switch family {
		case "contents":
			return f.Contents[i].Content, 0
		case "commands":
			return f.Commands[i].Envelope, 0
		case "orders":
			return f.Orders[i].Orders, f.Orders[i].Type
		case "statements":
			return f.Held[i].Envelope, 0
		case "beacons":
			return f.Beacons[i].Envelope, 0
		}
		panic("family " + family)
	}
	families := map[string]int{}
	for i, c := range mf.Cases {
		got := func() (v string) {
			defer func() {
				if r := recover(); r != nil {
					v = fmt.Sprintf("panic: %v", r)
				}
			}()
			h, t := input(c.Family, c.Index)
			raw := unhex(h)
			var top any
			var env []any
			switch c.Family {
			case "contents", "orders":
				x, err := strict(raw)
				must(err)
				if c.Family == "contents" {
					delete(x.(map[any]any), uint64(1))
				}
				top = x
			default:
				x, err := strict(raw)
				must(err)
				env = x.([]any)
				b, err := strict(env[0].([]byte))
				must(err)
				top = b
			}
			mutated := mutate(top, c.Path, c.Op, c.Arg, alts, alts[mf.AddValue])
			body, err := em.Marshal(mutated)
			must(err)
			switch c.Family {
			case "contents":
				padded, err := padded(mutated.(map[any]any), contentStep)
				must(err)
				return contentVerdict(padded)
			case "orders":
				return ordersVerdict(t, body)
			}
			m := mutated.(map[any]any)
			// signer2 names a second signature exactly when there is one
			if _, two := m[uint64(8)]; two != (len(env) == 3) {
				return "env/shape"
			}
			switch c.Family {
			case "commands":
				return commandVerdict(body, m)
			case "statements":
				return statementVerdict(body, m, len(env) == 3)
			case "beacons":
				return beaconVerdict(body, m)
			}
			return "family " + c.Family
		}()
		if got != c.Verdict {
			fail("wave4 mutant %d (%s %d %v %s %d): Go %q, Rust %q", i, c.Family, c.Index, c.Path, c.Op, c.Arg, got, c.Verdict)
		}
		families[c.Family]++
	}
	fmt.Printf("%-18s %d checked %v\n", "wave4-mutants.json", len(mf.Cases), families)
}

// mutate returns v with the item at path dropped, set to alts[arg], or,
// for "add" at a map's own path, key arg added with add.
func mutate(v any, path []uint64, op string, arg uint64, alts []any, add any) any {
	switch x := v.(type) {
	case map[any]any:
		out := map[any]any{}
		for k, e := range x {
			out[k] = e
		}
		if len(path) == 0 {
			if op != "add" {
				panic("add only at a map")
			}
			out[arg] = add
			return out
		}
		k := path[0]
		if len(path) == 1 {
			switch op {
			case "drop":
				delete(out, k)
			case "set":
				out[k] = alts[arg]
			}
			return out
		}
		out[k] = mutate(x[k], path[1:], op, arg, alts, add)
		return out
	case []any:
		i := path[0]
		out := append([]any{}, x...)
		if len(path) == 1 {
			switch op {
			case "drop":
				return append(out[:i:i], out[i+1:]...)
			case "set":
				out[i] = alts[arg]
			}
			return out
		}
		out[i] = mutate(x[i], path[1:], op, arg, alts, add)
		return out
	}
	panic("a path through a scalar")
}
