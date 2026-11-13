// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// The vectors of push (push.json, format section 20.4): registrations,
// sealed bodies, send keys' signatures, UnifiedPush tokens and the push service's
// messages. Each verdict is this file's own reading: the AEAD and the keys
// by Go's crypto, the fields by the tables the file gives, the padding and
// the rules between fields below.

type pushFile struct {
	Labels map[string]string `json:"labels"`
	Tables map[string][]row  `json:"tables"`
	Types  map[string]string `json:"types"`
	Envs   map[string]struct {
		Platform string `json:"platform"`
		Body     int    `json:"body"`
	} `json:"envs"`
	Registrations []struct {
		Name    string `json:"name"`
		Verdict string `json:"verdict"`
		Frame   string `json:"frame"`
	} `json:"registrations"`
	Bodies []struct {
		Name    string `json:"name"`
		Verdict string `json:"verdict"`
		Key     string `json:"key"`
		Seq     uint64 `json:"seq"`
		Sealed  string `json:"sealed"`
	} `json:"bodies"`
	Sends []struct {
		Name      string `json:"name"`
		Verdict   string `json:"verdict"`
		Key       string `json:"key"`
		Sig       string `json:"sig"`
		Env       uint64 `json:"env"`
		Token     string `json:"token"`
		Slot      string `json:"slot"`
		Face      string `json:"face"`
		Seq       uint64 `json:"seq"`
		Challenge string `json:"challenge"`
	} `json:"sends"`
	UnifiedPush []struct {
		Name    string `json:"name"`
		Verdict string `json:"verdict"`
		Token   string `json:"token"`
	} `json:"unifiedpush"`
	Messages []struct {
		Name    string `json:"name"`
		Verdict string `json:"verdict"`
		Frame   string `json:"frame"`
		Sized   *bool  `json:"sized"`
	} `json:"messages"`
}

// pushPlainFor returns the encoding of m (without key 1) padded with zeros
// in key 1 to exactly size bytes, or nil.
func pushPlainFor(m map[any]any, size int) []byte {
	if b := []byte(encOf(m)); len(b) == size {
		return b
	}
	for plen := 0; plen < size; plen++ {
		c := map[any]any{uint64(1): make([]byte, plen)}
		for k, v := range m {
			c[k] = v
		}
		b := []byte(encOf(c))
		if len(b) == size {
			return b
		}
		if len(b) > size {
			return nil
		}
	}
	return nil
}

func pushBodyVerdict(plain []byte) string {
	v, err := strict(plain)
	if err != nil {
		return "cbor"
	}
	// A kind a later version numbers is the neutral hint before any other
	// field is read against the table.
	vm, isMap := v.(map[any]any)
	k, isUint := vm[uint64(0)].(uint64)
	if !isMap || !isUint || k < 1 {
		return "pushbody/kind"
	}
	if k > 3 {
		return "neutral"
	}
	if r := checkTable("pushbody", v); r != "" {
		return r
	}
	m := v.(map[any]any)
	if p, there := m[uint64(1)]; there {
		z, ok := p.([]byte)
		if !ok {
			return "pushbody/pad"
		}
		for _, x := range z {
			if x != 0 {
				return "pushbody/pad"
			}
		}
	}
	kind := m[uint64(0)].(uint64)
	// A copy carries age 0, written by leaving it out: age is outside the
	// origin's signature, so one copy has one plaintext.
	if c, isBytes := m[uint64(2)].([]byte); kind == 1 && isBytes {
		if cv, err := strict(c); err == nil {
			if cm, isMap := cv.(map[any]any); isMap {
				if _, there := cm[uint64(2)]; there {
					return "pushbody/age"
				}
			}
		}
	}
	needs := map[uint64][]uint64{1: {2}, 2: {3, 4}, 3: {3, 5}}[kind]
	names := map[uint64]string{2: "pushbody/copy", 3: "pushbody/id", 4: "pushbody/origin", 5: "pushbody/event"}
	for _, n := range needs {
		if _, there := m[n]; !there {
			return names[n]
		}
	}
	rest := map[any]any{}
	for k, x := range m {
		if k != uint64(1) {
			rest[k] = x
		}
	}
	if !bytes.Equal(pushPlainFor(rest, len(plain)), plain) {
		return "pushbody/pad"
	}
	switch kind {
	case 1:
		return "copy"
	case 2:
		return "waits"
	case 3:
		return "event"
	}
	return "neutral"
}

func pushDerive(pk []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, pk, nil, info, 32)
	must(err)
	return k
}

func pushAD(labels map[string]string, seq uint64) []byte {
	ad := append([]byte(labels["ad"]), 0)
	return binary.BigEndian.AppendUint64(ad, seq)
}

func pushOpen(labels map[string]string, pk []byte, seq uint64, sealed []byte) string {
	// Only a size of the registry opens.
	if len(sealed) != 2972 {
		return "pushbody/size"
	}
	aead, err := chacha20poly1305.New(pushDerive(pk, labels["body"]))
	must(err)
	ad := pushAD(labels, seq)
	plain, err := aead.Open(nil, sealed[:12], sealed[12:], ad)
	if err != nil {
		return "pushbody/open"
	}
	// The nonce is derived from the plaintext: every honest sender of one
	// body makes the same bytes.
	mac := hmac.New(sha256.New, pushDerive(pk, labels["nonce"]))
	mac.Write(ad)
	mac.Write(plain)
	if !bytes.Equal(mac.Sum(nil)[:12], sealed[:12]) {
		return "pushbody/nonce"
	}
	return pushBodyVerdict(plain)
}

// pushSendVerdict checks the send key's signature over [env, token, slot,
// face, seq] and the service's challenge when there is one, as the service
// does: good, held (an algorithm 0.6 does not know) or the rule.
func pushSendVerdict(label string, keyEnc, sig []byte, env uint64, token, slot, face []byte, seq uint64, challenge []byte) string {
	k, err := strict(keyEnc)
	if err != nil || !tyOK("signer 1..4096", k) {
		return "push/send-sig"
	}
	key := k.([]any)
	if key[0].(uint64) != 1 {
		return "held"
	}
	signed := []any{env, token, slot, face, seq}
	if challenge != nil {
		signed = append(signed, challenge)
	}
	if es256(key[1].([]byte), label, []byte(encOf(signed)), sig) != nil {
		return "push/send-sig"
	}
	return "good"
}

func pushRegistration(m any) string {
	if r := checkTable("push", m); r != "" {
		return r
	}
	mm := m.(map[any]any)
	n := 0
	for _, k := range []uint64{2, 3, 4, 7, 8, 9, 11} {
		if _, there := mm[k]; there {
			n++
		}
	}
	kinds := mm[uint64(6)].(uint64)
	_, challenge := mm[uint64(10)]
	switch {
	case kinds == 0 && n == 0 && !challenge:
		return "off"
	case kinds != 0 && n == 7:
		if bytes.Equal(mm[uint64(4)].([]byte), make([]byte, 32)) {
			return "push/key"
		}
		return "on"
	}
	return "push/shape"
}

func pushUpVerdict(t []byte) string {
	v, err := strict(t)
	if err != nil {
		return "cbor"
	}
	if r := checkTable("push-up", v); r != "" {
		return r
	}
	if !pushUpURL(v.(map[any]any)[uint64(1)].(string)) {
		return "push-up/url"
	}
	// RFC 8291's key: an uncompressed point of P-256.
	if _, err := ecdh.P256().NewPublicKey(v.(map[any]any)[uint64(2)].([]byte)); err != nil {
		return "push-up/p256dh"
	}
	return "take"
}

// pushUpURL reads an endpoint by the rows: printable ASCII, https, no user
// or fragment, a host name of two labels at least that is no address, and
// port 443 when one is named.
func pushUpURL(u string) bool {
	rest, ok := strings.CutPrefix(u, "https://")
	if !ok || strings.Contains(u, "#") {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] < 0x21 || u[i] > 0x7e {
			return false
		}
	}
	authority := rest
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority = rest[:i]
	}
	if strings.Contains(authority, "@") {
		return false
	}
	host := authority
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		host = authority[:i]
		if authority[i+1:] != "443" {
			return false
		}
	}
	labels := strings.Split(host, ".")
	if len(host) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// No top-level name starts with a digit: a resolver may read such a
	// last label as part of an address.
	last := labels[len(labels)-1]
	return last[0] < '0' || last[0] > '9'
}

func pushFrame(b []byte) (map[any]any, bool) {
	if len(b) < 4 || int(binary.BigEndian.Uint32(b)) != len(b)-4 || !gridOK(len(b)-4) {
		return nil, false
	}
	v, err := strict(b[4:])
	if err != nil {
		return nil, false
	}
	m, ok := v.(map[any]any)
	return m, ok
}

func gridOK(n int) bool {
	switch n {
	case 64, 256, 1024, 4096, 16384:
		return true
	}
	return n > 16384 && n%16384 == 0
}

func cborVerdict(got, want string) bool {
	return got == want || (got == "cbor" && strings.HasPrefix(want, "cbor/"))
}

func checkPush(dir string) {
	var f pushFile
	load(dir, "push.json", &f)
	for name, rows := range f.Tables {
		if _, dup := msgTables[name]; dup {
			fail("push table %s named twice", name)
		}
		msgTables[name] = rows
	}
	count := 0
	for _, r := range f.Registrations {
		m, ok := pushFrame(unhex(r.Frame))
		if !ok || m[uint64(0)] != uint64(28) {
			fail("push registration %s: not a frame of t 28", r.Name)
			continue
		}
		if got := pushRegistration(m); got != r.Verdict {
			fail("push registration %s: %q, want %q", r.Name, got, r.Verdict)
		}
		count++
	}
	for _, b := range f.Bodies {
		got := pushOpen(f.Labels, unhex(b.Key), b.Seq, unhex(b.Sealed))
		if !cborVerdict(got, b.Verdict) {
			fail("push body %s: %q, want %q", b.Name, got, b.Verdict)
		}
		count++
	}
	for _, x := range f.Sends {
		got := pushSendVerdict(f.Labels["send"], unhex(x.Key), unhex(x.Sig), x.Env, unhex(x.Token), unhex(x.Slot), unhex(x.Face), x.Seq,
			challengeOf(x.Challenge))
		if got != x.Verdict {
			fail("push send key %s: %q, want %q", x.Name, got, x.Verdict)
		}
		count++
	}
	for _, u := range f.UnifiedPush {
		t := unhex(u.Token)
		if got := pushUpVerdict(t); !cborVerdict(got, u.Verdict) {
			fail("push unifiedpush %s: %q, want %q", u.Name, got, u.Verdict)
		}
		if len(t) > 4096 {
			fail("push unifiedpush %s: %d bytes", u.Name, len(t))
		}
		count++
	}
	for _, m := range f.Messages {
		mm, ok := pushFrame(unhex(m.Frame))
		if !ok {
			fail("push message %s: not a frame on the grid", m.Name)
			continue
		}
		t := mm[uint64(0)].(uint64)
		name, known := f.Types[strconv.FormatUint(t, 10)]
		if !known {
			fail("push message %s: type %d not numbered", m.Name, t)
			continue
		}
		got := checkTable(name, mm)
		if got == "" {
			got = "take"
		}
		if got != m.Verdict {
			fail("push message %s: %q, want %q", m.Name, got, m.Verdict)
		}
		if m.Sized != nil {
			env := strconv.FormatUint(mm[uint64(4)].(uint64), 10)
			e, there := f.Envs[env]
			sized := there && e.Body == len(mm[uint64(6)].([]byte))
			if sized != *m.Sized {
				fail("push message %s: sized %v, want %v", m.Name, sized, *m.Sized)
			}
			// An APNs token keeps a send on the 4096 step; the longest
			// token, 4096 bytes, takes it to the 16384 step.
			want := 4096
			if len(mm[uint64(3)].([]byte)) > 1024 {
				want = 16384
			}
			if sized && len(unhex(m.Frame))-4 != want {
				fail("push message %s: a send off the %d step", m.Name, want)
			}
		}
		count++
	}
	for t := range f.Types {
		n, _ := strconv.ParseUint(t, 10, 64)
		if (n < 28 || n > 29) && (n < 100 || n > 104) {
			fail("push type %d outside what architecture reserved", n)
		}
	}
	if count == 0 {
		fail("push.json has no vectors")
	}
	fmt.Printf("push.json          %d checked\n", count)
}

// challengeOf is the challenge of a send vector, nil when it has none.
func challengeOf(h string) []byte {
	if h == "" {
		return nil
	}
	return unhex(h)
}
