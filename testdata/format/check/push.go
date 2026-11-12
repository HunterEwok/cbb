// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
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
// sealed bodies, `once`, UnifiedPush tokens and the push service's
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
	Once []struct {
		Key  string `json:"key"`
		ID   string `json:"id"`
		Once string `json:"once"`
	} `json:"once"`
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

func pushOpen(labels map[string]string, pk []byte, seq uint64, sealed []byte) string {
	if len(sealed) < 28 || len(sealed) > 2972 {
		return "pushbody/size"
	}
	aead, err := chacha20poly1305.New(pushDerive(pk, labels["body"]))
	must(err)
	ad := append([]byte(labels["ad"]), 0)
	ad = binary.BigEndian.AppendUint64(ad, seq)
	plain, err := aead.Open(nil, sealed[:12], sealed[12:], ad)
	if err != nil {
		return "pushbody/open"
	}
	return pushBodyVerdict(plain)
}

func pushRegistration(m any) string {
	if r := checkTable("push", m); r != "" {
		return r
	}
	mm := m.(map[any]any)
	n := 0
	for _, k := range []uint64{2, 3, 4} {
		if _, there := mm[k]; there {
			n++
		}
	}
	kinds := mm[uint64(6)].(uint64)
	switch {
	case kinds == 0 && n == 0:
		return "off"
	case kinds != 0 && n == 3:
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
	u := v.(map[any]any)[uint64(1)].(string)
	if !strings.HasPrefix(u, "https://") || len(u) <= len("https://") {
		return "push-up/url"
	}
	return "take"
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
	for _, o := range f.Once {
		mac := hmac.New(sha256.New, pushDerive(unhex(o.Key), f.Labels["once"]))
		mac.Write(unhex(o.ID))
		if !bytes.Equal(mac.Sum(nil)[:16], unhex(o.Once)) {
			fail("push once %s", o.ID)
		}
		count++
	}
	for _, u := range f.UnifiedPush {
		t := unhex(u.Token)
		if got := pushUpVerdict(t); !cborVerdict(got, u.Verdict) {
			fail("push unifiedpush %s: %q, want %q", u.Name, got, u.Verdict)
		}
		if len(t) > 1024 {
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
			if sized && len(unhex(m.Frame))-4 != 4096 {
				fail("push message %s: a send off the 4096 step", m.Name)
			}
		}
		count++
	}
	for t := range f.Types {
		n, _ := strconv.ParseUint(t, 10, 64)
		if n != 28 && (n < 100 || n > 104) {
			fail("push type %d outside what architecture reserved", n)
		}
	}
	if count == 0 {
		fail("push.json has no vectors")
	}
	fmt.Printf("push.json          %d checked\n", count)
}
