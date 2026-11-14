// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// The 0.6 recovery sheet (sheet.json), read here apart from the core and
// from gen.py.
const sheetAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

type sheetRead struct {
	secret []byte
	group  []byte
}

func sheetCanonical(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\n' || r == '\t' || r == '\r':
		case r == 'I' || r == 'L':
			b.WriteByte('1')
		case r == 'O':
			b.WriteByte('0')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sheetBits reads base32 characters into n bytes, its spare bits zero.
func sheetBits(c string, n int) ([]byte, string) {
	if len(c) != (n*8+4)/5 {
		return nil, "length"
	}
	var out []byte
	acc, bits := uint64(0), 0
	for i := 0; i < len(c); i++ {
		v := strings.IndexByte(sheetAlphabet, c[i])
		if v < 0 {
			return nil, "damaged"
		}
		acc = acc<<5 | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	if acc&(1<<bits-1) != 0 {
		return nil, "padding"
	}
	return out, ""
}

func sheetCheck(n int, parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	d := h.Sum(nil)
	v := (int(d[0])<<8 | int(d[1])) >> (16 - n)
	var s []byte
	for i := n/5 - 1; i >= 0; i-- {
		s = append(s, sheetAlphabet[(v>>(5*i))&31])
	}
	return string(s)
}

func sheetParse(in string) (sheetRead, string) {
	c := sheetCanonical(in)
	if strings.HasPrefix(c, "CBB://REC0VER?") {
		return sheetRead{}, "earlier"
	}
	if rest, ok := strings.CutPrefix(c, "CBBR"); ok {
		if rest == "" {
			return sheetRead{}, "not_sheet"
		}
		if rest[0] != '1' {
			return sheetRead{}, "newer"
		}
		b, why := sheetBits(rest[1:], 48)
		if why != "" {
			return sheetRead{}, why
		}
		return sheetRead{b[:32], b[32:]}, ""
	}
	if c == "" || !strings.ContainsRune(sheetAlphabet, rune(c[0])) {
		return sheetRead{}, "not_sheet"
	}
	for i := 0; i < len(c); i++ {
		if strings.IndexByte(sheetAlphabet, c[i]) < 0 {
			if len(c) == 64 && c[0] == '1' {
				return sheetRead{}, "damaged"
			}
			return sheetRead{}, "not_sheet"
		}
	}
	switch {
	case len(c) == 56:
		return sheetRead{}, "earlier"
	case c[0] != '1':
		return sheetRead{}, "newer"
	case len(c) != 64:
		return sheetRead{}, "length"
	}
	wrong, data := 0, ""
	for i := 0; i < 4; i++ {
		line := c[16*i : 16*i+16]
		if sheetCheck(10, []byte("cbb recovery sheet v1\x00"), []byte{byte(i + 1)}, []byte(line[:14])) != line[14:] {
			wrong |= 1 << i
		}
		data += line[:14]
	}
	if wrong != 0 {
		return sheetRead{}, fmt.Sprintf("lines:%d", wrong)
	}
	secret, why := sheetBits(data[1:53], 32)
	if why != "" {
		return sheetRead{}, why
	}
	if sheetCheck(15, []byte("cbb recovery sheet v1 whole\x00"), []byte{data[0]}, secret) != data[53:] {
		return sheetRead{}, "whole"
	}
	return sheetRead{secret: secret}, ""
}

// sheetKeys gives K1's point and K2's public key of a secret.
func sheetKeys(secret []byte) ([]byte, []byte) {
	var k1 []byte
	for c := 0; c < 256; c++ {
		d := sha256.Sum256(append(append([]byte("cbb recovery key es256 v1\x00"), secret...), byte(c)))
		if k, err := ecdh.P256().NewPrivateKey(d[:]); err == nil {
			k1 = k.PublicKey().Bytes()
			break
		}
	}
	seeds := sha512.Sum512(append([]byte("cbb recovery key slh-dsa-sha2-128s v1\x00"), secret...))
	pub, _, err := slhdsa.GenerateKey(bytes.NewReader(seeds[:48]), slhdsa.SHA2_128s)
	must(err)
	k2, err := pub.MarshalBinary()
	must(err)
	return k1, k2
}

func checkSheet(dir string) {
	var v struct {
		Take []struct{ Name, Secret, Group, K1, K2, Text, QR string }
		Read []struct {
			Name, Input, Secret string
			Group               *string
		}
		Refuse []struct{ Name, Input, Reason string }
		Check  []struct{ Name, Input, Reason string }
	}
	load(dir, "sheet.json", &v)
	var k1, k2, group []byte
	for _, t := range v.Take {
		r, why := sheetParse(t.Text)
		if why != "" || hex.EncodeToString(r.secret) != t.Secret {
			fail("sheet %s: text read as %q", t.Name, why)
		}
		q, why := sheetParse(t.QR)
		if why != "" || hex.EncodeToString(q.secret) != t.Secret || hex.EncodeToString(q.group) != t.Group {
			fail("sheet %s: QR read as %q", t.Name, why)
		}
		if !strings.HasPrefix(t.QR, "CBBR1") || strings.Trim(t.QR, sheetAlphabet+"CBR") != "" {
			fail("sheet %s: QR not in alphanumeric mode", t.Name)
		}
		k1, k2 = sheetKeys(r.secret)
		if hex.EncodeToString(k1) != t.K1 || hex.EncodeToString(k2) != t.K2 {
			fail("sheet %s: keys", t.Name)
		}
		group = q.group
	}
	for _, t := range v.Read {
		r, why := sheetParse(t.Input)
		if why != "" || hex.EncodeToString(r.secret) != t.Secret || (t.Group != nil) != (r.group != nil) {
			fail("sheet read %s: %q", t.Name, why)
		}
	}
	for _, t := range v.Refuse {
		if _, why := sheetParse(t.Input); why != t.Reason {
			fail("sheet refuse %s: %q, want %s", t.Name, why, t.Reason)
		}
	}
	for _, t := range v.Check {
		r, why := sheetParse(t.Input)
		if why != "" {
			fail("sheet check %s: %q", t.Name, why)
			continue
		}
		a, b := sheetKeys(r.secret)
		same := bytes.Equal(a, k1) && bytes.Equal(b, k2)
		got := ""
		switch {
		case r.group != nil && !bytes.Equal(r.group, group):
			got = "other_group"
		case !same && r.group != nil:
			got = "damaged"
		case !same:
			got = "other_group"
		}
		if got != t.Reason {
			fail("sheet check %s: %q, want %s", t.Name, got, t.Reason)
		}
	}
	fmt.Printf("%-18s %d checked\n", "sheet.json", len(v.Take)+len(v.Read)+len(v.Refuse)+len(v.Check))
}
