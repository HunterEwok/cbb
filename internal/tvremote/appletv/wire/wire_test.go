// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wire

import (
	"bytes"
	"errors"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestOPACK(t *testing.T) {
	// The encodings pyatv's tests give.
	for _, c := range []struct {
		v    any
		want string
	}{
		{true, "\x01"},
		{false, "\x02"},
		{nil, "\x04"},
		{0, "\x08"},
		{0x27, "\x2f"},
		{0x28, "\x30\x28"},
		{0x1FF, "\x31\xff\x01"},
		{0x1FFFFFF, "\x32\xff\xff\xff\x01"},
		{0x1FFFFFFFFFFFFFF, "\x33\xff\xff\xff\xff\xff\xff\xff\x01"},
		{1.0, "\x36\x00\x00\x00\x00\x00\x00\xf0\x3f"},
		{"abc", "\x43abc"},
		{strings.Repeat("a", 32), "\x60" + strings.Repeat("a", 32)},
		{strings.Repeat("a", 33), "\x61\x21" + strings.Repeat("a", 33)},
		{strings.Repeat("a", 256), "\x62\x00\x01" + strings.Repeat("a", 256)},
		{[]byte{0x12, 0x34, 0x56}, "\x73\x12\x34\x56"},
		{bytes.Repeat([]byte("a"), 33), "\x91\x21" + strings.Repeat("a", 33)},
		{bytes.Repeat([]byte("a"), 65536), "\x93\x00\x00\x01\x00" + strings.Repeat("a", 65536)},
		{[]any{}, "\xd0"},
		{[]any{1, "test", false}, "\xd3\x09\x44test\x02"},
		{map[string]any{}, "\xe0"},
		{map[string]any{"a": 12}, "\xe1\x41\x61\x14"},
	} {
		got, err := Pack(c.v)
		if err != nil || string(got) != c.want {
			t.Errorf("Pack(%v) = %x, %v; want %x", c.v, got, err, c.want)
		}
	}

	// A message survives the round, long arrays and maps too.
	long := make([]any, 20)
	for i := range long {
		long[i] = int64(i * 1000)
	}
	m := map[string]any{
		"_i": "_tiC", "_t": int64(1), "_x": int64(70000),
		"_c":   map[string]any{"_tiV": int64(1), "_tiD": []byte("data"), "on": true, "off": nil},
		"list": long, "uuid": UUID{1, 2, 3}, "f": 2.5,
	}
	for i := range 16 {
		m[string(rune('a'+i))] = "same"
	}
	b, err := Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Errorf("round: %#v, want %#v", got, m)
	}

	if got, err := Unpack([]byte("\x33\xff\xff\xff\xff\xff\xff\xff\xff")); err != nil || got != uint64(1<<64-1) {
		t.Errorf("the largest integer: %v %v", got, err)
	}

	// pyatv's references back to earlier objects.
	got, err = Unpack([]byte("\xd2\x41\x61\xa0"))
	if err != nil || !reflect.DeepEqual(got, []any{"a", "a"}) {
		t.Errorf("a reference: %v, %v", got, err)
	}
	got, err = Unpack([]byte("\xdf\x41\x61" + strings.Repeat("\xa0", 14) + "\x03"))
	if l, ok := got.([]any); err != nil || !ok || len(l) != 15 {
		t.Errorf("an endless array: %v, %v", got, err)
	}

	for _, bad := range []string{"", "\x43ab", "\xa0", "\xe1\x08\x08", "\xd3\x08", "\x93\xff\xff\xff\xff", "\x42\xff\xfe", "\x08\x08", "\x7f"} {
		if _, err := Unpack([]byte(bad)); !errors.Is(err, ErrOPACK) {
			t.Errorf("Unpack(%x) = %v, want ErrOPACK", bad, err)
		}
	}
	if _, err := Unpack([]byte(strings.Repeat("\xd1", 40) + "\x08")); err == nil {
		t.Error("a message nested 40 deep was read")
	}
}

func TestTLV(t *testing.T) {
	long := bytes.Repeat([]byte{7}, 300)
	b := TLV{{Type: TLVState, Value: []byte{1}}, {Type: TLVPublicKey, Value: long}, {Type: TLVProof}}.Encode()
	if len(b) != 3+2+255+2+45+2 {
		t.Fatalf("encoded %d bytes", len(b))
	}
	m, err := DecodeTLV(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m[TLVState], []byte{1}) || !bytes.Equal(m[TLVPublicKey], long) {
		t.Errorf("decoded %v", m)
	}
	if _, ok := m[TLVProof]; !ok {
		t.Error("the empty item is lost")
	}
	for _, bad := range [][]byte{{1}, {1, 3, 0}, {6, 1, 1, 3, 0, 6, 1, 1}} {
		if _, err := DecodeTLV(bad); !errors.Is(err, ErrTLV) {
			t.Errorf("DecodeTLV(%x) = %v", bad, err)
		}
	}
}

func TestSRP(t *testing.T) {
	s, err := NewSRPServer("1234")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewSRPClient()
	if err != nil {
		t.Fatal(err)
	}
	a, m1, m2, key, err := c.Respond(s.Salt, s.Public(), "1234")
	if err != nil {
		t.Fatal(err)
	}
	sm2, skey, err := s.Verify(a, m1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m2, sm2) || !bytes.Equal(key, skey) || len(key) != 64 {
		t.Error("the two sides differ")
	}
	a, m1, _, _, err = c.Respond(s.Salt, s.Public(), "4321")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Verify(a, m1); !errors.Is(err, ErrProof) {
		t.Errorf("a wrong PIN: %v", err)
	}
	if _, _, _, _, err := c.Respond(s.Salt, srpN.Bytes(), "1234"); err == nil {
		t.Error("B = N was taken")
	}
	// Leading zeros: a salt that starts with one still agrees, as both
	// sides write it the same way.
	zs := newSRPServer(append([]byte{0}, s.Salt[1:]...), big.NewInt(99), "0000")
	a, m1, m2, _, _ = newSRPClient(big.NewInt(77)).Respond(zs.Salt, zs.Public(), "0000")
	if sm2, _, err := zs.Verify(a, m1); err != nil || !bytes.Equal(sm2, m2) {
		t.Errorf("a salt with a leading zero: %v", err)
	}
}

func TestFrames(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := NewConn(a), NewConn(b)
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if err := ca.Encrypt(k1, k2); err != nil {
		t.Fatal(err)
	}
	if err := cb.Encrypt(k2, k1); err != nil {
		t.Fatal(err)
	}
	go func() {
		ca.WriteOPACK(FrameEOPACK, map[string]any{"n": int64(1)})
		ca.WriteFrame(FrameEOPACK, nil)
		ca.WriteOPACK(FrameEOPACK, map[string]any{"n": int64(2)})
		ca.WriteFrame(FrameEOPACK, []byte("x"))
	}()
	for want := int64(1); want <= 2; want++ {
		typ, m, err := cb.ReadOPACK()
		if err != nil || typ != FrameEOPACK || m["n"] != want {
			t.Fatalf("frame %d: %v %v %v", want, typ, m, err)
		}
		if want == 1 {
			if _, p, err := cb.ReadFrame(); err != nil || len(p) != 0 {
				t.Fatalf("the empty frame: %x %v", p, err)
			}
		}
	}
	// A frame sealed with another counter does not open.
	cb.inCount++
	if _, _, err := cb.ReadFrame(); !errors.Is(err, ErrSeal) {
		t.Errorf("a frame out of order: %v", err)
	}

	key := bytes.Repeat([]byte{3}, 32)
	s, err := Seal(key, "PS-Msg05", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Open(key, "PS-Msg05", s); err != nil || string(p) != "hello" {
		t.Errorf("Open: %q %v", p, err)
	}
	if _, err := Open(key, "PS-Msg06", s); !errors.Is(err, ErrSeal) {
		t.Errorf("another label opened: %v", err)
	}
}

func TestPlist(t *testing.T) {
	v := map[string]any{
		"$top":     map[string]any{"root": UID(1)},
		"$objects": []any{"$null", "\u041f\u0440\u0438\u0432\u0435\u0442 👋", []byte{1, 2}, int64(1 << 40), true, 1.5, UID(300)},
		"long":     strings.Repeat("x", 40),
	}
	b, err := EncodePlist(v)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePlist(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, v) {
		t.Errorf("round: %#v", got)
	}
	big := make([]any, 300)
	for i := range big {
		big[i] = int64(i)
	}
	b, err = EncodePlist(big)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodePlist(b); err != nil || !reflect.DeepEqual(got, big) {
		t.Errorf("300 objects: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("bplist00"), append([]byte("bplist00\x08"), make([]byte, 32)...)} {
		if _, err := DecodePlist(bad); !errors.Is(err, ErrPlist) {
			t.Errorf("DecodePlist(%x) = %v", bad, err)
		}
	}
}

func TestArchives(t *testing.T) {
	session := bytes.Repeat([]byte{9}, 16)
	d, err := SessionArchive(session)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := InputSession(d); err != nil || !bytes.Equal(got, session) {
		t.Errorf("InputSession: %x %v", got, err)
	}
	for _, c := range []struct {
		text  string
		clear bool
	}{{"\u041f\u0440\u0438\u0432\u0435\u0442, TV 👋", false}, {"", true}} {
		d, err := TextArchive(session, c.text, c.clear)
		if err != nil {
			t.Fatal(err)
		}
		s, text, clear, err := TextOperation(d)
		if err != nil || !bytes.Equal(s, session) || text != c.text || clear != c.clear {
			t.Errorf("TextOperation: %x %q %v %v", s, text, clear, err)
		}
	}
	if _, err := TextArchive([]byte{1}, "x", false); !errors.Is(err, ErrArchive) {
		t.Errorf("a short session: %v", err)
	}
	empty, _ := EncodePlist(map[string]any{"$top": map[string]any{}, "$objects": []any{"$null"}})
	if _, err := InputSession(empty); !errors.Is(err, ErrArchive) {
		t.Errorf("no session: %v", err)
	}
}

func FuzzUnpack(f *testing.F) {
	for _, s := range []string{"\xe1\x41\x61\x14", "\xd2\x41\x61\xa0", "\x93\x01\x00\x00\x00a"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		// What reads, writes again.
		if v, err := Unpack(b); err == nil {
			if _, err := Pack(v); err != nil {
				t.Errorf("Pack(Unpack(%x)): %v", b, err)
			}
		}
	})
}

func FuzzDecodePlist(f *testing.F) {
	d, _ := SessionArchive(make([]byte, 16))
	f.Add(d)
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodePlist(b)
		InputSession(b)
		TextOperation(b)
	})
}
