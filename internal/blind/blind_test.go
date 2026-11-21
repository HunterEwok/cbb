// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package blind

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "format", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ruleOf is the rule an error names, "" for none.
func ruleOf(err error) string {
	var r Rule
	if errors.As(err, &r) {
		return string(r)
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// TestCredentialVectors reads the server credentials of the format's
// vectors as the Rust core does (core/src/blind/tests.rs,
// credentials_of_the_vectors): each one taken with its ID, each refused by
// the rule the vectors name, and the chain of the period, hubs' and
// members' credentials holds as a server checks it.
func TestCredentialVectors(t *testing.T) {
	var v struct {
		Take []struct {
			Name     string `json:"name"`
			ID       string `json:"id"`
			Envelope string `json:"envelope"`
		} `json:"take"`
		Refuse []struct {
			Name     string `json:"name"`
			Rule     string `json:"rule"`
			Envelope string `json:"envelope"`
		} `json:"refuse"`
	}
	load(t, "credentials.json", &v)
	var read []*Credential
	for _, c := range v.Take {
		got, err := ReadCredential(unhex(t, c.Envelope))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if hex.EncodeToString(got.ID[:]) != c.ID {
			t.Errorf("%s: id %x", c.Name, got.ID)
		}
		read = append(read, got)
	}
	for _, r := range v.Refuse {
		_, err := ReadCredential(unhex(t, r.Envelope))
		if ruleOf(err) != r.Rule {
			t.Errorf("%s: %v, want %s", r.Name, err, r.Rule)
		}
	}
	if len(read) < 4 {
		t.Fatalf("%d credentials taken", len(read))
	}
	period, server, hubs, members := read[0], read[1], read[2], read[3]
	if err := CheckChain(period, hubs, members); err != nil {
		t.Errorf("the vectors' chain: %v", err)
	}
	if err := CheckChain(period, members, nil); err != ChainHubs {
		t.Errorf("members in place of hubs: %v", err)
	}
	if err := CheckChain(server, hubs, nil); err != ChainPeriod {
		t.Errorf("a server credential in place of the period: %v", err)
	}
	if !period.Live(period.ExpiresMs-1) || period.Live(period.ExpiresMs) {
		t.Error("live up to its expiry")
	}
	for _, h := range hubs.Hubs {
		if !hubs.Lists(h) || members.Lists(h) {
			t.Error("only a hubs' credential lists hubs")
		}
	}
}

// TestCredentialRefusals changes a credential of the vectors in the ways
// a server must refuse: every byte cut off, a trailing byte, a field of
// another kind, and the signature bent.
func TestCredentialRefusals(t *testing.T) {
	var v struct {
		Take []struct {
			Envelope string `json:"envelope"`
		} `json:"take"`
	}
	load(t, "credentials.json", &v)
	env := unhex(t, v.Take[2].Envelope)
	for i := range env {
		if _, err := ReadCredential(env[:i]); err == nil {
			t.Fatalf("taken cut at %d", i)
		}
	}
	if _, err := ReadCredential(append(bytes.Clone(env), 0)); ruleOf(err) != string(RuleTrailing) {
		t.Errorf("a trailing byte: %v", err)
	}
	e, err := ParseEnvelope(env, MaxCredentialBody)
	if err != nil {
		t.Fatal(err)
	}
	bent := bytes.Clone(e.Sig)
	bent[10] ^= 1
	if _, err := ReadCredential(Encode(Array(Bytes(e.Body), Bytes(bent)))); err == nil {
		t.Error("a bent signature taken")
	}
	m := append([]Pair(nil), e.Map.Map...)
	m = append(m, P(14, Array()))
	if _, err := ReadCredential(Encode(Array(Bytes(Encode(Map(m...))), Bytes(e.Sig)))); ruleOf(err) != "credentials/members/members" {
		t.Errorf("a members' list in a hubs' credential: %v", err)
	}
	m = append([]Pair(nil), e.Map.Map...)
	m = append(m, P(20, Uint(1)))
	if _, err := ReadCredential(Encode(Array(Bytes(Encode(Map(m...))), Bytes(e.Sig)))); ruleOf(err) != string(RuleCritical) {
		t.Errorf("a field of a later version: %v", err)
	}
}

// TestFrameVectors reads the format's frames: each taken, and written
// again to the same bytes; each refused by its rule.
func TestFrameVectors(t *testing.T) {
	var v struct {
		Take []struct {
			Name   string `json:"name"`
			Frame  string `json:"frame"`
			Length int    `json:"length"`
		} `json:"take"`
		Refuse []struct {
			Name  string `json:"name"`
			Rule  string `json:"rule"`
			Frame string `json:"frame"`
		} `json:"refuse"`
	}
	load(t, "frames.json", &v)
	for _, f := range v.Take {
		b := unhex(t, f.Frame)
		_, m, body, err := ReadFrame(bytes.NewReader(b), 7<<20)
		if err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		if len(body) != f.Length {
			t.Errorf("%s: %d bytes", f.Name, len(body))
		}
		if again := WriteFrame(m.Map...); !bytes.Equal(again, b) {
			t.Errorf("%s: written again as %x", f.Name, again)
		}
	}
	for _, f := range v.Refuse {
		_, _, _, err := ReadFrame(bytes.NewReader(unhex(t, f.Frame)), 7<<20)
		if ruleOf(err) != f.Rule {
			t.Errorf("%s: %v, want %s", f.Name, err, f.Rule)
		}
	}
}

// TestProfile refuses what the profile does not hold and writes each item
// in its one form.
func TestProfile(t *testing.T) {
	for _, c := range []struct {
		hex, rule string
	}{
		{"20", "cbor/negative"},
		{"c0", "cbor/tag"},
		{"f5", "cbor/simple"},
		{"5f", "cbor/indefinite"},
		{"1c", "cbor/reserved"},
		{"1817", "cbor/shortest"},
		{"1b8000000000000000", "cbor/int-range"},
		{"a1400a", "cbor/map-key"},
		{"a202000100", "cbor/map-order"},
		{"61ff", "cbor/utf8"},
		{"818181818181818181", "cbor/depth"},
		{"0000", "cbor/trailing"},
		{"42", "cbor/truncated"},
	} {
		if _, err := Decode(unhex(t, c.hex)); ruleOf(err) != c.rule {
			t.Errorf("%s: %v, want %s", c.hex, err, c.rule)
		}
	}
	v := Map(P(3, Text("é")), P(1, Array(Uint(500), Bytes([]byte{1}))))
	b := Encode(v)
	if hex.EncodeToString(b) != "a201821901f441010362c3a9" {
		t.Errorf("written as %x", b)
	}
	back, err := Decode(b)
	if err != nil || !bytes.Equal(Encode(back), b) {
		t.Errorf("%x read back: %v", b, err)
	}
}

// TestSignCredential writes credentials the reader takes back as written,
// their lists padded to the next length, real entries first, and refuses
// to write what is no credential.
func TestSignCredential(t *testing.T) {
	root, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tag := [16]byte{1, 2, 3}
	env, err := SignCredential(Credential{Kind: TypePeriod, Group: [16]byte{9}, Version: 1, ExpiresMs: 1 << 50, Tag: &tag, Key: Point(&pk.PublicKey)}, root)
	if err != nil {
		t.Fatal(err)
	}
	period, err := ReadCredential(env)
	if err != nil {
		t.Fatal(err)
	}
	five := [][32]byte{{1}, {2}, {3}, {4}, {5}}
	env, err = SignCredential(Credential{Kind: TypeHubs, Group: tag, Version: 3, ExpiresMs: 1 << 50, Hubs: five}, pk)
	if err != nil {
		t.Fatal(err)
	}
	hubs, err := ReadCredential(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(hubs.Hubs) != 8 || !slices.Equal(hubs.Hubs[:5], five) || len(hubs.Admins) != 4 || hubs.Version != 3 {
		t.Errorf("hubs %d, admins %d", len(hubs.Hubs), len(hubs.Admins))
	}
	if err := CheckChain(period, hubs, nil); err != nil {
		t.Error(err)
	}
	if _, err := SignCredential(Credential{Kind: TypeHubs, Group: tag, Version: 1, ExpiresMs: 1, Hubs: make([][32]byte, 17)}, pk); err == nil {
		t.Error("17 hubs written")
	}
	if _, err := SignCredential(Credential{Kind: TypePeriod, Group: tag, Version: 1, ExpiresMs: 1}, pk); err == nil {
		t.Error("a period without its tag written")
	}
}
