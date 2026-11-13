// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package seal

import (
	"bytes"
	"crypto/hpke"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

// vectors is the form of testdata/interop/seal-go.json and seal-rust.json:
// messages one side sealed for the other to open, and sealed messages that
// must not open.
type vectors struct {
	Info    string    `json:"info"`
	Cases   []vector  `json:"cases"`
	Refused []refusal `json:"refused"`
}

type vector struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Public string `json:"public"`
	AAD    string `json:"aad"`
	Msg    string `json:"msg"`
	Sealed string `json:"sealed"`
}

type refusal struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	AAD    string `json:"aad"`
	Sealed string `json:"sealed"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustSecret(t *testing.T) []byte {
	t.Helper()
	s, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	secret := mustSecret(t)
	pub, err := PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != SecretSize || len(pub) != PublicKeySize {
		t.Fatalf("secret %d bytes, public key %d", len(secret), len(pub))
	}
	for _, msg := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("paste "), 1000)} {
		sealed, err := Seal(pub, []byte("header"), msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != len(msg)+Overhead {
			t.Fatalf("sealed %d bytes for %d", len(sealed), len(msg))
		}
		got, err := Open(secret, []byte("header"), sealed)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("open: %q, %v", got, err)
		}
		if _, err := Open(secret, []byte("other"), sealed); !errors.Is(err, ErrOpen) {
			t.Fatalf("opened with other associated data: %v", err)
		}
		if _, err := Open(mustSecret(t), []byte("header"), sealed); !errors.Is(err, ErrOpen) {
			t.Fatalf("opened with another key: %v", err)
		}
	}
}

func TestRefusesBadKeys(t *testing.T) {
	if _, err := PublicKey(make([]byte, 31)); err == nil {
		t.Error("took a short secret")
	}
	if _, err := Seal(make([]byte, PublicKeySize-1), nil, nil); err == nil {
		t.Error("took a short public key")
	}
	if err := CheckPublicKey(make([]byte, PublicKeySize+1)); err == nil {
		t.Error("took a long public key")
	}
	if _, err := Open(mustSecret(t), nil, make([]byte, Overhead-1)); !errors.Is(err, ErrOpen) {
		t.Errorf("short message: %v", err)
	}
}

func goVectors(t *testing.T) vectors {
	v := vectors{Info: string(Info)}
	inputs := []struct{ name, aad, msg string }{
		{"empty", "", ""},
		{"text", "group a to b id 1", "hello from go"},
		{"no associated data", "", "only the message"},
		{"utf-8", "\u0437\u0430\u0433\u043e\u043b\u043e\u0432\u043e\u043a", "\u0442\u0435\u043a\u0441\u0442 \u0434\u043b\u044f \u0432\u0441\u0442\u0430\u0432\u043a\u0438 \u2713"},
		{"long", "header", string(bytes.Repeat([]byte("0123456789abcdef"), 256))},
	}
	secret := mustSecret(t)
	pub, err := PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range inputs {
		sealed, err := Seal(pub, []byte(in.aad), []byte(in.msg))
		if err != nil {
			t.Fatal(err)
		}
		v.Cases = append(v.Cases, vector{
			Name: in.name, Secret: hex.EncodeToString(secret), Public: hex.EncodeToString(pub),
			AAD: hex.EncodeToString([]byte(in.aad)), Msg: hex.EncodeToString([]byte(in.msg)),
			Sealed: hex.EncodeToString(sealed),
		})
	}
	sealed, err := Seal(pub, []byte("header"), []byte("secret text"))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		b := bytes.Clone(sealed)
		b[i] ^= 1
		return b
	}
	refuse := func(name string, secret []byte, aad string, b []byte) {
		v.Refused = append(v.Refused, refusal{Name: name, Secret: hex.EncodeToString(secret),
			AAD: hex.EncodeToString([]byte(aad)), Sealed: hex.EncodeToString(b)})
	}
	refuse("other associated data", secret, "headeR", sealed)
	refuse("no associated data", secret, "", sealed)
	refuse("another key", mustSecret(t), "header", sealed)
	refuse("encapsulated key changed", secret, "header", flip(0))
	refuse("x25519 share changed", secret, "header", flip(EncSize-1))
	refuse("ciphertext changed", secret, "header", flip(EncSize))
	refuse("tag changed", secret, "header", flip(len(sealed)-1))
	refuse("cut", secret, "header", sealed[:len(sealed)-1])
	refuse("shorter than the overhead", secret, "header", sealed[:Overhead-1])
	refuse("extra byte", secret, "header", append(bytes.Clone(sealed), 0))
	return v
}

// TestVectors writes (with -update) testdata/interop/seal-go.json and
// checks it and seal-rust.json, which the Rust core writes.
func TestVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "interop")
	if *update {
		data, err := json.MarshalIndent(goVectors(t), "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "seal-go.json"), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"seal-go.json", "seal-rust.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			var v vectors
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatal(err)
			}
			if v.Info != string(Info) || len(v.Cases) == 0 || len(v.Refused) == 0 {
				t.Fatalf("info %q, %d cases, %d refused", v.Info, len(v.Cases), len(v.Refused))
			}
			for _, c := range v.Cases {
				secret := unhex(t, c.Secret)
				pub, err := PublicKey(secret)
				if err != nil || !bytes.Equal(pub, unhex(t, c.Public)) {
					t.Errorf("%s: public key differs (%v)", c.Name, err)
				}
				got, err := Open(secret, unhex(t, c.AAD), unhex(t, c.Sealed))
				if err != nil || !bytes.Equal(got, unhex(t, c.Msg)) {
					t.Errorf("%s: open: %v", c.Name, err)
				}
			}
			for _, r := range v.Refused {
				if _, err := Open(unhex(t, r.Secret), unhex(t, r.AAD), unhex(t, r.Sealed)); !errors.Is(err, ErrOpen) {
					t.Errorf("%s: opened (%v)", r.Name, err)
				}
			}
		})
	}
}

// TestDraftVector checks the suite against the vector of the standard's
// draft, from outside the project (testdata/interop/xwing-hpke-pq.json):
// the public key of its secret and every message and exported value
// opened from its encapsulated key. The Rust core checks the same file.
func TestDraftVector(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "xwing-hpke-pq.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		KEM         int    `json:"kem_id"`
		KDF         int    `json:"kdf_id"`
		AEAD        int    `json:"aead_id"`
		Info        string `json:"info"`
		SkRm        string `json:"skRm"`
		PkRm        string `json:"pkRm"`
		Enc         string `json:"enc"`
		Encryptions []struct {
			AAD string `json:"aad"`
			CT  string `json:"ct"`
			PT  string `json:"pt"`
		} `json:"encryptions"`
		Exports []struct {
			Context string `json:"exporter_context"`
			L       int    `json:"L"`
			Value   string `json:"exported_value"`
		} `json:"exports"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.KEM != 0x647a || v.KDF != 1 || v.AEAD != 3 || len(v.Encryptions) == 0 {
		t.Fatalf("the vector is for %#x, %d, %d with %d messages", v.KEM, v.KDF, v.AEAD, len(v.Encryptions))
	}
	pub, err := PublicKey(unhex(t, v.SkRm))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, unhex(t, v.PkRm)) {
		t.Error("the public key differs from the draft's")
	}
	sk, err := privateKey(unhex(t, v.SkRm))
	if err != nil {
		t.Fatal(err)
	}
	r, err := hpke.NewRecipient(unhex(t, v.Enc), sk, kdf, aead, unhex(t, v.Info))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range v.Encryptions {
		pt, err := r.Open(unhex(t, e.AAD), unhex(t, e.CT))
		if err != nil || !bytes.Equal(pt, unhex(t, e.PT)) {
			t.Fatalf("message %d: %q, %v", i, pt, err)
		}
	}
	for i, e := range v.Exports {
		got, err := r.Export(string(unhex(t, e.Context)), e.L)
		if err != nil || hex.EncodeToString(got) != e.Value {
			t.Errorf("export %d: %x, %v", i, got, err)
		}
	}
}
