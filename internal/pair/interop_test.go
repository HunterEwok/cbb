// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package pair

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"testing/cryptotest"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

// interopVectors are what another implementation of pairing, such as the
// phone app's CBBKit, must compute and encode the same way.
type interopVectors struct {
	MemberCert  []byte            `json:"member_cert"`
	JoinerCert  []byte            `json:"joiner_cert"`
	ChannelID   string            `json:"channel_id"` // hex
	Fingerprint string            `json:"fingerprint"`
	Frames      []json.RawMessage `json:"frames"` // as the Go side writes them
}

func TestInteropVectors(t *testing.T) {
	// A fixed random source makes the same joiner certificate each time:
	// its key's fingerprint is what a join QR code carries.
	cryptotest.SetGlobalRandom(t, 1)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := (&Joiner{ID: "00112233445566778899aabbccddeeff", Key: key}).cert()
	if err != nil {
		t.Fatal(err)
	}
	member := []byte("member certificate DER")
	info, _ := json.Marshal(Info{Name: "laptop", OS: "linux"})
	mad, _ := json.Marshal(memberAD{Device: "0123456789abcdef0123456789abcdef", Group: "0011223344556677"})
	frames := []*frame{
		{Msg: bytes.Repeat([]byte{1}, 32), AD: info},
		{Msg: bytes.Repeat([]byte{2}, 32), AD: mad, Tag: bytes.Repeat([]byte{3}, 64)},
		{Tag: bytes.Repeat([]byte{4}, 64)},
		{Welcome: &Welcome{Cert: []byte("cert"), GroupCA: []byte("group CA")}},
		{Welcome: &Welcome{Cert: []byte("cert"), Issuer: []byte("admin CA"), GroupCA: []byte("group CA"), Roots: [][]byte{[]byte("root")}}},
		{Error: "wrong-code"},
		{OK: true},
	}
	v := interopVectors{MemberCert: member, JoinerCert: joiner,
		ChannelID: hex.EncodeToString(channelID(member, joiner)), Fingerprint: CertFingerprint(joiner)}
	for _, f := range frames {
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		v.Frames = append(v.Frames, data)
	}
	got, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("..", "..", "testdata", "interop", "pairing.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; run go test ./internal/pair -run TestInteropVectors -update", path)
	}
}
