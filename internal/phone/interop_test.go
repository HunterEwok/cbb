// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

// joinQRVector is a join QR code text and what it carries, or nil when it
// is not one, for another implementation such as the phone app.
type joinQRVector struct {
	Text string    `json:"text"`
	Want *JoinCode `json:"want"`
}

func TestJoinQRInteropVectors(t *testing.T) {
	full := JoinCode{Code: "246802", Addrs: []string{"192.168.1.20:8767", "[fd00::5]:8767"}, Fingerprint: "qFnj7Uv+CE/WNnna2IEmMaLbkA6tHcKf0VijTRzekKA="}
	texts := []string{
		JoinQR(full),
		JoinQR(JoinCode{Code: "012345"}),
		" CBB://JOIN?code=111111&x=1\n",
		"cbb://join?code=3&addr=a:1&addr=b:1&addr=c:1&addr=d:1&addr=e:1&addr=10.0.0.2",
		"cbb://join",
		"cbb://pair?code=123456",
		"cbb-join:123456",
		"https://join/?code=1",
		"cbb://join?code=246802&fp=ab+c/d=",
	}
	var vs []joinQRVector
	for _, text := range texts {
		v := joinQRVector{Text: text}
		if jc, ok := ParseJoinQR(text); ok {
			v.Want = &jc
		}
		vs = append(vs, v)
	}
	got, err := json.MarshalIndent(vs, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("..", "..", "testdata", "interop", "joinqr.json")
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
		t.Errorf("%s is out of date; run go test ./internal/phone -run TestJoinQRInteropVectors -update", path)
	}
}
