// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/phone"
)

// The QR code's text cbb pair -qr reads arrives whole, fingerprint and all,
// though it is longer than a pairing code's line.
func TestReadQRText(t *testing.T) {
	want := phone.JoinCode{
		Code:        "123456",
		Addrs:       []string{"192.168.0.179:8764", "10.0.0.2:8764", "[fe80::1]:8764", "172.16.5.5:8764"},
		Fingerprint: "sdyYqdtKW+HR+0ALkJovRReX54G3FuWvIEXFFSKjNGs=",
	}
	text := phone.JoinQR(want)
	line, err := readLineUpTo(strings.NewReader(text+"\n"), maxQRText)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := phone.ParseJoinQR(line)
	if !ok || got.Code != want.Code || got.Fingerprint != want.Fingerprint || len(got.Addrs) != len(want.Addrs) {
		t.Fatalf("read %q as %+v", line, got)
	}
}
