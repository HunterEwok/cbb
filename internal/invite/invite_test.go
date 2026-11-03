// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package invite

import (
	"bytes"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tunnel"
)

func sample(t *testing.T) *Invitation {
	t.Helper()
	k := func() tunnel.Key {
		k, err := tunnel.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	return &Invitation{
		Group: "0f1e2d3c4b5a6978", Hub: "0123456789abcdef0123456789abcdef", HubKey: k().Public(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:8764"), netip.MustParseAddrPort("[2001:db8::7]:8764")},
		GuestKey:  k(), GuestPSK: k(), Secret: bytes.Repeat([]byte{7}, 16),
		Expires: time.Unix(1_800_000_000, 0),
	}
}

func TestRoundTrip(t *testing.T) {
	in := sample(t)
	text := in.String()
	if !strings.HasPrefix(text, "cbb://invite#") || len(text) > 600 {
		t.Errorf("text %q (%d bytes)", text, len(text))
	}
	got, err := Parse("\n " + text + "\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("got %+v, want %+v", got, in)
	}
}

// TestRoundTripObfuscated checks an invitation from an obfuscated hub,
// which carries the hub's AmneziaWG settings.
func TestRoundTripObfuscated(t *testing.T) {
	in := sample(t)
	var err error
	if in.Obfuscation, err = tunnel.NewObfuscation(); err != nil {
		t.Fatal(err)
	}
	text := in.String()
	if len(text) > 1000 {
		t.Errorf("text of %d bytes", len(text))
	}
	got, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("got %+v, want %+v", got, in)
	}
	in.Obfuscation.JC = 100
	if _, err := Parse(in.String()); err == nil {
		t.Error("bad obfuscation settings were read")
	}
}

func TestParseRefuses(t *testing.T) {
	in := sample(t)
	short := sample(t)
	short.Secret = short.Secret[:15]
	noAddr := sample(t)
	noAddr.Endpoints = nil
	noKey := sample(t)
	noKey.GuestPSK = tunnel.Key{}
	text := in.String()
	for name, s := range map[string]string{
		"not an invitation": "cbb://join?code=123456",
		"damaged":           text[:len(text)-5],
		"short secret":      short.String(),
		"no address":        noAddr.String(),
		"no key":            noKey.String(),
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
