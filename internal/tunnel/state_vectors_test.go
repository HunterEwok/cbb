// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/interop/tunnel-state.json")

const stateVectors = "../../testdata/interop/tunnel-state.json"

// TestStateVectors writes (with -update) and checks the tunnel state a Go
// hub keeps, which the Rust service reads and writes back the same
// (member/src/tunnel.rs): loading it and saving it again gives the same
// bytes.
func TestStateVectors(t *testing.T) {
	if *update {
		key := func(b byte) Key { return Key(bytes.Repeat([]byte{b}, 32)) }
		var o Obfuscation
		if err := json.Unmarshal([]byte(`{"jc":5,"jmin":50,"jmax":300,"s1":20,"s2":33,"s3":17,"s4":25,"h1":"1000016-1065551","h2":"1073741840-1073807375","h3":"2147483664-2147549199","h4":"3221225488-3221291023","header_protection_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}`), &o); err != nil {
			t.Fatal(err)
		}
		id := "6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"
		s := &State{Key: key(1), PSK: key(2), Group: "0f1e2d3c4b5a6978", IsHub: true, KeysInFile: true, ListenPort: 51820,
			Endpoints:   []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:8764"), netip.MustParseAddrPort("192.0.2.1:8764")},
			Obfuscation: &o,
			Forwarder: &ForwarderLink{Endpoint: netip.MustParseAddrPort("198.51.100.9:8764"), Pin: "cGlu", VLESSID: id, Project: true,
				VLESS: &VLESS{Transport: TransportXHTTP, Endpoint: netip.MustParseAddrPort("198.51.100.9:443"), ServerName: "cbb.example.org",
					Path: "/AbC-12_xyz0123456/a-group-of-its-own", ID: id}},
			Members: []Member{
				{Device: "00112233445566778899aabbccddeeff", PublicKey: key(3), PresharedKey: key(4), Chain: [][]byte{[]byte("leaf"), []byte("ca")}},
				{Device: "ffeeddccbbaa99887766554433221100", PublicKey: key(5), PresharedKey: key(6)},
			},
			Hubs: []HubLink{{Device: "0123456789abcdef0123456789abcdef", PublicKey: key(7), PresharedKey: key(8),
				Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:8764")}, Obfuscation: &o, Next: key(9)}},
			Serving: key(10), ServingFor: "2026-11", Next: key(11), NextFor: "2026-12", NextAt: time.UnixMilli(1796083200000)}
		dir := t.TempDir()
		if err := s.Save(dir); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, StateFile))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stateVectors, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(stateVectors)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, StateFile), want, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the state saved again differs:\n%s\nwant\n%s", got, want)
	}
}
