// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"net/netip"
	"testing"
)

func TestXHTTPIsChecked(t *testing.T) {
	id, err := NewVLESSID()
	if err != nil {
		t.Fatal(err)
	}
	path, err := NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	good := VLESS{Transport: TransportXHTTP, Endpoint: netip.MustParseAddrPort("198.51.100.9:443"), ServerName: "cbb.tools", Path: path, ID: id}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	if err := CheckVLESSPath("/banMEJvnYJJap8S"); err != nil {
		t.Errorf("a path of 15 letters: %v", err)
	}
	for name, change := range map[string]func(*VLESS){
		"no endpoint":     func(v *VLESS) { v.Endpoint = netip.AddrPort{} },
		"no path":         func(v *VLESS) { v.Path = "" },
		"short path":      func(v *VLESS) { v.Path = "/abc" },
		"path with query": func(v *VLESS) { v.Path = "/abcdefghij?x=1" },
		"relative path":   func(v *VLESS) { v.Path = "abcdefghijkl" },
		"bad name":        func(v *VLESS) { v.ServerName = "not a name" },
		"bad ID":          func(v *VLESS) { v.ID = "a3482e88" },
		"REALITY":         func(v *VLESS) { v.Transport = "" },
		"a new transport": func(v *VLESS) { v.Transport = "quic" },
	} {
		v := good
		change(&v)
		if v.Check() == nil {
			t.Errorf("%s: passed", name)
		}
	}
}
