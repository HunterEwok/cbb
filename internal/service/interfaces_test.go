// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInterfacesSetting(t *testing.T) {
	dir := t.TempDir()
	old := EnvFile
	t.Cleanup(func() { EnvFile = old })
	EnvFile = filepath.Join(dir, "missing.env")
	if names, err := Interfaces(); err != nil || len(names) != 0 {
		t.Errorf("default: %q %v", names, err)
	}
	EnvFile = filepath.Join(dir, "cbb.env")
	os.WriteFile(EnvFile, []byte("CBB_INTERFACES=\"br-lan, br-iot\"\n"), 0o644)
	if names, err := Interfaces(); err != nil || !slices.Equal(names, []string{"br-lan", "br-iot"}) {
		t.Errorf("from the file: %q %v", names, err)
	}
	t.Setenv("CBB_INTERFACES", "eth1")
	if names, err := Interfaces(); err != nil || !slices.Equal(names, []string{"eth1"}) {
		t.Errorf("from the environment: %q %v", names, err)
	}
	for _, bad := range []string{"br-lan,../x", "a-name-that-is-too-long", "fe80::1%eth0"} {
		t.Setenv("CBB_INTERFACES", bad)
		if _, err := Interfaces(); err == nil || !strings.Contains(err.Error(), "CBB_INTERFACES") {
			t.Errorf("CBB_INTERFACES=%s: %v", bad, err)
		}
	}
}

func TestOnLink(t *testing.T) {
	p := netip.MustParsePrefix
	ifs := []netInterface{
		{index: 2, name: "br-lan", prefixes: []netip.Prefix{p("192.168.0.1/24"), p("fe80::1/64"), p("fd00::1/64")}},
		{index: 3, name: "wan", prefixes: []netip.Prefix{p("192.168.1.2/24")}},
		{index: 4, name: "br-iot", prefixes: []netip.Prefix{p("10.0.20.1/24")}},
	}
	only := onlyIn([]string{"br-lan", "br-iot"})
	a := netip.MustParseAddr
	for _, c := range []struct {
		local, remote string
		want          bool
	}{
		{"192.168.0.1", "192.168.0.10", true},
		{"10.0.20.1", "10.0.20.5", true},
		{"fd00::1", "fd00::5", true},
		{"fe80::1%br-lan", "fe80::5%br-lan", true},
		// The internet side, double NAT: a private address, but not a
		// listed interface.
		{"192.168.1.2", "192.168.1.1", false},
		// To the home address, from the internet side's network.
		{"192.168.0.1", "192.168.1.1", false},
		// From another home network, to the wrong interface's address.
		{"192.168.0.1", "10.0.20.5", false},
		{"fe80::1%wan", "fe80::5%wan", false},
		{"192.168.0.1", "203.0.113.7", false},
	} {
		if got := onLink(ifs, only, a(c.local), a(c.remote)); got != c.want {
			t.Errorf("onLink(%s, %s) = %v, want %v", c.local, c.remote, got, c.want)
		}
	}
	if onlyIn(nil) != nil {
		t.Error("an empty list limits the interfaces")
	}
}
