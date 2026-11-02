// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// fakeNetworks returns known networks in dir whose interface and gateway
// the test sets.
func fakeNetworks(t *testing.T, dir string, inGroup bool, ifc *netInterface, gw *string) *networks {
	t.Helper()
	n := loadNetworksWith(dir, inGroup, t.Logf, func() map[int]string { return map[int]string{ifc.index: *gw} },
		func() ([]netInterface, error) { return []netInterface{*ifc}, nil })
	return n
}

func TestKnownNetworks(t *testing.T) {
	dir := t.TempDir()
	home := netInterface{index: 7, name: "wlan0", prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.225/24")}}
	ifc, gw := home, "aa:bb:cc:dd:ee:ff"
	n := fakeNetworks(t, dir, false, &ifc, &gw)
	addr := netip.MustParseAddr("192.168.0.225")
	if n.Knows(addr) || n.knownLocked(ifc.index, ifc.prefixes) {
		t.Fatal("a new device knows a network")
	}
	if got := n.Unknown(); len(got) != 1 || got[0] != "wlan0" {
		t.Errorf("Unknown() = %v", got)
	}
	if !n.Learn(addr) || n.Learn(addr) {
		t.Error("Learn did not report the new network once")
	}
	if !n.Knows(addr) || len(n.Unknown()) != 0 {
		t.Error("a network learned is not known")
	}
	// A café on the same subnet behind another router: unknown.
	gw = "11:22:33:44:55:66"
	n.gw = nil
	if n.Knows(addr) {
		t.Error("the same subnet behind another gateway is known")
	}
	// Home again, just after the link came up, before the gateway's
	// address is in the ARP table: known by the addresses.
	gw = ""
	n.gw = nil
	if !n.Knows(addr) {
		t.Error("home is not known before its gateway's address is")
	}
	// A network learned before its gateway's address was known is bound
	// to the first gateway seen there.
	other := netInterface{index: 7, name: "wlan0", prefixes: []netip.Prefix{netip.MustParsePrefix("10.1.0.2/16")}}
	ifc, gw = other, ""
	n.gw = nil
	n.learnAll()
	gw = "aa:aa:aa:aa:aa:aa"
	n.gw = nil
	if !n.Knows(netip.MustParseAddr("10.1.0.2")) {
		t.Error("a network learned without its gateway is not known once the gateway is")
	}
	gw = "bb:bb:bb:bb:bb:bb"
	n.gw = nil
	if n.Knows(netip.MustParseAddr("10.1.0.2")) {
		t.Error("a network bound to its gateway is known behind another one")
	}
	ifc = home
	// The list survives a restart.
	gw = "aa:bb:cc:dd:ee:ff"
	again := fakeNetworks(t, dir, true, &ifc, &gw)
	if !again.Knows(addr) {
		t.Error("the known networks were lost on a restart")
	}
}

func TestKnownNetworksAtUpdate(t *testing.T) {
	// A device in a group that has no list yet takes the networks it is on
	// as known; a device in no group does not.
	ifc := netInterface{index: 2, name: "eth0", prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")}}
	gw := "aa:bb:cc:dd:ee:01"
	addr := netip.MustParseAddr("10.0.0.5")
	if fakeNetworks(t, t.TempDir(), false, &ifc, &gw).Knows(addr) {
		t.Error("a device in no group knows the network it is on")
	}
	dir := t.TempDir()
	if !fakeNetworks(t, dir, true, &ifc, &gw).Knows(addr) {
		t.Error("an updated member does not know the network it is on")
	}
	if _, err := os.Stat(filepath.Join(dir, networksFile)); err != nil {
		t.Errorf("the list was not saved: %v", err)
	}
}

// A connection to a link-local address carries the interface as its zone,
// which the interface's own address has not: it is the same address.
func TestKnownNetworksLinkLocal(t *testing.T) {
	home := netInterface{index: 4, name: "en0", prefixes: []netip.Prefix{
		netip.MustParsePrefix("192.168.0.175/24"), netip.MustParsePrefix("fe80::1400:9600:8ed5:7ad4/64")}}
	ifc, gw := home, "aa:bb:cc:dd:ee:ff"
	n := fakeNetworks(t, t.TempDir(), false, &ifc, &gw)
	if !n.Learn(netip.MustParseAddr("192.168.0.175")) {
		t.Fatal("the network was not learned")
	}
	if a := netip.MustParseAddr("fe80::1400:9600:8ed5:7ad4%en0"); !n.Knows(a) {
		t.Errorf("Knows(%v) = false on the network learned", a)
	}
}
