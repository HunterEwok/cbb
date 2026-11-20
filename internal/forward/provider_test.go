// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"net/netip"
	"testing"
)

// addr6 returns an address of the IPv6 provider 2001:db8:p::/32 in its
// wide network w, network n, with the host h.
func addr6(p, w, n, h int) netip.Addr {
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, byte(p), 0, byte(w), 0, byte(n), 15: byte(h)})
}

// The registrations held or being set up are bounded by the network, the
// wide network and the IPv6 provider they come from, as the limits say.
func TestRegistrationsBoundByEveryLevel(t *testing.T) {
	l := Limits{Groups: 100, Connections: 100, PerAddress: 1, PerNetwork: 2, PerWide: 4, PerProvider: 8}
	f, _ := startForwarder(t, l)
	take := func(p, wides, networks, hosts int) int {
		f.mu.Lock()
		defer f.mu.Unlock()
		held := 0
		for w := range wides {
			for n := range networks {
				for h := range hosts {
					if f.from.Take(addr6(p, w, n, h+1), 1) {
						held++
					}
				}
			}
		}
		return held
	}
	for i, c := range []struct {
		name                   string
		wides, networks, hosts int
		want                   int
	}{
		{"the addresses of one network", 1, 1, 2 * l.PerNetwork, l.PerNetwork},
		{"the networks of one wide network", 1, 2 * l.PerWide / l.PerNetwork, l.PerNetwork, l.PerWide},
		{"the wide networks of one provider", 2 * l.PerProvider / l.PerWide, l.PerWide / l.PerNetwork, l.PerNetwork, l.PerProvider},
	} {
		if got := take(0xb8+i, c.wides, c.networks, c.hosts); got != c.want {
			t.Errorf("%s hold %d registrations, want %d", c.name, got, c.want)
		}
	}
	if take(0xf0, 1, 1, 1) != 1 {
		t.Error("another provider refused")
	}
}
