// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/budget"
)

// from6 returns an address of the IPv6 provider 2001:db8::/32 in its wide
// network w, network n, with the host h.
func from6(w, n, h int) netip.Addr {
	return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(w), 0, byte(n), 14: byte(h >> 8), 15: byte(h)})
}

// The setups from the wide networks of one IPv6 provider are bounded by the
// provider's share, below the relay's total, and leave room for another
// provider.
func TestSetupsBoundByProvider(t *testing.T) {
	const wides = 3
	perWide := maxSetupsWide / maxSetupsNetwork
	if wides*maxSetupsWide <= maxSetupsProvider || maxSetupsProvider >= maxSetups {
		t.Fatal("the wide networks must hold more than the provider's share, and the share less than all")
	}
	r := &Relay{setups: budget.NewCount(setupCaps), allow: newAllowance(), now: func() time.Time { return time.Unix(1000, 0) }}
	held := 0
	for w := range wides {
		for n := range perWide {
			for i := range maxSetupsNetwork {
				if r.takeSlot(from6(w, n, i+1)) {
					held++
				}
			}
		}
	}
	if held != maxSetupsProvider {
		t.Errorf("the wide networks of one provider hold %d setups, want %d", held, maxSetupsProvider)
	}
	if !r.takeSlot(netip.MustParseAddr("2001:db9::1")) {
		t.Error("another provider refused")
	}
}

// The requests being read are also counted by the IPv6 provider the
// devices registered from, so the wide networks of one provider cannot take
// all the slots between them.
func TestRequestsBoundByProvider(t *testing.T) {
	const wides = 4
	if wides*maxRequestsWide <= maxRequestsProv || maxRequestsProv >= maxRequests {
		t.Fatal("the wide networks must hold more than the provider's share, and the share less than all")
	}
	r := newRequestRelay()
	got := 0
	for w := range wides {
		for h := range maxRequestsWide / maxRequestsSource {
			from := from6(w, 0, h+1)
			for range maxRequestsSource / maxRequestsOne {
				m := &member{from: from, greads: new(int)}
				r.mu.Lock()
				for range maxRequestsOne {
					if r.takeRequestLocked(m) {
						got++
					}
				}
				r.mu.Unlock()
			}
		}
	}
	if got != maxRequestsProv {
		t.Errorf("the wide networks of one provider hold %d requests, want %d", got, maxRequestsProv)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.takeRequestLocked(&member{from: netip.MustParseAddr("2001:db9::1"), greads: new(int)}) {
		t.Error("a device from another provider refused")
	}
}

// The records an open relay keeps are bounded by the wide network and by
// the IPv6 provider they came from, each a few groups' worth.
func TestRecordCapsOfWideNetworkAndProvider(t *testing.T) {
	l := DefaultOpenLimits
	g := l.GroupRecordBytes
	caps := l.recordCaps()
	if caps.Wide != 16*g || caps.Provider != 64*g || caps.All <= caps.Provider {
		t.Fatalf("record caps %+v for a group's %d bytes", caps, g)
	}
	fill := func(c *budget.Count, wides, networks int) int {
		held := 0
		for w := range wides {
			for n := range networks {
				for c.Take(from6(w, n, 1), g) {
					held += g
				}
			}
		}
		return held
	}
	// The networks of one wide network hold its share between them.
	if got := fill(budget.NewCount(caps), 1, 2*caps.Wide/caps.Network); got != caps.Wide {
		t.Errorf("the networks of one wide network hold %d bytes, want %d", got, caps.Wide)
	}
	// The wide networks of one provider hold its share between them.
	c := budget.NewCount(caps)
	if got := fill(c, 2*caps.Provider/caps.Wide, caps.Wide/caps.Network); got != caps.Provider {
		t.Errorf("the wide networks of one provider hold %d bytes, want %d", got, caps.Provider)
	}
	if !c.Take(netip.MustParseAddr("2001:db9::1"), g) {
		t.Error("another provider refused")
	}
}

// The work an IPv6 provider may start is bounded by its own allowance,
// whatever wide networks of it ask.
func TestAllowanceBoundByProvider(t *testing.T) {
	now := time.Unix(1000, 0)
	a := newAllowance()
	const chunk = 1024
	took := 0.0
	for w := range 3 {
		for n := range int(wideBurst / chunk) {
			if a.Take(from6(w, n, 1), chunk, now) {
				took += chunk
			}
		}
	}
	if took != providerBurst {
		t.Errorf("the wide networks of one provider took %v units, want %v", took, providerBurst)
	}
	if !a.Take(netip.MustParseAddr("2001:db9::1"), chunk, now) {
		t.Error("another provider refused")
	}
	// A second later the provider has earned its rate, and no more.
	later := now.Add(time.Second)
	for n := range int(providerRate / chunk) {
		if !a.Take(from6(9, n, 1), chunk, later) {
			t.Fatalf("network %d of a new wide network refused what the provider earned", n)
		}
	}
	if a.Take(from6(9, 99, 1), 1, later) {
		t.Error("the provider took more than it earned in a second")
	}
}
