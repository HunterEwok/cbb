// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// A flood of handshakes over VLESS from the clients of one group, over
// many connections, leaves the clients of another group over VLESS their
// own budget, and the budget of all sources.
func TestVLESSUsersScanApart(t *testing.T) {
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, VLESS: &VLESSConfig{Listen: "127.0.0.1:0", XHTTP: testXHTTP()}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The VLESS side sends the flooding group's packets from ports below
	// 40000, the other group's from those above.
	f.mu.Lock()
	f.vlessUser = func(a netip.AddrPort) (string, bool) {
		if !a.Addr().IsLoopback() {
			return "", false
		}
		if a.Port() < 40000 {
			return "flooding group", true
		}
		return "other group", true
	}
	f.mu.Unlock()
	for i := range 200 {
		fakeReg(f, fmt.Sprintf("group %d", i), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(8000+i)))
	}
	// The flooding group's VLESS user ID is the first group's; the other
	// group's clients come to the victim's hub.
	f.mu.Lock()
	vlessUser(f, f.regs["group 0"], "flooding group")
	f.mu.Unlock()
	victim, pub := fakeReg(f, "victim", netip.MustParseAddrPort("198.51.100.2:8764"))
	f.mu.Lock()
	vlessUser(f, victim, "other group")
	f.mu.Unlock()
	now := time.Now()
	var nobody [32]byte
	rand.Read(nobody[:])
	if _, ok := f.route(netip.MustParseAddrPort("127.0.0.1:50000"), initiation(pub, 1), now); !ok {
		t.Fatal("a handshake over VLESS was dropped before any flood")
	}
	for i := range 8000 {
		f.route(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(30000+i%1000)), initiation(nobody, uint32(i)), now)
	}
	if _, ok := f.route(netip.MustParseAddrPort("127.0.0.1:50001"), initiation(pub, 2), now); !ok {
		t.Fatal("a handshake of another group's client over VLESS was dropped after a flood")
	}
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.10:4000"), initiation(pub, 3), now); !ok {
		t.Fatal("a direct client's handshake was dropped after a flood over VLESS")
	}
}

// vlessUser gives the group of r the VLESS user ID user, as a registration
// with it does; the caller holds f.mu.
func vlessUser(f *Forwarder, r *reg, user string) {
	r.vlessID = user
	f.byVLESS[user] = r
}

// The clients over VLESS of however many groups, each flooding the
// forwarder with handshakes, leave the scan budget to the clients of every
// other group, over VLESS and not: a client over VLESS reaches only its own
// group's hub, so its handshakes are checked against that group alone.
func TestVLESSUsersLeaveTheScanBudget(t *testing.T) {
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits
	limits.ScanRate = 4000 // with 200 groups, the burst of 40 handshakes to an unknown group
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits,
		VLESS: &VLESSConfig{Listen: "127.0.0.1:0", XHTTP: testXHTTP()}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Each VLESS client's packets come from a loopback port; the port's
	// hundreds tell its group's user ID.
	f.mu.Lock()
	f.vlessUser = func(a netip.AddrPort) (string, bool) {
		if !a.Addr().IsLoopback() {
			return "", false
		}
		return fmt.Sprintf("user %d", a.Port()/100), true
	}
	f.mu.Unlock()
	const users = 64
	for i := range 200 {
		r, _ := fakeReg(f, fmt.Sprintf("group %d", i), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(8000+i)))
		if i < users {
			f.mu.Lock()
			vlessUser(f, r, fmt.Sprintf("user %d", 100+i))
			f.mu.Unlock()
		}
	}
	victim, pub := fakeReg(f, "victim", netip.MustParseAddrPort("198.51.100.2:8764"))
	f.mu.Lock()
	vlessUser(f, victim, "user 600")
	f.mu.Unlock()
	now := time.Now()
	var nobody [32]byte
	rand.Read(nobody[:])
	for u := range users {
		for i := range 8 {
			from := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16((100+u)*100+i))
			f.route(from, initiation(nobody, uint32(u*8+i)), now)
		}
	}
	if _, ok := f.route(netip.MustParseAddrPort("127.0.0.1:60000"), initiation(pub, 1), now); !ok {
		t.Error("a client of another group over VLESS was dropped after the flood")
	}
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.10:4000"), initiation(pub, 2), now); !ok {
		t.Error("a direct client was dropped after the flood over VLESS")
	}
	// A client over VLESS reaches no other group's hub.
	if _, ok := f.route(netip.MustParseAddrPort("127.0.0.1:10000"), initiation(pub, 3), now); ok {
		t.Error("a client over VLESS reached the hub of a group whose user ID it has not")
	}
}

// A client that already has a session with its group makes its next
// handshake from the same address without the scan budget, so a flood of
// handshakes to unknown groups from every network does not cut it off.
func TestKnownClientKeepsItsGroup(t *testing.T) {
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits
	limits.ScanRate = 400 // with 100 groups, the burst of 8 handshakes to an unknown group
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := range 99 {
		fakeReg(f, fmt.Sprintf("group %d", i), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(8000+i)))
	}
	hub := netip.MustParseAddrPort("198.51.100.2:8764")
	_, pub := fakeReg(f, "victim", hub)
	now := time.Now()
	client := netip.MustParseAddrPort("192.0.2.10:51820")
	if _, ok := f.route(client, initiation(pub, 1), now); !ok {
		t.Fatal("the client's first handshake was dropped")
	}
	if _, ok := f.route(hub, response(100, 1), now); !ok {
		t.Fatal("the hub's answer was dropped")
	}
	var nobody [32]byte
	rand.Read(nobody[:])
	for i := range 1000 {
		from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(1 + i/256), byte(i), 0, 1}), 4000)
		f.route(from, initiation(nobody, uint32(i)), now)
	}
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.10:4000"), initiation(pub, 2), now); ok {
		t.Fatal("the flood left the scan budget; the test shows nothing")
	}
	if _, ok := f.route(client, initiation(pub, 3), now); !ok {
		t.Error("the client's next handshake was dropped after the flood")
	}
}

// Addresses that fill the tables of sources and networks do not keep a
// new client's handshake out: the table drops the entry used least
// recently, and stays at its bound.
func TestSourceTablesKeepNewClients(t *testing.T) {
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits
	limits.Groups = 100
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, pub := fakeReg(f, "victim", netip.MustParseAddrPort("198.51.100.2:8764"))
	now := time.Now()
	var nobody [32]byte
	rand.Read(nobody[:])
	for i := 0; i < 5*limits.Groups; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		f.route(netip.AddrPortFrom(a, 1000), initiation(nobody, uint32(i)), now)
	}
	f.mu.Lock()
	sources, nets := f.sources.len(), f.netScans.len()
	f.mu.Unlock()
	if sources > 4*limits.Groups || nets > 4*limits.Groups {
		t.Fatalf("tables hold %d sources and %d networks, over the bound %d", sources, nets, 4*limits.Groups)
	}
	if _, ok := f.route(netip.MustParseAddrPort("192.0.2.77:40000"), initiation(pub, 2), now); !ok {
		t.Fatal("a new client's handshake was dropped while the tables were full")
	}
}
