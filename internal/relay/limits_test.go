// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/budget"
)

// posing is a listener that gives each accepted connection the source
// address its client's port was given, so a test on the loopback address
// can play connections from many addresses.
type posing struct {
	net.Listener
	mu       sync.Mutex
	as       map[uint16]netip.Addr // by the client's port
	other    netip.Addr            // for every other client
	accepted chan struct{}         // a value for each connection accepted
}

type posedConn struct {
	net.Conn
	addr net.Addr
}

func (c posedConn) RemoteAddr() net.Addr { return c.addr }

func (l *posing) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	port := netip.MustParseAddrPort(c.RemoteAddr().String()).Port()
	l.mu.Lock()
	a, ok := l.as[port]
	if !ok {
		a = l.other
	}
	l.mu.Unlock()
	select {
	case l.accepted <- struct{}{}:
	default:
	}
	return posedConn{c, net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, port))}, nil
}

// dialAs opens a connection to the relay that it takes as one from a, and
// waits until the relay accepted it: a backlog that fills up resets new
// connections on some systems (FreeBSD, Windows) instead of holding them.
func (l *posing) dialAs(t *testing.T, a netip.Addr) net.Conn {
	t.Helper()
	l.mu.Lock()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		l.mu.Unlock()
		t.Fatal(err)
	}
	l.as[netip.MustParseAddrPort(c.LocalAddr().String()).Port()] = a
	l.mu.Unlock()
	t.Cleanup(func() { c.Close() })
	select {
	case <-l.accepted:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the relay to accept a connection")
	}
	return c
}

// startPosing runs an open relay behind a posing listener, whose
// registrations may take setupWait to be set up.
func startPosing(t *testing.T, setupWait time.Duration) (*Relay, *posing, Link) {
	t.Helper()
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Listen(Config{Listen: "127.0.0.1:0", Keys: keys, Open: true, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	l := &posing{Listener: r.tcp, as: map[uint16]netip.Addr{}, accepted: make(chan struct{}, 1), other: netip.MustParseAddr("198.51.100.20")}
	r.tcp = l
	r.setupWait = setupWait
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return r, l, Link{Endpoint: netip.MustParseAddrPort(r.Addr().String()), Pin: keys.Pin()}
}

func (r *Relay) settingNow() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.setups.Held(netip.Addr{}, budget.All)
}

// Connections that never finish their setup hold only their address's and
// network's share of the setups, and devices from elsewhere still register
// and reach each other. The setups never time out here, so that on a slow
// machine the first ones are still held when the last are counted.
func TestSetupsBoundByAddress(t *testing.T) {
	r, l, link := startPosing(t, time.Hour)
	one := netip.MustParseAddr("203.0.113.7")
	for range maxSetupsAddress + 10 {
		l.dialAs(t, one)
	}
	waitFor(t, "the setups from one address", func() bool { return r.settingNow() == maxSetupsAddress })
	// Many addresses of one network.
	for i := range maxSetupsNetwork + 10 {
		l.dialAs(t, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	waitFor(t, "the setups from one network", func() bool { return r.settingNow() == maxSetupsAddress+maxSetupsNetwork })
	time.Sleep(100 * time.Millisecond)
	if n := r.settingNow(); n != maxSetupsAddress+maxSetupsNetwork {
		t.Fatalf("%d setups held, want %d", n, maxSetupsAddress+maxSetupsNetwork)
	}

	g := newGroup(t)
	a, b := newDevice(t, g), newDevice(t, g)
	if a.id > b.id {
		a, b = b, a
	}
	ja, jb := join(t, link, a), join(t, link, b)
	if got := receive(t, jb.called, "b's call"); got != a.id {
		t.Fatalf("b was called by %s, want %s", got, a.id)
	}
	if got := receive(t, ja.dialed, "a's dial"); got != b.id {
		t.Fatalf("a dialed %s, want %s", got, b.id)
	}
}

// A device's requests in its tunnel take only its own share of the
// requests being read, so one device cannot hold up the others'.
func TestRequestsBoundByDevice(t *testing.T) {
	r := newRequestRelay()
	a, b := &member{from: netip.MustParseAddr("192.0.2.1")}, &member{from: netip.MustParseAddr("198.51.100.1")}
	r.mu.Lock()
	defer r.mu.Unlock()
	for range maxRequestsOne {
		if !r.takeRequestLocked(a) {
			t.Fatal("a device's request refused within its share")
		}
	}
	if r.takeRequestLocked(a) {
		t.Fatal("a device's request taken beyond its share")
	}
	if !r.takeRequestLocked(b) {
		t.Fatal("another device's request refused")
	}
	b.dropped = true
	if r.takeRequestLocked(b) {
		t.Fatal("a request taken for a dropped device")
	}
}

// noAddrConn is a connection that has no remote address any more.
type noAddrConn struct{ net.Conn }

func (noAddrConn) RemoteAddr() net.Addr { return nil }

// A connection without a remote address has the zero address, which no
// device is registered under.
func TestAddrOfWithoutAddress(t *testing.T) {
	if a := addrOf(noAddrConn{}); a.IsValid() {
		t.Fatalf("addrOf of a connection without an address: %v", a)
	}
}
