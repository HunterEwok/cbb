// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/dokodemo"

	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

// outside stands for the internet, and for any service on the forwarder's
// own server: a UDP and a TCP port on the loopback address that count what
// reaches them and answer so that it would be seen.
type outside struct {
	udp, tcp netip.AddrPort
	packets  atomic.Int64
	streams  atomic.Int64
}

func newOutside(t *testing.T) *outside {
	t.Helper()
	o := &outside{}
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	o.udp = pc.LocalAddr().(*net.UDPAddr).AddrPort()
	go func() {
		b := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			o.packets.Add(1)
			pc.WriteToUDPAddrPort([]byte("the internet"), from)
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	o.tcp = ln.Addr().(*net.TCPAddr).AddrPort()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o.streams.Add(1)
			c.Write([]byte("the internet\n"))
			c.Close()
		}
	}()
	return o
}

// check fails the test if anything reached the outside.
func (o *outside) check(t *testing.T) {
	t.Helper()
	if n := o.packets.Load(); n != 0 {
		t.Errorf("%d packets reached an address a client asked for", n)
	}
	if n := o.streams.Load(); n != 0 {
		t.Errorf("%d streams reached an address a client asked for", n)
	}
}

// hostile starts a client's side that asks the forwarder's side for the
// target, over the network, as a client that is not ours could: our own
// clients name an address that means nothing. It returns the local port
// that leads there.
func hostile(t *testing.T, l tunnel.VLESS, network xnet.Network, host string, port uint16) netip.AddrPort {
	t.Helper()
	var addr netip.AddrPort
	if network == xnet.Network_UDP {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = pc.LocalAddr().(*net.UDPAddr).AddrPort()
		pc.Close()
	} else {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = ln.Addr().(*net.TCPAddr).AddrPort()
		ln.Close()
	}
	in := &dokodemo.Config{
		RewriteAddress:  xnet.NewIPOrDomain(xnet.ParseAddress(host)),
		RewritePort:     uint32(port),
		AllowedNetworks: []xnet.Network{network},
	}
	inst, err := startClient(l, addr, in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	return addr
}

// packetBack sends a packet to the local port and returns the first
// answer, or "".
func packetBack(t *testing.T, to netip.AddrPort) string {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := make([]byte, 64)
	for range 10 {
		conn.Write([]byte("a packet"))
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := conn.Read(b); err == nil {
			return string(b[:n])
		}
	}
	return ""
}

// lineBack sends a line over TCP to the local port and returns what came
// back, or "".
func lineBack(t *testing.T, to netip.AddrPort) string {
	t.Helper()
	for range 3 {
		c, err := net.DialTimeout("tcp", to.String(), time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("a line\n"))
		b := make([]byte, 13)
		n, _ := io.ReadAtLeast(c, b, 7)
		c.Close()
		if n > 0 {
			return string(b[:n])
		}
	}
	return ""
}

// targets are what a hostile client asks for: the outside's ports, a
// service on the forwarder's own server, public addresses and a name.
func targets(o *outside, network xnet.Network) []netip.AddrPort {
	own := o.tcp
	if network == xnet.Network_UDP {
		own = o.udp
	}
	return []netip.AddrPort{
		own,
		netip.MustParseAddrPort("127.0.0.1:10041"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
	}
}

// onlyCBB checks a forwarder's side, running with a mirror, as a hostile
// client of a group that is let in: a UDP packet to any address reaches
// only the forwarder's port, a TCP stream to any address only the mirror,
// and the registrations' user ID neither.
func onlyCBB(t *testing.T, s *Server, l tunnel.VLESS, o *outside) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	for _, to := range targets(o, xnet.Network_UDP) {
		if got := packetBack(t, hostile(t, l, xnet.Network_UDP, to.Addr().String(), to.Port())); got != "a packet" {
			t.Errorf("a packet to %v: the answer %q did not come from the forwarder's port", to, got)
		}
	}
	if got := packetBack(t, hostile(t, l, xnet.Network_UDP, "example.com", 53)); got != "a packet" {
		t.Errorf("a packet to a name: the answer %q did not come from the forwarder's port", got)
	}
	for _, to := range targets(o, xnet.Network_TCP) {
		if got := lineBack(t, hostile(t, l, xnet.Network_TCP, to.Addr().String(), to.Port())); got != "a line\n" {
			t.Errorf("a stream to %v: the answer %q did not come from the mirror", to, got)
		}
	}
	if got := lineBack(t, hostile(t, l, xnet.Network_TCP, "example.com", 80)); got != "a line\n" {
		t.Errorf("a stream to a name: the answer %q did not come from the mirror", got)
	}
	// RegistrationPort without registrations is any other port: the
	// mirror.
	if got := lineBack(t, hostile(t, l, xnet.Network_TCP, "127.0.0.1", RegistrationPort)); got != "a line\n" {
		t.Errorf("a stream to the registrations' port without registrations: the answer %q did not come from the mirror", got)
	}
	reg := l
	reg.ID = RegistrationID
	if l.Transport == tunnel.TransportXHTTP {
		reg.Path = tunnel.RegistrationPath(l.Path)
	}
	if got := packetBack(t, hostile(t, reg, xnet.Network_UDP, o.udp.Addr().String(), o.udp.Port())); got != "" {
		t.Errorf("the registrations' user ID sent a packet somewhere: %q", got)
	}
	if got := lineBack(t, hostile(t, reg, xnet.Network_TCP, o.tcp.Addr().String(), o.tcp.Port())); got != "" {
		t.Errorf("the registrations' user ID reached a stream: %q", got)
	}
	o.check(t)
}

// A client of a group, asking the forwarder's side over REALITY for any
// address, TCP or UDP, reaches only the forwarder and the mirror.
func TestOnlyCBBThroughREALITY(t *testing.T) {
	o := newOutside(t)
	var key [32]byte
	rand.Read(key[:])
	s, err := Listen(ServerConfig{Listen: "127.0.0.1:0", Dest: vlesstest.Decoy(t), ServerName: vlesstest.Site, Key: key,
		To: echo(t), Mirror: tcpEcho(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	id, _ := tunnel.NewVLESSID()
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	onlyCBB(t, s, link(t, s, key, id), o)
}

// The same over XHTTP behind a web server.
func TestOnlyCBBThroughXHTTP(t *testing.T) {
	o := newOutside(t)
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := tunnel.NewVLESSID()
	s, l := behindWebServerWith(t, ServerConfig{Listen: "127.0.0.1:0", Path: path, To: echo(t), Mirror: tcpEcho(t)}, id)
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	onlyCBB(t, s, l, o)
}

// Without a mirror a TCP stream to any address goes nowhere.
func TestNoMirrorNoStreams(t *testing.T) {
	o := newOutside(t)
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := tunnel.NewVLESSID()
	s, l := behindWebServerWith(t, ServerConfig{Listen: "127.0.0.1:0", Path: path, To: echo(t)}, id)
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	for _, to := range targets(o, xnet.Network_TCP) {
		if got := lineBack(t, hostile(t, l, xnet.Network_TCP, to.Addr().String(), to.Port())); got != "" {
			t.Errorf("a stream to %v without a mirror got %q", to, got)
		}
	}
	o.check(t)
}
