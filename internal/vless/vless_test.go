// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

// echo answers every UDP packet with itself, in the forwarder's place.
func echo(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			pc.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func server(t *testing.T) (*Server, [32]byte) {
	t.Helper()
	var key [32]byte
	rand.Read(key[:])
	s, err := Listen(ServerConfig{Listen: "127.0.0.1:0", Dest: vlesstest.Decoy(t), ServerName: vlesstest.Site, Key: key, To: echo(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, key
}

func link(t *testing.T, s *Server, key [32]byte, id string) tunnel.VLESS {
	t.Helper()
	pub, err := PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return tunnel.VLESS{Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Port()), PublicKey: pub,
		ShortID: ShortID(key), ServerName: vlesstest.Site, ID: id}
}

// roundTrip sends a packet through the client and tells whether it came
// back.
func roundTrip(t *testing.T, l tunnel.VLESS) bool {
	t.Helper()
	c, err := Dial(l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(c.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := make([]byte, 64)
	for range 10 {
		conn.Write([]byte("a packet"))
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := conn.Read(b); err == nil {
			return string(b[:n]) == "a packet"
		}
	}
	return false
}

func TestThroughVLESS(t *testing.T) {
	s, key := server(t)
	id, err := tunnel.NewVLESSID()
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip(t, link(t, s, key, id)) {
		t.Fatal("a group that was not let in got through")
	}
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	if !roundTrip(t, link(t, s, key, id)) {
		t.Fatal("nothing came back")
	}
	other, _ := tunnel.NewVLESSID()
	if roundTrip(t, link(t, s, key, other)) {
		t.Fatal("another group's ID got through")
	}
	var wrong [32]byte
	rand.Read(wrong[:])
	if roundTrip(t, link(t, s, wrong, id)) {
		t.Fatal("a client with another REALITY key got through")
	}
	if err := s.RemoveUser(id); err != nil {
		t.Fatal(err)
	}
	if roundTrip(t, link(t, s, key, id)) {
		t.Fatal("a group that was shut out got through")
	}
}

// TestProbe checks that whoever is not a client sees the borrowed site.
func TestProbe(t *testing.T) {
	s, _ := server(t)
	c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(s.Port()))), &tls.Config{ServerName: vlesstest.Site, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("a probe: %v", err)
	}
	defer c.Close()
	if names := c.ConnectionState().PeerCertificates[0].DNSNames; len(names) != 1 || names[0] != vlesstest.Site {
		t.Fatalf("a probe got the certificate for %v", names)
	}
}

// TestUserOfEachClient checks that the forwarder's side tells the clients
// of one VLESS user from those of another by the loopback port their
// packets come from.
func TestUserOfEachClient(t *testing.T) {
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var key [32]byte
	rand.Read(key[:])
	s, err := Listen(ServerConfig{Listen: "127.0.0.1:0", Dest: vlesstest.Decoy(t), ServerName: vlesstest.Site, Key: key, To: pc.LocalAddr().(*net.UDPAddr).AddrPort()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	// The forwarder's port answers each packet with the user it came from.
	go func() {
		b := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			u, _ := s.User(from)
			pc.WriteToUDPAddrPort([]byte(u), from)
		}
	}()
	ask := func(id string) string {
		c, err := Dial(link(t, s, key, id))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(c.Addr()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		b := make([]byte, 64)
		for range 10 {
			conn.Write([]byte("who"))
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if n, err := conn.Read(b); err == nil {
				return string(b[:n])
			}
		}
		return ""
	}
	// A client that comes before the server has learned the site's
	// handshakes waits for it, longer than ask does.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := tunnel.NewVLESSID()
	b, _ := tunnel.NewVLESSID()
	for _, id := range []string{a, b} {
		if err := s.AddUser(id); err != nil {
			t.Fatal(err)
		}
	}
	if got := ask(a); got != a {
		t.Errorf("a client of %s came as %q", a, got)
	}
	if got := ask(b); got != b {
		t.Errorf("a client of %s came as %q", b, got)
	}
	if u, ok := s.User(netip.MustParseAddrPort("192.0.2.1:1")); ok {
		t.Errorf("an address that is not the loopback came as %q", u)
	}
}

// behindWebServer runs XHTTP behind a TLS web server that passes the path
// to it, as nginx would on the forwarder's site, and returns the link for
// the group id.
func behindWebServer(t *testing.T, path, id string) (*Server, tunnel.VLESS) {
	t.Helper()
	s, err := Listen(ServerConfig{Listen: "127.0.0.1:0", Path: path, To: echo(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	back := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(s.Port())))
	web, cert := vlesstest.WebServer(t, path, func() string { return back })
	TrustForTests(cert)
	return s, tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: path, ID: id}
}

func TestThroughXHTTP(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := tunnel.NewVLESSID()
	s, l := behindWebServer(t, path, id)
	if err := l.Check(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if roundTrip(t, l) {
		t.Fatal("a group that was not let in got through")
	}
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	if !roundTrip(t, l) {
		t.Fatal("nothing came back")
	}
	other := l
	other.Path = path + "x"
	if roundTrip(t, other) {
		t.Fatal("another path got through")
	}
	wrongName := l
	wrongName.ServerName = "www.example.org"
	if roundTrip(t, wrongName) {
		t.Fatal("a site whose certificate does not carry the name got through")
	}
}
