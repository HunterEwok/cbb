// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
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
	return behindWebServerWith(t, ServerConfig{Listen: "127.0.0.1:0", Path: path, To: echo(t)}, id)
}

func behindWebServerWith(t *testing.T, cfg ServerConfig, id string) (*Server, tunnel.VLESS) {
	t.Helper()
	path := cfg.Path
	s, err := Listen(cfg)
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

// The client's XHTTP drops its connections after a while and spaces its
// uploads at random, as Xray's own configuration does, rather than one
// connection for ever at a fixed rhythm.
func TestXHTTPClientShape(t *testing.T) {
	c := xhttpClient("example.com", "/abcdefgh")
	if c.Mode != "packet-up" || c.Host != "example.com" || c.Path != "/abcdefgh" {
		t.Fatalf("the client's XHTTP: %v", c)
	}
	if r := c.GetNormalizedScMinPostsIntervalMs(); r.From >= r.To {
		t.Errorf("the gap between uploads is fixed: %d to %d ms", r.From, r.To)
	}
	x := c.Xmux
	for name, r := range map[string]interface{ GetTo() int32 }{
		"connections": x.GetNormalizedMaxConnections(), "requests": x.GetNormalizedHMaxRequestTimes(),
		"seconds": x.GetNormalizedHMaxReusableSecs(),
	} {
		if r.GetTo() == 0 {
			t.Errorf("the %s of a connection are unlimited", name)
		}
	}
	if x.GetNormalizedHMaxRequestTimes().From >= x.GetNormalizedHMaxRequestTimes().To ||
		x.GetNormalizedHMaxReusableSecs().From >= x.GetNormalizedHMaxReusableSecs().To {
		t.Error("a connection is dropped after a fixed count")
	}
}

// A stranger with no VLESS user makes the server hold little: one upload
// carries at most MaxPostBytes, and a session keeps at most
// MaxBufferedPosts of them until its client shows up.
func TestXHTTPHoldsLittleForStrangers(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Listen(ServerConfig{Listen: "127.0.0.1:0", Path: path, To: echo(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	padding := "?x_padding=" + strings.Repeat("X", 500)
	// An upload that the server neither takes nor refuses waits for a
	// place in the queue: 0 here.
	client := &http.Client{Timeout: 2 * time.Second}
	post := func(session string, seq, size int) int {
		u := fmt.Sprintf("http://127.0.0.1:%d%s/%s/%d%s", s.Port(), path, session, seq, padding)
		resp, err := client.Post(u, "application/octet-stream", bytes.NewReader(make([]byte, size)))
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("a", 0, MaxPostBytes); code != http.StatusOK {
		t.Fatalf("an upload of the largest size: %d", code)
	}
	if code := post("b", 0, MaxPostBytes+1); code != http.StatusRequestEntityTooLarge {
		t.Errorf("an upload over the limit: %d", code)
	}
	// No client reads the session, so its uploads stay queued until the
	// queue is full; the next one waits (behind nginx, which bounds the
	// requests waiting) or is refused.
	refused := false
	for seq := 1; seq <= MaxBufferedPosts+1; seq++ {
		if post("a", seq, 1) != http.StatusOK {
			refused = true
			break
		}
	}
	if !refused {
		t.Errorf("a session with no client took more than %d uploads", MaxBufferedPosts)
	}
}

// tcpEcho answers every TCP connection with what it sends, in the
// mirror's place.
func tcpEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// throughMirror sends a line through the way to the mirror and tells
// whether it came back.
func throughMirror(t *testing.T, l tunnel.VLESS) bool {
	t.Helper()
	m, err := DialMirror(l)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for range 10 {
		c, err := net.DialTimeout("tcp", m.Addr().String(), time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("a line\n"))
		b := make([]byte, 7)
		_, err = io.ReadFull(c, b)
		c.Close()
		if err == nil {
			return string(b) == "a line\n"
		}
	}
	return false
}

// A registered group's client reaches the mirror over VLESS, and only
// the mirror; without one a TCP stream goes nowhere.
func TestMirrorThroughXHTTP(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := tunnel.NewVLESSID()
	s, l := behindWebServerWith(t, ServerConfig{Listen: "127.0.0.1:0", Path: path, To: echo(t), Mirror: tcpEcho(t)}, id)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if throughMirror(t, l) {
		t.Fatal("a group that was not let in reached the mirror")
	}
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	if !throughMirror(t, l) {
		t.Fatal("nothing came back from the mirror")
	}
	if !roundTrip(t, l) {
		t.Fatal("the packets stopped with a mirror")
	}

	path2, _ := tunnel.NewVLESSPath()
	none, l2 := behindWebServerWith(t, ServerConfig{Listen: "127.0.0.1:0", Path: path2, To: echo(t)}, id)
	if err := none.AddUser(id); err != nil {
		t.Fatal(err)
	}
	if throughMirror(t, l2) {
		t.Fatal("a TCP stream went somewhere without a mirror")
	}
}
