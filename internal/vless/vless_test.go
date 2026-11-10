// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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

// roundTrip sends a packet through the client and tells whether it came
// back. Each try sends from a port of its own: the client carries the
// packets of one source port in one flow, an XHTTP session of its own,
// for as long as packets keep coming, and Xray gives up on none of its
// requests, so a session whose first request got no answer would keep
// every later try from the same port too.
func roundTrip(t *testing.T, l tunnel.VLESS) bool {
	t.Helper()
	c, err := Dial(l)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 64)
	for range 10 {
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(c.Addr()))
		if err != nil {
			t.Fatal(err)
		}
		conn.Write([]byte("a packet"))
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(b)
		conn.Close()
		if err == nil {
			return string(b[:n]) == "a packet"
		}
	}
	return false
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
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	s, l := behindWebServerWith(t, ServerConfig{Listen: "127.0.0.1:0", Path: path, To: pc.LocalAddr().(*net.UDPAddr).AddrPort()}, "")
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
		l := l
		l.ID = id
		c, err := Dial(l)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		b := make([]byte, 64)
		for range 10 {
			// A port of its own for each try, as in roundTrip.
			conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(c.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte("who"))
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.Read(b)
			conn.Close()
			if err == nil {
				return string(b[:n])
			}
		}
		return ""
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
	return behindWebServerNaming(t, cfg, id, netip.Addr{})
}

// behindWebServerNaming is behindWebServerWith with a web server that
// names client as the client's address (vlesstest.WebServerNaming).
func behindWebServerNaming(t *testing.T, cfg ServerConfig, id string, client netip.Addr) (*Server, tunnel.VLESS) {
	t.Helper()
	path := cfg.Path
	s, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	back := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(s.Port())))
	web, cert := vlesstest.WebServerNaming(t, path, func() string { return back }, client)
	TrustForTests(cert)
	// A group's packets come under its own path.
	const group = "a-group-of-its-own"
	if err := s.AddPath(group); err != nil {
		t.Fatal(err)
	}
	return s, tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: path + "/" + group, ID: id}
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
	otherID := l
	otherID.ID, _ = tunnel.NewVLESSID()
	if roundTrip(t, otherID) {
		t.Fatal("another group's ID got through")
	}
	wrongName := l
	wrongName.ServerName = "www.example.org"
	if roundTrip(t, wrongName) {
		t.Fatal("a site whose certificate does not carry the name got through")
	}
	if err := s.RemoveUser(id); err != nil {
		t.Fatal(err)
	}
	if roundTrip(t, l) {
		t.Fatal("a group that was shut out got through")
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

// A registration stream reaches the forwarder's registrations, also with
// the registrations' user ID, which reaches neither the mirror nor the
// forwarder's UDP port.
func TestRegistrationStream(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	streams := make(chan net.Conn, 4)
	client := netip.MustParseAddr("203.0.113.7")
	var froms sync.Map
	cfg := ServerConfig{Listen: "127.0.0.1:0", Path: path, To: echo(t), Mirror: tcpEcho(t),
		Register: func(c net.Conn, from netip.Addr) {
			froms.Store(from, true)
			defer c.Close()
			b := make([]byte, 5)
			if _, err := io.ReadFull(c, b); err == nil && string(b) == "hello" {
				c.Write([]byte("hub!!"))
			}
			streams <- c
		}}
	_, l := behindWebServerNaming(t, cfg, RegistrationID, client)
	way, err := DialRegistration(l)
	if err != nil {
		t.Fatal(err)
	}
	defer way.Close()
	got := ""
	for range 10 {
		c, err := net.DialTimeout("tcp", way.Addr().String(), time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("hello"))
		b := make([]byte, 5)
		io.ReadFull(c, b)
		c.Close()
		if got = string(b); got == "hub!!" {
			break
		}
	}
	if got != "hub!!" {
		t.Fatalf("the registrations answered %q", got)
	}
	// The registration is charged to the address the web server named.
	froms.Range(func(k, _ any) bool {
		if k.(netip.Addr) != client {
			t.Errorf("a registration came from %v, not %v as the web server named it", k, client)
		}
		return true
	})
	if throughMirror(t, l) {
		t.Error("the registrations' user ID reached the mirror")
	}
	if roundTrip(t, l) {
		t.Error("the registrations' user ID reached the forwarder's UDP port")
	}
}

// Over XHTTP a group's packets pass only under a group's path: not under
// the path every build carries, nor under a path that is not let in.
func TestGroupPaths(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := tunnel.NewVLESSID()
	s, l := behindWebServer(t, path, id)
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	base, other := l, l
	base.Path = path
	other.Path = path + "/not-a-group-path-at-all"
	if roundTrip(t, base) {
		t.Error("a group's packets passed under the registrations' path")
	}
	if roundTrip(t, other) {
		t.Error("a group's packets passed under a path that is not let in")
	}
	s.RemovePath("a-group-of-its-own")
	if roundTrip(t, l) {
		t.Error("a group's packets passed under its path once it was taken back")
	}
	if err := s.AddPath("short"); err == nil {
		t.Error("a short group path was taken")
	}
}

// A port another socket holds is told apart, so that Listen picks other
// free ports then.
func TestAddrInUse(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, err = net.Listen("tcp", l.Addr().String())
	if err == nil || !addrInUse(err) {
		t.Errorf("addrInUse(%v) = false", err)
	}
	if addrInUse(errors.New("vless: something else")) {
		t.Error("another error counted as a port in use")
	}
}
