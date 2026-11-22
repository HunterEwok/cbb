// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

func startForwarder(t *testing.T, limits Limits) (*Forwarder, string) {
	return startForwarderWith(t, Config{Limits: limits})
}

func startForwarderWith(t *testing.T, cfg Config) (*Forwarder, string) {
	t.Helper()
	if cfg.Cert.Certificate == nil {
		cert, err := NewCert()
		if err != nil {
			t.Fatal(err)
		}
		cfg.Cert = cert
	}
	cfg.Listen = "127.0.0.1:0"
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	f, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := f.Serve(ctx); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return f, Pin(cfg.Cert.Leaf)
}

type hubSide struct {
	hub     *tunnel.Hub
	key     tunnel.Key
	addr    netip.Addr
	obf     *tunnel.Obfuscation
	vless   *tunnel.VLESS // how the hub's clients reach the forwarder over VLESS
	reports chan Report
}

// startHub brings up a hub for the clients and registers it with the
// forwarder; it returns once the forwarder saw the hub's port.
func startHub(t *testing.T, f *Forwarder, pin string, clients []tunnel.Peer, obf *tunnel.Obfuscation) *hubSide {
	return startHubWith(t, f, pin, clients, HubConfig{Obfuscation: obf})
}

// startHubWith is startHub with more of the hub's configuration.
func startHubWith(t *testing.T, f *Forwarder, pin string, clients []tunnel.Peer, hc HubConfig) *hubSide {
	obf := hc.Obfuscation
	t.Helper()
	_, _, g := member(t)
	key, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := tunnel.Addr(string(group.NewDeviceID()))
	if err != nil {
		t.Fatal(err)
	}
	h, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: key, Addr: addr, Peers: clients, Obfuscation: obf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	hs := &hubSide{hub: h, key: key, addr: addr, obf: obf, reports: make(chan Report, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		link := Link{Endpoint: f.Addr(), Pin: pin}
		if hc.Link.Endpoint.IsValid() {
			link.Endpoint = hc.Link.Endpoint
		}
		Register(ctx, HubConfig{Link: link, Key: key, Obfuscation: obf, VLESSID: hc.VLESSID, VLESS: hc.VLESS,
			Credentials: g.credentials(t), HubCert: g.hubCert(), Send: h.Send, Report: func(r Report) {
				select {
				case hs.reports <- r:
				default:
				}
			}})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-hs.reports:
			if r.Err != nil {
				t.Fatalf("registering: %v", r.Err)
			}
			if r.VLESS != nil {
				hs.vless = r.VLESS
			}
			if r.Seen.IsValid() {
				if r.OverVLESS != (hc.VLESS != nil && hc.Link.Endpoint.IsValid()) {
					t.Fatalf("over VLESS: %v", r.OverVLESS)
				}
				// Over VLESS the forwarder sees the hub at the port its
				// side of VLESS sends the hub's packets from.
				if !r.OverVLESS && r.Seen.Port() != uint16(h.UDPPort()) {
					t.Fatalf("the forwarder sees the hub at %v, not on its port %d", r.Seen, h.UDPPort())
				}
				return hs
			}
		case <-deadline:
			t.Fatal("the forwarder never saw the hub's port")
		}
	}
}

func newClient(t *testing.T) (tunnel.Key, tunnel.Peer) {
	t.Helper()
	key, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := tunnel.NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := tunnel.Addr(string(group.NewDeviceID()))
	if err != nil {
		t.Fatal(err)
	}
	return key, tunnel.Peer{PublicKey: key.Public(), PresharedKey: psk, Addr: addr}
}

// roundTrip connects a client through the forwarder to the hub and back.
func roundTrip(t *testing.T, f *Forwarder, hs *hubSide, key tunnel.Key, peer tunnel.Peer) error {
	t.Helper()
	return roundTripTo(t, f.Addr(), hs, key, peer)
}

// roundTripTo is roundTrip with the client sending to ep.
func roundTripTo(t *testing.T, ep netip.AddrPort, hs *hubSide, key tunnel.Key, peer tunnel.Peer) error {
	t.Helper()
	c, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: key, PresharedKey: peer.PresharedKey, Addr: peer.Addr,
		HubPublicKey: hs.key.Public(), HubAddr: hs.addr, Endpoint: ep, Obfuscation: hs.obf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := hs.hub.Listener().Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	// WireGuard sends a lost handshake again only after 5 s, and through
	// VLESS the first ones can be lost while Xray connects; on a loaded
	// runner 10 s left room for just one retry.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer server.Close()
	if from := server.RemoteAddr().(*net.TCPAddr).AddrPort().Addr(); from != peer.Addr {
		t.Fatalf("the hub got a connection from %v, not %v", from, peer.Addr)
	}
	go io.Copy(server, server)
	if _, err := conn.Write([]byte("clipboard")); err != nil {
		return err
	}
	buf := make([]byte, 9)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "clipboard" {
		t.Fatalf("got %q back", buf)
	}
	return nil
}

func newObfuscation(t *testing.T) *tunnel.Obfuscation {
	t.Helper()
	o, err := tunnel.NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestThroughForwarder(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	key, peer := newClient(t)
	hs := startHub(t, f, pin, []tunnel.Peer{peer}, nil)
	if err := roundTrip(t, f, hs, key, peer); err != nil {
		t.Fatal(err)
	}
}

func TestObfuscatedThroughForwarder(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	key, peer := newClient(t)
	hs := startHub(t, f, pin, []tunnel.Peer{peer}, newObfuscation(t))
	if err := roundTrip(t, f, hs, key, peer); err != nil {
		t.Fatal(err)
	}
}

// TestGroupsApart runs two plain groups and two obfuscated ones through one
// forwarder.
func TestGroupsApart(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	for i, obf := range []*tunnel.Obfuscation{nil, newObfuscation(t), nil, newObfuscation(t)} {
		key, peer := newClient(t)
		hs := startHub(t, f, pin, []tunnel.Peer{peer}, obf)
		if err := roundTrip(t, f, hs, key, peer); err != nil {
			t.Fatalf("group %d: %v", i, err)
		}
	}
}

// initiation returns a handshake initiation addressed to pub, with the
// sender index idx: the rest is random, which the forwarder cannot tell.
func initiation(pub [32]byte, idx uint32) []byte {
	p := make([]byte, initiationSize)
	rand.Read(p)
	p[0], p[1], p[2], p[3] = msgInitiation, 0, 0, 0
	binary.LittleEndian.PutUint32(p[4:8], idx)
	k := mac1Key(pub)
	h, _ := blake2s.New128(k[:])
	h.Write(p[:initiationSize-32])
	h.Sum(p[:initiationSize-32])
	return p
}

func response(hubIdx, clientIdx uint32) []byte {
	p := make([]byte, responseSize)
	p[0] = msgResponse
	binary.LittleEndian.PutUint32(p[4:8], hubIdx)
	binary.LittleEndian.PutUint32(p[8:12], clientIdx)
	return p
}

func data(idx uint32) []byte {
	p := make([]byte, 64)
	p[0] = msgData
	binary.LittleEndian.PutUint32(p[4:8], idx)
	return p
}

// fakeReg registers a hub without a connection, for route's tests.
func fakeReg(f *Forwarder, tag string, hubEP netip.AddrPort) (*reg, [32]byte) {
	var pub [32]byte
	rand.Read(pub[:])
	now := time.Now()
	r := &reg{tag: tag, key: pub, mac1: mac1Key(pub), hubEP: hubEP, seen: make(chan netip.AddrPort, 1),
		clients: map[netip.AddrPort]int{}, conn: nopConn{}, raw: nopConn{}}
	rand.Read(r.helloKey[:])
	r.id = uint64(len(f.regs) + 1)
	r.packets, r.bytes = *newBucket(f.limits.PacketRate, now), *newBucket(f.limits.ByteRate, now)
	f.mu.Lock()
	f.regs[tag], f.byID[r.id], f.byHubEP[hubEP] = r, r, r
	f.mu.Unlock()
	return r, pub
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

func TestRoute(t *testing.T) {
	cert, _ := NewCert()
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hubA, hubB := netip.MustParseAddrPort("198.51.100.1:8764"), netip.MustParseAddrPort("198.51.100.2:8764")
	client := netip.MustParseAddrPort("203.0.113.5:40000")
	other := netip.MustParseAddrPort("203.0.113.6:40000")
	_, pubA := fakeReg(f, "a", hubA)
	_, pubB := fakeReg(f, "b", hubB)
	now := time.Now()
	expect := func(what string, from netip.AddrPort, p []byte, want netip.AddrPort) {
		t.Helper()
		got, ok := f.route(from, p, now)
		if !want.IsValid() {
			if ok {
				t.Errorf("%s: went to %v, want dropped", what, got)
			}
			return
		}
		if !ok || got != want {
			t.Errorf("%s: went to %v (%v), want %v", what, got, ok, want)
		}
	}

	expect("a handshake to A", client, initiation(pubA, 7), hubA)
	expect("a handshake to B", client, initiation(pubB, 8), hubB)
	var nobody [32]byte
	rand.Read(nobody[:])
	expect("a handshake to no group", client, initiation(nobody, 9), netip.AddrPort{})
	expect("junk", client, []byte("GET / HTTP/1.1\r\n"), netip.AddrPort{})

	// A's answer goes to the client, and the session's data both ways.
	expect("A's answer", hubA, response(100, 7), client)
	expect("the client's data to A", client, data(100), hubA)
	expect("A's data to the client", hubA, data(7), client)
	// B knows no client index 7 of its own: its packets go nowhere.
	expect("B's data with A's client index", hubB, data(7), netip.AddrPort{})
	expect("B's answer for A's handshake", hubB, response(200, 7), netip.AddrPort{})
	// Data with an index no hub chose goes nowhere.
	expect("data of no session", other, data(12345), netip.AddrPort{})
	// A hub's own handshake has no route.
	expect("a handshake from A", hubA, initiation(pubB, 1), netip.AddrPort{})
	// A client sends no answers.
	expect("an answer from a client", client, response(1, 2), netip.AddrPort{})
}

func TestRouteLimits(t *testing.T) {
	cert, _ := NewCert()
	limits := DefaultLimits
	limits.Clients = 2
	limits.SourceRate = 1000
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hub := netip.MustParseAddrPort("198.51.100.1:8764")
	_, pub := fakeReg(f, "a", hub)
	now := time.Now()
	for i := range 3 {
		from := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), uint16(40000+i))
		_, ok := f.route(from, initiation(pub, uint32(i)), now)
		if want := i < 2; ok != want {
			t.Errorf("client %d: passed %v, want %v", i, ok, want)
		}
	}
	// One source may not flood the hubs with handshakes.
	limits.SourceRate = 1
	g, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	_, pub = fakeReg(g, "a", hub)
	from := netip.MustParseAddrPort("203.0.113.5:40000")
	passed := 0
	for range 10 {
		if _, ok := g.route(from, initiation(pub, 1), now); ok {
			passed++
		}
	}
	if passed != 2 {
		t.Errorf("%d handshakes passed in a burst; want 2", passed)
	}
	// The sweep forgets a handshake the hub never answered.
	g.sweepAt(now.Add(time.Minute))
	if len(g.pending) != 0 {
		t.Errorf("%d handshakes still wait after a minute", len(g.pending))
	}
}

// TestScanLimit checks that handshakes to unknown groups, from any number
// of sources, cost the forwarder at most ScanRate group checks a second.
func TestScanLimit(t *testing.T) {
	cert, _ := NewCert()
	limits := DefaultLimits
	limits.SourceRate = 1000
	limits.ScanRate = 10 // a burst of 20 checks
	limits.NetworkScanRate = 10
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := range 4 {
		fakeReg(f, string(rune('a'+i)), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(8000+i)))
	}
	now := time.Now()
	var stranger [32]byte
	rand.Read(stranger[:])
	for i := range 5 { // 5 handshakes x 4 groups spend the burst
		from := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), uint16(40000+i))
		f.route(from, initiation(stranger, uint32(i)), now)
	}
	_, pub := fakeReg(f, "e", netip.MustParseAddrPort("198.51.100.2:8764"))
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.6:40000"), initiation(pub, 1), now); ok {
		t.Error("a handshake passed after the scan budget was spent")
	}
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.6:40000"), initiation(pub, 1), now.Add(time.Second)); !ok {
		t.Error("a handshake did not pass once the budget refilled")
	}
}

func TestHello(t *testing.T) {
	cert, _ := NewCert()
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hub := netip.MustParseAddrPort("198.51.100.1:8764")
	r, _ := fakeReg(f, "a", hub)
	moved := netip.MustParseAddrPort("198.51.100.1:9000")
	h := hello(&f.mask, &r.helloKey, r.id, 10)
	if h2 := hello(&f.mask, &r.helloKey, r.id, 10); bytes.Equal(h[:helloMin], h2[:helloMin]) {
		t.Error("two hellos look the same on the wire")
	}
	if messageType(h) != 0 || h[0] == msgHello && h[1] == 0 && h[2] == 0 && h[3] == 0 {
		t.Error("a hello shows its type")
	}
	now := time.Now()
	f.route(moved, h, now)
	if r.hubEP != moved {
		t.Fatalf("the hub is at %v after its hello from %v", r.hubEP, moved)
	}
	// The same hello again, from elsewhere: a replay moves nothing.
	f.route(netip.MustParseAddrPort("203.0.113.66:1"), h, now)
	if r.hubEP != moved {
		t.Fatalf("a replayed hello moved the hub to %v", r.hubEP)
	}
	// A hello under another key moves nothing.
	var wrong [32]byte
	f.route(netip.MustParseAddrPort("203.0.113.66:1"), hello(&f.mask, &wrong, r.id, 11), now)
	if r.hubEP != moved {
		t.Fatalf("a forged hello moved the hub to %v", r.hubEP)
	}
	// A hello under another forwarder's mask moves nothing either.
	f.route(netip.MustParseAddrPort("203.0.113.66:1"), hello(&wrong, &r.helloKey, r.id, 12), now)
	if r.hubEP != moved {
		t.Fatalf("a forged hello moved the hub to %v", r.hubEP)
	}
}

func TestRegistration(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	cert, tag, g := member(t)
	auth := g.auth(t)
	mine, _ := ecdh.X25519().GenerateKey(rand.Reader)
	theirs, _ := ecdh.X25519().GenerateKey(rand.Reader)

	if a := rawRegister(t, f, pin, cert, theirs.PublicKey().Bytes(), mine, auth); !strings.Contains(a.Error, "does not hold") {
		t.Errorf("a hub that claims another's WireGuard key: %+v", a)
	}
	a := rawRegister(t, f, pin, cert, mine.PublicKey().Bytes(), mine, auth)
	if a.Error != "" || a.ID == 0 || len(a.Mask) != 32 {
		t.Fatalf("a hub with its own key: %+v", a)
	}
	for i := 0; ; i++ {
		f.mu.Lock()
		_, there := f.regs[tag]
		f.mu.Unlock()
		if !there {
			break
		}
		if i == 100 {
			t.Fatal("the registration outlived its connection")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Another group cannot register that key.
	other, _, otherGroup := member(t)
	tc, a := rawOpen(t, f, pin, cert, mine.PublicKey().Bytes(), mine, auth)
	if a.Error != "" {
		t.Fatalf("registering: %+v", a)
	}
	defer tc.Close()
	if a := rawRegister(t, f, pin, other, mine.PublicKey().Bytes(), mine, otherGroup.auth(t)); !strings.Contains(a.Error, "another group") {
		t.Errorf("another group with the same WireGuard key: %+v", a)
	}

	// A certificate that is not of a server key gets no registration.
	self, _ := NewCert()
	if a := rawRegister(t, f, pin, self, mine.PublicKey().Bytes(), mine, auth); a.ID != 0 {
		t.Errorf("a certificate of no server key registered: %+v", a)
	}
	withCA := cert
	withCA.Certificate = [][]byte{cert.Certificate[0], self.Certificate[0]}
	if a := rawRegister(t, f, pin, withCA, mine.PublicKey().Bytes(), mine, auth); a.ID != 0 {
		t.Errorf("a server key's certificate with another behind it registered: %+v", a)
	}
}

func TestWrongPin(t *testing.T) {
	f, _ := startForwarder(t, Limits{})
	_, _, g := member(t)
	key, _ := tunnel.NewPrivateKey()
	other, _ := NewCert()
	reports := make(chan Report, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Register(ctx, HubConfig{Link: Link{Endpoint: f.Addr(), Pin: Pin(other.Leaf)}, Key: key, Credentials: g.credentials(t), HubCert: g.hubCert(),
		Send: func(netip.AddrPort, []byte) error { return nil }, Report: func(r Report) { reports <- r }})
	select {
	case r := <-reports:
		if r.Registered || r.Err == nil || !strings.Contains(r.Err.Error(), "not the one given") {
			t.Fatalf("with another forwarder's pin: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no report")
	}
}

func TestPin(t *testing.T) {
	cert, _ := NewCert()
	if err := CheckPin(Pin(cert.Leaf)); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "sha256:" + strings.Repeat("A", 43) + "=", "abc", strings.Repeat("A", 43), strings.Repeat("A", 42) + "==", strings.Repeat("-", 43) + "="} {
		if CheckPin(bad) == nil {
			t.Errorf("CheckPin(%q) passed", bad)
		}
	}
	path := t.TempDir() + "/key.pem"
	a, err := LoadCert(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadCert(path)
	if err != nil {
		t.Fatal(err)
	}
	if Pin(a.Leaf) != Pin(b.Leaf) {
		t.Error("the forwarder's key changed when it was read again")
	}
}

// obfuscate pads the plain message m and protects its header, as
// amneziawg-go sends it in a group with the settings o; m's type field is
// set to a value of the type's range.
func obfuscate(o *tunnel.Obfuscation, m []byte) []byte {
	var padding int
	var types tunnel.Range
	switch m[0] {
	case msgInitiation:
		padding, types = o.S1, o.H1
	case msgResponse:
		padding, types = o.S2, o.H2
	case msgCookie:
		padding, types = o.S3, o.H3
	default:
		padding, types = o.S4, o.H4
	}
	p := make([]byte, padding+len(m))
	rand.Read(p[:padding])
	copy(p[padding:], m)
	binary.LittleEndian.PutUint32(p[padding:], types.Min+uint32(m[1]))
	n := len(m)
	if m[0] == msgData {
		n = dataHeaderSize
	}
	c, _ := chacha20.NewUnauthenticatedCipher(o.HeaderKey[:], p[:headerNonceSize])
	c.XORKeyStream(p[padding:padding+n], p[padding:padding+n])
	return p
}

// obfuscatedInitiation is initiation's message to pub as an obfuscated
// group sends it: mac1 covers the type field the group chose.
func obfuscatedInitiation(o *tunnel.Obfuscation, pub [32]byte, idx uint32) []byte {
	m := make([]byte, initiationSize)
	rand.Read(m)
	binary.LittleEndian.PutUint32(m[0:4], o.H1.Min+5)
	binary.LittleEndian.PutUint32(m[4:8], idx)
	k := mac1Key(pub)
	h, _ := blake2s.New128(k[:])
	h.Write(m[:initiationSize-32])
	h.Sum(m[:initiationSize-32])
	p := make([]byte, o.S1+initiationSize)
	rand.Read(p[:o.S1])
	copy(p[o.S1:], m)
	c, _ := chacha20.NewUnauthenticatedCipher(o.HeaderKey[:], p[:headerNonceSize])
	c.XORKeyStream(p[o.S1:], p[o.S1:])
	return p
}

func TestRouteObfuscated(t *testing.T) {
	cert, _ := NewCert()
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hubA, hubB, hubP := netip.MustParseAddrPort("198.51.100.1:8764"), netip.MustParseAddrPort("198.51.100.2:8764"), netip.MustParseAddrPort("198.51.100.3:8764")
	client := netip.MustParseAddrPort("203.0.113.5:40000")
	other := netip.MustParseAddrPort("203.0.113.6:40000")
	// B's handshake initiation has the size of A's, so that only the
	// header key tells them apart.
	oA, oB := newObfuscation(t), newObfuscation(t)
	for oB.S1 = oA.S1; oB.Check() != nil; oB.S1 = oA.S1 {
		oB = newObfuscation(t)
	}
	rA, pubA := fakeReg(f, "a", hubA)
	rB, pubB := fakeReg(f, "b", hubB)
	_, pubP := fakeReg(f, "p", hubP)
	f.mu.Lock()
	rA.obf, rB.obf = oA, oB
	f.byInit[initSize(oA)] = append(f.byInit[initSize(oA)], rA)
	f.byInit[initSize(oB)] = append(f.byInit[initSize(oB)], rB)
	f.mu.Unlock()
	now := time.Now()
	expect := func(what string, from netip.AddrPort, p []byte, want netip.AddrPort) {
		t.Helper()
		got, ok := f.route(from, p, now)
		if !want.IsValid() {
			if ok {
				t.Errorf("%s: went to %v, want dropped", what, got)
			}
			return
		}
		if !ok || got != want {
			t.Errorf("%s: went to %v (%v), want %v", what, got, ok, want)
		}
	}

	expect("a handshake to A", client, obfuscatedInitiation(oA, pubA, 7), hubA)
	expect("a handshake to B", other, obfuscatedInitiation(oB, pubB, 8), hubB)
	expect("a plain handshake to A", client, initiation(pubA, 9), netip.AddrPort{})
	expect("a handshake to A with B's settings", client, obfuscatedInitiation(oB, pubA, 10), netip.AddrPort{})
	expect("a plain handshake to the plain group", client, initiation(pubP, 11), hubP)

	expect("A's answer", hubA, obfuscate(oA, response(100, 7)), client)
	expect("a plain answer from A", hubA, response(101, 7), netip.AddrPort{})
	expect("the client's data to A", client, obfuscate(oA, data(100)), hubA)
	expect("the client's plain data to A", client, data(100), netip.AddrPort{})
	expect("A's data to the client", hubA, obfuscate(oA, data(7)), client)
	expect("data to A with B's settings", client, obfuscate(oB, data(100)), netip.AddrPort{})
	expect("A's data from another address", other, obfuscate(oA, data(100)), netip.AddrPort{})
	expect("junk", client, make([]byte, 200), netip.AddrPort{})

	expect("B's answer", hubB, obfuscate(oB, response(200, 8)), other)
	expect("the other client's data to B", other, obfuscate(oB, data(200)), hubB)
}

// TestThroughXHTTP checks VLESS over XHTTP behind the web server of the
// forwarder's site, with and without AmneziaWG's obfuscation: the hub
// learns the transport, the site's name, the web server's port and the
// path, and a client gets through with them.
func TestThroughXHTTP(t *testing.T) {
	for _, obfuscated := range []bool{false, true} {
		t.Run(fmt.Sprintf("obfuscated=%v", obfuscated), func(t *testing.T) {
			// A forwarder of its own, so that the first case's hub and
			// Xray are gone before the second.
			path, err := tunnel.NewVLESSPath()
			if err != nil {
				t.Fatal(err)
			}
			var back atomic.Value
			back.Store("127.0.0.1:9")
			web, cert := vlesstest.WebServer(t, path, func() string { return back.Load().(string) })
			vless.TrustForTests(cert)
			f, pin := startForwarderWith(t, Config{VLESS: &VLESSConfig{Listen: "127.0.0.1:0",
				XHTTP: &XHTTPConfig{Host: vlesstest.WebName, Port: web.Port(), Path: path}}})
			back.Store(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.vless.Port()))))
			var obf *tunnel.Obfuscation
			if obfuscated {
				obf = newObfuscation(t)
			}
			id, _ := tunnel.NewVLESSID()
			key, peer := newClient(t)
			hs := startHubWith(t, f, pin, []tunnel.Peer{peer}, HubConfig{Obfuscation: obf, VLESSID: id})
			// The group's packets come under a path of its own below the path.
			group, ok := strings.CutPrefix(hs.vless.Path, path+"/")
			if !ok || tunnel.CheckGroupPath(group) != nil {
				t.Fatalf("the hub learned the path %q", hs.vless.Path)
			}
			want := tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: hs.vless.Path, ID: id}
			if !hs.vless.Equal(&want) {
				t.Fatalf("the hub learned %+v, want %+v", hs.vless, want)
			}
			vc, err := vless.Dial(*hs.vless)
			if err != nil {
				t.Fatal(err)
			}
			defer vc.Close()
			if err := roundTripTo(t, vc.Addr(), hs, key, peer); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestHubOverXHTTP checks a hub that reaches its forwarder only over VLESS:
// its TCP port does not answer, so the hub registers inside VLESS with the
// settings it was given, its own packets go there too, and a client gets
// through to it.
func TestHubOverXHTTP(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	var back atomic.Value
	back.Store("127.0.0.1:9")
	web, cert := vlesstest.WebServer(t, path, func() string { return back.Load().(string) })
	vless.TrustForTests(cert)
	f, pin := startForwarderWith(t, Config{VLESS: &VLESSConfig{Listen: "127.0.0.1:0",
		XHTTP: &XHTTPConfig{Host: vlesstest.WebName, Port: web.Port(), Path: path}}})
	back.Store(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.vless.Port()))))
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := closed.Addr().(*net.TCPAddr).AddrPort()
	closed.Close()
	id, _ := tunnel.NewVLESSID()
	given := &tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: path, ID: vless.RegistrationID}
	key, peer := newClient(t)
	// A way in that leads nowhere first: the hub tries the next.
	nowhere := *given
	nowhere.Path = "/nowhere-at-all"
	ways := func() []tunnel.VLESS { return []tunnel.VLESS{nowhere, *given} }
	hs := startHubWith(t, f, pin, []tunnel.Peer{peer}, HubConfig{VLESSID: id, VLESS: ways, Link: Link{Endpoint: dead}})
	// The group's packets come under a path of its own below the path.
	group, ok := strings.CutPrefix(hs.vless.Path, path+"/")
	if !ok || tunnel.CheckGroupPath(group) != nil {
		t.Fatalf("the hub learned the path %q", hs.vless.Path)
	}
	want := tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: hs.vless.Path, ID: id}
	if !hs.vless.Equal(&want) {
		t.Fatalf("the hub learned %+v, want %+v", hs.vless, want)
	}
	vc, err := vless.Dial(*hs.vless)
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()
	if err := roundTripTo(t, vc.Addr(), hs, key, peer); err != nil {
		t.Fatal(err)
	}
}

// The registrations' user ID reaches nothing but the registrations, and
// no group may take it as its own.
func TestRegistrationIDIsNoGroups(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	f, pin := startForwarderWith(t, Config{VLESS: &VLESSConfig{Listen: "127.0.0.1:0",
		XHTTP: &XHTTPConfig{Host: vlesstest.WebName, Port: 443, Path: path}}})
	_, _, g := member(t)
	key, _ := tunnel.NewPrivateKey()
	reports := make(chan Report, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Register(ctx, HubConfig{Link: Link{Endpoint: f.Addr(), Pin: pin}, Key: key, VLESSID: vless.RegistrationID,
		Credentials: g.credentials(t), HubCert: g.hubCert(), Send: func(netip.AddrPort, []byte) error { return nil },
		Report: func(r Report) { reports <- r }})
	select {
	case r := <-reports:
		if r.Err == nil || !strings.Contains(r.Err.Error(), "not usable") {
			t.Fatalf("a hub taking the registrations' user ID: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}
	if err := f.vless.AddUser(vless.RegistrationID); err == nil {
		t.Error("the registrations' user ID was added as a group's")
	}
}

func TestVLESSRefused(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	_, _, g := member(t)
	key, _ := tunnel.NewPrivateKey()
	id, _ := tunnel.NewVLESSID()
	reports := make(chan Report, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Register(ctx, HubConfig{Link: Link{Endpoint: f.Addr(), Pin: pin}, Key: key, VLESSID: id,
		Credentials: g.credentials(t), HubCert: g.hubCert(), Send: func(netip.AddrPort, []byte) error { return nil },
		Report: func(r Report) { reports <- r }})
	select {
	case r := <-reports:
		if r.Err == nil || !strings.Contains(r.Err.Error(), "no VLESS") {
			t.Fatalf("a hub asking a forwarder without VLESS: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}
}

// TestRegistrationNeedsTheHubsCredential checks that a hub registers only
// with its group's hubs' credential alone, signed by the period key and
// listing the server key of its certificate: not without it, not with
// the period credential, which names the group and its root, and not
// with one that lists another key.
func TestRegistrationNeedsTheHubsCredential(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	cert, tag, g := member(t)
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := newServerKey(t)
	for _, c := range []struct {
		name  string
		creds [][]byte
		why   string
	}{
		{"no credential", nil, "forward/register/credentials"},
		{"the period credential alone", [][]byte{g.periodCredential(t)}, "does not verify"},
		{"the period credential beside the hubs'", [][]byte{g.periodCredential(t), g.hubs(t, 1)}, "alone"},
		{"one that lists another hub", [][]byte{g.hubs(t, 1, other)}, "does not list"},
	} {
		if a := rawRegister(t, f, pin, cert, k.PublicKey().Bytes(), k, hubAuth{creds: c.creds}); !strings.Contains(a.Error, c.why) {
			t.Errorf("%s: %+v, want a refusal for %q", c.name, a, c.why)
		}
		if f.registered(tag) {
			t.Fatalf("%s: the group is registered", c.name)
		}
	}
	tc, a := rawOpen(t, f, pin, cert, k.PublicKey().Bytes(), k, g.auth(t))
	if a.Error != "" || a.ID == 0 {
		t.Fatalf("the listed hub: %+v", a)
	}
	defer tc.Close()
	if !f.registered(tag) {
		t.Fatal("the listed hub is not registered")
	}
}

// TestRegistrationByListedServerKey checks that every hub a hubs'
// credential lists registers the group, the last one taking over, and
// that a newer credential which no longer lists a hub keeps it out.
func TestRegistrationByListedServerKey(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	_, tag, g := member(t)
	second, secondCert := newServerKey(t)
	both := g.hubs(t, 1, g.hub, second)
	k1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	k2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c1, a := rawOpen(t, f, pin, g.cert, k1.PublicKey().Bytes(), k1, hubAuth{creds: [][]byte{both}})
	if a.Error != "" {
		t.Fatalf("the first hub: %+v", a)
	}
	defer c1.Close()
	c2, a := rawOpen(t, f, pin, secondCert, k2.PublicKey().Bytes(), k2, hubAuth{creds: [][]byte{both}})
	if a.Error != "" {
		t.Fatalf("the second hub: %+v", a)
	}
	defer c2.Close()
	f.mu.Lock()
	r := f.regs[tag]
	f.mu.Unlock()
	if r == nil || r.key != [32]byte(k2.PublicKey().Bytes()) {
		t.Fatal("the second hub did not take over")
	}
	// The group drops the second hub from version 2 on.
	c1b, a := rawOpen(t, f, pin, g.cert, k1.PublicKey().Bytes(), k1, hubAuth{creds: [][]byte{g.hubs(t, 2)}})
	if a.Error != "" {
		t.Fatalf("the first hub with version 2: %+v", a)
	}
	defer c1b.Close()
	if a := rawRegister(t, f, pin, secondCert, k2.PublicKey().Bytes(), k2, hubAuth{creds: [][]byte{both}}); !strings.Contains(a.Error, "older") {
		t.Errorf("the dropped hub with the older credential: %+v", a)
	}
	if a := rawRegister(t, f, pin, secondCert, k2.PublicKey().Bytes(), k2, hubAuth{creds: [][]byte{g.hubs(t, 2)}}); !strings.Contains(a.Error, "does not list") {
		t.Errorf("the dropped hub with the newer credential: %+v", a)
	}
}

// TestRegistrationRemembersVersions checks that the forwarder keeps the
// newest version of a group's hubs' credential after its registration
// ends, so that a hub the group dropped cannot register again with the
// credential from before while the group is away; what it writes names
// neither the period's tag nor the period key.
func TestRegistrationRemembersVersions(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	f, pin := startForwarderWith(t, Config{StateFile: state})
	_, tag, g := member(t)
	dropped, droppedCert := newServerKey(t)
	before := g.hubs(t, 1, g.hub, dropped)
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	dk, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// The group's hub registers with the credential that drops the other
	// hub, then goes away.
	rc, a := rawOpen(t, f, pin, g.cert, k.PublicKey().Bytes(), k, hubAuth{creds: [][]byte{g.hubs(t, 2)}})
	if a.Error != "" {
		t.Fatalf("the group's hub: %+v", a)
	}
	rc.Close()
	waitUntil(t, "the registration to end with its connection", func() bool { return !f.registered(tag) })
	if a := rawRegister(t, f, pin, droppedCert, dk.PublicKey().Bytes(), dk, hubAuth{creds: [][]byte{before}}); !strings.Contains(a.Error, "older") {
		t.Errorf("the dropped hub while the group is away: %+v", a)
	}

	// What goes to disk names neither the tag nor the period key.
	f.Close()
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	pk := serverKeyHash(g.period)
	for _, c := range []string{hex.EncodeToString(g.tag[:]), hex.EncodeToString(pk[:])} {
		if strings.Contains(string(b), c) {
			t.Errorf("the state file holds %q: %s", c, b)
		}
	}
}

// TestNetworkScanLimit checks that the handshakes from one network spend
// only that network's share of the scan budget.
func TestNetworkScanLimit(t *testing.T) {
	cert, _ := NewCert()
	limits := DefaultLimits
	limits.SourceRate = 1000
	limits.NetworkScanRate = 4 // a burst of 8 checks per network
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := range 3 {
		fakeReg(f, string(rune('a'+i)), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(8000+i)))
	}
	_, pub := fakeReg(f, "d", netip.MustParseAddrPort("198.51.100.2:8764"))
	now := time.Now()
	var stranger [32]byte
	rand.Read(stranger[:])
	for i := range 2 { // 2 handshakes x 4 groups spend the network's burst
		f.route(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), uint16(40000+i)), initiation(stranger, uint32(i)), now)
	}
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.77:40000"), initiation(pub, 1), now); ok {
		t.Error("a handshake from the same /24 passed after its budget was spent")
	}
	if _, ok := f.route(netip.MustParseAddrPort("192.0.2.9:40000"), initiation(pub, 2), now); !ok {
		t.Error("a handshake from another network did not pass")
	}
}

// TestRegistrationsPerAddress checks that one address holds at most
// PerAddress registrations, set up or held.
func TestRegistrationsPerAddress(t *testing.T) {
	f, pin := startForwarder(t, Limits{Groups: 100, Connections: 100, PerAddress: 2, PerNetwork: 100})
	var open []*tls.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for i := range 3 {
		cert, _, g := member(t)
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		tc, a := rawOpen(t, f, pin, cert, k.PublicKey().Bytes(), k, g.auth(t))
		if tc != nil {
			open = append(open, tc)
		}
		if ok := a.Error == "" && a.ID != 0; ok != (i < 2) {
			t.Errorf("registration %d from one address: %+v", i+1, a)
		}
	}
}

// A hub that puts a certificate of its own beside its server key's, or a
// credential another key signed for the period's tag, is checked under the
// period key the forwarder saw first for that tag, so it does not register
// and the hub's registration stays.
func TestRegistrationUnderFirstPeriodKey(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	hubCert, tag, g := member(t)
	hk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	hc, a := rawOpen(t, f, pin, hubCert, hk.PublicKey().Bytes(), hk, g.auth(t))
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	defer hc.Close()

	rogue, rogueCert := newServerKey(t)
	rogueKey, _ := group.NewKey()
	own, _ := NewCert()
	ak, _ := ecdh.X25519().GenerateKey(rand.Reader)
	forged := g.signHubs(t, rogueKey, 9, time.Now().Add(time.Hour), rogue)
	for name, c := range map[string]struct {
		chain [][]byte
		creds [][]byte
	}{
		"own certificate first":       {[][]byte{own.Certificate[0], rogueCert.Certificate[0]}, [][]byte{forged}},
		"own certificate last":        {[][]byte{rogueCert.Certificate[0], own.Certificate[0]}, [][]byte{forged}},
		"own certificate only":        {[][]byte{own.Certificate[0]}, [][]byte{forged}},
		"another key for the tag":     {[][]byte{rogueCert.Certificate[0]}, [][]byte{forged}},
		"the group's hub's, unlisted": {[][]byte{hubCert.Certificate[0]}, [][]byte{forged}},
	} {
		cert := tls.Certificate{Certificate: c.chain, PrivateKey: rogue}
		if name == "own certificate only" {
			cert.PrivateKey = own.PrivateKey
		}
		if name == "the group's hub's, unlisted" {
			cert.PrivateKey = g.hub
		}
		if a := rawRegister(t, f, pin, cert, ak.PublicKey().Bytes(), ak, hubAuth{creds: c.creds}); a.Error == "" {
			t.Errorf("%s: the rogue hub registered", name)
		}
	}
	f.mu.Lock()
	r := f.regs[tag]
	f.mu.Unlock()
	if r == nil || r.key != [32]byte(hk.PublicKey().Bytes()) {
		t.Fatal("the hub's registration was replaced")
	}
}

// Handshakes that come over VLESS, from the loopback, spend the budget of
// one network, so a flood of them leaves the budget of every other source.
func TestVLESSScansApart(t *testing.T) {
	cert, err := NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, VLESS: &VLESSConfig{Listen: "127.0.0.1:0", XHTTP: testXHTTP()}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := range 200 {
		fakeReg(f, fmt.Sprintf("group %d", i), netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(8000+i)))
	}
	_, pub := fakeReg(f, "victim", netip.MustParseAddrPort("198.51.100.2:8764"))
	now := time.Now()
	var nobody [32]byte
	rand.Read(nobody[:])
	for i := range 8000 {
		f.route(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(30000+i%1000)), initiation(nobody, uint32(i)), now)
	}
	if _, ok := f.route(netip.MustParseAddrPort("203.0.113.10:4000"), initiation(pub, 2), now); !ok {
		t.Fatal("a client's handshake was dropped after a flood over VLESS")
	}
}

// TestGroupPathKept checks the group's own part of the XHTTP path: made
// from its VLESS user ID, the same at each registration and after a
// restart, and another for another ID. The values are the Rust core's
// (vless::tests::the_path_of_a_user_id), so a hub knows the path of its
// next ID.
func TestGroupPathKept(t *testing.T) {
	if p := tunnel.GroupPath("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"); p != "FAf82MUKFMjUNz3SkIYXXw" || tunnel.CheckGroupPath(p) != nil {
		t.Fatalf("path %q", p)
	}
	if tunnel.GroupPath("0b6e7f10-2a3b-4c5d-9e8f-112233445566") != "mefvDB5qwj9eeFnyKOOk4A" {
		t.Fatal("another ID")
	}
}

// A hub whose hellos over VLESS the forwarder never sees, as when the
// first request of the local way's flow got no answer, registers again
// with a way of its own rather than wait for ever, and gets seen then.
func TestHubRegistersAgainWhenNoHelloComes(t *testing.T) {
	old := helloUnseen.Load()
	helloUnseen.Store(int64(2 * time.Second))
	t.Cleanup(func() { helloUnseen.Store(old) })
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	var back atomic.Value
	back.Store("127.0.0.1:9")
	web, webCert := vlesstest.WebServer(t, path, func() string { return back.Load().(string) })
	vless.TrustForTests(webCert)
	f, pin := startForwarderWith(t, Config{VLESS: &VLESSConfig{Listen: "127.0.0.1:0",
		XHTTP: &XHTTPConfig{Host: vlesstest.WebName, Port: web.Port(), Path: path}}})
	back.Store(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.vless.Port()))))
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := closed.Addr().(*net.TCPAddr).AddrPort()
	closed.Close()
	given := tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: path, ID: vless.RegistrationID}
	id, _ := tunnel.NewVLESSID()
	key, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := tunnel.Addr(string(group.NewDeviceID()))
	if err != nil {
		t.Fatal(err)
	}
	h, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: key, Addr: addr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	_, _, g := member(t)
	// The first registration's hellos are lost on the way.
	var lose atomic.Bool
	lose.Store(true)
	send := func(to netip.AddrPort, b []byte) error {
		if lose.Load() {
			return nil
		}
		return h.Send(to, b)
	}
	reports := make(chan Report, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Register(ctx, HubConfig{Link: Link{Endpoint: dead, Pin: pin}, Key: key, VLESSID: id,
			VLESS:       func() []tunnel.VLESS { return []tunnel.VLESS{given} },
			Credentials: g.credentials(t), HubCert: g.hubCert(), Send: send,
			Report: func(r Report) {
				select {
				case reports <- r:
				default:
				}
			}})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	deadline := time.After(30 * time.Second)
	for {
		select {
		case r := <-reports:
			switch {
			case r.Err != nil:
				if !lose.Load() || !strings.Contains(r.Err.Error(), "saw none of the hub's hellos") {
					t.Fatalf("registering: %v", r.Err)
				}
				lose.Store(false)
			case r.Seen.IsValid():
				if lose.Load() {
					t.Fatal("seen with every hello lost")
				}
				return
			}
		case <-deadline:
			t.Fatal("the hub never registered again")
		}
	}
}

// testXHTTP is a web server in front of the forwarder's XHTTP for tests
// that need VLESS on but send nothing through it.
func testXHTTP() *XHTTPConfig {
	return &XHTTPConfig{Host: "example.com", Port: 443, Path: "/test-xhttp-path"}
}
