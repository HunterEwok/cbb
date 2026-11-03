// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"

	"github.com/HunterEwok/cbb/internal/third_party/netstack"
)

// A negative dial waits this long: several handshake attempts would be made
// if anything answered.
const refuseWait = 3 * time.Second

type testDevice struct {
	id   string
	addr netip.Addr
	priv Key
	psk  Key
}

func newDevice(t *testing.T) testDevice {
	t.Helper()
	var raw [16]byte
	rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	addr, err := Addr(id)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{id: id, addr: addr, priv: priv, psk: psk}
}

func (d testDevice) peer() Peer {
	return Peer{PublicKey: d.priv.Public(), PresharedKey: d.psk, Addr: d.addr}
}

type testHub struct {
	*Hub
	dev testDevice
}

// startHub starts a hub on the loopback address that echoes every line it
// receives, prefixed with the client's tunnel address.
func startHub(t *testing.T, peers ...Peer) testHub {
	t.Helper()
	return startObfuscatedHub(t, nil, peers...)
}

// startObfuscatedHub is startHub with obfuscation settings, nil for none.
func startObfuscatedHub(t *testing.T, obf *Obfuscation, peers ...Peer) testHub {
	t.Helper()
	d := newDevice(t)
	h, err := StartHub(HubConfig{PrivateKey: d.priv, Addr: d.addr, Peers: peers, Obfuscation: obf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	go func() {
		for {
			c, err := h.Listener().Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				from := c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
				fmt.Fprintf(c, "%s %s", from, buf[:n])
			}()
		}
	}()
	return testHub{h, d}
}

func (h testHub) endpoint() netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(h.UDPPort()))
}

func startClient(t *testing.T, h testHub, d testDevice) *Client {
	t.Helper()
	c, err := StartClient(ClientConfig{
		PrivateKey: d.priv, PresharedKey: d.psk, Addr: d.addr,
		HubPublicKey: h.dev.priv.Public(), HubAddr: h.dev.addr, Endpoint: h.endpoint(),
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// roundTrip sends a line to the hub and returns its answer.
func roundTrip(ctx context.Context, c *Client) (string, error) {
	conn, err := c.Dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "hello"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	return string(b), err
}

func TestClientsReachTheHub(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())
	for _, d := range []testDevice{a, b} {
		c := startClient(t, h, d)
		if n := c.Received(); n != 0 {
			t.Fatalf("%d bytes from the hub before anything was sent", n)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		got, err := roundTrip(ctx, c)
		cancel()
		if err != nil {
			t.Fatalf("client %s: %v", d.addr, err)
		}
		if c.Received() == 0 {
			t.Fatal("nothing from the hub after a connection through the tunnel")
		}
		// The hub sees each client by its own tunnel address.
		if want := d.addr.String() + " hello"; got != want {
			t.Fatalf("hub answered %q, want %q", got, want)
		}
	}
}

func TestOnlyTheMemberPortIsOpen(t *testing.T) {
	a := newDevice(t)
	h := startHub(t, a.peer())
	c := startClient(t, h, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{22, 80, 443, Port + 1} {
		conn, err := c.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(h.dev.addr, port))
		if err == nil {
			conn.Close()
			t.Fatalf("port %d of the hub accepted a connection", port)
		}
	}
}

// rawClient is a tunnel to the hub that a hostile client configures by
// hand: any local address, and any destination routed to the hub.
func rawClient(t *testing.T, h testHub, d testDevice, local netip.Addr) *netstack.Net {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{local}, nil, MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, newBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=::/0\n",
		d.priv.hex(), h.dev.priv.Public().hex(), d.psk.hex(), h.endpoint())
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return tnet
}

func TestClientsCannotReachEachOther(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())

	// b is up and listening on the member port of its own stack.
	bc := startClient(t, h, b)
	l, err := bc.net.ListenTCPAddrPort(netip.AddrPortFrom(b.addr, Port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := roundTrip(ctx, bc); err != nil {
		t.Fatal(err)
	}
	cancel()

	// a sends everything to the hub, b's address included.
	an := rawClient(t, h, a, a.addr)
	ctx, cancel = context.WithTimeout(context.Background(), refuseWait)
	defer cancel()
	if c, err := an.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(b.addr, Port)); err == nil {
		c.Close()
		t.Fatal("a client reached another client through the hub")
	}
	select {
	case <-accepted:
		t.Fatal("a client's connection reached another client")
	default:
	}
	// The same tunnel does reach the hub.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := an.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(h.dev.addr, Port))
	if err != nil {
		t.Fatalf("the hostile client's tunnel does not work at all: %v", err)
	}
	c.Close()
}

func TestClientCannotUseAnotherAddress(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())
	// a claims b's address.
	an := rawClient(t, h, a, b.addr)
	ctx, cancel := context.WithTimeout(context.Background(), refuseWait)
	defer cancel()
	if c, err := an.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(h.dev.addr, Port)); err == nil {
		c.Close()
		t.Fatal("the hub accepted a client with another client's address")
	}
}

func TestUnknownKeysAreDropped(t *testing.T) {
	a := newDevice(t)
	h := startHub(t, a.peer())

	stranger := newDevice(t)
	wrongPSK := a
	wrongPSK.psk, _ = NewPresharedKey()
	for name, d := range map[string]testDevice{"unknown key": stranger, "wrong preshared key": wrongPSK} {
		c := startClient(t, h, d)
		ctx, cancel := context.WithTimeout(context.Background(), refuseWait)
		_, err := roundTrip(ctx, c)
		cancel()
		if err == nil {
			t.Fatalf("%s: the hub answered", name)
		}
	}
}

func TestRemovedClientIsDropped(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer(), b.peer())
	c := startClient(t, h, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}
	cancel()

	if err := h.SetPeers([]Peer{b.peer()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), refuseWait)
	defer cancel()
	if _, err := roundTrip(ctx, c); err == nil {
		t.Fatal("the hub still answers a removed client")
	}
}

// TestStayingClientKeepsItsSession checks that a client the hub keeps
// when its peers change keeps its session: the hub still knows where it
// is, so it can send to it at once.
func TestStayingClientKeepsItsSession(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	h := startHub(t, a.peer())
	c := startClient(t, h, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := h.SetPeers([]Peer{a.peer(), b.peer()}); err != nil {
		t.Fatal(err)
	}
	cfg, err := h.Hub.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	_, rest, _ := strings.Cut(cfg, "public_key="+a.priv.Public().hex()+"\n")
	rest, _, _ = strings.Cut(rest, "public_key=")
	if !strings.Contains(rest, "endpoint=") || strings.Contains(rest, "last_handshake_time_sec=0\n") {
		t.Errorf("the staying client lost its session:\n%s", rest)
	}
	if !strings.Contains(cfg, "public_key="+b.priv.Public().hex()+"\n") {
		t.Error("the new client is missing")
	}
}

func TestSetEndpoint(t *testing.T) {
	a := newDevice(t)
	h := startHub(t, a.peer())
	// The first endpoint takes packets and never answers, like a hub's old
	// address. (A closed port would answer with ICMP, which Windows reports
	// as receive errors.)
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	c, err := StartClient(ClientConfig{
		PrivateKey: a.priv, PresharedKey: a.psk, Addr: a.addr,
		HubPublicKey: h.dev.priv.Public(), HubAddr: h.dev.addr,
		Endpoint: sink.LocalAddr().(*net.UDPAddr).AddrPort(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetEndpoint(h.endpoint()); err != nil {
		t.Fatal(err)
	}
	// A handshake already sent to the old endpoint is retried after
	// WireGuard's rekey timeout of 5 s.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := roundTrip(ctx, c); err != nil {
		t.Fatal(err)
	}
}

func TestPeersAreChecked(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	hub := newDevice(t)
	sameAddr := b.peer()
	sameAddr.Addr = a.addr
	sameKey := b.peer()
	sameKey.PublicKey = a.priv.Public()
	noPSK := b.peer()
	noPSK.PresharedKey = Key{}
	outside := b.peer()
	outside.Addr = netip.MustParseAddr("fd00::1")
	hubAddr := b.peer()
	hubAddr.Addr = hub.addr
	for name, p := range map[string]Peer{
		"same address": sameAddr, "same key": sameKey, "no preshared key": noPSK,
		"outside the prefix": outside, "the hub's address": hubAddr,
	} {
		if _, err := StartHub(HubConfig{PrivateKey: hub.priv, Addr: hub.addr, Peers: []Peer{a.peer(), p}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAddr(t *testing.T) {
	got, err := Addr("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("fd00:cbb:123:4567:89ab:cdef:123:4567"); got != want {
		t.Fatalf("Addr = %v, want %v", got, want)
	}
	for _, bad := range []string{"", "0123", "0123456789ABCDEF0123456789ABCDEF", "zz23456789abcdef0123456789abcdef"} {
		if _, err := Addr(bad); err == nil {
			t.Errorf("Addr(%q) accepted", bad)
		}
	}
}

func TestPublicKey(t *testing.T) {
	// RFC 7748, section 6.1: Alice's keys.
	var priv Key
	hex.Decode(priv[:], []byte("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	pub := priv.Public()
	if got, want := pub.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"; got != want {
		t.Fatalf("public key %s, want %s", got, want)
	}
}

// TestGuest checks that a guest reaches the hub from its own address,
// outside the members' prefix, and cannot take a member's address.
func TestGuest(t *testing.T) {
	g := newDevice(t)
	g.addr = GuestAddr(g.priv.Public())
	if !IsGuest(g.addr) || prefix.Contains(g.addr) {
		t.Fatalf("guest address %v", g.addr)
	}
	if m := newDevice(t); IsGuest(m.addr) {
		t.Fatalf("member address %v is a guest's", m.addr)
	}
	h := startHub(t, g.peer())
	c := startClient(t, h, g)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := roundTrip(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, g.addr.String()+" ") {
		t.Errorf("the hub saw %q, want it from %v", got, g.addr)
	}

	// With the guest's key, a member's address gets nowhere.
	member := newDevice(t)
	tnet := rawClient(t, h, g, member.addr)
	rctx, rcancel := context.WithTimeout(context.Background(), refuseWait)
	defer rcancel()
	if conn, err := tnet.DialContextTCPAddrPort(rctx, netip.AddrPortFrom(h.dev.addr, Port)); err == nil {
		conn.Close()
		t.Error("a guest reached the hub from a member's address")
	}
}

// TestBindKeepsItsPort checks that the UDP socket reports the port it was
// asked for on a host without IPv6 too. wireguard-go replaced it with 0
// there, and the hub's next rebind, which a netstack device's own "up"
// event can cause right after the port is set, listened on a random port.
func TestBindKeepsItsPort(t *testing.T) {
	port, err := freeUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	b := newBind()
	_, got, err := b.Open(uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if int(got) != port {
		t.Fatalf("the bind reports port %d, asked for %d", got, port)
	}
}
