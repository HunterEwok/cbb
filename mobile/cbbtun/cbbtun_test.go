// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

const (
	hubID   = "00112233445566778899aabbccddeeff"
	phoneID = "ffeeddccbbaa99887766554433221100"
)

// TestThroughTunnel connects to the loopback port and reaches the hub's
// member port, both ways.
func TestThroughTunnel(t *testing.T) { throughTunnel(t, nil, "") }

// TestThroughObfuscatedTunnel does the same with a hub that speaks
// AmneziaWG, whose settings the phone gets as JSON.
func TestThroughObfuscatedTunnel(t *testing.T) {
	obf, err := tunnel.NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	throughTunnel(t, obf, "")
}

// TestThroughVLESS does the same over VLESS to a forwarder, here one that
// passes the packets straight to the hub: with REALITY, plain and
// obfuscated, and with XHTTP behind a web server.
func TestThroughVLESS(t *testing.T) {
	t.Run("plain", func(t *testing.T) { throughTunnel(t, nil, "reality") })
	t.Run("xhttp", func(t *testing.T) { throughTunnel(t, nil, tunnel.TransportXHTTP) })
	t.Run("obfuscated", func(t *testing.T) {
		obf, err := tunnel.NewObfuscation()
		if err != nil {
			t.Fatal(err)
		}
		throughTunnel(t, obf, "reality")
	})
}

// overVLESS starts VLESS with REALITY in front of the hub's UDP port and
// returns the settings a hub's offer would carry, as JSON.
func overVLESS(t *testing.T, port uint16) string {
	t.Helper()
	var key [32]byte
	rand.Read(key[:])
	s, err := vless.Listen(vless.ServerConfig{Listen: "127.0.0.1:0", Dest: vlesstest.Decoy(t), ServerName: vlesstest.Site,
		Key: key, To: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	// A client that came before REALITY has learned the decoy would wait
	// 5 seconds or more, its WireGuard handshakes held, the first ones
	// stale by then.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := tunnel.NewVLESSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	pub, err := vless.PublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(tunnel.VLESS{Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Port()),
		PublicKey: pub, ShortID: vless.ShortID(key), ServerName: vlesstest.Site, ID: id})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// overXHTTP starts VLESS over XHTTP, behind a web server, in front of the
// hub's UDP port and returns the settings a hub's offer would carry, as
// JSON.
func overXHTTP(t *testing.T, port uint16) string {
	t.Helper()
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	s, err := vless.Listen(vless.ServerConfig{Listen: "127.0.0.1:0", Path: path, To: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	back := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Port()).String()
	web, cert := vlesstest.WebServer(t, path, func() string { return back })
	vless.TrustForTests(cert)
	id, _ := tunnel.NewVLESSID()
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	// A group's packets come on a path of its own under the base one.
	const group = "a-group-of-its-own"
	if err := s.AddPath(group); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: path + "/" + group, ID: id})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// throughTunnel sends through the tunnel to the hub, over VLESS with the
// transport via ("reality" or "xhttp"), or straight with "".
func throughTunnel(t *testing.T, obf *tunnel.Obfuscation, via string) {
	priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	psk, _ := tunnel.NewPresharedKey()
	hubKey, _ := tunnel.NewPrivateKey()
	hubAddr, _ := tunnel.Addr(hubID)
	phoneAddr, _ := tunnel.Addr(phoneID)
	var pk tunnel.Key
	copy(pk[:], pub)
	hub, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: hubKey, Addr: hubAddr,
		Peers: []tunnel.Peer{{PublicKey: pk, PresharedKey: psk, Addr: phoneAddr}}, Obfuscation: obf})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	go func() {
		for {
			c, err := hub.Listener().Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	hubPub := hubKey.Public()
	settings := ""
	if obf != nil {
		b, err := json.Marshal(obf)
		if err != nil {
			t.Fatal(err)
		}
		settings = string(b)
	}
	endpoint, link := fmt.Sprintf("127.0.0.1:%d", hub.UDPPort()), ""
	switch via {
	case "reality":
		endpoint, link = "", overVLESS(t, uint16(hub.UDPPort()))
	case tunnel.TransportXHTTP:
		endpoint, link = "", overXHTTP(t, uint16(hub.UDPPort()))
	}
	tun, err := Start(priv, psk[:], hubPub[:], phoneID, hubID, endpoint, settings, link)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	for i := range 2 {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port()))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(30 * time.Second))
		msg := []byte(fmt.Sprintf("hello %d", i))
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
		c.Close()
	}
	if err := tun.SetEndpoint(fmt.Sprintf("[::1]:%d", hub.UDPPort())); err != nil {
		t.Fatal(err)
	}
}

// TestCloseEndsConnections checks that Close ends a connection in use and
// closes the port.
func TestCloseEndsConnections(t *testing.T) {
	priv, _ := NewKey()
	psk, _ := tunnel.NewPresharedKey()
	hubKey, _ := tunnel.NewPrivateKey()
	hubPub := hubKey.Public()
	// No hub answers: the connection waits in the dial until Close.
	tun, err := Start(priv, psk[:], hubPub[:], phoneID, hubID, "127.0.0.1:9", "", "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %v", d)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the connection read data after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connection stayed open after Close")
	}
	if _, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port())); err == nil {
		t.Fatal("the port still accepts after Close")
	}
}

func TestBadArguments(t *testing.T) {
	priv, _ := NewKey()
	k := make([]byte, 32)
	k[0] = 1
	cases := []struct {
		name                                string
		priv, psk, hub                      []byte
		device, hubID, endpoint, obf, vless string
	}{
		{"short key", priv[:31], k, k, phoneID, hubID, "127.0.0.1:1", "", ""},
		{"short psk", priv, nil, k, phoneID, hubID, "127.0.0.1:1", "", ""},
		{"bad device", priv, k, k, "phone", hubID, "127.0.0.1:1", "", ""},
		{"bad hub", priv, k, k, phoneID, "HUB", "127.0.0.1:1", "", ""},
		{"bad endpoint", priv, k, k, phoneID, hubID, "example.org:1", "", ""},
		{"obfuscation not JSON", priv, k, k, phoneID, hubID, "127.0.0.1:1", "{", ""},
		{"bad obfuscation", priv, k, k, phoneID, hubID, "127.0.0.1:1", `{"jc":1}`, ""},
		{"VLESS not JSON", priv, k, k, phoneID, hubID, "", "", "{"},
		{"bad VLESS", priv, k, k, phoneID, hubID, "", "", `{"endpoint":"127.0.0.1:443","id":"x"}`},
	}
	for _, tc := range cases {
		if tun, err := Start(tc.priv, tc.psk, tc.hub, tc.device, tc.hubID, tc.endpoint, tc.obf, tc.vless); err == nil {
			tun.Close()
			t.Errorf("%s: Start succeeded", tc.name)
		}
	}
	if _, err := PublicKey(nil); err == nil {
		t.Error("PublicKey(nil) succeeded")
	}
}

// TestNewObfuscation makes settings StartHub takes and a VLESS ID Register
// takes.
func TestNewObfuscation(t *testing.T) {
	text, err := NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	var o tunnel.Obfuscation
	if err := json.Unmarshal([]byte(text), &o); err != nil {
		t.Fatal(err)
	}
	if err := o.Check(); err != nil {
		t.Fatal(err)
	}
	id, err := NewVLESSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.CheckVLESSID(id); err != nil {
		t.Fatal(err)
	}
}
