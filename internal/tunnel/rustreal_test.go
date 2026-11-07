// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel_test

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// TestRustPhoneThroughRealForwarder runs the phones' Rust hub and client
// (the example tunnel-on-linux) through a real forwarder on the internet,
// for a check from a network that blocks WireGuard: CBB_REAL_FORWARDER is
// the forwarder's host:port (cbb.tools:8764 for the project's), and
// CBB_REAL_FORWARDER_PIN its pin when it is not the project's. The hub
// registers (inside VLESS when the forwarder's TCP port does not answer),
// then a client reaches its member listener over VLESS with XHTTP alone;
// plain WireGuard to the forwarder's UDP port is tried as well and only
// reported, since a blocking network is expected to drop it.
func TestRustPhoneThroughRealForwarder(t *testing.T) {
	bin, at := os.Getenv("CBB_TUNNEL_ON_LINUX"), os.Getenv("CBB_REAL_FORWARDER")
	if bin == "" || at == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX or CBB_REAL_FORWARDER is not set")
	}
	host, port, err := net.SplitHostPort(at)
	if err != nil {
		t.Fatal(err)
	}
	ips, err := net.DefaultResolver.LookupNetIP(t.Context(), "ip4", host)
	if err != nil || len(ips) == 0 {
		t.Fatalf("%s: %v", host, err)
	}
	endpoint := net.JoinHostPort(ips[0].String(), port)
	pinText := os.Getenv("CBB_REAL_FORWARDER_PIN")
	if pinText == "" {
		pinText = forward.ProjectPins(nil)[0]
	}
	pin, err := base64.StdEncoding.DecodeString(pinText)
	if err != nil {
		t.Fatal(err)
	}

	h := startRustRootHub(t, startRustPhone(t, bin))
	defer h.p.call(t, map[string]any{"op": "hub_stop", "id": h.id})
	id, _ := tunnel.NewVLESSID()
	h.register(endpoint, pin, []group.Record{h.own}, id)
	var link map[string]any
	h.waitFor("the forwarder did not take the hub", func(r map[string]any) bool {
		link, _ = r["vless"].(map[string]any)
		seen, _ := r["seen"].(string)
		return link != nil && seen != ""
	})
	t.Logf("the hub is registered: %v", h.p.call(t, map[string]any{"op": "hub_status", "id": h.id})["forwarder"])
	link["id"] = id

	pub := h.hubKey.Public()
	offer := func(extra map[string]any) map[string]any {
		o := map[string]any{"hub_key": pub[:], "psk": h.psk[:]}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	if err := rustClientEcho(t, bin, string(h.dev), h.clientKey, offer(map[string]any{"vless": link})); err != nil {
		t.Fatalf("over VLESS with XHTTP: %v", err)
	}
	t.Log("over VLESS with XHTTP: through")
	if err := rustClientEcho(t, bin, string(h.dev), h.clientKey, offer(map[string]any{"endpoints": []string{endpoint}})); err != nil {
		t.Logf("plain WireGuard to the forwarder's UDP port: %v", err)
	} else {
		t.Log("plain WireGuard to the forwarder's UDP port: through")
	}
}

// rustClientEcho starts the Rust client with offer and sends a line
// through its loopback port to the hub's member listener and back.
func rustClientEcho(t *testing.T, bin, hub string, key tunnel.Key, offer map[string]any) error {
	t.Helper()
	p := startRustPhone(t, bin)
	started := p.call(t, map[string]any{"op": "start", "key": key[:], "device": rustPhoneID, "hub": hub, "offer": offer})
	defer p.call(t, map[string]any{"op": "stop", "id": started["id"]})
	c, err := net.Dial("tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(started["port"].(float64))).String())
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(45 * time.Second))
	msg := []byte("through the real forwarder")
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("%w (status %v)", err, p.call(t, map[string]any{"op": "status", "id": started["id"]}))
	}
	if string(got) != string(msg) {
		return fmt.Errorf("got %q", got)
	}
	return nil
}
