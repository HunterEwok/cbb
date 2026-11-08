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
// registers, inside VLESS when its hellos over UDP do not reach the
// forwarder, then a client reaches its member listener over VLESS with XHTTP alone;
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

	// The hub sends its hellos to the forwarder from its UDP socket, so that
	// socket is on every address, not the loopback one.
	h := startRustRootHubAt(t, startRustPhone(t, bin), "0.0.0.0:0")
	defer h.p.call(t, map[string]any{"op": "hub_stop", "id": h.id})
	id, _ := tunnel.NewVLESSID()
	h.register(endpoint, pin, []group.Record{h.own}, id)
	var link map[string]any
	h.waitFor("the forwarder did not take the hub", func(r map[string]any) bool {
		link, _ = r["vless"].(map[string]any)
		return link != nil
	})
	if !h.seenWithin(20 * time.Second) {
		// The hub's hellos over UDP do not reach the forwarder from here:
		// the hub registers inside VLESS instead, as it does when the
		// forwarder's TCP port does not answer, and its packets go there.
		t.Logf("the hub's hellos over UDP did not reach the forwarder; registering inside VLESS")
		h.register(net.JoinHostPort(ips[0].String(), "9"), pin, []group.Record{h.own}, id)
		h.waitFor("the forwarder never saw the hub over VLESS", func(r map[string]any) bool {
			seen, _ := r["seen"].(string)
			if l, _ := r["vless"].(map[string]any); l != nil {
				link = l
			}
			return seen != ""
		})
	}
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

// seenWithin reports whether the forwarder sees the hub's hellos within d.
func (h *rustRootHub) seenWithin(d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		st := h.p.call(h.t, map[string]any{"op": "hub_status", "id": h.id})
		if r, _ := st["forwarder"].(map[string]any); r != nil {
			if seen, _ := r["seen"].(string); seen != "" {
				return true
			}
		}
	}
	return false
}
