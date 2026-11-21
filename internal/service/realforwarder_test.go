// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
)

// TestAwayThroughRealForwarder makes the pi a hub at a real forwarder on
// the internet, for a check from a network that blocks WireGuard:
// CBB_REAL_FORWARDER is the forwarder's host:port (cbb.tools:8764 for the
// project's), and CBB_REAL_FORWARDER_PIN its pin when it is not the
// project's. The pi registers, and the deck, for which no UDP passes,
// reaches it over VLESS with XHTTP alone and syncs both ways.
func TestAwayThroughRealForwarder(t *testing.T) {
	at := os.Getenv("CBB_REAL_FORWARDER")
	if at == "" {
		t.Skip("CBB_REAL_FORWARDER is not set")
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
	pin := os.Getenv("CBB_REAL_FORWARDER_PIN")
	if pin == "" {
		pin = forward.ProjectPins(nil)[0]
	}
	t.Setenv("CBB_DEBUG", "1")

	var h hub
	pi := startEnv(t, &h, "pi")
	deck := startEnv(t, &h, "deck", "CBB_TEST_DEAD_UDP="+deadUDP(t))
	pairWith(t, pi, deck)
	nameHubs(t, pi, "pi")
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: endpoint, ForwarderKey: pin}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 90*time.Second, "the hub registers with the real forwarder", func() bool {
		a := pi.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered && a.Forwarder.Seen != ""
	})
	t.Logf("the hub is registered: %+v", *pi.status(t).Away.Forwarder)
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer over VLESS", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID && a.VLESS
	})

	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 120*time.Second, "the deck reaches the hub through the real forwarder", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "through the real forwarder"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "through the real forwarder" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "back home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck has it", func() bool { return deck.paste(t) == "back home" })
}
