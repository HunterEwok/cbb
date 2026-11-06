// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
	"github.com/HunterEwok/cbb/internal/relay"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/uptime"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

func tunnelState(t *testing.T, s *testService) *tunnel.State {
	t.Helper()
	// On Windows a read fails for a moment while the service replaces the
	// file (a sharing violation), so a failed read is tried again.
	var err error
	for range 50 {
		var st *tunnel.State
		if st, err = tunnel.LoadState(s.dir); err == nil {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

// turnTunnelOn writes a tunnel state, as cbb will when the user turns sync
// away from home on.
func turnTunnelOn(t *testing.T, s *testService) {
	t.Helper()
	st, err := tunnel.NewState()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(s.dir); err != nil {
		t.Fatal(err)
	}
}

// TestTunnelKeys checks that the hub admits the tunnel key of each member
// it meets, that each member keeps the hub's offer with the same preshared
// key, and that the hub drops a member the group removes.
func TestTunnelKeys(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	mac := startRole(t, &h, "mac", group.OSMacOS)
	for _, s := range []*testService{pi, deck, mac} {
		turnTunnelOn(t, s)
	}
	pairWith(t, pi, deck)
	pairWith(t, pi, mac)

	// Make the pi the hub, as cbb will when the user turns it on.
	pi.stop()
	st := tunnelState(t, pi)
	if st.Group == "" {
		t.Fatal("the tunnel state names no group")
	}
	st.IsHub = true
	if err := st.Save(pi.dir); err != nil {
		t.Fatal(err)
	}
	pi = restartService(t, &h, pi)
	piID := pi.status(t).Device
	hubKey := st.Key.Public()

	for _, s := range []*testService{deck, mac} {
		// The members dial the restarted hub again with their backoff,
		// which a loaded machine stretches past 10 s.
		waitUpTo(t, 30*time.Second, s.name+" keeps the hub's offer", func() bool {
			return tunnelState(t, s).Hub(piID) != nil
		})
		mine := tunnelState(t, s)
		if got := mine.Hub(piID).PublicKey; got != hubKey {
			t.Errorf("%s keeps hub key %x, want %x", s.name, got, hubKey)
		}
		dev := s.status(t).Device
		var found bool
		for _, m := range tunnelState(t, pi).Members {
			if m.Device == dev {
				found = true
				if m.PublicKey != mine.Key.Public() || m.PresharedKey != mine.Hub(piID).PresharedKey || m.PresharedKey != mine.PSK {
					t.Errorf("the hub keeps %s with other keys", s.name)
				}
			}
		}
		if !found {
			t.Errorf("the hub does not keep %s", s.name)
		}
	}
	if n := len(tunnelState(t, pi).Members); n != 2 {
		t.Errorf("the hub keeps %d members, want 2", n)
	}
	if len(tunnelState(t, pi).Hubs) != 0 {
		t.Error("the hub keeps an offer of its own")
	}

	// A member that is no admin making itself a hub too gets nowhere: the
	// Mac keeps the offer of the pi, the group's root.
	macID := mac.status(t).Device
	deck.stop()
	dst := tunnelState(t, deck)
	dst.IsHub, dst.Hubs = true, nil
	if err := dst.Save(deck.dir); err != nil {
		t.Fatal(err)
	}
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck takes the Mac's key", func() bool {
		for _, m := range tunnelState(t, deck).Members {
			if m.Device == macID {
				return true
			}
		}
		return false
	})
	if st := tunnelState(t, mac); st.Hub(piID) == nil || len(st.Hubs) != 1 {
		t.Errorf("the Mac took the offer of a member that is no admin")
	}

	// Removing the Mac drops it from the hub.
	if _, err := pi.do(t, control.Header{Op: control.OpRevoke, Name: "mac"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub drops the Mac", func() bool {
		for _, m := range tunnelState(t, pi).Members {
			if m.Device == macID {
				return false
			}
		}
		return true
	})
}

// TestAwayOffCommand checks that an admin turns sync away from home off on
// another member with an away-off command (cbb global off -on), which
// takes its keys too, and that a member that is no admin sends none.
func TestAwayOffCommand(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	turnTunnelOn(t, deck)
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if st := deck.status(t); st.Away == nil {
		t.Fatal("sync away from home is not on on the deck")
	}
	if _, err := deck.do(t, control.Header{Op: control.OpAway, Name: "off", Device: "pi"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("the deck turned it off on the pi: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "off", Device: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	if st := deck.status(t); st.Away != nil {
		t.Errorf("away is still on on the deck: %+v", st.Away)
	}
	if _, err := os.Stat(filepath.Join(deck.dir, tunnel.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the deck's tunnel state is still there: %v", err)
	}
}

// TestTunnelOffByDefault checks that a member where sync away from home is
// off offers no key and makes no tunnel state, even when the group has a
// hub.
func TestTunnelOffByDefault(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	turnTunnelOn(t, pi)
	pairWith(t, pi, deck)

	pi.stop()
	st := tunnelState(t, pi)
	st.IsHub = true
	if err := st.Save(pi.dir); err != nil {
		t.Fatal(err)
	}
	pi = restartService(t, &h, pi)
	waitFor(t, "the hub meets the deck", func() bool { return len(pi.status(t).Peers) > 0 })

	if n := len(tunnelState(t, pi).Members); n != 0 {
		t.Errorf("the hub keeps %d members, want none", n)
	}
	if _, err := os.Stat(filepath.Join(deck.dir, tunnel.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the deck made a tunnel state: %v", err)
	}
}

// TestAwayFromHome turns sync away from home on, makes the pi the hub, and
// checks that the deck, once on another network, syncs with it through the
// tunnel, and that turning it off forgets the keys.
func TestAwayFromHome(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1") // WireGuard's messages in the log, if it fails
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)

	if _, err := deck.do(t, control.Header{Op: control.OpAway, Name: "on"}, ""); err == nil || !strings.Contains(err.Error(), "consent") {
		t.Errorf("away on without consent: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Addrs: []string{"127.0.0.1:1"}}, ""); err == nil {
		t.Error("a hub while sync away from home is off")
	}
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	m, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := m.Status.Away; a == nil || !a.Hub || a.Port != port || a.Error != "" {
		t.Fatalf("the hub's status: %+v", a)
	}
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID
	})

	// The deck leaves the home network: it reaches the pi only through
	// the tunnel.
	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	// A first WireGuard handshake that is lost is sent again after the
	// rekey timeout of 5 s, and the TCP connection inside waits for it with
	// its own backoff; on Windows CI that has taken more than 10 s.
	waitUpTo(t, 30*time.Second, "the deck reaches the hub through the tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from far away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from far away" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck has it", func() bool { return deck.paste(t) == "from home" })

	// Off: the keys are gone and the deck no longer reaches the pi.
	m, err = deck.do(t, control.Header{Op: control.OpAway, Name: "off"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Status.Away != nil {
		t.Errorf("away is still on: %+v", m.Status.Away)
	}
	if _, err := os.Stat(filepath.Join(deck.dir, tunnel.StateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the tunnel state is still there: %v", err)
	}
	waitFor(t, "the deck is alone", func() bool { return len(deck.status(t).Peers) == 0 })
}

// TestHubKeyRotation checks that the hub takes a new WireGuard key for
// each period of the server credentials: its offers give the next key
// ahead of time, and a client that was away while the hub moved on to it
// reaches the hub with it.
func TestHubKeyRotation(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1")
	every, ahead := renewEvery, hubKeyAhead
	renewEvery, hubKeyAhead = 200*time.Millisecond, 24*time.Hour
	t.Cleanup(func() { renewEvery, hubKeyAhead = every, ahead })
	var skew atomic.Int64
	var h hub
	pi := startWith(t, &h, "pi", group.OSLinux, func(c *Config) {
		c.now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	})
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device
	// The pi replaces its state every renewEvery. On Windows a file cannot
	// be opened for the moment it is being replaced ("used by another
	// process"), so a read tries again for up to two seconds, as the
	// writer does (atomicfile).
	load := func(s *testService) *tunnel.State {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			st, err := tunnel.LoadState(s.dir)
			if err == nil {
				return st
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	var old, next tunnel.Key
	waitFor(t, "the deck keeps the hub's key for the next period", func() bool {
		st := load(pi)
		if st.Next.IsZero() {
			return false
		}
		old, next = st.ServingKey().Public(), st.Next.Public()
		l := load(deck).Hub(piID)
		return l != nil && l.PublicKey == old && l.Next == next
	})

	// The deck is away and off while the hub moves on to the new key.
	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	skew.Store(int64(25 * time.Hour))
	waitFor(t, "the hub serves with the new key", func() bool {
		st := load(pi)
		return st.Next.IsZero() && st.ServingKey().Public() == next
	})
	deck = restartService(t, &h, deck)
	// The deck tries the old key and the new one at once, so the old one,
	// which gets no answer, costs it no time.
	waitFor(t, "the deck reaches the hub with the new key", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	waitFor(t, "the deck keeps the new key", func() bool {
		l := load(deck).Hub(piID)
		return l != nil && l.PublicKey == next && l.Next.IsZero()
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "after the new period"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "after the new period" })
}

// TestAwayObfuscated makes the pi an obfuscated hub: the deck gets its
// AmneziaWG settings with the offer at home and syncs with it away, and
// setting the hub again keeps the settings.
func TestAwayObfuscated(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1")
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	hubAt := control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}, Obfuscate: true}
	m, err := pi.do(t, hubAt, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := m.Status.Away; a == nil || !a.Hub || !a.Obfuscated {
		t.Fatalf("the hub's status: %+v", a)
	}
	obf := tunnelState(t, pi).Obfuscation
	if obf == nil {
		t.Fatal("the hub keeps no obfuscation settings")
	}
	if _, err := pi.do(t, hubAt, ""); err != nil {
		t.Fatal(err)
	}
	if again := tunnelState(t, pi).Obfuscation; !again.Equal(obf) {
		t.Error("setting the hub again made new obfuscation settings")
	}
	// The apps' switch sets only how the tunnel hides and keeps the rest.
	keep := control.Header{Op: control.OpAway, Name: "hub", Keep: true, Obfuscate: true}
	if _, err := pi.do(t, keep, ""); err != nil {
		t.Fatal(err)
	}
	if st := tunnelState(t, pi); !st.Obfuscation.Equal(obf) || st.ListenPort != port || len(st.Endpoints) != 1 || st.Endpoints[0].Port() != uint16(port) || st.Forwarder != nil {
		t.Errorf("-keep changed the hub: port %d, endpoints %v, forwarder %+v", st.ListenPort, st.Endpoints, st.Forwarder)
	}
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer with its settings", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID && a.Obfuscated
	})
	if got := tunnelState(t, deck).Hub(piID).Obfuscation; !got.Equal(obf) {
		t.Fatalf("the deck keeps %+v, the hub has %+v", got, obf)
	}

	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck reaches the hub through the obfuscated tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "hidden on the way"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "hidden on the way" })

	keep.Obfuscate = false
	if _, err := pi.do(t, keep, ""); err != nil {
		t.Fatal(err)
	}
	if st := tunnelState(t, pi); st.Obfuscation != nil || st.ListenPort != port || len(st.Endpoints) != 1 {
		t.Errorf("-keep without -obfuscate: obfuscation %+v, port %d, endpoints %v", st.Obfuscation, st.ListenPort, st.Endpoints)
	}
	if _, err := deck.do(t, keep, ""); err == nil {
		t.Error("-keep made a device that is no hub one")
	}
}

// TestAwayThroughForwarder makes the pi a hub that only a forwarder
// reaches, as behind carrier-grade NAT, and checks that the deck syncs with
// it through the forwarder, with plain WireGuard and obfuscated.
func TestAwayThroughForwarder(t *testing.T) {
	t.Run("plain", func(t *testing.T) { testAwayThroughForwarder(t, false, false) })
	t.Run("obfuscated", func(t *testing.T) { testAwayThroughForwarder(t, true, false) })
	// VLESS comes with AmneziaWG, which goes first over UDP.
	t.Run("vless", func(t *testing.T) { testAwayThroughForwarder(t, false, true) })
	// Where no UDP passes, the deck falls back to VLESS.
	t.Run("vless without UDP", func(t *testing.T) {
		dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		// Put back after the services stop, which their cleanups do.
		t.Cleanup(func() { dead.Close(); udpBlocked = nil })
		udpBlocked = func(eps []netip.AddrPort) []netip.AddrPort {
			out := make([]netip.AddrPort, len(eps))
			for i := range out {
				out[i] = dead.LocalAddr().(*net.UDPAddr).AddrPort()
			}
			return out
		}
		testAwayThroughForwarder(t, false, true)
	})
}

func testAwayThroughForwarder(t *testing.T, obfuscate, overVLESS bool) {
	t.Setenv("CBB_DEBUG", "1")
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state.json")
	cfg := forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf, StateFile: state}
	if overVLESS {
		cfg.VLESS = &forward.VLESSConfig{Listen: "127.0.0.1:0", Site: vlesstest.Site, Dest: vlesstest.Decoy(t)}
		rand.Read(cfg.VLESS.Key[:])
	}
	f, err := forward.Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// A client that comes before the forwarder has learned the site
	// waits for it, and its handshakes with it.
	rctx, rcancel := context.WithTimeout(context.Background(), time.Minute)
	defer rcancel()
	if err := f.Ready(rctx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		f.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()

	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Forwarder: f.Addr().String(), ForwarderKey: "nope"}, ""); err == nil {
		t.Error("a forwarder with a bad key")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(), ForwarderKey: forward.Pin(cert.Leaf),
		Obfuscate: obfuscate, VLESS: overVLESS}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub registers with the forwarder", func() bool {
		a := pi.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered && a.Forwarder.Seen != ""
	})
	// The pi, the group's root, registered with the period's hubs'
	// credential it signed, which the deck keeps too. The forwarder writes
	// its state a moment after a change.
	waitFor(t, "the forwarder's state after a registration with a credential", func() bool {
		var kept map[string]json.RawMessage
		b, err := os.ReadFile(state)
		return err == nil && json.Unmarshal(b, &kept) == nil && len(kept) == 1
	})
	waitFor(t, "the deck keeps the credential", func() bool {
		_, err := os.Stat(filepath.Join(deck.dir, group.CredentialsFileName))
		return err == nil
	})
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID && len(a.Endpoints) == 1 && a.Endpoints[0] == f.Addr().String() && a.Obfuscated == (obfuscate || overVLESS) &&
			a.VLESS == overVLESS
	})

	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	// Without UDP the deck waits out a window on each endpoint before
	// VLESS, which under the race detector on a slow runner takes a
	// while as well.
	waitUpTo(t, 90*time.Second, "the deck reaches the hub through the forwarder", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "via the forwarder"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "via the forwarder" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "back home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck has it", func() bool { return deck.paste(t) == "back home" })
}

// TestAwayThroughRelay checks a group without a hub: both devices meet at a
// blind relay, and once one leaves the home network they sync through it.
func TestAwayThroughRelay(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	keys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen(relay.Config{Listen: "127.0.0.1:0", Keys: keys, Groups: []string{pi.status(t).Group}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()

	// The relay turns sync away from home on by itself (pi), or takes the
	// place of its hubs (deck).
	if _, err := deck.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: "nope"}, ""); err == nil {
			t.Error("a relay with a bad key")
		}
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin()}, ""); err == nil || !strings.Contains(err.Error(), "learns") {
			t.Errorf("a relay without consent: %v", err)
		}
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin(), Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	piID, deckID := pi.status(t).Device, deck.status(t).Device
	// Two registrations, each with a tunnel of its own in the process: about
	// a second, but five under the race detector on a Mac, and longer still on
	// CI's Mac runners.
	waitUpTo(t, 60*time.Second, "both meet at the relay", func() bool {
		a, b := pi.status(t).Away, deck.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected && len(a.Relay.Online) == 1 && a.Relay.Online[0] == deckID &&
			b != nil && b.Relay != nil && b.Relay.Connected && len(b.Relay.Online) == 1 && b.Relay.Online[0] == piID
	})

	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck reaches the pi through the relay", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "via the relay"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "via the relay" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "back home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck has it", func() bool { return deck.paste(t) == "back home" })

	// Turning sync away from home off leaves the relay.
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay drops the pi", func() bool {
		_, n := r.Stats()
		return n == 1
	})
}

// freeUDP returns a UDP port that is free on all addresses, as the hub
// listens. It picks it below the systems' ephemeral ranges (Linux from
// 32768, macOS and Windows from 49152): a port the kernel handed out and
// took back could go to a socket of another test package before the hub
// binds it. It never hands out a port twice: a test that takes two ports
// before binding either, such as one for each of two hubs, would otherwise
// get the same port now and then, and one hub's packets would go to the
// other.
func freeUDP(t *testing.T) int {
	t.Helper()
	udpPorts.Lock()
	defer udpPorts.Unlock()
	for range 100 {
		port := 20000 + mrand.IntN(10000)
		if udpPorts.given[port] {
			continue
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err != nil {
			continue
		}
		c.Close()
		udpPorts.given[port] = true
		return port
	}
	t.Fatal("no free UDP port")
	return 0
}

// udpPorts holds the ports freeUDP handed out.
var udpPorts = struct {
	sync.Mutex
	given map[int]bool
}{given: map[int]bool{}}

// TestJoinByAddress checks that a device that joined at an address, as
// through an SSH forward or a VPN, keeps a member connection to the member
// that admitted it although discovery cannot find it, and so meets the hub
// and learns its offer when sync away from home is turned on.
func TestJoinByAddress(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	c, code := openWindow(t, pi)
	defer c.Close()
	piID := pi.status(t).Device
	h.hide(piID) // the deck is on another network
	addr := h.memberAddr(t, piID)
	if _, err := deck.do(t, control.Header{Op: control.OpJoin, Code: code, Address: addr}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck connects to the pi where it joined", func() bool {
		p := deck.status(t).Peers
		return len(p) == 1 && p[0].ID == piID
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from the deck"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from the deck" })

	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck keeps the hub's offer", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID
	})
}

// TestNearOnlyForAWhile checks that an announcement alone keeps a member
// "on this network" only for nearGrace: anyone can announce a hub's name
// and the group's tag on a foreign network.
func TestNearOnlyForAWhile(t *testing.T) {
	id := group.DeviceID(strings.Repeat("a", 32))
	s := &Service{nearby: map[group.DeviceID]time.Duration{id: uptime.Now()}}
	if !s.nearLocked(id) {
		t.Error("a member just found does not count as near")
	}
	s.nearby[id] = uptime.Now() - nearGrace - time.Second
	if s.nearLocked(id) {
		t.Error("a member found long ago without a connection still counts as near")
	}
	if s.nearLocked(group.DeviceID(strings.Repeat("b", 32))) {
		t.Error("a member never found counts as near")
	}
}

// TestHubWait checks that a member tries a hub that is a phone, there
// only while its app is open, more often than one that is a computer.
func TestHubWait(t *testing.T) {
	now := time.Now()
	ca, err := group.NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{records: group.NewRecords(ca.Cert)}
	phone, pc := group.NewDeviceID(), group.NewDeviceID()
	for _, d := range []struct {
		id   group.DeviceID
		role string
	}{{phone, group.RolePhone}, {pc, group.RoleFull}} {
		key, _ := group.NewKey()
		leaf, err := ca.IssueMember(d.id, &key.PublicKey, now)
		if err != nil {
			t.Fatal(err)
		}
		k := group.KeyHashOf(leaf)
		r := grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: group.Tag(ca.Cert), TimeMS: now.UnixMilli(),
			Device: string(d.id), Name: d.role, Role: d.role, Key: &k}, ca.Key)
		if ok, err := s.records.Add(r); !ok || err != nil {
			t.Fatalf("adding the record of the %s: %v", d.role, err)
		}
	}
	if w := s.hubWait(phone); w != phoneHubWait {
		t.Errorf("a phone hub: %v", w)
	}
	if w := s.hubWait(pc); w != maxBackoff {
		t.Errorf("a computer hub: %v", w)
	}
	if w := (&Service{}).hubWait(phone); w != maxBackoff {
		t.Errorf("no records: %v", w)
	}
}

// TestMoveHub moves the hub from the pi to the Mac, an admin, while the
// deck is far away and reaches the pi through the tunnel: the Mac takes the
// pi's clients, the deck gets the Mac's offer through the tunnel with its
// own preshared key and reaches the Mac, and the pi becomes the Mac's
// client (docs/protocol.md, section 11, "Moving the hub").
func TestMoveHub(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1")
	var h hub
	pi := startService(t, &h, "pi")
	mac := startService(t, &h, "mac")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, mac)
	pairWith(t, pi, deck)
	makeAdmin(t, pi, mac)
	for _, s := range []*testService{pi, mac, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	// The Mac's hub will listen on a port of its own.
	macPort := freeUDP(t)
	mac.stop()
	mst := tunnelState(t, mac)
	mst.ListenPort = macPort
	if err := mst.Save(mac.dir); err != nil {
		t.Fatal(err)
	}
	mac = restartService(t, &h, mac)

	piPort := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: piPort, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", piPort)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID, macID, deckID := pi.status(t).Device, mac.status(t).Device, deck.status(t).Device
	for _, s := range []*testService{mac, deck} {
		waitUpTo(t, 30*time.Second, s.name+" keeps the pi's offer", func() bool {
			a := s.status(t).Away
			return a != nil && a.HubDevice == piID
		})
	}
	deckPSK := tunnelState(t, deck).Hub(piID).PresharedKey

	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck reaches the pi through the tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})

	if _, err := deck.do(t, control.Header{Op: control.OpAway, Name: "move", Device: "mac"}, ""); err == nil {
		t.Error("a device that is not the hub moved it")
	}
	m, err := pi.do(t, control.Header{Op: control.OpAway, Name: "move", Device: "mac", Addrs: []string{fmt.Sprintf("127.0.0.1:%d", macPort)}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if a := m.Status.Away; a == nil || a.Hub || a.HubDevice != macID {
		t.Errorf("the pi after the move: %+v", a)
	}
	if a := mac.status(t).Away; a == nil || !a.Hub {
		t.Errorf("the Mac after the move: %+v", a)
	}
	waitUpTo(t, 30*time.Second, "the deck takes the Mac's offer", func() bool {
		st := tunnelState(t, deck)
		return st.Hub(macID) != nil && st.Hub(piID) == nil
	})
	if got := tunnelState(t, deck).Hub(macID).PresharedKey; got != deckPSK {
		t.Error("the deck's preshared key changed with the move")
	}
	var kept bool
	for _, c := range tunnelState(t, mac).Members {
		kept = kept || c.Device == deckID && c.PresharedKey == deckPSK
	}
	if !kept {
		t.Error("the Mac does not keep the deck with its preshared key")
	}
	waitUpTo(t, 30*time.Second, "the deck reaches the Mac through the tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == macID })
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "after the move"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Mac has it", func() bool { return mac.paste(t) == "after the move" })

	// The pi, the root, is a hub again: the Mac gives way, but first passes
	// the pi's offer on to the deck, which knew only the Mac's since the
	// move, so that the deck far away reaches the pi.
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: piPort, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", piPort)}}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 60*time.Second, "the Mac gives way to the pi", func() bool {
		a := mac.status(t).Away
		return a != nil && a.Hub && a.Standby
	})
	waitUpTo(t, 60*time.Second, "the deck reaches the pi through the tunnel again", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && st.Away.HubDevice == piID &&
			slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == piID })
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "the root is the hub again"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "the root is the hub again" })
}

// TestSeveralHubs runs two hubs, the pi, the root, above the Mac, an
// admin, with the deck far away: the deck keeps both offers and reaches the
// pi; the Mac waits as the pi's client; when the pi stops, the Mac serves
// and the deck reaches it; when the pi comes back, the Mac yields and the
// deck moves back to the pi (docs/protocol.md, section 11, "Several hubs").
func TestSeveralHubs(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1")
	// The deck stays on the Mac, below the pi, for upCheck, then dials the
	// pi for up to handshakeTimeout: long enough to sync on a slow runner.
	upCheck, standbyGrace = 20*time.Second, 2*time.Second
	t.Cleanup(func() { upCheck, standbyGrace = 5*time.Minute, time.Minute })
	var h hub
	pi := startService(t, &h, "pi")
	mac := startService(t, &h, "mac")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, mac)
	pairWith(t, pi, deck)
	makeAdmin(t, pi, mac)
	for _, s := range []*testService{pi, mac, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	piPort, macPort := freeUDP(t), freeUDP(t)
	for _, c := range []struct {
		s    *testService
		port int
	}{{pi, piPort}, {mac, macPort}} {
		if _, err := c.s.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: c.port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", c.port)}}, ""); err != nil {
			t.Fatal(err)
		}
	}
	piID, macID, deckID := pi.status(t).Device, mac.status(t).Device, deck.status(t).Device
	waitUpTo(t, 30*time.Second, "the deck keeps both hubs' offers", func() bool {
		st := tunnelState(t, deck)
		return st.Hub(piID) != nil && st.Hub(macID) != nil && st.PSK == st.Hub(macID).PresharedKey
	})
	waitUpTo(t, 30*time.Second, "the Mac waits as the pi's client", func() bool {
		a := mac.status(t).Away
		return a != nil && a.Hub && a.Standby && a.HubDevice == piID
	})
	if a := pi.status(t).Away; a == nil || a.Standby {
		t.Errorf("the pi, the first hub, does not serve: %+v", a)
	}
	// The pi shares the clients it admits with the Mac, so the deck may
	// fail over to the Mac even if the two never met.
	waitUpTo(t, 30*time.Second, "the Mac knows the deck", func() bool {
		return slices.ContainsFunc(tunnelState(t, mac).Members, func(m tunnel.Member) bool { return m.Device == deckID })
	})

	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	through := func(hub string) func() bool {
		return func() bool {
			st := deck.status(t)
			return st.Away != nil && st.Away.Through && st.Away.HubDevice == hub &&
				slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == hub })
		}
	}
	waitUpTo(t, 30*time.Second, "the deck reaches the pi through the tunnel", through(piID))

	// The pi stops: the Mac serves, and the deck reaches it.
	pi.stop()
	waitUpTo(t, 60*time.Second, "the Mac serves", func() bool {
		a := mac.status(t).Away
		return a != nil && !a.Standby
	})
	waitUpTo(t, 60*time.Second, "the deck reaches the Mac through the tunnel", through(macID))
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "while the pi is off"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Mac has it", func() bool { return mac.paste(t) == "while the pi is off" })

	// The pi comes back: the Mac yields, and the deck moves back.
	pi = restartService(t, &h, pi)
	waitUpTo(t, 60*time.Second, "the Mac yields to the pi", func() bool {
		a := mac.status(t).Away
		return a != nil && a.Standby
	})
	waitUpTo(t, 60*time.Second, "the deck reaches the pi again", through(piID))
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "the pi is back"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "the pi is back" })
}

// TestHubsToTry checks the hubs a member tries, in the group's order: all
// it keeps offers of, or on a hub those above it; never a device outside
// the order, itself or one without an address.
func TestHubsToTry(t *testing.T) {
	ep := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:8764")}
	link := func(dev string) tunnel.HubLink { return tunnel.HubLink{Device: dev, Endpoints: ep} }
	order := []group.DeviceID{"phone", "mac", "pi"}
	st := &tunnel.State{Hubs: []tunnel.HubLink{link("pi"), link("stranger"), link("phone"), {Device: "mac"}}}
	devs := func(hs []tunnel.HubLink) (out []string) {
		for _, h := range hs {
			out = append(out, h.Device)
		}
		return out
	}
	if got := devs(hubsToTry(order, "deck", st)); !slices.Equal(got, []string{"phone", "pi"}) {
		t.Errorf("a client tries %v", got)
	}
	st.IsHub = true
	if got := devs(hubsToTry(order, "pi", st)); !slices.Equal(got, []string{"phone"}) {
		t.Errorf("the lowest hub tries %v", got)
	}
	if got := devs(hubsToTry(order, "phone", st)); len(got) != 0 {
		t.Errorf("the first hub tries %v", got)
	}

	// A hub with a key for the next period is tried once, with both keys
	// (tryHub).
	st.IsHub = false
	st.Hubs[2].PublicKey, st.Hubs[2].Next = tunnel.Key{1}, tunnel.Key{2}
	got := hubsToTry(order, "deck", st)
	if !slices.Equal(devs(got), []string{"phone", "pi"}) || got[0].PublicKey != (tunnel.Key{1}) || got[0].Next != (tunnel.Key{2}) {
		t.Errorf("a client tries %+v", got)
	}
}

// TestMakeHub has the pi, the group's root and not a hub, make the Mac, an
// admin, a hub of the group: the Mac refuses while sync away from home is
// off there, then becomes a hub and serves, and the pi keeps its offer. A
// device that is no admin cannot be made one.
func TestMakeHub(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	mac := startService(t, &h, "mac")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, mac)
	pairWith(t, pi, deck)
	makeAdmin(t, pi, mac)
	macID := mac.status(t).Device

	for _, d := range pi.devices(t) {
		if want := d.Name == "pi" || d.Name == "mac"; d.MayHub != want {
			t.Errorf("%s: may_hub %v", d.Name, d.MayHub)
		}
	}
	port := freeUDP(t)
	addr := []string{fmt.Sprintf("127.0.0.1:%d", port)}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "mac", Addrs: addr}, ""); err == nil || !strings.Contains(err.Error(), "turn it on there first") {
		t.Errorf("a Mac without sync away from home became a hub: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "deck", Addrs: addr}, ""); err == nil || !strings.Contains(err.Error(), "make it an admin first") {
		t.Errorf("a device that is no admin became a hub: %v", err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "mac", Addrs: addr}, ""); err == nil {
		t.Error("a device that is no admin made another a hub")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "mac"}, ""); err == nil {
		t.Error("made a hub without addresses or a forwarder")
	}

	for _, s := range []*testService{pi, mac} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	mac.stop()
	mst := tunnelState(t, mac)
	mst.ListenPort = port
	if err := mst.Save(mac.dir); err != nil {
		t.Fatal(err)
	}
	mac = restartService(t, &h, mac)
	waitUpTo(t, 30*time.Second, "the pi and the Mac meet again", func() bool {
		return len(pi.status(t).Peers) == 2
	})
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "mac", Addrs: addr}, ""); err != nil {
		t.Fatal(err)
	}
	if a := mac.status(t).Away; a == nil || !a.Hub {
		t.Errorf("the Mac: %+v", a)
	}
	if a := pi.status(t).Away; a == nil || a.Hub {
		t.Errorf("the pi became a hub itself: %+v", a)
	}
	if tunnelState(t, pi).Hub(macID) == nil {
		t.Error("the pi did not keep the Mac's offer")
	}
	var pid string
	for _, c := range tunnelState(t, mac).Members {
		pid = c.Device
	}
	if pid != pi.status(t).Device {
		t.Errorf("the Mac's clients: %+v", tunnelState(t, mac).Members)
	}
	// Both list the Mac as the group's hub, and only the Mac.
	for _, s := range []*testService{pi, mac} {
		for _, d := range s.devices(t) {
			if want := d.Name == "mac"; d.Hub != want {
				t.Errorf("on %s, %s: hub %v", s.name, d.Name, d.Hub)
			}
		}
	}
}

// TestStopHub has the pi, the group's root, and the Mac, an admin, both be
// hubs: the deck, no admin, cannot stop one; the pi makes the Mac stop
// being a hub, and every device forgets the Mac's offer; the pi, then the
// only hub, stops only with the user's word, and the deck forgets its offer
// too.
func TestStopHub(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	mac := startService(t, &h, "mac")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, mac)
	pairWith(t, pi, deck)
	makeAdmin(t, pi, mac)
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub-off"}, ""); err == nil || !strings.Contains(err.Error(), "no hub") {
		t.Errorf("a device that is no hub stopped being one: %v", err)
	}
	// The Mac turns sync away from home on with its hub, by its user's
	// word (cbb global hub -away-on), and not without it.
	hubAt := func(port int) control.Header {
		return control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}
	}
	if _, err := mac.do(t, hubAt(freeUDP(t)), ""); err == nil || !strings.Contains(err.Error(), "-away-on") {
		t.Errorf("a hub without sync away from home: %v", err)
	}
	withAway := hubAt(freeUDP(t))
	withAway.Consent = true
	if _, err := mac.do(t, withAway, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, hubAt(freeUDP(t)), ""); err != nil {
		t.Fatal(err)
	}
	piID, macID := pi.status(t).Device, mac.status(t).Device
	waitUpTo(t, 30*time.Second, "the deck and the pi keep the Mac's offer", func() bool {
		return tunnelState(t, deck).Hub(macID) != nil && tunnelState(t, pi).Hub(macID) != nil && tunnelState(t, deck).Hub(piID) != nil
	})
	if _, err := deck.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Device: "mac"}, ""); err == nil {
		t.Error("a device that is no admin stopped a hub")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Device: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "no hub") {
		t.Errorf("stopped a device that is no hub: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Device: "mac"}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the Mac is no hub", func() bool {
		a := mac.status(t).Away
		return a != nil && !a.Hub && tunnelState(t, mac).Retired
	})
	// Until it stopped, the Mac may share its offer again, so the others
	// forget it for good once it says it stopped.
	waitUpTo(t, 30*time.Second, "the pi and the deck forget the Mac's offer", func() bool {
		return tunnelState(t, pi).Hub(macID) == nil && tunnelState(t, deck).Hub(macID) == nil
	})
	for _, d := range deck.devices(t) {
		if want := d.Name == "pi"; d.Hub != want {
			t.Errorf("on the deck, %s: hub %v", d.Name, d.Hub)
		}
	}

	// The pi is the only hub now.
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub-off"}, ""); err == nil || !strings.Contains(err.Error(), "no other hub") {
		t.Errorf("the only hub stopped without the user's word: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Force: true}, ""); err != nil {
		t.Fatal(err)
	}
	if a := pi.status(t).Away; a == nil || a.Hub {
		t.Errorf("the pi: %+v", a)
	}
	waitUpTo(t, 30*time.Second, "the deck forgets the pi's offer", func() bool {
		return tunnelState(t, deck).Hub(piID) == nil
	})
	// It is a hub again at its user's word.
	if _, err := pi.do(t, hubAt(freeUDP(t)), ""); err != nil {
		t.Fatal(err)
	}
	if st := tunnelState(t, pi); !st.IsHub || st.Retired {
		t.Errorf("the pi as a hub again: hub %v, retired %v", st.IsHub, st.Retired)
	}
}
