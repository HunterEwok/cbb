// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestMediaAway: the hub passes images and files between the members at
// home and the one away from home, which reaches only the hub, even in a
// mode that keeps the hub's clipboard to itself; the hub's limit away from
// home caps what goes through its tunnel.
func TestMediaAway(t *testing.T) {
	t.Setenv("CBB_DEBUG", "1")
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	mac := startService(t, &h, "mac")
	pairWith(t, pi, deck)
	pairWith(t, pi, mac)
	for _, s := range []*testService{pi, deck} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpSync, On: control.Bool(false)}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device
	waitFor(t, "the deck keeps the hub's offer", func() bool {
		a := deck.status(t).Away
		return a != nil && a.HubDevice == piID
	})
	deckID := deck.status(t).Device
	deck.stop()
	h.hide(deckID)
	deck = restartService(t, &h, deck)
	waitUpTo(t, 30*time.Second, "the deck reaches the hub through the tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == piID
	})
	waitFor(t, "the Mac meets the hub", func() bool { return len(mac.status(t).Peers) == 1 })

	// The Rust service keeps a copy's sealed blob under its own hash, not
	// its parts: there a copy has arrived when a file at least as large as
	// the part is in the cache that was not before the copy was made.
	before := map[[sha256.Size]byte]map[*testService]map[string]bool{}
	files := func(s *testService) map[string]bool {
		es, _ := os.ReadDir(filepath.Join(s.dir, contentDir))
		names := map[string]bool{}
		for _, e := range es {
			names[e.Name()] = true
		}
		return names
	}
	send := func(s *testService, name string, p sentPart) error {
		snap := map[*testService]map[string]bool{}
		for _, q := range []*testService{pi, deck, mac} {
			snap[q] = files(q)
		}
		before[sha256.Sum256(p.data)] = snap
		return s.copyMedia(t, name, p)
	}
	has := func(s *testService, data []byte) bool {
		sum := sha256.Sum256(data)
		if rustService() == "" {
			_, err := os.Stat(filepath.Join(s.dir, contentDir, hex.EncodeToString(sum[:])))
			return err == nil
		}
		es, _ := os.ReadDir(filepath.Join(s.dir, contentDir))
		for _, e := range es {
			fi, err := e.Info()
			if err == nil && !strings.HasSuffix(e.Name(), ".part") && !before[sum][s][e.Name()] && fi.Size() >= int64(len(data)) {
				return true
			}
		}
		return false
	}
	// Megabytes through the tunnel's WireGuard and TCP in the process take
	// a fraction of a second, but ten times as long under the race
	// detector, and longer still on CI's Mac runners: more than 30 s there.
	arrives := func(s *testService, sent sentPart) {
		t.Helper()
		waitUpTo(t, 90*time.Second, s.name+" fetches the copy", func() bool { return has(s, sent.data) })
		if _, got, err := s.pasteMedia(t); err != nil || len(got) != 1 || !bytes.Equal(got[0].data, sent.data) {
			t.Errorf("the copy on %s: %d parts, %v", s.name, len(got), err)
		}
	}

	// From home to the deck, and from the deck home, through the hub.
	fromMac := file("from-mac.bin", randomBytes(2<<20+7))
	if err := send(mac, "from-mac.bin", fromMac); err != nil {
		t.Fatal(err)
	}
	arrives(deck, fromMac)
	fromDeck := file("from-deck.bin", randomBytes(1<<20+3))
	if err := send(deck, "from-deck.bin", fromDeck); err != nil {
		t.Fatal(err)
	}
	arrives(mac, fromDeck)

	// Over the hub's limit away from home: the Mac's copy stays at home.
	if _, err := pi.do(t, control.Header{Op: control.OpConfig, Name: "max-copy-away", Value: "1MiB"}, ""); err != nil {
		t.Fatal(err)
	}
	large := file("large.bin", randomBytes(2<<20))
	if err := send(mac, "large.bin", large); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deck sees the copy", func() bool { return deck.paste(t) == "large.bin" })
	time.Sleep(3 * time.Second)
	if has(pi, large.data) || has(deck, large.data) {
		t.Errorf("a copy over the hub's limit away from home went on: the hub has it %v, the deck %v", has(pi, large.data), has(deck, large.data))
	}
	// One within it still goes.
	small := file("small.bin", randomBytes(512<<10))
	if err := send(mac, "small.bin", small); err != nil {
		t.Fatal(err)
	}
	arrives(deck, small)

	// A hub with sync on fetches it, but still serves through
	// its tunnel only what is within its limit away from home.
	if _, err := pi.do(t, control.Header{Op: control.OpSync, On: control.Bool(true)}, ""); err != nil {
		t.Fatal(err)
	}
	large = file("large.bin", randomBytes(2<<20))
	if err := send(mac, "large again", large); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the hub fetches the copy", func() bool { return has(pi, large.data) })
	time.Sleep(3 * time.Second)
	if has(deck, large.data) {
		t.Error("the hub served a copy over its limit away from home through its tunnel")
	}
}
