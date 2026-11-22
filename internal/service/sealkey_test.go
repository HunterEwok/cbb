// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestSealKeysRecorded: on the records of 0.6 each member offers its
// sealing key in its statement, which the others hold; a command's orders
// are sealed to the receiver's key (format section 6), so the deck takes a
// command only when the root holds its key, and again after a restart,
// whose keys stay.
func TestSealKeysRecorded(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	var deckID string
	for _, d := range pi.devices(t) {
		if d.Name == "deck" {
			deckID = d.ID
		}
	}
	command := func(on bool, word string) {
		t.Helper()
		// Until the root holds the deck's statement it has no key to
		// seal to, and says so; it holds it once they talked.
		waitFor(t, "the root seals a command to the deck", func() bool {
			_, err := pi.do(t, control.Header{Op: control.OpSync, Device: deckID, On: control.Bool(on)}, "")
			return err == nil
		})
		waitFor(t, "the deck opens the sealed command", func() bool { return deck.logged("turned sync " + word + " here") })
	}
	command(false, "off")
	if deck.status(t).Mode != "own" {
		t.Error("the deck did not take the sealed mode command")
	}
	// The deck's sealing keys stay across a restart: a command sealed to
	// them still opens.
	deck.stop()
	deck = restartService(t, &h, deck)
	waitFor(t, "the deck is back", func() bool { return len(pi.status(t).Peers) == 1 })
	command(true, "on")
	if deck.status(t).Mode != "shared" {
		t.Error("the deck did not take the sealed mode command after a restart")
	}
}
