// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
)

// copies signs a copies record by signer, at time ms.
func (w *world) copies(name, signer string, ms, incoming int64) authority.Record {
	return w.sign(name, signer, authority.Body{Type: authority.TypeCopies, TimeMS: ms, IncomingMS: &incoming}, nil)
}

func (w *world) wantIncoming(s *authority.State, ms int64) {
	w.t.Helper()
	if s.IncomingMS != ms {
		w.t.Fatalf("incoming_ms %d, want %d: %s", s.IncomingMS, ms, mustEncode(w.t, s))
	}
}

// TestCopiesSetting: the copies record that counts gives how long an
// incoming copy stays live: any admin may sign one, whatever its powers,
// a root's beats an admin's whatever its time, between admins the later
// time wins.
func TestCopiesSetting(t *testing.T) {
	w := newWorld(t)
	w.makeAdmin("C", "member", computerPowers)
	w.makeAdmin("D", "member", []string{authority.PowerAdmit})
	w.wantIncoming(w.evalAll(nil), 0)

	// An admin with no power beyond admit sets it.
	w.copies("copies by D", "D", 10, 90_000)
	w.wantIncoming(w.evalAll(nil), 90_000)

	// A later admin record wins, an earlier one does not.
	w.copies("copies by C early", "C", 5, 20_000)
	w.wantIncoming(w.evalAll(nil), 90_000)
	w.copies("copies by C", "C", 30, 120_000)
	w.wantIncoming(w.evalAll(nil), 120_000)

	// The root's wins, though older by its clock.
	w.copies("copies by root", "root", 1, 30_000)
	w.wantIncoming(w.evalAll(nil), 30_000)
}

// TestCopiesBounds: incoming_ms is needed in a copies record and lies from
// MinIncoming to MaxIncoming.
func TestCopiesBounds(t *testing.T) {
	for _, ms := range []int64{authority.MinIncoming - 1, authority.MaxIncoming + 1, 0, -1} {
		b := authority.Body{V: 2, Alg: authority.AlgES256, Type: authority.TypeCopies, Group: "g", Seq: 1, TimeMS: 1, IncomingMS: &ms}
		if _, err := b.Encode(); err == nil {
			t.Errorf("incoming_ms %d encoded", ms)
		}
	}
	b := authority.Body{V: 2, Alg: authority.AlgES256, Type: authority.TypeCopies, Group: "g", Seq: 1, TimeMS: 1}
	if _, err := b.Encode(); err == nil {
		t.Error("a copies record without incoming_ms encoded")
	}
}
