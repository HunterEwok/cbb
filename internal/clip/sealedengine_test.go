// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/hlc"
)

// sealedEngine is an engine of the device d that seals its copies to
// readers.
func sealedEngine(d testDevice, readers ...testDevice) *Engine {
	return New(Config{
		Self: d.id, Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil),
		Seal: func(ev Event) (*Sealed, error) {
			return SealCopy(ev.ID, ev.Origin, ev.Time, d.cert.Raw, nil, readersOf(readers...),
				Content{Kind: ev.Kind, Via: ev.Via, Text: ev.Text, Media: ev.Media}, nil, NewKey(), d.key)
		},
	})
}

// TestSealedEvents: a reader opens and writes a copy; a member it is not
// sealed to keeps it as current, unread, forwards it and writes nothing;
// a reader sends a secret in its hello only as the mark, and the full
// copy that follows the mark gives the reader its text.
func TestSealedEvents(t *testing.T) {
	a, b, hub := newDevice(t), newDevice(t), newDevice(t)
	ea := sealedEngine(a, a, b)
	ev, res, err := ea.Send("hello", Text, Copy)
	if err != nil || ev.Sealed == nil || !res.Write {
		t.Fatalf("send: %v, sealed %v", err, ev.Sealed != nil)
	}
	got, err := EventOf(ev.Sealed, b.id, b.secret)
	if err != nil || got.Unread || got.Text != "hello" {
		t.Fatalf("b reads %+v, %v", got, err)
	}
	eb := New(Config{Self: b.id, Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	if r, err := eb.Received(got); err != nil || !r.Write || r.Forward == nil {
		t.Fatalf("b: %+v, %v", r, err)
	}
	unread, err := EventOf(ev.Sealed, hub.id, hub.secret)
	if err != nil || !unread.Unread || unread.Text != "" {
		t.Fatalf("the hub reads %+v, %v", unread, err)
	}
	eh := New(Config{Self: hub.id, Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	r, err := eh.Received(unread)
	if err != nil || r.Write || r.Forward == nil || r.Forward.Sealed != ev.Sealed {
		t.Fatalf("the hub: %+v, %v", r, err)
	}
	if _, ok := eh.Current(); ok {
		t.Error("an unread copy is a usable current text")
	}
	if h := eh.Connected("x"); h.Current == nil || h.Current.Sealed == nil || h.Current.Sealed.IsMark() {
		t.Error("the hub does not pass the copy on in its hello as it holds it")
	}

	// A secret: the reader's hello carries the mark, the full copy follows.
	sec, _, err := ea.Send("hunter2", Secret, Copy)
	if err != nil {
		t.Fatal(err)
	}
	h := ea.Connected("b")
	if h.Current == nil || !h.Current.Sealed.IsMark() || h.Current.Text != "" {
		t.Fatal("a reader's hello carries a secret's payload")
	}
	mark, _ := EventOf(h.Current.Sealed, b.id, b.secret)
	ec := New(Config{Self: b.id, Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil)})
	if r, err := ec.Reconcile("a", Hello{Wall: time.Now().UnixMilli(), Current: &mark}); err != nil || r.Write {
		t.Fatalf("the mark: %+v, %v", r, err)
	}
	other, _, _ := sealedEngine(a, a, b).Send("hunter2", Secret, Copy)
	wrong, _ := EventOf(other.Sealed, b.id, b.secret)
	wrong.ID, wrong.Sealed.ID = sec.ID, sec.ID
	if r, _ := ec.Received(wrong); r.Write || r.Forward != nil {
		t.Error("another payload under the mark's ID is taken")
	}
	full, _ := EventOf(sec.Sealed, b.id, b.secret)
	if r, err := ec.Received(full); err != nil || !r.Write || r.Forward == nil {
		t.Fatalf("the full secret after its mark: %+v, %v", r, err)
	}
	if text, kind, _, ok := ec.Local(); !ok || text != "hunter2" || kind != Secret {
		t.Errorf("the secret's text: %q %v %v", text, kind, ok)
	}
}
