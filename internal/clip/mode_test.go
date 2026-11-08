// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"errors"
	"testing"
	"time"
)

func TestModes(t *testing.T) {
	for _, tc := range []struct {
		mode            Mode
		sends, receives bool
	}{
		{Shared, true, true},
		{Own, false, false},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			w := newWorld()
			e := w.member(idA)
			e.SetMode(tc.mode)
			if e.Mode() != tc.mode {
				t.Fatalf("Mode() = %v", e.Mode())
			}
			ev, ok, err := e.Copied("mine", Text, Copy)
			if err != nil || ok != tc.sends {
				t.Fatalf("Copied = %v, %v; want %v", ok, err, tc.sends)
			}
			if ok && ev.Text != "mine" {
				t.Fatalf("the event has %q", ev.Text)
			}
			// What a watcher reported is the clipboard's text in every mode.
			if text, _, _, ok := e.Local(); !ok || text != "mine" {
				t.Fatalf("Local() = %q, %v", text, ok)
			}
			if cur, ok := e.Current(); ok != tc.sends || ok && cur.Text != "mine" {
				t.Fatalf("Current() = %q, %v", cur.Text, ok)
			}

			w.advance(time.Second)
			res := mustReceive(t, e, event(w, "theirs", 0, 0))
			if res.Write != tc.receives || res.Forward == nil {
				t.Fatalf("Received: Write %v, forwarded %v; want %v, true", res.Write, res.Forward != nil, tc.receives)
			}
			// The group's text is at hand in every mode.
			if cur, ok := e.Current(); !ok || cur.Text != "theirs" {
				t.Fatalf("Current() = %q, %v", cur.Text, ok)
			}
			want := "mine"
			if tc.receives {
				want = "theirs"
			}
			if text, _, _, _ := e.Local(); text != want {
				t.Fatalf("Local() = %q, want %q", text, want)
			}

			// A deliberate action makes an event and fills the clipboard in every mode.
			ev, res, err = e.Send("sent", Text, Phone)
			if err != nil || ev.Text != "sent" || !res.Write {
				t.Fatalf("Send = %q, %+v, %v", ev.Text, res, err)
			}
		})
	}
}

func TestModeSecretStaysSecret(t *testing.T) {
	w := newWorld()
	e := w.member(idA)
	e.SetMode(Own)
	if _, ok, _ := e.Copied("hunter2", Secret, Copy); ok {
		t.Fatal("own mode sent a secret")
	}
	// Offered again without its mark, it is still known as a secret.
	if !e.KnownSecret("hunter2") {
		t.Fatal("the secret is forgotten")
	}
}

func TestParseMode(t *testing.T) {
	for m := Shared; m <= Own; m++ {
		if got, err := ParseMode(m.String()); err != nil || got != m {
			t.Fatalf("ParseMode(%q) = %v, %v", m, got, err)
		}
	}
	for _, name := range []string{"everything", "receive", "send"} {
		if _, err := ParseMode(name); err == nil {
			t.Fatalf("ParseMode took %q", name)
		}
	}
}

// TestMute keeps a muted member's copies, deliberate ones too, from the
// group until the mute ends.
func TestMute(t *testing.T) {
	w := newWorld()
	e := w.member(idA)
	e.SetMute(time.UnixMilli(w.wall).Add(time.Hour))
	if _, ok, err := e.Copied("noise", Text, Copy); ok || err != nil {
		t.Fatalf("a muted member made an event: %v, %v", ok, err)
	}
	if _, _, err := e.Send("deliberate", Text, Copy); !errors.Is(err, ErrMuted) {
		t.Fatalf("Send on a muted member = %v", err)
	}
	if muted, left := e.MuteLeft(); !muted || left != time.Hour {
		t.Fatalf("MuteLeft() = %v, %v", muted, left)
	}
	w.advance(time.Hour)
	if muted, _ := e.Muted(); muted {
		t.Fatal("the mute outlasted its end")
	}
	if _, ok, _ := e.Copied("heard", Text, Copy); !ok {
		t.Fatal("no event after the mute ended")
	}
	e.SetMute(time.Time{})
	w.advance(30 * 24 * time.Hour)
	if muted, left := e.MuteLeft(); !muted || left != 0 {
		t.Fatalf("a mute until Unmute: %v, %v", muted, left)
	}
	e.Unmute()
	if muted, _ := e.Muted(); muted {
		t.Fatal("Unmute left the mute")
	}
}

// TestSyncOffForAWhile turns sync off until a time: the member neither
// sends nor takes copies, keeps the group's text at hand, and syncs again
// once the time has passed.
func TestSyncOffForAWhile(t *testing.T) {
	w := newWorld()
	e := w.member(idA)
	until := time.UnixMilli(w.wall).Add(time.Minute)
	e.SetSync(false, until)
	if on, at := e.Sync(); on || !at.Equal(until) || e.Mode() != Own {
		t.Fatalf("Sync() = %v, %v; Mode() = %v", on, at, e.Mode())
	}
	w.advance(time.Second)
	res := mustReceive(t, e, event(w, "theirs", 0, 0))
	if res.Write || res.Forward == nil {
		t.Fatalf("a copy while off: Write %v, forwarded %v", res.Write, res.Forward != nil)
	}
	if cur, _ := e.Current(); cur.Text != "theirs" {
		t.Fatal("a member with sync off does not keep the group's text at hand")
	}
	if _, ok, _ := e.Copied("mine while off", Text, Copy); ok {
		t.Fatal("a member with sync off sent its copy")
	}
	w.advance(time.Minute)
	if on, at := e.Sync(); !on || !at.IsZero() || e.Mode() != Shared {
		t.Fatalf("after its time: Sync() = %v, %v", on, at)
	}
	w.advance(time.Second)
	if res := mustReceive(t, e, event(w, "after", 0, 0)); !res.Write {
		t.Fatal("a copy after sync turned on again was not taken")
	}

	e.SetSync(false, time.Time{})
	w.advance(30 * 24 * time.Hour)
	if on, at := e.Sync(); on || !at.IsZero() {
		t.Fatalf("off until turned on: Sync() = %v, %v", on, at)
	}
	e.SetSync(true, time.Time{})
	if on, _ := e.Sync(); !on {
		t.Fatal("SetSync(true) left sync off")
	}
}
