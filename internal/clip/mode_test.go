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
		{Receive, false, true},
		{SendOnly, true, false},
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
	for m := Shared; m <= SendOnly; m++ {
		if got, err := ParseMode(m.String()); err != nil || got != m {
			t.Fatalf("ParseMode(%q) = %v, %v", m, got, err)
		}
	}
	if _, err := ParseMode("everything"); err == nil {
		t.Fatal("ParseMode took an unknown mode")
	}
}

// TestMute keeps a muted member's copies, deliberate ones too, from the
// group until the mute ends, and the group's copies out of a member that
// paused receiving.
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

	e.PauseReceiving(time.UnixMilli(w.wall).Add(time.Minute))
	w.advance(time.Second)
	res := mustReceive(t, e, event(w, "theirs", 0, 0))
	if res.Write || res.Forward == nil {
		t.Fatalf("a copy while paused: Write %v, forwarded %v", res.Write, res.Forward != nil)
	}
	if cur, _ := e.Current(); cur.Text != "theirs" {
		t.Fatal("a paused member does not keep the group's text at hand")
	}
	if _, ok, _ := e.Copied("mine while paused", Text, Copy); !ok {
		t.Fatal("a paused member's own copy did not go out")
	}
	w.advance(time.Minute)
	if paused, _ := e.ReceivingPaused(); paused {
		t.Fatal("the pause outlasted its end")
	}
	w.advance(time.Second)
	if res := mustReceive(t, e, event(w, "after the pause", 0, 0)); !res.Write {
		t.Fatal("a copy after the pause ended was not taken")
	}
}
