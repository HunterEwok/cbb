// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/hlc"
)

// Device IDs of the test members.
var (
	idA = strings.Repeat("a", 32)
	idB = strings.Repeat("b", 32)
	idC = strings.Repeat("c", 32)
	idD = strings.Repeat("d", 32)
)

// world holds the two clocks a member reads: the wall clock and the uptime,
// which counts sleep and does not jump when the wall clock is set.
type world struct {
	wall int64         // milliseconds since the Unix epoch
	up   time.Duration // uptime
}

func newWorld() *world { return &world{wall: 1_761_024_000_000, up: time.Hour} }

// advance lets time pass, awake or asleep: both clocks move.
func (w *world) advance(d time.Duration) { w.wall += d.Milliseconds(); w.up += d }

// step sets the wall clock, as NTP does; the uptime does not jump.
func (w *world) step(d time.Duration) { w.wall += d.Milliseconds() }

func (w *world) member(id string) *Engine { return w.memberSkewed(id, 0) }

func (w *world) memberSkewed(id string, offsetMs int64) *Engine {
	wall := func() time.Time { return time.UnixMilli(w.wall + offsetMs) }
	return New(Config{Self: id, Clock: hlc.NewClock(wall, hlc.Timestamp{}, nil), Wall: wall, Uptime: func() time.Duration { return w.up }})
}

// event makes an event from member b, aged as given, stamped at the world's
// wall time plus logical, so tests can order events made in the same moment.
func event(w *world, text string, age time.Duration, logical uint32) Event {
	return Event{ID: NewID(), Origin: idB, Time: hlc.Timestamp{Wall: w.wall, Logical: logical}, Age: age.Milliseconds(), Kind: Text, Text: text}
}

func ptr(e Event) *Event { return &e }

func mustCopy(t *testing.T, e *Engine, text string) Event {
	t.Helper()
	ev, ok, err := e.Copied(text, Text, Copy)
	if err != nil || !ok {
		t.Fatalf("Copied(%q) = %v, %v; want a new event", text, ok, err)
	}
	return ev
}

func mustReceive(t *testing.T, e *Engine, ev Event) Result {
	t.Helper()
	res, err := e.Received(ev)
	if err != nil {
		t.Fatalf("Received(%q): %v", ev.Text, err)
	}
	return res
}

func mustReconcile(t *testing.T, e *Engine, from string, h Hello) Result {
	t.Helper()
	res, err := e.Reconcile(from, h)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return res
}

// join opens a connection to peer and reconciles the peer's hello, carrying
// cur (nil for none), as the transport does.
func join(t *testing.T, w *world, e *Engine, peer string, cur *Event) Result {
	t.Helper()
	e.Connected(peer)
	return mustReconcile(t, e, peer, Hello{Wall: w.wall, Current: cur})
}

func currentText(e *Engine) string {
	ev, ok := e.Current()
	if !ok {
		return ""
	}
	return ev.Text
}

func localOf(e *Engine) string {
	text, _, _, ok := e.Local()
	if !ok {
		return ""
	}
	return text
}

func TestCopied(t *testing.T) {
	w := newWorld()
	a := w.member(idA)
	ev := mustCopy(t, a, "hello")
	if ev.Origin != idA || ev.Text != "hello" || ev.Kind != Text || ev.Via != Copy || !isID(ev.ID) || ev.Time.IsZero() || ev.Age != 0 {
		t.Errorf("Copied() = %+v", ev)
	}
	if localOf(a) != "hello" || currentText(a) != "hello" {
		t.Errorf("local %q, current %q; want both %q", localOf(a), currentText(a), "hello")
	}
	if _, ok, _ := a.Copied("hello", Text, Copy); ok {
		t.Error("copying the current text again made a new event")
	}
	for _, text := range []string{"", strings.Repeat("x", MaxText+1), "\xff\xfe"} {
		if _, _, err := a.Copied(text, Text, Copy); err == nil {
			t.Errorf("Copied(%.20q) succeeded, want an error", text)
		}
	}
	if _, _, err := a.Copied("x", Kind(9), Copy); err == nil {
		t.Error("Copied() with an unknown kind succeeded")
	}
	if _, _, err := a.Copied("x", Text, Via(9)); err == nil {
		t.Error("Copied() with an unknown via succeeded")
	}
}

func TestEcho(t *testing.T) {
	w := newWorld()
	a := w.member(idA)
	join(t, w, a, idB, nil)
	if res := mustReceive(t, a, event(w, "first", time.Second, 0)); !res.Write || localOf(a) != "first" {
		t.Fatalf("a live event was not written: %+v, local %q", res, localOf(a))
	}
	if _, ok, _ := a.Copied("first", Text, Copy); ok {
		t.Error("the echo of a written text made a new event")
	}
	// A late echo: the clipboard reports "first" only after "second" arrived.
	w.advance(time.Second)
	mustReceive(t, a, event(w, "second", time.Second, 0))
	if _, ok, _ := a.Copied("first", Text, Copy); ok {
		t.Error("a late echo of an earlier write made a new event")
	}
	w.advance(echoWindow + time.Second)
	if _, ok, _ := a.Copied("first", Text, Copy); !ok {
		t.Error("copying a text written long ago made no event")
	}
}

func TestReceivedOrdering(t *testing.T) {
	w := newWorld()
	a := w.member(idA)
	join(t, w, a, idB, nil)
	old := event(w, "old", 0, 0)
	newer := event(w, "newer", 0, 1)
	if res := mustReceive(t, a, newer); res.Forward == nil || !res.Write || res.Seq != 1 {
		t.Errorf("Received(newer) = %+v, want Forward, Write and Seq 1", res)
	}
	if res := mustReceive(t, a, old); res.Forward == nil || res.Write {
		t.Errorf("Received(older) = %+v, want only Forward", res)
	}
	if got := currentText(a); got != "newer" {
		t.Errorf("current = %q, want %q", got, "newer")
	}
	if res := mustReceive(t, a, newer); res != (Result{}) {
		t.Errorf("Received(duplicate) = %+v, want nothing", res)
	}
	w.advance(time.Millisecond)
	if res := mustReceive(t, a, event(w, "third", 0, 0)); res.Seq != 2 {
		t.Errorf("the second write has Seq %d, want 2", res.Seq)
	}
}

func TestSameTextNewerEvent(t *testing.T) {
	// a copied "x"; b's later "x" replaces it in the group state, without a
	// write, and is forwarded. c's "y", made between the two, then loses.
	w := newWorld()
	a := w.member(idA)
	join(t, w, a, idB, nil)
	mustCopy(t, a, "x")
	y := event(w, "y", 0, 5)
	w.advance(20 * time.Millisecond)
	x2 := event(w, "x", 0, 0)
	if res := mustReceive(t, a, x2); res.Forward == nil || res.Write {
		t.Errorf("Received(same text, newer) = %+v, want Forward without Write", res)
	}
	if res := mustReceive(t, a, y); res.Write {
		t.Errorf("Received(older y) = %+v, want no write", res)
	}
	if ev, _ := a.Current(); ev.ID != x2.ID {
		t.Errorf("current = %q (%s), want b's later event %s", ev.Text, ev.ID, x2.ID)
	}
}

func TestLocalClipboard(t *testing.T) {
	w := newWorld()
	a := w.member(idA)
	join(t, w, a, idC, nil)
	mustCopy(t, a, "mine")
	// An old event from a returning member wins the group state but stays off
	// the local clipboard.
	w.advance(time.Hour)
	if res := mustReceive(t, a, event(w, "stale", 20*time.Minute, 0)); res.Write {
		t.Fatal("an old event was written")
	}
	if localOf(a) != "mine" || currentText(a) != "stale" {
		t.Fatalf("local %q, current %q; want %q and %q", localOf(a), currentText(a), "mine", "stale")
	}
	// The user copies the group's text deliberately: a new event, and the
	// local clipboard follows.
	if _, ok, _ := a.Copied("stale", Text, Copy); !ok || localOf(a) != "stale" {
		t.Errorf("copying the group's text made no event, or local is %q", localOf(a))
	}
	// A written event becomes the local text, with its age.
	w.advance(time.Second)
	if res := mustReceive(t, a, event(w, "fresh", 3*time.Second, 0)); !res.Write {
		t.Fatal("a live event was not written")
	}
	if text, _, age, ok := a.Local(); !ok || text != "fresh" || age != 3*time.Second {
		t.Errorf("Local() = %q, %v, %v; want %q aged 3s", text, age, ok, "fresh")
	}
	a.ClipboardIs("from the desktop", Text)
	if localOf(a) != "from the desktop" {
		t.Errorf("ClipboardIs did not set the local text: %q", localOf(a))
	}
	a.ClipboardIs("", Text)
	if _, _, _, ok := a.Local(); ok {
		t.Error("ClipboardIs with an empty text left a known local text")
	}
}

func TestReceivedValidation(t *testing.T) {
	w := newWorld()
	a := w.member(idA)
	good := event(w, "ok", 0, 0)
	tests := map[string]func(e *Event){
		"short ID":            func(e *Event) { e.ID = "abc" },
		"upper-case ID":       func(e *Event) { e.ID = strings.Repeat("A", 32) },
		"bad origin":          func(e *Event) { e.Origin = "b" },
		"no timestamp":        func(e *Event) { e.Time = hlc.Timestamp{} },
		"past the end":        func(e *Event) { e.Time.Wall = hlc.MaxWall + 1 },
		"unknown kind":        func(e *Event) { e.Kind = 7 },
		"unknown via":         func(e *Event) { e.Via = 7 },
		"negative age":        func(e *Event) { e.Age = -1 },
		"empty text":          func(e *Event) { e.Text = "" },
		"invalid UTF-8":       func(e *Event) { e.Text = "\xff" },
		"text over the limit": func(e *Event) { e.Text = strings.Repeat("x", MaxText+1) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ev := good
			mutate(&ev)
			if _, err := a.Received(ev); err == nil {
				t.Error("Received() succeeded, want an error")
			}
		})
	}
	t.Run("an age beyond the cap is accepted and capped", func(t *testing.T) {
		ev := event(w, "very old", 3*maxAge, 0)
		if _, err := a.Received(ev); err != nil {
			t.Fatal(err)
		}
		h := a.Connected(idC)
		if h.Current == nil || h.Current.Age != maxAge.Milliseconds() {
			t.Errorf("hello age = %+v, want the cap %d", h.Current, maxAge.Milliseconds())
		}
	})
	t.Run("an age that would overflow does not make an event live", func(t *testing.T) {
		b := w.member(idB)
		join(t, w, b, idA, nil)
		ev := event(w, "ancient", 0, 0)
		ev.Age = math.MaxInt64
		res, err := b.Received(ev)
		if err != nil || res.Write {
			t.Errorf("Received(age MaxInt64) = %+v, %v; want accepted and not written", res, err)
		}
		if cur, _ := b.Current(); cur.Age != maxAge.Milliseconds() {
			t.Errorf("the event's age is %d ms, want the cap", cur.Age)
		}
	})
}

func TestTimeAndSleep(t *testing.T) {
	t.Run("a copy made before a sleep is old after it", func(t *testing.T) {
		w := newWorld()
		laptop := w.member(idA)
		mustCopy(t, laptop, "before the lid closed")
		w.advance(10 * time.Hour) // asleep: uptime counts it
		h := laptop.Connected(idB)
		if h.Current == nil || h.Current.Age != (10*time.Hour).Milliseconds() {
			t.Fatalf("hello after a sleep = %+v, want an age of 10h", h.Current)
		}
		desk := w.member(idB)
		join(t, w, desk, idC, nil)
		if res := mustReconcile(t, desk, idA, h); res.Write {
			t.Error("a copy from before the sleep was written as live on a member that stayed")
		}
	})
	t.Run("setting the wall clock ages nothing", func(t *testing.T) {
		w := newWorld()
		pi := w.member(idA)
		join(t, w, pi, idB, nil)
		mustReceive(t, pi, event(w, "just copied", 0, 0))
		w.step(6 * time.Hour) // NTP corrects a clock that was behind
		w.advance(2 * time.Second)
		if ev, ok := pi.Current(); !ok || ev.Age != 2000 {
			t.Errorf("Current() after a clock step = %+v, %v; want an age of 2 s", ev, ok)
		}
	})
}

func TestSkew(t *testing.T) {
	w := newWorld()
	a := w.member(idA)
	ahead := w.memberSkewed(idB, (10 * time.Minute).Milliseconds())
	a.Connected(idB)
	mustReconcile(t, a, idB, ahead.Connected(idA))
	if got := a.Skews()[idB]; got != 10*time.Minute {
		t.Errorf("Skews()[b] = %v, want 10m", got)
	}
	ev := mustCopy(t, ahead, "from a clock 10 minutes ahead")
	if res := mustReceive(t, a, ev); !res.Write {
		t.Errorf("an event from a skewed clock was not applied: %+v", res)
	}
	w.advance(time.Second)
	if mine := mustCopy(t, a, "after it"); !mine.later(ev) {
		t.Errorf("a's later copy %v sorts before b's %v", mine.Time, ev.Time)
	}
	a.Disconnected(idB)
	if _, ok := a.Skews()[idB]; ok {
		t.Error("the skew of a disconnected peer is still reported")
	}
}

func TestSecrets(t *testing.T) {
	t.Run("expires and travels only as a mark", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		if _, ok, err := a.Copied("hunter2", Secret, Copy); !ok || err != nil {
			t.Fatalf("Copied(secret) = %v, %v", ok, err)
		}
		if h := a.Connected(idB); h.Current == nil || !h.Current.IsMark() {
			t.Fatalf("hello = %+v: a secret must travel only as a mark", h.Current)
		}
		w.advance(DefaultSecretTTL)
		if _, ok := a.Current(); ok {
			t.Error("the secret is still current after its TTL")
		}
		if _, _, _, ok := a.Local(); ok {
			t.Error("the secret is still on the local clipboard after its TTL")
		}
	})
	t.Run("a secret stays a secret when offered again", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		join(t, w, a, idB, nil)
		mustCopy(t, a, "older text")
		if _, _, err := a.Copied("pw-1234", Secret, Phone); err != nil {
			t.Fatal(err)
		}
		w.advance(2 * time.Minute)
		if !a.KnownSecret("pw-1234") {
			t.Fatal("KnownSecret() forgot a secret after 2 minutes")
		}
		// A clipboard manager restores it without its mark: not a new copy.
		if _, ok, _ := a.Copied("pw-1234", Text, Copy); ok {
			t.Error("an earlier secret restored by a clipboard manager made a new event")
		}
		// The plain button, with the password still on the iPhone: a secret.
		ev, _, err := a.Send("pw-1234", Text, Phone)
		if err != nil || ev.Kind != Secret {
			t.Errorf("Send(known secret as text) = %+v, %v; want a secret event", ev, err)
		}
		w.advance(DefaultSecretMemory + time.Minute)
		if a.KnownSecret("pw-1234") {
			t.Error("KnownSecret() still remembers past the secret memory")
		}
	})
	t.Run("expires by its age", func(t *testing.T) {
		w := newWorld()
		b := w.member(idB)
		join(t, w, b, idA, nil)
		sec := Event{ID: NewID(), Origin: idA, Time: hlc.Timestamp{Wall: w.wall}, Age: 50_000, Kind: Secret, Text: "pin 1234"}
		if res := mustReceive(t, b, sec); !res.Write {
			t.Errorf("a live secret was not written: %+v", res)
		}
		w.advance(10 * time.Second)
		if _, ok := b.Current(); ok {
			t.Error("the secret outlived its age")
		}
		if !b.KnownSecret("pin 1234") {
			t.Error("a received secret is not remembered as a secret")
		}
	})
	t.Run("a skipped marked item is remembered", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		a.ClipboardIs("from the password manager", Secret)
		if !a.KnownSecret("from the password manager") {
			t.Error("a skipped secret reported by ClipboardIs is not remembered")
		}
		w.advance(2 * time.Minute)
		if _, ok, _ := a.Copied("from the password manager", Text, Copy); ok {
			t.Error("a skipped secret offered again without its mark became a normal event")
		}
	})
	t.Run("the memory holds many secrets, by age", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		for i := range 40 {
			if _, _, err := a.Send(fmt.Sprintf("one-time code %d", i), Secret, Copy); err != nil {
				t.Fatal(err)
			}
			w.advance(time.Minute)
		}
		if !a.KnownSecret("one-time code 0") {
			t.Error("the first of 40 secrets was forgotten within the memory time")
		}
	})
	t.Run("a restored secret does not circulate", func(t *testing.T) {
		// Two desktops whose clipboard managers restore every expired text.
		w := newWorld()
		mac, d1, d2 := w.member(idA), w.member(idB), w.member(idC)
		for _, m := range []*Engine{mac, d1, d2} {
			for _, peer := range []string{idA, idB, idC} {
				join(t, w, m, peer, nil)
			}
		}
		sec, _, err := mac.Send("hunter2", Secret, Copy)
		if err != nil {
			t.Fatal(err)
		}
		queue := []Event{sec}
		sends := 0
		for round := 0; round < 20 && len(queue) > 0; round++ {
			var next []Event
			for _, ev := range queue {
				for _, d := range []*Engine{d1, d2} {
					if res := mustReceive(t, d, ev); res.Write {
						w.advance(DefaultSecretTTL + time.Second) // the secret expires; the manager restores it
						if again, ok, _ := d.Copied("hunter2", Text, Copy); ok {
							sends++
							next = append(next, again)
						}
					}
				}
			}
			queue = next
		}
		if sends != 0 {
			t.Errorf("a restored secret was sent again %d times", sends)
		}
	})
	t.Run("a hello refuses a secret's text", func(t *testing.T) {
		w := newWorld()
		b := w.member(idB)
		sec := Event{ID: NewID(), Origin: idA, Time: hlc.Timestamp{Wall: w.wall}, Kind: Secret, Text: "pin"}
		if _, err := b.Reconcile(idA, Hello{Current: &sec}); err == nil {
			t.Error("Reconcile accepted a secret's text in a hello")
		}
	})
	t.Run("a mark hides an older text, and the full secret replaces the mark", func(t *testing.T) {
		w := newWorld()
		b := w.member(idB)
		join(t, w, b, idC, nil)
		mustReceive(t, b, Event{ID: NewID(), Origin: idC, Time: hlc.Timestamp{Wall: w.wall}, Kind: Text, Text: "older text"})
		full := Event{ID: NewID(), Origin: idA, Time: hlc.Timestamp{Wall: w.wall, Logical: 9}, Age: 2000, Kind: Secret, Text: "pw"}
		mark := full
		mark.Text = ""
		res := join(t, w, b, idA, &mark)
		if res.Write || res.Forward == nil || !res.Forward.IsMark() {
			t.Errorf("Reconcile(mark) = %+v, want the mark forwarded and no write", res)
		}
		if _, ok := b.Current(); ok {
			t.Error("a mark left the older text current")
		}
		res = mustReceive(t, b, full)
		if !res.Write || res.Forward == nil || res.Forward.Text != "pw" || currentText(b) != "pw" {
			t.Errorf("Received(full secret after its mark) = %+v, current %q", res, currentText(b))
		}
		if res := mustReceive(t, b, full); res != (Result{}) {
			t.Errorf("a second copy of the full secret = %+v, want nothing", res)
		}
	})
}

func TestWritePolicy(t *testing.T) {
	t.Run("a live event is written", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		join(t, w, a, idC, nil)
		if res := mustReceive(t, a, event(w, "fresh", 5*time.Second, 0)); !res.Write {
			t.Errorf("Received(live) = %+v, want Write", res)
		}
	})
	t.Run("an old event reaches a member that stayed connected", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		join(t, w, a, idC, nil)
		mustCopy(t, a, "copied at home")
		w.advance(time.Hour)
		res := mustReceive(t, a, event(w, "copied while away", 20*time.Minute, 0))
		if res.Write || localOf(a) != "copied at home" {
			t.Error("a returning member's old copy overwrote the clipboard of a member that stayed")
		}
	})
	t.Run("a member that only lost its peers keeps its clipboard", func(t *testing.T) {
		w := newWorld()
		desk := w.member(idA)
		join(t, w, desk, idB, nil)
		mustCopy(t, desk, "desk text")
		desk.Disconnected(idB)
		w.advance(time.Hour)
		if res := join(t, w, desk, idB, ptr(event(w, "laptop's old copy", 50*time.Minute, 0))); res.Write {
			t.Error("the desktop took the laptop's old copy into its clipboard")
		}
	})
	t.Run("a member that wakes up gets the group's text", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		a.Rejoin()
		if res := join(t, w, a, idB, ptr(event(w, "copied while it slept", 2*time.Hour, 0))); !res.Write {
			t.Errorf("Reconcile() = %+v, want Write", res)
		}
	})
	t.Run("a hello taken before the wake-up was noticed is written after it", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		ev := event(w, "copied while it slept", 10*time.Minute, 0)
		w.advance(time.Hour)
		if res := join(t, w, a, idB, ptr(ev)); res.Write {
			t.Fatalf("Reconcile() before Rejoin = %+v, want no write", res)
		}
		a.Disconnected(idB)
		a.Rejoin()
		if res := join(t, w, a, idB, ptr(ev)); !res.Write || localOf(a) != "copied while it slept" {
			t.Errorf("Reconcile() after Rejoin = %+v, want Write", res)
		}
		if res := join(t, w, a, idC, ptr(ev)); res.Write {
			t.Error("the same event was written twice")
		}
	})
	t.Run("a member that copied while away keeps its copy", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		mustCopy(t, a, "copied while alone")
		w.advance(time.Minute)
		a.Rejoin()
		if res := join(t, w, a, idB, ptr(event(w, "the group's text", 10*time.Minute, 0))); res.Write {
			t.Error("a copy made while away was overwritten")
		}
		w.advance(time.Millisecond)
		if res := mustReceive(t, a, event(w, "copied just now", time.Second, 0)); !res.Write {
			t.Errorf("Received(live) = %+v, want Write", res)
		}
	})
	t.Run("a flapping connection inside the window keeps the protection", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		mustCopy(t, a, "copied while alone")
		a.Rejoin()
		join(t, w, a, idB, nil)
		w.advance(5 * time.Second)
		a.Disconnected(idB)
		if res := join(t, w, a, idB, ptr(event(w, "older group text", 10*time.Minute, 0))); res.Write || localOf(a) != "copied while alone" {
			t.Error("a Wi-Fi blip inside the window let the group's old text overwrite the copy")
		}
	})
	t.Run("an earlier copy while away does not block a later wake-up", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		mustCopy(t, a, "copied at the cafe")
		a.Rejoin()
		join(t, w, a, idB, nil) // home again; the window passes quietly
		w.advance(3 * time.Hour)
		a.Rejoin() // woke up, before the dead connection is noticed
		a.Disconnected(idB)
		w.advance(time.Second)
		if res := join(t, w, a, idB, ptr(event(w, "copied while it slept", 20*time.Minute, 0))); !res.Write {
			t.Error("a copy from an earlier absence blocked the group's text after a wake-up")
		}
	})
	t.Run("peers leave first, then the member goes away", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		mustCopy(t, a, "copied at the cafe")
		a.Rejoin()
		join(t, w, a, idB, nil) // home again; the window passes quietly
		w.advance(time.Hour)
		a.Disconnected(idB) // the peer goes away; a stays
		w.advance(time.Hour)
		a.Rejoin() // now a itself sleeps and wakes
		if res := join(t, w, a, idB, ptr(event(w, "copied meanwhile", 20*time.Minute, 0))); !res.Write {
			t.Error("a copy from an earlier absence blocked the group's text after a wake-up")
		}
	})
	t.Run("a copy made alone, then a peer appears, then a wake-up", func(t *testing.T) {
		w := newWorld()
		mac := w.member(idA)
		mustCopy(t, mac, "x")
		join(t, w, mac, idB, nil) // a Linux desktop comes up; the Mac was not away
		w.advance(time.Hour)
		mac.Rejoin() // the Mac sleeps and wakes
		mac.Disconnected(idB)
		if res := join(t, w, mac, idB, ptr(event(w, "y", 10*time.Minute, 0))); !res.Write {
			t.Error("a long-delivered copy made alone blocked the group's text at the wake-up")
		}
	})
	t.Run("copies after a wake count as away until a hello is reconciled", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		join(t, w, a, idB, nil)
		a.Rejoin() // woke up at a cafe; the old connection still looks up
		mustCopy(t, a, "copied at the cafe")
		a.Disconnected(idB)
		w.advance(time.Hour)
		a.Rejoin() // home: the network is back
		if res := join(t, w, a, idB, ptr(event(w, "group text", 5*time.Minute, 0))); res.Write {
			t.Error("a copy made after a wake-up, over a stale connection, was overwritten")
		}
	})
	t.Run("two connections to one peer", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		join(t, w, a, idB, nil)
		join(t, w, a, idB, nil)
		a.Disconnected(idB)
		if _, ok := a.Skews()[idB]; !ok {
			t.Error("closing one of two connections dropped the peer's skew")
		}
		a.Rejoin()
		mustReconcile(t, a, idB, Hello{Wall: w.wall})
		mustCopy(t, a, "connected copy")
		if a.offlineCopy {
			t.Error("a copy made while one connection was still up counted as made while away")
		}
	})
	t.Run("the rejoin window closes", func(t *testing.T) {
		w := newWorld()
		a := w.member(idA)
		a.Rejoin()
		join(t, w, a, idB, nil)
		w.advance(DefaultRejoinWindow + time.Second)
		if res := mustReceive(t, a, event(w, "late catch-up", 10*time.Minute, 0)); res.Write {
			t.Error("an old event was written after the rejoin window closed")
		}
	})
}

func TestReofferOfLocalText(t *testing.T) {
	// The desk adopted a returning laptop's cafe copy without writing it; a
	// clipboard manager on the desk then offers the desk's unchanged text again.
	w := newWorld()
	desk := w.member(idA)
	join(t, w, desk, idC, nil)
	mustCopy(t, desk, "report draft")
	w.advance(time.Hour)
	mustReceive(t, desk, event(w, "cafe link", 30*time.Minute, 0))
	w.advance(5 * time.Minute)
	if _, ok, _ := desk.Copied("report draft", Text, Copy); ok {
		t.Error("an unchanged clipboard offered again made a new live event")
	}
	// A deliberate send of the same text does make one.
	if ev, _, err := desk.Send("report draft", Text, Copy); err != nil || ev.Text != "report draft" {
		t.Errorf("Send() = %+v, %v", ev, err)
	}
}

func TestSendFromThePhone(t *testing.T) {
	// The member a phone sends to gets the text on its own clipboard too.
	w := newWorld()
	holder := w.member(idA)
	join(t, w, holder, idB, nil)
	mustCopy(t, holder, "desk text")
	ev, res, err := holder.Send("from the iPhone", Text, Phone)
	if err != nil || ev.Via != Phone || !res.Write || res.Seq != 1 {
		t.Fatalf("Send() = %+v, %+v, %v; want an iphone event and a write with Seq 1", ev, res, err)
	}
	if localOf(holder) != "from the iPhone" || currentText(holder) != "from the iPhone" {
		t.Errorf("local %q, current %q", localOf(holder), currentText(holder))
	}
	if _, ok, _ := holder.Copied("from the iPhone", Text, Copy); ok {
		t.Error("the connector's report of the written text made a new event")
	}
	// Sending what the clipboard already holds needs no write.
	if _, res, _ := holder.Send("from the iPhone", Text, Phone); res.Write {
		t.Error("Send() asked to write a text the clipboard already holds")
	}
}

func TestUniversalClipboardRelay(t *testing.T) {
	// A MacBook writes the group's text during its rejoin window; Universal
	// Clipboard carries it to the iMac, whose agent reports it. That is not a
	// new copy.
	w := newWorld()
	imac := w.member(idA)
	join(t, w, imac, idB, nil)
	mustCopy(t, imac, "imac text")
	w.advance(time.Hour)
	old := event(w, "laptop's cafe copy", 3*time.Hour, 0)
	mustReceive(t, imac, old) // adopted, not written
	if _, ok, _ := imac.Copied("laptop's cafe copy", Text, Universal); ok {
		t.Error("the group's own text, relayed by Universal Clipboard, became a new live event")
	}
	if localOf(imac) != "laptop's cafe copy" {
		t.Errorf("local = %q, want the relayed text", localOf(imac))
	}
	if ev, ok, _ := imac.Copied("copied on the iPhone", Text, Universal); !ok || ev.Via != Universal {
		t.Errorf("a new Universal Clipboard item = %+v, %v; want an event via universal-clipboard", ev, ok)
	}
}

func TestHello(t *testing.T) {
	w := newWorld()
	a := w.member(idA)
	if h := a.Connected(idB); h.Current != nil || h.Wall != w.wall {
		t.Errorf("hello of an empty member = %+v", h)
	}
	ev := mustCopy(t, a, "x")
	w.advance(1500 * time.Millisecond)
	h := a.Connected(idC)
	if h.Current == nil || h.Current.ID != ev.ID || h.Current.Age != 1500 || h.Current.Text != "x" {
		t.Errorf("hello = %+v, want the current event aged 1500 ms", h.Current)
	}
}

func TestJSON(t *testing.T) {
	ev := Event{ID: NewID(), Origin: idA, Via: Universal, Time: hlc.Timestamp{Wall: 5, Logical: 2}, Age: 42, Kind: Secret, Text: "t"}
	b, err := json.Marshal(Hello{Wall: 7, Current: &ev})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"wall_ms":7`, `"kind":"secret"`, `"time":"5.2"`, `"via":"universal-clipboard"`, `"age_ms":42`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON %s lacks %s", b, want)
		}
	}
	var back Hello
	if err := json.Unmarshal(b, &back); err != nil || back.Current == nil || *back.Current != ev || back.Wall != 7 {
		t.Errorf("round trip = %+v, %v; want %+v", back, err, ev)
	}
	plain, _ := json.Marshal(Event{Via: Copy, Kind: Text})
	if strings.Contains(string(plain), "via") {
		t.Errorf("a plain copy should omit via: %s", plain)
	}
	var e Event
	for _, bad := range []string{`{"kind":"image"}`, `{"via":"fax"}`, `{"time":"1"}`} {
		if err := json.Unmarshal([]byte(bad), &e); err == nil {
			t.Errorf("Unmarshal(%s) succeeded", bad)
		}
	}
}

// TestReviewChain is the case that broke an earlier design: an event adopted
// from a hello must be forwarded, or members behind the adopting one keep an
// older event and a later copy can sort between the two.
func TestReviewChain(t *testing.T) {
	w := newWorld()
	a, b, c := w.member(idA), w.memberSkewed(idB, 2000), w.member(idC)
	join(t, w, a, idC, nil)
	join(t, w, c, idA, nil)
	mustReceive(t, c, mustCopy(t, a, "s"))
	w.advance(100 * time.Millisecond)
	mustReceive(t, c, mustCopy(t, a, "x"))
	w.advance(100 * time.Millisecond)
	xb := mustCopy(t, b, "x") // the same item, reported by an offline Mac with a clock 2 s ahead
	hb, ha := b.Connected(idA), a.Connected(idB)
	res := mustReconcile(t, a, idB, hb)
	if res.Forward == nil || res.Forward.ID != xb.ID {
		t.Fatalf("Reconcile() = %+v, want xb forwarded", res)
	}
	mustReceive(t, c, *res.Forward)
	mustReconcile(t, b, idA, ha)
	w.advance(600 * time.Millisecond)
	y := mustCopy(t, c, "y")
	for _, m := range []*Engine{a, b} {
		mustReceive(t, m, y)
	}
	for name, m := range map[string]*Engine{"a": a, "b": b, "c": c} {
		if got := currentText(m); got != "y" {
			t.Errorf("%s holds %q, want %q", name, got, "y")
		}
	}
}

// TestConvergence runs a group of members over links that go up and down,
// with random copies and secrets, deliveries in any order, duplicates, lost
// messages on broken links, skewed clocks, time steps that cross every
// window, wake-ups and crashes. At the end the links form a connected but
// incomplete graph, so forwarding is needed; once every message is
// delivered, all members must hold the same current event, and without
// crashes it must be the latest event made.
//
// CLIP_SIM_SEEDS sets the number of runs, 300 by default.
func TestConvergence(t *testing.T) {
	seeds := uint64(300)
	if n, err := strconv.ParseUint(os.Getenv("CLIP_SIM_SEEDS"), 10, 64); err == nil && n > 0 {
		seeds = n
	}
	for seed := range seeds {
		crashes := seed%2 == 1
		t.Run(fmt.Sprintf("seed %d crashes %v", seed, crashes), func(t *testing.T) { simulate(t, seed, crashes) })
	}
}

func simulate(t *testing.T, seed uint64, crashes bool) {
	rng := rand.New(rand.NewPCG(seed, 7))
	w := newWorld()
	ids := []string{idA, idB, idC, idD}
	offsets := make(map[string]int64)
	marks := make(map[string]hlc.Timestamp) // what each member saved
	members := make(map[string]*Engine)
	start := func(id string) {
		wall := func() time.Time { return time.UnixMilli(w.wall + offsets[id]) }
		clock := hlc.NewClock(wall, marks[id], func(m hlc.Timestamp) error { marks[id] = m; return nil })
		members[id] = New(Config{Self: id, Clock: clock, Wall: wall, Uptime: func() time.Duration { return w.up }})
		members[id].Rejoin()
	}
	for _, id := range ids {
		offsets[id] = int64(rng.IntN(6001) - 3000) // up to 3 s either way
		start(id)
	}
	type link struct{ x, y string }
	type message struct {
		from, to string
		ev       Event
	}
	up := make(map[link]bool)
	var queue []message
	var latest Event
	key := func(x, y string) link {
		if x > y {
			x, y = y, x
		}
		return link{x, y}
	}
	sendAll := func(from, except string, ev Event) {
		for _, to := range ids {
			if to != from && to != except && up[key(from, to)] {
				queue = append(queue, message{from, to, ev})
			}
		}
	}
	handle := func(member, from string, res Result) {
		if res.Forward != nil {
			sendAll(member, from, *res.Forward)
		}
	}
	connect := func(x, y string) {
		up[key(x, y)] = true
		hx, hy := members[x].Connected(y), members[y].Connected(x)
		handle(x, y, mustReconcile(t, members[x], y, hy))
		handle(y, x, mustReconcile(t, members[y], x, hx))
	}
	disconnect := func(x, y string) {
		up[key(x, y)] = false
		members[x].Disconnected(y)
		members[y].Disconnected(x)
		kept := queue[:0]
		for _, m := range queue {
			if key(m.from, m.to) != key(x, y) {
				kept = append(kept, m)
			}
		}
		queue = kept
	}
	isolate := func(id string) {
		for _, other := range ids {
			if other != id && up[key(id, other)] {
				disconnect(id, other)
			}
		}
	}
	deliver := func(i int) {
		m := queue[i]
		queue = append(queue[:i], queue[i+1:]...)
		res, err := members[m.to].Received(m.ev)
		if err != nil {
			t.Fatal(err)
		}
		handle(m.to, m.from, res)
		if rng.IntN(5) == 0 {
			queue = append(queue, m) // a duplicate
		}
	}
	for i, x := range ids {
		for _, y := range ids[i+1:] {
			if rng.IntN(2) == 0 {
				connect(x, y)
			}
		}
	}
	for range 150 {
		switch rng.IntN(20) {
		case 0:
			w.advance(time.Duration(rng.IntN(120)) * time.Second) // crosses the windows
		case 1:
			w.step(time.Duration(rng.IntN(7200)-3600) * time.Second) // NTP sets the clocks
		default:
			w.advance(time.Duration(rng.IntN(3)) * time.Millisecond)
		}
		switch r := rng.IntN(22); {
		case r < 6:
			from := ids[rng.IntN(len(ids))]
			kind := Text
			if rng.IntN(5) == 0 {
				kind = Secret
			}
			text, via := fmt.Sprint("text ", rng.IntN(4)), Via(rng.IntN(3))
			var ev Event
			var ok bool
			var err error
			if rng.IntN(3) == 0 {
				ev, _, err = members[from].Send(text, kind, via)
				ok = err == nil
			} else {
				ev, ok, err = members[from].Copied(text, kind, via)
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				if latest.ID == "" || ev.later(latest) {
					latest = ev
				}
				sendAll(from, "", ev)
			}
		case r < 10:
			x, y := ids[rng.IntN(len(ids))], ids[rng.IntN(len(ids))]
			if x == y {
				continue
			}
			if up[key(x, y)] {
				disconnect(x, y)
			} else {
				connect(x, y)
			}
		case r == 10: // a member sleeps and wakes
			id := ids[rng.IntN(len(ids))]
			isolate(id)
			members[id].Rejoin()
		case r == 11 && crashes:
			id := ids[rng.IntN(len(ids))]
			isolate(id)
			start(id)
		default:
			if len(queue) > 0 {
				deliver(rng.IntN(len(queue)))
			}
		}
	}
	// End on a random spanning tree, plus the links that are still up.
	order := append([]string(nil), ids...)
	rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	for i := 1; i < len(order); i++ {
		if parent := order[rng.IntN(i)]; !up[key(order[i], parent)] {
			connect(order[i], parent)
		}
	}
	for len(queue) > 0 {
		deliver(rng.IntN(len(queue)))
	}
	first := members[idA].current
	for _, id := range ids {
		if got := members[id].current; got.ID != first.ID {
			t.Errorf("member %s holds %q (%s), member a holds %q (%s)", id[:1], got.Text, got.ID, first.Text, first.ID)
		}
	}
	if !crashes && latest.ID != "" && first.ID != latest.ID {
		t.Errorf("the group holds %q (%s), but the latest event made was %q (%s)", first.Text, first.ID, latest.Text, latest.ID)
	}
}

// TestAheadRefused checks that an event far ahead of this clock is refused,
// so that no member moves the group's clocks to the end of time.
func TestAheadRefused(t *testing.T) {
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	clock := hlc.NewClock(func() time.Time { return now }, hlc.Timestamp{}, nil)
	e := New(Config{Self: idA, Clock: clock, Wall: func() time.Time { return now }, Uptime: func() time.Duration { return time.Hour }})
	far := Event{ID: NewID(), Origin: idB, Time: hlc.Timestamp{Wall: hlc.MaxWall}, Kind: Text, Text: "stuck"}
	if _, err := e.Received(far); err == nil {
		t.Error("an event at MaxWall was taken")
	}
	if got := clock.Last(); got.Wall >= hlc.MaxWall {
		t.Errorf("the clock moved to %v", got)
	}
	res, err := e.Reconcile(idB, Hello{Wall: now.UnixMilli(), Current: &far})
	if err != nil || res.Forward != nil {
		t.Errorf("a hello with an event at MaxWall: %+v, %v", res, err)
	}
	near := Event{ID: NewID(), Origin: idB, Time: hlc.Timestamp{Wall: now.Add(6 * 24 * time.Hour).UnixMilli()}, Kind: Text, Text: "fine"}
	if _, err := e.Received(near); err != nil {
		t.Errorf("an event 6 days ahead: %v", err)
	}
}
