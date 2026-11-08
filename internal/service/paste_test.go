// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/remotepaste"
)

func TestRemotePaste(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	paste := func(text string, h control.Header) error {
		h.Op, h.Device = control.OpPasteOn, "deck"
		_, err := pi.do(t, h, text)
		return err
	}
	wantRefused := func(what, text string, h control.Header, reason string) {
		t.Helper()
		if err := paste(text, h); err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v, want %q", what, err, reason)
		}
	}
	wantRefused("off", "ls", control.Header{}, "remote paste is off on this device")
	if _, err := pi.do(t, control.Header{Op: control.OpReceive, Name: "on", Device: "deck"}, ""); err == nil {
		t.Error("an admin turned remote paste on on another device")
	}
	if m, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil || m.Status.Paste == nil || !m.Status.Paste.On {
		t.Fatalf("paste-receive on: %+v, %v", m, err)
	}
	wantRefused("no target", "ls", control.Header{}, "nothing on this device can paste")

	// A desktop connector on deck offers to paste.
	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetDesktop}}); err != nil {
		t.Fatal(err)
	}
	got := make(chan *control.Message, 4)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op != control.OpInject {
				continue
			}
			got <- m
			ans := control.Header{Op: control.OpInjected, Seq: m.Seq}
			if strings.Contains(string(m.Payload), "locked") {
				ans.Error, ans.Refused = "the session is locked", true
			}
			w.Send(&control.Message{Header: ans})
		}
	}()
	waitFor(t, "deck offers the desktop", func() bool {
		p := deck.status(t).Paste
		return p != nil && len(p.Targets) == 1 && p.Targets[0] == targetDesktop
	})
	time.Sleep(time.Second) // the paste without a target counted
	if err := paste("echo \x1b[31mhi\x1b[0m", control.Header{Method: "type"}); err != nil {
		t.Fatal(err)
	}
	m := <-got
	if string(m.Payload) != "echo hi" || m.Method != "type" || m.Enter || m.NoLockCheck || m.Name != "pi" {
		t.Errorf("the desktop got %q %+v", m.Payload, m.Header)
	}
	time.Sleep(time.Second) // one paste a second from one sender
	wantRefused("enter", "ls", control.Header{Enter: true}, "without Enter only")
	time.Sleep(time.Second)
	wantRefused("locked", "locked", control.Header{}, "the session is locked")
	<-got
	if wantRefused("too fast", "ls", control.Header{}, "too many pastes"); len(got) != 0 {
		t.Error("a paste too fast reached the desktop")
	}
	time.Sleep(time.Second)
	if err := paste("hunter2", control.Header{Kind: control.KindSecret}); err != nil {
		t.Fatal(err)
	}
	if m := <-got; m.Kind != control.KindSecret {
		t.Errorf("a secret came as %q", m.Kind)
	}

	// The log keeps who and how, never the text, and no secret.
	log, err := remotepaste.ReadLog(deck.dir)
	if err != nil || len(log) != 6 {
		t.Fatalf("the log: %d entries, %v", len(log), err)
	}
	for _, e := range log {
		if e.Name != "pi" && e.Name != "" {
			t.Errorf("an entry names %q", e.Name)
		}
	}
	if e := log[2]; e.Result != "done" || e.Len != len("echo hi") || e.Method != "type" || e.Unverified {
		t.Errorf("the paste's entry: %+v", e)
	}

	// Its user lets it paste where nothing tells whether the session is
	// locked: the inject says so.
	if m, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on", NoLockCheck: true}, ""); err != nil || m.Status.Paste == nil || !m.Status.Paste.NoLockCheck {
		t.Fatalf("paste-receive on -no-lock-check: %+v, %v", m, err)
	}
	time.Sleep(time.Second)
	if err := paste("ls", control.Header{}); err != nil {
		t.Fatal(err)
	}
	if m := <-got; !m.NoLockCheck {
		t.Errorf("the inject does not let the target paste without the lock check: %+v", m.Header)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "off", NoLockCheck: true}, ""); err == nil {
		t.Error("off took -no-lock-check")
	}

	// Any admin turns it off.
	if _, err := pi.do(t, control.Header{Op: control.OpReceive, Name: "off", Device: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	if p := deck.status(t).Paste; p == nil || p.On {
		t.Errorf("after paste-off: %+v", p)
	}
	time.Sleep(time.Second)
	wantRefused("off again", "ls", control.Header{}, "remote paste is off")
	// A member that is not an admin sends none.
	if _, err := deck.do(t, control.Header{Op: control.OpPasteOn, Device: "pi"}, "ls"); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("deck pasted on pi: %v", err)
	}
}

// TestPasteTargetHasNoClipboard checks that a tmux helper and the Mac app,
// which only paste, get no writes: the next desktop connector still gets
// the text that came while none was there.
func TestPasteTargetHasNoClipboard(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	tm := deck.dial(t)
	defer tm.Close()
	if _, err := tm.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetTmux}, Payload: []byte("not a clipboard")}); err != nil {
		t.Fatal(err)
	}
	app := deck.dial(t)
	defer app.Close()
	if _, err := app.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetDesktop, PasteOnly: true}, Payload: []byte("not a clipboard")}); err != nil {
		t.Fatal(err)
	}
	writes := make(chan *control.Message, 4)
	for _, c := range []*control.Client{tm, app} {
		go func() {
			for {
				m, err := c.Receive()
				if err != nil {
					return
				}
				writes <- m
			}
		}()
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from pi"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "deck has the text", func() bool { return deck.paste(t) == "from pi" })
	select {
	case m := <-writes:
		t.Errorf("a paste target got %q %q", m.Op, m.Payload)
	case <-time.After(500 * time.Millisecond):
	}
	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetDesktop}}); err != nil {
		t.Fatal(err)
	}
	m, err := w.Receive()
	if err != nil || m.Op != control.OpWrite || string(m.Payload) != "from pi" {
		t.Errorf("the desktop connector got %+v, %v", m, err)
	}
}

// TestPasteLineBreaks: a line break may run the text on any target (a
// desktop's focused program may be a shell that takes no bracketed paste),
// so everywhere it needs the user's leave for Enter.
func TestPasteLineBreaks(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	watch := func(target string) {
		c := deck.dial(t)
		t.Cleanup(func() { c.Close() })
		if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: target}}); err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				m, err := c.Receive()
				if err != nil {
					return
				}
				if m.Op != control.OpInject {
					continue
				}
				got <- target + ": " + string(m.Payload)
				c.Send(&control.Message{Header: control.Header{Op: control.OpInjected, Seq: m.Seq}})
			}
		}()
	}
	paste := func(text, method string) error {
		time.Sleep(time.Second) // one paste a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "deck", Method: method}, text)
		return err
	}
	const reason = "the text has a line break"
	watch(targetTmux)
	waitFor(t, "deck offers tmux", func() bool {
		p := deck.status(t).Paste
		return p != nil && len(p.Targets) == 1
	})
	if err := paste("rm -rf x\nls", "paste"); err == nil || !strings.Contains(err.Error(), reason) {
		t.Errorf("two lines into tmux: %v", err)
	}
	if err := paste("x\ny", "type"); err == nil || !strings.Contains(err.Error(), reason) {
		t.Errorf("two lines typed: %v", err)
	}
	if err := paste("one line", "paste"); err != nil {
		t.Fatal(err)
	}
	if g := <-got; g != "tmux: one line" {
		t.Errorf("got %q", g)
	}
	watch(targetDesktop)
	waitFor(t, "deck offers the desktop", func() bool {
		p := deck.status(t).Paste
		return p != nil && len(p.Targets) == 2
	})
	if err := paste("rm -rf x\nls", "paste"); err == nil || !strings.Contains(err.Error(), reason) {
		t.Errorf("two lines onto the desktop: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a refused paste reached %q", <-got)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on", Enter: true}, ""); err != nil {
		t.Fatal(err)
	}
	if err := paste("a\nb", "paste"); err != nil {
		t.Fatal(err)
	}
	if g := <-got; g != "desktop: a\nb" {
		t.Errorf("got %q", g)
	}
}

// TestCommandSignedBeforeStart: the replay cache starts empty, so a device
// refuses a command signed before it started, which it may have carried
// out before.
func TestCommandSignedBeforeStart(t *testing.T) {
	clock := newTestClock(t, time.Minute) // deck starts a minute "later"
	var h hub
	pi := startService(t, &h, "pi")
	deck := startEnv(t, &h, "deck", clock.env())
	clock.set(t, 0)
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := pi.do(t, control.Header{Op: control.OpReceive, Name: "off", Device: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "started after the command was signed") {
		t.Errorf("a command signed before the device started: %v", err)
	}
}
