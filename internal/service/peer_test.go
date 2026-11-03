// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
)

// Users that the tests' fake system names: one at the screen, one that is
// not, and one it cannot tell about. They are far from the uids of real
// accounts, so none is the test's own, which counts as the service's.
const (
	uidAtScreen = 2_000_000_000 + iota
	uidAway
	uidUnknown
)

// fakeUsers gives each control connection the user next holds, and tells
// whether a user is at the screen by uidAtScreen and friends.
func fakeUsers(next *atomic.Pointer[peer]) func(*Config) {
	return func(c *Config) {
		c.peerOf = func(net.Conn) peer { return *next.Load() }
		c.atScreen = func(p peer, _ string) verdict {
			switch p.uid {
			case uidAtScreen:
				return allowed
			case uidUnknown:
				return unchecked
			}
			return refused
		}
	}
}

// pasteTarget opens a watcher as the user next holds, offering target and,
// with act, the actions; what it gets goes to got.
func pasteTarget(t *testing.T, s *testService, next *atomic.Pointer[peer], p peer, h control.Header, got chan<- string) {
	t.Helper()
	next.Store(&p)
	w := s.dial(t)
	t.Cleanup(func() { w.Close() })
	h.Op = control.OpWatch
	if _, err := w.Do(&control.Message{Header: h}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			switch m.Op {
			case control.OpInject:
				got <- string(m.Payload)
				w.Send(&control.Message{Header: control.Header{Op: control.OpInjected, Seq: m.Seq}})
			case control.OpAct:
				got <- m.Name
				w.Send(&control.Message{Header: control.Header{Op: control.OpActed, Seq: m.Seq}})
			}
		}
	}()
}

// TestPasteTargetUser: a watcher's remote pastes and actions go only to the
// user at the screen, a console's only to root, and a secret only where the
// system tells who is at the screen; a watcher of another user of the
// socket's group gets none.
func TestPasteTargetUser(t *testing.T) {
	var next atomic.Pointer[peer]
	next.Store(&peer{})
	var h hub
	pi := startService(t, &h, "pi")
	deck := startWith(t, &h, "deck", "linux", fakeUsers(&next))
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	paste := func(text, kind string) error {
		time.Sleep(time.Second) // one paste a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "deck", Kind: kind}, text)
		return err
	}
	away, unknown, screen := make(chan string, 8), make(chan string, 8), make(chan string, 8)

	// Another user of the group offers the desktop, and a console helper
	// that is not root; a user the system does not name offers tmux.
	pasteTarget(t, deck, &next, peer{known: true, uid: uidAway}, control.Header{Inject: targetDesktop}, away)
	pasteTarget(t, deck, &next, peer{known: true, uid: uidAway}, control.Header{Inject: targetConsole}, away)
	pasteTarget(t, deck, &next, peer{}, control.Header{Inject: targetTmux}, away)
	waitFor(t, "deck offers the desktop", func() bool {
		p := deck.status(t).Paste
		return p != nil && slices.Equal(p.Targets, []string{targetDesktop})
	})
	if err := paste("ls", "text"); err == nil || !strings.Contains(err.Error(), "not at the screen") {
		t.Errorf("a paste with only another user's target: %v", err)
	}

	// Where the system cannot tell who is at the screen, a paste goes and
	// a secret does not.
	pasteTarget(t, deck, &next, peer{known: true, uid: uidUnknown}, control.Header{Inject: targetDesktop}, unknown)
	time.Sleep(200 * time.Millisecond)
	if err := paste("pwd", "text"); err != nil {
		t.Fatal(err)
	}
	if got := <-unknown; got != "pwd" {
		t.Errorf("the unchecked target got %q", got)
	}
	if err := paste("hunter2", "secret"); err == nil || !strings.Contains(err.Error(), "takes no secret pastes") {
		t.Errorf("a secret to an unchecked target: %v", err)
	}

	// The user at the screen takes them, the secret too.
	pasteTarget(t, deck, &next, peer{known: true, uid: uidAtScreen}, control.Header{Inject: targetDesktop}, screen)
	time.Sleep(200 * time.Millisecond)
	for range 3 {
		if err := paste("hunter2", "secret"); err != nil {
			t.Fatal(err)
		}
		if got := <-screen; got != "hunter2" {
			t.Errorf("the user at the screen got %q", got)
		}
	}
	if len(away) != 0 || len(unknown) != 0 {
		t.Errorf("the other users' targets got %d and %d pastes", len(away), len(unknown))
	}
}

// TestActionsAgentUser: the actions go only to an agent of the user at the
// screen.
func TestActionsAgentUser(t *testing.T) {
	var next atomic.Pointer[peer]
	next.Store(&peer{})
	var h hub
	pi := startService(t, &h, "pi")
	deck := startWith(t, &h, "deck", "linux", func(c *Config) {
		fakeUsers(&next)(c)
		c.actInSession = true
	})
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := deck.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{{Name: actions.Lock, On: true}}}, ""); err != nil {
		t.Fatal(err)
	}
	run := func() error {
		time.Sleep(time.Second) // one action a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: actions.Lock}, "")
		return err
	}
	away, screen := make(chan string, 4), make(chan string, 4)
	pasteTarget(t, deck, &next, peer{known: true, uid: uidAway}, control.Header{Act: true}, away)
	pasteTarget(t, deck, &next, peer{known: true, uid: uidUnknown}, control.Header{Act: true}, away)
	time.Sleep(200 * time.Millisecond)
	if err := run(); err == nil || !strings.Contains(err.Error(), "not signed in at the screen") {
		t.Errorf("an action with only other users' agents: %v", err)
	}
	pasteTarget(t, deck, &next, peer{known: true, uid: uidAtScreen}, control.Header{Act: true}, screen)
	time.Sleep(200 * time.Millisecond)
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if got := <-screen; got != actions.Lock || len(away) != 0 {
		t.Errorf("the agent at the screen got %q, the others %d", got, len(away))
	}
}

// TestConnPeer: the system names the user at the other end of a control
// connection, here this test's own.
func TestConnPeer(t *testing.T) {
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if p := connPeer(s); !p.known || !p.privileged() {
		t.Errorf("the peer is %+v", p)
	}
}

// TestKeysGrant: the uinput helper presses keys only for a remote paste
// that the service handed to a desktop session, for that session's user,
// the paste keys once and Enter once when the command asked for it, and
// none after the session answered.
func TestKeysGrant(t *testing.T) {
	var next atomic.Pointer[peer]
	next.Store(&peer{known: true, uid: uidAtScreen})
	var h hub
	pi := startService(t, &h, "pi")
	deck := startWith(t, &h, "deck", "linux", fakeUsers(&next))
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on", Enter: true}, ""); err != nil {
		t.Fatal(err)
	}
	// The helper is root; another user of the socket's group asks for none.
	keysAs := func(as peer, grant, req string, uid int) error {
		next.Store(&as)
		_, err := deck.do(t, control.Header{Op: control.OpKeys, Name: req, Value: strconv.Itoa(uid), Keys: grant}, "")
		return err
	}
	// root on Unix, the system's account on Windows
	root := peer{known: true, uid: 0, sid: "S-1-5-18"}
	keys := func(grant, req string, uid int) error { return keysAs(root, grant, req, uid) }
	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetDesktop}}); err != nil {
		t.Fatal(err)
	}
	grants := make(chan string, 4)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op != control.OpInject {
				continue
			}
			g := m.Keys
			var errs []string
			if err := keysAs(peer{known: true, uid: uidAtScreen}, g, "paste", uidAtScreen); err == nil || !strings.Contains(err.Error(), "as root") {
				errs = append(errs, fmt.Sprintf("the session's user asked for the keys itself: %v", err))
			}
			check := func(what string, err error, ok bool) {
				if (err == nil) != ok {
					errs = append(errs, fmt.Sprintf("%s: %v", what, err))
				}
			}
			check("another user's paste keys", keys(g, "paste", uidAway), false)
			check("Enter before the paste", keys(g, "enter", uidAtScreen), false)
			check("the paste keys", keys(g, "paste", uidAtScreen), true)
			check("the paste keys again", keys(g, "paste", uidAtScreen), false)
			check("Enter", keys(g, "enter", uidAtScreen), m.Enter)
			check("Enter again", keys(g, "enter", uidAtScreen), false)
			ans := control.Header{Op: control.OpInjected, Seq: m.Seq}
			if len(errs) > 0 {
				ans.Error = strings.Join(errs, "; ")
			}
			w.Send(&control.Message{Header: ans})
			grants <- g
		}
	}()
	waitFor(t, "deck offers the desktop", func() bool {
		p := deck.status(t).Paste
		return p != nil && slices.Equal(p.Targets, []string{targetDesktop})
	})
	for _, enter := range []bool{true, false} {
		time.Sleep(time.Second) // one paste a second from one sender
		if _, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "deck", Enter: enter}, "ls"); err != nil {
			t.Fatal(err)
		}
		g := <-grants
		if g == "" {
			t.Fatal("the inject carries no grant")
		}
		time.Sleep(100 * time.Millisecond) // the answer ends it
		if err := keys(g, "paste", uidAtScreen); err == nil {
			t.Error("the paste keys after the session answered")
		}
	}
	if err := keys("00", "paste", uidAtScreen); err == nil {
		t.Error("the paste keys under a grant the service did not make")
	}
}
