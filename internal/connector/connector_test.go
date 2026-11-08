// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package connector

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/service"
)

// fakeBoard is a clipboard that the test changes by hand.
type fakeBoard struct {
	mu       sync.Mutex
	item     Item
	has      bool
	changes  chan Item
	writes   chan Item
	ownWrite bool // the clipboard still holds the last Write
	cleared  chan struct{}
}

func newBoard() *fakeBoard {
	return &fakeBoard{changes: make(chan Item, 16), writes: make(chan Item, 16), cleared: make(chan struct{}, 4)}
}

func (b *fakeBoard) Current() (Item, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.item, b.has, nil
}

func (b *fakeBoard) Next(ctx context.Context) (Item, bool, error) {
	select {
	case it := <-b.changes:
		b.mu.Lock()
		b.item, b.has, b.ownWrite = it, true, false
		b.mu.Unlock()
		return it, true, nil
	case <-ctx.Done():
		return Item{}, false, ctx.Err()
	}
}

func (b *fakeBoard) Write(text string, secret bool) error {
	b.mu.Lock()
	b.item, b.has, b.ownWrite = Item{Text: text, Secret: secret}, true, true
	b.mu.Unlock()
	b.writes <- Item{Text: text, Secret: secret}
	return nil
}

func (b *fakeBoard) ClearIfUnchanged() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ownWrite {
		b.item, b.has = Item{}, false
		b.cleared <- struct{}{}
	}
	return nil
}

// copyOn is the user copying on the desktop.
func (b *fakeBoard) copyOn(it Item) { b.changes <- it }

// noDiscovery finds no one: the test has one member.
type noDiscovery struct{}

func (noDiscovery) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (noDiscovery) SetTXT([]string)               {}

func startService(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- service.Run(ctx, service.Config{StateDir: dir, Socket: socket, Role: node.Full, OS: group.OSLinux, Name: "pi",
			Discover: func(service.DiscoveryConfig) (service.Discovery, error) { return noDiscovery{}, nil }})
	}()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	// The admin socket, which OpNew goes to, opens a moment after the
	// user's one: wait for both.
	var c *control.Client
	for {
		if u, err := control.Dial(socket); err == nil {
			u.Close()
			if c, err = control.DialAt(socket, control.OpNew); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the service did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpNew}}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	return socket
}

func do(t *testing.T, socket string, h control.Header, payload string) *control.Message {
	t.Helper()
	c, err := control.DialAt(socket, h.Op)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h, Payload: []byte(payload)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func paste(t *testing.T, socket string) string {
	t.Helper()
	c, err := control.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPaste}})
	if err != nil {
		return ""
	}
	return string(m.Payload)
}

func run(t *testing.T, socket string, b Board) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Config{Socket: socket, Board: b, Logf: t.Logf}) }()
	t.Cleanup(func() { cancel(); <-done })
}

func TestConnector(t *testing.T) {
	socket := startService(t)
	b := newBoard()
	b.item, b.has = Item{Text: "already there"}, true
	run(t, socket, b)
	// What the clipboard held at start is known to the service, without
	// an event (TestReport checks the message).
	waitFor(t, "the starting text", func() bool { return paste(t, socket) == "already there" })

	// A copy on the desktop reaches the service.
	b.copyOn(Item{Text: "copied on the desktop"})
	waitFor(t, "the desktop copy", func() bool { return paste(t, socket) == "copied on the desktop" })

	// One that came through Universal Clipboard too.
	b.copyOn(Item{Text: "from the iPhone", Remote: true})
	waitFor(t, "the Universal Clipboard copy", func() bool { return paste(t, socket) == "from the iPhone" })

	// A deliberate copy, as from tmux, reaches the desktop clipboard.
	do(t, socket, control.Header{Op: control.OpCopy}, "from tmux")
	expectWrite(t, b, "from tmux", false)

	// A marked secret is not sent: the service only remembers it.
	b.copyOn(Item{Text: "hunter2", Secret: true})
	waitFor(t, "the marked secret", func() bool { return paste(t, socket) == "hunter2" })

	// A copy the group does not carry is skipped, and the session goes on.
	b.copyOn(Item{Text: strings.Repeat("x", clip.MaxText+100)})
	do(t, socket, control.Header{Op: control.OpCopy}, "after the big copy")
	expectWrite(t, b, "after the big copy", false)
}

func expectWrite(t *testing.T, b *fakeBoard, text string, secret bool) {
	t.Helper()
	select {
	case w := <-b.writes:
		if w.Text != text || w.Secret != secret {
			t.Errorf("write %+v, want %q (secret %v)", w, text, secret)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no write of %q", text)
	}
}

func TestReport(t *testing.T) {
	for _, tt := range []struct {
		name    string
		op      string
		it      Item
		wantOp  string
		kind    string
		via     string
		skipped bool
	}{
		{name: "a copy", op: control.OpCopied, it: Item{Text: "x"}, wantOp: control.OpCopied, kind: control.KindText, via: control.ViaCopy},
		{name: "the clipboard at start", op: control.OpClipboard, it: Item{Text: "x"}, wantOp: control.OpClipboard, kind: control.KindText, via: control.ViaCopy},
		{name: "a marked secret is never a copy", op: control.OpCopied, it: Item{Text: "x", Secret: true}, wantOp: control.OpClipboard, kind: control.KindSecret, via: control.ViaCopy},
		{name: "Universal Clipboard", op: control.OpCopied, it: Item{Text: "x", Remote: true}, wantOp: control.OpCopied, kind: control.KindText, via: control.ViaUniversal},
		{name: "a secret through Universal Clipboard", op: control.OpCopied, it: Item{Text: "x", Secret: true, Remote: true}, wantOp: control.OpClipboard, kind: control.KindSecret, via: control.ViaUniversal},
		{name: "empty", op: control.OpCopied, it: Item{}, skipped: true},
		{name: "over 1 MiB", op: control.OpCopied, it: Item{Text: strings.Repeat("x", clip.MaxText+1)}, skipped: true},
		{name: "not UTF-8", op: control.OpCopied, it: Item{Text: "\xff\xfe"}, skipped: true},
	} {
		m := report(tt.op, tt.it)
		if tt.skipped {
			if m != nil {
				t.Errorf("%s: reported %+v", tt.name, m.Header)
			}
			continue
		}
		if m == nil || m.Op != tt.wantOp || m.Kind != tt.kind || m.Via != tt.via || string(m.Payload) != tt.it.Text {
			t.Errorf("%s: got %+v", tt.name, m)
		}
	}
}

// fakeService is a control socket that the test drives: each session it
// accepts is handed to the test after the watch request.
type fakeService struct {
	ln       net.Listener
	sessions chan *fakeSession
}

type fakeSession struct {
	c     net.Conn
	r     *control.Reader
	watch *control.Message
}

func (f *fakeSession) write(t *testing.T, h control.Header, text string) {
	t.Helper()
	h.Op = control.OpWrite
	if err := control.Write(f.c, &control.Message{Header: h, Payload: []byte(text)}); err != nil {
		t.Fatal(err)
	}
}

func listenFake(t *testing.T, socket string) *fakeService {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeService{ln: ln, sessions: make(chan *fakeSession, 8)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r := control.NewReader(c)
			m, err := r.Read()
			if err != nil || m.Op != control.OpWatch {
				c.Close()
				continue
			}
			control.Write(c, &control.Message{Header: control.Header{Op: control.OpReply}})
			f.sessions <- &fakeSession{c: c, r: r, watch: m}
		}
	}()
	return f
}

func (f *fakeService) next(t *testing.T) *fakeSession {
	t.Helper()
	select {
	case s := <-f.sessions:
		t.Cleanup(func() { s.c.Close() })
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("the connector did not connect")
		return nil
	}
}

func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func expectCleared(t *testing.T, b *fakeBoard, want bool) {
	t.Helper()
	select {
	case <-b.cleared:
		if !want {
			t.Error("the clipboard was given up")
		}
	case <-time.After(time.Second):
		if want {
			t.Error("the clipboard was not given up")
		}
	}
}

func TestSecretExpires(t *testing.T) {
	socket := socketPath(t)
	f := listenFake(t, socket)
	b := newBoard()
	b.item, b.has = Item{Text: "on the desktop"}, true
	run(t, socket, b)
	s := f.next(t)
	if string(s.watch.Payload) != "on the desktop" || s.watch.Kind != control.KindText {
		t.Errorf("the watch request carried %+v %q", s.watch.Header, s.watch.Payload)
	}

	// The connector gives up a secret after the lifetime the service sent.
	s.write(t, control.Header{Kind: control.KindSecret, Seq: 1, TTLMS: 50}, "one-time code")
	expectWrite(t, b, "one-time code", true)
	expectCleared(t, b, true)

	// Not when the user copied something else meanwhile.
	s.write(t, control.Header{Kind: control.KindSecret, Seq: 2, TTLMS: 300}, "another code")
	expectWrite(t, b, "another code", true)
	b.copyOn(Item{Text: "the user's copy"})
	expectCleared(t, b, false)

	// A text written after a secret cancels its expiry.
	s.write(t, control.Header{Kind: control.KindSecret, Seq: 3, TTLMS: 300}, "a third code")
	expectWrite(t, b, "a third code", true)
	s.write(t, control.Header{Seq: 4}, "plain text")
	expectWrite(t, b, "plain text", false)
	expectCleared(t, b, false)

	// Writes out of order are dropped.
	s.write(t, control.Header{Seq: 2}, "old")
	s.write(t, control.Header{Seq: 5}, "new")
	expectWrite(t, b, "new", false)

	// A secret still expires when the service connection ends.
	s.write(t, control.Header{Kind: control.KindSecret, Seq: 6, TTLMS: 300}, "code before a restart")
	expectWrite(t, b, "code before a restart", true)
	s.c.Close()
	expectCleared(t, b, true)
}

func TestReconnect(t *testing.T) {
	socket := socketPath(t)
	b := newBoard()
	// No service yet: Run keeps trying and does not fail.
	run(t, socket, b)
	time.Sleep(200 * time.Millisecond)
	f := listenFake(t, socket)
	s := f.next(t)
	s.write(t, control.Header{Seq: 1}, "first session")
	expectWrite(t, b, "first session", false)
	// The service restarts: the connector comes back.
	s.c.Close()
	s = f.next(t)
	s.write(t, control.Header{Seq: 1}, "second session")
	expectWrite(t, b, "second session", false)
}

// goneBoard is a clipboard whose display went away.
type goneBoard struct{ *fakeBoard }

func (goneBoard) Next(context.Context) (Item, bool, error) { return Item{}, false, ErrBoardGone }

func TestBoardGone(t *testing.T) {
	socket := socketPath(t)
	listenFake(t, socket)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Run(ctx, Config{Socket: socket, Board: goneBoard{newBoard()}, Logf: t.Logf}); !errors.Is(err, ErrBoardGone) {
		t.Errorf("Run = %v, want ErrBoardGone", err)
	}
}

// TestRefusedThenWatches: a service that turns the watch down, as one in no
// group does, is asked again soon, so the connector watches within a few
// seconds of the device joining, not after a grown backoff.
func TestRefusedThenWatches(t *testing.T) {
	socket := socketPath(t)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	inGroup := false
	watching := make(chan time.Time, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r := control.NewReader(c)
			if _, err := r.Read(); err != nil {
				c.Close()
				continue
			}
			mu.Lock()
			ok := inGroup
			mu.Unlock()
			if !ok {
				control.Write(c, &control.Message{Header: control.Header{Op: control.OpReply, Error: "this device is in no group", Done: true}})
				c.Close()
				continue
			}
			control.Write(c, &control.Message{Header: control.Header{Op: control.OpReply}})
			watching <- time.Now()
			t.Cleanup(func() { c.Close() })
			return
		}
	}()
	run(t, socket, newBoard())
	// A growing backoff would wait from 7 s to 15 s here.
	time.Sleep(8 * time.Second)
	mu.Lock()
	inGroup = true
	joined := time.Now()
	mu.Unlock()
	select {
	case at := <-watching:
		if d := at.Sub(joined); d > refusedWait+time.Second {
			t.Errorf("watching %v after the join, want within %v", d, refusedWait)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the connector never watched")
	}
}

// fakeTarget pastes into a list, and refuses what says "locked".
type fakeTarget struct {
	name string
	got  chan string
}

func (f *fakeTarget) Target() string { return f.name }

func (f *fakeTarget) Inject(_ context.Context, text, method string, enter, secret bool) error {
	switch {
	case strings.Contains(text, "locked"):
		return &Refusal{Reason: "the session is locked"}
	case strings.Contains(text, "broken"):
		return errors.New("XTEST went away")
	}
	f.got <- method + ":" + text
	return nil
}

// TestTarget runs a connector with a paste target and no clipboard, as
// the tmux helper does: it offers the target, answers each inject, and
// ignores writes.
func TestTarget(t *testing.T) {
	socket := socketPath(t)
	f := listenFake(t, socket)
	tgt := &fakeTarget{name: "tmux", got: make(chan string, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, Config{Socket: socket, Target: tgt, Logf: t.Logf}); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	s := f.next(t)
	if s.watch.Inject != "tmux" || len(s.watch.Payload) != 0 {
		t.Errorf("the watch request: %+v %q", s.watch.Header, s.watch.Payload)
	}
	s.write(t, control.Header{Seq: 1}, "a write")
	for i, tt := range []struct {
		text, method string
		want         control.Header
	}{
		{"ls", "type", control.Header{}},
		{"locked", "paste", control.Header{Error: "the session is locked", Refused: true}},
		{"broken", "paste", control.Header{Error: "the tmux target could not paste", Detail: "XTEST went away"}},
	} {
		seq := uint64(i + 1)
		h := control.Header{Op: control.OpInject, Seq: seq, Method: tt.method}
		if err := control.Write(s.c, &control.Message{Header: h, Payload: []byte(tt.text)}); err != nil {
			t.Fatal(err)
		}
		m, err := s.r.Read()
		if err != nil {
			t.Fatal(err)
		}
		if m.Op != control.OpInjected || m.Seq != seq || m.Error != tt.want.Error || m.Refused != tt.want.Refused || m.Detail != tt.want.Detail {
			t.Errorf("%s: answered %+v", tt.text, m.Header)
		}
	}
	if got := <-tgt.got; got != "type:ls" {
		t.Errorf("the target got %q", got)
	}
}

type fakeActor func(name string) error

func (f fakeActor) Run(_ context.Context, name string) error { return f(name) }

// TestActed: an action's answer says done, refused with the reason as it is,
// or failed with its cause in Detail.
func TestActed(t *testing.T) {
	act := fakeActor(func(name string) error {
		switch name {
		case actions.Sleep:
			return &actions.Refusal{Reason: "the lid is closed"}
		case actions.Reboot:
			return errors.New("osascript: exit status 1")
		}
		return nil
	})
	logf := func(string, ...any) {}
	for _, c := range []struct {
		act            Actor
		name, err, det string
		refused        bool
	}{
		{act, actions.Lock, "", "", false},
		{act, actions.Sleep, "the lid is closed", "", true},
		{act, actions.Reboot, "the session could not run reboot", "osascript: exit status 1", false},
		{nil, actions.Lock, "this session runs no presets: the service runs them", "", true},
	} {
		m := acted(context.Background(), c.act, &control.Message{Header: control.Header{Op: control.OpAct, Seq: 7, Name: c.name}}, logf)
		if m.Op != control.OpActed || m.Seq != 7 || m.Error != c.err || m.Detail != c.det || m.Refused != c.refused {
			t.Errorf("%s: %+v", c.name, m.Header)
		}
	}
}

// ctxTarget keeps the context of its last inject.
type ctxTarget struct{ ctx context.Context }

func (c *ctxTarget) Target() string { return "desktop" }

func (c *ctxTarget) Inject(ctx context.Context, text, method string, enter, secret bool) error {
	c.ctx = ctx
	return nil
}

// An inject hands its target whether the device lets it paste where
// nothing tells whether the session is locked, and the keys grant.
func TestInjectCarriesTheSwitches(t *testing.T) {
	tgt := &ctxTarget{}
	for _, yes := range []bool{false, true} {
		m := &control.Message{Header: control.Header{Op: control.OpInject, Seq: 1, Method: "paste", Keys: "g", NoLockCheck: yes}, Payload: []byte("x")}
		if ans := injected(context.Background(), tgt, m, t.Logf); ans.Error != "" {
			t.Fatalf("injected: %+v", ans.Header)
		}
		if NoLockCheck(tgt.ctx) != yes || KeysGrant(tgt.ctx) != "g" {
			t.Errorf("no_lock_check %v: the target got %v, grant %q", yes, NoLockCheck(tgt.ctx), KeysGrant(tgt.ctx))
		}
	}
}
