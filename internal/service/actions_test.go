// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
)

// fakeRunner records the presets it ran, and refuses those in refuse: the
// Go service's runner, and the Rust service's through the folder dir that
// CBB_TEST_ACTIONS names (member/src/actions.rs).
type fakeRunner struct {
	mu     sync.Mutex
	ran    []string
	refuse map[string]string
	dir    string
}

func newFakeRunner(t *testing.T, refuse map[string]string) *fakeRunner {
	t.Helper()
	r := &fakeRunner{refuse: refuse, dir: t.TempDir()}
	for name, reason := range refuse {
		if err := os.WriteFile(filepath.Join(r.dir, "refuse-"+name), []byte(reason), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (r *fakeRunner) Run(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reason, ok := r.refuse[name]; ok {
		return &actions.Refusal{Reason: reason}
	}
	r.ran = append(r.ran, name)
	return nil
}

// env is the Rust service's environment for the runner.
func (r *fakeRunner) env() string { return "CBB_TEST_ACTIONS=" + r.dir }

func (r *fakeRunner) took() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ran := append([]string(nil), r.ran...)
	if data, err := os.ReadFile(filepath.Join(r.dir, "ran")); err == nil {
		ran = append(ran, strings.Fields(string(data))...)
	}
	return ran
}

func TestQuickActions(t *testing.T) {
	var h hub
	runner := newFakeRunner(t, map[string]string{actions.Sleep: "the session is locked"})
	pi := startService(t, &h, "pi")
	deck := startEnv(t, &h, "deck", func(c *Config) { c.runner = runner }, runner.env())
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	run := func(name string) error {
		time.Sleep(time.Second) // one action a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: name}, "")
		return err
	}
	set := func(a control.Action) {
		t.Helper()
		if _, err := deck.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{a}}, ""); err != nil {
			t.Fatalf("setting %+v: %v", a, err)
		}
	}
	wantRefused := func(name, reason string) {
		t.Helper()
		if err := run(name); err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v, want %q", name, err, reason)
		}
	}

	wantRefused(actions.Lock, "the action lock is off on this device")
	wantRefused("format-disk", "this device has no action")
	set(control.Action{Name: actions.Lock, On: true})
	if err := run(actions.Lock); err != nil {
		t.Fatal(err)
	}
	set(control.Action{Name: actions.Lock, On: true, By: []string{actions.ByPhone}})
	wantRefused(actions.Lock, "only for phone")

	// pi's keys are in files: reboot takes it only with any key.
	set(control.Action{Name: actions.Reboot, On: true})
	wantRefused(actions.Reboot, "keys are in hardware")
	set(control.Action{Name: actions.Reboot, On: true, AnyKey: true})
	if err := run(actions.Reboot); err != nil {
		t.Fatal(err)
	}
	set(control.Action{Name: actions.Sleep, On: true})
	wantRefused(actions.Sleep, "the session is locked")
	if got := runner.took(); strings.Join(got, ",") != "lock,reboot" {
		t.Errorf("ran %v", got)
	}

	// A member that is not an admin runs none.
	if _, err := deck.do(t, control.Header{Op: control.OpActionOn, Device: "pi", Name: actions.Lock}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("deck ran an action on pi: %v", err)
	}

	// The log keeps who asked and how it ended.
	log, err := actions.ReadLog(deck.dir)
	if err != nil || len(log) != 7 {
		t.Fatalf("the log: %+v, %v", log, err)
	}
	if e := log[2]; e.Action != actions.Lock || e.Result != "done" || e.Name != "pi" || e.Unverified {
		t.Errorf("the lock's entry: %+v", e)
	}

	// Any admin turns them all off, and only deck's user on again.
	if _, err := pi.do(t, control.Header{Op: control.OpActionOff, Device: "deck"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, a := range deck.status(t).Actions {
		if a.On {
			t.Errorf("%s is on after actions-off", a.Name)
		}
	}
	wantRefused(actions.Reboot, "is off on this device")

	// restart ends Run with ErrRestart, for the service manager.
	set(control.Action{Name: actions.Restart, On: true})
	if err := run(actions.Restart); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-deck.done:
		deck.cancel = nil
		if !errors.Is(err, ErrRestart) {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("deck did not restart")
	}
}

// TestQuickActionsInSession: on a Mac and on Windows the agent runs the
// presets in the user's session.
func TestQuickActionsInSession(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startWith(t, &h, "deck", "linux", func(c *Config) { c.actInSession = true })
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	for _, name := range []string{actions.Lock, actions.Sleep} {
		if _, err := deck.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{{Name: name, On: true}}}, ""); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string) error {
		time.Sleep(time.Second) // one action a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: name}, "")
		return err
	}
	if err := run(actions.Lock); err == nil || !strings.Contains(err.Error(), "nobody is signed in here") {
		t.Errorf("without an agent: %v", err)
	}
	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Act: true}}); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op != control.OpAct {
				continue
			}
			got <- m.Name
			ans := control.Header{Op: control.OpActed, Seq: m.Seq}
			if m.Name == actions.Sleep {
				ans.Error, ans.Refused = "the lid is closed", true
			}
			w.Send(&control.Message{Header: ans})
		}
	}()
	if err := run(actions.Lock); err != nil {
		t.Fatal(err)
	}
	if err := run(actions.Sleep); err == nil || !strings.Contains(err.Error(), "the lid is closed") {
		t.Errorf("sleep: %v", err)
	}
	if a, b := <-got, <-got; a != actions.Lock || b != actions.Sleep {
		t.Errorf("the agent got %s and %s", a, b)
	}
}

// TestOwnActions: the user's own action runs in the session, through the
// agent, with the program and arguments its user gave and nothing else.
func TestOwnActions(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })
	set := func(a control.Action) error {
		_, err := deck.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{a}}, "")
		return err
	}
	for _, c := range []struct {
		a    control.Action
		want string
	}{
		{control.Action{Name: actions.Lock, On: true, Command: []string{"/bin/true"}}, "is a preset"},
		{control.Action{Name: "backup", On: true, Command: []string{"backup.sh"}}, "full path"},
		{control.Action{Name: "Backup", On: true, Command: []string{"/bin/true"}}, "not an action's name"},
		{control.Action{Name: "backup", On: true}, "has no action"},
	} {
		if err := set(c.a); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.a, err, c.want)
		}
	}
	prog := "/usr/local/bin/backup"
	if runtime.GOOS == "windows" {
		prog = `C:\Tools\backup.exe`
	}
	if err := set(control.Action{Name: "backup", On: true, Command: []string{prog, "--quick"}}); err != nil {
		t.Fatal(err)
	}
	var own *control.Action
	for _, a := range deck.status(t).Actions {
		if a.Name == "backup" {
			own = &a
		}
	}
	if own == nil || !own.On || strings.Join(own.Command, " ") != prog+" --quick" {
		t.Fatalf("the status lists %+v", own)
	}

	w := deck.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Act: true}}); err != nil {
		t.Fatal(err)
	}
	got := make(chan *control.Message, 2)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op == control.OpAct {
				got <- m
				w.Send(&control.Message{Header: control.Header{Op: control.OpActed, Seq: m.Seq}})
			}
		}
	}()
	if _, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: "backup"}, ""); err != nil {
		t.Fatal(err)
	}
	if m := <-got; m.Name != "backup" || strings.Join(m.Command, " ") != prog+" --quick" {
		t.Errorf("the agent got %+v", m.Header)
	}

	// Disabling keeps the command; removing takes it away, and a preset
	// stays.
	if err := set(control.Action{Name: "backup"}); err != nil {
		t.Fatal(err)
	}
	if a, err := actions.Load(deck.dir); err != nil || a.Get("backup").On || len(a.Get("backup").Command) != 2 {
		t.Errorf("after disable: %+v, %v", a, err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpActionDel, Name: actions.Lock}, ""); err == nil || !strings.Contains(err.Error(), "is a preset") {
		t.Errorf("removing a preset: %v", err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpActionDel, Name: "backup"}, ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second) // one action a second from one sender
	if _, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "deck", Name: "backup"}, ""); err == nil || !strings.Contains(err.Error(), "has no action") {
		t.Errorf("a removed action: %v", err)
	}
}
