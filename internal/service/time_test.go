// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// The rules that live for minutes or days, walked with the test clock
// (testClock.run) instead of waited for: the service counts running time
// on its one clock, so moving that clock walks the rule in seconds. The
// rules of records v3 (a takeover's 72 hours of held time, the weekly key
// change, a guarded leaf's 35 days) join here when the service moves to
// the 0.6 core; docs/testing.md, "Time", lists them.

// TestPairingWindowCloses checks that a pairing window closes after its
// five minutes of the admin's running time, and not before.
func TestPairingWindowCloses(t *testing.T) {
	clock := newTestClock(t, 0)
	var h hub
	pi := startService(t, &h, "pi")
	pi.env = []string{clock.env()}
	pi.stop()
	pi = restartService(t, &h, pi)
	c, _ := openWindow(t, pi)
	defer c.Close()
	// Four minutes: still open, so a second window is refused.
	clock.run(t, 4*time.Minute)
	time.Sleep(2 * time.Second)
	if _, err := pi.do(t, control.Header{Op: control.OpPair}, ""); err == nil {
		t.Fatal("a second window opened while the first is open")
	}
	// Past five minutes: the window ends as expired within its second of
	// polling.
	clock.run(t, 61*time.Second)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	m, err := c.Receive()
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the window ended with %+v, %v; want expired", m, err)
	}
}

// TestSetWallClockMovesNoRunningTime checks that setting the wall clock a
// day ahead does not end a window that counts running time.
func TestSetWallClockMovesNoRunningTime(t *testing.T) {
	clock := newTestClock(t, 0)
	var h hub
	pi := startService(t, &h, "pi")
	pi.env = []string{clock.env()}
	pi.stop()
	pi = restartService(t, &h, pi)
	c, _ := openWindow(t, pi)
	defer c.Close()
	clock.set(t, 24*time.Hour)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if m, err := c.Receive(); err == nil || !isTimeout(err) {
		t.Fatalf("a window ended when the wall clock was set: %+v, %v", m, err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
