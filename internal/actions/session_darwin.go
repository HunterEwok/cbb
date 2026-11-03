// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package actions

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// On a Mac the agent runs the presets as the signed-in user: pmset for the
// display and sleep, Apple events to loginwindow for restart and shut down,
// which ask the open apps to quit as the Apple menu does. The minute before
// a restart or shutdown is the agent's own timer.

// Session returns the runner of the presets in this session.
func Session() Runner { return &mac{} }

type mac struct {
	mu      sync.Mutex
	pending *time.Timer
}

func (m *mac) Run(ctx context.Context, name string) error {
	switch name {
	case Lock:
		// The display sleeps; the Mac locks when it asks for the password
		// right after that (System Settings, Lock Screen).
		return run(ctx, "pmset", "displaysleepnow")
	case Sleep:
		return run(ctx, "pmset", "sleepnow")
	case Reboot, Shutdown:
		event := "aevtrrst"
		if name == Shutdown {
			event = "aevtrsdn"
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.pending != nil {
			return &Refusal{Reason: "a reboot or shutdown is pending here already; cancel-shutdown stops it"}
		}
		m.pending = time.AfterFunc(ScheduleDelay, func() {
			m.mu.Lock()
			m.pending = nil
			m.mu.Unlock()
			run(context.Background(), "osascript", "-e", fmt.Sprintf(`tell application "loginwindow" to «event %s»`, event))
		})
		return nil
	case Cancel:
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.pending == nil || !m.pending.Stop() {
			return &Refusal{Reason: "no reboot or shutdown is pending here"}
		}
		m.pending = nil
		return nil
	}
	return &Refusal{Reason: fmt.Sprintf("this device has no action %q", name)}
}

// run runs a system tool; macOS's refusal to let it send Apple events is
// the user's to lift.
func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, "/usr/bin/"+name, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "-1743") {
		return &Refusal{Reason: "macOS did not let CBB's agent control the Mac; its user allows it in System Settings, Privacy & Security, Automation"}
	}
	return fmt.Errorf("%s: %w: %s", name, err, msg)
}
