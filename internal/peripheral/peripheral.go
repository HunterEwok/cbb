// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package peripheral is a member as the keyboard and the remote of other
// devices (docs/roadmap.md, item 25): the Bluetooth keyboard on Linux
// (internal/blekeyboard) and the TVs' remotes (internal/tvremote), with
// cbb keyboard and cbb remote, and the remote pastes the user sends there.
// The Go service and cbb-helper, for the Rust service, both run it.
package peripheral

import (
	"context"
	"errors"
	"sync"
	"time"
)

// A Host is this device as the keyboard and the remote: its state folder,
// its name, which the keyboard and the TVs show, and its log.
type Host struct {
	Dir  string
	Name string
	// OS is the group's name of this device's system (group.OSLinux...);
	// only Linux has the Bluetooth keyboard, unless Bus is set.
	OS string
	// Bus connects to the bus BlueZ is on; the system bus on Linux if nil.
	// Tests replace it.
	Bus  BusDialer
	Logf func(format string, args ...any)

	kbd keyboardState
	tv  tvState

	mu sync.Mutex
	// typing holds the targets that type a paste after its answer (the
	// Bluetooth keyboard, a Roku): one text at a time on each.
	typing map[string]bool
}

// Close takes the keyboard off BlueZ and ends a TV pairing, as the service
// stops.
func (h *Host) Close() {
	h.closeKeyboard()
	h.endTVPairing()
}

// The statuses of a paste's result, as the member protocol's.
const (
	Done    = "done"
	Refused = "refused"
	Failed  = "failed"
)

// A Result is how a paste ended here: done, refused or failed, and why.
type Result struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Paste types a remote paste on the Bluetooth keyboard's host or the TV
// the user sends pastes to, the keyboard first; ok is false when pastes go
// to this computer's screen. enter is whether the user allows Enter, and
// bodyEnter whether the command asks for Enter after the text. still says
// whether a paste typed after its answer may go on.
func (h *Host) Paste(text string, enter, bodyEnter bool, still func() bool) (Result, bool) {
	if r, ok := h.keyboardPaste(text, enter, bodyEnter, still); ok {
		return r, true
	}
	return h.tvPaste(text, enter, bodyEnter, still)
}

// Targets lists the targets remote pastes go to here instead of the
// screen: keyboard and tv.
func (h *Host) Targets() []string {
	var out []string
	if h.keyboardPastes() {
		out = append(out, TargetKeyboard)
	}
	if h.tvPastes() {
		out = append(out, TargetTV)
	}
	return out
}

// The paste targets of the keyboard and of a TV's remote, which no
// watcher offers.
const (
	TargetKeyboard = "bluetooth-keyboard"
	TargetTV       = "tv"
)

// pasteWait is how long a TV may take to take a paste, as a watcher.
const pasteWait = 5 * time.Second

// TypingCheck is how often a paste typed after its answer checks that it
// may go on.
var TypingCheck = 500 * time.Millisecond

// typeLater types with typ after the answer, as a long text takes longer
// than the sender waits: one text at a time on target, false when one is
// typing there. Typing stops once still says the paste may no longer go on.
func (h *Host) typeLater(target string, still func() bool, typ func(context.Context) error) bool {
	h.mu.Lock()
	if h.typing == nil {
		h.typing = map[string]bool{}
	}
	if h.typing[target] {
		h.mu.Unlock()
		return false
	}
	h.typing[target] = true
	h.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	t := time.NewTicker(TypingCheck)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !still() {
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		defer func() {
			cancel()
			h.mu.Lock()
			delete(h.typing, target)
			h.mu.Unlock()
		}()
		if err := typ(ctx); err != nil && !errors.Is(err, context.Canceled) {
			h.Logf("cbb: typing a paste on %s: %v", target, err)
		} else if errors.Is(err, context.Canceled) {
			h.Logf("cbb: stopped typing a paste on %s: it may no longer go on", target)
		}
	}()
	return true
}

// ErrKeyboardOS is the answer where there is no Bluetooth keyboard.
var ErrKeyboardOS = errors.New("only a Linux computer can be a Bluetooth keyboard: macOS and Windows let no program be one; an Android phone or the Nano ESP32 can")

// A Refusal is an action the device will not do, which its user fixes
// there; the reason goes to the sender as it is.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }
