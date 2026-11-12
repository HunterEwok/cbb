// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

// Package lockcheck tells a remote paste target whether a session is
// locked (design.md, "The lock check"): synthetic keys do not stop at a
// lock screen, so a target asks right before it presses them.
package lockcheck

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// lockers are screen and console lockers that run only while they lock,
// for those that do not tell logind: swaylock and its kin, vlock.
var lockers = []string{"swaylock", "hyprlock", "waylock", "gtklock", "i3lock", "slock", "xsecurelock", "physlock", "vlock",
	// KDE's lock screen tells logind on Linux; on FreeBSD its greeter
	// running is the only sign.
	"kscreenlocker_greet"}

// Unknown is the reason a target gives when nothing tells whether the
// session is locked and its user did not allow pastes without the check.
const Unknown = "this device cannot tell whether its session is locked, as logind does not say, so it takes no remote paste; its user may allow pastes without that check with cbb paste-receive on -no-lock-check"

// Reason says why the graphical session of this process takes no keys
// now, or "" if it does: logind marks it locked, as GNOME, KDE and most
// lock screens tell it, or a locker runs as this user, or logind does not
// tell, without logind (as on FreeBSD) or when it does not answer, unless
// noLockCheck lets the paste go on then.
func Reason(noLockCheck bool) string {
	locked, known := State(sessionID())
	if locked {
		return "the session is locked"
	}
	if name := Locker(false); name != "" {
		return "the screen is locked (" + name + " runs)"
	}
	if !known && !noLockCheck {
		return Unknown
	}
	return ""
}

// sessionID is the logind session to check for this process: its own,
// or, for a process started outside one (a user service, whose
// environment has no XDG_SESSION_ID), the one logind picks for its user,
// "auto", the user's graphical session when there is one.
func sessionID() string {
	if id := os.Getenv("XDG_SESSION_ID"); id != "" {
		return id
	}
	return "auto"
}

// State reports whether logind marks the session id locked, and whether
// it told at all: known is false without logind or an id, when loginctl
// fails, and when it gives no LockedHint of yes or no.
func State(id string) (locked, known bool) {
	if id == "" {
		return false, false
	}
	switch Show(id, "LockedHint")["LockedHint"] {
	case "yes":
		return true, true
	case "no":
		return false, true
	}
	return false, false
}

// Show returns logind's properties of the session id, empty when logind
// does not answer.
func Show(id string, props ...string) map[string]string {
	args := []string{"show-session", id}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	out, err := loginctl(args...)
	m := map[string]string{}
	if err != nil {
		return m
	}
	for line := range strings.Lines(out) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// ActiveSession returns the ID of the session active on seat, or "".
func ActiveSession(seat string) string {
	out, err := loginctl("show-seat", seat, "-p", "ActiveSession", "--value")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func loginctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "loginctl", args...).Output()
	return string(out), err
}

// Locker returns the name of a locker that runs, as this user or, with
// anyUser, as anyone, or "".
func Locker(anyUser bool) string {
	uid := uint32(os.Getuid())
	for _, p := range running() {
		if slices.Contains(lockers, p.name) && (anyUser || p.uid == uid) {
			return p.name
		}
	}
	return ""
}

// running lists the running processes; tests replace it, so that a
// locker they pretend runs is not seen by the tests of other packages
// running at the same time.
var running = processes

// A process is the command name and user of a running process.
type process struct {
	name string
	uid  uint32
}
