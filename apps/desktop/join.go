// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
)

// JoinGroup joins a group by the six digits of a pairing window open on
// one of its devices (cbb pair -code as the administrator): on 0.6 a
// device in no group dials the window, and none waits for a phone to dial
// it (D-119). The digits go on standard input, never the command line.
func (d *Desk) JoinGroup(code string) {
	d.adminWith([]string{"pair", "-code"}, strings.TrimSpace(code)+"\n", "Joined the group.")
}

// Joining is a join by invitation as the window shows it: under way, and
// this computer's key fingerprint once cbb wrote it, which whoever invited
// it compares before admitting it.
type Joining struct {
	Running     bool   `json:"running"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// appJoin is what cbb pair -invite -app writes (member/src/lib.rs,
// join_invited).
type appJoin struct {
	Fingerprint string `json:"fingerprint"`
	Done        bool   `json:"done"`
}

// JoinInvite joins a group far away by an invitation (cbb pair -invite -
// -app as the administrator): its text and the user's consent to sync
// away from home, which the window asked for, go on standard input, and
// cbb writes the fingerprint into a file the window reads while it waits
// (JoinState). Removing the file gives up (CancelJoin).
func (d *Desk) JoinInvite(text string) {
	f, err := os.CreateTemp("", "cbb-join-*.json")
	if err != nil {
		msg := d.describe(err) // describe takes d.mu
		d.mu.Lock()
		d.message = msg
		d.mu.Unlock()
		return
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)
	d.mu.Lock()
	if d.joinPath != "" {
		d.mu.Unlock()
		return
	}
	d.joinPath, d.joinCancelled = path, false
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.joinPath = ""
		d.mu.Unlock()
	}()
	// One line each: the invitation, then yes to sync away from home.
	input := strings.Join(strings.Fields(text), "") + "\nyes\n"
	details := d.showDetails()
	d.act(func() (string, error) {
		err := adminRun([]string{"pair", "-invite", "-", "-app", path}, input, details)
		d.mu.Lock()
		cancelled := d.joinCancelled
		d.mu.Unlock()
		switch {
		case cancelled:
			return "", nil
		case err != nil:
			return "", err
		}
		return d.T("Joined the group."), nil
	})
}

// readAppJoin reads what cbb pair -invite -app wrote, if it wrote a whole
// line.
func readAppJoin(path string) (appJoin, bool) {
	var a appJoin
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return a, false
	}
	if err := json.Unmarshal(data, &a); err != nil || a.Fingerprint == "" {
		return a, false // cbb is still writing it
	}
	return a, true
}

// JoinState is the join by invitation now: its fingerprint as soon as cbb
// wrote it.
func (d *Desk) JoinState() Joining {
	d.mu.Lock()
	path := d.joinPath
	d.mu.Unlock()
	if path == "" {
		return Joining{}
	}
	j := Joining{Running: true}
	if a, ok := readAppJoin(path); ok {
		j.Fingerprint = a.Fingerprint
	}
	return j
}

// CancelJoin gives up the join by invitation: cbb sees its file gone and
// hangs up.
func (d *Desk) CancelJoin() {
	d.mu.Lock()
	path := d.joinPath
	if path != "" {
		d.joinCancelled = true
	}
	d.mu.Unlock()
	if path != "" {
		os.Remove(path)
	}
}

// Dismiss hides the group's notice id on this computer, as a phone's user
// hides it (control.Status.Notices); it needs no administrator.
func (d *Desk) Dismiss(id string) {
	d.plain(control.Header{Op: control.OpDismiss, Value: id}, "")
}
