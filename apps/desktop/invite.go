// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"rsc.io/qr"
)

// A remote invitation from the window (docs/protocol.md, section 12): on an
// admin, cbb invite -app runs as the administrator (admin.go), opens the
// invitation on the group's hub, writes its state into a file the app
// made, and reads the user's answer about the device that uses it from
// another; removing the first file cancels.

// Invitation is the window's picture of an invitation: its QR code once
// cbb wrote it, when it ends, the device that asks to join, and the name
// of the one that joined.
type Invitation struct {
	Running bool `json:"running"`
	// Image is the QR code as a data: URL of a PNG, Text what it says.
	Image string `json:"image,omitempty"`
	Text  string `json:"text,omitempty"`
	// Ends is when it ends, in Unix milliseconds.
	Ends    int64          `json:"ends,omitempty"`
	Joining *InviteJoining `json:"joining,omitempty"`
	Joined  string         `json:"joined,omitempty"`
}

// InviteJoining is the device that used the invitation, which the user
// admits only if it shows the same fingerprint.
type InviteJoining struct {
	Name        string `json:"name"`
	OS          string `json:"os"`
	Fingerprint string `json:"fingerprint"`
}

// appInvite is what cbb invite -app writes (member/src/admit_cli.rs).
type appInvite struct {
	Invite  string         `json:"invite"`
	Expires int64          `json:"expires"`
	Joining *InviteJoining `json:"joining"`
	Done    bool           `json:"done"`
	Name    string         `json:"name"`
}

// inviteSeconds is how long an invitation from the window is valid: an
// hour, as cbb invite's default.
const inviteSeconds = 3600

// Invite opens an invitation for a device far away; it returns when the
// invitation ends, while the window asks InviteState for its code.
func (d *Desk) Invite() {
	dir, err := os.MkdirTemp("", "cbb-invite-")
	if err != nil {
		msg := d.describe(err) // describe takes d.mu
		d.mu.Lock()
		d.message = msg
		d.mu.Unlock()
		return
	}
	defer os.RemoveAll(dir)
	path, answers := filepath.Join(dir, "invite.json"), filepath.Join(dir, "answers")
	for _, f := range []string{path, answers} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			msg := d.describe(err)
			d.mu.Lock()
			d.message = msg
			d.mu.Unlock()
			return
		}
	}
	d.mu.Lock()
	if d.invitePath != "" {
		d.mu.Unlock()
		return
	}
	d.invitePath, d.answersPath, d.inviteCancelled = path, answers, false
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.invitePath, d.answersPath = "", ""
		d.mu.Unlock()
	}()
	details := d.showDetails()
	d.act(func() (string, error) {
		err := adminRun([]string{"invite", "-for", "1h", "-app", path, "-answers", answers}, "", details)
		d.mu.Lock()
		cancelled := d.inviteCancelled
		d.mu.Unlock()
		switch {
		case cancelled:
			return "", nil
		case err != nil:
			return "", err
		}
		if a, ok := readAppInvite(path); ok && a.Done {
			return d.T("The device joined the group; it appears in the list once it connects."), nil
		}
		return "", nil
	})
}

// readAppInvite reads what cbb invite -app wrote, if it wrote a whole line.
func readAppInvite(path string) (appInvite, bool) {
	var a appInvite
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return a, false
	}
	if err := json.Unmarshal(data, &a); err != nil || a.Invite == "" {
		return a, false // cbb is still writing it
	}
	return a, true
}

// InviteState is the invitation now: its QR code as soon as cbb wrote it,
// and the device it asks about.
func (d *Desk) InviteState() Invitation {
	d.mu.Lock()
	path := d.invitePath
	d.mu.Unlock()
	if path == "" {
		return Invitation{}
	}
	inv := Invitation{Running: true}
	a, ok := readAppInvite(path)
	if !ok {
		return inv
	}
	code, err := qr.Encode(a.Invite, qr.M)
	if err != nil {
		return inv
	}
	code.Scale = 8
	inv.Image = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	inv.Text = a.Invite
	inv.Ends = d.inviteEnds(path, a.Expires)
	inv.Joining = a.Joining
	if a.Done {
		inv.Joined = a.Name
	}
	return inv
}

// inviteEnds is when the invitation in path ends: expires seconds after
// cbb first wrote it, which the window remembers.
func (d *Desk) inviteEnds(path string, expires int64) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inviteSeen != path {
		d.inviteSeen, d.inviteEndsMs = path, time.Now().Add(time.Duration(expires)*time.Second).UnixMilli()
	}
	return d.inviteEndsMs
}

// AnswerInvite is the user's answer about the device that used the
// invitation: yes admits it.
func (d *Desk) AnswerInvite(yes bool) {
	d.mu.Lock()
	answers := d.answersPath
	d.mu.Unlock()
	if answers == "" {
		return
	}
	line := "no\n"
	if yes {
		line = "yes\n"
	}
	f, err := os.OpenFile(answers, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line)
}

// CancelInvite ends the invitation: cbb sees its file gone and hangs up.
func (d *Desk) CancelInvite() {
	d.mu.Lock()
	path := d.invitePath
	if path != "" {
		d.inviteCancelled = true
	}
	d.mu.Unlock()
	if path != "" {
		os.Remove(path)
	}
}
