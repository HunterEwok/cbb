// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"time"

	"rsc.io/qr"

	"github.com/HunterEwok/cbb/internal/phone"
)

// Joining a group from the window: the window shows the QR code a phone of
// the group scans and the six digits a computer of the group types (cbb
// pair -qr there). Joining changes the group, so cbb pair -app runs as the
// administrator (admin.go) and writes the code's text into a file the app
// made, which the app reads while cbb waits; removing the file cancels.

// Join is the window's picture of a join: the QR code once cbb wrote it,
// when its wait ends, and the port the firewall must let the phone reach.
type Join struct {
	Running bool `json:"running"`
	// Image is the QR code as a data: URL of a PNG, Text what it says.
	Image string `json:"image,omitempty"`
	Text  string `json:"text,omitempty"`
	// Code is the six digits the QR code holds, which a computer of the
	// group types to admit this one, in two groups of three.
	Code string `json:"code,omitempty"`
	// Ends is when the wait ends, in Unix milliseconds.
	Ends int64 `json:"ends,omitempty"`
	Port int   `json:"port,omitempty"`
}

// appJoin is what cbb pair -app writes (cmd/cbb/joinapp.go).
type appJoin struct {
	QR      string `json:"qr"`
	Expires int    `json:"expires"`
	Port    int    `json:"port"`
}

// JoinGroup joins the group of the device that admits this one by its
// code; it returns when the join ends, while the window asks JoinState for
// the code.
func (d *Desk) JoinGroup() {
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
	d.joinPath, d.join, d.joinCancelled = path, Join{Running: true}, false
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.joinPath, d.join = "", Join{}
		d.mu.Unlock()
	}()
	details := d.showDetails()
	d.act(func() (string, error) {
		err := adminRun([]string{"pair", "-app", path}, "", details)
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

// JoinState is the join now: the QR code as soon as cbb wrote it.
func (d *Desk) JoinState() Join {
	d.mu.Lock()
	path, j := d.joinPath, d.join
	d.mu.Unlock()
	if path == "" || j.Text != "" {
		return j
	}
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return j
	}
	var a appJoin
	if err := json.Unmarshal(data, &a); err != nil || a.QR == "" {
		return j // cbb is still writing it
	}
	code, err := qr.Encode(a.QR, qr.M)
	if err != nil {
		return j
	}
	code.Scale = 8
	j.Image = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	j.Text, j.Port = a.QR, a.Port
	if jc, ok := phone.ParseJoinQR(a.QR); ok && len(jc.Code) == 6 {
		j.Code = jc.Code[:3] + " " + jc.Code[3:]
	}
	j.Ends = time.Now().Add(time.Duration(a.Expires) * time.Second).UnixMilli()
	d.mu.Lock()
	if d.joinPath == path {
		d.join = j
	}
	d.mu.Unlock()
	return j
}

// CancelJoin ends the wait: cbb sees its file gone and hangs up.
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
