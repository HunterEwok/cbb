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
)

// Adding a device from the window: on the root or an admin, cbb pair -app
// runs as the administrator (admin.go), opens a pairing window and writes
// its six digits and QR code into a file the app made, which the app reads
// while cbb waits; the new device dials the window with the digits (a
// computer) or the QR code (a phone), D-119. Removing the file closes the
// window.

// Window is the add dialog's picture of a pairing window: its QR code and
// digits once cbb wrote them, when it closes, the last device that failed,
// and the name of the one that joined.
type Window struct {
	Running bool `json:"running"`
	// Image is the QR code as a data: URL of a PNG.
	Image string `json:"image,omitempty"`
	// Code is the six digits, in two groups of three.
	Code string `json:"code,omitempty"`
	// Address is where a computer without mDNS dials the window.
	Address string `json:"address,omitempty"`
	// Ends is when the window closes, in Unix milliseconds.
	Ends    int64  `json:"ends,omitempty"`
	Refused string `json:"refused,omitempty"`
	Joined  string `json:"joined,omitempty"`
}

// appWindow is what cbb pair -app writes (member/src/admit_cli.rs).
type appWindow struct {
	Code    string `json:"code"`
	QR      string `json:"qr"`
	Address string `json:"address"`
	Expires int64  `json:"expires"`
	Refused string `json:"refused"`
	Done    bool   `json:"done"`
	Name    string `json:"name"`
}

// OpenWindow opens a pairing window for a new device; with admin, on the
// group's root, the phone that joins becomes an admin (cbb pair -admin).
// It returns when the window closes, while the dialog asks WindowState for
// its code.
func (d *Desk) OpenWindow(admin bool) {
	f, err := os.CreateTemp("", "cbb-window-*.json")
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
	if d.windowPath != "" {
		d.mu.Unlock()
		return
	}
	d.windowPath, d.windowCancelled, d.windowSeen = path, false, ""
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.windowPath = ""
		d.mu.Unlock()
	}()
	args := []string{"pair", "-app", path}
	if admin {
		args = append(args, "-admin")
	}
	details := d.showDetails()
	d.act(func() (string, error) {
		err := adminRun(args, "", details)
		d.mu.Lock()
		cancelled := d.windowCancelled
		d.mu.Unlock()
		switch {
		case cancelled:
			return "", nil
		case err != nil:
			return "", err
		}
		if a, ok := readAppWindow(path); ok && a.Done {
			return d.T("It joined the group."), nil
		}
		return "", nil
	})
}

// readAppWindow reads what cbb pair -app wrote, if it wrote a whole line.
func readAppWindow(path string) (appWindow, bool) {
	var a appWindow
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return a, false
	}
	if err := json.Unmarshal(data, &a); err != nil || len(a.Code) != 6 {
		return a, false // cbb is still writing it
	}
	return a, true
}

// WindowState is the pairing window now: its code and QR code as soon as
// cbb wrote them.
func (d *Desk) WindowState() Window {
	d.mu.Lock()
	path := d.windowPath
	d.mu.Unlock()
	if path == "" {
		return Window{}
	}
	w := Window{Running: true}
	a, ok := readAppWindow(path)
	if !ok {
		return w
	}
	if a.QR != "" {
		if code, err := qr.Encode(a.QR, qr.M); err == nil {
			code.Scale = 8
			w.Image = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
		}
	}
	w.Code = a.Code[:3] + " " + a.Code[3:]
	w.Address, w.Refused = a.Address, a.Refused
	d.mu.Lock()
	if d.windowSeen != path {
		d.windowSeen, d.windowEndsMs = path, time.Now().Add(time.Duration(a.Expires)*time.Second).UnixMilli()
	}
	w.Ends = d.windowEndsMs
	d.mu.Unlock()
	if a.Done {
		w.Joined = a.Name
	}
	return w
}

// CloseWindow closes the pairing window: cbb sees its file gone and hangs
// up.
func (d *Desk) CloseWindow() {
	d.mu.Lock()
	path := d.windowPath
	if path != "" {
		d.windowCancelled = true
	}
	d.mu.Unlock()
	if path != "" {
		os.Remove(path)
	}
}
