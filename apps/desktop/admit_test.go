// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/base64"
	"path/filepath"
	"slices"
	"testing"

	"rsc.io/qr"
)

const joinText = "cbb://join?code=123456&addr=192.0.2.7:8764&fp=AbC%2Bd%2F0="

func qrPicture(t *testing.T, text string) string {
	t.Helper()
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	c.Scale = 6
	return base64.StdEncoding.EncodeToString(c.PNG())
}

// A picture of the code that a waiting phone shows gives back its text;
// another code, or no picture, an error.
func TestReadQR(t *testing.T) {
	d := &Desk{tr: map[string]string{}}
	if got, err := d.ReadQR(qrPicture(t, joinText)); err != nil || got != joinText {
		t.Fatalf("ReadQR = %q, %v", got, err)
	}
	if _, err := d.ReadQR(qrPicture(t, "https://cbb.tools")); err == nil {
		t.Error("read a code that is no join code")
	}
	if _, err := d.ReadQR(qrPicture(t, "cbb://join?code=123456")); err == nil {
		t.Error("read the code of a joiner that does not listen")
	}
	if _, err := d.ReadQR(base64.StdEncoding.EncodeToString([]byte("not a picture"))); err == nil {
		t.Error("read a file that is no picture")
	}
}

// TestAdmitByQR: Admit runs cbb pair -qr as the administrator with the text on its
// standard input, never among its arguments.
func TestAdmitByQR(t *testing.T) {
	var args []string
	var input string
	old := adminRun
	adminRun = func(a []string, in string, _ bool) error {
		args, input = a, in
		return nil
	}
	defer func() { adminRun = old }()
	d := &Desk{tr: map[string]string{}, socket: filepath.Join(t.TempDir(), "none.sock")}
	d.Admit("  "+joinText+"\n", false)
	if !slices.Equal(args, []string{"pair", "-qr"}) || input != joinText+"\n" {
		t.Fatalf("ran %q with %q", args, input)
	}
	d.Admit(joinText, true)
	if !slices.Equal(args, []string{"pair", "-qr", "-admin"}) {
		t.Fatalf("as an admin, ran %q", args)
	}
	// The six digits the new device shows, typed with a space.
	d.Admit(" 246 810 ", false)
	if !slices.Equal(args, []string{"pair", "-qr"}) || input != "246810\n" {
		t.Fatalf("by the shown code, ran %q with %q", args, input)
	}
	for _, bad := range []string{"cbb://join?code=123456", "12345", "1234567", "12a456"} {
		args, d.message = nil, ""
		d.Admit(bad, false)
		if args != nil || d.message == "" {
			t.Errorf("admitted %q: %q, %q", bad, args, d.message)
		}
	}
}
