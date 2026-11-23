// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// inviteRun stands for cbb invite -app as the administrator: it writes the
// invitation, then the device that used it, waits for the user's answer
// and writes that the device joined when the answer is yes; it hangs up
// when the window removes the file.
func inviteRun(t *testing.T, got chan<- string) func([]string, string, bool) error {
	return func(args []string, _ string, _ bool) error {
		var file, answers string
		for i := range args[:len(args)-1] {
			switch args[i] {
			case "-app":
				file = args[i+1]
			case "-answers":
				answers = args[i+1]
			}
		}
		if args[0] != "invite" || file == "" || answers == "" {
			t.Errorf("cbb %v", args)
			return errCancelled
		}
		write := func(a appInvite) {
			b, _ := json.Marshal(a)
			if err := os.WriteFile(file, append(b, '\n'), 0o600); err != nil {
				t.Error(err)
			}
		}
		a := appInvite{Invite: "cbb://join#pAFQq83vEjRWeJA", Expires: inviteSeconds}
		write(a)
		a.Joining = &InviteJoining{Name: "Anna's laptop", OS: "Windows", Fingerprint: "3F9A 1C2E"}
		write(a)
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if _, err := os.Stat(file); err != nil {
				return &adminError{msg: "cancelled"}
			}
			f, err := os.Open(answers)
			if err != nil {
				return err
			}
			line, _ := bufio.NewReader(f).ReadString('\n')
			f.Close()
			if line == "" {
				continue
			}
			got <- strings.TrimSpace(line)
			if line == "yes\n" {
				a.Done, a.Name = true, "Anna's laptop"
				write(a)
			}
			return nil
		}
		return &adminError{msg: "no answer"}
	}
}

// TestInvite walks an invitation from the window: its QR code once cbb
// wrote it, the device that used it, the user's yes, and the device in the
// group; a second invitation waits for none; a cancelled one says nothing.
func TestInvite(t *testing.T) {
	answers := make(chan string, 1)
	old := adminRun
	adminRun = inviteRun(t, answers)
	t.Cleanup(func() { adminRun = old })
	d := &Desk{tr: map[string]string{}}

	if inv := d.InviteState(); inv.Running {
		t.Fatalf("an invitation before one opened: %+v", inv)
	}
	d.AnswerInvite(true) // nobody asks: nothing happens
	d.CancelInvite()

	done := make(chan struct{})
	go func() { d.Invite(); close(done) }()
	var inv Invitation
	for deadline := time.Now().Add(10 * time.Second); inv.Joining == nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no device asked: %+v", inv)
		}
		inv = d.InviteState()
	}
	if !inv.Running || !strings.HasPrefix(inv.Image, "data:image/png;base64,") || inv.Text != "cbb://join#pAFQq83vEjRWeJA" {
		t.Fatalf("the invitation: %+v", inv)
	}
	if left := time.Until(time.UnixMilli(inv.Ends)); left < 59*time.Minute || left > time.Hour {
		t.Errorf("it ends in %v", left)
	}
	// Its end stays where it was first seen.
	if again := d.InviteState(); again.Ends != inv.Ends {
		t.Errorf("the end moved from %d to %d", inv.Ends, again.Ends)
	}
	// One invitation at a time: a second returns at once.
	d.Invite()
	d.AnswerInvite(true)
	if a := <-answers; a != "yes" {
		t.Fatalf("cbb heard %q", a)
	}
	<-done
	if d.message != "The device joined the group; it appears in the list once it connects." {
		t.Errorf("the window says %q", d.message)
	}
	if inv := d.InviteState(); inv.Running {
		t.Errorf("still running after it ended: %+v", inv)
	}

	// A no: cbb hears it and the device stays out.
	done = make(chan struct{})
	go func() { d.Invite(); close(done) }()
	waitInvite(t, d)
	d.AnswerInvite(false)
	if a := <-answers; a != "no" {
		t.Fatalf("cbb heard %q", a)
	}
	<-done
	if d.message != "" {
		t.Errorf("after a no the window says %q", d.message)
	}

	// Cancelled: cbb hangs up, and the window says nothing of it.
	done = make(chan struct{})
	go func() { d.Invite(); close(done) }()
	waitInvite(t, d)
	d.CancelInvite()
	<-done
	if d.message != "" {
		t.Errorf("after a cancel the window says %q", d.message)
	}
}

func waitInvite(t *testing.T, d *Desk) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); d.InviteState().Joining == nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no device asked")
		}
	}
}

// TestReadAppInvite: a line cbb has not finished, or one without an
// invitation, is no invitation yet.
func TestReadAppInvite(t *testing.T) {
	path := t.TempDir() + "/invite.json"
	if _, ok := readAppInvite(path); ok {
		t.Error("a missing file read")
	}
	for _, text := range []string{"", "  \n", `{"invite":"cbb://jo`, `{"expires":3600}`} {
		os.WriteFile(path, []byte(text), 0o600)
		if _, ok := readAppInvite(path); ok {
			t.Errorf("%q read", text)
		}
	}
	os.WriteFile(path, []byte(`{"invite":"cbb://join#x","expires":60,"done":true,"name":"pi"}`+"\n"), 0o600)
	if a, ok := readAppInvite(path); !ok || !a.Done || a.Name != "pi" {
		t.Errorf("%+v, %v", a, ok)
	}
}
