// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/invite"
)

// liteBin returns the Rust member's program, or skips the test.
func liteBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	return bin
}

// TestLiteInvite checks a remote invitation from the Rust service as the
// group's hub: a Go device on another network joins through the hub's
// guest tunnel once the admin confirmed the device it shows, after one the
// admin declined, then reaches the hub through the tunnel with its own key.
func TestLiteInvite(t *testing.T) {
	bin := liteBin(t)
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	rust := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr())
	waitFor(t, "the Rust member connected to the desk", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1
	})
	if _, err := rust.do(t, control.Header{Op: control.OpInvite}, ""); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Errorf("an invitation from a member that is no admin: %v", err)
	}
	adminOn(t, cli, desk, "rust")
	port := freeUDP(t)
	hubAt := []string{fmt.Sprintf("127.0.0.1:%d", port)}
	waitFor(t, "the Rust member a hub", func() bool {
		_, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: hubAt, Consent: true}, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub on the Rust member: %v", err)
		}
		return err == nil
	})
	rustID := rust.status(t).Device
	if _, err := rust.do(t, control.Header{Op: control.OpInvite, Expires: 2 * 86400}, ""); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("an invitation for two days: %v", err)
	}
	// The hub's tunnel starts a moment after it became the hub.
	var inv *control.Client
	var m *control.Message
	waitFor(t, "an invitation on the Rust hub", func() bool {
		inv = rust.dial(t)
		inv.SetDeadline(time.Now().Add(90 * time.Second))
		var err error
		m, err = inv.Do(&control.Message{Header: control.Header{Op: control.OpInvite, Expires: 600}})
		if err != nil {
			inv.Close()
			if !strings.Contains(err.Error(), "not running") {
				t.Fatalf("invite on the Rust hub: %v", err)
			}
		}
		return err == nil
	})
	defer inv.Close()
	if m.Expires != 600 || m.Done {
		t.Fatalf("the invitation's answer: %+v", m)
	}
	in, err := invite.Parse(m.Invite)
	if err != nil {
		t.Fatal(err)
	}
	if in.Hub != rustID || len(in.Secret) != 16 || len(in.Endpoints) != 1 || in.Endpoints[0].Port() != uint16(port) {
		t.Errorf("the Rust hub's invitation %+v", in)
	}

	// A stranger the admin does not confirm stays out.
	stranger := startService(t, &h, "stranger")
	s := stranger.dial(t)
	defer s.Close()
	s.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := s.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: m.Invite, Consent: true}}); err != nil {
		t.Fatal(err)
	}
	if ask, err := inv.Receive(); err != nil || ask.Joining == nil || ask.Joining.Name != "stranger" || ask.Done {
		t.Fatalf("the Rust hub asked %+v, %v", ask, err)
	}
	if err := inv.Send(&control.Message{Header: control.Header{Op: control.OpAnswer}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Receive(); err == nil || !strings.Contains(err.Error(), "did not confirm") {
		t.Errorf("the declined join ended with %v", err)
	}

	// The deck, which the admin confirms, joins.
	deck := startService(t, &h, "deck")
	j := deck.dial(t)
	defer j.Close()
	j.SetDeadline(time.Now().Add(60 * time.Second))
	fp, err := j.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: m.Invite, Consent: true}})
	if err != nil || fp.Fingerprint == "" {
		t.Fatalf("join: %+v, %v", fp, err)
	}
	ask, err := inv.Receive()
	if err != nil || ask.Joining == nil {
		t.Fatalf("the Rust hub asked %+v, %v", ask, err)
	}
	if ask.Joining.Name != "deck" || ask.Joining.Fingerprint != fp.Fingerprint {
		t.Errorf("the Rust hub asks about %+v, the deck shows %s", ask.Joining, fp.Fingerprint)
	}
	if err := inv.Send(&control.Message{Header: control.Header{Op: control.OpAnswer, Consent: true}}); err != nil {
		t.Fatal(err)
	}
	if m, err := inv.Receive(); err != nil || !m.Done || m.Name != "deck" {
		t.Fatalf("the invitation ended with %+v, %v", m, err)
	}
	if m, err := j.Receive(); err != nil || !m.Done {
		t.Fatalf("the join ended with %+v, %v", m, err)
	}
	waitUpTo(t, 30*time.Second, "the deck reaches the Rust hub through its own tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.HubDevice == rustID && st.Away.Through &&
			slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == rustID })
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from afar"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust hub has it", func() bool { return rust.paste(t) == "from afar" })
	waitFor(t, "the guest tunnel is gone", func() bool { return rust.logged("the hub cut off 1 client(s)") })
}

// TestLiteJoinInvite checks that the Rust member joins with a Go hub's
// remote invitation (cbb pair -invite): through the guest tunnel, once the
// admin confirmed it, and that its service then offers its own key through
// the guest tunnel and reaches the hub through the tunnel with it.
func TestLiteJoinInvite(t *testing.T) {
	bin := liteBin(t)
	var h hub
	pi := startService(t, &h, "pi")
	inv, text := inviteHub(t, &h, pi)
	piID := pi.status(t).Device

	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "cbb.cbbinvite")
	if err := os.WriteFile(file, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-invite", file)
	join.Stdin = strings.NewReader("yes\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := join.Output()
		done <- result{out, err}
	}()
	ask, err := inv.Receive()
	if err != nil || ask.Joining == nil || ask.Joining.Name != "rust" {
		t.Fatalf("the hub asked %+v, %v", ask, err)
	}
	if err := inv.Send(&control.Message{Header: control.Header{Op: control.OpAnswer, Consent: true}}); err != nil {
		t.Fatal(err)
	}
	if m, err := inv.Receive(); err != nil || !m.Done || m.Name != "rust" {
		t.Fatalf("the invitation ended with %+v, %v", m, err)
	}
	r := <-done
	if r.err != nil || !strings.Contains(string(r.out), "Joined the group") || !strings.Contains(string(r.out), ask.Joining.Fingerprint[:23]) {
		t.Fatalf("cbb pair -invite: %v; %s", r.err, r.out)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the used invitation's file is still there: %v", err)
	}

	rust := startLite(t, bin, dir, "-no-mdns")
	waitUpTo(t, 60*time.Second, "the Rust member reaches the hub through its own tunnel", func() bool {
		st := rust.status(t)
		return st.Away != nil && st.Away.HubDevice == piID && st.Away.Through &&
			slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == piID })
	})
	if !rust.logged("the invitation's guest tunnel is closed") {
		t.Error("the Rust member did not offer its key through the guest tunnel")
	}
	if _, err := os.Stat(filepath.Join(dir, "invite-guest")); !os.IsNotExist(err) {
		t.Errorf("the guest file is still there: %v", err)
	}
}
