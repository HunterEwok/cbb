// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/invite"
)

// inviteHub makes the pi a group's hub on the loopback address, on
// another network than the other test services, and opens an invitation
// there.
func inviteHub(t *testing.T, h *hub, pi *testService) (inv *control.Client, text string) {
	t.Helper()
	makeHub(t, h, pi)
	inv = pi.dial(t)
	t.Cleanup(func() { inv.Close() })
	inv.SetDeadline(time.Now().Add(60 * time.Second))
	m, err := inv.Do(&control.Message{Header: control.Header{Op: control.OpInvite, Expires: 600}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Expires != 600 {
		t.Errorf("the invitation is valid for %d s, want 600", m.Expires)
	}
	return inv, m.Invite
}

// makeHub makes the pi a group's hub on the loopback address, on another
// network than the other test services.
func makeHub(t *testing.T, h *hub, pi *testService) {
	t.Helper()
	c, _ := openWindow(t, pi) // creates the group
	c.Close()
	if _, err := pi.do(t, control.Header{Op: control.OpInvite}, ""); err == nil || !strings.Contains(err.Error(), "hub") {
		t.Errorf("an invitation from a member that is not the hub: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	h.hide(pi.status(t).Device)
}

// TestInviteApp runs cbb invite -app as the desktop apps do: cbb writes
// the invitation's state into the app's file, a device on another network
// uses it, and the user's answer in the answers file admits it.
func TestInviteApp(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	makeHub(t, &h, pi)
	dir := t.TempDir()
	state, answers := filepath.Join(dir, "invite.json"), filepath.Join(dir, "answers")
	for _, f := range []string{state, answers} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(rustService(), "-state", pi.dir, "-socket", pi.socket, "invite", "-for", "10m", "-app", state, "-answers", answers)
	out := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })
	type appState struct {
		Invite  string `json:"invite"`
		Expires int64  `json:"expires"`
		Joining *struct {
			Name        string `json:"name"`
			Fingerprint string `json:"fingerprint"`
		} `json:"joining"`
		Done bool   `json:"done"`
		Name string `json:"name"`
	}
	read := func() appState {
		var a appState
		data, _ := os.ReadFile(state)
		json.Unmarshal(data, &a)
		return a
	}
	waitUpTo(t, 60*time.Second, "cbb writes the invitation", func() bool { return read().Invite != "" })
	if a := read(); a.Expires != 600 {
		t.Errorf("the invitation is valid for %d s, want 600", a.Expires)
	}

	j := deck.dial(t)
	defer j.Close()
	j.SetDeadline(time.Now().Add(90 * time.Second))
	m, err := j.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: read().Invite, Consent: true}})
	if err != nil || m.Fingerprint == "" {
		t.Fatalf("join: %+v, %v", m, err)
	}
	waitUpTo(t, 60*time.Second, "cbb asks about the deck", func() bool { return read().Joining != nil })
	if a := read(); a.Joining.Name != "deck" || a.Joining.Fingerprint != m.Fingerprint {
		t.Fatalf("cbb asks about %+v; the deck shows %s", a.Joining, m.Fingerprint)
	}
	if err := os.WriteFile(answers, []byte("yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ended:
		if err != nil {
			t.Fatalf("cbb invite -app: %v\n%s", err, out)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("cbb invite -app did not end\n%s", out)
	}
	if a := read(); !a.Done || a.Name != "deck" {
		t.Errorf("cbb wrote %+v at the end", a)
	}
	if m, err := j.Receive(); err != nil || !m.Done {
		t.Fatalf("the join ended with %+v, %v", m, err)
	}
}

// TestInvite checks a remote invitation from end to end: a device on
// another network joins through the hub's guest tunnel once the admin
// confirms the device it shows, then reaches the hub through the tunnel
// with its own key and syncs.
func TestInvite(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	inv, text := inviteHub(t, &h, pi)
	in, err := invite.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if in.Hub != pi.status(t).Device || len(in.Secret) != 16 {
		t.Errorf("the invitation %+v", in)
	}

	if _, err := deck.do(t, control.Header{Op: control.OpJoin, Invite: text}, ""); err == nil || !strings.Contains(err.Error(), "consent") {
		t.Errorf("a join with an invitation without consent: %v", err)
	}
	j := deck.dial(t)
	defer j.Close()
	j.SetDeadline(time.Now().Add(60 * time.Second))
	m, err := j.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: text, Consent: true}})
	if err != nil || m.Fingerprint == "" {
		t.Fatalf("join: %+v, %v", m, err)
	}
	ask, err := inv.Receive()
	if err != nil || ask.Joining == nil {
		t.Fatalf("the hub asked %+v, %v", ask, err)
	}
	if ask.Joining.Name != "deck" || ask.Joining.Fingerprint != m.Fingerprint {
		t.Errorf("the hub asks about %+v, the deck shows %s", ask.Joining, m.Fingerprint)
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

	piID := pi.status(t).Device
	waitUpTo(t, 30*time.Second, "the deck reaches the hub through its own tunnel", func() bool {
		st := deck.status(t)
		return st.Away != nil && st.Away.HubDevice == piID && st.Away.Through && len(st.Peers) == 1
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from afar"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from afar" })
	if st := deck.status(t); st.Group != pi.status(t).Group {
		t.Errorf("the deck is in group %q", st.Group)
	}

	// The invitation is used up: its guest tunnel went once the deck had
	// its own, so a copy of it does not even reach the hub.
	other := startService(t, &h, "other")
	o := other.dial(t)
	defer o.Close()
	o.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := o.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: text, Consent: true}}); err != nil {
		t.Fatal(err) // the fingerprint, before it tries
	}
	if _, err := o.Receive(); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("a used invitation: %v, want the hub not answering", err)
	}
	if st := other.status(t); st.Group != "" {
		t.Errorf("another device joined with a used invitation: %+v", st)
	}
}

// TestInviteDeclined checks that a device the admin does not confirm
// stays out, and that the invitation then still serves the right one.
func TestInviteDeclined(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	stranger := startService(t, &h, "stranger")
	inv, text := inviteHub(t, &h, pi)

	j := stranger.dial(t)
	defer j.Close()
	j.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := j.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: text, Consent: true}}); err != nil {
		t.Fatal(err)
	}
	if ask, err := inv.Receive(); err != nil || ask.Joining == nil {
		t.Fatalf("the hub asked %+v, %v", ask, err)
	}
	if err := inv.Send(&control.Message{Header: control.Header{Op: control.OpAnswer}}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Receive(); err == nil || !strings.Contains(err.Error(), "did not confirm") {
		t.Errorf("the declined join ended with %v", err)
	}
	if st := stranger.status(t); st.Group != "" {
		t.Errorf("a declined device is in group %q", st.Group)
	}
}

// TestInviteThroughHub checks a remote invitation that an admin which is
// not the hub makes through the hub (docs/protocol.md, section 12, "Through
// the hub"): the hub lets the admin's guest in and passes the pairing to
// the admin, which confirms the device and admits it, and the device then
// syncs with the group.
func TestInviteThroughHub(t *testing.T) {
	cli := cbbCLI(t)
	var h hub
	pi := startService(t, &h, "pi")
	desk := startService(t, &h, "desk")
	deck := startService(t, &h, "deck")
	c, code := openWindow(t, pi)
	if _, err := desk.do(t, control.Header{Op: control.OpJoin, Code: code, Address: pi.addr()}, ""); err != nil {
		t.Fatalf("the desk joins: %v", err)
	}
	if m, err := c.Receive(); err != nil || m.Name != "desk" {
		t.Fatalf("pair on the pi ended with %+v, %v", m, err)
	}
	c.Close()
	piID := pi.status(t).Device

	// Not an admin yet, and with no hub.
	if _, err := desk.do(t, control.Header{Op: control.OpInvite}, ""); err == nil {
		t.Error("an invitation from a member that is no admin")
	}
	adminOn(t, cli, pi, "desk")
	waitFor(t, "the desk an admin, in a group with no hub", func() bool {
		_, err := desk.do(t, control.Header{Op: control.OpInvite}, "")
		if err == nil {
			t.Fatal("an invitation in a group with no hub")
		}
		return strings.Contains(err.Error(), "no hub")
	})
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}

	var inv *control.Client
	var m *control.Message
	waitFor(t, "an invitation through the pi", func() bool {
		inv = desk.dial(t)
		inv.SetDeadline(time.Now().Add(90 * time.Second))
		var err error
		m, err = inv.Do(&control.Message{Header: control.Header{Op: control.OpInvite, Expires: 600}})
		if err != nil {
			inv.Close()
			if !strings.Contains(err.Error(), "hub") && !strings.Contains(err.Error(), "not running") {
				t.Fatalf("invite on the desk: %v", err)
			}
		}
		return err == nil
	})
	defer inv.Close()
	in, err := invite.Parse(m.Invite)
	if err != nil {
		t.Fatal(err)
	}
	if in.Hub != piID || len(in.Endpoints) != 1 || in.Endpoints[0].Port() != uint16(port) {
		t.Errorf("the invitation through the pi: %+v", in)
	}
	if !pi.logged("is open through this hub") {
		t.Error("the pi did not log the invitation it carries")
	}

	j := deck.dial(t)
	defer j.Close()
	j.SetDeadline(time.Now().Add(90 * time.Second))
	fp, err := j.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: m.Invite, Consent: true}})
	if err != nil || fp.Fingerprint == "" {
		t.Fatalf("join: %+v, %v", fp, err)
	}
	ask, err := inv.Receive()
	if err != nil || ask.Joining == nil || ask.Joining.Name != "deck" || ask.Joining.Fingerprint != fp.Fingerprint {
		t.Fatalf("the desk asked %+v, %v; the deck shows %s", ask, err, fp.Fingerprint)
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
	if st := deck.status(t); st.Group != pi.status(t).Group {
		t.Fatalf("the deck is in group %q", st.Group)
	}
	waitUpTo(t, 60*time.Second, "the deck reaches the pi", func() bool {
		return slices.ContainsFunc(deck.status(t).Peers, func(p control.Device) bool { return p.ID == piID })
	})
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "from afar"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the desk has it", func() bool { return desk.paste(t) == "from afar" })
}
