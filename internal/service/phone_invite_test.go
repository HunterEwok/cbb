// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/invite"
	"github.com/HunterEwok/cbb/internal/phone"
)

// phoneCall asks phone-on-linux's member (cbb_member_call) and returns the
// answer's ok, failing the test on an error.
func phoneCall(t *testing.T, next func(string) string, in io.Writer) func(op string, args any) map[string]any {
	return func(op string, args any) map[string]any {
		t.Helper()
		req, err := json.Marshal(map[string]any{"op": op, "args": args})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(in, "CALL %s\n", req)
		var ans struct {
			OK    map[string]any `json:"ok"`
			Error map[string]any `json:"error"`
		}
		if err := json.Unmarshal([]byte(next("ANSWER ")), &ans); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if ans.Error != nil {
			t.Fatalf("%s: %v", op, ans.Error)
		}
		return ans.OK
	}
}

// TestFFIJoinInvite runs a phone's app (phone-on-linux, built with the
// features member and tunnel) that joins by a remote invitation: it dials
// the invitation's guest tunnel, the hub's admin admits it by the
// fingerprint it shows, and its member then offers its own tunnel key to
// the hub through the guest tunnel, keeps the hub's offer and syncs from
// afar.
func TestFFIJoinInvite(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	inv, text := inviteHub(t, &h, pi)
	piID := pi.status(t).Device

	next, in := phoneOnLinux(t, bin, "-name", "phone", "-dir", t.TempDir(), "-invite", text)
	fp := next("Fingerprint ")
	ask, err := inv.Receive()
	if err != nil || ask.Joining == nil || ask.Joining.Name != "phone" || ask.Joining.Fingerprint != fp {
		t.Fatalf("the hub asked %+v, %v; the phone shows %s", ask, err, fp)
	}
	if err := inv.Send(&control.Message{Header: control.Header{Op: control.OpAnswer, Consent: true}}); err != nil {
		t.Fatal(err)
	}
	if m, err := inv.Receive(); err != nil || !m.Done || m.Name != "phone" {
		t.Fatalf("the invitation ended with %+v, %v", m, err)
	}
	if joined := next("Joined "); !strings.HasSuffix(joined, " "+pi.status(t).Group) {
		t.Fatalf("the phone joined %q, not the group %s", joined, pi.status(t).Group)
	}

	call := phoneCall(t, next, in)
	waitUpTo(t, 60*time.Second, "the phone keeps the hub's offer and reaches it", func() bool {
		a, _ := call("away_status", nil)["away"].(map[string]any)
		return a != nil && a["hub_device"] == piID && len(call("peers", nil)["peers"].([]any)) == 1
	})
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the invited phone"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the phone has it", func() bool {
		c, _ := call("current", nil)["copy"].(map[string]any)
		return c != nil && c["text"] == "to the invited phone"
	})
}

// TestFFIInviteThroughHub runs an admin phone's app (phone-on-linux) that
// makes a remote invitation: the computer that holds the group's root is
// its hub, so the guest tunnel opens there, and the phone's window admits
// a computer from another network once the user confirms the fingerprint
// it shows.
func TestFFIInviteThroughHub(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device

	// The phone joins at home as an admin.
	next, in := phoneOnLinux(t, bin, "-name", "phone", "-admin", "-dir", t.TempDir(), "-peer", pi.addr())
	jc, ok := phone.ParseJoinQR(next("QR: "))
	if !ok {
		t.Fatal("not a join QR code")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint, Admins: true}, ""); err != nil {
		t.Fatalf("admitting the phone: %v", err)
	}
	if ca := next("Admin CA "); ca == "" {
		t.Fatal("the phone is not an admin")
	}
	next("Joined ")
	call := phoneCall(t, next, in)
	waitFor(t, "the phone connected", func() bool { return len(call("peers", nil)["peers"].([]any)) == 1 })

	var text string
	waitUpTo(t, 60*time.Second, "an invitation through the pi", func() bool {
		fmt.Fprintln(in, "INVITE 600")
		got := next("INVITE ")
		if msg, failed := strings.CutPrefix(got, "FAILED "); failed {
			if !strings.Contains(msg, "hub") {
				t.Fatalf("the phone's invitation: %s", msg)
			}
			return false
		}
		text = got
		return true
	})
	in2, err := invite.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if in2.Hub != piID || in2.Endpoints[0].Port() != uint16(port) {
		t.Errorf("the phone's invitation: %+v", in2)
	}

	j := deck.dial(t)
	defer j.Close()
	j.SetDeadline(time.Now().Add(90 * time.Second))
	fp, err := j.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Invite: text, Consent: true}})
	if err != nil || fp.Fingerprint == "" {
		t.Fatalf("join: %+v, %v", fp, err)
	}
	if asked := next("INVITE JOINING "); asked != "deck "+fp.Fingerprint {
		t.Fatalf("the phone asked about %q; the deck shows %s", asked, fp.Fingerprint)
	}
	fmt.Fprintln(in, "INVITE ANSWER yes")
	if done := next("INVITE DONE "); done != "deck" {
		t.Fatalf("the invitation ended with %q", done)
	}
	if m, err := j.Receive(); err != nil || !m.Done {
		t.Fatalf("the join ended with %+v, %v", m, err)
	}
	if st := deck.status(t); st.Group != pi.status(t).Group {
		t.Fatalf("the deck is in group %q", st.Group)
	}
	waitUpTo(t, 60*time.Second, "the deck reaches the pi", func() bool {
		for _, p := range deck.status(t).Peers {
			if p.ID == piID {
				return true
			}
		}
		return false
	})
}
