// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFFIPhoneYubiKey: on a group of 0.6 a phone whose app has no PIV of its
// own seals the recovery sheet's secret onto a YubiKey through the core
// (cbb_piv's seal, into the first empty retired slot, its certificate
// naming the group), as the root phone does when the group is made; once
// the root is lost, the phone opens the group's slot with its PIN
// (cbb_piv's open) and changes the root with the secret it gave
// (docs/protocol.md, "The recovery key on a YubiKey (0.6)"), over NFC or
// over the CCID interface of a YubiKey on USB-C.
func TestFFIPhoneYubiKey(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	var h hub
	// No pcscd here: the transport pcsc must reach for it and say so.
	t.Setenv("PCSCLITE_CSOCK_NAME", filepath.Join(t.TempDir(), "no-pcscd"))
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	card := filepath.Join(t.TempDir(), "card.json")
	next, in, _ := phoneJoins(t, bin, pi, "-name", "aurora", "-dir", t.TempDir(), "-peer", a.addr(), "-card", card)
	waitFor(t, "a lists the phone", func() bool { return strings.Contains(listed(a.devices(t)), "aurora") })
	piv := func(req map[string]any) string {
		t.Helper()
		b, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(in, "PIV "+string(b))
		return next("PIV ")
	}
	qr := map[string]any{"qr": sheet}
	// The group's tag, as the app names its group: the first 16 hex
	// digits of its ID; the core takes the whole ID too.
	const group = "0123456789abcdef00112233"

	if got := piv(map[string]any{"op": "seal", "pin": "000000", "recovery": qr, "group": group}); !strings.Contains(got, "PIN") {
		t.Fatalf("a wrong PIN: %s", got)
	}
	if got := piv(map[string]any{"op": "seal", "pin": "123456", "recovery": qr}); !strings.Contains(got, "names no group") {
		t.Fatalf("sealing for no group: %s", got)
	}
	if got := piv(map[string]any{"op": "seal", "pin": "123456", "recovery": map[string]any{"text": "a typo"}, "group": group}); !strings.Contains(got, "error") {
		t.Fatalf("sealing what is no sheet: %s", got)
	}
	if got := piv(map[string]any{"op": "open", "pin": "123456", "group": group}); !strings.Contains(got, "no recovery key") {
		t.Fatalf("opening a card that holds nothing: %s", got)
	}
	got := piv(map[string]any{"op": "seal", "pin": "123456", "recovery": qr, "group": group})
	if !strings.Contains(got, `"slot":149`) || !strings.Contains(got, `"default_key":true`) {
		t.Fatalf("sealing: %s", got)
	}
	if got := piv(map[string]any{"op": "seal", "pin": "123456", "recovery": qr, "group": group}); !strings.Contains(got, "already holds") {
		t.Fatalf("sealing a card that holds the group's already: %s", got)
	}

	pi.stop()
	if got := piv(map[string]any{"op": "open", "pin": "123456", "group": "fedcba9876543210"}); !strings.Contains(got, "no recovery key") {
		t.Fatalf("opening another group's: %s", got)
	}
	if got := piv(map[string]any{"op": "open", "pin": "000000", "group": group}); !strings.Contains(got, "PIN") {
		t.Fatalf("opening with a wrong PIN: %s", got)
	}
	var opened struct {
		OK struct {
			Secret string `json:"secret"`
		} `json:"ok"`
	}
	got = piv(map[string]any{"op": "open", "pin": "123456", "group": group})
	if err := json.Unmarshal([]byte(got), &opened); err != nil || opened.OK.Secret == "" {
		t.Fatalf("opening: %s", got)
	}
	// A YubiKey on USB-C: the app moves the bytes of its CCID interface
	// and the core frames them, through a time extension for the touch.
	if got := piv(map[string]any{"op": "open", "pin": "123456", "group": group, "transport": "ccid_bulk"}); !strings.Contains(got, opened.OK.Secret) {
		t.Fatalf("opening over CCID: %s", got)
	}
	if got := piv(map[string]any{"op": "open", "pin": "123456", "group": group, "transport": "lightning"}); !strings.Contains(got, "no YubiKey transport") {
		t.Errorf("a transport there is none of: %s", got)
	}
	// A phone whose system runs pcscd (Aurora OS): the core is the PC/SC
	// client, and the app's callback is not called.
	for _, op := range []string{"open", "seal"} {
		if got := piv(map[string]any{"op": op, "pin": "123456", "recovery": qr, "group": group, "transport": "pcsc"}); !strings.Contains(got, "needs pcscd") {
			t.Errorf("%s over pcsc without pcscd: %s", op, got)
		}
	}
	newRoot := func(req map[string]any) string {
		t.Helper()
		b, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(in, "NEWROOT "+string(b))
		return next("NEWROOTED ")
	}
	if got := newRoot(map[string]any{"action": "change_root", "recovery": map[string]any{"secret": "AAAA"}}); !strings.Contains(got, "32 bytes") {
		t.Errorf("a secret of the wrong length: %s", got)
	}
	secret := map[string]any{"secret": opened.OK.Secret}
	if got := newRoot(map[string]any{"action": "change_root", "recovery": secret, "leave_out": []string{"pi"}}); !strings.Contains(got, `"seq"`) {
		t.Fatalf("changing the root with the card's secret: %s", got)
	}
	waitFor(t, "a follows the new root", rootIs(t, a, "aurora"))
	waitFor(t, "pi is out of the group", func() bool { return !strings.Contains(listed(a.devices(t)), "pi") })
}
