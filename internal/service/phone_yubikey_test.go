// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/group"
)

// TestFFIPhoneYubiKey: a root phone whose app has no PIV of its own puts
// the group's recovery key on a YubiKey through the core (cbb_piv: a key
// made in a retired slot, its admin CA stored there), and a new phone
// restores the group with that card alone and claims it, the card signing
// the claim (docs/protocol.md, section 10, "On a hardware key").
func TestFFIPhoneYubiKey(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	var h hub
	card := filepath.Join(t.TempDir(), "card.json")
	next, in, _, laptop, _, _ := rootPhoneWithLaptopArgs(t, &h, "-card", card)
	piv := func(req map[string]any) map[string]any {
		t.Helper()
		data, _ := json.Marshal(req)
		fmt.Fprintln(in, "PIV "+string(data))
		var m struct {
			OK    map[string]any `json:"ok"`
			Error map[string]any `json:"error"`
		}
		got := next("PIV ")
		if err := json.Unmarshal([]byte(got), &m); err != nil || m.OK == nil {
			t.Fatalf("PIV %v: %s", req["op"], got)
		}
		return m.OK
	}
	manage := func(req string) map[string]any {
		t.Helper()
		fmt.Fprintln(in, "MANAGE "+req)
		got := next("MANAGED ")
		var m struct {
			OK map[string]any `json:"ok"`
		}
		if err := json.Unmarshal([]byte(got), &m); err != nil || m.OK == nil {
			t.Fatalf("MANAGE %s: %s", req, got)
		}
		return m.OK
	}

	// A wrong PIN makes nothing.
	fmt.Fprintln(in, `PIV {"op":"make","pin":"000000"}`)
	if got := next("PIV "); !strings.Contains(got, "error") {
		t.Fatalf("a wrong PIN made a key: %s", got)
	}
	made := piv(map[string]any{"op": "make", "pin": "123456"})
	slot, _ := made["slot"].(float64)
	if slot < 0x82 || slot > 0x95 {
		t.Fatalf("the key is not in a retired slot: %v", made)
	}
	ca := manage(`{"action":"recovery_for","key":"` + made["key"].(string) + `"}`)["admin_ca"].(string)
	piv(map[string]any{"op": "put", "slot": slot, "cert": ca})
	manage(`{"action":"takeover_delay","delay_ms":0}`)
	waitFor(t, "the laptop holds the recovery key's record and no delay", func() bool {
		id, err := group.Load(laptop.dir)
		if err != nil {
			return false
		}
		recs, err := group.LoadRecords(laptop.dir, id.GroupCA.Cert)
		return err == nil && recs.State().Recovery != nil && holdsNoWait(laptop.dir)
	})

	// The root phone is lost; a new phone has only the YubiKey.
	in.(io.Closer).Close()
	der, _ := base64.StdEncoding.DecodeString(ca)
	adminCA, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := adminCA.PublicKey.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := phoneOnLinux(t, bin, "-keys", "1", "-card", card, "-restore-card", "000000", "-peer", laptop.addr()); !strings.Contains(got("RESTORE FAILED "), "PIN") {
		t.Error("restored with a wrong PIN")
	}
	next, in = phoneOnLinux(t, bin, "-keys", "1", "-name", "new phone", "-card", card, "-restore-card", "123456",
		"-dir", t.TempDir(), "-peer", laptop.addr())
	next("Restored ")
	root, _ := manage(`{"action":"root_ca"}`)["root_ca"].(string)
	if root == "" {
		t.Fatal("no root CA")
	}
	wrong, _ := json.Marshal(map[string]any{"action": "recover", "root_ca": root, "admin_ca": ca, "slot": slot,
		"pin": "000000", "public": base64.StdEncoding.EncodeToString(pub.Bytes())})
	fmt.Fprintln(in, "MANAGE_CARD "+string(wrong))
	if got := next("MANAGED "); !strings.Contains(got, "PIN") {
		t.Fatalf("a claim with a wrong PIN: %s", got)
	}
	claim, _ := json.Marshal(map[string]any{"action": "recover", "root_ca": root, "admin_ca": ca, "slot": slot,
		"pin": "123456", "public": base64.StdEncoding.EncodeToString(pub.Bytes())})
	fmt.Fprintln(in, "MANAGE_CARD "+string(claim))
	if got := next("MANAGED "); got != `{"ok":{}}` {
		t.Fatalf("the claim signed by the card: %s", got)
	}
	waitFor(t, "the claim takes effect", func() bool {
		return manage(`{"action":"finish_takeover","root_ca":"` + root + `","name":"new phone","os":"aurora"}`)["state"] == "effective"
	})
	waitFor(t, "the laptop lists the new phone as the root", func() bool {
		for _, d := range laptop.devices(t) {
			if d.Name == "new phone" {
				return d.Root && d.Role == group.RolePhone
			}
		}
		return false
	})
}
