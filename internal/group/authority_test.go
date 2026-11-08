// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"testing"
	"time"
)

// TestGoAuthorityVectors checks that a device is an admin, and an admin has
// its role, store and powers, only by a record a root's own key signed, and
// that a removed admin's later records no longer decide a device's entry:
// the cases of testdata/interop/v2-records.json for it through a Records
// set.
func TestGoAuthorityVectors(t *testing.T) {
	checkV2Cases(t, "basic", "powers", "removed admin's device", "ignored records")
}

// A command signed by a computer's admin CA has the role and store the
// root's record gives that computer, whatever record the admin signed for
// itself.
func TestCommandSignerByRoot(t *testing.T) {
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	pc := pg.a
	pcKey := KeyHashOf(pc.Cert)
	pcMember := member(t, pc)
	s := NewRecords(g)
	mustAdd(t, s, computerAdminRecord(t, pg, pcMember, "pc", pcKey))
	fake := KeyHash{1, 2, 3}
	self, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: nextTime(), Device: string(NewDeviceID()), Name: "0",
		Role: RolePhone, OS: OSiOS, Key: &fake, Admin: &pcKey, Store: StoreHardware}, pc.Key, pc.Cert)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, s, self)
	now := time.Now()
	cmd, err := SignCommand(CommandBody{Type: CommandAction, Group: Tag(g), By: DeviceID(pcMember.Subject.CommonName), To: NewDeviceID(),
		ID: NewCommandID(), TimeMS: now.UnixMilli(), ExpiresMS: now.Add(20 * time.Second).UnixMilli(), Action: "reboot"}, pc.Key, pc.Cert)
	if err != nil {
		t.Fatal(err)
	}
	dev, root, ok := s.CommandSigner(cmd)
	if !ok || root || dev.ID != DeviceID(pcMember.Subject.CommonName) || dev.Role != RoleMember || dev.Store != StoreFile {
		t.Fatalf("the signer: ok %v, root %v, %+v", ok, root, dev)
	}
}
