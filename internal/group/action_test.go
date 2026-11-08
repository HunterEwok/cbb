// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
)

func TestValidActionName(t *testing.T) {
	for name, ok := range map[string]bool{
		"reboot": true, "cancel-shutdown": true, "backup2": true, "a": true,
		"": false, "Reboot": false, "2fa": false, "-x": false, "rm -rf": false, "ä": false,
		"abcdefghijklmnopqrstuvwxyz012345": true, "abcdefghijklmnopqrstuvwxyz0123456": false,
	} {
		if ValidActionName(name) != ok {
			t.Errorf("ValidActionName(%q) = %v", name, !ok)
		}
	}
}

func TestActionCommand(t *testing.T) {
	pg := newPhoneGroup(t)
	to, now := NewDeviceID(), time.UnixMilli(1_761_400_000_000)
	body := func(typ, action string) CommandBody {
		return CommandBody{Type: typ, Group: Tag(pg.root.Cert), By: NewDeviceID(), To: to, ID: NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli(), Action: action}
	}
	s := NewRecords(pg.root.Cert)
	unlisted, err := SignCommand(body(CommandAction, "reboot"), pg.a.Key, pg.a.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyCommand(unlisted, to, now); err == nil {
		t.Error("a command from an admin whose device has no record here was taken")
	}
	// An admin gives commands once the records list its device.
	aM := member(t, pg.a)
	if _, err := s.Add(adminRecord(t, pg.root.Cert, pg.root, nil, aM, "phone a", KeyHashOf(pg.a.Cert))); err != nil {
		t.Fatal(err)
	}
	listed := body(CommandAction, "reboot")
	listed.By = DeviceID(aM.Subject.CommonName)
	c, err := SignCommand(listed, pg.a.Key, pg.a.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.VerifyCommand(c, to, now); err != nil || got.Action != "reboot" {
		t.Errorf("the action command: %+v, %v", got, err)
	}
	if d, root, ok := s.CommandSigner(c); root || !ok || d.ID != listed.By {
		t.Errorf("a listed admin: %+v, root %v, found %v", d, root, ok)
	}
	withMode := body(CommandAction, "lock")
	withMode.Mode = "own"
	withText := body(CommandAction, "lock")
	withText.Text = "x"
	for what, b := range map[string]CommandBody{
		"no name":               body(CommandAction, ""),
		"a bad name":            body(CommandAction, "rm -rf /"),
		"with a mode":           withMode,
		"with a text":           withText,
		"a name on paste-off":   body(CommandPasteOff, "lock"),
		"a name on actions-off": body(CommandActionsOff, "lock"),
	} {
		if _, err := SignCommand(b, pg.root.Key); err == nil {
			t.Errorf("%s: signed", what)
		}
	}
	if _, err := SignCommand(body(CommandActionsOff, ""), pg.root.Key); err != nil {
		t.Errorf("actions-off: %v", err)
	}
}

type actionSigner struct {
	Root  bool   `json:"root,omitempty"`
	Role  string `json:"role,omitempty"`
	Store string `json:"store,omitempty"`
	Found bool   `json:"found,omitempty"`
}

type actionVector struct {
	Name    string       `json:"name"`
	Command Record       `json:"command"`
	OK      bool         `json:"ok"`
	Action  string       `json:"action,omitempty"`
	Signer  actionSigner `json:"signer"`
}

type actionVectors struct {
	GroupCA  []byte         `json:"group_ca"`
	Records  []Record       `json:"records"`
	Self     DeviceID       `json:"self"`
	NowMS    int64          `json:"now_ms"`
	Commands []actionVector `json:"commands"`
}

// TestGoActionVectors checks action and actions-off commands for a lite
// member, signed by the root phone, an admin phone, an admin computer with
// its keys in a file and one with them in a TPM, and which device each
// signer is (docs/protocol.md, section 15), in records v:2.
func TestGoActionVectors(t *testing.T) {
	var v actionVectors
	{
		pg := newPhoneGroup(t)
		g := pg.root.Cert
		phone, pc, tpm := pg.a, pg.b, adminCA(t, pg.root)
		rootPhone, self := member(t, pg.root), member(t, pg.root)
		selfID, rootID := DeviceID(self.Subject.CommonName), DeviceID(rootPhone.Subject.CommonName)
		rootKey, selfKey := KeyHashOf(rootPhone), KeyHashOf(self)
		own, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 1, Device: string(rootID), Name: "root phone", Role: RolePhone, OS: OSiOS, Key: &rootKey, HoldsRoot: true}, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		lite, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 2, Device: string(selfID), Name: "pi", Role: RoleMember, Caps: []string{CapDials}, OS: OSLinux, Key: &selfKey}, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		tpmMember := member(t, tpm)
		tpmKey, tpmAdmin := KeyHashOf(tpmMember), KeyHashOf(tpm.Cert)
		tpmRecord, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(g), TimeMS: 3, Device: string(DeviceID(tpmMember.Subject.CommonName)), Name: "tpm pc", Role: RoleMember, Caps: AllCaps, OS: OSLinux, Key: &tpmKey,
			Admin: &tpmAdmin, Store: StoreHardware, Powers: computerPowers(false), Commands: authority.Commands}, pg.root.Key)
		if err != nil {
			t.Fatal(err)
		}
		phoneM, pcM := member(t, phone), member(t, pc)
		all := []Record{
			own, lite, tpmRecord,
			adminRecord(t, g, pg.root, nil, phoneM, "admin phone", KeyHashOf(phone.Cert)),
			computerAdminRecord(t, pg, pcM, "file pc", KeyHashOf(pc.Cert)),
		}
		// A command's by is its signer's device.
		byOf := map[*CA]DeviceID{pg.root: rootID, phone: DeviceID(phoneM.Subject.CommonName),
			pc: DeviceID(pcM.Subject.CommonName), tpm: DeviceID(tpmMember.Subject.CommonName)}
		now := int64(1_800_000_000_000)
		sign := func(signer *CA, chain []*x509.Certificate, typ, action string) Record {
			by := byOf[signer]
			if by == "" {
				by = selfID // a key of no device here
			}
			r, err := SignCommand(CommandBody{Type: typ, Group: Tag(g), By: by, To: selfID, ID: NewCommandID(),
				TimeMS: now, ExpiresMS: now + CommandLifetime.Milliseconds(), Action: action}, signer.Key, chain...)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		v = actionVectors{GroupCA: g.Raw, Records: all, Self: selfID, NowMS: now, Commands: []actionVector{
			{Name: "reboot by the root phone", Command: sign(pg.root, nil, CommandAction, "reboot"), OK: true, Action: "reboot",
				Signer: actionSigner{Root: true, Role: RolePhone, Store: StoreHardware, Found: true}},
			{Name: "lock by the admin phone", Command: sign(phone, []*x509.Certificate{phone.Cert}, CommandAction, "lock"), OK: true, Action: "lock",
				Signer: actionSigner{Role: RolePhone, Store: StoreHardware, Found: true}},
			{Name: "reboot by an admin computer with its keys in a file", Command: sign(pc, []*x509.Certificate{pc.Cert}, CommandAction, "reboot"), OK: true, Action: "reboot",
				Signer: actionSigner{Role: RoleMember, Store: StoreFile, Found: true}},
			{Name: "shutdown by an admin computer with its keys in a TPM", Command: sign(tpm, []*x509.Certificate{tpm.Cert}, CommandAction, "shutdown"), OK: true, Action: "shutdown",
				Signer: actionSigner{Role: RoleMember, Store: StoreHardware, Found: true}},
			{Name: "actions-off by an admin computer", Command: sign(pc, []*x509.Certificate{pc.Cert}, CommandActionsOff, ""), OK: true,
				Signer: actionSigner{Role: RoleMember, Store: StoreFile, Found: true}},
			{Name: "a key of another group", Command: sign(newRoot(t), nil, CommandAction, "reboot")},
		}}
	}
	writeV2Vectors(t, "v2-actions.json", v)
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	if _, errs := s.AddAll(v.Records); len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(v.Commands) != 6 {
		t.Fatalf("the file has %d commands", len(v.Commands))
	}
	for _, c := range v.Commands {
		body, err := s.VerifyCommand(c.Command, v.Self, time.UnixMilli(v.NowMS))
		if (err == nil) != c.OK || (c.OK && body.Action != c.Action) {
			t.Errorf("%s: %+v, %v", c.Name, body, err)
			continue
		}
		if !c.OK {
			continue
		}
		d, root, found := s.CommandSigner(c.Command)
		if got := (actionSigner{Root: root, Role: d.Role, Store: d.Store, Found: found}); got != c.Signer {
			t.Errorf("%s: the signer is %+v, want %+v", c.Name, got, c.Signer)
		}
	}
}
