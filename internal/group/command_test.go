// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestCommands(t *testing.T) {
	pg := newPhoneGroup(t)
	s := NewRecords(pg.root.Cert)
	to, now := NewDeviceID(), time.UnixMilli(1_761_400_000_000)
	body := func() CommandBody {
		return CommandBody{Type: CommandMode, Group: Tag(pg.root.Cert), By: NewDeviceID(), To: to, ID: NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli(), Mode: "own"}
	}
	sign := func(b CommandBody, ca *CA, chain ...*x509.Certificate) Record {
		t.Helper()
		c, err := SignCommand(b, ca.Key, chain...)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	check := func(what string, c Record, at time.Time, ok bool) {
		t.Helper()
		got, err := s.VerifyCommand(c, to, at)
		if (err == nil) != ok {
			t.Errorf("%s: %v, want ok %v", what, err, ok)
		}
		if err == nil && got.Mode != "own" {
			t.Errorf("%s: mode %q", what, got.Mode)
		}
	}
	check("an admin not yet listed", sign(body(), pg.a, pg.a.Cert), now, false)
	mustAdd(t, s, adminRecord(t, pg.root.Cert, pg.root, nil, member(t, pg.a), "phone a", KeyHashOf(pg.a.Cert)))
	mustAdd(t, s, adminRecord(t, pg.root.Cert, pg.root, nil, member(t, pg.b), "phone b", KeyHashOf(pg.b.Cert)))
	check("the root", sign(body(), pg.root), now, true)
	byA := sign(body(), pg.a, pg.a.Cert)
	check("an admin naming no device shown", byA, now, false)
	byOf := func(ca *CA) DeviceID {
		for _, d := range s.Devices() {
			if d.AdminKey != nil && *d.AdminKey == KeyHashOf(ca.Cert) {
				return d.ID
			}
		}
		return ""
	}
	bodyBy := func(ca *CA) CommandBody { b := body(); b.By = byOf(ca); return b }
	byA = sign(bodyBy(pg.a), pg.a, pg.a.Cert)
	check("an admin", byA, now, true)
	check("expired", byA, now.Add(CommandLifetime), false)
	check("from the future", byA, now.Add(-CommandAhead-time.Second), false)
	if _, err := s.VerifyCommand(byA, NewDeviceID(), now); err == nil {
		t.Error("a command for another device was taken")
	}
	other := newPhoneGroup(t)
	check("another group's admin", sign(body(), other.a, other.a.Cert), now, false)
	b := body()
	b.Group = Tag(other.root.Cert)
	check("for another group", sign(b, pg.root), now, false)
	forged := byA
	forged.Body = append([]byte(nil), byA.Body...)
	forged.Body[len(forged.Body)-3] = 'x' // "own" becomes "owx"
	check("a changed body", forged, now, false)

	removed := bodyBy(pg.a)
	mustAdd(t, s, revokeRecord(t, pg.root.Cert, pg.root, nil, []KeyHash{KeyHashOf(pg.a.Cert)}))
	removed.ID = NewCommandID()
	check("a removed admin", sign(removed, pg.a, pg.a.Cert), now, false)
	check("the other admin", sign(bodyBy(pg.b), pg.b, pg.b.Cert), now, true)

	if _, err := SignCommand(CommandBody{Type: CommandMode, To: to, ID: NewCommandID(), TimeMS: 1, ExpiresMS: 1 + time.Hour.Milliseconds(), Mode: "own"}, pg.root.Key); err == nil {
		t.Error("a command that lives an hour was signed")
	}
}

func TestHubCommand(t *testing.T) {
	pg := newPhoneGroup(t)
	s := NewRecords(pg.root.Cert)
	to, now := NewDeviceID(), time.UnixMilli(1_761_400_000_000)
	key := make([]byte, 32)
	order := func() *HubOrder {
		return &HubOrder{Forwarder: &HubForwarder{Endpoint: "203.0.113.9:8764", Key: "pin"},
			Clients: []HubClient{{Device: NewDeviceID(), Key: key, PSK: key}}}
	}
	body := func(o *HubOrder) CommandBody {
		return CommandBody{Type: CommandHub, Group: Tag(pg.root.Cert), By: NewDeviceID(), To: to, ID: NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli(), Hub: o}
	}
	c, err := SignCommand(body(order()), pg.root.Key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.VerifyCommand(c, to, now)
	if err != nil || got.Hub == nil || len(got.Hub.Clients) != 1 || got.Hub.Forwarder.Endpoint != "203.0.113.9:8764" {
		t.Fatalf("the hub command: %+v, %v", got.Hub, err)
	}
	// Many clients fit, since a hub command is no record that is stored.
	many := order()
	for len(many.Clients) < MaxHubClients {
		many.Clients = append(many.Clients, HubClient{Device: NewDeviceID(), Key: key, PSK: key})
	}
	if c, err := SignCommand(body(many), pg.root.Key); err != nil {
		t.Error(err)
	} else if _, err := s.VerifyCommand(c, to, now); err != nil {
		t.Errorf("%d clients: %v", len(many.Clients), err)
	}
	one := order().Clients
	for what, o := range map[string]*HubOrder{
		"no order":            nil,
		"nowhere to reach":    {Clients: order().Clients},
		"short keys":          {Endpoints: []string{"203.0.113.7:8764"}, Clients: []HubClient{{Device: NewDeviceID(), Key: key[:31], PSK: key}}},
		"a client twice":      {Endpoints: []string{"203.0.113.7:8764"}, Clients: append(one, one...)},
		"too many clients":    {Endpoints: []string{"203.0.113.7:8764"}, Clients: append(many.Clients, order().Clients...)},
		"a bad device":        {Endpoints: []string{"203.0.113.7:8764"}, Clients: []HubClient{{Device: "x", Key: key, PSK: key}}},
		"a forwarder w/o key": {Forwarder: &HubForwarder{Endpoint: "203.0.113.9:8764"}},
	} {
		if _, err := SignCommand(body(o), pg.root.Key); err == nil {
			t.Errorf("%s: signed", what)
		}
	}
	mixed := body(order())
	mixed.Mode = "own"
	if _, err := SignCommand(mixed, pg.root.Key); err == nil {
		t.Error("a hub command with a mode was signed")
	}
}

func TestPasteCommand(t *testing.T) {
	pg := newPhoneGroup(t)
	s := NewRecords(pg.root.Cert)
	to, now := NewDeviceID(), time.UnixMilli(1_761_400_000_000)
	body := func(mode, kind, text string) CommandBody {
		return CommandBody{Type: CommandPaste, Group: Tag(pg.root.Cert), By: NewDeviceID(), To: to, ID: NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli(), Mode: mode, Kind: kind, Text: text, Enter: true}
	}
	aM, bM := member(t, pg.a), member(t, pg.b)
	for _, r := range []Record{
		adminRecord(t, pg.root.Cert, pg.root, nil, aM, "phone a", KeyHashOf(pg.a.Cert)),
		adminRecord(t, pg.root.Cert, pg.root, nil, bM, "phone b", KeyHashOf(pg.b.Cert)),
	} {
		if _, err := s.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	byA := body(PasteByClipboard, "text", "ls -l")
	byA.By = DeviceID(aM.Subject.CommonName)
	c, err := SignCommand(byA, pg.a.Key, pg.a.Cert)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.VerifyCommand(c, to, now)
	if err != nil || got.Text != "ls -l" || !got.Enter || got.Mode != PasteByClipboard {
		t.Fatalf("the paste command: %+v, %v", got, err)
	}
	// A megabyte of text that JSON escapes still fits.
	big := strings.Repeat("<", MaxPasteText)
	if c, err := SignCommand(body(PasteByClipboard, "secret", big), pg.root.Key); err != nil {
		t.Errorf("a long paste: %v", err)
	} else if _, err := s.VerifyCommand(c, to, now); err != nil {
		t.Errorf("a long paste: %v", err)
	}
	for what, b := range map[string]CommandBody{
		"no text":        body(PasteByClipboard, "text", ""),
		"too long":       body(PasteByClipboard, "text", big+"x"),
		"too long typed": body(PasteByTyping, "text", strings.Repeat("a", MaxTypeText+1)),
		"another way":    body("drop", "text", "x"),
		"another kind":   body(PasteByTyping, "image", "x"),
	} {
		if _, err := SignCommand(b, pg.root.Key); err == nil {
			t.Errorf("%s: signed", what)
		}
	}
	mode := body(PasteByClipboard, "text", "x")
	mode.Type = CommandMode
	if _, err := SignCommand(mode, pg.root.Key); err == nil {
		t.Error("a mode command with a text was signed")
	}
	off := CommandBody{Type: CommandPasteOff, Group: Tag(pg.root.Cert), By: DeviceID(bM.Subject.CommonName), To: to, ID: NewCommandID(),
		TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli()}
	if c, err := SignCommand(off, pg.b.Key, pg.b.Cert); err != nil {
		t.Error(err)
	} else if got, err := s.VerifyCommand(c, to, now); err != nil || got.Type != CommandPasteOff {
		t.Errorf("paste-off: %+v, %v", got, err)
	}
}

// A command's by is a device ID, and the device of its signer when the
// records show that device.
func TestCommandByIsItsSigner(t *testing.T) {
	pg := newPhoneGroup(t)
	pc := adminCA(t, pg.root)
	pcM := member(t, pc)
	s := NewRecords(pg.root.Cert)
	if _, err := s.Add(computerAdminRecord(t, pg, pcM, "pc", KeyHashOf(pc.Cert))); err != nil {
		t.Fatal(err)
	}
	to, now := NewDeviceID(), time.Now()
	sign := func(by DeviceID) (Record, error) {
		return SignCommand(CommandBody{Type: CommandMode, Group: Tag(pg.root.Cert), By: by, To: to, ID: NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli(), Mode: "own"}, pc.Key, pc.Cert)
	}
	for _, by := range []DeviceID{"", "x\ny", DeviceID(strings.ToUpper(string(NewDeviceID())))} {
		if _, err := sign(by); err == nil {
			t.Errorf("a command with by %q was signed", by)
		}
	}
	own, err := sign(DeviceID(pcM.Subject.CommonName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyCommand(own, to, now); err != nil {
		t.Errorf("a command by its signer's device: %v", err)
	}
	other, err := sign(NewDeviceID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyCommand(other, to, now); err == nil {
		t.Error("a command naming another device than its signer's was taken")
	}
}

// TestCommandSenders checks whom a command counts for: by when the
// records show that its device holds the signing key, and otherwise the
// key, so a signer whose device is not shown can neither name a device
// that is nor spread its commands over made-up ones.
func TestCommandSenders(t *testing.T) {
	now := time.UnixMilli(1_761_400_000_000)
	command := func(ca *CA, tag string, by, to DeviceID) Record {
		t.Helper()
		c, err := SignCommand(CommandBody{Type: CommandMode, Group: tag, By: by, To: to, ID: NewCommandID(),
			TimeMS: now.UnixMilli(), ExpiresMS: now.Add(CommandLifetime).UnixMilli(), Mode: "own"}, ca.Key)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	check := func(s *Records, what string, c Record, to DeviceID, ok, verified bool) string {
		t.Helper()
		body, err := s.VerifyCommand(c, to, now)
		if (err == nil) != ok {
			t.Fatalf("%s: %v, want ok %v", what, err, ok)
		}
		if err != nil {
			return ""
		}
		sender, v := s.CommandSender(c, body.By)
		if v != verified || (v && sender != string(body.By)) || (!v && !strings.HasPrefix(sender, "key ")) {
			t.Errorf("%s: the sender is %q, verified %v", what, sender, v)
		}
		return sender
	}

	// A group whose root has no device record yet.
	pg := newPhoneGroup(t)
	s := NewRecords(pg.root.Cert)
	self := member(t, pg.root)
	selfID := DeviceID(self.Subject.CommonName)
	mustAdd(t, s, deviceRecord(t, pg.root.Cert, pg.root, nil, self, "pi", 1))
	tag := Tag(pg.root.Cert)
	one := check(s, "the root naming no device shown", command(pg.root, tag, NewDeviceID(), selfID), selfID, true, false)
	two := check(s, "the root naming another such device", command(pg.root, tag, NewDeviceID(), selfID), selfID, true, false)
	if one != two {
		t.Errorf("the root counts as %q and as %q", one, two)
	}
	check(s, "the root naming this device", command(pg.root, tag, selfID, selfID), selfID, false, false)

}
