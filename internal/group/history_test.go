// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
)

// nextCase is a case of testdata/interop/v2-next.json: a set, a signer, and
// what the member gives it to sign next.
type nextCase struct {
	Name         string   `json:"name"`
	GroupCA      []byte   `json:"group_ca"`
	Group        string   `json:"group"`
	NowMS        int64    `json:"now_ms"`
	Records      []Record `json:"records"`
	Signer       KeyHash  `json:"signer"`
	TwoHistories bool     `json:"two_histories"`
	Seq          int64    `json:"seq"`
	Prev         *KeyHash `json:"prev,omitempty"`
}

var nextPath = filepath.Join("..", "..", "testdata", "interop", "v2-next.json")

// snapshot is the case of s for signer now.
func snapshot(name string, s *Records, signer KeyHash) nextCase {
	seq, prev := s.Next(signer)
	return nextCase{
		Name: name, GroupCA: s.groupCA.Raw, Group: s.tag, NowMS: s.now().UnixMilli(), Records: s.All(),
		Signer: signer, TwoHistories: s.TwoHistories(signer), Seq: seq, Prev: prev,
	}
}

// TestNextVectors writes (with -update) and checks
// testdata/interop/v2-next.json, which the core's tests check too.
func TestNextVectors(t *testing.T) {
	if *update {
		cryptotest.SetGlobalRandom(t, 11)
		data, err := json.MarshalIndent(struct {
			Comment string     `json:"comment"`
			Cases   []nextCase `json:"cases"`
		}{
			Comment: "Written by internal/group's TestNextVectors -update: the seq and prev a member gives a key's next record, and whether the key signed two histories (docs/protocol.md, section 10, \"Two numbers\").",
			Cases:   resolveBothHistories(t),
		}, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(nextPath, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []nextCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		s := NewRecords(ca)
		s.tag = c.Group
		s.SetClock(func() time.Time { return time.UnixMilli(c.NowMS) })
		for _, r := range c.Records {
			mustAdd(t, s, r)
		}
		got := snapshot(c.Name, s, c.Signer)
		if got.TwoHistories != c.TwoHistories || got.Seq != c.Seq || (got.Prev == nil) != (c.Prev == nil) || got.Prev != nil && *got.Prev != *c.Prev {
			t.Errorf("%s: two histories %v, next %d after %v; want %v, %d after %v", c.Name, got.TwoHistories, got.Seq, got.Prev, c.TwoHistories, c.Seq, c.Prev)
		}
	}
}

// TestResolveBothHistories plays an admin device brought back from an old
// backup: it signs again with a number the group already holds, the key
// may sign nothing while the two histories stand, and once the root voids
// both of them the key goes on from the record below the fork, and what it
// signs counts (docs/protocol.md, section 10, "Two numbers").
func TestResolveBothHistories(t *testing.T) {
	resolveBothHistories(t)
}

// resolveBothHistories plays TestResolveBothHistories and returns its
// steps as cases of v2-next.json.
func resolveBothHistories(t *testing.T) []nextCase {
	var cases []nextCase
	pg := newPhoneGroup(t)
	root := pg.root.Cert
	phone := member(t, pg.a)
	admin := KeyHashOf(pg.a.Cert)
	key := KeyHashOf(phone)
	tag := Tag(root)

	s := NewRecords(root)
	sign := func(body RecordBody, ca *CA, chain *x509.Certificate) Record {
		t.Helper()
		body.Group = tag
		r, err := s.Sign(body, ca.Key, chain)
		if err != nil {
			t.Fatal(err)
		}
		mustAdd(t, s, r)
		return r
	}
	device := func(c *x509.Certificate, name string, ms int64) RecordBody {
		k := KeyHashOf(c)
		return RecordBody{Type: RecordDevice, TimeMS: ms, Device: string(DeviceID(c.Subject.CommonName)), Name: name, Role: RoleMember, Caps: AllCaps, Key: &k}
	}
	sign(RecordBody{
		Type: RecordDevice, TimeMS: 1, Device: string(DeviceID(phone.Subject.CommonName)), Name: "phone", Role: RolePhone,
		Key: &key, Admin: &admin, Powers: authority.Powers, Commands: authority.Commands,
	}, pg.root, nil)
	first := sign(device(member(t, pg.a), "first", 2), pg.a, pg.a.Cert)

	// The backup holds the records up to here.
	backup := NewRecords(root)
	for _, r := range s.All() {
		mustAdd(t, backup, r)
	}
	cases = append(cases, snapshot("one history", s, admin))
	lost := sign(device(member(t, pg.a), "lost", 3), pg.a, pg.a.Cert)

	// The device, brought back, signs its second record again.
	again, err := backup.Sign(func() RecordBody { b := device(member(t, pg.a), "again", 4); b.Group = tag; return b }(), pg.a.Key, pg.a.Cert)
	if err != nil {
		t.Fatal(err)
	}
	mustAdd(t, s, again)
	if !s.TwoHistories(admin) {
		t.Fatalf("no two histories; conflicts %+v", s.State().Conflicts)
	}
	cases = append(cases, snapshot("two histories", s, admin))
	b := device(member(t, pg.a), "while forked", 5)
	b.Group = tag
	if _, err := s.Sign(b, pg.a.Key, pg.a.Cert); !errors.Is(err, ErrTwoHistories) {
		t.Fatalf("a forked key signed: %v", err)
	}

	// The root voids both histories.
	sign(RecordBody{Type: RecordResolve, TimeMS: 6, Records: sortedIDs(lost.ID(), again.ID())}, pg.root, nil)
	if s.TwoHistories(admin) || s.Stop() != authority.StopNone {
		t.Fatalf("after the resolve: two histories %v, stop %q", s.TwoHistories(admin), s.Stop())
	}
	cases = append(cases, snapshot("both histories voided", s, admin))
	seq, prev := s.Next(admin)
	if seq != 2 || prev == nil || *prev != first.ID() {
		t.Fatalf("next %d after %v, want 2 after the first record", seq, prev)
	}
	sign(device(member(t, pg.a), "re-signed", 7), pg.a, pg.a.Cert)
	if got := names(s.Devices()); got != "first phone re-signed" {
		t.Errorf("devices %q, want first phone re-signed", got)
	}
	return append(cases, snapshot("re-signed after the resolve", s, admin))
}

func sortedIDs(ids ...KeyHash) []KeyHash {
	if ids[1].String() < ids[0].String() {
		ids[0], ids[1] = ids[1], ids[0]
	}
	return ids
}
