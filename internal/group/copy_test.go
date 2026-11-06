// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/hlc"
	"github.com/HunterEwok/cbb/internal/seal"
)

// copyChecks is testdata/interop/go-copy-checks.json: a group's records,
// the copies a member checks against them, which it takes, and the
// readers the records give, for the Rust core to agree with.
type copyChecks struct {
	Comment string      `json:"comment"`
	GroupCA []byte      `json:"group_ca"`
	NowMS   int64       `json:"now_ms"`
	Records []Record    `json:"records"`
	Copies  []copyCheck `json:"copies"`
	Readers []string    `json:"readers"`
	Secret  []string    `json:"secret_readers"`
	Hubs    []DeviceID  `json:"hub_order"`
}

type copyCheck struct {
	Name  string       `json:"name"`
	Event *clip.Sealed `json:"event"`
	OK    bool         `json:"ok"`
}

// sealedFrom seals a text from id to readers and signs it with id's key.
func sealedFrom(t *testing.T, id *Identity, readers []clip.Reader) *clip.Sealed {
	t.Helper()
	var issuer []byte
	if id.Issuer != nil {
		issuer = id.Issuer.Raw
	}
	s, err := clip.SealCopy(clip.NewID(), string(id.ID), hlc.Timestamp{Wall: t0.UnixMilli(), Logical: 1}, id.Cert.Raw, issuer, readers,
		clip.Content{Kind: clip.Text, Text: "from " + string(id.ID)}, nil, clip.NewKey(), id.Key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sealKeyOf(t *testing.T) []byte {
	t.Helper()
	secret, err := seal.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := seal.PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func writeCopyChecks(t *testing.T, path string) {
	admin := newGroup(t)
	mac, pi, gone, stranger := join(t, admin, t0), join(t, admin, t0), join(t, admin, t0), join(t, admin, t0)
	other := newGroup(t)
	root := admin.GroupCA.Cert
	var recs []Record
	device := func(id *Identity, name string, ms int64, sealKey []byte, forwardOnly bool) {
		key := KeyHashOf(id.Cert)
		r, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(root), TimeMS: ms, Device: string(id.ID), Name: name, Role: RoleFull,
			Key: &key, Seal: sealKey, ForwardOnly: forwardOnly, HoldsRoot: id == admin}, admin.GroupCA.Key)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	device(admin, "desk", 1, sealKeyOf(t), false)
	device(mac, "mac", 2, sealKeyOf(t), false)
	device(pi, "pi", 3, sealKeyOf(t), true)
	device(gone, "gone", 4, sealKeyOf(t), false)
	recs = append(recs, revokeRecord(t, root, &admin.GroupCA, nil, []KeyHash{KeyHashOf(gone.Cert)}))
	s := NewRecords(root)
	for _, r := range recs {
		mustAdd(t, s, r)
	}
	readers := s.Readers(false)
	good := sealedFrom(t, mac, readers)
	forged := *good
	forged.Sig = sealedFrom(t, admin, readers).Sig
	posing := sealedFrom(t, mac, readers)
	posing.Cert = admin.Cert.Raw
	v := copyChecks{
		Comment: "Written by internal/group's TestCopyCheckVectors -update. A member checks each copy against the records at now_ms and takes those with ok (docs/protocol.md, section 4, \"Opening\"); readers and secret_readers are the devices the records seal copies to, sorted, and hub_order the order of the hubs.",
		GroupCA: root.Raw, NowMS: t0.Add(time.Hour).UnixMilli(), Records: recs,
		Copies: []copyCheck{
			{"from a member", good, true},
			{"from the root's computer", sealedFrom(t, admin, readers), true},
			{"from a hub that only passes copies on", sealedFrom(t, pi, readers), true},
			{"from a member no record names", sealedFrom(t, stranger, readers), false},
			{"from a removed member", sealedFrom(t, gone, readers), false},
			{"from another group", sealedFrom(t, other, readers), false},
			{"signed by another member", &forged, false},
			{"in another member's certificate", posing, false},
		},
	}
	for _, r := range readers {
		v.Readers = append(v.Readers, r.ID)
	}
	for _, r := range s.Readers(true) {
		v.Secret = append(v.Secret, r.ID)
	}
	v.Hubs = s.HubOrder()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCopyCheckVectors writes (with -update) and checks
// testdata/interop/go-copy-checks.json.
func TestCopyCheckVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-copy-checks.json")
	if *update {
		writeCopyChecks(t, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v copyChecks
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(ca)
	for _, r := range v.Records {
		mustAdd(t, s, r)
	}
	if len(v.Copies) < 8 {
		t.Fatalf("%d copies", len(v.Copies))
	}
	for _, c := range v.Copies {
		if err := s.CheckCopy(c.Event, time.UnixMilli(v.NowMS)); (err == nil) != c.OK {
			t.Errorf("%s: CheckCopy = %v, the file says ok %v", c.Name, err, c.OK)
		}
	}
	ids := func(rs []clip.Reader) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	if got := ids(s.Readers(false)); !slices.Equal(got, v.Readers) || len(got) != 2 {
		t.Errorf("readers %v, the file has %v", got, v.Readers)
	}
	if got := ids(s.Readers(true)); !slices.Equal(got, v.Secret) {
		t.Errorf("secret readers %v, the file has %v", got, v.Secret)
	}
	if got := s.HubOrder(); !slices.Equal(got, v.Hubs) || len(got) != 2 {
		t.Errorf("hub order %v, the file has %v", got, v.Hubs)
	}
}
