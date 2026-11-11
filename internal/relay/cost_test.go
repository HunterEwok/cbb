// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
)

// listedDevices holds the device each record of deviceRecords lists, by
// the record's ID, and whether a test registered it already.
var listedDevices = struct {
	sync.Mutex
	dev  map[[32]byte]device
	used map[[32]byte]bool
}{dev: map[[32]byte]device{}, used: map[[32]byte]bool{}}

// deviceRecords returns n records of the group ca, each for a new device
// of it with a key of its own (listedDevice returns it).
func deviceRecords(t *testing.T, ca *group.CA, n int) []group.Record {
	t.Helper()
	tag := group.Tag(ca.Cert)
	var recs []group.Record
	for range n {
		d := newDevice(t, ca)
		kh := group.KeyHashOf(d.cert.Leaf)
		rec := grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: tag, TimeMS: time.Now().UnixMilli(),
			Device: d.id, Name: "device", Role: group.RoleMember, Caps: group.AllCaps, Key: &kh}, ca.Key)
		listedDevices.Lock()
		listedDevices.dev[rec.ID()] = d
		listedDevices.Unlock()
		recs = append(recs, rec)
	}
	return recs
}

// listedDevice returns a device that one of recs, from deviceRecords,
// lists and that no test registered yet, or a new device of ca when there
// is none: in records v:2 a member registers only when a device record
// names its key.
func listedDevice(t *testing.T, ca *group.CA, recs []group.Record) device {
	t.Helper()
	listedDevices.Lock()
	defer listedDevices.Unlock()
	for _, r := range recs {
		id := r.ID()
		if d, ok := listedDevices.dev[id]; ok && !listedDevices.used[id] {
			listedDevices.used[id] = true
			return d
		}
	}
	return newDevice(t, ca)
}

// registerWith registers a device of ca that recs list with recs, and
// keeps it.
func registerWith(t *testing.T, link Link, ca *group.CA, recs []group.Record) error {
	t.Helper()
	d := listedDevice(t, ca, recs)
	tc, _, _, err := register(context.Background(), MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert },
		Records: func() []group.Record { return recs }})
	if err == nil {
		t.Cleanup(func() { tc.Close() })
	}
	return err
}

// An open relay keeps at most so many bytes of records for a group, and in
// all, and gives a group's records up when its last device goes.
func TestRecordBytesBounded(t *testing.T) {
	one := recordSize(deviceRecords(t, newGroup(t), 2)[1]) // with prev, as all but a group's first
	_, link := startWith(t, Config{Open: true, Limits: Limits{PerAddress: 100, PerNetwork: 100, GroupRecordBytes: 40 * one, RecordBytes: 70 * one}})
	a, b, c := newGroup(t), newGroup(t), newGroup(t)
	if err := registerWith(t, link, a, deviceRecords(t, a, 30)); err != nil {
		t.Fatalf("30 records of a group with room for 40: %v", err)
	}
	if err := registerWith(t, link, a, deviceRecords(t, a, 30)); err == nil || !strings.Contains(err.Error(), "as many records") {
		t.Errorf("30 more records of the same group: %v", err)
	}
	if err := registerWith(t, link, b, deviceRecords(t, b, 30)); err != nil {
		t.Fatalf("30 records of a second group, 60 in all: %v", err)
	}
	if err := registerWith(t, link, c, deviceRecords(t, c, 20)); err == nil || !strings.Contains(err.Error(), "as many records") {
		t.Errorf("records past the relay's total: %v", err)
	}
	// A refused registration of a group the relay holds no device of keeps
	// nothing: the room it would have taken is still there.
	d := newGroup(t)
	if err := registerWith(t, link, d, deviceRecords(t, d, 10)); err != nil {
		t.Errorf("10 records of a fourth group, 70 in all: %v", err)
	}
}

// The records a network brings to an open relay are bounded, whatever
// group they are of, so the groups of one network cannot take the records'
// room in all.
func TestRecordBytesChargedToTheSource(t *testing.T) {
	one := recordSize(deviceRecords(t, newGroup(t), 2)[1]) // with prev, as all but a group's first
	r, link := startWith(t, Config{Open: true, Limits: Limits{PerAddress: 100, PerNetwork: 100, GroupRecordBytes: 11 * one, RecordBytes: 1000 * one}})
	for i := range 4 {
		g := newGroup(t)
		if err := registerWith(t, link, g, deviceRecords(t, g, 10)); err != nil {
			t.Fatalf("group %d of one network, within its share: %v", i, err)
		}
	}
	g := newGroup(t)
	if err := registerWith(t, link, g, deviceRecords(t, g, 10)); err == nil || !strings.Contains(err.Error(), "from this network") {
		t.Errorf("records past the network's share: %v", err)
	}
	if g, n := r.Stats(); g != 4 || n != 4 {
		t.Errorf("after a refused registration the relay holds %d groups and %d devices, want 4 and 4", g, n)
	}
}

// recordSize is what a record takes in the relay's memory, as far as its
// limits count (member/src/relayd/records.rs).
func recordSize(r group.Record) int {
	n := len(r.Body) + len(r.Sig)
	for _, c := range r.Chain {
		n += len(c)
	}
	return n
}
