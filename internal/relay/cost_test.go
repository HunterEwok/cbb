// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/tls"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/budget"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/group/grouptest"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// newRequestRelay is a relay with only what the counting of requests needs.
func newRequestRelay() *Relay {
	return &Relay{requests: budget.NewCount(requestCaps)}
}

// The requests being read are also counted by the address and the network
// the devices registered from, and by group, so devices registered by one
// source or one group cannot take all the slots between them.
func TestRequestsBoundBySourceAndGroup(t *testing.T) {
	r := newRequestRelay()
	take := func(m *member, n int) (taken int) {
		r.mu.Lock()
		defer r.mu.Unlock()
		for range n {
			if r.takeRequestLocked(m) {
				taken++
			}
		}
		return
	}
	// Devices of groups of their own, from one address.
	one := netip.MustParseAddr("203.0.113.7")
	got := 0
	for range maxRequests / maxRequestsOne {
		got += take(&member{from: one, greads: new(int)}, maxRequestsOne)
	}
	if got != maxRequestsSource {
		t.Errorf("one address holds %d requests, want %d", got, maxRequestsSource)
	}
	// Addresses of one network.
	got = 0
	for i := range 16 {
		got += take(&member{from: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), greads: new(int)}, maxRequestsSource)
	}
	if got != maxRequestsNet {
		t.Errorf("one network holds %d requests, want %d", got, maxRequestsNet)
	}
	// Devices of one group, from many networks.
	shared := new(int)
	got = 0
	for i := range 8 {
		got += take(&member{from: netip.AddrFrom4([4]byte{10, 0, byte(i), 1}), greads: shared}, maxRequestsOne)
	}
	if got != maxRequestsGroup {
		t.Errorf("one group holds %d requests, want %d", got, maxRequestsGroup)
	}
	// What is left of the slots is for others, and what is read is freed.
	if take(&member{from: netip.MustParseAddr("198.51.100.9"), greads: new(int)}, 1) != 1 {
		t.Error("a device from elsewhere refused while slots are left")
	}
	for range maxRequestsOne {
		r.freeRequest(&member{from: one, greads: new(int), reading: 1})
	}
	if n := r.requests.Held(one, budget.Address); n != maxRequestsSource-maxRequestsOne {
		t.Errorf("%d requests counted for the address after some were read, want %d", n, maxRequestsSource-maxRequestsOne)
	}
}

// One address registers devices of groups of its own, each of which holds
// idle connections in its tunnel: the relay reads no more of them than one
// address may have read, and still reads the requests of devices from
// elsewhere.
func TestRegisteredStrangersLeaveRequestSlots(t *testing.T) {
	r, l, link := startPosing(t, setupTimeout)
	// The idle connections stay until all are open, however slowly they
	// open (the race detector makes the tunnels slow).
	r.mu.Lock()
	r.requestWait = 5 * time.Minute
	r.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// open registers a device of a group of its own from a and opens n
	// connections in its tunnel.
	open := func(a netip.Addr, n int) {
		l.mu.Lock()
		l.other = a
		l.mu.Unlock()
		d := newDevice(t, newGroup(t))
		cfg := MemberConfig{Link: link, Self: d.id, Key: d.key, Cert: func() tls.Certificate { return d.cert }, Logf: t.Logf}
		tc, w, _, err := register(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tc.Close() })
		var relayKey, psk tunnel.Key
		copy(relayKey[:], w.Key)
		copy(psk[:], w.PSK)
		client, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: d.key, PresharedKey: psk, Addr: netip.MustParseAddr(w.Addr),
			HubPublicKey: relayKey, HubAddr: Addr, Endpoint: link.Endpoint, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		for range n {
			dctx, c := context.WithTimeout(ctx, 30*time.Second)
			conn, err := client.Dial(dctx)
			c()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
		}
	}
	reading := func(a netip.Addr) (all, from int) {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.requests.Held(a, budget.All), r.requests.Held(a, budget.Address)
	}
	// Three devices with all their connections are more than one address
	// may have read at once.
	stranger, other := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("198.51.100.77")
	for range maxRequestsSource/maxRequestsOne + 1 {
		open(stranger, maxRequestsOne)
	}
	waitFor(t, "the relay to take or close every connection", func() bool {
		n, ip := reading(stranger)
		return n == maxRequestsSource && ip == maxRequestsSource
	})
	// A device from elsewhere still has its requests read.
	open(other, 1)
	waitFor(t, "the relay to read a request of a device from elsewhere", func() bool {
		n, ip := reading(other)
		return ip == 1 && n == maxRequestsSource+1
	})
}

// What a source may start is paid for by the second: a registration's setup
// costs setupCost, so a source that sets up and closes over and over runs
// out, and earns more as time passes.
func TestSetupsChargedPerSecond(t *testing.T) {
	now := time.Unix(1000, 0)
	r := &Relay{setups: budget.NewCount(setupCaps), allow: newAllowance(), now: func() time.Time { return now }}
	one, other := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("198.51.100.1")
	// A source is refused well before 1024 setups; the bound keeps a
	// relay that never refuses from holding the test.
	setups := func() (n int) {
		for n < 1024 && r.takeSlot(one) {
			r.freeSlot(one)
			n++
		}
		return
	}
	if n, want := setups(), int(addressBurst/setupCost); n != want {
		t.Fatalf("%d setups in a burst, want %d", n, want)
	}
	if !r.takeSlot(other) {
		t.Error("another source refused")
	}
	now = now.Add(time.Second)
	if n, want := setups(), int(addressRate/setupCost); n != want {
		t.Fatalf("%d setups in the next second, want %d", n, want)
	}
}

// The setups from the networks of one wide network are bounded by the wide
// network, even when each network holds less than its own share: three
// networks of one IPv4 /16 set up as many as each may, and only
// maxSetupsWide of them are held; another wide network still sets up.
func TestSetupsBoundByWideNetwork(t *testing.T) {
	const networks = 3
	if networks*maxSetupsNetwork <= maxSetupsWide || networks*maxSetupsNetwork >= maxSetups {
		t.Fatal("the networks must hold more than the wide network's share and less than all")
	}
	r := &Relay{setups: budget.NewCount(setupCaps), allow: newAllowance(), now: func() time.Time { return time.Unix(1000, 0) }}
	held := 0
	for n := range networks {
		for i := range maxSetupsNetwork {
			if r.takeSlot(netip.AddrFrom4([4]byte{198, 51, byte(n), byte(i)})) {
				held++
			}
		}
	}
	if held != maxSetupsWide {
		t.Errorf("the networks of one wide network hold %d setups, want %d", held, maxSetupsWide)
	}
	if !r.takeSlot(netip.MustParseAddr("203.0.113.7")) {
		t.Error("another wide network refused")
	}
}

func TestAllowance(t *testing.T) {
	now := time.Unix(1000, 0)
	a := newAllowance()
	// Addresses of one network share the network's allowance.
	for i := range 5 {
		ok := a.Take(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), 1024, now)
		if want := i < 4; ok != want {
			t.Fatalf("address %d: took %v, want %v", i, ok, want)
		}
	}
	if !a.Take(netip.MustParseAddr("198.51.100.1"), 1024, now) {
		t.Error("another network refused")
	}
	// A refused request charges nothing, and time earns it back.
	if a.Take(netip.MustParseAddr("192.0.2.50"), 1024, now) {
		t.Error("an exhausted network took more")
	}
	if !a.Take(netip.MustParseAddr("192.0.2.50"), 1, now.Add(10*time.Second)) {
		t.Error("an exhausted network earned nothing in 10 s")
	}
	// Sources whose allowance is full again are forgotten.
	a.Sweep(now.Add(time.Hour))
	a.Take(netip.MustParseAddr("198.51.100.2"), 1, now.Add(time.Hour))
	if n := a.Payers(); n != 3 {
		t.Errorf("%d sources kept after an hour, want the address, network and wide network of 1", n)
	}
}

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
			Device: d.id, Name: "device", Role: group.RoleFull, Key: &kh}, ca.Key)
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

// The relay verifies a record when it first gets it and keeps the verified
// set: a group's later registrations, which send the same records again,
// cost it no more checks, and a source that sends a great many new records
// is held to what it may start by the second.
func TestRecordsVerifiedOnce(t *testing.T) {
	r, link := startWith(t, Config{Open: true, Limits: Limits{PerAddress: 100, PerNetwork: 100, GroupRecordBytes: 4 << 20}})
	// The allowance's clock stands still, so what the test spends does not
	// come back while the registrations take their time (the race detector
	// makes them slow).
	stopped := time.Now()
	r.mu.Lock()
	r.now = func() time.Time { return stopped }
	r.mu.Unlock()
	ca := newGroup(t)
	recs := deviceRecords(t, ca, group.MaxPerSigner)
	if err := registerWith(t, link, ca, recs); err != nil {
		t.Fatal(err)
	}
	local := netip.MustParseAddr("127.0.0.1")
	units := func() float64 {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.allow.Left(local, budget.Address)
	}
	r.mu.Lock()
	rs := r.records[group.Tag(ca.Cert)]
	if rs == nil || rs.set.Len() != len(recs) {
		r.mu.Unlock()
		t.Fatalf("the relay keeps %v of %d records", rs, len(recs))
	}
	r.mu.Unlock()
	before := units()
	for range 3 {
		if err := registerWith(t, link, ca, recs); err != nil {
			t.Fatal(err)
		}
	}
	// Three setups, and no check of a record: only a little of the
	// allowance.
	if spent := before - units(); spent > 3*setupCost {
		t.Errorf("sending the same records again spent %.0f units of the allowance", spent)
	}
	// New records of a group of its own are what the allowance is for.
	other := newGroup(t)
	if err := registerWith(t, link, other, deviceRecords(t, other, group.MaxPerSigner)); err == nil || !strings.Contains(err.Error(), "try again later") {
		t.Errorf("1024 new records from one address after 1024 others: %v", err)
	}
	// Records that do not verify are not kept.
	if err := registerWith(t, link, other, []group.Record{{Body: recs[0].Body, Sig: recs[0].Sig}}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if kept := r.records[group.Tag(other.Cert)]; kept != nil && (kept.set.Len() != 0 || kept.bytes != 0) {
		t.Errorf("the relay kept %d records of the other group, %d bytes", kept.set.Len(), kept.bytes)
	}
}

// An open relay keeps at most so many bytes of records for a group, and in
// all, and gives a group's records up when its last device goes.
func TestRecordBytesBounded(t *testing.T) {
	one := recordSize(deviceRecords(t, newGroup(t), 2)[1]) // with prev, as all but a group's first
	r, link := startWith(t, Config{Open: true, Limits: Limits{PerAddress: 100, PerNetwork: 100, GroupRecordBytes: 40 * one, RecordBytes: 70 * one}})
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
	// A refused registration of a group the relay holds no device of keeps nothing.
	r.mu.Lock()
	_, kept := r.records[group.Tag(c.Cert)]
	r.mu.Unlock()
	if kept {
		t.Error("records kept for a group whose registration was refused")
	}
}
