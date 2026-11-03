// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/budget"
	"github.com/HunterEwok/cbb/internal/group"
)

// nopConn is the connection of a member registered without one.
type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// fakeMember registers a device of the group tag from the address from as
// a registration does after its checks, without a connection; it returns
// the member, or the refusal.
func fakeMember(r *Relay, tag string, from netip.Addr) (*member, error) {
	m := &member{tag: tag, device: string(group.NewDeviceID()), from: from, raw: nopConn{}, streams: map[net.Conn]bool{}}
	r.mu.Lock()
	defer r.mu.Unlock()
	copy(m.key[:], []byte(m.device+m.device))
	copy(m.psk[:], []byte(m.device+m.device))
	if err := r.admitLocked(m, nil); err != nil {
		return nil, err
	}
	return m, r.addLocked(m)
}

// The requests being read are also counted by the wide network the devices
// registered from, so the networks of one site or provider cannot take all
// the slots between them.
func TestRequestsBoundByWideNetwork(t *testing.T) {
	r := newRequestRelay()
	got := 0
	for i := range 8 {
		from := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 7, 0, byte(i), 15: 1})
		for range maxRequestsNet / maxRequestsOne {
			m := &member{from: from, greads: new(int)}
			r.mu.Lock()
			for range maxRequestsOne {
				if r.takeRequestLocked(m) {
					got++
				}
			}
			r.mu.Unlock()
		}
	}
	if got != maxRequestsWide {
		t.Errorf("the networks of one wide network hold %d requests, want %d", got, maxRequestsWide)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.takeRequestLocked(&member{from: netip.MustParseAddr("2001:db8:8::1"), greads: new(int)}) {
		t.Error("a device from another wide network refused")
	}
}

// The registrations from the wide networks of one IPv6 provider, however
// many, are bounded by the provider's share, so a provider's customers
// cannot take every group's place on an open relay between them.
func TestRegistrationsBoundByProvider(t *testing.T) {
	r, _ := startWith(t, Config{Open: true})
	l := DefaultOpenLimits
	taken := 0
	for w := 0; w < l.PerProvider/l.PerWide+2; w++ {
		for n := range l.PerWide / l.PerNetwork {
			for a := range l.PerNetwork / l.PerAddress {
				from := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(w), 0, byte(n), 15: byte(a + 1)})
				for i := range l.PerAddress {
					if _, err := fakeMember(r, fmt.Sprintf("%04x%04x%04x%04x", w, n, a, i), from); err == nil {
						taken++
					}
				}
			}
		}
	}
	if taken != l.PerProvider {
		t.Errorf("the wide networks of one provider registered %d devices, want %d", taken, l.PerProvider)
	}
	if _, err := fakeMember(r, "ffffffffffffffff", netip.MustParseAddr("2001:db9::1")); err != nil {
		t.Errorf("a group from another provider: %v", err)
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
	before := r.state()
	g := newGroup(t)
	if err := registerWith(t, link, g, deviceRecords(t, g, 10)); err == nil || !strings.Contains(err.Error(), "from this network") {
		t.Errorf("records past the network's share: %v", err)
	}
	if after := r.settled(t); after != before {
		t.Errorf("a refused registration changed the relay\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// For every kind of payer, sources that hold all the registrations they may
// leave room for a group from another wide network, and never push out a
// device registered before them: random sources of a few wide networks, in
// random order, against an open relay. The seed is fixed, so a failure
// repeats.
func TestOpenRelayBudgetProperty(t *testing.T) {
	limits := Limits{Groups: 64, PerAddress: 4, PerNetwork: 8, PerWide: 16}
	r, _ := startWith(t, Config{Open: true, Limits: limits})
	rng := mrand.New(mrand.NewPCG(6, 2026))
	var first []*member
	for i := range 4 {
		m, err := fakeMember(r, fmt.Sprintf("%016x", i), netip.AddrFrom4([4]byte{100, byte(i), 0, 1}))
		if err != nil {
			t.Fatal(err)
		}
		first = append(first, m)
	}
	for round := range 6 {
		// A few wide networks, fewer than fill the relay, flood it with
		// devices of groups of their own and of each other's groups.
		var wides []netip.Prefix
		for w := range 1 + rng.IntN((limits.Groups-len(first))/limits.PerWide-1) {
			if rng.IntN(2) == 0 {
				wides = append(wides, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + w), byte(round), 0, 0}), 16))
			} else {
				wides = append(wides, netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, byte(w), byte(round)}), 48))
			}
		}
		var flood []*member
		for i := range 40 * limits.PerWide {
			w := wides[rng.IntN(len(wides))]
			b := w.Addr().AsSlice()
			for j := w.Bits() / 8; j < len(b); j++ {
				b[j] = byte(rng.IntN(3))
			}
			from, _ := netip.AddrFromSlice(b)
			tag := fmt.Sprintf("%08x%08x", round, rng.IntN(i+1))
			if m, err := fakeMember(r, tag, from); err == nil {
				flood = append(flood, m)
			}
		}
		r.mu.Lock()
		for _, m := range first {
			if r.groups[m.tag][m.device] != m {
				t.Fatalf("round %d: a device registered first was pushed out", round)
			}
		}
		r.mu.Unlock()
		if _, err := fakeMember(r, fmt.Sprintf("%016x", 1000+round), netip.AddrFrom4([4]byte{203, 0, 113, byte(round)})); err != nil {
			t.Fatalf("round %d: %d wide networks at their cap left no room for a group from elsewhere: %v", round, len(wides), err)
		}
		// The flood leaves; the next round floods anew.
		r.mu.Lock()
		for _, m := range flood {
			r.dropLocked(m)
		}
		r.mu.Unlock()
	}
}

// What an open relay holds after many strangers registered and left is
// bounded by the budget's numbers: nothing of their groups, registrations
// or records, and of what their sources may start, only the sources that
// spent some in the last half minute, which it then forgets. Measured: a
// second crowd of strangers who come and go leaves the heap where the first
// left it, so what the relay holds does not grow with how many came.
func TestOpenRelayForgetsStrangers(t *testing.T) {
	r, link := startWith(t, Config{Open: true})
	now := time.Now()
	r.mu.Lock()
	r.now = func() time.Time { return now }
	r.mu.Unlock()
	for range 3 {
		g := newGroup(t)
		recs := deviceRecords(t, g, 5)
		d := listedDevice(t, g, recs)
		tc, _, _, err := register(context.Background(), MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert },
			Records: func() []group.Record { return recs }})
		if err != nil {
			t.Fatal(err)
		}
		tc.Close()
	}
	waitFor(t, "the relay to forget the real ones", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.groups) == 0
	})
	const strangers = 5000
	crowd := func(first int) uint64 {
		t.Helper()
		for i := first; i < first+strangers; i++ {
			from := netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 1})
			r.mu.Lock()
			r.allow.Take(from, setupCost, now)
			r.mu.Unlock()
			m, err := fakeMember(r, fmt.Sprintf("%016x", i), from)
			if err != nil {
				t.Fatal(err)
			}
			r.mu.Lock()
			r.dropLocked(m)
			r.mu.Unlock()
		}
		r.mu.Lock()
		// docs/relay-budget.md: until a source's allowance is full again,
		// which takes under 30 s, the relay holds it, three payers a source.
		if n := r.allow.Payers(); n > 3*strangers {
			t.Errorf("the allowance holds %d payers for %d strangers", n, strangers)
		}
		now = now.Add(time.Minute)
		r.allow.Sweep(now)
		if n := r.allow.Payers(); n != 0 {
			t.Errorf("a minute later the allowance holds %d sources", n)
		}
		if len(r.groups) != 0 || len(r.byAddr) != 0 || len(r.records) != 0 || len(r.periods) != 0 || len(r.tagLocks) != 0 {
			t.Errorf("after the strangers left the relay holds %d groups, %d devices, %d groups' records, %d periods, %d locks",
				len(r.groups), len(r.byAddr), len(r.records), len(r.periods), len(r.tagLocks))
		}
		if r.held.Payers() != 0 || r.recordBytes.Payers() != 0 || r.held.Held(netip.Addr{}, budget.All) != 0 {
			t.Errorf("after the strangers left the counts hold\n%s\n%s", r.held, r.recordBytes)
		}
		r.mu.Unlock()
		return settledHeap()
	}
	first := crowd(0)
	crowd(strangers)
	// The tunnel stops a removed peer's work a moment later, and later on a
	// slow machine: the heap is read until it comes down to the first
	// crowd's, for a while. 50 bytes a stranger that stay would be a leak.
	var grown int64
	for deadline := time.Now().Add(20 * time.Second); ; {
		if grown = int64(settledHeap()) - int64(first); grown <= 50*strangers || time.Now().After(deadline) {
			break
		}
	}
	if grown > 50*strangers {
		t.Errorf("a second crowd of %d strangers grew the relay by %d bytes", strangers, grown)
	}
}

// settledHeap is the heap in use a moment after the last work, once collected.
func settledHeap() uint64 {
	time.Sleep(time.Second)
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}
