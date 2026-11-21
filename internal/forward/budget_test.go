// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/blind"
	"github.com/HunterEwok/cbb/internal/budget"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
)

// state is what a forwarder holds of the groups and the sources, as text
// that two moments compare by; from is left out, since a registration
// holds its share of it until its connection closes, refused or not.
func (f *Forwarder) state() string {
	var lines []string
	f.mu.Lock()
	for tag, r := range f.regs {
		lines = append(lines, fmt.Sprintf("reg %s %p %d %x %q", tag, r, r.id, r.key, r.vlessID))
	}
	for id, r := range f.byID {
		lines = append(lines, fmt.Sprintf("id %d %p", id, r))
	}
	for u, r := range f.byVLESS {
		lines = append(lines, fmt.Sprintf("vless %s %p", u, r))
	}
	for n, rs := range f.byInit {
		lines = append(lines, fmt.Sprintf("init %d %d", n, len(rs)))
	}
	f.mu.Unlock()
	f.versions.mu.Lock()
	for t, e := range f.versions.entries {
		lines = append(lines, fmt.Sprintf("version %s %+v", t, e))
	}
	lines = append(lines, "version nets:\n"+f.versions.nets.String())
	f.versions.mu.Unlock()
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// fromNow returns what the sources hold of registrations, set up or held.
func (f *Forwarder) fromNow() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("%s\nsetting %d", f.from, f.setting)
}

// A registration the forwarder refuses leaves it as it was, whatever the
// reason: the groups registered before keep their registrations, and it
// keeps nothing of the refused hub's group or its credential's version;
// once the refused connection is closed, the sources hold what they held
// before.
func TestRefusedRegistrationLeavesForwarder(t *testing.T) {
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	f, pin := startForwarderWith(t, Config{Limits: Limits{Groups: 3, Connections: 64},
		VLESS: &VLESSConfig{Listen: "127.0.0.1:0", XHTTP: &XHTTPConfig{Host: "example.com", Port: 443, Path: path}}})
	now := time.Now()
	var open []*tls.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	wgKey := func() *ecdh.PrivateKey {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return k
	}
	// A group that registers with a VLESS user ID.
	certA, _, gA := member(t)
	keyA := wgKey()
	vlessA, _ := tunnel.NewVLESSID()
	tc, a := rawOpen(t, f, pin, certA, keyA.PublicKey().Bytes(), keyA, hubAuth{creds: [][]byte{gA.hubs(t, 1)},
		edit: func(r *register) { r.VLESS = vlessA }})
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	open = append(open, tc)
	// A group at version 5 of its hubs' credential.
	certC, _, gC := member(t)
	keyC := wgKey()
	tc, a = rawOpen(t, f, pin, certC, keyC.PublicKey().Bytes(), keyC, hubAuth{creds: [][]byte{gC.hubs(t, 5)}})
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	open = append(open, tc)

	certB, _, gB := member(t)
	keyB := wgKey()
	rogueKey, _ := group.NewKey()
	other, _ := newServerKey(t)
	authB := hubAuth{creds: [][]byte{gB.hubs(t, 1)}}
	with := func(edit func(*register)) hubAuth { return hubAuth{creds: authB.creds, edit: edit} }
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		key  []byte
		auth hubAuth
		why  string
	}{
		{"the period credential", certB, keyB.PublicKey().Bytes(), hubAuth{creds: [][]byte{gB.periodCredential(t)}}, "does not verify"},
		{"too many credentials", certB, keyB.PublicKey().Bytes(), hubAuth{creds: [][]byte{authB.creds[0], authB.creds[0], authB.creds[0], authB.creds[0]}}, "forward/register/credentials"},
		{"a short WireGuard key", certB, []byte{1, 2, 3}, authB, "forward/register/key"},
		{"another hub's WireGuard key", certB, keyA.PublicKey().Bytes(), authB, "does not hold"},
		{"obfuscation that cannot be used", certB, keyB.PublicKey().Bytes(), with(func(r *register) { r.Obfuscation = &tunnel.Obfuscation{} }), "obfuscation"},
		{"a VLESS user ID that cannot be used", certB, keyB.PublicKey().Bytes(), with(func(r *register) { r.VLESS = vless.RegistrationID }), "VLESS user ID"},
		{"a credential that lists another hub", certB, keyB.PublicKey().Bytes(), hubAuth{creds: [][]byte{gB.hubs(t, 1, other)}}, "does not list"},
		{"an expired credential", certB, keyB.PublicKey().Bytes(), hubAuth{creds: [][]byte{gB.signHubs(t, gB.period, 1, now.Add(-time.Minute))}}, "expired"},
		{"another group's WireGuard key", certB, keyA.PublicKey().Bytes(), authB, "another group"},
		{"another group's VLESS user ID", certB, keyB.PublicKey().Bytes(), with(func(r *register) { r.VLESS = vlessA }), "VLESS user ID"},
		{"a credential of another period key", certC, keyB.PublicKey().Bytes(), hubAuth{creds: [][]byte{gC.signHubs(t, rogueKey, 6, now.Add(time.Hour))}}, "first"},
		{"an older credential", certC, keyB.PublicKey().Bytes(), hubAuth{creds: [][]byte{gC.hubs(t, 4)}}, "older"},
	} {
		before, from := f.state(), f.fromNow()
		holder := keyB
		if tc.name == "another group's WireGuard key" {
			holder = keyA
		}
		c, a := rawOpen(t, f, pin, tc.cert, tc.key, holder, tc.auth)
		if c != nil {
			c.Close()
		}
		if !strings.Contains(a.Error, tc.why) {
			t.Errorf("%s: %q, want a refusal for %q", tc.name, a.Error, tc.why)
			continue
		}
		if after := f.state(); after != before {
			t.Errorf("%s: a refused registration changed the forwarder\nbefore:\n%s\nafter:\n%s", tc.name, before, after)
		}
		waitUntil(t, tc.name+": the sources to hold what they held", func() bool { return f.fromNow() == from })
	}

	// The forwarder holds as many groups as it may: a new group is refused
	// and changes nothing.
	certD, _, gD := member(t)
	keyD := wgKey()
	tc, a = rawOpen(t, f, pin, certD, keyD.PublicKey().Bytes(), keyD, gD.auth(t))
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	open = append(open, tc)
	certE, _, gE := member(t)
	keyE := wgKey()
	before := f.state()
	c, a := rawOpen(t, f, pin, certE, keyE.PublicKey().Bytes(), keyE, gE.auth(t))
	if c != nil {
		c.Close()
	}
	if !strings.Contains(a.Error, "full") {
		t.Errorf("a group past the forwarder's bound: %q", a.Error)
	}
	if after := f.state(); after != before {
		t.Errorf("a refused group changed the forwarder\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// The loopback's wide network has added all the credentials' versions
	// it may: a new period is refused and changes nothing.
	f.versions.mu.Lock()
	for i := f.versions.nets.Held(netip.MustParseAddr("127.0.0.1"), budget.Wide); i < wideTags; i++ {
		from := netip.AddrFrom4([4]byte{127, 0, byte(1 + i/networkTags), 1})
		f.versions.mu.Unlock()
		if err := f.versions.keep(periodOf(fmt.Sprintf("filler %d", i), 1, now.Add(time.Hour)), from); err != nil {
			t.Fatal(err)
		}
		f.versions.mu.Lock()
	}
	f.versions.mu.Unlock()
	certN, _, gN := member(t)
	before, from := f.state(), f.fromNow()
	c, a = rawOpen(t, f, pin, certN, keyB.PublicKey().Bytes(), keyB, gN.auth(t))
	if c != nil {
		c.Close()
	}
	if !strings.Contains(a.Error, "cannot remember another group") {
		t.Errorf("a new period past the wide network's share: %q", a.Error)
	}
	if after := f.state(); after != before {
		t.Errorf("a new period past the wide network's share changed the forwarder\nbefore:\n%s\nafter:\n%s", before, after)
	}
	waitUntil(t, "the sources to hold what they held", func() bool { return f.fromNow() == from })
}

// A registration leaves nothing of its group at the forwarder but the
// group's entry in the table of versions, bounded by rememberedGroups: no
// list of the group's devices or records, however much a hub sends with
// it in fields the forwarder passes over, and nothing more once the group
// is away.
func TestRegistrationKeepsNoRecords(t *testing.T) {
	f, pin := startForwarder(t, Limits{})
	cert, tag, g := member(t)
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	tc, a := rawOpen(t, f, pin, cert, k.PublicKey().Bytes(), k, g.auth(t))
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	tc.Close()
	waitUntil(t, "the registration to end with its connection", func() bool { return !f.registered(tag) })
	away := f.state()

	// The same hub again, with 512 KiB in a field of a later version.
	big := make([]byte, 512<<10)
	rand.Read(big)
	tc, err := tls.Dial("tcp", f.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{Protocol}, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ty, m, _, err := blind.ReadFrame(tc, maxSetup)
	if err != nil || ty != tChallenge {
		t.Fatalf("challenge: %v (t %d)", err, ty)
	}
	ev, _ := m.Get(2)
	e, _ := ecdh.X25519().NewPublicKey(ev.Bytes)
	shared, _ := k.ECDH(e)
	p, _ := proof(shared, tc.ConnectionState())
	creds, _ := blind.Decode(g.hubs(t, 1))
	frame := blind.WriteFrame(blind.P(blind.FieldT, blind.Uint(tRegister)),
		blind.P(2, blind.Array(blind.Uint(3), blind.Bytes(k.PublicKey().Bytes()))),
		blind.P(3, blind.Bytes(p)), blind.P(6, blind.Array(creds)), blind.P(300, blind.Bytes(big)))
	if _, err := tc.Write(frame); err != nil {
		t.Fatal(err)
	}
	if a, err := readAnswerFrom(tc); err != nil || a.Error != "" || a.ID == 0 {
		t.Fatalf("with a field of a later version: %+v, %v", a, err)
	}
	tc.Close()
	waitUntil(t, "the registration to end with its connection", func() bool { return !f.registered(tag) })
	// The entry's sequence number and expiry move with the new
	// registration; nothing else may.
	moving := regexp.MustCompile(`Seq:\d+ Expires:\d+`)
	if after := f.state(); moving.ReplaceAllString(after, "") != moving.ReplaceAllString(away, "") {
		t.Errorf("a registration with more kept more\nbefore:\n%s\nafter:\n%s", away, after)
	}
	var entries []string
	for _, l := range strings.Split(away, "\n") {
		if strings.HasPrefix(l, "version ") && !strings.HasPrefix(l, "version nets:") {
			entries = append(entries, l)
		}
		if strings.HasPrefix(l, "reg ") || strings.HasPrefix(l, "id ") || strings.HasPrefix(l, "vless ") {
			t.Errorf("a group that is away holds %q", l)
		}
	}
	if len(entries) != 1 {
		t.Errorf("a group that is away holds %d entries, want its one: %q", len(entries), entries)
	}
}

// waitUntil waits up to ten seconds for ok.
func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; !ok(); i++ {
		if i == 200 {
			t.Fatalf("waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The networks of one wide network, however many, add no more than their
// wide network's share of the credentials' versions: the table keeps room
// for the new period of a group from elsewhere.
func TestVersionsWideNetworkLeavesRoom(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	expires := now.Add(periodLifetime)
	site := netip.MustParsePrefix("2001:db8:77::/48").Addr().As16()
	taken := 0
	for n := 0; n < rememberedGroups/networkTags+16; n++ {
		a := site
		a[6], a[7] = byte(n>>8), byte(n)
		from := netip.AddrFrom16(a)
		for i := range networkTags {
			if v.keep(periodOf(fmt.Sprintf("flood %d %d", n, i), 1, expires), from) == nil {
				taken++
			}
		}
	}
	if taken != wideTags {
		t.Errorf("one wide network added %d entries, want %d", taken, wideTags)
	}
	genuine := periodOf("genuine", 1, expires)
	if err := v.check(genuine, netip.MustParseAddr("2001:db8:1234:5678::1")); err != nil {
		t.Fatalf("a group's new period from elsewhere: %v", err)
	}
}

// For every kind of payer, sources that hold all they may leave room for a
// group from another wide network, and never push out a group that came
// before them: random sources of random networks, in random order, against
// the table of the credentials' versions. The seed is fixed, so a failure
// repeats.
func TestVersionsBudgetProperty(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(6, 2026))
	for round := range 8 {
		v := testVersions(t, "")
		now := time.Now()
		v.now = func() time.Time { return now }
		expires := now.Add(periodLifetime)
		// Groups that came first, from wide networks of their own.
		first := map[*shown]netip.Addr{}
		for i := range 1 + rng.IntN(20) {
			from := netip.AddrFrom4([4]byte{100, byte(i), byte(rng.IntN(256)), 1})
			p := periodOf(fmt.Sprintf("first %d %d", round, i), 3, expires)
			if err := v.keep(p, from); err != nil {
				t.Fatalf("round %d: a first group: %v", round, err)
			}
			first[p] = from
		}
		// The attacker has a few wide networks, some IPv4, some IPv6, and
		// floods new tags from random addresses in them, until refused
		// many times over.
		var wides []netip.Prefix
		for w := range 1 + rng.IntN(rememberedGroups/wideTags/2) {
			if rng.IntN(2) == 0 {
				wides = append(wides, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + w), byte(rng.IntN(256)), 0, 0}), 16))
			} else {
				wides = append(wides, netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, byte(w), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))}), 48))
			}
		}
		refused := 0
		for i := 0; refused < 4*wideTags; i++ {
			w := wides[rng.IntN(len(wides))]
			b := w.Addr().AsSlice()
			for j := w.Bits() / 8; j < len(b); j++ {
				b[j] = byte(rng.IntN(4)) // a few networks of each wide network
			}
			from, _ := netip.AddrFromSlice(b)
			if v.keep(periodOf(fmt.Sprintf("flood %d %d", round, i), 1, expires), from) != nil {
				refused++
			}
		}
		for p, from := range first {
			if err := v.check(withVersion(p, 2), from); err == nil {
				t.Fatalf("round %d: a first group's older credential passed after the flood", round)
			}
			if err := v.check(withVersion(p, 4), from); err != nil {
				t.Fatalf("round %d: a first group's newer credential: %v", round, err)
			}
		}
		genuine := netip.AddrFrom16([16]byte{0x2a, 0x02, byte(round), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		if err := v.keep(periodOf(fmt.Sprintf("genuine %d", round), 1, expires), genuine); err != nil {
			t.Fatalf("round %d: %d wide networks at their cap left no room for a group from elsewhere: %v", round, len(wides), err)
		}
	}
}

// The wide networks of one IPv6 provider, however many, add no more than
// the provider's share of the credentials' versions, so a provider's
// customers cannot fill the table between them.
func TestVersionsProviderLeavesRoom(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	expires := now.Add(periodLifetime)
	taken := 0
	for w := 0; w < providerTags/wideTags+2; w++ {
		for n := range wideTags / networkTags {
			from := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(w >> 8), byte(w), 0, byte(n), 15: 1})
			for i := range networkTags {
				if v.keep(periodOf(fmt.Sprintf("flood %d %d %d", w, n, i), 1, expires), from) == nil {
					taken++
				}
			}
		}
	}
	if taken != providerTags {
		t.Errorf("the wide networks of one provider added %d entries, want %d", taken, providerTags)
	}
	genuine := periodOf("genuine", 1, expires)
	if err := v.check(genuine, netip.MustParseAddr("2001:db9:1234:5678::1")); err != nil {
		t.Fatalf("a group's new period from another provider: %v", err)
	}
}

// What the forwarder holds after many strangers registered with
// credentials and left is bounded by the table's numbers: the entries of
// their periods, until they expire, within rememberedGroups; and the count
// of their sources, which forgets a source with nothing.
func TestVersionsMemoryBounded(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	expires := now.Add(periodLifetime)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range 2 * rememberedGroups {
		from := netip.AddrFrom4([4]byte{byte(1 + i>>18), byte(i >> 10), byte(i>>8) & 3, byte(i)})
		v.keep(periodOf(fmt.Sprintf("stranger %d", i), 1, expires), from)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if len(v.entries) > rememberedGroups {
		t.Fatalf("%d entries, bound %d", len(v.entries), rememberedGroups)
	}
	// docs/relay-budget.md: about 400 bytes an entry, with its networks.
	const perEntry = 400
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > perEntry*rememberedGroups {
		t.Errorf("the table took %d bytes for %d entries, more than %d each", grown, len(v.entries), perEntry)
	}
	// Once they expire, nothing of them is left.
	now = expires.Add(time.Hour)
	v.mu.Lock()
	v.pruneLocked()
	n, payers := len(v.entries), v.nets.Payers()
	v.mu.Unlock()
	if n != 0 || payers != 0 {
		t.Errorf("after expiry the table holds %d entries and %d payers", n, payers)
	}
}

// Registrations over VLESS pay as direct ones do when the VLESS server
// knows their source: no source takes more setup slots than its caps, and
// from a source not known (a web server in front that does not name it)
// they take at most an eighth of the slots, so a hub that registers
// directly still finds room (docs/relay-budget.md, "The forwarder").
func TestRegistrationsOverVLESSPayBySource(t *testing.T) {
	const slots = 24
	f, _ := startForwarderWith(t, Config{Limits: Limits{Connections: slots, PerAddress: 2, PerNetwork: 2, PerWide: 2, PerProvider: 2}})
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	stall := func(from netip.Addr) {
		ours, theirs := net.Pipe()
		conns = append(conns, ours)
		go f.registrationOverVLESS(theirs, from)
	}
	counts := func() (setting, unknown, over int) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.setting, f.vlessSet, f.overVLESS
	}
	settle := func(want int) {
		t.Helper()
		for range 100 {
			if s, _, _ := counts(); s == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		s, u, o := counts()
		t.Fatalf("setting %d (from sources not known %d, over VLESS %d), want %d", s, u, o, want)
	}
	stranger := netip.MustParseAddr("198.51.100.9")
	for range slots {
		stall(stranger)
	}
	settle(2)
	if f.from.Held(stranger, budget.Address) != 2 {
		t.Errorf("the stranger holds %d, want 2", f.from.Held(stranger, budget.Address))
	}
	for range slots {
		stall(netip.IPv6Loopback())
		stall(netip.Addr{})
	}
	settle(2 + slots/8)
	// A hub that registers directly is still let in to set up.
	c, err := net.Dial("tcp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	settle(2 + slots/8 + 1)
}
