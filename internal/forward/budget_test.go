// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/budget"
	"github.com/HunterEwok/cbb/internal/frame"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
	"github.com/HunterEwok/cbb/internal/tunnel"
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
	f.memory.mu.Lock()
	for tag, g := range f.memory.groups {
		lines = append(lines, fmt.Sprintf("memory %s %d %d %v", tag, len(g.recs), g.bytes, g.paid))
	}
	lines = append(lines, fmt.Sprintf("memory bytes %d\n%s", f.memory.bytes, f.memory.payers))
	f.memory.mu.Unlock()
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// fromNow returns what the sources hold of registrations, set up or held.
func (f *Forwarder) fromNow() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("%s\nsetting %d", f.from, f.setting)
}

// rawClaim registers by hand with the claim that edit makes of a claim of
// key, proven by holder.
func rawClaim(t *testing.T, f *Forwarder, pin string, cert tls.Certificate, key []byte, holder *ecdh.PrivateKey, edit func(*claim, tls.ConnectionState)) (*tls.Conn, answer) {
	t.Helper()
	tc, err := tls.Dial("tcp", f.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{Protocol},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, answer{Error: err.Error()}
	}
	if Pin(tc.ConnectionState().PeerCertificates[0]) != pin {
		t.Fatal("the forwarder's pin changed")
	}
	dec := frame.NewDecoder(tc, 1<<20)
	var ch challenge
	if err := dec.Decode(&ch); err != nil {
		tc.Close()
		return nil, answer{Error: err.Error()}
	}
	e, _ := ecdh.X25519().NewPublicKey(ch.E)
	shared, _ := holder.ECDH(e)
	p, _ := proof(shared, tc.ConnectionState())
	c := claim{Key: key, Proof: p}
	edit(&c, tc.ConnectionState())
	frame.NewEncoder(tc, 1<<20).Encode(c)
	var a answer
	if err := dec.Decode(&a); err != nil {
		tc.Close()
		return nil, answer{Error: err.Error()}
	}
	return tc, a
}

// A registration the forwarder refuses leaves it as it was, whatever the
// reason: the groups registered before keep their registrations, and it
// keeps nothing of the refused hub's group, its credential's version or
// its records; once the refused connection is closed, the sources hold
// what they held before.
func TestRefusedRegistrationLeavesForwarder(t *testing.T) {
	vk, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	f, pin := startForwarderWith(t, Config{Limits: Limits{Groups: 3, Connections: 64},
		VLESS: &VLESSConfig{Listen: "127.0.0.1:0", Site: "example.com", Dest: "127.0.0.1:1", Key: vk}})
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
	withAdmin := func(key crypto.Signer, recs []group.Record) func(*claim, tls.ConnectionState) {
		return func(c *claim, cs tls.ConnectionState) {
			hubAuth{key: key, records: recs}.sign(t, c, cs)
		}
	}
	// A group that registers with records and a VLESS user ID.
	certA, tagA, caA := member(t)
	recsA := revokes(t, caA, tagA, 3, 4)
	keyA := wgKey()
	vlessA, _ := tunnel.NewVLESSID()
	tc, a := rawClaim(t, f, pin, certA, keyA.PublicKey().Bytes(), keyA, func(c *claim, cs tls.ConnectionState) {
		withAdmin(caA.Key, recsA)(c, cs)
		c.VLESS = vlessA
	})
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	open = append(open, tc)
	// A group that registers with a credential.
	period, periodKey, hubKey, hubCert := newPeriod(t, now)
	keyC := wgKey()
	tc, a = rawClaim(t, f, pin, hubCert, keyC.PublicKey().Bytes(), keyC, func(c *claim, cs tls.ConnectionState) {
		c.Credentials = []group.Credential{signHubs(t, period, periodKey, hubKey, 5)}
	})
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	open = append(open, tc)

	certB, tagB, caB := member(t)
	keyB := wgKey()
	rogueKey, _ := group.NewKey()
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		key  []byte
		edit func(*claim, tls.ConnectionState)
		why  string
	}{
		{"too many records", certB, keyB.PublicKey().Bytes(), withAdmin(caB.Key, make([]group.Record, maxClaimRecords+1)), "too many records"},
		{"too many credentials", hubCert, keyB.PublicKey().Bytes(), func(c *claim, _ tls.ConnectionState) {
			c.Credentials = make([]group.Credential, 4)
		}, "too many credentials"},
		{"a short WireGuard key", certB, []byte{1, 2, 3}, withAdmin(caB.Key, nil), "32 bytes"},
		{"another hub's WireGuard key", certB, keyA.PublicKey().Bytes(), withAdmin(caB.Key, nil), "does not hold"},
		{"obfuscation that cannot be used", certB, keyB.PublicKey().Bytes(), func(c *claim, cs tls.ConnectionState) {
			withAdmin(caB.Key, nil)(c, cs)
			c.Obfuscation = &tunnel.Obfuscation{}
		}, "obfuscation"},
		{"a VLESS user ID that cannot be used", certB, keyB.PublicKey().Bytes(), func(c *claim, cs tls.ConnectionState) {
			withAdmin(caB.Key, nil)(c, cs)
			c.VLESS = "not an ID"
		}, "VLESS user ID"},
		{"neither root nor admin", certB, keyB.PublicKey().Bytes(), withAdmin(rogueKey, nil), "neither"},
		{"records too large", certB, keyB.PublicKey().Bytes(), withAdmin(caB.Key, revokes(t, caB, tagB, 100, 110)), "too large"},
		{"another group's WireGuard key", certB, keyA.PublicKey().Bytes(), withAdmin(caB.Key, nil), "another group"},
		{"another group's VLESS user ID", certB, keyB.PublicKey().Bytes(), func(c *claim, cs tls.ConnectionState) {
			withAdmin(caB.Key, nil)(c, cs)
			c.VLESS = vlessA
		}, "VLESS user ID"},
		{"a credential of another period key", hubCert, keyB.PublicKey().Bytes(), func(c *claim, _ tls.ConnectionState) {
			c.Credentials = []group.Credential{signHubs(t, period, rogueKey, hubKey, 6)}
		}, "first"},
		{"an older credential", hubCert, keyB.PublicKey().Bytes(), func(c *claim, _ tls.ConnectionState) {
			c.Credentials = []group.Credential{signHubs(t, period, periodKey, hubKey, 4)}
		}, "older"},
	} {
		before, from := f.state(), f.fromNow()
		holder := keyB
		if tc.name == "another group's WireGuard key" {
			holder = keyA
		}
		c, a := rawClaim(t, f, pin, tc.cert, tc.key, holder, tc.edit)
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

	// The loopback's wide network has added all the credentials' versions
	// it may, and its network brought all the records it may: a new period
	// and a group with new records are refused and change nothing.
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
	for _, size := range []int{8 << 10, 256} {
		// The network is full within its share in records of this size.
		bound := networkRecordBytes/size + 1
		i := 0
		for ; i < bound && f.memory.room("filler", netip.MustParseAddr("127.0.0.1"), fakeRecords(1, size)) == nil; i++ {
			f.memory.keep(fmt.Sprintf("filler %d %d", size, i/30), netip.MustParseAddr("127.0.0.1"), fakeRecords(1, size))
		}
		if i == bound {
			t.Fatalf("the network kept %d records of %d bytes and was not refused", i, size)
		}
	}
	period2, periodKey2, hubKey2, hubCert2 := newPeriod(t, now)
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		edit func(*claim, tls.ConnectionState)
		why  string
	}{
		{"a new period past the wide network's share", hubCert2, func(c *claim, _ tls.ConnectionState) {
			c.Credentials = []group.Credential{signHubs(t, period2, periodKey2, hubKey2, 1)}
		}, "cannot remember another group"},
		{"records past the network's share", certB, withAdmin(caB.Key, revokes(t, caB, tagB, 3, 4)), "records from this network"},
	} {
		before, from := f.state(), f.fromNow()
		c, a := rawClaim(t, f, pin, tc.cert, keyB.PublicKey().Bytes(), keyB, tc.edit)
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
	certD, _, caD := member(t)
	keyD := wgKey()
	tc, a = rawClaim(t, f, pin, certD, keyD.PublicKey().Bytes(), keyD, withAdmin(caD.Key, nil))
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	open = append(open, tc)
	before := f.state()
	certE, _, caE := member(t)
	keyE := wgKey()
	if _, a := rawClaim(t, f, pin, certE, keyE.PublicKey().Bytes(), keyE, withAdmin(caE.Key, nil)); !strings.Contains(a.Error, "full") {
		t.Errorf("a group past the forwarder's bound: %q", a.Error)
	}
	if after := f.state(); after != before {
		t.Errorf("a refused group changed the forwarder\nbefore:\n%s\nafter:\n%s", before, after)
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

// revokes returns n revoke records of the group ca, each naming keys keys.
func revokes(t *testing.T, ca *group.CA, tag string, n, keys int) []group.Record {
	t.Helper()
	var recs []group.Record
	for range n {
		var hs []group.KeyHash
		for range keys {
			var h group.KeyHash
			rand.Read(h[:])
			hs = append(hs, h)
		}
		r := grouptest.Sign(t, group.RecordBody{Type: group.RecordRevoke, Group: tag, TimeMS: time.Now().UnixMilli(), Keys: hs}, ca.Key)
		recs = append(recs, r)
	}
	return recs
}

// newPeriod returns a period of a new group, its period key, and a hub's
// server key with its certificate.
func newPeriod(t *testing.T, now time.Time) (*group.CredentialBody, *ecdsa.PrivateKey, *ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	root, err := group.NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	periodKey, _ := group.NewKey()
	tag, _ := group.NewPeriodTag()
	pc, err := group.SignPeriod(group.Tag(root.Cert), tag, &periodKey.PublicKey, 1, now, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	period, _ := pc.Open()
	hubKey, _ := group.NewKey()
	hub, err := group.ServerCertificate(hubKey)
	if err != nil {
		t.Fatal(err)
	}
	return period, periodKey, hubKey, hub
}

// signHubs is the period's hubs' credential at version v, listing hub,
// signed by key.
func signHubs(t *testing.T, period *group.CredentialBody, key, hub *ecdsa.PrivateKey, v uint64) group.Credential {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&hub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := group.SignHubs(period, []group.KeyHash{sha256.Sum256(spki)}, nil, v, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The networks of one wide network, however many, add no more than their
// wide network's share of the credentials' versions: the table keeps room
// for the new period of a group from elsewhere.
func TestVersionsWideNetworkLeavesRoom(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	expires := now.Add(group.PeriodLifetime)
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
		expires := now.Add(group.PeriodLifetime)
		// Groups that came first, from wide networks of their own.
		first := map[*group.Presented]netip.Addr{}
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

// The memory keeps every envelope of a record: the same body under another
// signer is a record of its own, which a group's records keep.
func TestMemoryKeepsEveryEnvelope(t *testing.T) {
	m := newMemory(nil)
	a := fakeRecords(1, 100)[0]
	b := a
	b.Sig = []byte{2}
	m.keep("g", noSource, []group.Record{a})
	m.keep("g", noSource, []group.Record{b, a})
	if _, n, _ := m.total(); n != 2 {
		t.Errorf("the memory keeps %d envelopes of one body, want 2", n)
	}
}

// The wide networks of one IPv6 provider, however many, add no more than
// the provider's share of the credentials' versions, so a provider's
// customers cannot fill the table between them.
func TestVersionsProviderLeavesRoom(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	expires := now.Add(group.PeriodLifetime)
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

// The records that the registrations from one network and one wide
// network bring are bounded, registered groups or not, and a registration
// past that is refused before anything is kept.
func TestMemoryChargesTheSource(t *testing.T) {
	m := newMemory(func(string) bool { return true })
	from := netip.MustParseAddr("2001:db8:5::7")
	// Each registration brings 30 records of 8 KiB: the network is
	// refused within its share and one more, which bounds the loop.
	kept, refused := 0, false
	for i := 0; i <= networkRecordBytes/(30*(8<<10))+1; i++ {
		recs := fakeRecords(30, 8<<10)
		tag := fmt.Sprintf("g%d", i)
		if m.room(tag, from, recs) != nil {
			refused = true
			break
		}
		m.keep(tag, from, recs)
		kept++
	}
	if !refused {
		t.Fatalf("one network kept %d registrations and was not refused", kept)
	}
	if _, _, n := m.total(); n > networkRecordBytes {
		t.Errorf("one network brought %d bytes, limit %d", n, networkRecordBytes)
	}
	if kept == 0 {
		t.Fatal("one network kept nothing")
	}
	if err := m.room("other", netip.MustParseAddr("2001:db8:6::7"), fakeRecords(30, 8<<10)); err != nil {
		t.Errorf("another network refused: %v", err)
	}
}

// The records that the networks of one wide network bring are bounded by
// the wide network, even when each network brings less than its own
// share: five networks of one IPv6 /48 bring all they may, and together
// they keep no more than wideRecordBytes; another wide network still
// brings records.
func TestMemoryChargesTheWideNetwork(t *testing.T) {
	const networks = 5
	if networks*networkRecordBytes <= wideRecordBytes {
		t.Fatal("the networks must be able to bring more than the wide network's share")
	}
	m := newMemory(func(string) bool { return true })
	body := make([]byte, 8<<10)
	// A registration of 30 records of 8 KiB; a network is refused within
	// its share and one more, which bounds each loop.
	per := 30
	bound := networkRecordBytes/(per*len(body)) + 2
	for n := range networks {
		from := netip.MustParseAddr(fmt.Sprintf("2001:db8:7:%x::7", n))
		refused := false
		for i := 0; i < bound; i++ {
			recs := sharedRecords(per, len(body), body)
			tag := fmt.Sprintf("g%d %d", n, i)
			if m.room(tag, from, recs) != nil {
				refused = true
				break
			}
			m.keep(tag, from, recs)
		}
		if !refused {
			t.Fatalf("network %d was not refused", n)
		}
	}
	if _, _, n := m.total(); n > wideRecordBytes {
		t.Errorf("the networks of one wide network brought %d bytes, limit %d", n, wideRecordBytes)
	}
	if err := m.room("other", netip.MustParseAddr("2001:db8:8::7"), fakeRecords(per, len(body))); err != nil {
		t.Errorf("another wide network refused: %v", err)
	}
}

// sharedRecords returns n records of about size bytes each that share one
// body, each its own envelope: they cost the memory as much as n bodies
// would, without the test holding them.
func sharedRecords(n, size int, body []byte) []group.Record {
	rs := make([]group.Record, n)
	for i := range rs {
		sig := make([]byte, 16)
		rand.Read(sig)
		rs[i] = group.Record{Body: body[:size], Sig: sig}
	}
	return rs
}

// The records of a genuine group that is away are not pushed out by the
// groups of other networks: not while those are registered, since only
// the groups that are away share the bound, nor once they leave, since
// past it the wide network that holds the most gives up its groups first.
// Strangers from many wide networks, each bringing all it may, register
// groups with records, in random order with a fixed seed, and then leave.
func TestMemoryKeepsGroupsThatAreAway(t *testing.T) {
	registered := map[string]bool{}
	m := newMemory(func(tag string) bool { return registered[tag] })
	genuine := netip.MustParseAddr("198.51.100.7")
	m.keep("genuine", genuine, fakeRecords(5, 1<<10))
	body := make([]byte, 8<<10)
	rng := mrand.New(mrand.NewPCG(4, 2026))
	var strangers []string
	// A registration brings at least one record of more than 64 bytes, so
	// a wide network is refused within wideRecordBytes/64 of them.
	for w := 0; w < 3*rememberedBytes/wideRecordBytes; w++ {
		refused := false
		for i := 0; i < wideRecordBytes/64; i++ {
			from := netip.AddrFrom4([4]byte{byte(10 + w), 7, byte(rng.IntN(256)), 1})
			tag := fmt.Sprintf("stranger %d %d", w, i)
			recs := sharedRecords(1+rng.IntN(30), 1+rng.IntN(len(body)), body)
			if m.room(tag, from, recs) != nil {
				refused = true
				break
			}
			registered[tag] = true
			m.keep(tag, from, recs)
			strangers = append(strangers, tag)
		}
		if !refused {
			t.Fatalf("wide network %d was not refused", w)
		}
	}
	if n := len(m.records("genuine")); n != 5 {
		t.Fatalf("while strangers are registered a group that is away keeps %d records, want 5", n)
	}
	rng.Shuffle(len(strangers), func(i, j int) { strangers[i], strangers[j] = strangers[j], strangers[i] })
	for _, tag := range strangers {
		delete(registered, tag)
		m.left(tag)
		m.mu.Lock()
		over := m.awayBytes > rememberedBytes
		m.mu.Unlock()
		if over {
			t.Fatalf("the groups that are away take %d bytes, limit %d", m.awayBytes, rememberedBytes)
		}
	}
	if n := len(m.records("genuine")); n != 5 {
		t.Errorf("after strangers left a group that is away keeps %d records, want 5", n)
	}
	// A group that registers again is no longer away, and the bytes of the
	// groups that are away are what they hold.
	registered["genuine"] = true
	m.keep("genuine", genuine, nil)
	m.mu.Lock()
	defer m.mu.Unlock()
	sum := 0
	for _, g := range m.groups {
		if g.holder != nil {
			sum += g.bytes
		}
	}
	if m.groups["genuine"].holder != nil || sum != m.awayBytes {
		t.Errorf("the groups that are away hold %d bytes, counted %d; genuine away: %v", sum, m.awayBytes, m.groups["genuine"].holder != nil)
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
	expires := now.Add(group.PeriodLifetime)
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
