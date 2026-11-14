// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

func newGroup(t *testing.T) *group.CA {
	t.Helper()
	ca, err := group.NewGroupCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// device is a member of a group as the relay sees it: its certificate with
// the chain, its ID and its WireGuard key.
type device struct {
	cert    tls.Certificate
	id      string
	key     tunnel.Key
	records []group.Record
	cred    *Credentialed // registers with credentials; id is then its pseudonym
}

func newDevice(t *testing.T, ca *group.CA) device {
	t.Helper()
	now := time.Now()
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	id := group.NewDeviceID()
	leaf, err := ca.IssueMember(id, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	wg, err := tunnel.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return device{cert: tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, id: string(id), key: wg}
}

func startRelay(t *testing.T, groups ...*group.CA) (running, Link) {
	t.Helper()
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, g := range groups {
		tags = append(tags, group.Tag(g.Cert))
	}
	return startWith(t, Config{Keys: keys, Groups: tags})
}

// joined is a member's link to the relay in a test: it echoes each line it
// is sent on a connection it answers, and reports what happens.
type joined struct {
	mu      sync.Mutex
	reports []Report
	called  chan string
	dialed  chan string
	stop    context.CancelFunc
	done    chan struct{}
}

func (j *joined) last() Report {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.reports) == 0 {
		return Report{}
	}
	return j.reports[len(j.reports)-1]
}

// join starts d's link; a dialed connection sends "hello from <id>" and
// expects it back.
func join(t *testing.T, link Link, d device) *joined {
	t.Helper()
	j := &joined{called: make(chan string, 8), dialed: make(chan string, 8), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	j.stop = cancel
	cfg := MemberConfig{
		Link: link, Self: d.id, Key: d.key,
		Cert:    func() tls.Certificate { return d.cert },
		Records: func() []group.Record { return d.records },
		Credentialed: func() (Credentialed, bool) {
			if d.cred == nil {
				return Credentialed{}, false
			}
			return *d.cred, true
		},
		Want: func(string) bool { return true },
		Dialed: func(ctx context.Context, peer string, c net.Conn) error {
			msg := "hello from " + d.id + "\n"
			if _, err := c.Write([]byte(msg)); err != nil {
				return err
			}
			got, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return err
			}
			if got != msg {
				return errors.New("a wrong echo " + got)
			}
			j.dialed <- peer
			<-ctx.Done()
			return nil
		},
		Called: func(ctx context.Context, peer string, c net.Conn) error {
			got, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return err
			}
			if got != "hello from "+peer+"\n" {
				return errors.New("a call from someone else: " + got)
			}
			if _, err := c.Write([]byte(got)); err != nil {
				return err
			}
			j.called <- peer
			<-ctx.Done()
			return nil
		},
		Report: func(r Report) {
			j.mu.Lock()
			j.reports = append(j.reports, r)
			j.mu.Unlock()
		},
		Logf: t.Logf,
	}
	go func() {
		defer close(j.done)
		Join(ctx, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		<-j.done
	})
	return j
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func receive(t *testing.T, ch chan string, what string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	// A registration, a WireGuard handshake and a connection through the
	// tunnel take far longer under -race on a loaded runner than they do
	// anywhere else; the wait only says when to give up.
	case <-time.After(time.Minute):
		t.Fatalf("timed out waiting for %s", what)
		return ""
	}
}

func TestThroughRelay(t *testing.T) {
	g := newGroup(t)
	_, link := startRelay(t, g)
	a, b := newDevice(t, g), newDevice(t, g)
	if a.id > b.id {
		a, b = b, a
	}
	ja := join(t, link, a)
	jb := join(t, link, b)
	if got := receive(t, ja.dialed, "a's dial"); got != b.id {
		t.Errorf("a dialed %s, want %s", got, b.id)
	}
	if got := receive(t, jb.called, "b's answer"); got != a.id {
		t.Errorf("b was called by %s, want %s", got, a.id)
	}
	waitFor(t, "both count the connection", func() bool {
		ra, rb := ja.last(), jb.last()
		return ra.Connected && rb.Connected && ra.Through == 1 && rb.Through == 1 &&
			slices.Equal(ra.Online, []string{b.id}) && slices.Equal(rb.Online, []string{a.id})
	})
	select {
	case p := <-jb.dialed:
		t.Errorf("the higher ID dialed %s too", p)
	default:
	}

	// When b goes, a hears it and its connection ends.
	jb.stop()
	<-jb.done
	waitFor(t, "a sees b gone", func() bool {
		r := ja.last()
		return r.Connected && len(r.Online) == 0 && r.Through == 0
	})
}

func TestGroupsApart(t *testing.T) {
	g1, g2 := newGroup(t), newGroup(t)
	r, link := startRelay(t, g1, g2)
	a, c := newDevice(t, g1), newDevice(t, g2)
	ja := join(t, link, a)
	jc := join(t, link, c)
	waitFor(t, "both registered", func() bool {
		_, n := r.Stats()
		return n == 2 && ja.last().Connected && jc.last().Connected
	})
	time.Sleep(200 * time.Millisecond)
	if o := ja.last().Online; len(o) != 0 {
		t.Errorf("a sees %v of another group", o)
	}

	// Asked by hand, the relay does not join a to the other group's
	// device either.
	cl, stop := rawTunnel(t, link, newDevice(t, g1))
	defer stop()
	conn, err := cl.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeLine(conn, request{Dial: c.id}, time.Second); err != nil {
		t.Fatal(err)
	}
	var n note
	if err := readLine(conn, &n, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n.OK || !strings.Contains(n.Error, "not on the relay") {
		t.Errorf("a dial to another group's device: %+v", n)
	}
}

// rawTunnel registers d and brings its tunnel up, without a watch.
func rawTunnel(t *testing.T, link Link, d device) (*tunnel.Client, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := MemberConfig{Link: link, Self: d.id, Key: d.key, Cert: func() tls.Certificate { return d.cert }}
	tc, w, _, err := register(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var relayKey, psk tunnel.Key
	copy(relayKey[:], w.Key)
	copy(psk[:], w.PSK)
	cl, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: d.key, PresharedKey: psk, Addr: netip.MustParseAddr(w.Addr),
		HubPublicKey: relayKey, HubAddr: Addr, Endpoint: link.Endpoint})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return cl, func() {
		cl.Close()
		tc.Close()
		cancel()
	}
}

func TestRefused(t *testing.T) {
	g, other := newGroup(t), newGroup(t)
	r, link := startRelay(t, g)
	ctx := context.Background()

	stranger := newDevice(t, other)
	_, _, _, err := register(ctx, MemberConfig{Link: link, Key: stranger.key, Cert: func() tls.Certificate { return stranger.cert }})
	if err == nil {
		t.Error("a device of a group the relay does not serve registered")
	}

	d := newDevice(t, g)
	bad := link
	bad.Pin = strings.Repeat("A", 43) + "="
	_, _, _, err = register(ctx, MemberConfig{Link: bad, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
	if err == nil || !strings.Contains(err.Error(), "not the one given") {
		t.Errorf("a wrong pin: %v", err)
	}

	tc, _, _, err := register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	thief := newDevice(t, g)
	_, _, _, err = register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return thief.cert }})
	if err == nil || !strings.Contains(err.Error(), "another device") {
		t.Errorf("another device with the same WireGuard key: %v", err)
	}

	// The same device registering again takes the place of the first.
	tc2, _, _, err := register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
	if err != nil {
		t.Fatal(err)
	}
	defer tc2.Close()
	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tc.Read(make([]byte, 1)); err == nil {
		t.Error("the first registration still holds")
	}
	if _, n := r.Stats(); n != 1 {
		t.Errorf("the relay holds %d devices, want 1", n)
	}
}

// TestOpenRelay: an open relay serves any group that registers, within
// its limits on groups and on registrations from one address.
func TestOpenRelay(t *testing.T) {
	r, link := startWith(t, Config{Open: true, Limits: Limits{Groups: 2, PerAddress: 3}})
	ctx := context.Background()
	reg := func(d device) error {
		tc, _, _, err := register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
		if err == nil {
			t.Cleanup(func() { tc.Close() })
		}
		return err
	}
	g1, g2, g3 := newGroup(t), newGroup(t), newGroup(t)
	for _, g := range []*group.CA{g1, g2} {
		if err := reg(newDevice(t, g)); err != nil {
			t.Fatalf("a group of its own on an open relay: %v", err)
		}
	}
	if err := reg(newDevice(t, g3)); err == nil || !strings.Contains(err.Error(), "as many groups") {
		t.Errorf("a third group on a relay for two: %v", err)
	}
	if err := reg(newDevice(t, g1)); err != nil {
		t.Fatalf("a second device of a group already there: %v", err)
	}
	// Every registration here comes from 127.0.0.1.
	if err := reg(newDevice(t, g2)); err == nil || !strings.Contains(err.Error(), "this network") {
		t.Errorf("a fourth registration from one address: %v", err)
	}
	if g, n := r.Stats(); g != 2 || n != 3 {
		t.Errorf("the relay holds %d groups and %d devices, want 2 and 3", g, n)
	}
	if bin := Binary(); bin != "" {
		if _, err := Start(bin, Config{Open: true, Groups: []string{group.Tag(g1.Cert)}}); err == nil {
			t.Error("an open relay with groups given")
		}
		if _, err := Start(bin, Config{}); err == nil {
			t.Error("a relay for no group")
		}
		if _, err := Start(bin, Config{Groups: []string{"nope"}}); err == nil {
			t.Error("a relay for a bad tag")
		}
	}
}

// TestRemovedDevice checks that the records one member sends make the relay
// drop, and then refuse, a device its group removed.
func TestRemovedDevice(t *testing.T) {
	ca := newGroup(t)
	_, link := startRelay(t, ca)
	recs := deviceRecords(t, ca, 2)
	gone, stays := listedDevice(t, ca, recs), listedDevice(t, ca, recs)
	j := join(t, link, gone)
	waitFor(t, "the device to connect", func() bool { return j.last().Connected })
	revoke := grouptest.Sign(t, group.RecordBody{Type: group.RecordRevoke, Group: group.Tag(ca.Cert), TimeMS: time.Now().UnixMilli(),
		Keys: []group.KeyHash{group.KeyHashOf(gone.cert.Leaf)}}, ca.Key)
	stays.records = append(recs, revoke)
	k := join(t, link, stays)
	waitFor(t, "the other device to connect", func() bool { return k.last().Connected })
	waitFor(t, "the removed device to be refused", func() bool {
		r := j.last()
		return !r.Connected && r.Err != nil && strings.Contains(r.Err.Error(), "removed")
	})
}

// TestRemovedAdmin checks that the relay goes by the whole certificate
// chain: once the records it holds remove an admin, it drops the devices
// the removal names, keeps the others that admin certified, whose records
// stay, and refuses a device the removed admin lists afterwards.
func TestRemovedAdmin(t *testing.T) {
	root, err := group.NewRootCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tag := group.Tag(root.Cert)
	_, link := startRelay(t, root)
	adminKey, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	adminDev := newDevice(t, root)
	adminCert, err := root.IssueAdmin(group.DeviceID(adminDev.id), &adminKey.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	admin := &group.CA{Cert: adminCert, Key: adminKey}
	adminHash, adminDevKey := group.KeyHashOf(adminCert), group.KeyHashOf(adminDev.cert.Leaf)
	recs := []group.Record{grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: tag, TimeMS: time.Now().UnixMilli(),
		Device: adminDev.id, Name: "admin", Role: group.RolePhone, Key: &adminDevKey, Admin: &adminHash,
		Powers: authority.Powers, Commands: authority.Commands}, root.Key)}
	// certified is a device the admin admits, with the admin's record of it.
	certified := func() (device, group.Record) {
		d := newDevice(t, admin)
		d.cert.Certificate = append(d.cert.Certificate, root.Cert.Raw)
		k := group.KeyHashOf(d.cert.Leaf)
		r := grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: tag, TimeMS: time.Now().UnixMilli(),
			Device: d.id, Name: "pc", Role: group.RoleMember, Caps: group.AllCaps, Key: &k}, admin.Key, adminCert)
		return d, r
	}
	gone, goneRec := certified()
	kept, keptRec := certified()
	recs = append(recs, goneRec, keptRec)
	jg, jk := join(t, link, gone), join(t, link, kept)
	waitFor(t, "the admin's devices to connect", func() bool { return jg.last().Connected && jk.last().Connected })

	revoke := grouptest.Sign(t, group.RecordBody{Type: group.RecordRevoke, Group: tag, TimeMS: time.Now().UnixMilli(),
		Keys: []group.KeyHash{adminHash, adminDevKey, group.KeyHashOf(gone.cert.Leaf)}}, root.Key)
	stays := newDevice(t, root)
	staysKey := group.KeyHashOf(stays.cert.Leaf)
	own := grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: tag, TimeMS: time.Now().UnixMilli(),
		Device: stays.id, Name: "root phone", Role: group.RolePhone, Key: &staysKey, HoldsRoot: true}, root.Key)
	stays.records = append(slices.Clip(recs), own, revoke)
	js := join(t, link, stays)
	waitFor(t, "the root's device to connect", func() bool { return js.last().Connected })
	waitFor(t, "the removed device to be refused", func() bool {
		r := jg.last()
		return !r.Connected && r.Err != nil && strings.Contains(r.Err.Error(), "removed")
	})
	if r := jk.last(); !r.Connected {
		t.Errorf("the device whose record stays: %+v", r)
	}
	fresh, freshRec := certified()
	fresh.records = []group.Record{freshRec}
	jf := join(t, link, fresh)
	waitFor(t, "a device the removed admin listed later to be refused", func() bool {
		r := jf.last()
		return !r.Connected && r.Err != nil && strings.Contains(r.Err.Error(), "the admin that certified the device was removed")
	})
}

// TestRefusedGroupsList: a group on the operator's list cannot register,
// one put on it is dropped within ten seconds, and the others go on
// (docs/relay-budget.md, "Abuse reports"; the forwarder's
// TestRefusedGroups).
func TestRefusedGroupsList(t *testing.T) {
	g1, g2, g3 := newGroup(t), newGroup(t), newGroup(t)
	list := filepath.Join(t.TempDir(), "refused-groups")
	if err := os.WriteFile(list, []byte("# reported\n"+group.Tag(g1.Cert)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, link := startWith(t, Config{Keys: keys, Groups: []string{group.Tag(g1.Cert), group.Tag(g2.Cert), group.Tag(g3.Cert)}, Refused: list})
	ctx := context.Background()
	reg := func(d device) (net.Conn, error) {
		tc, _, _, err := register(ctx, MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
		if err == nil {
			t.Cleanup(func() { tc.Close() })
		}
		return tc, err
	}
	if _, err := reg(newDevice(t, g1)); err == nil || !strings.Contains(err.Error(), "refuses this group") {
		t.Fatalf("a refused group: %v", err)
	}
	if _, err := reg(newDevice(t, g2)); err != nil {
		t.Fatalf("a group not on the list: %v", err)
	}
	if _, err := reg(newDevice(t, g3)); err != nil {
		t.Fatalf("a group not on the list: %v", err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.WriteFile(list, []byte(group.Tag(g2.Cert)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(list, later, later); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if g, _ := r.Stats(); g == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the group put on the list was not dropped")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := reg(newDevice(t, g1)); err != nil {
		t.Fatalf("a group taken off the list: %v", err)
	}
}

// TestManyDevicesThroughRelay: the relay passes the connections of more
// devices at once than one device's hub holds, each with its watch and a
// call to the other device of its group.
func TestManyDevicesThroughRelay(t *testing.T) {
	const groups = 20
	var cas []*group.CA
	var tags []string
	for range groups {
		ca := newGroup(t)
		cas = append(cas, ca)
		tags = append(tags, group.Tag(ca.Cert))
	}
	keys, err := NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, link := startWith(t, Config{Keys: keys, Groups: tags})
	var all []*joined
	for _, ca := range cas {
		for range 2 {
			all = append(all, join(t, link, newDevice(t, ca)))
		}
	}
	for i, j := range all {
		select {
		case <-j.dialed:
		case <-j.called:
		case <-time.After(2 * time.Minute):
			t.Fatalf("device %d of %d made no call through the relay", i+1, len(all))
		}
	}
}
