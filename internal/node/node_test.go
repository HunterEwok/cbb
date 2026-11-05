// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
	"github.com/HunterEwok/cbb/internal/hlc"
	signed "github.com/HunterEwok/cbb/internal/release"
	"github.com/HunterEwok/cbb/internal/seal"
	"github.com/HunterEwok/cbb/internal/testnet"
	"github.com/HunterEwok/cbb/internal/uptime"
)

func socketPair(t *testing.T) (net.Conn, net.Conn) { return testnet.SocketPair(t) }

// clock is an uptime clock a test moves by hand.
type clock struct{ d atomic.Int64 }

func (c *clock) now() time.Duration      { return time.Duration(c.d.Load()) }
func (c *clock) advance(d time.Duration) { c.d.Add(int64(d)) }

// member is a node with its engine and the writes it received.
type member struct {
	*Node
	t      *testing.T
	id     *group.Identity
	engine *clip.Engine
	writes chan Write
	peers  chan int // len(Peers()) at each OnPeers call
}

var (
	adminOnce sync.Once
	admin     *group.Identity
)

type option func(*clip.Config, *Config)

// withUptime gives the engine and the node one clock the test moves.
func withUptime(c *clock) option {
	return func(ec *clip.Config, nc *Config) { ec.Uptime, nc.Uptime = c.now, c.now }
}

// withNodeUptime gives only the node a clock, which measures queue times.
func withNodeUptime(f func() time.Duration) option {
	return func(_ *clip.Config, nc *Config) { nc.Uptime = f }
}

func withTimers(ping, timeout time.Duration) option {
	return func(_ *clip.Config, nc *Config) { nc.PingEvery, nc.Timeout = ping, timeout }
}

// ensureAdmin creates the group all test members belong to.
func ensureAdmin() {
	adminOnce.Do(func() {
		var err error
		if admin, err = group.Create(time.Now()); err != nil {
			panic(err)
		}
	})
}

func newMember(t *testing.T, role Role, opts ...option) *member {
	t.Helper()
	ensureAdmin()
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	devID := group.NewDeviceID()
	cert, err := admin.GroupCA.IssueMember(devID, &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := &group.Identity{ID: devID, Key: key, Cert: cert, GroupCA: group.CA{Cert: admin.GroupCA.Cert}}
	m := &member{t: t, id: id, writes: make(chan Write, 1024), peers: make(chan int, 1024)}
	secret := testReaders.add(t, devID)
	ec := clip.Config{Self: string(devID), Clock: hlc.NewClock(nil, hlc.Timestamp{}, nil), Seal: func(ev clip.Event) (*clip.Sealed, error) {
		// The node passes a copy's blob on by its name alone; these tests
		// fetch parts by their own hashes.
		var blob *clip.Blob
		if ev.Media != nil && ev.Media.Size > 0 {
			blob = &clip.Blob{Size: clip.BlobSize(ev.Media.Size), SHA256: make([]byte, sha256.Size)}
		}
		return clip.SealCopy(ev.ID, ev.Origin, ev.Time, cert.Raw, nil, testReaders.of(t), clip.Content{Kind: ev.Kind, Via: ev.Via, Text: ev.Text, Media: ev.Media}, blob, clip.NewKey(), key)
	}}
	nc := Config{
		Identity: id, Role: role,
		TakeCopy:  func(_ group.DeviceID, s *clip.Sealed) (clip.Event, error) { return takeTestCopy(s, devID, secret) },
		OnWrite:   func(w Write) { m.writes <- w },
		PingEvery: 50 * time.Millisecond, Timeout: 300 * time.Millisecond,
		Logf: t.Logf,
	}
	for _, o := range opts {
		o(&ec, &nc)
	}
	m.engine = clip.New(ec)
	nc.Engine = m.engine
	nc.OnPeers = func() { m.peers <- len(m.Peers()) }
	m.Node = New(nc)
	t.Cleanup(m.Close)
	return m
}

// testReaders are, for each test, its members, which its copies are sealed
// to, as the records of a group would give.
var testReaders = readerSet{readers: map[string][]clip.Reader{}}

type readerSet struct {
	mu      sync.Mutex
	readers map[string][]clip.Reader // by the test's name
}

// add makes a secret for sealed messages for dev, a member of the test t,
// and adds it to the test's readers.
func (r *readerSet) add(t *testing.T, dev group.DeviceID) []byte {
	t.Helper()
	secret, err := seal.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := seal.PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.readers[t.Name()] = append(r.readers[t.Name()], clip.Reader{ID: string(dev), Seal: pub})
	return secret
}

func (r *readerSet) of(t *testing.T) []clip.Reader {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.readers[t.Name()])
}

// takeTestCopy checks a copy as a member of the tests' group, which keeps
// no records: the copy's own certificate must be from the group CA and
// have signed it.
func takeTestCopy(s *clip.Sealed, me group.DeviceID, secret []byte) (clip.Event, error) {
	if err := s.Validate(); err != nil {
		return clip.Event{}, err
	}
	cert, err := x509.ParseCertificate(s.Cert)
	if err != nil || cert.CheckSignatureFrom(admin.GroupCA.Cert) != nil || !s.Verifies(cert) {
		return clip.Event{}, errors.New("the copy is not from a member, or not signed by it")
	}
	ev, _ := clip.EventOf(s, string(me), secret)
	return ev, nil
}

// link connects client to server and returns channels with the result of
// each side's Serve.
func link(t *testing.T, client, server *member) (clientDone, serverDone chan error) {
	t.Helper()
	return linkCtx(t, context.Background(), client, server)
}

func linkCtx(t *testing.T, ctx context.Context, client, server *member) (clientDone, serverDone chan error) {
	t.Helper()
	a, b := socketPair(t)
	clientDone, serverDone = make(chan error, 1), make(chan error, 1)
	go func() {
		serverDone <- server.Serve(context.Background(), tls.Server(b, server.ServerTLS()))
	}()
	go func() {
		clientDone <- client.run(ctx, tls.Client(a, client.id.ClientTLS(server.id.ID, group.TLSOptions{})), true)
	}()
	return clientDone, serverDone
}

func wait(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

func waitPeers(t *testing.T, m *member, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(m.Peers()) != n {
		if time.Now().After(deadline) {
			t.Fatalf("%s has %d peers, want %d", m.id.ID, len(m.Peers()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitWrite(t *testing.T, m *member, text string) Write {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case w := <-m.writes:
			if w.Text == text {
				return w
			}
		case <-timeout:
			t.Fatalf("%s never wrote %q", m.id.ID, text)
		}
	}
}

func noWrite(t *testing.T, m *member, text string, d time.Duration) {
	t.Helper()
	timeout := time.After(d)
	for {
		select {
		case w := <-m.writes:
			if w.Text == text {
				t.Errorf("%s wrote %q", m.id.ID, text)
				return
			}
		case <-timeout:
			return
		}
	}
}

// raw is a hand-driven peer: TLS with a member certificate, and frames the
// test writes and reads itself.
type raw struct {
	t    *testing.T
	tc   *tls.Conn
	done chan error // the node's Serve
}

func rawPeer(t *testing.T, node, as *member) *raw {
	t.Helper()
	a, b := socketPair(t)
	r := &raw{t: t, done: make(chan error, 1)}
	go func() { r.done <- node.Serve(context.Background(), tls.Server(b, node.ServerTLS())) }()
	r.tc = tls.Client(a, as.id.ClientTLS(node.id.ID, group.TLSOptions{}))
	if err := r.tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *raw) send(m *message) {
	r.t.Helper()
	f, err := frame(m)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.tc.Write(f); err != nil {
		r.t.Fatal(err)
	}
}

func (r *raw) hello(h clip.Hello) {
	r.t.Helper()
	out := struct {
		Wall    int64 `json:"wall_ms"`
		Current any   `json:"current,omitempty"`
	}{Wall: h.Wall}
	if h.Current != nil {
		out.Current = wireOf(*h.Current)
	}
	data, _ := json.Marshal(out)
	r.send(&message{Type: typeHello, Role: Full, Hello: data})
}

func (r *raw) event(ev clip.Event) {
	r.t.Helper()
	data, _ := json.Marshal(wireOf(ev))
	r.send(&message{Type: typeEvent, Event: data})
}

// frames reads frames for d and returns them.
func (r *raw) frames(d time.Duration) []*message {
	var out []*message
	deadline := time.Now().Add(d)
	for {
		r.tc.SetReadDeadline(deadline)
		m, err := readMessage(r.tc, time.Until(deadline))
		if err != nil {
			return out
		}
		out = append(out, m)
	}
}

var eventClock = hlc.NewClock(nil, hlc.Timestamp{}, nil)

// newEvent makes an event with a timestamp after every earlier one.
func newEvent(origin *member, text string) clip.Event {
	ev := clip.Event{ID: clip.NewID(), Origin: string(origin.id.ID), Time: eventClock.Now(), Kind: clip.Text, Text: text}
	s, err := clip.SealCopy(ev.ID, ev.Origin, ev.Time, origin.id.Cert.Raw, nil, testReaders.of(origin.t),
		clip.Content{Kind: ev.Kind, Text: text}, nil, clip.NewKey(), origin.id.Key)
	if err != nil {
		panic(err)
	}
	ev.Sealed = s
	return ev
}

// wireOf is an event as it travels: its sealed copy with its age, or, for
// a test of what a member refuses, the event in the open.
func wireOf(ev clip.Event) any {
	if ev.Sealed == nil {
		return ev
	}
	s := *ev.Sealed
	s.Age = ev.Age
	return s
}

func TestCopyReachesTheOtherMember(t *testing.T) {
	// The Pi's hello says what it is; the invalid version is dropped.
	device := func(_ *clip.Config, c *Config) {
		c.Device = group.DeviceInfo{Form: "board", OSVersion: "Debian 13", Version: "bad\x00", MAC: "dc:a6:32:00:00:01"}
		c.Actions = func() []string { return []string{"lock", "Not A Name", "backup"} }
	}
	mac, pi := newMember(t, Full), newMember(t, Full, device)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	waitPeers(t, pi, 1)
	if p := mac.Peers()[0]; p.ID != pi.id.ID || p.Role != Full ||
		p.Device != (group.DeviceInfo{Form: "board", OSVersion: "Debian 13", MAC: "dc:a6:32:00:00:01"}) {
		t.Errorf("the Mac sees %+v", p)
	}
	if p := mac.Peers()[0]; strings.Join(p.Actions, ",") != "lock,backup" {
		t.Errorf("the Mac sees the actions %q", p.Actions)
	}
	if p := pi.Peers()[0]; !p.Device.IsZero() {
		t.Errorf("the Pi sees a device %+v from a hello without one", p.Device)
	}
	if ok, err := mac.Copied("hello from the Mac", clip.Text, clip.Copy); err != nil || !ok {
		t.Fatalf("Copied = %v, %v", ok, err)
	}
	w := waitWrite(t, pi, "hello from the Mac")
	if w.Kind != clip.Text || w.Seq == 0 {
		t.Errorf("write %+v", w)
	}
	if err := pi.Send("hello from tmux", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, pi, "hello from tmux") // the member's own clipboard
	waitWrite(t, mac, "hello from tmux")
}

func TestSecretsKeepTheirKind(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	if _, err := mac.Copied("hunter2", clip.Secret, clip.Copy); err != nil {
		t.Fatal(err)
	}
	if w := waitWrite(t, pi, "hunter2"); w.Kind != clip.Secret {
		t.Errorf("a secret was written as %v", w.Kind)
	}
	if err := pi.Send("otp 123456", clip.Secret, clip.Copy); err != nil {
		t.Fatal(err)
	}
	if w := waitWrite(t, pi, "otp 123456"); w.Kind != clip.Secret {
		t.Errorf("the member's own secret was written as %v", w.Kind)
	}
}

func TestHelloCarriesAnOldTextAfterRejoin(t *testing.T) {
	// A text copied long ago reaches a member that was away, and only
	// then: a member that merely lost its peers keeps its clipboard.
	for _, rejoin := range []bool{true, false} {
		t.Run(fmt.Sprintf("rejoin=%v", rejoin), func(t *testing.T) {
			var c clock
			c.advance(time.Hour)
			mac, pi := newMember(t, Full, withUptime(&c)), newMember(t, Full, withUptime(&c))
			if _, err := pi.Copied("copied long ago", clip.Text, clip.Copy); err != nil {
				t.Fatal(err)
			}
			c.advance(2 * time.Minute)
			if rejoin {
				mac.Rejoin()
			}
			link(t, mac, pi)
			waitPeers(t, mac, 1)
			if rejoin {
				waitWrite(t, mac, "copied long ago")
			} else {
				noWrite(t, mac, "copied long ago", 300*time.Millisecond)
			}
			if ev, ok := mac.engine.Current(); !ok || ev.Text != "copied long ago" {
				t.Errorf("the group text did not arrive: %+v", ev)
			}
		})
	}
}

func TestRejoinClosesTheConnectionsFirst(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	cd, _ := link(t, mac, pi)
	waitPeers(t, mac, 1)
	mac.Rejoin()
	if len(mac.Peers()) != 0 {
		t.Errorf("peers after Rejoin: %v", mac.Peers())
	}
	wait(t, cd, "the old connection to end")
}

func TestRejoinHoldsNewConnections(t *testing.T) {
	// A connection that starts while Rejoin waits for the old ones is
	// registered only after the engine knows the member was away.
	mac, pi := newMember(t, Full), newMember(t, Full)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	mac.mu.Lock()
	old := mac.conns[pi.id.ID]
	ch := make(chan struct{})
	mac.rejoining = ch
	mac.mu.Unlock()
	link(t, mac, pi)
	time.Sleep(200 * time.Millisecond)
	mac.mu.Lock()
	cur := mac.conns[pi.id.ID]
	mac.mu.Unlock()
	if cur != nil && cur != old {
		t.Error("a new connection registered during a rejoin")
	}
	mac.mu.Lock()
	mac.rejoining = nil
	mac.mu.Unlock()
	close(ch)
	waitPeers(t, mac, 1)
}

func TestForwardedOnlyToOthers(t *testing.T) {
	// An event that comes in on a connection never goes back out on it.
	pi, mac := newMember(t, Full), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	cur := newEvent(mac, "current of the peer")
	r.hello(clip.Hello{Wall: time.Now().UnixMilli(), Current: &cur})
	r.event(newEvent(mac, "an event"))
	waitWrite(t, pi, "an event")
	for _, m := range r.frames(100 * time.Millisecond) {
		if m.Type == typeEvent {
			t.Errorf("the node sent an event back to its source: %s", m.Event)
		}
	}
}

func TestQueueTimeIsAddedToTheAge(t *testing.T) {
	// The node's clock moves two minutes on every reading, so each queued
	// event waits two minutes.
	var steps atomic.Int64
	slow := func() time.Duration { return uptime.Now() + time.Duration(steps.Add(1))*2*time.Minute }
	mac, pi := newMember(t, Full), newMember(t, Full, withNodeUptime(slow))
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	waitPeers(t, pi, 1)
	if _, err := pi.Copied("queued for a long time", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ev, ok := mac.engine.Current(); ok && ev.Text == "queued for a long time" {
			if ev.Age < 2*60*1000 {
				t.Errorf("age %d ms, want the two minutes in the queue added", ev.Age)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the event never arrived")
		}
		time.Sleep(10 * time.Millisecond)
	}
	noWrite(t, mac, "queued for a long time", 200*time.Millisecond)
}

func TestHelloAfterJoiningTheForwardingSet(t *testing.T) {
	// The connection joins the forwarding set before the engine makes the
	// hello: a copy made in between reaches the peer one way or the other.
	mac, pi := newMember(t, Full), newMember(t, Full)
	pi.mu.Lock()
	link(t, mac, pi)
	time.Sleep(200 * time.Millisecond) // the handshake is done; Serve waits for the lock
	if _, _, err := pi.engine.Copied("made meanwhile", clip.Text, clip.Copy); err != nil {
		pi.mu.Unlock()
		t.Fatal(err)
	}
	pi.mu.Unlock()
	waitWrite(t, mac, "made meanwhile")
}

func TestSilentPeerIsDropped(t *testing.T) {
	pi, mac := newMember(t, Full), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.hello(clip.Hello{Wall: time.Now().UnixMilli()})
	go func() {
		for {
			r.tc.SetReadDeadline(time.Now().Add(time.Minute))
			if _, err := readMessage(r.tc, time.Minute); err != nil {
				return
			}
		}
	}()
	if err := wait(t, r.done, "a silent peer to be dropped"); err == nil {
		t.Error("Serve returned no error for a silent peer")
	}
}

func TestStalledPeerIsDropped(t *testing.T) {
	// A peer that stops reading fills the socket and then the queue; the
	// node drops it instead of waiting.
	pi, mac := newMember(t, Full, withTimers(time.Second, 3*time.Second)), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.hello(clip.Hello{Wall: time.Now().UnixMilli()})
	waitPeers(t, pi, 1)
	start := time.Now()
	text := strings.Repeat("x", 4096)
	for i := range 2000 {
		pi.Copied(fmt.Sprintf("%d %s", i, text), clip.Text, clip.Copy)
	}
	wait(t, r.done, "a stalled peer to be dropped")
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("dropping a stalled peer took %v", d)
	}
}

func TestPingCadence(t *testing.T) {
	// Pings come every PingEvery, so a connection survives a Timeout of
	// three PingEvery, as in production. The node's own Timeout here is
	// longer, so that a stall of this reader on a busy test machine (the
	// FreeBSD VM) does not end the connection; the gaps are checked
	// against three PingEvery below.
	pi, mac := newMember(t, Full, withTimers(100*time.Millisecond, 2*time.Second)), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.hello(clip.Hello{Wall: time.Now().UnixMilli()})
	var last time.Time
	var gaps []time.Duration
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.tc.SetReadDeadline(time.Now().Add(time.Second))
		m, err := readMessage(r.tc, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if m.Type != typePing {
			continue
		}
		if !last.IsZero() {
			gaps = append(gaps, time.Since(last))
		}
		last = time.Now()
		r.send(&message{Type: typePing})
	}
	// Each gap stays under three PingEvery, production's Timeout, which is
	// what keeps the connection;
	// the cadence is the median gap, so that one gap a busy test machine
	// stretched (it measures this reader's scheduling too) does not count
	// as a slow pinger.
	if len(gaps) < 4 {
		t.Fatalf("%d pings in a second, want about 10", len(gaps)+1)
	}
	for _, g := range gaps {
		if g >= 300*time.Millisecond {
			t.Errorf("%v between pings, past the Timeout", g)
		}
	}
	slices.Sort(gaps)
	if m := gaps[len(gaps)/2]; m < 60*time.Millisecond || m > 180*time.Millisecond {
		t.Errorf("the median gap between pings is %v, want about 100 ms (all: %v)", m, gaps)
	}
}

func TestPingsKeepAnIdleConnection(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	cd, sd := link(t, mac, pi)
	waitPeers(t, mac, 1)
	select {
	case err := <-cd:
		t.Fatalf("the client ended: %v", err)
	case err := <-sd:
		t.Fatalf("the server ended: %v", err)
	case <-time.After(time.Second): // more than three timeouts
	}
}

func TestByeEndsTheConnectionAtOnce(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	cd, sd := link(t, mac, pi)
	waitPeers(t, pi, 1)
	// The peer shows in Peers once its hello is read, a moment before the
	// engine takes the hello in.
	deadline := time.Now().Add(5 * time.Second)
	for len(pi.engine.Skews()) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the engine does not count the connection")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	mac.Close()
	// Close waits for its connections: when it returns, Serve is ending.
	select {
	case <-cd:
	case <-time.After(100 * time.Millisecond):
		t.Error("Close returned while its connection was still running")
	}
	if err := wait(t, sd, "the goodbye"); err != nil {
		t.Errorf("Serve after a goodbye: %v", err)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("the goodbye took %v to notice", time.Since(start))
	}
	if len(pi.Peers()) != 0 || len(pi.engine.Skews()) != 0 {
		t.Errorf("after the goodbye: peers %v, engine peers %v", pi.Peers(), pi.engine.Skews())
	}
}

func TestQueuedEventsGoOutBeforeTheGoodbye(t *testing.T) {
	pi, mac := newMember(t, Full), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.hello(clip.Hello{Wall: time.Now().UnixMilli()})
	waitPeers(t, pi, 1)
	for i := range 20 {
		pi.Copied(fmt.Sprintf("last copy %d", i), clip.Text, clip.Copy)
	}
	pi.Close()
	var events int
	var bye bool
	for _, m := range r.frames(time.Second) {
		switch m.Type {
		case typeEvent:
			events++
		case typeBye:
			bye = true
		}
	}
	if events != 20 || !bye {
		t.Errorf("got %d events and goodbye %v, want 20 and a goodbye", events, bye)
	}
}

func TestCancelEndsServe(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	ctx, cancel := context.WithCancel(context.Background())
	cd, _ := linkCtx(t, ctx, mac, pi)
	waitPeers(t, mac, 1)
	cancel()
	wait(t, cd, "Serve to end after cancel")
}

func TestOnPeers(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	_, sd := link(t, mac, pi)
	got := func(want int) {
		t.Helper()
		timeout := time.After(5 * time.Second)
		for {
			select {
			case n := <-pi.peers:
				if n == want {
					return
				}
			case <-timeout:
				t.Fatalf("OnPeers never reported %d peers", want)
			}
		}
	}
	got(1)
	mac.Close()
	wait(t, sd, "the connection to end")
	got(0)
}

func TestReconnectReplacesTheOldConnection(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	cd1, _ := link(t, mac, pi)
	waitPeers(t, pi, 1)
	link(t, mac, pi)
	wait(t, cd1, "the old connection to end")
	waitPeers(t, pi, 1)
	if _, err := mac.Copied("after the reconnect", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, pi, "after the reconnect")
}

func TestTheConnectionTheLowerIDDialedStays(t *testing.T) {
	a, b := newMember(t, Full), newMember(t, Full)
	low, high := a, b
	if b.id.ID < a.id.ID {
		low, high = b, a
	}
	cd, _ := link(t, low, high)
	waitPeers(t, high, 1)
	hd, ld := link(t, high, low)
	if err := wait(t, ld, "the low member to refuse the second connection"); !errors.Is(err, errOtherConn) {
		t.Fatalf("the low member's side of the second connection: %v, want errOtherConn", err)
	}
	wait(t, hd, "the second connection to end")
	select {
	case err := <-cd:
		t.Fatalf("the connection the lower ID dialed ended: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := high.Copied("over the first connection", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, low, "over the first connection")

	// The other way round, the connection the lower ID dials replaces one
	// the higher ID dialed.
	c, d := newMember(t, Full), newMember(t, Full)
	low, high = c, d
	if d.id.ID < c.id.ID {
		low, high = d, c
	}
	first, _ := link(t, high, low)
	waitPeers(t, low, 1)
	link(t, low, high)
	wait(t, first, "the connection the higher ID dialed to end")
}

func TestBadFirstMessage(t *testing.T) {
	pi, mac := newMember(t, Full), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.event(newEvent(mac, "sneaky"))
	if err := wait(t, r.done, "Serve to refuse"); err == nil {
		t.Error("Serve accepted an event before the hello")
	}
	if ev, ok := pi.engine.Current(); ok {
		t.Errorf("the event before the hello was applied: %+v", ev)
	}
}

func TestBadEventsAreDropped(t *testing.T) {
	// Events this member cannot use, as a buggy or newer member might send
	// them, are dropped, and the connection goes on.
	pi, mac := newMember(t, Full), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.hello(clip.Hello{Wall: time.Now().UnixMilli()})
	r.send(&message{Type: typeEvent, Event: json.RawMessage(`{"id":"x","kind":"pdf","via":"telepathy"}`)})
	r.send(&message{Type: typeEvent, Event: json.RawMessage(`{"id":"bad"}`)})
	r.send(&message{Type: "from-the-future"})
	r.event(newEvent(mac, "still connected"))
	waitWrite(t, pi, "still connected")
}

func TestHelloWithAnUnreadableCurrent(t *testing.T) {
	// A hello whose current event does not decode counts as one without a
	// current event.
	pi, mac := newMember(t, Full), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.send(&message{Type: typeHello, Role: Full, Hello: json.RawMessage(`{"wall_ms":1,"current":{"kind":"pdf"}}`)})
	r.event(newEvent(mac, "after an odd hello"))
	waitWrite(t, pi, "after an odd hello")
}

func TestConnectingToItself(t *testing.T) {
	pi := newMember(t, Full)
	a, b := socketPair(t)
	go pi.Serve(context.Background(), tls.Server(b, pi.ServerTLS()))
	err := pi.Serve(context.Background(), tls.Client(a, pi.id.ClientTLS(pi.id.ID, group.TLSOptions{})))
	if err == nil {
		t.Error("a member connected to itself")
	}
}

func TestClosedNodeRefuses(t *testing.T) {
	mac, pi := newMember(t, Full), newMember(t, Full)
	pi.Close()
	cd, sd := link(t, mac, pi)
	if err := wait(t, sd, "the closed node"); err == nil {
		t.Error("a closed node served a connection")
	}
	wait(t, cd, "the client")
}

func TestQueueFullCloses(t *testing.T) {
	a, _ := socketPair(t)
	n := New(Config{Logf: t.Logf})
	c := &conn{n: n, tc: tls.Client(a, &tls.Config{}), out: make(chan outgoing, 1), done: make(chan struct{})}
	c.enqueue(outgoing{event: &clip.Event{}})
	c.enqueue(outgoing{event: &clip.Event{}})
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("a full queue did not close the connection")
	}
	c.enqueue(outgoing{event: &clip.Event{}}) // closed: no panic, no log flood
}

func TestAddAge(t *testing.T) {
	if got := addAge(math.MaxInt64-5, time.Second); got != math.MaxInt64 {
		t.Errorf("addAge near the top = %d", got)
	}
	if got := addAge(100, -time.Second); got != 100 {
		t.Errorf("a negative wait changed the age to %d", got)
	}
	if got := addAge(100, 2*time.Second); got != 2100 {
		t.Errorf("addAge = %d", got)
	}
}

func TestConverges(t *testing.T) {
	// Many copies from both sides end with both members on the same event.
	mac, pi := newMember(t, Full), newMember(t, Full)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	waitPeers(t, pi, 1)
	var wg sync.WaitGroup
	for i, m := range []*member{mac, pi} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				kind := clip.Text
				if j%7 == 0 {
					kind = clip.Secret
				}
				m.Copied(fmt.Sprintf("%d-%d-%d", i, j, time.Now().UnixNano()), kind, clip.Copy)
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, _ := mac.engine.Current()
		b, _ := pi.engine.Current()
		if a.ID == b.ID && a.ID != "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the members did not converge: %s vs %s", a.ID, b.ID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRenewPeer(t *testing.T) {
	// A Linux member that holds the group CA key, with its clock 18
	// months ahead, finds the Mac's certificate due and sends a renewed
	// one; the Mac takes it.
	pi := newMember(t, Full, func(_ *clip.Config, nc *Config) {
		nc.Now = func() time.Time { return time.Now().AddDate(1, 6, 0) }
	})
	piID := *pi.id
	piID.GroupCA = admin.GroupCA
	pi.SetIdentity(&piID)
	got := make(chan *group.Identity, 2)
	var mac *member
	mac = newMember(t, Full, func(_ *clip.Config, nc *Config) {
		nc.OnCert = func(der, _ []byte) error {
			next, err := mac.id.WithCert(der)
			if err == nil {
				got <- next
			}
			return err
		}
	})
	link(t, mac, pi)
	select {
	case next := <-got:
		if !next.Cert.NotAfter.After(mac.id.Cert.NotAfter.AddDate(1, 0, 0)) {
			t.Errorf("the renewed certificate ends at %v", next.Cert.NotAfter)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no renewed certificate")
	}
	// Once per connection, also when asked again.
	pi.RenewPeers()
	select {
	case <-got:
		t.Error("a second renewed certificate on the same connection")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestAdminKeyAndAdminCA checks that a computer offers its admin key in
// its hello until it holds an admin CA, and passes an admin message on to
// OnAdmin.
func TestAdminKeyAndAdminCA(t *testing.T) {
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	pi := newMember(t, Full, func(_ *clip.Config, nc *Config) {
		nc.OnAdmin = func(der []byte) error {
			got <- der
			return nil
		}
	})
	offered := *pi.id
	offered.AdminKey = key
	pi.SetIdentity(&offered)
	r := rawPeer(t, pi, newMember(t, Phone))
	r.send(&message{Type: typeHello, Role: Phone, Hello: json.RawMessage(`{"wall_ms":0}`)})
	var hello helloOut
	for _, m := range r.frames(100 * time.Millisecond) {
		if m.Type == typeHello {
			if err := json.Unmarshal(m.Hello, &hello); err != nil {
				t.Fatal(err)
			}
		}
	}
	want, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hello.AdminKey, want) {
		t.Errorf("the hello offers %x, want the admin key", hello.AdminKey)
	}
	r.send(&message{Type: typeAdmin, AdminCA: []byte("the admin CA")})
	select {
	case der := <-got:
		if string(der) != "the admin CA" {
			t.Errorf("OnAdmin got %q", der)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnAdmin was not called")
	}

	// A computer that holds its admin CA offers no key.
	admin := offered
	admin.AdminCA = admin.Cert
	pi.SetIdentity(&admin)
	r = rawPeer(t, pi, newMember(t, Phone))
	r.send(&message{Type: typeHello, Role: Phone, Hello: json.RawMessage(`{"wall_ms":0}`)})
	for _, m := range r.frames(100 * time.Millisecond) {
		if m.Type == typeHello && bytes.Contains(m.Hello, []byte("admin_key")) {
			t.Error("an admin offered its admin key")
		}
	}
}

func TestRoles(t *testing.T) {
	// A phone app and a lite member connect like a Mac and show their
	// role; an unknown role is refused.
	for _, role := range []Role{Phone, Lite} {
		pi, other := newMember(t, Full), newMember(t, role)
		link(t, other, pi)
		waitPeers(t, pi, 1)
		if got := pi.Peers()[0].Role; got != role {
			t.Errorf("the peer's role is %q, want %q", got, role)
		}
	}
	pi, mac := newMember(t, Full), newMember(t, Full)
	r := rawPeer(t, pi, mac)
	r.send(&message{Type: typeHello, Role: "robot", Hello: json.RawMessage(`{"wall_ms":0}`)})
	if err := wait(t, r.done, "Serve to refuse"); err == nil {
		t.Error("Serve accepted an unknown role")
	}
}

// recordStore is a RecordStore over group.Records, with Allow refusing what
// the records refuse and the records added reported on a channel.
type recordStore struct {
	mu    sync.Mutex
	s     *group.Records
	added chan int
	node  func() *Node
}

func newRecordStore() *recordStore {
	ensureAdmin()
	return &recordStore{s: group.NewRecords(admin.GroupCA.Cert), added: make(chan int, 64)}
}

func (r *recordStore) Digest() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.s.Digest()
}

func (r *recordStore) All() []group.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.s.All()
}

func (r *recordStore) Add(_ group.DeviceID, rs []group.Record) []group.Record {
	r.mu.Lock()
	var fresh []group.Record
	for _, rec := range rs {
		if ok, err := r.s.Add(rec); ok && err == nil {
			fresh = append(fresh, rec)
		}
	}
	r.mu.Unlock()
	r.added <- len(fresh)
	return fresh
}

// fresh waits for an Add that took records, skipping those that brought
// only records the store had: a peer may send them again, as when b passes
// on the device record that c already took from it.
func (r *recordStore) fresh(timeout time.Duration) (int, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case n := <-r.added:
			if n > 0 {
				return n, true
			}
		case <-deadline:
			return 0, false
		}
	}
}

func (r *recordStore) Settle([]group.Record) { r.node().Recheck() }

func (r *recordStore) allow(_ group.DeviceID, chain []*x509.Certificate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.s.Refused(chain)
}

func withRecords(r *recordStore) option {
	return func(_ *clip.Config, nc *Config) { nc.Records, nc.Allow = r, r.allow }
}

func (m *member) record(t *testing.T, body group.RecordBody) group.Record {
	t.Helper()
	body.Group = group.Tag(admin.GroupCA.Cert)
	r := grouptest.Sign(t, body, admin.GroupCA.Key)
	return r
}

// TestRecordsSpread links a, b and c in a chain: records a holds reach c
// through b, and a revocation of c reaches c before it closes b's
// connection to it.
func TestRecordsSpread(t *testing.T) {
	stores := []*recordStore{newRecordStore(), newRecordStore(), newRecordStore()}
	var ms []*member
	for _, st := range stores {
		m := newMember(t, Full, withRecords(st))
		st.node = func() *Node { return m.Node }
		ms = append(ms, m)
	}
	a, b, c := ms[0], ms[1], ms[2]
	// In records v:2 a member is taken only when a device record names its
	// key, so every store starts with the records of all three; a then
	// holds one more, of a device that is not here, which spreads.
	var devs []group.Record
	for _, m := range ms {
		key := group.KeyHashOf(m.id.Cert)
		devs = append(devs, a.record(t, group.RecordBody{Type: group.RecordDevice, Device: string(m.id.ID), Name: "m", Role: group.RoleFull, Key: &key}))
	}
	for _, st := range stores {
		st.Add("", devs)
		<-st.added
	}
	other := group.KeyHash{1}
	dev := a.record(t, group.RecordBody{Type: group.RecordDevice, Device: string(group.NewDeviceID()), Name: "d", Role: group.RoleFull, Key: &other})
	stores[0].Add("", []group.Record{dev})
	<-stores[0].added

	_, bcDone := link(t, b, c)
	link(t, a, b)
	for i, st := range stores[1:] {
		n, ok := st.fresh(5 * time.Second)
		if !ok {
			t.Fatalf("store %d got no records", i+1)
		}
		if n != 1 {
			t.Fatalf("store %d added %d records, want 1", i+1, n)
		}
	}
	if stores[2].Digest() != stores[0].Digest() {
		t.Fatal("c's records differ from a's")
	}

	revoke := a.record(t, group.RecordBody{Type: group.RecordRevoke, Keys: []group.KeyHash{group.KeyHashOf(c.id.Cert)}})
	stores[0].Add("", []group.Record{revoke})
	<-stores[0].added
	a.SendRecords([]group.Record{revoke})
	n, ok := stores[2].fresh(5 * time.Second)
	if !ok {
		t.Fatal("c never got the record that revokes it")
	}
	if n != 1 {
		t.Fatalf("c added %d records of its revocation, want 1", n)
	}
	if err := wait(t, bcDone, "c's connection on b's side"); err != nil {
		t.Logf("c's connection ended with %v", err)
	}
	// c can no longer connect to b. In TLS 1.3 the client's handshake ends
	// before the server checks its certificate, so b's side tells.
	_, bDone := link(t, c, b)
	if err := wait(t, bDone, "b's side of c's new connection"); err == nil {
		t.Error("the revoked c connected again")
	}
}

func TestChunkRecords(t *testing.T) {
	big := group.Record{Body: make([]byte, 6<<10), Sig: make([]byte, 72)}
	rs := make([]group.Record, 400) // about 3.3 MB encoded
	for i := range rs {
		rs[i] = big
	}
	chunks := chunkRecords(rs)
	total := 0
	for _, c := range chunks {
		f, err := frame(&message{Type: typeRecs, Records: c})
		if err != nil {
			t.Fatal(err)
		}
		if len(f) > recordsChunk*5/4 {
			t.Errorf("a chunk of %d records takes %d bytes", len(c), len(f))
		}
		total += len(c)
	}
	if total != len(rs) || len(chunks) < 3 {
		t.Errorf("%d records in %d chunks", total, len(chunks))
	}
	if chunkRecords(nil) != nil {
		t.Error("no records make a chunk")
	}
}

// TestTunnelKeyAndOffer checks that a member offers its tunnel key and
// preshared key in its hello, that the hub's OnTunnelKey gets them with the
// chain the member presented, that the member's OnTunnel gets the hub's
// offers, its own and one it passes on, and that OnHubs gets what the hub
// shares.
func TestTunnelKeyAndOffer(t *testing.T) {
	type offered struct {
		peer     group.DeviceID
		chain    []*x509.Certificate
		key, psk []byte
	}
	keys := make(chan offered, 4)
	offers := make(chan TunnelOffer, 4)
	from := make(chan group.DeviceID, 4)
	shares := make(chan HubShare, 4)
	offer := TunnelOffer{HubKey: bytes.Repeat([]byte{1}, 32), PSK: bytes.Repeat([]byte{5}, 32), Endpoints: []string{"192.0.2.1:8764"}}
	other := TunnelOffer{HubKey: bytes.Repeat([]byte{6}, 32), PSK: bytes.Repeat([]byte{5}, 32), Endpoints: []string{"192.0.2.6:8764"},
		Hub: "cccccccccccccccccccccccccccccccc"}
	share := HubShare{Serving: true, Offer: &TunnelOffer{HubKey: offer.HubKey, Endpoints: offer.Endpoints}}
	hub := newMember(t, Full, func(_ *clip.Config, nc *Config) {
		nc.TunnelKey = bytes.Repeat([]byte{3}, 32)
		nc.OnTunnelKey = func(peer group.DeviceID, chain []*x509.Certificate, key, psk []byte) []TunnelOffer {
			keys <- offered{peer, chain, key, psk}
			return []TunnelOffer{offer, other}
		}
		nc.HubShare = func(group.DeviceID) *HubShare { return &share }
	})
	mac := newMember(t, Full, func(_ *clip.Config, nc *Config) {
		nc.TunnelKey, nc.TunnelPSK = bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)
		nc.OnTunnelKey = func(group.DeviceID, []*x509.Certificate, []byte, []byte) []TunnelOffer { return nil }
		nc.OnTunnel = func(id group.DeviceID, _ []*x509.Certificate, o TunnelOffer) error {
			from <- id
			offers <- o
			return nil
		}
		nc.OnHubs = func(_ group.DeviceID, _ []*x509.Certificate, h HubShare) error {
			shares <- h
			return nil
		}
	})
	link(t, mac, hub)
	select {
	case k := <-keys:
		if k.peer != mac.id.ID || !bytes.Equal(k.key, bytes.Repeat([]byte{4}, 32)) || !bytes.Equal(k.psk, bytes.Repeat([]byte{5}, 32)) {
			t.Errorf("the hub got key %x and psk %x from %s", k.key, k.psk, k.peer)
		}
		if len(k.chain) == 0 || !k.chain[0].Equal(mac.id.Cert) {
			t.Error("the hub did not get the member's certificate")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnTunnelKey was not called")
	}
	select {
	case o := <-offers:
		if id := <-from; id != hub.id.ID {
			t.Errorf("the offer came from %s", id)
		}
		if !bytes.Equal(o.HubKey, offer.HubKey) || !bytes.Equal(o.PSK, offer.PSK) || !slices.Equal(o.Endpoints, offer.Endpoints) {
			t.Errorf("the member got %+v, want %+v", o, offer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnTunnel was not called")
	}
	select {
	case o := <-offers:
		<-from
		if o.Hub != other.Hub || !bytes.Equal(o.HubKey, other.HubKey) {
			t.Errorf("the offer passed on is %+v, want %+v", o, other)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the offer passed on did not arrive")
	}
	select {
	case h := <-shares:
		if !h.Serving || h.Offer == nil || !bytes.Equal(h.Offer.HubKey, offer.HubKey) {
			t.Errorf("the member got the share %+v", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnHubs was not called")
	}
	// The member's own OnTunnelKey answered nil: the hub gets no offer.
	noOffer := time.After(200 * time.Millisecond)
	select {
	case <-offers:
		t.Fatal("a second offer arrived")
	case <-noOffer:
	}
}

// TestNoTunnelKey checks that a member without a tunnel key sends none
// and that a hello without one asks nothing of OnTunnelKey.
func TestNoTunnelKey(t *testing.T) {
	called := make(chan struct{}, 1)
	pi := newMember(t, Full, func(_ *clip.Config, nc *Config) {
		nc.OnTunnelKey = func(group.DeviceID, []*x509.Certificate, []byte, []byte) []TunnelOffer {
			called <- struct{}{}
			return nil
		}
	})
	r := rawPeer(t, pi, newMember(t, Phone))
	r.send(&message{Type: typeHello, Role: Phone, Hello: json.RawMessage(`{"wall_ms":0}`)})
	for _, m := range r.frames(100 * time.Millisecond) {
		if m.Type == typeHello && bytes.Contains(m.Hello, []byte("tunnel_key")) {
			t.Error("a member without a tunnel key offered one")
		}
	}
	select {
	case <-called:
		t.Error("OnTunnelKey was called for a hello without a key")
	default:
	}
}

func TestCommandsPassThroughAMember(t *testing.T) {
	// a reaches b only through the hub, which passes the command on and
	// the result back; the hub carries out none of it.
	got := make(chan string, 4)
	on := func(name string) option {
		return func(_ *clip.Config, nc *Config) {
			nc.OnCommand = func(peer group.DeviceID, c group.Record) Result {
				got <- name
				return Result{Status: ResultDone}
			}
		}
	}
	a, hub, b := newMember(t, Full, on("a")), newMember(t, Full, on("hub")), newMember(t, Full, on("b"))
	link(t, a, hub)
	link(t, b, hub)
	waitPeers(t, hub, 2)
	waitPeers(t, a, 1)
	waitPeers(t, b, 1)
	id := group.NewCommandID()
	body, _ := json.Marshal(map[string]any{"id": id, "to": b.id.ID, "expires_ms": time.Now().Add(10 * time.Second).UnixMilli()})
	cmd := group.Record{Body: body}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.SendCommand(ctx, b.id.ID, cmd, id, nil); err == nil {
		t.Error("a command went to a member that is not connected, without via")
	}
	// A member that is not one of the hubs never gets it.
	other := group.DeviceID("not the hub")
	short, stop := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stop()
	if _, err := a.SendCommand(short, b.id.ID, cmd, id, []group.DeviceID{other}); err == nil {
		t.Error("a command for b reached it through a member that is not one of the hubs")
	}
	select {
	case who := <-got:
		t.Fatalf("%s got a command that should have gone to the hubs only", who)
	default:
	}
	res, err := a.SendCommand(ctx, b.id.ID, cmd, id, []group.DeviceID{other, hub.id.ID})
	if err != nil || res.Status != ResultDone || res.ID != id {
		t.Fatalf("the command through the hub: %+v, %v", res, err)
	}
	if who := <-got; who != "b" {
		t.Errorf("%s carried out the command", who)
	}
	// The same command again is passed on once only.
	short, stop = context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer stop()
	if _, err := a.SendCommand(short, b.id.ID, cmd, id, []group.DeviceID{hub.id.ID}); err == nil {
		t.Error("the hub passed the same command on twice")
	}
	select {
	case who := <-got:
		t.Errorf("%s carried out a command again", who)
	default:
	}
}

// releaseStore is a ReleaseStore that takes a release whose channel seq is
// higher, without checking signatures, and reports what it took.
type releaseStore struct {
	mu    sync.Mutex
	cur   *ReleaseSet
	seq   uint64
	added chan uint64
}

func newReleaseStore() *releaseStore { return &releaseStore{added: make(chan uint64, 16)} }

func releaseSet(t *testing.T, seq uint64) *ReleaseSet {
	t.Helper()
	body, err := json.Marshal(signed.Channel{V: 1, Type: "channel", Channel: "stable", Seq: seq})
	if err != nil {
		t.Fatal(err)
	}
	return &ReleaseSet{Keys: signed.File{Body: []byte("{}")}, Channel: signed.File{Body: body}, Release: signed.File{Body: []byte("{}")}}
}

func (r *releaseStore) Current() (*ReleaseSet, ReleaseOrder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur, ReleaseOrder{Channel: r.seq}
}

func (r *releaseStore) Add(_ group.DeviceID, s ReleaseSet) bool {
	var c signed.Channel
	if json.Unmarshal(s.Channel.Body, &c) != nil {
		return false
	}
	r.mu.Lock()
	newer := c.Seq > r.seq
	if newer {
		r.cur, r.seq = &s, c.Seq
	}
	r.mu.Unlock()
	if newer {
		r.added <- c.Seq
	}
	return newer
}

func withReleases(r *releaseStore) option {
	return func(_ *clip.Config, nc *Config) { nc.Releases = r }
}

// TestReleaseSpreads links a, b and c in a chain: the release a holds
// reaches c through b after the hellos, and a newer one a takes later
// follows the same way; b never takes an older one back.
func TestReleaseSpreads(t *testing.T) {
	stores := []*releaseStore{newReleaseStore(), newReleaseStore(), newReleaseStore()}
	var ms []*member
	for _, st := range stores {
		ms = append(ms, newMember(t, Full, withReleases(st)))
	}
	a, b, c := ms[0], ms[1], ms[2]
	stores[0].Add("", *releaseSet(t, 3))
	<-stores[0].added

	link(t, b, c)
	link(t, a, b)
	for i, st := range stores[1:] {
		select {
		case seq := <-st.added:
			if seq != 3 {
				t.Fatalf("store %d took seq %d, want 3", i+1, seq)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("store %d got no release", i+1)
		}
	}

	stores[0].Add("", *releaseSet(t, 4))
	<-stores[0].added
	a.SendRelease(releaseSet(t, 4))
	for i, st := range stores[1:] {
		select {
		case seq := <-st.added:
			if seq != 4 {
				t.Fatalf("store %d took seq %d, want 4", i+1, seq)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("store %d got no newer release", i+1)
		}
	}
	if stores[1].Add("", *releaseSet(t, 2)) {
		t.Error("b took an older release")
	}
}

// TestRecordsOnlyLetIn: a records-only connection ends with ErrLetIn as soon
// as the records let the peer in, also when the record that does came over
// another connection and none came on this one, so that the dialer
// connects again as a member at once.
func TestRecordsOnlyLetIn(t *testing.T) {
	var listed atomic.Bool
	st := newRecordStore()
	a := newMember(t, Full, withRecords(st), func(_ *clip.Config, nc *Config) {
		nc.Allow = func(group.DeviceID, []*x509.Certificate) error {
			if listed.Load() {
				return nil
			}
			return group.ErrNotListed
		}
	})
	st.node = func() *Node { return a.Node }
	// b does not list a either, so both keep the connection for records.
	bst := newRecordStore()
	b := newMember(t, Full, withRecords(bst), func(_ *clip.Config, nc *Config) {
		nc.Allow = func(group.DeviceID, []*x509.Certificate) error { return group.ErrNotListed }
	})
	bst.node = func() *Node { return b.Node }
	aDone, _ := link(t, a, b)
	time.Sleep(3 * recordsRecheck)
	select {
	case err := <-aDone:
		t.Fatalf("the records-only connection ended before the records let b in: %v", err)
	default:
	}
	listed.Store(true)
	if err := wait(t, aDone, "the records-only connection to end"); !errors.Is(err, ErrLetIn) {
		t.Fatalf("the connection ended with %v, want ErrLetIn", err)
	}
}

// TestNoSecretsSendsTheMark checks that a member sends a peer that the
// records stop secrets to (Config.NoSecrets) the mark of a secret, never
// its text, and other copies as they are (docs/protocol.md, section 10,
// "Stopping the exchange").
func TestNoSecretsSendsTheMark(t *testing.T) {
	var stopped atomic.Bool
	stopped.Store(true)
	mac := newMember(t, Full, func(_ *clip.Config, nc *Config) {
		nc.NoSecrets = func(group.DeviceID) bool { return stopped.Load() }
	})
	pi := newMember(t, Full)
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	if _, err := mac.Copied("hunter2", clip.Secret, clip.Copy); err != nil {
		t.Fatal(err)
	}
	noWrite(t, pi, "hunter2", 300*time.Millisecond)
	if _, err := mac.Copied("plain text", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, pi, "plain text")
	stopped.Store(false)
	if _, err := mac.Copied("otp 123456", clip.Secret, clip.Copy); err != nil {
		t.Fatal(err)
	}
	if w := waitWrite(t, pi, "otp 123456"); w.Kind != clip.Secret {
		t.Errorf("a secret was written as %v", w.Kind)
	}
}
