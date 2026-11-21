// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/mdns"
)

// hub is the network the tests' services share. Each is a Rust cbb that
// finds the others by mDNS; hide puts one on another network.
type hub struct {
	mu sync.Mutex
	// rust are the services started on this hub.
	rust map[*testService]bool
}

// hide puts the member with this device ID on another network: the Rust
// service looks for its device ID in CBB_TEST_ELSEWHERE.
func (h *hub) hide(id string) {
	os.WriteFile(filepath.Join(elsewhereDir(), id), nil, 0o600)
}

// elsewhereDir is the folder the Rust services read as CBB_TEST_ELSEWHERE:
// a file named by a device ID puts that device on another network.
var elsewhereDir = sync.OnceValue(func() string {
	d, err := os.MkdirTemp("", "cbb-elsewhere")
	if err != nil {
		panic(err)
	}
	return d
})

// txtOf returns the TXT record that the member with this device ID
// publishes, as mDNS finds it.
func (h *hub) txtOf(id string) []string {
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if p, ok := h.found(id); ok || time.Now().After(deadline) {
			return p.TXT
		}
	}
}

// anyPublishes says whether a member publishes the TXT string kv by mDNS.
func (h *hub) anyPublishes(kv string) bool {
	h.found("")
	realBrowse.mu.Lock()
	defer realBrowse.mu.Unlock()
	for _, p := range realBrowse.peers {
		if slices.Contains(p.TXT, kv) {
			return true
		}
	}
	return false
}

// found is the member with this device ID that mDNS finds: one browser runs
// for all the tests.
func (h *hub) found(id string) (mdns.Peer, bool) {
	realBrowse.once.Do(func() {
		realBrowse.peers = map[string]mdns.Peer{}
		r, err := mdns.New(mdns.Config{ID: "browse-test", BrowseOnly: true, OnPeers: func(peers []mdns.Peer) {
			realBrowse.mu.Lock()
			realBrowse.peers = map[string]mdns.Peer{}
			for _, p := range peers {
				realBrowse.peers[p.ID] = p
			}
			realBrowse.mu.Unlock()
		}})
		if err == nil {
			go r.Run(context.Background())
		}
	})
	realBrowse.mu.Lock()
	defer realBrowse.mu.Unlock()
	p, ok := realBrowse.peers[id]
	return p, ok
}

var realBrowse struct {
	once  sync.Once
	mu    sync.Mutex
	peers map[string]mdns.Peer
}

type testService struct {
	name string
	dir  string
	os   string // group.OSLinux: every service of the tests is a Linux computer's
	// socket is the control socket.
	socket string
	done   chan error
	cancel func()   // asks it to stop; stop then waits for done
	env    []string // the Rust service's settings for the test
	port   int      // the member port it listens on, 0 for any
	rust   bool     // a Rust cbb: every service of the tests is

	logMu   sync.Mutex
	stopped bool     // the test may have ended: the log goes nowhere
	lines   []string // what it logged
}

// logged reports whether the service logged a line that contains part.
func (s *testService) logged(part string) bool {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	return slices.ContainsFunc(s.lines, func(l string) bool { return strings.Contains(l, part) })
}

// linesWith returns the lines the service logged that contain part.
func (s *testService) linesWith(part string) []string {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	var out []string
	for _, l := range s.lines {
		if strings.Contains(l, part) {
			out = append(out, l)
		}
	}
	return out
}

// addr returns the member port's address, which the service logs a moment
// after it is in a group.
func (s *testService) addr() string {
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		s.logMu.Lock()
		for _, l := range s.lines {
			if _, p, ok := strings.Cut(l, "listening on port "); ok {
				s.logMu.Unlock()
				return "127.0.0.1:" + strings.TrimSpace(p)
			}
		}
		s.logMu.Unlock()
		if time.Now().After(deadline) {
			return ""
		}
	}
}

func startService(t *testing.T, h *hub, name string) *testService {
	t.Helper()
	return startEnv(t, h, name)
}

// startEnv starts a service with env, settings for the test that the Rust
// service takes from its environment (docs/reference/config.md).
func startEnv(t *testing.T, h *hub, name string, env ...string) *testService {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return startIn(t, h, &testService{name: name, dir: dir, os: group.OSLinux, env: env})
}

// restartService starts a stopped service again with its state.
func restartService(t *testing.T, h *hub, old *testService) *testService {
	t.Helper()
	return startIn(t, h, &testService{name: old.name, dir: old.dir, os: old.os, env: old.env, port: old.port})
}

// portOf is the port of the address addr.
func portOf(t *testing.T, addr string) int {
	t.Helper()
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return int(ap.Port())
}

// rustService is the Rust cbb (member/) that CBB_TEST_RUST_SERVICE names,
// with cbb-helper beside it: every service of the tests runs it.
func rustService() string { return os.Getenv("CBB_TEST_RUST_SERVICE") }

// testClock moves a service's clocks through the file CBB_TEST_AHEAD_FILE
// names, which the service reads each time, so that a test can move them
// while the service runs: the wall clock (the file's first number) and the
// time since boot (its second), the one clock the service counts running
// time on (member/src/uptime.rs; docs/testing.md, "Time"). Only a cbb built
// with the feature testhooks reads the file, never a release's.
type testClock struct {
	file       string
	ahead, ran time.Duration
}

// testHooksBuilt tells, once, whether the Rust cbb under test reads the
// tests' hooks (CBB_TEST_*): its version names the feature testhooks.
var testHooksBuilt = sync.OnceValues(func() (bool, error) {
	out, err := exec.Command(rustService(), "version").Output()
	if err != nil {
		return false, err
	}
	first, _, _ := strings.Cut(string(out), "\n")
	return strings.Contains(first, "testhooks"), nil
})

// needHooks fails the test unless the Rust cbb under test reads the tests'
// hooks, which a release's build ignores.
func needHooks(t *testing.T) {
	t.Helper()
	if ok, err := testHooksBuilt(); err != nil {
		t.Fatalf("cbb version: %v", err)
	} else if !ok {
		t.Fatal("the service's tests steer cbb through their hooks: build it with cargo build --release -p cbb-member --features testhooks, and cbb-helper with go build -tags testhooks")
	}
}

// newTestClock starts a clock ahead of the real time for a service the
// test starts with the clock's env, after checking that the Rust cbb under
// test reads the hook; without the Rust service the test is skipped, as
// startService skips it.
func newTestClock(t *testing.T, ahead time.Duration) *testClock {
	t.Helper()
	if rustService() == "" {
		t.Skip("CBB_TEST_RUST_SERVICE is not set: the service's tests run the Rust cbb, with cbb-helper beside it")
	}
	needHooks(t)
	c := &testClock{file: filepath.Join(t.TempDir(), "clock")}
	c.set(t, ahead)
	return c
}

// set moves the wall clock to ahead of the real time, as when a person
// sets it: the time since boot does not move.
func (c *testClock) set(t *testing.T, ahead time.Duration) {
	t.Helper()
	c.ahead = ahead
	c.write(t)
}

// run moves both clocks forward by d, as if the machine had run that much
// longer: the way a test walks a rule of hours or days in seconds.
func (c *testClock) run(t *testing.T, d time.Duration) {
	t.Helper()
	if d < 0 {
		t.Fatalf("the running time does not go back (%v)", d)
	}
	c.ahead += d
	c.ran += d
	c.write(t)
}

func (c *testClock) write(t *testing.T) {
	t.Helper()
	text := strconv.FormatInt(c.ahead.Milliseconds(), 10) + " " + strconv.FormatInt(c.ran.Milliseconds(), 10)
	if err := os.WriteFile(c.file, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// env is the Rust service's environment for the clock.
func (c *testClock) env() string { return "CBB_TEST_AHEAD_FILE=" + c.file }

// renewEvery is how often the services renew certificates, and hubKeyAhead
// how long before its key's end a hub offers its next key: the Rust
// service's defaults, which a test may shorten for the services it starts
// after.
var (
	renewEvery  = 12 * time.Hour
	hubKeyAhead = 3 * 24 * time.Hour
)

// errBroken is what the service says while its group file is damaged.
const errBroken = "this device's group file (identity.json in the service's state directory) is damaged, so the service does not start the group; restore the file from a backup, or leave the group (cbb leave) and join again"

// ErrLeft and ErrRestart are how a service ends after cbb leave and after
// an admin's restart, for systemd to start it again.
var (
	ErrLeft    = errors.New("restarting after leaving the group")
	ErrRestart = errors.New("restarting at an admin's request")
)

func startIn(t *testing.T, h *hub, s *testService) *testService {
	t.Helper()
	bin := rustService()
	if bin == "" {
		t.Skip("CBB_TEST_RUST_SERVICE is not set: the service's tests run the Rust cbb, with cbb-helper beside it")
	}
	r := startRust(t, bin, s)
	h.mu.Lock()
	if h.rust == nil {
		h.rust = map[*testService]bool{}
	}
	h.rust[r] = true
	h.mu.Unlock()
	return r
}

func (s *testService) stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
		s.cancel = nil
	}
	s.logMu.Lock()
	s.stopped = true
	s.logMu.Unlock()
}

// dial connects to the service's admin socket, which takes every operation,
// with a deadline, so that a missing answer fails the test instead of
// hanging it.
func (s *testService) dial(t *testing.T) *control.Client {
	t.Helper()
	c, err := control.Dial(control.AdminSocketFor(s.socket))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	return c
}

func (s *testService) do(t *testing.T, h control.Header, payload string) (*control.Message, error) {
	t.Helper()
	c := s.dial(t)
	defer c.Close()
	return c.Do(&control.Message{Header: h, Payload: []byte(payload)})
}

func (s *testService) status(t *testing.T) *control.Status {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpStatus}, "")
	if err != nil {
		t.Fatal(err)
	}
	return m.Status
}

func (s *testService) paste(t *testing.T) string {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpPaste}, "")
	if err != nil {
		return ""
	}
	return string(m.Payload)
}

// openWindow opens a pairing window on admin, which first creates a group
// when it is in none; closing the client closes it.
func openWindow(t *testing.T, admin *testService) (*control.Client, string) {
	t.Helper()
	c, m := openWindowMsg(t, admin)
	return c, m.Code
}

// openWindowLink is openWindow with the link of the window's QR code
// (cbb://pair?...), which a home window of a group of 0.6 gives and an
// old window does not: the link names the window's ID and member key,
// which six digits alone leave to mDNS.
func openWindowLink(t *testing.T, admin *testService) (*control.Client, string, string) {
	t.Helper()
	c, m := openWindowMsg(t, admin)
	return c, m.Code, m.Invite
}

// on06 tells whether s is in a group on the records of 0.6: its state
// holds the group's records (group.cbor) instead of identity.json.
func (s *testService) on06() bool {
	_, err := os.Stat(filepath.Join(s.dir, "group.cbor"))
	return err == nil
}

func openWindowMsg(t *testing.T, admin *testService) (*control.Client, *control.Message) {
	t.Helper()
	if admin.status(t).Group == "" {
		if _, err := admin.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
			t.Fatalf("new on %s: %v", admin.name, err)
		}
	}
	c := admin.dial(t)
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
	if err != nil {
		c.Close()
		t.Fatalf("pair on %s: %v", admin.name, err)
	}
	return c, m
}

// pairWith opens a pairing window on admin and joins s through it, found
// by discovery.
func pairWith(t *testing.T, admin, s *testService) {
	t.Helper()
	c, code := openWindow(t, admin)
	defer c.Close()
	join := control.Header{Op: control.OpJoin, Code: code}
	if admin.rust && !s.rust {
		// A Go service's fresh browse does not hear a Rust service's
		// answers when both run on one host, as here, only its
		// announcements: it joins at the address. A Rust joiner finds the
		// window by mDNS.
		join.Address = admin.addr()
	}
	if _, err := s.do(t, join, ""); err != nil {
		t.Fatalf("join on %s: %v", s.name, err)
	}
	m, err := c.Receive()
	if err != nil || m.Name != s.name {
		t.Fatalf("pair on %s ended with %+v, %v", admin.name, m, err)
	}
}

// makeAdmin makes s an admin on the group's root and waits until it holds
// its admin CA.
func makeAdmin(t *testing.T, root, s *testService) {
	t.Helper()
	waitFor(t, s.name+" is connected to the root", func() bool {
		for _, p := range root.status(t).Peers {
			if p.ID == s.status(t).Device {
				return true
			}
		}
		return false
	})
	// A connection seen a moment ago may be on its way to a new one, as
	// right after a claim takes effect, when the members connect again with
	// the new root's chain: the admin CA goes over the next.
	var m *control.Message
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for {
		m, err = root.do(t, control.Header{Op: control.OpMakeAdmin, Device: s.name, AllowFileKey: true}, "")
		if err == nil || !strings.Contains(err.Error(), "is not connected") || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || m.Name != s.name {
		t.Fatalf("admin %s on %s: %+v, %v", s.name, root.name, m, err)
	}
	waitFor(t, s.name+" is an admin", func() bool { return s.isAdmin(t) })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	waitUpTo(t, 10*time.Second, what, ok)
}

// waitUpTo waits up to d for ok; on a timeout, the message has what each
// of state says.
func waitUpTo(t *testing.T, d time.Duration, what string, ok func() bool, state ...func() string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			for _, f := range state {
				what += "; " + f()
			}
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestThreeMembers(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c := startService(t, &h, "gamma")
	if st := a.status(t); st.Group != "" {
		t.Fatalf("a new service is in a group: %+v", st)
	}
	if _, err := a.do(t, control.Header{Op: control.OpPaste}, ""); err == nil || !strings.Contains(err.Error(), "cbb new here to start one") {
		t.Errorf("paste in no group: %v", err)
	}
	pairWith(t, a, b) // creates the group on alpha, its root
	if _, err := b.do(t, control.Header{Op: control.OpPair}, ""); err == nil || !strings.Contains(err.Error(), "root or an admin") {
		t.Errorf("pair on a member that is no admin: %v", err)
	}
	makeAdmin(t, a, b)
	pairWith(t, b, c) // an admin admits too
	tag := a.status(t).Group
	for _, s := range []*testService{b, c} {
		if g := s.status(t).Group; g != tag {
			t.Fatalf("%s is in group %q, want %q", s.name, g, tag)
		}
	}
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" connected to both others", func() bool { return len(s.status(t).Peers) == 2 })
		// Its certificate is from an admin CA, which the check of its
		// status takes into account.
		if st := s.status(t); st.Removed || st.Frozen {
			t.Errorf("%s says it was removed (%v) or frozen (%v)", s.name, st.Removed, st.Frozen)
		}
	}
	// The root made b an admin once, not again for the same root.
	if a.logged("a new admin CA from this root") {
		t.Error("the root gave b a second admin CA")
	}
	// One copy reaches every member's own clipboard.
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from alpha"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{a, b, c} {
		waitFor(t, s.name+" has the text", func() bool { return s.paste(t) == "from alpha" })
	}
}

func TestOneConnectionBetweenTwo(t *testing.T) {
	// Only the member with the lower device ID dials, so the one with the
	// higher ID accepts the only connection between them
	// (member/src/discovery.rs). Each member logs each connection with the
	// address it went to or came from.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 && len(b.status(t).Peers) == 1 })
	since := a.status(t).Peers[0]
	time.Sleep(1500 * time.Millisecond)
	low, high := a, b
	if b.status(t).Device < a.status(t).Device {
		low, high = b, a
	}
	lowID, highID := low.status(t).Device, high.status(t).Device
	highPort := ":" + strconv.Itoa(portOf(t, high.addr()))
	var dialed, other int
	for _, l := range low.linesWith("connected to " + highID + " at ") {
		if strings.HasSuffix(l, highPort) {
			dialed++
		} else {
			other++
		}
	}
	if dialed != 1 || other != 0 {
		t.Errorf("the member with the lower ID dialed %d connections and accepted %d", dialed, other)
	}
	if n := len(high.linesWith("connected to " + lowID + " at ")); n != 1 {
		t.Errorf("the member with the higher ID has %d connections, want 1", n)
	}
	// The skew comes from the hello, which the engine may take only after
	// the peer shows in the status: it is no sign of a new connection.
	since.SkewMS = 0
	now := a.status(t).Peers
	for i := range now {
		now[i].SkewMS = 0
	}
	if len(now) != 1 || !reflect.DeepEqual(now[0], since) {
		t.Errorf("the connection changed: %+v, then %+v", since, now)
	}
}

func TestWatcher(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 })
	// A desktop connector on b watches its clipboard.
	w := b.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "for the desktop"); err != nil {
		t.Fatal(err)
	}
	m, err := w.Receive()
	if err != nil || m.Op != control.OpWrite || string(m.Payload) != "for the desktop" || m.Seq == 0 || m.Kind != control.KindText {
		t.Fatalf("watcher got %+v, %v", m, err)
	}
	// A secret carries what is left of its lifetime.
	if _, err := a.do(t, control.Header{Op: control.OpCopy, Kind: control.KindSecret}, "one-time code"); err != nil {
		t.Fatal(err)
	}
	m, err = w.Receive()
	if err != nil || string(m.Payload) != "one-time code" || m.Kind != control.KindSecret {
		t.Fatalf("watcher got %+v, %v", m, err)
	}
	if m.TTLMS <= 55000 || m.TTLMS > 60000 {
		t.Errorf("a fresh secret came with ttl_ms %d", m.TTLMS)
	}
	// A copy on b's desktop reaches a.
	if err := w.Send(&control.Message{Header: control.Header{Op: control.OpCopied, Kind: control.KindText}, Payload: []byte("from the desktop")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has the desktop copy", func() bool { return a.paste(t) == "from the desktop" })
	// So does one that came through Universal Clipboard, by its name.
	if err := w.Send(&control.Message{Header: control.Header{Op: control.OpCopied, Via: control.ViaUniversal}, Payload: []byte("from the iPhone")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has the Universal Clipboard copy", func() bool { return a.paste(t) == "from the iPhone" })
}

func TestWatcherGetsAMissedWrite(t *testing.T) {
	// A write made while no watcher was connected goes to the next one,
	// instead of the stale text its clipboard holds.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 })
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "while the desktop was away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta has it", func() bool { return b.paste(t) == "while the desktop was away" })
	w := b.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch}, Payload: []byte("stale desktop text")}); err != nil {
		t.Fatal(err)
	}
	m, err := w.Receive()
	if err != nil || m.Op != control.OpWrite || string(m.Payload) != "while the desktop was away" {
		t.Fatalf("watcher got %+v, %v", m, err)
	}
	if got := b.paste(t); got != "while the desktop was away" {
		t.Errorf("paste %q after the watcher started", got)
	}
	w.Close()
	// Without a missed write, what the watcher reports is the clipboard.
	w2 := b.dial(t)
	defer w2.Close()
	if _, err := w2.Do(&control.Message{Header: control.Header{Op: control.OpWatch}, Payload: []byte("on the desktop")}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "beta knows the desktop text", func() bool { return b.paste(t) == "on the desktop" })
}

func TestRestartWithANewPort(t *testing.T) {
	// A member that restarts on a new port while discovery still lists it
	// is dialed at the new port.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 })
	high, low := b, a
	if a.status(t).Device > b.status(t).Device {
		high, low = a, b
	}
	high.stop()
	high2 := restartService(t, &h, high)
	waitFor(t, "connected again", func() bool { return len(low.status(t).Peers) == 1 && len(high2.status(t).Peers) == 1 })
}

func TestRenewal(t *testing.T) {
	// Eighteen months after pairing, the pi and the deck each move their
	// sealing key to a new epoch when they start (on the records of 0.6
	// the member key, the device's identity, stays and has nothing to
	// renew); both keep the new statement, and they connect again.
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	statements := func(s *testService) string { return filepath.Join(s.dir, "statements.json") } // src/sealed.rs in cbb
	// Each keeps the other's statement as well as its own before they stop.
	for _, s := range []*testService{pi, deck} {
		waitFor(t, s.name+" keeps both statements", func() bool {
			var f struct {
				Statements []string `json:"statements"`
			}
			b, err := os.ReadFile(statements(s))
			return err == nil && json.Unmarshal(b, &f) == nil && len(f.Statements) == 2
		})
	}
	before := map[string][]byte{}
	for _, s := range []*testService{pi, deck} {
		s.stop()
		b, err := os.ReadFile(statements(s))
		if err != nil {
			t.Fatal(err)
		}
		before[s.name] = b
	}
	clock := newTestClock(t, 548*24*time.Hour)
	pi.env, deck.env = []string{clock.env()}, []string{clock.env()}
	pi, deck = restartService(t, &h, pi), restartService(t, &h, deck)
	for _, s := range []*testService{pi, deck} {
		waitFor(t, s.name+" keeps a renewed statement", func() bool {
			b, err := os.ReadFile(statements(s))
			return err == nil && !bytes.Equal(b, before[s.name])
		})
	}
	// The renewed keys work: the members connect again, and a copy goes.
	deck.stop()
	deck = restartService(t, &h, deck)
	waitFor(t, "connected with the renewed keys", func() bool { return len(deck.status(t).Peers) == 1 })
	if _, err := deck.do(t, control.Header{Op: control.OpCopy}, "after the renewal"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "after the renewal" })
}

func TestWrongCode(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c, code := openWindow(t, a)
	defer c.Close()
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: wrong}, ""); err == nil || !strings.Contains(err.Error(), "the code is not the window's") {
		t.Fatalf("join with a wrong code: %v", err)
	}
	if st := b.status(t); st.Group != "" {
		t.Errorf("beta is in a group after a wrong code")
	}
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "12345"}, ""); err == nil || !strings.Contains(err.Error(), "six digits") {
		t.Errorf("join with five digits: %v", err)
	}
}

func TestPairingWindow(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	c, _ := openWindow(t, a)
	id := a.status(t).Device
	waitFor(t, "p=1 published", func() bool { return slices.Contains(h.txtOf(id), "p=1") })
	if _, err := a.do(t, control.Header{Op: control.OpPair}, ""); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Errorf("a second window: %v", err)
	}
	// The client hanging up closes the window.
	c.Close()
	waitFor(t, "p=1 gone", func() bool { txt := h.txtOf(id); return txt != nil && !slices.Contains(txt, "p=1") })
	c2, _ := openWindow(t, a)
	c2.Close()
}

func TestConcurrentPairs(t *testing.T) {
	// Two pairs at once open one window.
	var h hub
	a := startService(t, &h, "alpha")
	if _, err := a.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpNew}, ""); err == nil || !strings.Contains(err.Error(), "already in a group") {
		t.Errorf("a second new: %v", err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	clients := make([]*control.Client, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := control.DialAt(a.socket, control.OpPair)
			if err != nil {
				errs[i] = err
				return
			}
			clients[i] = c
			_, errs[i] = c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
		}()
	}
	wg.Wait()
	for _, c := range clients {
		if c != nil {
			defer c.Close()
		}
	}
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("two pairs at once: %v, %v; want one to fail", errs[0], errs[1])
	}
	// The window is published once.
	id := a.status(t).Device
	waitFor(t, "p=1 published", func() bool { return slices.Contains(h.txtOf(id), "p=1") })
}

// TestNoGroupSaysItsPort: out of a group the service says the member port
// it was given, the one its firewall rule opens, so that cbb pair waits for
// the phone there (OpenWrt's init script passes the port in
// /etc/config/cbb).
func TestNoGroupSaysItsPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(t, ln.Addr().String())
	ln.Close()
	dir := t.TempDir()
	var h hub
	s := startIn(t, &h, &testService{name: "router", dir: dir, os: group.OSLinux, port: port})
	if st := s.status(t); st.Group != "" || st.Port != port {
		t.Fatalf("status in no group: group %q, port %d; want port %d", st.Group, st.Port, port)
	}
}

func TestJoinFindsTheWindow(t *testing.T) {
	// A member without a window is found first; join goes to the one that
	// announces a window.
	var h hub
	a := startService(t, &h, "alpha")
	c := startService(t, &h, "gamma")
	pairWith(t, a, c)
	b := startService(t, &h, "beta")
	// No window anywhere once alpha's announcement no longer says so.
	aID := a.status(t).Device
	waitFor(t, "alpha's window gone from mDNS", func() bool { txt := h.txtOf(aID); return txt != nil && !slices.Contains(txt, "p=1") })
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "no member with an open pairing window") {
		t.Errorf("join with no window anywhere: %v", err)
	}
	pairWith(t, a, b)
	if b.status(t).Group != a.status(t).Group {
		t.Error("beta is not in alpha's group")
	}
	// Joining again from a device in a group fails and changes nothing.
	before := b.status(t)
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "already in a group") {
		t.Errorf("join in a group: %v", err)
	}
	if after := b.status(t); after.Device != before.Device || after.Group != before.Group {
		t.Errorf("status changed from %+v to %+v", before, after)
	}
}

func TestJoinRefusesTwoWindows(t *testing.T) {
	var h hub
	a := startService(t, &h, "alpha")
	d := startService(t, &h, "delta")
	b := startService(t, &h, "beta")
	ca, _ := openWindow(t, a)
	defer ca.Close()
	cd, _ := openWindow(t, d)
	defer cd.Close()
	waitFor(t, "both windows published", func() bool {
		return slices.Contains(h.txtOf(a.status(t).Device), "p=1") && slices.Contains(h.txtOf(d.status(t).Device), "p=1")
	})
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: "123456"}, ""); err == nil || !strings.Contains(err.Error(), "2 devices announce a pairing window") {
		t.Errorf("join with two windows: %v", err)
	}
}

func TestJoinWaitsForASecondWindow(t *testing.T) {
	// A second window that answers a moment after the first still makes
	// join refuse, rather than try the code on the first one found.
	var h hub
	a := startService(t, &h, "alpha")
	d := startService(t, &h, "delta")
	b := startService(t, &h, "beta")
	// delta's group exists before the join starts: creating it can take
	// longer than the joiner browses (keys on a slow runner), and only its
	// window should come a moment later.
	if _, err := d.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatalf("new on delta: %v", err)
	}
	ca, _ := openWindow(t, a)
	defer ca.Close()
	waitFor(t, "alpha's window published", func() bool { return slices.Contains(h.txtOf(a.status(t).Device), "p=1") })
	done := make(chan error, 1)
	go func() {
		_, err := b.do(t, control.Header{Op: control.OpJoin, Code: "123456"}, "")
		done <- err
	}()
	// The second window opens while the joiner still looks for windows.
	time.Sleep(500 * time.Millisecond)
	cd, _ := openWindow(t, d)
	defer cd.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "2 devices announce a pairing window") {
		t.Errorf("join with a second window a moment later: %v", err)
	}
}

// memberAddr returns the loopback address of the member port of the
// service with this device ID, once it listens.
func (h *hub) memberAddr(t *testing.T, id string) string {
	t.Helper()
	addr := ""
	waitFor(t, "the member listens", func() bool {
		h.mu.Lock()
		rust := slices.Collect(maps.Keys(h.rust))
		h.mu.Unlock()
		// A service says where it listens, hidden or not.
		for _, s := range rust {
			c, err := control.Dial(control.AdminSocketFor(s.socket))
			if err != nil {
				continue // stopped, or not yet listening
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
			c.Close()
			if err == nil && m.Status != nil && m.Status.Device == id {
				addr = s.addr()
			}
		}
		return addr != ""
	})
	return addr
}

func TestJoinAClosedWindow(t *testing.T) {
	// At a member's address with no window, the joiner hears that the
	// window is closed, not a TLS error: with six digits, which mDNS finds
	// no window for there, and with the QR code's link of a window that
	// closed since.
	var h hub
	a := startService(t, &h, "alpha")
	b := startService(t, &h, "beta")
	c := startService(t, &h, "gamma")
	pairWith(t, a, b)
	addr := h.memberAddr(t, a.status(t).Device)
	if _, err := c.do(t, control.Header{Op: control.OpJoin, Code: "123456", Address: addr}, ""); err == nil || !strings.Contains(err.Error(), "no pairing window") {
		t.Errorf("join at %s without a window: %v", addr, err)
	}
	w, _, link := openWindowLink(t, a)
	id := a.status(t).Device
	waitFor(t, "alpha announces its window", func() bool { return slices.Contains(h.txtOf(id), "p=1") })
	w.Close()
	waitFor(t, "alpha's window closed", func() bool { txt := h.txtOf(id); return txt != nil && !slices.Contains(txt, "p=1") })
	if _, err := c.do(t, control.Header{Op: control.OpJoin, Code: link, Address: addr}, ""); err == nil || !strings.Contains(err.Error(), "the pairing window is closed") {
		t.Errorf("join at %s with the link of a closed window: %v", addr, err)
	}
	if st := c.status(t); st.Group != "" {
		t.Error("gamma is in a group after a closed window")
	}
}

func TestControlSocketMode(t *testing.T) {
	// The control socket is for the users of the service's group, the
	// admin socket for root and the service's user only.
	var h hub
	pi := startService(t, &h, "pi")
	for _, admin := range []bool{false, true} {
		path := pi.socket
		if admin {
			path = control.AdminSocketFor(path)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		checkSocketAccess(t, path, fi, admin)
	}
}

// TestAdminOpsOnlyOnTheAdminSocket checks that the control socket, which the
// members of the service's group reach, refuses what changes the group
// unless the user at the screen confirmed it, which nobody does here (no
// polkit agent in the test's session; docs/design.md, "Confirming admin
// actions").
func TestAdminOpsOnlyOnTheAdminSocket(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	for _, op := range []string{control.OpNew, control.OpPair, control.OpRemove, control.OpAway, control.OpMakeAdmin, "unknown"} {
		c, err := control.Dial(pi.socket)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Do(&control.Message{Header: control.Header{Op: op, Name: "x"}})
		c.Close()
		if err == nil || !strings.Contains(err.Error(), "administrator") {
			t.Errorf("%s on the control socket: %v", op, err)
		}
	}
	c, err := control.Dial(pi.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}}); err != nil {
		t.Errorf("status on the control socket: %v", err)
	}
	if pi.status(t).Group != "" {
		t.Error("a refused new made a group")
	}
}

func TestLinuxMemberWithoutCAKeys(t *testing.T) {
	// A Linux member that holds neither the root key nor an admin key, as
	// any computer of a group whose root is a phone, connects and syncs,
	// but admits nobody.
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	box := startService(t, &h, "box")
	pairWith(t, pi, box)
	waitFor(t, "connected", func() bool { return len(box.status(t).Peers) == 1 })
	if _, err := box.do(t, control.Header{Op: control.OpCopy}, "from the box"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pi has it", func() bool { return pi.paste(t) == "from the box" })
	if _, err := box.do(t, control.Header{Op: control.OpPair}, ""); err == nil {
		t.Error("a member without the group's keys opened a pairing window")
	}
}

func (s *testService) devices(t *testing.T) []control.Device {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpDevices}, "")
	if err != nil {
		t.Fatalf("devices on %s: %v", s.name, err)
	}
	return m.Devices
}

// listed returns the names of the listed devices, sorted.
func listed(devs []control.Device) string {
	var names []string
	for _, d := range devs {
		if d.Listed {
			names = append(names, d.Name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

func TestDevicesAndRevoke(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, deck)
	pairWith(t, pi, laptop)
	for _, s := range []*testService{pi, deck, laptop} {
		waitFor(t, s.name+" lists every device", func() bool { return listed(s.devices(t)) == "deck laptop pi" })
	}
	waitFor(t, "the laptop connects to both", func() bool { return len(laptop.status(t).Peers) == 2 })
	for _, d := range laptop.devices(t) {
		if d.Admin || d.Root != (d.Name == "pi") || !d.Online || d.Role != "member" {
			t.Errorf("on the laptop: %+v", d)
		}
		if d.Self != (d.Name == "laptop") {
			t.Errorf("self is wrong: %+v", d)
		}
	}

	if _, err := laptop.do(t, control.Header{Op: control.OpRemove, Device: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "only an admin") {
		t.Errorf("revoke on the laptop: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "pi"}, ""); err == nil || !strings.Contains(err.Error(), "cannot remove itself") {
		t.Errorf("revoking itself: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "toaster"}, ""); err == nil {
		t.Error("revoked a device that is not there")
	}
	if _, err := deck.do(t, control.Header{Op: control.OpMakeAdmin, Device: "laptop"}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("admin on a member that is not the root: %v", err)
	}
	makeAdmin(t, pi, deck)
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "deck"}, ""); err == nil || !strings.Contains(err.Error(), "already an admin") {
		t.Errorf("making an admin twice: %v", err)
	}
	waitFor(t, "the laptop sees the admin", func() bool {
		for _, d := range laptop.devices(t) {
			if d.Name == "deck" {
				return d.Admin
			}
		}
		return false
	})
	if _, err := deck.do(t, control.Header{Op: control.OpRemove, Device: "pi"}, ""); err == nil || !strings.Contains(err.Error(), "holds the group's root") {
		t.Errorf("revoking the root: %v", err)
	}
	// The admin removes a member.
	m, err := deck.do(t, control.Header{Op: control.OpRemove, Device: "LAPTOP"}, "")
	if err != nil || m.Name != "laptop" {
		t.Fatalf("revoke the laptop: %+v, %v", m, err)
	}
	for _, s := range []*testService{pi, deck} {
		waitFor(t, s.name+" drops the laptop", func() bool {
			return listed(s.devices(t)) == "deck pi" && len(s.status(t).Peers) == 1
		})
	}
	waitFor(t, "the laptop is alone", func() bool { return len(laptop.status(t).Peers) == 0 })
	// The root removes the admin.
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "deck"}, ""); err != nil {
		t.Fatalf("revoke the admin: %v", err)
	}
	waitFor(t, "the pi is alone", func() bool { return listed(pi.devices(t)) == "pi" && len(pi.status(t).Peers) == 0 })
	// The records survive a restart.
	pi.stop()
	pi = restartService(t, &h, pi)
	if got := listed(pi.devices(t)); got != "pi" {
		t.Errorf("after a restart the pi lists %q", got)
	}
}

// TestOnlyTheRootRemovesAnAdmin checks that an admin computer does not
// remove another admin, and that the other admin drops the one the root
// removed.
func TestOnlyTheRootRemovesAnAdmin(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	makeAdmin(t, pi, a)
	makeAdmin(t, pi, b)
	b.stop()
	if _, err := a.do(t, control.Header{Op: control.OpRemove, Device: "b"}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("an admin removed another admin: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a drops b", func() bool { return listed(a.devices(t)) == "a pi" })
}

// TestTakeover checks that an admin takes a group over from its lost root
// computer: on the records of 0.6 only with the group's recovery key (cbb
// recovery, D-117), and a takeover without it, by a member or an admin, is
// refused with that way, as is removing the root. The new root leaves the
// lost root out; the devices that the root and the admin admitted stay and
// keep syncing; the new root admits a computer and makes it an admin; and
// the old root is refused when it comes back.
func TestTakeover(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	c := startService(t, &h, "c")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	makeAdmin(t, pi, a)
	pairWith(t, a, c)
	old := pi.status(t).Device
	if _, err := b.do(t, control.Header{Op: control.OpTakeOver, Device: "pi"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("a member that is no admin took the group over: %v", err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpTakeOver, Device: "b"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("an admin took the group over from a device that is not its root: %v", err)
	}
	pi.stop()
	if _, err := a.do(t, control.Header{Op: control.OpTakeOver, Device: "pi"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("an admin took the group over without the recovery key: %v", err)
	}
	if _, err := a.do(t, control.Header{Op: control.OpRemove, Device: "pi"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("revoking the root: %v", err)
	}
	a = recoverOn(t, &h, a, sheet, "pi")
	waitFor(t, "a is the root", rootIs(t, a, "a"))
	for _, s := range []*testService{b, c} {
		waitFor(t, s.name+" follows the new root", rootIs(t, s, "a"))
	}
	waitFor(t, "a lists itself as the root and the pi no more", func() bool {
		root := false
		for _, d := range a.devices(t) {
			if d.Name == "pi" {
				return false
			}
			root = root || d.Self && d.Root
		}
		return root
	})
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "after the takeover"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "c has it", func() bool { return c.paste(t) == "after the takeover" })
	// The new root admits a new computer by code, which offers it its admin
	// key, and makes it an admin.
	d := startService(t, &h, "d")
	pairWith(t, a, d)
	if _, err := d.do(t, control.Header{Op: control.OpCopy}, "from the newcomer"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "c has the newcomer's copy", func() bool { return c.paste(t) == "from the newcomer" })
	makeAdmin(t, a, d)

	// The old root, left out, is refused: no member keeps a connection
	// to it, and it learns no more of the group.
	restartService(t, &h, pi)
	time.Sleep(3 * time.Second)
	for _, s := range []*testService{a, b, c, d} {
		for _, p := range s.status(t).Peers {
			if p.ID == old {
				t.Errorf("%s is connected to the old root", s.name)
			}
		}
	}
}

// TestSecondTakeover checks that the group is taken over again when the
// second root is lost too: on the records of 0.6 again with the group's
// recovery key (cbb recovery), which outlives the first change of root,
// and what the second root signed, as a name, counts on.
func TestSecondTakeover(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	c := startService(t, &h, "c")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	pairWith(t, pi, c)
	makeAdmin(t, pi, a)
	makeAdmin(t, pi, b)
	pi.stop()
	a = recoverOn(t, &h, a, sheet, "pi")
	for _, s := range []*testService{b, c} {
		waitFor(t, s.name+" follows a's root", rootIs(t, s, "a"))
	}
	if _, err := a.do(t, control.Header{Op: control.OpRename, Device: "c", Name: "named by a"}, ""); err != nil {
		t.Fatal(err)
	}
	named := func(s *testService) bool {
		for _, d := range s.devices(t) {
			if d.Name == "named by a" {
				return true
			}
		}
		return false
	}
	waitFor(t, "b has c's new name", func() bool { return named(b) })
	a.stop()
	if _, err := b.do(t, control.Header{Op: control.OpTakeOver, Device: "a"}, ""); err == nil || !strings.Contains(err.Error(), "cbb recovery") {
		t.Errorf("a takeover of the second root without the recovery key: %v", err)
	}
	b = recoverOn(t, &h, b, sheet, "a")
	waitFor(t, "b is the root", rootIs(t, b, "b"))
	waitFor(t, "c follows the second root", rootIs(t, c, "b"))
	if !named(b) || !named(c) {
		t.Error("the name a's root gave c is gone after b's recovery")
	}
	if _, err := c.do(t, control.Header{Op: control.OpCopy}, "after the second takeover"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b has it", func() bool { return b.paste(t) == "after the second takeover" })
}

func TestUnfrozenAfterTakeover(t *testing.T) {
	// The lost root froze its admin b, which the others then refuse (a
	// frozen device need not learn why, as a removed one). On the records
	// of 0.6 a takes the group over with the recovery key: the freeze stays
	// (docs/protocol.md, section 10, "Re-issue") until the new root thaws
	// b, which then syncs again, an admin no more, and can take the group
	// over from a in turn with the same key.
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	makeAdmin(t, pi, a)
	makeAdmin(t, pi, b)
	bID := b.status(t).Device
	connectedTo := func(s *testService, id string) bool {
		for _, p := range s.status(t).Peers {
			if p.ID == id {
				return true
			}
		}
		return false
	}
	frozenOn := func(s *testService) bool {
		for _, d := range s.devices(t) {
			if d.Name == "b" && d.Frozen {
				return true
			}
		}
		return false
	}
	if _, err := pi.do(t, control.Header{Op: control.OpFreeze, Device: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a knows b is frozen", func() bool { return frozenOn(a) })
	waitFor(t, "the pi and a refuse b", func() bool { return !connectedTo(pi, bID) && !connectedTo(a, bID) })
	pi.stop()
	a = recoverOn(t, &h, a, sheet, "pi")
	waitFor(t, "a is the root", rootIs(t, a, "a"))
	waitFor(t, "b stays frozen under the new root", func() bool { return frozenOn(a) })
	if connectedTo(a, bID) {
		t.Error("the new root is connected to the frozen b")
	}
	if _, err := a.do(t, control.Header{Op: control.OpThaw, Device: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b follows a's root", rootIs(t, b, "a"))
	waitFor(t, "b is frozen no more and stays, an admin no more", func() bool {
		st := b.status(t)
		return !st.Frozen && !st.Removed && !b.isAdmin(t)
	})
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "from b"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a has b's copy", func() bool { return a.paste(t) == "from b" })
	a.stop()
	b = recoverOn(t, &h, b, sheet, "a")
	waitFor(t, "b is the root", rootIs(t, b, "b"))
}

func TestAwayDuringTakeover(t *testing.T) {
	// A member that was away during the change of root knows only the old
	// root, and meets only the new one, which took the group over with the
	// recovery key (cbb recovery): the member takes the new root's records
	// from it and syncs on.
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	c := startService(t, &h, "c")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	pairWith(t, pi, c)
	makeAdmin(t, pi, a)
	c.stop()
	pi.stop()
	a = recoverOn(t, &h, a, sheet, "pi")
	c = restartService(t, &h, c)
	waitFor(t, "c follows the new root", rootIs(t, c, "a"))
	if _, err := c.do(t, control.Header{Op: control.OpCopy}, "after the takeover"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a has it", func() bool { return a.paste(t) == "after the takeover" })
}

func TestTakeoverUndone(t *testing.T) {
	// The old root comes back after an admin took the group over. On the
	// records of 0.6 the change of root by the recovery key is not undone:
	// the old root, which the new root kept in the group, learns that it is
	// a plain device now, its root key revoked, and its removal of the new
	// root is refused; the others stay with the new root, and the old root
	// syncs with them as a member.
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	sheet := newGroup(t, pi)
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	makeAdmin(t, pi, a)
	pi.stop()
	a = recoverOn(t, &h, a, sheet)
	waitFor(t, "b follows the new root", rootIs(t, b, "a"))
	pi = restartService(t, &h, pi)
	waitFor(t, "the old root learns of the change", rootIs(t, pi, "a"))
	if st := pi.status(t); st.Removed {
		t.Error("the new root left the old one out, though it stays")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpRemove, Device: "a"}, ""); err == nil {
		t.Error("the old root removed the new one")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "from the old root"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b has the old root's copy", func() bool { return b.paste(t) == "from the old root" })
	for _, s := range []*testService{a, b} {
		if !rootIs(t, s, "a")() {
			t.Errorf("%s left the new root", s.name)
		}
	}
}

// TestFreezeAnAdmin checks that an admin computer freezes another one,
// which then changes nothing and is refused, and that only the root
// unfreezes it.
func TestFreezeAnAdmin(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "a")
	b := startService(t, &h, "b")
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	makeAdmin(t, pi, a)
	makeAdmin(t, pi, b)
	frozen := func(s *testService) bool {
		for _, d := range s.devices(t) {
			if d.Name == "b" {
				return d.Frozen && !d.Admin
			}
		}
		return false
	}
	if _, err := a.do(t, control.Header{Op: control.OpFreeze, Device: "pi"}, ""); err == nil {
		t.Error("an admin froze the root")
	}
	// b's admin record comes to a from the root, maybe after b holds its
	// admin CA; until then a takes b for an ordinary device.
	waitFor(t, "a knows b is an admin", func() bool {
		for _, d := range a.devices(t) {
			if d.Name == "b" {
				return d.Admin
			}
		}
		return false
	})
	if _, err := a.do(t, control.Header{Op: control.OpFreeze, Device: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	// A frozen device learns nothing, its freeze included: the root and
	// a list it frozen, and the root refuses it.
	waitFor(t, "the root and a hold the freeze", func() bool { return frozen(pi) && frozen(a) })
	waitFor(t, "b is refused", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := b.do(t, control.Header{Op: control.OpRemove, Device: "a"}, ""); err == nil {
		t.Error("a frozen admin signed a record")
	}
	if _, err := a.do(t, control.Header{Op: control.OpThaw, Device: "b"}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("an admin computer unfroze another: %v", err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpThaw, Device: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b is an admin again", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "b" {
				return d.Admin && !d.Frozen
			}
		}
		return false
	})
}

// TestThawReconnectsAtOnce checks that an unfrozen admin connects again
// at once, not when the dialer's backoff, grown while it was refused, ends.
func TestThawReconnectsAtOnce(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	b := startService(t, &h, "b")
	pairWith(t, pi, b)
	makeAdmin(t, pi, b)
	if _, err := pi.do(t, control.Header{Op: control.OpFreeze, Device: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "b is refused", func() bool { return len(pi.status(t).Peers) == 0 })
	// Refused at 0, 1, 3 and 7 s, the dialer waits 8 s for its next try.
	time.Sleep(8 * time.Second)
	if _, err := pi.do(t, control.Header{Op: control.OpThaw, Device: "b"}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 3*time.Second, "b connects again", func() bool { return len(pi.status(t).Peers) == 1 })
}

// TestMacsListen checks that every computer, a Mac as these Linux ones,
// is a full member: it publishes no role and takes connections, so two of
// them keep syncing when no other computer is on.
func TestMacsListen(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	a := startService(t, &h, "mac-a")
	b := startService(t, &h, "mac-b")
	pairWith(t, pi, a)
	pairWith(t, pi, b)
	for _, s := range []*testService{pi, a, b} {
		// The pi publishes p=1 until it sees its pairing window closed,
		// which its mDNS loop checks once a second.
		var txt []string
		waitUpTo(t, 10*time.Second, s.name+" publishes only v and g", func() bool {
			txt = h.txtOf(s.status(t).Device)
			return len(txt) == 2
		}, func() string { return fmt.Sprintf("it publishes %q", txt) })
		waitFor(t, s.name+" meets the pi and the other Mac", func() bool { return len(s.status(t).Peers) == 2 })
	}

	pi.stop()
	waitFor(t, "the Macs are alone together", func() bool {
		return len(a.status(t).Peers) == 1 && len(b.status(t).Peers) == 1
	})
	if _, err := a.do(t, control.Header{Op: control.OpCopy}, "from one Mac"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the other Mac has it", func() bool { return b.paste(t) == "from one Mac" })
}

// TestFallbackDial checks that the member with the higher device ID dials
// when the one with the lower ID cannot reach it.
func TestFallbackDial(t *testing.T) {
	var h hub
	// Each dials the members with a greater device ID at a closed port, so
	// only the fallback connects, after 500 ms (CBB_TEST_FALLBACK).
	a := startEnv(t, &h, "alpha", "CBB_TEST_FALLBACK=500")
	b := startEnv(t, &h, "beta", "CBB_TEST_FALLBACK=500")
	pairWith(t, a, b)
	waitFor(t, "connected", func() bool { return len(a.status(t).Peers) == 1 && len(b.status(t).Peers) == 1 })
	if _, err := b.do(t, control.Header{Op: control.OpCopy}, "through the fallback"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alpha has it", func() bool { return a.paste(t) == "through the fallback" })
	// The member with the higher ID says the other could not reach it.
	hi, lo := a, b
	if a.status(t).Device < b.status(t).Device {
		hi, lo = b, a
	}
	waitFor(t, "unreached", func() bool {
		st := hi.status(t)
		return len(st.Unreached) == 1 && st.Unreached[0] == lo.status(t).Device && st.Port != 0
	})
	if u := lo.status(t).Unreached; len(u) != 0 {
		t.Errorf("the member that dials says it is unreached: %v", u)
	}
}

// A damaged identity file keeps the service running without its group: it
// says what is wrong and refuses everything, so nothing writes over it.
func TestBrokenIdentity(t *testing.T) {
	var h hub
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, group.FileName), []byte(`{"version":1,"devi`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := startIn(t, &h, &testService{name: "a", dir: dir, os: group.OSLinux})
	for _, op := range []string{control.OpStatus, control.OpNew} {
		c := s.dial(t)
		_, err := c.Do(&control.Message{Header: control.Header{Op: op}})
		c.Close()
		var re *control.RequestError
		if !errors.As(err, &re) || re.Msg != errBroken || !strings.Contains(re.Detail, group.FileName) {
			t.Fatalf("%s: %v (%#v)", op, err, re)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, group.FileName))
	if err != nil || string(data) != `{"version":1,"devi` {
		t.Fatalf("the identity file changed: %q, %v", data, err)
	}
}

// TestPairingAcrossARenewal checks that a pairing window keeps working when
// the admin's keys change while it is open: on the records of 0.6 the root's
// sealing key moves to a new epoch and a new statement goes out (as a jump
// of the wall clock past the statements' age brings), while the window binds
// the exchange to the member key, which stays.
func TestPairingAcrossARenewal(t *testing.T) {
	every := renewEvery
	renewEvery = 200 * time.Millisecond
	t.Cleanup(func() { renewEvery = every })
	clock := newTestClock(t, 0)
	var h hub
	pi := startService(t, &h, "pi")
	pi.env = []string{clock.env()}
	pi.stop()
	pi = restartService(t, &h, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	b := startService(t, &h, "b")
	c, code := openWindow(t, pi)
	defer c.Close()
	statements := filepath.Join(pi.dir, "statements.json") // src/sealed.rs in cbb
	before, err := os.ReadFile(statements)
	if err != nil {
		t.Fatal(err)
	}
	clock.set(t, 548*24*time.Hour)
	waitFor(t, "the pi renews its sealing key", func() bool {
		now, err := os.ReadFile(statements)
		return err == nil && !bytes.Equal(now, before)
	})
	if _, err := b.do(t, control.Header{Op: control.OpJoin, Code: code}, ""); err != nil {
		t.Fatalf("join after the renewal: %v", err)
	}
	if m, err := c.Receive(); err != nil || m.Name != "b" {
		t.Fatalf("pair ended with %+v, %v", m, err)
	}
}

// logTrace logs the service's mDNS trace (CBB_MDNS_TRACE) when the test
// failed: what browsing saw and mdns-sd's packets and cache, by the time of
// day in UTC, so that a member that never found another on CI shows why.
// A restarted service's runs share the file; only its last lines are kept.
func logTrace(t *testing.T, name, path string) {
	if !t.Failed() {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Logf("%s mdns: no trace: %v", name, err)
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	const keep = 4000
	if len(lines) > keep {
		t.Logf("%s mdns: the trace's first %d lines left out", name, len(lines)-keep)
		lines = lines[len(lines)-keep:]
	}
	for _, l := range lines {
		t.Logf("%s mdns: %s", name, l)
	}
}

// startRust runs s on the Rust service as a computer's, on a port
// of its own, which addr reads from its log once it is in a group.
func startRust(t *testing.T, bin string, s *testService) *testService {
	t.Helper()
	needHooks(t)
	trace := filepath.Join(s.dir, "mdns-trace.log")
	env := append([]string{"CBB_TEST_ELSEWHERE=" + elsewhereDir(), fmt.Sprintf("CBB_TEST_RENEW_EVERY=%d", renewEvery.Milliseconds()), fmt.Sprintf("CBB_TEST_HUB_KEY_AHEAD=%d", int64(hubKeyAhead.Seconds())), "CBB_MDNS_TRACE=" + trace}, s.env...)
	r := startAloneEnv(t, bin, s.dir, env, "-port", strconv.Itoa(s.port), "-name", s.name)
	t.Cleanup(func() { logTrace(t, s.name, trace) })
	r.name, r.os, r.rust, r.env, r.port = s.name, s.os, true, s.env, s.port
	// It ends with an error after cbb leave or an admin's restart, for
	// systemd to start it again.
	inner := r.done
	r.done = make(chan error, 1)
	go func() {
		err := <-inner
		r.logMu.Lock()
		for _, l := range r.lines {
			if err != nil && strings.Contains(l, "restarting after leaving the group") {
				err = ErrLeft
			}
			if err != nil && strings.Contains(l, "restarting at an admin's request") {
				err = ErrRestart
			}
		}
		r.logMu.Unlock()
		r.done <- err
	}()
	return r
}
