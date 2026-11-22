// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/mdns"
	"github.com/HunterEwok/cbb/internal/remotepaste"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

// publishMember publishes a member by mDNS, as the real one publishes
// itself: TXT v, g and the extra strings, at this computer's addresses and
// port, until the end of the test.
func publishMember(t *testing.T, id, tag string, port int, extra ...string) {
	t.Helper()
	r, err := mdns.New(mdns.Config{ID: id, Port: uint16(port), TXT: append([]string{"v=1", "g=" + tag}, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// TestListenDialed: a member dials a member of the group that does not
// dial (TXT r=listen) as soon as it finds it, though its device ID is the
// higher one, which would otherwise wait for the other to dial. Only
// devices the records hold are dialed, so the one that listens takes the
// device ID of the other member, which stops.
func TestListenDialed(t *testing.T) {
	// On every address: the services dial the addresses mDNS publishes.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var dialed atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	var h hub
	pi := startService(t, &h, "pi")
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, laptop) // the group exists from here
	group := pi.status(t).Group
	// The lower device ID stops and listens: the member left, with the
	// higher one, would wait 30 s for it to dial.
	lower := pi
	if laptop.status(t).Device < pi.status(t).Device {
		lower = laptop
	}
	id := lower.status(t).Device
	lower.stop()
	publishMember(t, id, group, ln.Addr().(*net.TCPAddr).Port, "r=listen")
	waitFor(t, "the member dialed the member that listens", func() bool { return dialed.Load() > 0 })
}

// startAlone runs the small device (Rust, member/) with the state in
// dir; it is stopped by stop or at the end of the test.
func startAlone(t *testing.T, bin, dir string, args ...string) *testService {
	t.Helper()
	return startAloneEnv(t, bin, dir, nil, args...)
}

// startAloneEnv is startAlone with env added to the small device's
// environment.
func startAloneEnv(t *testing.T, bin, dir string, env []string, args ...string) *testService {
	t.Helper()
	s := &testService{name: "small", dir: dir, socket: filepath.Join(dir, "c.sock")}
	cmd := exec.Command(bin, append([]string{"-state", dir, "-socket", s.socket, "-debug", "service"}, args...)...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	// Each line names the service, by its -name when it has one, so that
	// a failing test's log tells the members apart.
	prefix := "small: "
	if i := slices.Index(args, "-name"); i >= 0 && i+1 < len(args) {
		prefix = args[i+1] + ": "
	}
	cmd.Stdout, cmd.Stderr = testWriter{t, prefix, s}, testWriter{t, prefix, s}
	// A child of cbb's that outlives it, such as a cbb-helper, keeps the
	// log's pipes open: the wait ends anyway, so that the test fails where
	// it went wrong rather than hanging the package.
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	s.done = done
	go func() { done <- cmd.Wait() }()
	s.cancel = func() {
		cmd.Process.Signal(os.Interrupt)
		time.AfterFunc(5*time.Second, func() { cmd.Process.Kill() })
	}
	t.Cleanup(s.stop)
	// The admin socket, which the tests dial, opens after the control socket.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := control.Dial(control.AdminSocketFor(s.socket)); err == nil {
			c.Close()
			return s
		}
		select {
		case err := <-s.done:
			s.cancel = nil
			t.Fatalf("the small device ended at the start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the admin socket of the small device never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// testWriter logs what a child process writes, and keeps it in the lines
// of s, if given, for logged.
type testWriter struct {
	t      *testing.T
	prefix string
	s      *testService
}

func (w testWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.t.Log(w.prefix + line)
		if w.s != nil {
			w.s.logMu.Lock()
			w.s.lines = append(w.s.lines, line)
			w.s.logMu.Unlock()
		}
	}
	return len(p), nil
}

// TestFFIJoiner runs the Aurora app's core through ffi's C functions
// with a software key (the example phone-on-linux, CBB_PHONE_ON_LINUX): the
// phone joins the group of 0.6 by the service's home window, as the app
// does when it scans the window's QR code, and then the phone's member
// dials the service and syncs with it both ways; the root mutes it.
func TestFFIJoiner(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	next, in, _ := phoneJoins(t, bin, pi, "-name", "aurora phone", "-dir", t.TempDir(), "-peer", pi.addr())
	var phoneDev *control.Device
	for _, d := range pi.devices(t) {
		if d.Name == "aurora phone" {
			phoneDev = &d
		}
	}
	if phoneDev == nil || phoneDev.OS != group.OSAurora || phoneDev.Role != group.RolePhone {
		t.Fatalf("the phone is listed as %+v", phoneDev)
	}

	// The phone's member dials the service, with its key outside the core.
	waitFor(t, "the phone connected", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	// Its hello presents it as the phone it is, not as a small device. Its
	// key counts as kept in a file: in a group of 0.6 only an attestation
	// the admitter checked makes it hardware (TestFFIPhoneAttest).
	for _, d := range pi.devices(t) {
		if d.Name == "aurora phone" && (d.OS != group.OSAurora || d.Store != "file" || d.Form != "phone" || d.OSVersion != "Aurora OS 5.1.5") {
			t.Fatalf("the connected phone is listed as %+v", d)
		}
	}
	// The app's devices list: the group's root online, and this phone,
	// both from the records, in the control socket's form, field for
	// field (docs/core-api.md, "Operations").
	var devs []control.Device
	waitFor(t, "the app lists the group's devices", func() bool {
		fmt.Fprintln(in, "DEVICES")
		devs = nil
		dec := json.NewDecoder(strings.NewReader(next("DEVICES ")))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&devs); err != nil {
			t.Fatal(err)
		}
		return len(devs) == 2 && devs[0].Listed && devs[1].Listed
	})
	piID := pi.status(t).Device
	var onPi []string
	for _, d := range pi.devices(t) {
		onPi = append(onPi, d.ID)
	}
	for _, d := range devs {
		if !slices.Contains(onPi, d.ID) {
			t.Errorf("the phone lists %s, which the root's devices do not: %v", d.ID, onPi)
		}
		switch {
		case d.ID == piID:
			if !d.Root || !d.Online || d.Self || d.OS == "" {
				t.Fatalf("the app lists the root as %+v", d)
			}
		case d.Name == "aurora phone":
			if !d.Self || d.Root || d.Admin || d.Role != group.RolePhone || d.OS != group.OSAurora {
				t.Fatalf("the app lists itself as %+v", d)
			}
		default:
			t.Fatalf("the app lists an unknown device %+v", d)
		}
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the phone"); err != nil {
		t.Fatal(err)
	}
	if got := next("WRITE "); got != "text to the phone" {
		t.Fatalf("the phone got %q", got)
	}
	fmt.Fprintln(in, "COPY from the phone")
	waitFor(t, "the service has the phone's text", func() bool { return pi.paste(t) == "from the phone" })

	// The app's switch turns sync off: the group's copies stay out of the
	// phone's clipboard, and a text the user hands to the app still goes.
	fmt.Fprintln(in, "SYNC OFF 3600000")
	if got := next("MUTED "); got != "true false" {
		t.Fatalf("with sync off the phone says %q", got)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "kept out"); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(in, "COPY while paused")
	waitFor(t, "the service has the paused phone's text", func() bool { return pi.paste(t) == "while paused" })
	fmt.Fprintln(in, "SYNC ON")
	if got := next("MUTED "); got != "false false" {
		t.Fatalf("with sync on again the phone says %q", got)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "after the pause"); err != nil {
		t.Fatal(err)
	}
	// The next write is this one: the copy made while paused never came.
	if got := next("WRITE "); got != "text after the pause" {
		t.Fatalf("the phone got %q after its pause", got)
	}

	// The root mutes the phone for the group: the app hears it, its copies
	// stay its own, and the root lists it as muted once it connected again.
	if _, err := pi.do(t, control.Header{Op: control.OpMute, Device: "aurora phone", ForMS: time.Hour.Milliseconds()}, ""); err != nil {
		t.Fatal(err)
	}
	if got := next("MUTE "); !strings.HasPrefix(got, "true ") {
		t.Fatalf("the app heard %q of the mute", got)
	}
	fmt.Fprintln(in, "COPY noise")
	if got := next("REFUSED "); !strings.Contains(got, "muted") {
		t.Fatalf("the muted phone's copy: %q", got)
	}
	phoneMuted := func(muted bool) bool {
		for _, d := range pi.devices(t) {
			if d.Name == "aurora phone" {
				return d.Muted == muted
			}
		}
		return false
	}
	waitFor(t, "the root lists the phone as muted", func() bool { return phoneMuted(true) })
	waitFor(t, "the phone connected again", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	if _, err := pi.do(t, control.Header{Op: control.OpUnmute, Device: "aurora phone"}, ""); err != nil {
		t.Fatal(err)
	}
	if got := next("MUTE "); !strings.HasPrefix(got, "false ") {
		t.Fatalf("the app heard %q of the unmute", got)
	}
	waitFor(t, "the root lists the phone as unmuted", func() bool { return phoneMuted(false) })
	waitFor(t, "the phone connected again", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	fmt.Fprintln(in, "COPY after the mute")
	waitFor(t, "the service has the phone's text after the mute", func() bool { return pi.paste(t) == "after the mute" })
}

// TestFFIMember runs the phones' member through ffi's one call
// (cbb_member_call) against a computer: the address the app hands in as
// Bonjour or NSD would find it, the button's rule, images both ways, and
// pausing in the background.
func TestFFIMember(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	next, in, me := phoneJoins(t, bin, pi, "-name", "phone", "-dir", t.TempDir())
	call := func(op string, args any) map[string]any {
		t.Helper()
		req, err := json.Marshal(map[string]any{"op": op, "args": args})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(in, "CALL %s\n", req)
		var ans struct {
			OK    map[string]any `json:"ok"`
			Error map[string]any `json:"error"`
		}
		if err := json.Unmarshal([]byte(next("ANSWER ")), &ans); err != nil || ans.Error != nil {
			t.Fatalf("%s: %v %v", op, err, ans.Error)
		}
		return ans.OK
	}
	peers := func() int { return len(call("peers", nil)["peers"].([]any)) }
	// The one button (D-128) with the clipboard's key: whether it goes to
	// the group, and the group's copy that comes into it.
	swap := func(board string) (bool, map[string]any) {
		a := call("swap", map[string]any{"board": board})
		c, _ := a["copy"].(map[string]any)
		return a["sends"].(bool), c
	}
	sends := func(board string) bool { s, _ := swap(board); return s }

	// The app hands in the computer's address, as Bonjour finds it.
	call("found", map[string]any{"key": "pi", "addrs": []string{pi.addr()}})
	waitFor(t, "the phone connected", func() bool { return peers() == 1 })

	// A command for the phone itself: the root turns its sync off, the
	// member carries it out and the app hears of it; then on again.
	if _, err := pi.do(t, control.Header{Op: control.OpSync, Device: me, On: control.Bool(false)}, ""); err != nil {
		t.Fatalf("the sync command: %v", err)
	}
	if got := next("SYNC "); !strings.HasPrefix(got, "true ") {
		t.Fatalf("the app heard %q of the sync command", got)
	}
	if st := call("muted", nil); st["sync_off"] != true {
		t.Fatalf("after the sync command the phone says %v", st)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpSync, Device: me, On: control.Bool(true)}, ""); err != nil {
		t.Fatalf("the sync command: %v", err)
	}
	if got := next("SYNC "); !strings.HasPrefix(got, "false ") {
		t.Fatalf("the app heard %q of the second sync command", got)
	}

	// The computer's copy comes in on the button over an empty clipboard;
	// once the app took it, the clipboard holds the group's text, and the
	// button neither sends it back nor takes it again.
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "for the button"); err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	waitFor(t, "the button takes the copy", func() bool { _, c = swap(""); return c != nil && c["text"] == "for the button" })
	call("took", map[string]any{"id": c["id"]})
	if s, again := swap("for the button"); s || again != nil {
		t.Fatal("a copy the phone took comes in again, or goes back")
	}

	// A text from the phone, then an image: the computer fetches the image
	// from the phone, and the button keeps the older text from going over
	// it (it did, comparing the clipboard with the group's copy only).
	call("copy", map[string]any{"text": "from the phone"})
	waitFor(t, "the computer has the phone's text", func() bool { return pi.paste(t) == "from the phone" })
	png := randomBytes(200_000)
	call("copy_media", map[string]any{"parts": []any{map[string]any{"type": "image/png", "data": png}}})
	waitFor(t, "the computer has the phone's image", func() bool {
		_, parts, err := pi.pasteMedia(t)
		return err == nil && len(parts) == 1 && bytes.Equal(parts[0].data, png)
	})
	if sends("from the phone") {
		t.Fatal("the button would send the text again over the phone's newer image")
	}
	if !sends("copied since") {
		t.Fatal("the button would not send a new text")
	}

	// An image from the computer: the phone fetches it and opens it.
	jpeg := randomBytes(300_000)
	if err := pi.copyMedia(t, "", sentPart{Part: control.Part{Type: "image/jpeg", Size: int64(len(jpeg))}, data: jpeg}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the button takes the image", func() bool { _, c = swap(""); return c != nil && c["kind"] == "media" })
	out := filepath.Join(t.TempDir(), "image")
	got := call("fetch", map[string]any{"id": c["id"], "max": 100 << 20, "out": out})["parts"].([]any)
	if len(got) != 1 {
		t.Fatalf("fetched %v", got)
	}
	if b, err := os.ReadFile(got[0].(map[string]any)["file"].(string)); err != nil || !bytes.Equal(b, jpeg) {
		t.Fatalf("the phone opened another image: %v", err)
	}

	// In the background the phone drops its connection and makes none; on
	// resume it connects again at once.
	call("pause", nil)
	waitFor(t, "the phone let go", func() bool { return peers() == 0 && len(pi.status(t).Peers) == 0 })
	call("resume", nil)
	if !call("wait", map[string]any{"timeout_ms": 10_000})["connected"].(bool) {
		t.Fatal("the phone did not connect again on resume")
	}

	// On the records of 0.6 the member makes its tunnel keys itself: sync
	// away from home on keeps them (keys_in_file), and the tunnel messages
	// offer them to the group's hubs (TestFFIPhoneAway); off forgets them.
	a, _ := call("away", map[string]any{"on": true})["away"].(map[string]any)
	if a == nil || a["keys_in_file"] != true {
		t.Fatalf("sync away from home on keeps no tunnel keys: %v", a)
	}
	if a := call("away", map[string]any{"on": false})["away"]; a != nil {
		t.Fatalf("the tunnel keys stay after turning it off: %v", a)
	}
}

// TestFFIPhoneAway syncs the phone's member away from home through a Go
// hub's tunnel, as the Aurora app does (member/src/away.rs inside the phone's
// node): turned on at home, it keeps the hub's offer; with no address of
// the hub but its tunnel's, it reaches the hub through the tunnel; off, it
// forgets the keys. CBB_PHONE_ON_LINUX names phone-on-linux built with the
// features member and tunnel.
func TestFFIPhoneAway(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	// On the records of 0.6 the root names its hubs.
	if _, err := pi.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"pi"}}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device
	dir := t.TempDir()
	next, in, _ := phoneJoins(t, bin, pi, "-name", "phone", "-dir", dir)
	try := func(op string, args any) (map[string]any, map[string]any) {
		t.Helper()
		req, err := json.Marshal(map[string]any{"op": op, "args": args})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(in, "CALL %s\n", req)
		var ans struct {
			OK    map[string]any `json:"ok"`
			Error map[string]any `json:"error"`
		}
		if err := json.Unmarshal([]byte(next("ANSWER ")), &ans); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		return ans.OK, ans.Error
	}
	call := func(op string, args any) map[string]any {
		t.Helper()
		ok, e := try(op, args)
		if e != nil {
			t.Fatalf("%s: %v", op, e)
		}
		return ok
	}
	peers := func() int { return len(call("peers", nil)["peers"].([]any)) }
	away := func() map[string]any {
		a, _ := call("away_status", nil)["away"].(map[string]any)
		return a
	}

	// At home: off until the user turns it on; then, on the next
	// connection, the hub's offer comes.
	call("found", map[string]any{"key": "pi", "addrs": []string{pi.addr()}})
	waitFor(t, "the phone connected", func() bool { return peers() == 1 })
	if a := away(); a != nil {
		t.Fatalf("sync away from home is on before it was turned on: %v", a)
	}
	if _, e := try("away", map[string]any{"on": true}); e != nil {
		if strings.Contains(fmt.Sprint(e), "no tunnel") {
			t.Skip("phone-on-linux was built without the feature tunnel")
		}
		t.Fatalf("away: %v", e)
	}
	call("pause", nil)
	waitFor(t, "the phone let go", func() bool { return peers() == 0 })
	call("resume", nil)
	waitFor(t, "the phone keeps the hub's offer", func() bool {
		a := away()
		return a != nil && a["hub_device"] == piID && a["through"] != true
	})

	// Away: the app lost the hub's address, so the phone reaches it
	// through the tunnel.
	call("lost", map[string]any{"key": "pi"})
	call("pause", nil)
	waitFor(t, "the phone let go", func() bool { return peers() == 0 && len(pi.status(t).Peers) == 0 })
	call("resume", nil)
	waitUpTo(t, 30*time.Second, "the phone reaches the hub through the tunnel", func() bool {
		a := away()
		return a != nil && a["through"] == true && peers() == 1
	})
	call("copy", map[string]any{"text": "from the phone, away"})
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the phone, away" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the phone, away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the phone has it", func() bool {
		c, _ := call("current", nil)["copy"].(map[string]any)
		return c != nil && c["text"] == "to the phone, away"
	})

	// Off: the keys are gone, and so is the connection through the tunnel.
	if a := call("away", map[string]any{"on": false})["away"]; a != nil {
		t.Fatalf("still on after turning it off: %v", a)
	}
	if _, err := os.Stat(filepath.Join(dir, "tunnel.json")); !os.IsNotExist(err) {
		t.Errorf("tunnel.json after turning it off: %v", err)
	}
	waitFor(t, "the phone syncs at home only", func() bool { return peers() == 0 })
}

// TestFFIPhoneReach: a computer tells the phone connected to it the other
// members it is connected to (docs/protocol.md, section 4, "Reach"), so
// that a phone away from home shows the members behind its hub as online;
// and a computer that turns sync away from home on sends its tunnel key
// (section 11) to the group's hub, here an admin phone, which answers with
// its offer.
func TestFFIPhoneReach(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi, next, in := adminPhone(t, bin, &h)
	m2 := startService(t, &h, "m2")
	c, _, link := openWindowLink(t, pi)
	if _, err := m2.do(t, control.Header{Op: control.OpJoin, Code: link}, ""); err != nil {
		t.Fatalf("join on m2: %v", err)
	}
	c.Close()
	piID, m2ID := pi.status(t).Device, m2.status(t).Device
	waitFor(t, "m2 is connected to pi", func() bool {
		for _, p := range pi.status(t).Peers {
			if p.ID == m2ID {
				return true
			}
		}
		return false
	})
	call := phoneCall(t, next, in)
	// The phone's view of pi, the only member it is connected to.
	piPeer := func() map[string]any {
		for _, p := range call("peers", nil)["peers"].([]any) {
			if m, _ := p.(map[string]any); m["device"] == string(piID) {
				return m
			}
		}
		return nil
	}
	waitFor(t, "pi tells the phone it reaches m2", func() bool {
		p := piPeer()
		return p != nil && fmt.Sprint(p["reach"]) == fmt.Sprint([]any{string(m2ID)})
	})

	// The admin phone serves as the group's hub; pi, away on, sends it its
	// tunnel key and takes its offer.
	var phoneID string
	for _, d := range pi.devices(t) {
		if d.Name == "member phone" {
			phoneID = d.ID
		}
	}
	port := freeUDP(t)
	call("hub", map[string]any{"port": port, "addrs": []string{fmt.Sprintf("127.0.0.1:%d", port)}})
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "pi took the phone hub's offer", func() bool {
		a := pi.status(t).Away
		return a != nil && a.HubDevice == phoneID
	})

	m2.stop()
	waitFor(t, "pi tells the phone it reaches no one now", func() bool {
		p := piPeer()
		return p != nil && fmt.Sprint(p["reach"]) == fmt.Sprint([]any{})
	})
}

// phoneOnLinux starts ffi's example phone-on-linux, the Aurora app on
// Linux, listening on a free port with the arguments, and returns what
// reads its next line with a prefix and its standard input.
func phoneOnLinux(t *testing.T, bin string, args ...string) (next func(prefix string) string, in io.Writer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	app := exec.Command(bin, append([]string{"-addr", addr}, args...)...)
	app.Stderr = testWriter{t, "phone-on-linux: ", nil}
	out, err := app.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := app.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	// The end of its input ends it, as an exit, so that a build with
	// instrument-coverage writes what it ran; a kill if it does not.
	exited := make(chan struct{})
	t.Cleanup(func() {
		stdin.Close()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			app.Process.Kill()
			<-exited
		}
	})
	lines := make(chan string, 64)
	go func() {
		// The process alone, not its pipes, which the scanner below reads.
		app.Process.Wait()
		close(exited)
	}()
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if l, ok := strings.CutPrefix(sc.Text(), "LOG "); ok {
				t.Logf("phone-on-linux: %s", l)
				continue
			}
			lines <- sc.Text()
		}
		close(lines)
	}()
	return func(prefix string) string {
		t.Helper()
		deadline := time.After(joinTimeout)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("phone-on-linux ended before %q", prefix)
				}
				if rest, ok := strings.CutPrefix(l, prefix); ok {
					return rest
				}
				t.Logf("phone-on-linux, passed over: %s", l)
			case <-deadline:
				t.Fatalf("phone-on-linux printed no %q", prefix)
			}
		}
	}, stdin
}

// phoneJoins opens pi's home window and starts phone-on-linux with args
// (which name its -dir), joining pi's group by the window's QR code as the
// app does when it scans it (-join-window). It returns what phoneOnLinux
// does once the phone joined, and the phone's device ID.
func phoneJoins(t *testing.T, bin string, pi *testService, args ...string) (next func(prefix string) string, in io.Writer, device string) {
	t.Helper()
	c, _, link := openWindowLink(t, pi)
	defer c.Close()
	if link == "" {
		t.Fatalf("%s's window has no QR code of 0.6: is its group one of 0.6?", pi.name)
	}
	next, in = phoneOnLinux(t, bin, append(args, "-join-window", link)...)
	// "Joined <device> <group tag> <name of the member that let it in>".
	joined := strings.Fields(next("Joined "))
	if len(joined) < 2 || !strings.HasPrefix(pi.status(t).Group, joined[1]) {
		t.Fatalf("phone-on-linux joined %q, not the group %s", joined, pi.status(t).Group)
	}
	if m, err := c.Receive(); err != nil || m.Name == "" {
		t.Fatalf("pair on %s ended with %+v, %v", pi.name, m, err)
	}
	return next, in, joined[0]
}

// adminPhone starts a root pi and phone-on-linux joining its group by its
// home window, offering its admin key (-admin), and makes the phone an
// admin as the root's "Make it an admin" does (cbb admin), with the key it
// offered. It returns the root and what phoneJoins does.
func adminPhone(t *testing.T, bin string, h *hub) (pi *testService, next func(prefix string) string, in io.Writer) {
	t.Helper()
	pi = startService(t, h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	next, in, _ = phoneJoins(t, bin, pi, "-name", "member phone", "-admin", "-dir", t.TempDir(), "-peer", pi.addr())
	listed := func() control.Device {
		for _, d := range pi.devices(t) {
			if d.Name == "member phone" {
				return d
			}
		}
		return control.Device{}
	}
	if d := listed(); d.Admin || d.Role != group.RolePhone {
		t.Fatalf("the phone joined as %+v, not as a member", d)
	}
	waitFor(t, "the phone connected", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	// On 0.6 no key a phone holds counts as proven without its
	// attestation (TestFFIPhoneAttest): its keys are "file", which the
	// root makes an admin only when told so.
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "member phone"}, ""); err == nil || !strings.Contains(err.Error(), "-allow-file-key") {
		t.Fatalf("made a phone with keys in a file an admin unasked: %v", err)
	}
	m, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "member phone", AllowFileKey: true}, "")
	if err != nil || m.Name != "member phone" {
		t.Fatalf("making the phone an admin: %+v, %v", m, err)
	}
	if d := listed(); !d.Admin || d.Role != group.RolePhone || d.Store != "file" {
		t.Fatalf("the phone made an admin is listed as %+v", d)
	}
	// The phone acts as an admin once the root's record reached it.
	waitFor(t, "the phone knows it is an admin", func() bool {
		fmt.Fprintln(in, "DEVICES")
		var devs []struct{ Admin, Self bool }
		if err := json.Unmarshal([]byte(next("DEVICES ")), &devs); err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(devs, func(d struct{ Admin, Self bool }) bool { return d.Self && d.Admin })
	})
	return pi, next, in
}

// joinPhoneWindow opens the home window of phone-on-linux (next, in), as
// the app's "Add a device" does, and starts a service named name that
// joins by the window's QR code; it returns that service once the window
// says it joined.
func joinPhoneWindow(t *testing.T, h *hub, next func(prefix string) string, in io.Writer, name string) *testService {
	t.Helper()
	fmt.Fprintln(in, "WINDOW")
	link := next("WINDOW ")
	if !strings.HasPrefix(link, "cbb://pair?") {
		t.Fatalf("the phone's window: %q", link)
	}
	s := startService(t, h, name)
	if _, err := s.do(t, control.Header{Op: control.OpJoin, Code: link}, ""); err != nil {
		t.Fatalf("%s joining the phone's window: %v; the phone: %s", name, err, next("WINDOW FAILED "))
	}
	if got := next("WINDOW DONE "); got != name {
		t.Fatalf("the phone's window admitted %q, not %s", got, name)
	}
	return s
}

// TestFFIJoinerMadeAdmin: the Aurora app joins a group of 0.6 as a member
// by the root's home window, offering its admin key with its proof over
// the pairing, and the root makes it an admin later with that key (cbb
// admin): the records list it as an admin, on the root and on the phone.
func TestFFIJoinerMadeAdmin(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi, next, in := adminPhone(t, bin, &h)
	// The phone's own list has it as an admin too, from the records.
	waitFor(t, "the app lists itself as an admin", func() bool {
		fmt.Fprintln(in, "DEVICES")
		var devs []struct{ Admin, Self bool }
		if err := json.Unmarshal([]byte(next("DEVICES ")), &devs); err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(devs, func(d struct{ Admin, Self bool }) bool { return d.Self && d.Admin })
	})
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "member phone", AllowFileKey: true}, ""); err == nil {
		t.Fatal("the root made the phone an admin twice")
	}

	// A phone that offered no admin key is never made an admin.
	phoneJoins(t, bin, pi, "-name", "plain phone", "-keys", "1", "-dir", t.TempDir(), "-peer", pi.addr())
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "plain phone", AllowFileKey: true}, ""); err == nil || !strings.Contains(err.Error(), "offered this device no admin key") {
		t.Fatalf("made a phone an admin that offered no key: %v", err)
	}
}

// TestFFIJoinerAdmin: an admin phone of a group of 0.6 opens its home
// window with its admin key, as the app's "Add a device" does, and a Go
// computer joins by its QR code: the phone's admin key signs its record,
// and the root lists the computer as a member, never an admin.
func TestFFIJoinerAdmin(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi, next, in := adminPhone(t, bin, &h)
	laptop := joinPhoneWindow(t, &h, next, in, "laptop")
	if g := laptop.status(t).Group; g != pi.status(t).Group {
		t.Fatalf("the computer joined %q, not the group %q", g, pi.status(t).Group)
	}
	waitFor(t, "the root lists the computer the phone admitted", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "laptop" {
				return d.Role == group.RoleMember && !d.Admin
			}
		}
		return false
	})
}

// TestFFIPhoneRoot: the Aurora app makes a group of 0.6 of its own, its
// root key outside the core (cbb_group_new), opens its home window with
// that key, and a Go computer joins by the window's QR code, as the app's
// "Add a device" does. The root phone then changes the computer through
// cbb_member_manage: renames it, mutes it and turns its sync off and on by
// commands the computer carries out, sets the key level, makes it an admin
// with the admin key it offered, and removes it.
func TestFFIPhoneRoot(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	next, in := phoneOnLinux(t, bin, "-name", "root phone", "-group06", "-dir", t.TempDir())
	made := strings.Fields(next("Group "))
	if len(made) != 2 {
		t.Fatalf("the phone's group: %q", made)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); !strings.Contains(devices, `"root phone"`) {
		t.Fatalf("the phone does not list itself: %s", devices)
	}

	var h hub
	laptop := joinPhoneWindow(t, &h, next, in, "laptop")
	st := laptop.status(t)
	if !strings.HasPrefix(st.Group, made[1]) {
		t.Fatalf("the computer joined group %s, not the phone's %s", st.Group, made[1])
	}
	admitted := st.Device
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); !strings.Contains(devices, `"laptop"`) {
		t.Fatalf("the phone does not list the computer: %s", devices)
	}

	// The root's changes to the computer, signed through cbb_member_manage.
	manage := func(req string) string {
		fmt.Fprintln(in, "MANAGE "+req)
		return next("MANAGED ")
	}
	if got := manage(`{"action":"rename","device":"` + admitted + `","name":"desk"}`); !strings.Contains(got, `"ok"`) {
		t.Fatalf("renaming the computer: %s", got)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); !strings.Contains(devices, `"desk"`) || strings.Contains(devices, `"laptop"`) {
		t.Fatalf("the phone does not list the computer's new name: %s", devices)
	}
	// Commands go over a connection to the computer: the phone dials the
	// address it is handed, as the app hands in what the system's DNS-SD
	// finds.
	found, _ := json.Marshal(map[string]any{"op": "found", "args": map[string]any{
		"key": "laptop", "addrs": []string{laptop.addr()}, "device": admitted,
	}})
	fmt.Fprintf(in, "CALL %s\n", found)
	next("ANSWER ")
	waitFor(t, "the root phone connected to the computer", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	if got := manage(`{"action":"mute","device":"` + admitted + `","for_ms":60000}`); !strings.Contains(got, `"status":"done"`) {
		t.Fatalf("muting the computer: %s", got)
	}
	waitFor(t, "the computer muted", func() bool { return laptop.status(t).Muted })
	if got := manage(`{"action":"unmute","device":"` + admitted + `"}`); !strings.Contains(got, `"status":"done"`) {
		t.Fatalf("ending the computer's mute: %s", got)
	}
	waitFor(t, "the computer unmuted", func() bool { return !laptop.status(t).Muted })
	if got := manage(`{"action":"sync_off","device":"` + admitted + `"}`); !strings.Contains(got, `"status":"done"`) {
		t.Fatalf("turning the computer's sync off: %s", got)
	}
	waitFor(t, "the computer's sync off", func() bool { return laptop.status(t).Mode == "own" })
	if got := manage(`{"action":"sync_on","device":"` + admitted + `"}`); !strings.Contains(got, `"status":"done"`) {
		t.Fatalf("turning the computer's sync on: %s", got)
	}
	waitFor(t, "the computer's sync on", func() bool { return laptop.status(t).Mode == "shared" })
	if got := manage(`{"action":"mute","device":"` + made[0] + `"}`); !strings.Contains(got, "its own, not a command") {
		t.Fatalf("the phone muting itself by a command: %s", got)
	}

	// The root's key level and "Make it an admin", by the core's key level
	// rule (cbb_core::keylevel). Neither the phone's keys nor the
	// computer's count as proven in this test: both are "file", which only
	// the level files lets be the root or an admin.
	if got := manage(`{"action":"key_level","level":"proven"}`); !strings.Contains(got, "error") {
		t.Fatalf("the root phone set a key level its own keys do not pass: %s", got)
	}
	if got := manage(`{"action":"make_admin","device":"` + admitted + `","allow_file_key":true}`); !strings.Contains(got, "key level") {
		t.Fatalf("made a computer with keys in a file an admin at the level hardware: %s", got)
	}
	if got := manage(`{"action":"key_level","level":"files"}`); got != `{"ok":{"below":[]}}` {
		t.Fatalf("setting the key level: %s", got)
	}
	if got := manage(`{"action":"make_admin","device":"` + admitted + `"}`); !strings.Contains(got, "allow keys in a file") {
		t.Fatalf("made a computer with keys in a file an admin unasked: %s", got)
	}
	if got := manage(`{"action":"make_admin","device":"` + admitted + `","allow_file_key":true}`); !strings.Contains(got, `"ok"`) {
		t.Fatalf("making the computer an admin: %s", got)
	}
	waitFor(t, "the computer is an admin", func() bool { return laptop.isAdmin(t) })
	if got := manage(`{"action":"make_admin","device":"` + admitted + `","allow_file_key":true}`); !strings.Contains(got, "already an admin") {
		t.Fatalf("making the computer an admin twice: %s", got)
	}

	if got := manage(`{"action":"remove","device":"` + made[0] + `"}`); !strings.Contains(got, "cannot remove itself") {
		t.Fatalf("the phone removing itself: %s", got)
	}
	if got := manage(`{"action":"remove","device":"` + admitted + `"}`); !strings.Contains(got, `"name":"desk"`) {
		t.Fatalf("removing the computer: %s", got)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); strings.Contains(devices, `"desk"`) {
		t.Fatalf("the phone still lists the computer it removed: %s", devices)
	}
}

// joinAlone has the small device join pi's group: cbb pair on pi shows a
// code, and cbb pair -code on the small device reads it from standard input
// and joins at pi's address. In a group of 0.6 it reads the link of the
// window's QR code, which names the window's ID: the address given here is
// the loopback one, which no window announces by mDNS. It returns the
// small device's state directory.
func joinAlone(t *testing.T, bin string, pi *testService) string {
	t.Helper()
	return joinAloneEnv(t, bin, pi, nil)
}

// joinAloneEnv is joinAlone with env added to cbb pair's environment.
func joinAloneEnv(t *testing.T, bin string, pi *testService, env []string) string {
	t.Helper()
	return joinAloneAs(t, bin, pi, "small", env)
}

// joinAloneAs is joinAloneEnv for a device of the name given.
func joinAloneAs(t *testing.T, bin string, pi *testService, name string, env []string) string {
	t.Helper()
	c, code, link := openWindowLink(t, pi)
	defer c.Close()
	if link != "" {
		code = link
	}
	pa := pi.addr()
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "-debug", "pair", "-name", name, "-code", pa)
	join.Stdin = strings.NewReader(code + "\n")
	if env != nil {
		join.Env = append(os.Environ(), env...)
	}
	join.Stderr = testWriter{t, name + " join: ", nil}
	out, err := join.Output()
	if err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != name {
		t.Fatalf("pair on pi ended with %+v, %v", m, err)
	}
	if link != "" {
		// A group of 0.6 has no CA keys: the device keeps the group's
		// records and its own key, and no identity.json.
		if _, err := os.Stat(filepath.Join(dir, "group.cbor")); err != nil {
			t.Fatalf("%s keeps no records of 0.6: %v", name, err)
		}
		return dir
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Errorf("%s saved a CA key", name)
	}
	return dir
}

// TestAloneMember runs the small device among Go members: it joins with the
// code of cbb pair, gets no CA keys, is listed as a small device and syncs
// both ways. (Joining by the phone's QR code, where the phone dials the
// small device, is covered by the phone kits' tests.) CBB_TEST_ALONE names the
// small device's binary (cargo build at the top).
func TestAloneMember(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, laptop)

	dir := joinAlone(t, bin, pi)
	pa := pi.addr()

	// The small device dials the computers, the desk too, and syncs with them.
	desk := startService(t, &h, "desk")
	pairWith(t, pi, desk)
	la := laptop.addr()
	da := desk.addr()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	small := startAlone(t, bin, dir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", pa, "-peer", la, "-peer", da)
	// The control socket answers while the service still loads its identity.
	waitFor(t, "the small device in the group", func() bool {
		_, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil
	})
	st := small.status(t)
	if st.Group != pi.status(t).Group || st.Role != "member" {
		t.Fatalf("small status %+v, want the group %s", st, pi.status(t).Group)
	}
	waitFor(t, "the small device connected", func() bool { return len(small.status(t).Peers) == 3 })
	if _, err := small.do(t, control.Header{Op: control.OpCopy}, "from the small device"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, laptop, desk} {
		waitFor(t, s.name+" has the small device text", func() bool { return s.paste(t) == "from the small device" })
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "from the laptop"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device has the laptop text", func() bool { return small.paste(t) == "from the laptop" })

	// The ZX Spectrum Next's front end: texts in the Spectrum character set,
	// with their length and CRC-32 (member/README.md, "ZX Spectrum Next").
	zx := []byte("ZX \x605\rnext")
	next := exec.Command(bin, "-socket", small.socket, "next", "copy", strconv.Itoa(len(zx)), fmt.Sprintf("%08x", crc32.ChecksumIEEE(zx)))
	next.Stdin = bytes.NewReader(zx)
	if out, err := next.Output(); err != nil || string(out) != "CBBGO\rCBBOK\r" {
		t.Fatalf("cbb next copy: %v; %q", err, out)
	}
	waitFor(t, "the laptop has the Next's text", func() bool { return laptop.paste(t) == "ZX £5\nnext" })
	// .cbb text -s: a secret from the Next arrives as a secret.
	pw := []byte("hunter2")
	next = exec.Command(bin, "-socket", small.socket, "next", "copy", "-secret", strconv.Itoa(len(pw)), fmt.Sprintf("%08x", crc32.ChecksumIEEE(pw)))
	next.Stdin = bytes.NewReader(pw)
	if out, err := next.Output(); err != nil || string(out) != "CBBGO\rCBBOK\r" {
		t.Fatalf("cbb next copy -secret: %v; %q", err, out)
	}
	waitFor(t, "the laptop has the Next's secret", func() bool {
		m, err := laptop.do(t, control.Header{Op: control.OpPaste}, "")
		return err == nil && string(m.Payload) == "hunter2" && m.Kind == control.KindSecret
	})
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "to the `Next` £\nαβγδ"); err != nil {
		t.Fatal(err)
	}
	want := []byte("to the ?Next? \x60\r????")
	waitFor(t, "the small device has the laptop text for the Next", func() bool { return strings.HasPrefix(small.paste(t), "to the") })
	zxOut, err := exec.Command(bin, "-socket", small.socket, "next", "paste").Output()
	if wantOut := fmt.Sprintf("CBB1 %d %08x\r%s\rCBBOK\r", len(want), crc32.ChecksumIEEE(want), want); err != nil || string(zxOut) != wantOut {
		t.Fatalf("cbb next paste: %v; %q, want %q", err, zxOut, wantOut)
	}

	// Every member lists it as a small device, not an admin.
	for _, s := range []*testService{pi, laptop, small} {
		waitFor(t, s.name+" lists the small device", func() bool {
			for _, d := range s.devices(t) {
				if d.ID == st.Device {
					return d.Role == group.RoleMember && !d.Admin && d.Name == "small"
				}
			}
			return false
		})
	}

	// A new small device syncs and says so in its hello; the root turns its
	// sync off with a command, and it keeps it.
	if m := small.status(t).Mode; m != "shared" {
		t.Errorf("a new small device's mode is %q, want shared", m)
	}
	waitFor(t, "the laptop sees the small device's mode", func() bool {
		for _, d := range laptop.devices(t) {
			if d.ID == st.Device {
				return d.Mode == "shared"
			}
		}
		return false
	})
	// The small device offers its key for sealed messages in its own
	// statement, which the root keeps beside the records: the root's
	// command, sealed to that key, goes once the root has it.
	waitFor(t, "the root commands the small device, sealed to its key", func() bool {
		_, err := pi.do(t, control.Header{Op: control.OpSync, Device: st.Device, On: control.Bool(false)}, "")
		return err == nil
	})
	if m := small.status(t).Mode; m != "own" {
		t.Errorf("after the root's command the small device's mode is %q, want own", m)
	}
	// A command with orders is always sealed (format section 6); the
	// device says what it carried out.
	if !small.logged("turned sync off here") {
		t.Error("the small device did not open the command sealed to it")
	}
	if b, err := os.ReadFile(filepath.Join(dir, syncFile)); err != nil || !strings.Contains(string(b), `"off":true`) {
		t.Errorf("the small device's %s: %q, %v", syncFile, b, err)
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpSync, Device: st.Device, On: control.Bool(true)}, ""); err == nil {
		t.Error("a device that is no admin turned the small device's sync on")
	}
	if _, err := small.do(t, control.Header{Op: control.OpSync, On: control.Bool(true)}, ""); err != nil || small.status(t).Mode != "shared" {
		t.Errorf("cbb sync on on the small device: %v", err)
	}

	// The small device and the desk dial each other, the lower device ID
	// first; with the other computers off the two still sync.
	publishMember(t, st.Device, st.Group, port)
	waitUpTo(t, 45*time.Second, "the desk connected to all three", func() bool { return len(desk.status(t).Peers) == 3 })
	pi.stop()
	laptop.stop()
	waitFor(t, "the desk and the small device alone", func() bool {
		return len(desk.status(t).Peers) == 1 && len(small.status(t).Peers) == 1
	})
	if _, err := desk.do(t, control.Header{Op: control.OpCopy}, "from the desk"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device has the desk text", func() bool { return small.paste(t) == "from the desk" })
	if _, err := small.do(t, control.Header{Op: control.OpCopy}, "back from the small device"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the desk has the small device text", func() bool { return desk.paste(t) == "back from the small device" })
}

// TestAloneRemotePaste: an admin's paste reaches the small device's tmux
// target, played here by the test, once the small device's own user turned
// remote paste on; the small device keeps the full member's rules and log,
// and any admin turns it off there.
func TestAloneRemotePaste(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAlone(t, bin, pi)
	pa := pi.addr()
	small := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the small device connected", func() bool {
		m, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(m.Status.Peers) == 1
	})
	// pi sends to the small device, so it must see the connection too: under
	// qemu it can come a moment after the small device's side.
	waitFor(t, "pi has the small device", func() bool { return len(pi.status(t).Peers) == 1 })
	paste := func(text string, h control.Header) error {
		h.Op, h.Device = control.OpPasteOn, "small"
		_, err := pi.do(t, h, text)
		return err
	}
	wantRefused := func(what, text string, h control.Header, reason string) {
		t.Helper()
		if err := paste(text, h); err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v, want %q", what, err, reason)
		}
		time.Sleep(time.Second) // one paste a second from one sender
	}
	wantRefused("off", "ls", control.Header{}, "remote paste is off on this device")
	if m, err := small.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil || m.Status == nil || m.Status.Paste == nil || !m.Status.Paste.On {
		t.Fatalf("paste-receive on: %+v, %v", m, err)
	}
	wantRefused("no target", "ls", control.Header{}, "nothing on this device can paste")

	// The tmux helper offers to paste.
	w := small.dial(t)
	defer w.Close()
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetTmux}}); err != nil {
		t.Fatal(err)
	}
	got := make(chan *control.Message, 4)
	go func() {
		for {
			m, err := w.Receive()
			if err != nil {
				return
			}
			if m.Op != control.OpInject {
				t.Errorf("the tmux helper got %q", m.Op)
				continue
			}
			got <- m
			ans := control.Header{Op: control.OpInjected, Seq: m.Seq}
			if strings.Contains(string(m.Payload), "locked") {
				ans.Error, ans.Refused = "the tmux client is locked", true
			}
			w.Send(&control.Message{Header: ans})
		}
	}()
	waitFor(t, "the small device offers tmux", func() bool {
		p := small.status(t).Paste
		return p != nil && len(p.Targets) == 1 && p.Targets[0] == targetTmux
	})
	out, err := exec.Command(bin, "-socket", small.socket, "paste-receive").Output()
	if err != nil || !strings.Contains(string(out), "Remote paste is on: the group's admins may paste here, without Enter.") {
		t.Errorf("cbb paste-receive: %v; %s", err, out)
	}
	if err := paste("echo \x1b[31mhi\x1b[0m", control.Header{Method: "type"}); err != nil {
		t.Fatal(err)
	}
	if m := <-got; string(m.Payload) != "echo hi" || m.Method != "type" || m.Enter || m.Name != "pi" {
		t.Errorf("tmux got %q %+v", m.Payload, m.Header)
	}
	time.Sleep(time.Second)
	wantRefused("a line break", "two\nlines", control.Header{}, "the text has a line break")
	wantRefused("enter", "ls", control.Header{Enter: true}, "without Enter only")
	wantRefused("locked", "locked", control.Header{}, "the tmux client is locked")
	<-got
	if len(got) != 0 {
		t.Error("a refused paste reached tmux")
	}

	// The log keeps who and how, never the text, in the full member's file.
	log, err := remotepaste.ReadLog(dir)
	if err != nil || len(log) != 6 {
		t.Fatalf("the log: %+v, %v", log, err)
	}
	if e := log[2]; e.Result != "done" || e.Len != len("echo hi") || e.Method != "type" || e.Name != "pi" {
		t.Errorf("the paste's entry: %+v", e)
	}

	// Any admin turns it off.
	if _, err := pi.do(t, control.Header{Op: control.OpReceive, Name: "off", Device: "small"}, ""); err != nil {
		t.Fatal(err)
	}
	if p := small.status(t).Paste; p == nil || p.On {
		t.Errorf("after paste-off: %+v", p)
	}
	if set, err := remotepaste.Load(dir); err != nil || set.On {
		t.Errorf("the small device's settings: %+v, %v", set, err)
	}
}

// TestAloneKeysGrant: the Rust service lets the uinput helper press the keys
// of a remote paste it handed to a desktop session only, for that session's
// user: the paste keys once, Enter once when the command asked for it, and
// none after the session answered, as TestKeysGrant on the Go service.
func TestAloneKeysGrant(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAlone(t, bin, pi)
	small := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pi.addr())
	waitFor(t, "the small device connected", func() bool {
		m, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(m.Status.Peers) == 1
	})
	waitFor(t, "pi has the small device", func() bool { return len(pi.status(t).Peers) == 1 })
	if _, err := small.do(t, control.Header{Op: control.OpReceive, Name: "on", Enter: true}, ""); err != nil {
		t.Fatal(err)
	}
	uid := strconv.Itoa(os.Getuid())
	keys := func(grant, req string) error {
		c, err := control.Dial(small.socket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = c.Do(&control.Message{Header: control.Header{Op: control.OpKeys, Name: req, Value: uid, Keys: grant}})
		return err
	}
	w := small.dial(t)
	defer w.Close()
	w.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := w.Do(&control.Message{Header: control.Header{Op: control.OpWatch, Inject: targetDesktop, PasteOnly: true}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device offers the desktop", func() bool {
		p := small.status(t).Paste
		return p != nil && len(p.Targets) == 1 && p.Targets[0] == targetDesktop
	})
	pasted := make(chan error, 1)
	go func() {
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "small", Enter: true}, "ls")
		pasted <- err
	}()
	m, err := w.Receive()
	if err != nil || m.Op != control.OpInject || len(m.Keys) != 32 || !m.Enter {
		t.Fatalf("the desktop session got %+v, %v", m, err)
	}
	if err := keys(m.Keys, "enter"); err == nil {
		t.Error("Enter before the paste keys")
	}
	// Another grant differs in its first byte; one grant in 256 starts
	// with 00 itself.
	other := "00" + m.Keys[2:]
	if other == m.Keys {
		other = "ff" + m.Keys[2:]
	}
	if err := keys(other, "paste"); err == nil {
		t.Error("the paste keys under another grant")
	}
	if err := keys(m.Keys, "paste"); err != nil {
		t.Errorf("the paste keys: %v", err)
	}
	if err := keys(m.Keys, "paste"); err == nil {
		t.Error("the paste keys twice")
	}
	if err := keys(m.Keys, "enter"); err != nil {
		t.Errorf("Enter after the paste: %v", err)
	}
	if err := keys(m.Keys, "enter"); err == nil {
		t.Error("Enter twice")
	}
	if err := w.Send(&control.Message{Header: control.Header{Op: control.OpInjected, Seq: m.Seq}}); err != nil {
		t.Fatal(err)
	}
	if err := <-pasted; err != nil {
		t.Fatalf("the paste: %v", err)
	}
	if err := keys(m.Keys, "paste"); err == nil {
		t.Error("keys after the session answered")
	}
}

// TestAloneQuickActions: the small device runs only the actions its own user
// turned on, for the signers they allow, and restarts at an admin's request by ending with an error, after which
// systemd starts it again. A reboot is not run here.
func TestAloneQuickActions(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAlone(t, bin, pi)
	pa := pi.addr()
	small := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the small device connected", func() bool {
		m, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(m.Status.Peers) == 1
	})
	// pi sends to the small device, so it must see the connection too: under
	// qemu it can come a moment after the small device's side.
	waitFor(t, "pi has the small device", func() bool { return len(pi.status(t).Peers) == 1 })
	run := func(name string) error {
		time.Sleep(time.Second) // one action a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "small", Name: name}, "")
		return err
	}
	set := func(a control.Action) {
		t.Helper()
		if _, err := small.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{a}}, ""); err != nil {
			t.Fatalf("setting %+v: %v", a, err)
		}
	}
	wantRefused := func(name, reason string) {
		t.Helper()
		if err := run(name); err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v, want %q", name, err, reason)
		}
	}

	wantRefused(actions.Restart, "the action restart is off on this device")
	wantRefused(actions.Lock, "the action lock is off on this device")
	wantRefused("backup", "this device has no action")
	// pi's keys are in files: reboot takes it only with any key, which this
	// test leaves off.
	set(control.Action{Name: actions.Reboot, On: true})
	wantRefused(actions.Reboot, "keys are in hardware")
	set(control.Action{Name: actions.Restart, On: true, By: []string{actions.ByPhone}})
	wantRefused(actions.Restart, "only for phone")
	set(control.Action{Name: actions.Restart, On: true})
	st := small.status(t)
	if len(st.Actions) != len(actions.Presets) || st.Actions[2].Name != actions.Reboot || !st.Actions[2].On || st.Actions[4].On || !st.Actions[5].On {
		t.Errorf("the small device's actions: %+v", st.Actions)
	}
	out, err := exec.Command(bin, "-socket", small.socket, "action").Output()
	if err != nil || !strings.Contains(string(out), "reboot           on, for every admin, keys in hardware only\n") {
		t.Errorf("cbb action: %v; %s", err, out)
	}
	if err := run(actions.Restart); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-small.done:
		small.cancel = nil
		if err == nil {
			t.Error("the small device ended without an error, so systemd would not start it again")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the small device did not restart")
	}

	// The log keeps who asked and how it ended, in the full member's file.
	log, err := actions.ReadLog(dir)
	if err != nil || len(log) != 6 {
		t.Fatalf("the log: %+v, %v", log, err)
	}
	if e := log[5]; e.Action != actions.Restart || e.Result != "done" || e.Name != "pi" {
		t.Errorf("the restart's entry: %+v", e)
	}

	// Started again, it keeps them, and any admin turns them off.
	small = startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the small device connected again", func() bool {
		m, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(m.Status.Peers) == 1
	})
	// pi may still hold the connection from before the restart a moment,
	// so the first try can find no small device to send to.
	waitFor(t, "pi turned the quick actions off", func() bool {
		_, err := pi.do(t, control.Header{Op: control.OpActionOff, Device: "small"}, "")
		if err != nil {
			t.Logf("actions-off: %v", err)
		}
		return err == nil
	})
	if set, err := actions.Load(dir); err != nil || len(set.On()) != 0 {
		t.Errorf("after actions-off: %+v, %v", set, err)
	}
}

// TestAloneMemberAwayXHTTP checks the small device's way over VLESS with
// XHTTP: the hub is reached only through a forwarder whose VLESS sits
// behind a TLS web server with an RSA certificate from a CA, which the small device
// member trusts through SSL_CERT_FILE. The offer's UDP address leads
// nowhere, so the small device tries it, then VLESS, and copies go both
// ways inside it. CBB_TEST_ALONE names the binary.
func TestAloneMemberAwayXHTTP(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	// The web server reaches the forwarder's VLESS listener, on a port of
	// its own once the forwarder listens.
	var vlessBack vlessAddr
	web, ca := vlesstest.WebServerCA(t, path, vlessBack.get)
	roots := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(roots, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf, StateFile: filepath.Join(t.TempDir(), "state.json"),
		VLESS: &forward.VLESSConfig{Listen: "127.0.0.1:0", XHTTP: &forward.XHTTPConfig{Host: vlesstest.WebName, Port: web.Port(), Path: path}}})
	if err != nil {
		t.Fatal(err)
	}
	vlessBack.set(f)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		f.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()

	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAlone(t, bin, pi)
	// The root names itself the group's hub (cbb global hubs); its own forwarder
	// gets a face of its own, whose hubs' credential it registers with.
	if _, err := pi.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"pi"}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(),
		ForwarderKey: forward.Pin(cert.Leaf)}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub registers with the forwarder", func() bool {
		a := pi.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered
	})
	piID := pi.status(t).Device
	home := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pi.addr())
	waitFor(t, "the small device at home", func() bool {
		st, err := home.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(st.Status.Peers) == 1
	})
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device keeps the hub's offer with VLESS", func() bool {
		a := home.status(t).Away
		return a != nil && a.HubDevice == piID
	})
	home.stop()

	// No UDP gets through: the offer's address becomes one that nobody
	// answers.
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	file := filepath.Join(dir, "tunnel.json")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	hubs, _ := st["hubs"].([]any)
	if len(hubs) != 1 {
		t.Fatalf("tunnel.json keeps %d hubs: %s", len(hubs), raw)
	}
	kept := hubs[0].(map[string]any)
	if kept["vless"] == nil || kept["obfuscation"] == nil {
		t.Fatalf("tunnel.json keeps no VLESS or AmneziaWG settings: %s", raw)
	}
	kept["endpoints"] = []string{dead.LocalAddr().String()}
	if raw, err = json.Marshal(st); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	away := startAloneEnv(t, bin, dir, []string{"SSL_CERT_FILE=" + roots}, "-no-mdns", "-no-listen")
	waitUpTo(t, 60*time.Second, "the small device reaches the hub over VLESS", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "from the small device, over VLESS"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the small device, over VLESS" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the small device, over VLESS"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device has it", func() bool { return away.paste(t) == "to the small device, over VLESS" })
}

// TestAloneRootless runs the small device as a rootless install (D-79): its
// hello says so, the root records it as rootless, and it refuses the
// console and the reboot, which need root. CBB_TEST_ALONE names the binary.
func TestAloneRootless(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	dir := joinAlone(t, bin, pi)
	pa := pi.addr()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	small := startAloneEnv(t, bin, dir, []string{"CBB_ROOTLESS=1"}, "-no-mdns", "-port", strconv.Itoa(port), "-peer", pa)
	waitFor(t, "small recorded as rootless", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "small" {
				return d.Store == group.StoreRootless && d.Role == group.RoleMember
			}
		}
		return false
	})
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bin, append([]string{"-socket", small.socket}, args...)...)
		cmd.Env = append(os.Environ(), "CBB_ROOTLESS=1")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run("paste-receive", "on", "-console"); err == nil || !strings.Contains(out, "without root") {
		t.Fatalf("paste-receive -console, rootless: %v; %s", err, out)
	}
	if out, err := run("action", "enable", "reboot", "-yes"); err == nil || !strings.Contains(out, "without root") {
		t.Fatalf("action enable reboot, rootless: %v; %s", err, out)
	}
	if out, err := run("action", "enable", "restart", "-yes"); err != nil {
		t.Fatalf("action enable restart, rootless: %v; %s", err, out)
	}
}

// TestFFIPhoneRemoves has the root phone remove a computer it is connected
// to, as the Android app's GroupTest.a8_renameAndRemove does: the group
// drops the removed computer and gives it nothing more, and the other
// computer stays.
func TestFFIPhoneRemoves(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	next, in := phoneOnLinux(t, bin, "-name", "root phone", "-group06", "-dir", t.TempDir())
	if made := strings.Fields(next("Group ")); len(made) != 2 {
		t.Fatalf("the phone's group: %q", made)
	}
	var h hub
	admit := func(name string) (*testService, string) {
		s := joinPhoneWindow(t, &h, next, in, name)
		return s, s.status(t).Device
	}
	pc, pcID := admit("pc")
	second, id := admit("second")
	call := func(req string) string {
		fmt.Fprintln(in, "CALL "+req)
		return next("ANSWER ")
	}
	call(`{"op":"found","args":{"key":"pc","addrs":["` + pc.addr() + `"]}}`)
	call(`{"op":"found","args":{"key":"second","addrs":["` + second.addr() + `"]}}`)
	waitFor(t, "the phone connected to both", func() bool {
		return len(pc.status(t).Peers) == 1 && len(second.status(t).Peers) == 1
	})
	manage := func(req string) string {
		fmt.Fprintln(in, "MANAGE "+req)
		return next("MANAGED ")
	}
	// A remote paste the root phone signs (the HarmonyOS and Aurora apps'
	// paste): the computer refuses it while its user has not turned remote
	// paste on, and takes the order to turn it off.
	if got := manage(`{"action":"paste","device":"` + pcID + `","method":"type","text":"hello","enter":true}`); !strings.Contains(got, `"status":"refused"`) || !strings.Contains(got, "remote paste is off") {
		t.Fatalf("a paste on a computer with remote paste off: %s", got)
	}
	// With remote paste on there, a paste of only control characters is
	// nothing to paste (remotepaste::to_paste), one paste a second apart.
	if m, err := pc.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil || m.Status == nil || m.Status.Paste == nil || !m.Status.Paste.On {
		t.Fatalf("paste-receive on: %+v, %v", m, err)
	}
	time.Sleep(time.Second)
	if got := manage(`{"action":"paste","device":"` + pcID + `","text":"\u001b[2J"}`); !strings.Contains(got, "nothing to paste") {
		t.Fatalf("a paste of only control characters: %s", got)
	}
	if got := manage(`{"action":"paste_off","device":"` + pcID + `"}`); !strings.Contains(got, `"status":"done"`) {
		t.Fatalf("turning remote paste off on the computer: %s", got)
	}
	if got := manage(`{"action":"rename","device":"` + id + `","name":"bench-second"}`); !strings.Contains(got, `"ok"`) {
		t.Fatalf("renaming the computer: %s", got)
	}
	waitFor(t, "the second computer has its new name", func() bool {
		m, err := second.do(t, control.Header{Op: control.OpDevices}, "")
		if err != nil {
			return false
		}
		for _, d := range m.Devices {
			if d.ID == id && d.Name == "bench-second" {
				return true
			}
		}
		return false
	})
	if got := manage(`{"action":"remove","device":"` + id + `"}`); !strings.Contains(got, `"ok"`) {
		t.Fatalf("removing the computer: %s", got)
	}
	// By the group's rule a removed device need not learn it was removed
	// (whether it sees it is not checked): the group refuses it and gives
	// it nothing more, not even the device list (TestFFIPhoneRemovesAway).
	// In a group of 0.6 a device's status lists as peers only the devices
	// it is connected to now.
	online := func(s *testService) bool { return len(s.status(t).Peers) > 0 }
	waitUpTo(t, 60*time.Second, "the group drops the removed computer", func() bool { return !online(second) })
	fmt.Fprintln(in, "COPY after the removal")
	waitFor(t, "the other computer has the phone's copy", func() bool { return pc.paste(t) == "after the removal" })
	if second.paste(t) == "after the removal" {
		t.Fatal("the phone's copy reached the removed computer")
	}
	if got := manage(`{"action":"rename","device":"` + pcID + `","name":"bench-pc"}`); !strings.Contains(got, `"ok"`) {
		t.Fatalf("renaming the other computer: %s", got)
	}
	waitFor(t, "the other computer has its new name", func() bool {
		return slices.ContainsFunc(pc.devices(t), func(d control.Device) bool { return d.Name == "bench-pc" })
	})
	for _, d := range second.devices(t) {
		if d.Name == "bench-pc" {
			t.Fatal("the removed computer got the records written after its removal")
		}
	}
	if st := pc.status(t); st.Removed || !online(pc) {
		t.Fatalf("the other computer left the group with the removed one: removed %v, peers %+v", st.Removed, st.Peers)
	}
}

// TestFFIPhoneRemovesAway: the root phone removes a computer it never
// connected to after it joined. By the group's rule a removed device need
// not learn it was removed: the group refuses it and gives it nothing, not
// even the device list. So the phone refuses its hello, nothing the
// computer copies reaches the phone and nothing of the phone's reaches it,
// and it never gets the records written after its removal.
func TestFFIPhoneRemovesAway(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	next, in := phoneOnLinux(t, bin, "-name", "root phone", "-group06", "-dir", t.TempDir())
	made := strings.Fields(next("Group "))
	if len(made) != 2 {
		t.Fatalf("the phone's group: %q", made)
	}
	var h hub
	second := joinPhoneWindow(t, &h, next, in, "second")
	id := second.status(t).Device
	manage := func(req string) string {
		fmt.Fprintln(in, "MANAGE "+req)
		return next("MANAGED ")
	}
	if got := manage(`{"action":"remove","device":"` + id + `"}`); !strings.Contains(got, `"ok"`) {
		t.Fatalf("removing the computer: %s", got)
	}
	// A record written after the removal, which the removed computer must
	// never get.
	if got := manage(`{"action":"rename","device":"` + made[0] + `","name":"renamed phone"}`); !strings.Contains(got, `"ok"`) {
		t.Fatalf("renaming the phone: %s", got)
	}
	fmt.Fprintln(in, `CALL {"op":"found","args":{"key":"second","addrs":["`+second.addr()+`"]}}`)
	next("ANSWER ")
	if _, err := second.do(t, control.Header{Op: control.OpCopy}, "from the removed computer"); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(in, "COPY from the root phone")
	// For a while, with the phone dialing it and it dialing the phone: no
	// connection stands, and nothing crosses either way.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		fmt.Fprintln(in, "PEERS")
		got := next("PEERS ")
		peers := second.status(t).Peers
		// In a group of 0.6 the status lists only the connected peers.
		if got != "0" || len(peers) > 0 {
			t.Fatalf("a connection with the removed computer stands: the phone has %s, the computer %+v", got, peers)
		}
	}
	fmt.Fprintln(in, `CALL {"op":"current"}`)
	if got := next("ANSWER "); strings.Contains(got, "from the removed computer") {
		t.Fatalf("the removed computer's copy reached the phone: %s", got)
	}
	if got := second.paste(t); got == "from the root phone" {
		t.Fatal("the phone's copy reached the removed computer")
	}
	for _, d := range second.devices(t) {
		if d.Name == "renamed phone" {
			t.Fatal("the removed computer got the records written after its removal")
		}
	}
}
