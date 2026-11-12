// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
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
	"github.com/HunterEwok/cbb/internal/phone"
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

// TestListenDialed: the members dial a member that does not dial (TXT
// r=listen) as soon as they find it, whatever the device IDs.
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
	// The lowest device ID: a member that dials would wait 30 s for it to dial.
	publishMember(t, strings.Repeat("0", 32), pi.status(t).Group, ln.Addr().(*net.TCPAddr).Port, "r=listen")
	waitFor(t, "the members dialed the member that listens", func() bool { return dialed.Load() > 0 })
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

// TestEmbassyJoiner: the ESP32 firmware's pairing code (embassy/),
// built for Linux as esp32-on-linux, joins by the phone over embassy-net on a
// TAP interface, as the board does over Wi-Fi. CBB_ESP32_ON_LINUX names the
// binary; the interface tap0 must be up as 192.168.69.1/24, and the device
// takes 192.168.69.2.
func TestEmbassyJoiner(t *testing.T) {
	bin := os.Getenv("CBB_ESP32_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_ESP32_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "identity.json")
	join := exec.Command(bin, "-debug", "-tap", "tap0", "-addr", "192.168.69.2/24", "-name", "board", "-identity", file)
	join.Stderr = testWriter{t, "esp32-on-linux: ", nil}
	out, err := join.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := join.Start(); err != nil {
		t.Fatal(err)
	}
	defer join.Process.Kill()
	const prefix = "Or paste this into the app: "
	var qr string
	sc := bufio.NewScanner(out)
	for qr == "" && sc.Scan() {
		if line, ok := strings.CutPrefix(sc.Text(), prefix); ok {
			qr = line
		}
	}
	if !strings.Contains(qr, "192.168.69.2%3A8764") && !strings.Contains(qr, "192.168.69.2:8764") {
		t.Fatalf("esp32-on-linux showed %q, not a QR code with its address", qr)
	}
	if name := admitJoiner(t, pi, qr); name != "board" {
		t.Fatalf("the board joined as %q", name)
	}
	waitFor(t, "pi lists the board as a member", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "board" {
				return d.Role == group.RoleMember && len(d.Caps) == 0
			}
		}
		return false
	})
	var rest strings.Builder
	for sc.Scan() {
		rest.WriteString(sc.Text() + "\n")
	}
	if err := join.Wait(); err != nil || !strings.Contains(rest.String(), "Joined the group "+pi.status(t).Group) {
		t.Fatalf("esp32-on-linux: %v; %s", err, rest.String())
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Error("the board saved a CA key")
	}
}

// TestFFIJoiner runs the Aurora app's core through ffi's C functions
// with a software key (the example phone-on-linux, CBB_PHONE_ON_LINUX): the
// phone shows its QR code, the service admits it as cbb pair -qr does, and
// then the phone's member dials the service and syncs with it both ways.
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
	next, in := phoneOnLinux(t, bin, "-name", "aurora phone", "-dir", t.TempDir(), "-peer", pi.addr())
	qr := next("QR: ")
	// The service admits it as cbb pair -qr does.
	jc, ok := phone.ParseJoinQR(qr)
	if !ok {
		t.Fatalf("not a join QR code: %q", qr)
	}
	m, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint}, "")
	if err != nil || m.Name != "aurora phone" {
		t.Fatalf("admitting the phone: %v, %+v", err, m)
	}
	var phoneDev *control.Device
	for _, d := range pi.devices(t) {
		if d.Name == "aurora phone" {
			phoneDev = &d
		}
	}
	if phoneDev == nil || phoneDev.OS != group.OSAurora || phoneDev.Role != group.RolePhone {
		t.Fatalf("the phone is listed as %+v", phoneDev)
	}
	if joined := next("Joined "); !strings.HasSuffix(joined, " "+pi.status(t).Group) {
		t.Fatalf("phone-on-linux joined %q, not the group %s", joined, pi.status(t).Group)
	}

	// The phone's member dials the service, with its key outside the core.
	waitFor(t, "the phone connected", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	// Its hello presents it as the phone it is, not as a small device.
	for _, d := range pi.devices(t) {
		if d.Name == "aurora phone" && (d.OS != group.OSAurora || d.Store != "hardware" || d.Form != "phone" || d.OSVersion != "Aurora OS 5.1.5") {
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

	// Eighteen months later the service renews the phone's certificate,
	// and the app gets it to keep in its own file: the core has no
	// identity file for a key outside it.
	pi.port = portOf(t, pi.addr())
	pi.stop()
	clock := newTestClock(t, 548*24*time.Hour)
	pi.env = []string{clock.env()}
	pi = restartService(t, &h, pi)
	der, err := base64.StdEncoding.DecodeString(next("IDENTITY "))
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := x509.ParseCertificate(der)
	if err != nil || renewed.NotAfter.Before(time.Now().Add(548*24*time.Hour)) {
		t.Fatalf("the phone kept no renewed certificate: %v", err)
	}
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
	next, in := phoneOnLinux(t, bin, "-name", "phone", "-dir", t.TempDir())
	jc, ok := phone.ParseJoinQR(next("QR: "))
	if !ok {
		t.Fatal("not a join QR code")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint}, ""); err != nil {
		t.Fatalf("admitting the phone: %v", err)
	}
	me, _, _ := strings.Cut(next("Joined "), " ")
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
	waiting := func() map[string]any {
		c, _ := call("waiting", nil)["copy"].(map[string]any)
		return c
	}
	sends := func(board string) bool { return call("sends", map[string]any{"board": board})["sends"].(bool) }

	// The app hands in the computer's address, as Bonjour finds it, and
	// hears of the computer with its certificate chain once its hello came.
	call("found", map[string]any{"key": "pi", "addrs": []string{pi.addr()}})
	var peer struct {
		Device string   `json:"device"`
		Chain  []string `json:"chain"`
	}
	if err := json.Unmarshal([]byte(next("PEER ")), &peer); err != nil || peer.Device == "" || len(peer.Chain) == 0 {
		t.Fatalf("the peer event: %+v %v", peer, err)
	}
	waitFor(t, "the phone connected", func() bool { return peers() == 1 })

	// A command for the phone itself other than a mute, which the member
	// carries out, goes to the app, whose answer goes back.
	answered := make(chan error, 1)
	go func() {
		_, err := pi.do(t, control.Header{Op: control.OpSync, Device: me, On: control.Bool(false)}, "")
		answered <- err
	}()
	token, cmd, _ := strings.Cut(next("COMMAND "), " ")
	if !strings.Contains(cmd, `"body"`) {
		t.Fatalf("the command event carries %s", cmd)
	}
	call("answer", map[string]any{"token": json.Number(token), "status": "done"})
	if err := <-answered; err != nil {
		t.Fatalf("the phone's answer to the sync command: %v", err)
	}
	// A tunnel key goes into the hellos; a key of the wrong size does not.
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	call("tunnel_key", map[string]any{"key": key, "psk": key})
	call("tunnel_key", map[string]any{})

	// The computer's copy waits for the phone until the app takes it; then
	// the clipboard holds the group's text, and the button sends nothing.
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "for the button"); err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	waitFor(t, "the copy waits", func() bool { c = waiting(); return c != nil && c["text"] == "for the button" })
	call("took", map[string]any{"id": c["id"]})
	if waiting() != nil || sends("for the button") {
		t.Fatal("a copy the phone took still waits, or goes back")
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
	waitFor(t, "the image waits", func() bool { c = waiting(); return c != nil && c["kind"] == "media" })
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
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device
	dir := t.TempDir()
	next, in := phoneOnLinux(t, bin, "-name", "phone", "-dir", dir)
	jc, ok := phone.ParseJoinQR(next("QR: "))
	if !ok {
		t.Fatal("not a join QR code")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint}, ""); err != nil {
		t.Fatalf("admitting the phone: %v", err)
	}
	next("Joined ")
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
// and turning sync away from home on there makes the phone connect again,
// so that the hello it gets carries the new tunnel key, which a phone that
// is the group's hub answers with its offer.
func TestFFIPhoneReach(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	m2 := startService(t, &h, "m2")
	c, code := openWindow(t, pi)
	if _, err := m2.do(t, control.Header{Op: control.OpJoin, Code: code, Address: pi.addr()}, ""); err != nil {
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
	next, in := phoneOnLinux(t, bin, "-name", "phone", "-dir", t.TempDir())
	jc, ok := phone.ParseJoinQR(next("QR: "))
	if !ok {
		t.Fatal("not a join QR code")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint}, ""); err != nil {
		t.Fatalf("admitting the phone: %v", err)
	}
	next("Joined ")
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
		if err := json.Unmarshal([]byte(next("ANSWER ")), &ans); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if ans.Error != nil {
			t.Fatalf("%s: %v", op, ans.Error)
		}
		return ans.OK
	}
	// The phone's view of pi, the only member it is told of.
	piPeer := func() map[string]any {
		for _, p := range call("peers", nil)["peers"].([]any) {
			if m, _ := p.(map[string]any); m["device"] == string(piID) {
				return m
			}
		}
		return nil
	}
	call("found", map[string]any{"key": "pi", "addrs": []string{pi.addr()}})
	waitFor(t, "pi tells the phone it reaches m2", func() bool {
		p := piPeer()
		return p != nil && fmt.Sprint(p["reach"]) == fmt.Sprint([]any{string(m2ID)})
	})
	if p := piPeer(); p["tunnel_key"] != nil {
		t.Fatalf("pi offers a tunnel key before sync away from home is on: %v", p["tunnel_key"])
	}

	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the phone connected again and got pi's tunnel key", func() bool {
		p := piPeer()
		return p != nil && p["tunnel_key"] != nil
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
	t.Cleanup(func() {
		stdin.Close()
		app.Process.Kill()
		app.Wait()
	})
	lines := make(chan string, 64)
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
			case <-deadline:
				t.Fatalf("phone-on-linux printed no %q", prefix)
			}
		}
	}, stdin
}

// TestFFIJoinerMadeAdmin: the Aurora app joins as a member, its member's
// hellos offering its admin key, and the root makes it an admin later, as
// the root's "Make it an admin" does (cbb admin): the phone gets its
// admin CA in the admin message and the records list it as an admin.
func TestFFIJoinerMadeAdmin(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	next, in := phoneOnLinux(t, bin, "-name", "member phone", "-offer-admin", "-dir", t.TempDir(), "-peer", pi.addr())
	jc, ok := phone.ParseJoinQR(next("QR: "))
	if !ok {
		t.Fatal("no join QR code")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint}, ""); err != nil {
		t.Fatalf("admitting the phone: %v", err)
	}
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
	m, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "member phone"}, "")
	if err != nil || m.Name != "member phone" {
		t.Fatalf("making the phone an admin: %+v, %v", m, err)
	}
	der, err := base64.StdEncoding.DecodeString(next("ADMIN CA "))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil || !ca.IsCA || !strings.HasPrefix(ca.Subject.CommonName, "cbb admin ") {
		t.Fatalf("the admin CA: %v, %+v", err, ca)
	}
	// The member checks the CA for the app and stops offering the key; a
	// second CA finds no key offered.
	take := func() map[string]any {
		req, _ := json.Marshal(map[string]any{"op": "take_admin_ca", "args": map[string]any{"key": der}})
		fmt.Fprintf(in, "CALL %s\n", req)
		var ans struct{ Error map[string]any }
		if err := json.Unmarshal([]byte(next("ANSWER ")), &ans); err != nil {
			t.Fatal(err)
		}
		return ans.Error
	}
	if e := take(); e != nil {
		t.Fatalf("the member refused the root's admin CA: %v", e)
	}
	if e := take(); e == nil {
		t.Fatal("the member took an admin CA with no admin key offered")
	}
	if d := listed(); !d.Admin || d.Role != group.RolePhone || d.Store != "hardware" {
		t.Fatalf("the phone made an admin is listed as %+v", d)
	}
	// The phone's own list has it as an admin too, from the records.
	waitFor(t, "the app lists itself as an admin", func() bool {
		fmt.Fprintln(in, "DEVICES")
		var devs []struct{ Admin, Self bool }
		if err := json.Unmarshal([]byte(next("DEVICES ")), &devs); err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(devs, func(d struct{ Admin, Self bool }) bool { return d.Self && d.Admin })
	})
	if _, err := pi.do(t, control.Header{Op: control.OpMakeAdmin, Device: "member phone"}, ""); err == nil {
		t.Fatal("the root made the phone an admin twice")
	}
}

// TestFFIJoinerAdmin: the Aurora app that offers an admin key joins as an
// admin through the root's window that may make admins (cbb pair -qr
// -admin), its admin CA for that key, and any other window refuses it.
func TestFFIJoinerAdmin(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	admit := func(next func(string) string, admins bool) (*control.Message, error) {
		jc, ok := phone.ParseJoinQR(next("QR: "))
		if !ok {
			t.Fatal("not a join QR code")
		}
		return pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint, Admins: admins}, "")
	}
	next, _ := phoneOnLinux(t, bin, "-name", "refused phone", "-admin")
	if _, err := admit(next, false); err == nil {
		t.Fatal("a window that makes no admins admitted a phone that offers an admin key")
	}
	next, in := phoneOnLinux(t, bin, "-name", "admin phone", "-admin", "-dir", t.TempDir(), "-peer", pi.addr())
	if m, err := admit(next, true); err != nil || m.Name != "admin phone" {
		t.Fatalf("admitting the phone as an admin: %v, %+v", err, m)
	}
	der, err := base64.StdEncoding.DecodeString(next("Admin CA "))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil || !ca.IsCA || !strings.HasPrefix(ca.Subject.CommonName, "cbb admin ") {
		t.Fatalf("the admin CA: %v, %+v", err, ca)
	}
	for _, d := range pi.devices(t) {
		if d.Name == "admin phone" && (!d.Admin || d.Role != group.RolePhone) {
			t.Errorf("the phone is listed as %+v", d)
		}
		if d.Name == "refused phone" {
			t.Errorf("the refused phone is listed: %+v", d)
		}
	}

	// The admin phone admits a computer that listens, as the app does when
	// it scans the computer's QR code: with a certificate from its admin
	// CA, and a device record the root takes from it.
	waitFor(t, "the admin phone connected", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	laptop, qr := listeningJoin(t, &h, "laptop")
	fmt.Fprintln(in, "ADMIT "+qr)
	admitted := next("ADMITTED ")
	t.Logf("the admin phone admitted the computer %s", admitted)
	if got := next("ADMIT DONE "); got != "true" {
		t.Fatalf("the computer did not confirm its join: %q", got)
	}
	id := joinedIdentity(t, laptop, admitted)
	if id.Issuer == nil || !bytes.Equal(id.Issuer.Raw, ca.Raw) {
		t.Fatalf("the computer's identity: %+v", id)
	}
	if err := id.Cert.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("the computer's certificate is not from the phone's admin CA: %v", err)
	}
	if got, err := group.DeviceOf(id.Cert); err != nil || string(got) != admitted {
		t.Fatalf("the computer's certificate names %q: %v", got, err)
	}
	waitFor(t, "the root lists the computer the phone admitted", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "laptop" {
				return d.Role == group.RoleMember && d.OS == group.OSLinux && !d.Admin
			}
		}
		return false
	})
}

// TestFFIPhoneTakeover: the Aurora app as an admin takes the group the
// computer root handed to it (cbb handover), through the core's takeover
// (cbb_member_manage): a root CA for its own admin key, the claim, and once
// it took effect the records and certificate of the new root, which the
// computer then lists as the group's root.
func TestFFIPhoneTakeover(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	next, in := phoneOnLinux(t, bin, "-name", "admin phone", "-admin", "-dir", t.TempDir(), "-peer", pi.addr())
	jc, ok := phone.ParseJoinQR(next("QR: "))
	if !ok {
		t.Fatal("not a join QR code")
	}
	if _, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint, Admins: true}, ""); err != nil {
		t.Fatal(err)
	}
	next("Admin CA ")
	waitFor(t, "the admin phone connected", func() bool {
		fmt.Fprintln(in, "PEERS")
		return next("PEERS ") == "1"
	})
	manage := func(req string) map[string]any {
		fmt.Fprintln(in, "MANAGE "+req)
		var a map[string]any
		got := next("MANAGED ")
		if err := json.Unmarshal([]byte(got), &a); err != nil {
			t.Fatalf("the answer %q: %v", got, err)
		}
		return a
	}
	ok2 := func(a map[string]any) map[string]any {
		t.Helper()
		o, ok := a["ok"].(map[string]any)
		if !ok {
			t.Fatalf("refused: %v", a)
		}
		return o
	}

	root, _ := ok2(manage(`{"action":"root_ca"}`))["root_ca"].(string)
	if root == "" {
		t.Fatal("no root CA")
	}
	if a := manage(`{"action":"take_handed_over","root_ca":"` + root + `"}`); a["error"] == nil {
		t.Fatalf("the phone claimed a group nobody handed to it: %v", a)
	}
	if st := ok2(manage(`{"action":"finish_takeover","root_ca":"` + root + `"}`))["state"]; st != "none" {
		t.Fatalf("a claim before claiming: %v", st)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpHandOver, Device: "admin phone"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the phone holds the handover", func() bool {
		return manage(`{"action":"take_handed_over","root_ca":"` + root + `"}`)["error"] == nil
	})
	done := ok2(manage(`{"action":"finish_takeover","root_ca":"` + root + `","name":"admin phone","os":"aurora"}`))
	if done["state"] != "effective" || done["cert"] == nil {
		t.Fatalf("finishing the takeover: %v", done)
	}
	waitFor(t, "the computer lists the phone as the root", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "admin phone" {
				return d.Root && d.Role == group.RolePhone
			}
		}
		return false
	})
	for _, d := range pi.devices(t) {
		if d.Self && d.Root {
			t.Errorf("the computer still holds the root: %+v", d)
		}
	}
}

// TestFFIPhoneRoot: the Aurora app makes a group of its own, its root key
// outside the core (cbb_group_new), and as the group's root admits a
// computer that listens, as the app does when it scans the computer's QR
// code: the computer takes the phone's group, a certificate from its root
// and no issuer.
func TestFFIPhoneRoot(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	next, in := phoneOnLinux(t, bin, "-name", "root phone", "-new-group", "-dir", t.TempDir())
	made := strings.Fields(next("Group "))
	if len(made) != 2 {
		t.Fatalf("the phone's group: %q", made)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); !strings.Contains(devices, `"root phone"`) {
		t.Fatalf("the phone does not list itself: %s", devices)
	}

	var h hub
	laptop, qr := listeningJoin(t, &h, "laptop")
	fmt.Fprintln(in, "ADMIT "+qr)
	admitted := next("ADMITTED ")
	if got := next("ADMIT DONE "); got != "true" {
		t.Fatalf("the computer did not confirm its join: %q", got)
	}
	id := joinedIdentity(t, laptop, admitted)
	if id.Issuer != nil {
		t.Fatalf("the computer's identity: %+v", id)
	}
	if got := group.Tag(id.GroupCA.Cert); got != made[1] {
		t.Fatalf("the computer joined group %s, not the phone's %s", got, made[1])
	}
	if !id.GroupCA.Cert.IsCA || !strings.HasPrefix(id.GroupCA.Cert.Subject.CommonName, "cbb group root ") {
		t.Fatalf("the group's root: %+v", id.GroupCA.Cert.Subject)
	}
	if err := id.Cert.CheckSignatureFrom(id.GroupCA.Cert); err != nil {
		t.Fatalf("the computer's certificate is not from the phone's root: %v", err)
	}
	if got, err := group.DeviceOf(id.Cert); err != nil || string(got) != admitted {
		t.Fatalf("the computer's certificate names %q: %v", got, err)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); !strings.Contains(devices, `"laptop"`) {
		t.Fatalf("the phone does not list the computer: %s", devices)
	}

	// The root's changes to the computer, signed through cbb_member_manage.
	manage := func(req string) string {
		fmt.Fprintln(in, "MANAGE "+req)
		return next("MANAGED ")
	}
	if got := manage(`{"action":"rename","device":"` + admitted + `","name":"desk"}`); got != `{"ok":{}}` {
		t.Fatalf("renaming the computer: %s", got)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); !strings.Contains(devices, `"desk"`) || strings.Contains(devices, `"laptop"`) {
		t.Fatalf("the phone does not list the computer's new name: %s", devices)
	}
	// The computer is not running, so a command for it finds no way there.
	if got := manage(`{"action":"mute","device":"` + admitted + `","for_ms":60000,"timeout_ms":1000}`); !strings.Contains(got, "not connected") {
		t.Fatalf("muting a computer that is not running: %s", got)
	}
	// The device's house is a command too: sync_off and sync_on are mode commands.
	if got := manage(`{"action":"sync_off","device":"` + admitted + `","timeout_ms":1000}`); !strings.Contains(got, "not connected") {
		t.Fatalf("turning the sync of a computer that is not running off: %s", got)
	}
	// Remote paste: the core checks the command before it looks for a way.
	if got := manage(`{"action":"paste","device":"` + admitted + `","text":"ls","mode":"shout","timeout_ms":1000}`); !strings.Contains(got, "not paste or type") {
		t.Fatalf("a paste by no way there is: %s", got)
	}
	for _, req := range []string{
		`"text":"ls","enter":true`,
		`"text":"hunter2","mode":"type","kind":"secret"`,
		`"text":"0123456789abcdef0123456789abcdef","kind":"media"`,
	} {
		if got := manage(`{"action":"paste","device":"` + admitted + `",` + req + `,"timeout_ms":1000}`); !strings.Contains(got, "not connected") {
			t.Fatalf("a paste (%s) for a computer that is not running: %s", req, got)
		}
	}
	// The admin key comes from the computer's hello, so it must be connected.
	if got := manage(`{"action":"make_admin","device":"` + admitted + `"}`); !strings.Contains(got, "not connected") {
		t.Fatalf("making a computer that is not running an admin: %s", got)
	}
	// The root's own records, built and signed in the core (cbb_core::root).
	if got := manage(`{"action":"takeover_delay","delay_ms":3600000}`); got != `{"ok":{}}` {
		t.Fatalf("setting the takeover delay: %s", got)
	}
	if got := manage(`{"action":"takeover_delay","delay_ms":-1}`); !strings.Contains(got, "from 0 to 7 days") {
		t.Fatalf("a negative takeover delay: %s", got)
	}
	if got := manage(`{"action":"key_level","level":"files"}`); got != `{"ok":{"below":[]}}` {
		t.Fatalf("setting the key level: %s", got)
	}
	if got := manage(`{"action":"hand_over","device":"` + admitted + `"}`); !strings.Contains(got, "no admin") {
		t.Fatalf("handing the group to a computer that is no admin: %s", got)
	}
	if got := manage(`{"action":"remove_recovery"}`); !strings.Contains(got, "no recovery key") {
		t.Fatalf("removing a recovery key the group does not have: %s", got)
	}
	var sheet struct {
		OK struct {
			QR      string   `json:"qr"`
			Text    string   `json:"text"`
			Modules []string `json:"modules"`
			Admin   []byte   `json:"admin"`
		} `json:"ok"`
	}
	if got := manage(`{"action":"make_recovery"}`); json.Unmarshal([]byte(got), &sheet) != nil ||
		!strings.HasPrefix(sheet.OK.QR, "cbb://recover?g="+made[1]+"&") || len(sheet.OK.Text) != 69 || len(sheet.OK.Modules) == 0 ||
		len(sheet.OK.Admin) != 32 {
		t.Fatalf("making the recovery key: %s", got)
	}
	// A YubiKey's key, which never leaves the card: the root issues its admin CA.
	card, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&card.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var onCard struct {
		OK struct {
			AdminCA []byte `json:"admin_ca"`
		} `json:"ok"`
	}
	got := manage(`{"action":"recovery_for","key":"` + base64.StdEncoding.EncodeToString(spki) + `"}`)
	if json.Unmarshal([]byte(got), &onCard) != nil {
		t.Fatalf("the card's recovery key: %s", got)
	}
	cardCA, err := x509.ParseCertificate(onCard.OK.AdminCA)
	if err != nil || !cardCA.IsCA || !card.PublicKey.Equal(cardCA.PublicKey) || cardCA.CheckSignatureFrom(id.GroupCA.Cert) != nil {
		t.Fatalf("the card's admin CA: %s, %v", got, err)
	}
	if got := manage(`{"action":"recovery_for","key":"AAAA"}`); !strings.Contains(got, "no P-256 key") {
		t.Fatalf("a recovery key that is no key: %s", got)
	}
	fmt.Fprintln(in, `CALL {"op":"records"}`)
	var recs struct {
		OK struct {
			Records []struct {
				Body []byte `json:"body"`
			} `json:"records"`
		} `json:"ok"`
	}
	if err := json.Unmarshal([]byte(next("ANSWER ")), &recs); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, r := range recs.OK.Records {
		var b struct {
			Type  string `json:"type"`
			Delay int64  `json:"takeover_delay_ms"`
			Level string `json:"key_level"`
		}
		if err := json.Unmarshal(r.Body, &b); err != nil {
			t.Fatal(err)
		}
		kinds[b.Type] = true
		// The key level's settings record keeps the delay set before it.
		if b.Type == "settings" && b.Level == "files" && b.Delay != 3600000 {
			t.Fatalf("the key level's settings record dropped the delay: %+v", b)
		}
	}
	if !kinds["settings"] || !kinds["recovery"] {
		t.Fatalf("the records hold no settings or recovery record: %v", kinds)
	}
	fmt.Fprintln(in, `CALL {"op":"root_view"}`)
	if got := next("ANSWER "); got != `{"ok":{"delay_ms":3600000,"handed_to":null,"key_level":"files","recovery":true}}` {
		t.Fatalf("the root's settings: %s", got)
	}
	if got := manage(`{"action":"remove_recovery"}`); got != `{"ok":{}}` {
		t.Fatalf("removing the recovery key: %s", got)
	}
	// A group made a moment ago stops nothing.
	fmt.Fprintln(in, `CALL {"op":"alerts"}`)
	if got := next("ANSWER "); got != `{"ok":{"alerts":[]}}` {
		t.Fatalf("the alerts: %s", got)
	}
	if got := manage(`{"action":"resolve","records":[]}`); !strings.Contains(got, "names the records") {
		t.Fatalf("resolving nothing: %s", got)
	}
	// Nothing is due in a group made a moment ago.
	if got := manage(`{"action":"renew"}`); got != `{"ok":{"renewed":0}}` {
		t.Fatalf("renewing: %s", got)
	}
	if got := manage(`{"action":"remove","device":"` + made[0] + `"}`); !strings.Contains(got, "cannot remove itself") {
		t.Fatalf("the phone removing itself: %s", got)
	}
	if got := manage(`{"action":"remove","device":"` + admitted + `"}`); got != `{"ok":{}}` {
		t.Fatalf("removing the computer: %s", got)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); strings.Contains(devices, `"desk"`) {
		t.Fatalf("the phone still lists the computer it removed: %s", devices)
	}
}

// admitJoiner plays the phone that scanned a listening joiner's QR code
// with pi, the group's root: pi dials the addresses in the QR code and
// admits the device with the certificate it names, as cbb pair -qr does,
// and returns the name the device joined with.
func admitJoiner(t *testing.T, pi *testService, qr string) string {
	t.Helper()
	jc, ok := phone.ParseJoinQR(qr)
	if !ok || len(jc.Addrs) == 0 || jc.Fingerprint == "" {
		t.Fatalf("not a QR code of a listening joiner: %q", qr)
	}
	m, err := pi.do(t, control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint}, "")
	if err != nil {
		t.Fatalf("admitting the joiner: %v", err)
	}
	return m.Name
}

// listeningJoin starts a service named name, out of a group, and has it
// wait for a phone, as cbb pair does: the QR code the phone scans.
func listeningJoin(t *testing.T, h *hub, name string) (*testService, string) {
	t.Helper()
	s := startService(t, h, name)
	c := s.dial(t)
	t.Cleanup(func() { c.Close() })
	code := newCode(t)
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: code, Expires: 300, Listen: true}})
	if err != nil || len(m.Addrs) == 0 {
		t.Fatalf("%s's listening join: %v, %+v", name, err, m)
	}
	return s, phone.JoinQR(phone.JoinCode{Code: code, Addrs: m.Addrs, Fingerprint: m.Fingerprint})
}

// joinedIdentity is the identity that s, which waited for a phone, keeps
// once the phone admitted it as the device admitted.
func joinedIdentity(t *testing.T, s *testService, admitted string) *group.Identity {
	t.Helper()
	waitFor(t, s.name+" in the group", func() bool {
		st := s.status(t)
		return st.Group != "" && st.Device == admitted
	})
	id, err := group.Load(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// newCode is a pairing code: six random digits.
func newCode(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// joinAlone has the small device join pi's group: cbb pair on pi shows a
// code, and cbb pair -code on the small device reads it from standard input
// and joins at pi's address. It returns the small device's state directory.
func joinAlone(t *testing.T, bin string, pi *testService) string {
	t.Helper()
	return joinAloneEnv(t, bin, pi, nil)
}

// joinAloneEnv is joinAlone with env added to cbb pair's environment.
func joinAloneEnv(t *testing.T, bin string, pi *testService, env []string) string {
	t.Helper()
	c, code := openWindow(t, pi)
	defer c.Close()
	pa := pi.addr()
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "-debug", "pair", "-name", "small", "-code", pa)
	join.Stdin = strings.NewReader(code + "\n")
	if env != nil {
		join.Env = append(os.Environ(), env...)
	}
	join.Stderr = testWriter{t, "small join: ", nil}
	out, err := join.Output()
	if err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "small" {
		t.Fatalf("pair on pi ended with %+v, %v", m, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Error("the small device saved a CA key")
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
	// The small device offers its key for sealed messages, and the root
	// records it, so the command below is sealed to it.
	waitFor(t, "the root records the small device's key for sealed messages", func() bool {
		id, err := group.Load(pi.dir)
		if err != nil {
			return false
		}
		recs, err := group.LoadRecords(pi.dir, id.GroupCA.Cert)
		if err != nil {
			return false
		}
		for _, d := range recs.Devices() {
			if string(d.ID) == st.Device {
				return len(d.Seal) > 0
			}
		}
		return false
	})
	if _, err := pi.do(t, control.Header{Op: control.OpSync, Device: st.Device, On: control.Bool(false)}, ""); err != nil {
		t.Fatal(err)
	}
	if m := small.status(t).Mode; m != "own" {
		t.Errorf("after the root's command the small device's mode is %q, want own", m)
	}
	if !small.logged("opened a sealed mode command") {
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

// TestAloneMemberAway: once sync away from home is on, the small device
// offers its tunnel key to the group's hub at home and keeps the hub's
// offer; away from home it reaches the hub only through the WireGuard
// tunnel (GotaTun and smoltcp in the small device, the Go hub's netstack),
// and syncs there.
func TestAloneMemberAway(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAlone(t, bin, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device

	// At home: off until the user agrees, then the hub's offer comes.
	pa := pi.addr()
	home := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the small device at home", func() bool {
		st, err := home.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(st.Status.Peers) == 1
	})
	if a := home.status(t).Away; a != nil {
		t.Fatalf("sync away from home is on before it was turned on: %+v", a)
	}
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on"}, ""); err == nil || !strings.Contains(err.Error(), "consent") {
		t.Errorf("turning it on without consent: %v", err)
	}
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device keeps the hub's offer", func() bool {
		a := home.status(t).Away
		return a != nil && a.HubDevice == piID && !a.Through
	})
	home.stop()

	// Away: no address of the hub but its tunnel's.
	away := startAlone(t, bin, dir, "-no-mdns", "-no-listen")
	waitUpTo(t, 30*time.Second, "the small device reaches the hub through the tunnel", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "from the small device, away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the small device, away" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the small device, away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device has it", func() bool { return away.paste(t) == "to the small device, away" })
	away.stop()

	// Through a local UDP port that leads to the hub (cbb next link -udp
	// on the ZX Spectrum Next): -tunnel-via sends the tunnel's packets
	// there instead of the hub's address.
	relayed := udpRelay(t, port)
	away = startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-tunnel-via", relayed.addr)
	waitUpTo(t, 30*time.Second, "the small device reaches the hub through the local UDP port", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if relayed.n.Load() == 0 {
		t.Fatal("no packet went through the local UDP port")
	}

	// Off, from an admin (cbb global off -on, an away-off command
	// through the tunnel): the key is gone, and so is the connection
	// through the tunnel. Its own user turning it off again changes
	// nothing.
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "off", Device: "small"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tunnel.json")); !os.IsNotExist(err) {
		t.Errorf("tunnel.json after the away-off command: %v", err)
	}
	waitFor(t, "the small device syncs at home only", func() bool {
		st := away.status(t)
		return st.Away == nil && len(st.Peers) == 0
	})
	if _, err := away.do(t, control.Header{Op: control.OpAway, Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}
}

// TestAloneMemberAwayObfuscated syncs the small device away from home with a
// hub that hides its tunnel with AmneziaWG: the small device keeps the
// offer's settings and speaks AmneziaWG to the Go hub (member/src/awg.rs
// around GotaTun, amneziawg-go on the hub). CBB_TEST_ALONE names the binary.
func TestAloneMemberAwayObfuscated(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAlone(t, bin, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device
	home := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pi.addr())
	waitFor(t, "the small device at home", func() bool {
		st, err := home.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(st.Status.Peers) == 1
	})
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device keeps the obfuscated hub's offer", func() bool {
		a := home.status(t).Away
		return a != nil && a.HubDevice == piID
	})
	home.stop()
	raw, err := os.ReadFile(filepath.Join(dir, "tunnel.json"))
	if err != nil || !strings.Contains(string(raw), "header_protection_key") {
		t.Fatalf("tunnel.json keeps no AmneziaWG settings (%v): %s", err, raw)
	}

	// The hub speaks AmneziaWG only: a small device that reaches it speaks
	// it too.
	away := startAlone(t, bin, dir, "-no-mdns", "-no-listen")
	waitUpTo(t, 30*time.Second, "the small device reaches the obfuscated hub through the tunnel", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "from the small device, hidden"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the small device, hidden" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the small device, hidden"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the small device has it", func() bool { return away.paste(t) == "to the small device, hidden" })
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
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	vlessAddr := free.Addr().String()
	free.Close()
	web, ca := vlesstest.WebServerCA(t, path, func() string { return vlessAddr })
	roots := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(roots, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf, StateFile: filepath.Join(t.TempDir(), "state.json"),
		VLESS: &forward.VLESSConfig{Listen: vlessAddr, XHTTP: &forward.XHTTPConfig{Host: vlesstest.WebName, Port: web.Port(), Path: path}}})
	if err != nil {
		t.Fatal(err)
	}
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

// udpRelayPort is a UDP port that passes every datagram to a port on 127.0.0.1
// and the answers back to the last sender, as cbb next link -udp does
// through the Next's ESP; n counts the datagrams it passed out.
type udpRelayPort struct {
	addr string
	n    atomic.Int64
}

func udpRelay(t *testing.T, to int) *udpRelayPort {
	t.Helper()
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: to})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); out.Close() })
	r := &udpRelayPort{addr: in.LocalAddr().String()}
	var last atomic.Pointer[net.UDPAddr]
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			last.Store(from)
			r.n.Add(1)
			out.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := out.Read(buf)
			if err != nil {
				return
			}
			if a := last.Load(); a != nil {
				in.WriteToUDP(buf[:n], a)
			}
		}
	}()
	return r
}

// TestFFIPhoneRemoves has the root phone remove a computer it is connected
// to, as the Android app's GroupTest.a8_renameAndRemove does: the removed
// computer must hear it was removed, though the phone ends the connection
// right after the records that remove it, and the other computer stays.
func TestFFIPhoneRemoves(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	next, in := phoneOnLinux(t, bin, "-name", "root phone", "-new-group", "-dir", t.TempDir())
	if made := strings.Fields(next("Group ")); len(made) != 2 {
		t.Fatalf("the phone's group: %q", made)
	}
	var h hub
	admit := func(name string) (*testService, string) {
		s, qr := listeningJoin(t, &h, name)
		fmt.Fprintln(in, "ADMIT "+qr)
		admitted := next("ADMITTED ")
		if got := next("ADMIT DONE "); got != "true" {
			t.Fatalf("%s did not confirm its join: %q", name, got)
		}
		joinedIdentity(t, s, admitted)
		return s, admitted
	}
	pc, _ := admit("pc")
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
	if got := manage(`{"action":"rename","device":"` + id + `","name":"bench-second"}`); got != `{"ok":{}}` {
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
	if got := manage(`{"action":"remove","device":"` + id + `"}`); got != `{"ok":{}}` {
		t.Fatalf("removing the computer: %s", got)
	}
	waitUpTo(t, 60*time.Second, "the second computer says it was removed", func() bool { return second.status(t).Removed })
	if pc.status(t).Removed {
		t.Fatal("the other computer says it was removed")
	}
}

// TestFFIPhoneRemovesAway: the root phone removes a computer it never
// connected to after admitting it; the phone's next connection with the
// computer carries the records that remove it, and the computer says so.
func TestFFIPhoneRemovesAway(t *testing.T) {
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	next, in := phoneOnLinux(t, bin, "-name", "root phone", "-new-group", "-dir", t.TempDir())
	if made := strings.Fields(next("Group ")); len(made) != 2 {
		t.Fatalf("the phone's group: %q", made)
	}
	var h hub
	second, qr := listeningJoin(t, &h, "second")
	fmt.Fprintln(in, "ADMIT "+qr)
	id := next("ADMITTED ")
	if got := next("ADMIT DONE "); got != "true" {
		t.Fatalf("the computer did not confirm its join: %q", got)
	}
	joinedIdentity(t, second, id)
	fmt.Fprintln(in, "MANAGE "+`{"action":"remove","device":"`+id+`"}`)
	if got := next("MANAGED "); got != `{"ok":{}}` {
		t.Fatalf("removing the computer: %s", got)
	}
	fmt.Fprintln(in, `CALL {"op":"found","args":{"key":"second","addrs":["`+second.addr()+`"]}}`)
	next("ANSWER ")
	waitUpTo(t, 30*time.Second, "the computer says it was removed", func() bool { return second.status(t).Removed })
	waitFor(t, "the removed computer keeps no connection", func() bool { return len(second.status(t).Peers) == 0 })
}
