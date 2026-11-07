// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/phone"
	"github.com/HunterEwok/cbb/internal/remotepaste"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

// publishLite puts a lite member on the fake network, as the real one
// publishes itself: TXT r=lite, at 127.0.0.1 and port.
func publishLite(h *hub, id, tag string, port int) {
	h.mu.Lock()
	if h.ghosts == nil {
		h.ghosts = map[string]mdns.Peer{}
	}
	h.ghosts[id] = mdns.Peer{ID: id, Port: uint16(port), TXT: []string{"v=1", "g=" + tag, "r=lite"},
		Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	h.mu.Unlock()
	h.update()
}

// TestLiteNotDialed: the full members, a Mac too, leave a lite member they
// find to dial them, whatever the device IDs.
func TestLiteNotDialed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, mac) // the group exists from here
	// The greatest device ID: a full member would dial a full member with it.
	publishLite(&h, strings.Repeat("f", 32), pi.status(t).Group, ln.Addr().(*net.TCPAddr).Port)
	time.Sleep(2 * time.Second)
	if n := dialed.Load(); n != 0 {
		t.Fatalf("the full members dialed the lite member %d times", n)
	}
}

// startLite runs the lite member (Rust, member/) with the state in
// dir; it is stopped by stop or at the end of the test.
func startLite(t *testing.T, bin, dir string, args ...string) *testService {
	t.Helper()
	return startLiteEnv(t, bin, dir, nil, args...)
}

// startLiteEnv is startLite with env added to the lite member's
// environment.
func startLiteEnv(t *testing.T, bin, dir string, env []string, args ...string) *testService {
	t.Helper()
	s := &testService{name: "lite", dir: dir, socket: filepath.Join(dir, "c.sock")}
	cmd := exec.Command(bin, append([]string{"-state", dir, "-socket", s.socket, "-debug", "service"}, args...)...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdout, cmd.Stderr = testWriter{t, "lite: ", s}, testWriter{t, "lite: ", s}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.done = make(chan error, 1)
	go func() { s.done <- cmd.Wait() }()
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
			t.Fatalf("the lite member ended at the start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the admin socket of the lite member never appeared")
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
	res := dialJoiner(t, pi.dir, qr)
	if res.Info.Name != "board" || res.Info.Role != pair.RoleLite || !res.Confirmed {
		t.Fatalf("the board joined as %+v", res)
	}
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
	// Its hello presents it as the phone it is, not as a lite member.
	for _, d := range pi.devices(t) {
		if d.Name == "aurora phone" && (d.OS != group.OSAurora || d.Store != "hardware" || d.Form != "phone" || d.OSVersion != "Aurora OS 5.1.5") {
			t.Fatalf("the connected phone is listed as %+v", d)
		}
	}
	// The app's devices list: the group's root online, and this phone,
	// both from the records.
	type appDevice struct {
		Device, Name, Role, OS            string
		Admin, Root, Frozen, Online, Self bool
		Listed                            bool
	}
	var devs []appDevice
	waitFor(t, "the app lists the group's devices", func() bool {
		fmt.Fprintln(in, "DEVICES")
		devs = nil
		if err := json.Unmarshal([]byte(next("DEVICES ")), &devs); err != nil {
			t.Fatal(err)
		}
		return len(devs) == 2 && devs[0].Listed && devs[1].Listed
	})
	piID := pi.status(t).Device
	for _, d := range devs {
		switch {
		case d.Device == piID:
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

	// The app's switch pauses receiving: the group's copies stay out of
	// the phone's clipboard, its own still go out.
	fmt.Fprintln(in, "PAUSE 3600000")
	if got := next("MUTED "); got != "true false" {
		t.Fatalf("after the pause the phone says %q", got)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "kept out"); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(in, "COPY while paused")
	waitFor(t, "the service has the paused phone's text", func() bool { return pi.paste(t) == "while paused" })
	fmt.Fprintln(in, "RESUME")
	if got := next("MUTED "); got != "false false" {
		t.Fatalf("after the resume the phone says %q", got)
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
	piAddr := pi.addr()
	pi.stop()
	pi.cfg = func(c *Config) {
		c.now = func() time.Time { return time.Now().AddDate(1, 6, 0) }
		c.listen = func() (net.Listener, error) { return net.Listen("tcp", piAddr) }
	}
	pi = restartService(t, &h, pi)
	der, err := base64.StdEncoding.DecodeString(next("IDENTITY "))
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := x509.ParseCertificate(der)
	if err != nil || renewed.NotAfter.Before(time.Now().AddDate(1, 6, 0)) {
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
		_, err := pi.do(t, control.Header{Op: control.OpMode, Device: me, Name: "receive"}, "")
		answered <- err
	}()
	token, cmd, _ := strings.Cut(next("COMMAND "), " ")
	if !strings.Contains(cmd, `"body"`) {
		t.Fatalf("the command event carries %s", cmd)
	}
	call("answer", map[string]any{"token": json.Number(token), "status": "done"})
	if err := <-answered; err != nil {
		t.Fatalf("the phone's answer to the mode: %v", err)
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
	j, err := pair.NewJoiner(pair.Info{Name: "laptop", OS: group.OSLinux})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := j.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	joined := make(chan *group.Identity, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			joined <- nil
			return
		}
		id, err := j.Accept(context.Background(), conn, "135790", func(*group.Identity) error { return nil })
		if err != nil {
			t.Errorf("the computer's join: %v", err)
		}
		joined <- id
	}()
	fmt.Fprintln(in, "ADMIT "+phone.JoinQR(phone.JoinCode{Code: "135790", Addrs: []string{ln.Addr().String()}, Fingerprint: fp}))
	if got := next("ADMITTED "); got != string(j.ID) {
		t.Fatalf("the phone admitted %q, not the computer %s", got, j.ID)
	}
	t.Logf("the admin phone admitted the computer %s", j.ID)
	if got := next("ADMIT DONE "); got != "true" {
		t.Fatalf("the computer did not confirm its join: %q", got)
	}
	id := <-joined
	if id == nil || id.Issuer == nil || !bytes.Equal(id.Issuer.Raw, ca.Raw) {
		t.Fatalf("the computer's identity: %+v", id)
	}
	if err := id.Cert.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("the computer's certificate is not from the phone's admin CA: %v", err)
	}
	if got, err := group.DeviceOf(id.Cert); err != nil || got != j.ID {
		t.Fatalf("the computer's certificate names %q: %v", got, err)
	}
	waitFor(t, "the root lists the computer the phone admitted", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "laptop" {
				return d.Role == group.RoleFull && d.OS == group.OSLinux && !d.Admin
			}
		}
		return false
	})
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

	j, err := pair.NewJoiner(pair.Info{Name: "laptop", OS: group.OSLinux})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := j.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	joined := make(chan *group.Identity, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			joined <- nil
			return
		}
		id, err := j.Accept(context.Background(), conn, "246801", func(*group.Identity) error { return nil })
		if err != nil {
			t.Errorf("the computer's join: %v", err)
		}
		joined <- id
	}()
	fmt.Fprintln(in, "ADMIT "+phone.JoinQR(phone.JoinCode{Code: "246801", Addrs: []string{ln.Addr().String()}, Fingerprint: fp}))
	if got := next("ADMITTED "); got != string(j.ID) {
		t.Fatalf("the phone admitted %q, not the computer %s", got, j.ID)
	}
	if got := next("ADMIT DONE "); got != "true" {
		t.Fatalf("the computer did not confirm its join: %q", got)
	}
	id := <-joined
	if id == nil || id.Issuer != nil {
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
	if got, err := group.DeviceOf(id.Cert); err != nil || got != j.ID {
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
	if got := manage(`{"action":"rename","device":"` + string(j.ID) + `","name":"desk"}`); got != `{"ok":{}}` {
		t.Fatalf("renaming the computer: %s", got)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); !strings.Contains(devices, `"desk"`) || strings.Contains(devices, `"laptop"`) {
		t.Fatalf("the phone does not list the computer's new name: %s", devices)
	}
	// The computer is not running, so a command for it finds no way there.
	if got := manage(`{"action":"mute","device":"` + string(j.ID) + `","for_ms":60000,"timeout_ms":1000}`); !strings.Contains(got, "not connected") {
		t.Fatalf("muting a computer that is not running: %s", got)
	}
	// The admin key comes from the computer's hello, so it must be connected.
	if got := manage(`{"action":"make_admin","device":"` + string(j.ID) + `"}`); !strings.Contains(got, "not connected") {
		t.Fatalf("making a computer that is not running an admin: %s", got)
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
	if got := manage(`{"action":"remove","device":"` + string(j.ID) + `"}`); got != `{"ok":{}}` {
		t.Fatalf("removing the computer: %s", got)
	}
	fmt.Fprintln(in, "DEVICES")
	if devices := next("DEVICES "); strings.Contains(devices, `"desk"`) {
		t.Fatalf("the phone still lists the computer it removed: %s", devices)
	}
}

// dialJoiner plays the phone that scanned a listening joiner's QR code: it
// opens a window with the identity in dir, dials the addresses in the QR
// code and admits the device with the certificate it names, as the phone
// kits do.
func dialJoiner(t *testing.T, dir, qr string) *pair.Result {
	t.Helper()
	jc, ok := phone.ParseJoinQR(qr)
	if !ok || len(jc.Addrs) == 0 || jc.Fingerprint == "" {
		t.Fatalf("not a QR code of a listening joiner: %q", qr)
	}
	id, err := group.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pair.Open(id, jc.Code, pair.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), joinTimeout)
	defer cancel()
	var lastErr error
	for _, addr := range jc.Addrs {
		raw, err := net.DialTimeout("tcp", addr, handshakeTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		if lastErr = w.Dial(ctx, raw, jc.Fingerprint); lastErr == nil {
			break
		}
	}
	select {
	case <-w.Done():
	default:
		t.Fatalf("dialing the joiner: %v", lastErr)
	}
	res, err := w.Result()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// joinLite has the lite member join pi's group: cbb pair on pi shows a
// code, and cbb pair -code on the lite member reads it from standard input
// and joins at pi's address. It returns the lite member's state directory.
func joinLite(t *testing.T, bin string, pi *testService) string {
	t.Helper()
	return joinLiteEnv(t, bin, pi, nil)
}

// joinLiteEnv is joinLite with env added to cbb pair's environment.
func joinLiteEnv(t *testing.T, bin string, pi *testService, env []string) string {
	t.Helper()
	c, code := openWindow(t, pi)
	defer c.Close()
	pa := pi.addr()
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "-debug", "pair", "-name", "lite", "-code", pa)
	join.Stdin = strings.NewReader(code + "\n")
	if env != nil {
		join.Env = append(os.Environ(), env...)
	}
	join.Stderr = testWriter{t, "lite join: ", nil}
	out, err := join.Output()
	if err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "lite" {
		t.Fatalf("pair on pi ended with %+v, %v", m, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "_key") {
		t.Error("the lite member saved a CA key")
	}
	return dir
}

// TestLiteMember runs the lite member among Go members: it joins with the
// code of cbb pair, gets no CA keys, is listed as a lite device and syncs
// both ways. (Joining by the phone's QR code, where the phone dials the
// lite member, is covered by the phone kits' tests.) CBB_LITE names the
// lite member's binary (cargo build at the top).
func TestLiteMember(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	laptop := startService(t, &h, "laptop")
	pairWith(t, pi, laptop)

	dir := joinLite(t, bin, pi)
	pa := pi.addr()

	// The lite member dials the computers, a Mac too, and syncs with them.
	mac := startRole(t, &h, "mac", group.OSMacOS)
	pairWith(t, pi, mac)
	la := laptop.addr()
	ma := mac.addr()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	lite := startLite(t, bin, dir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", pa, "-peer", la, "-peer", ma)
	// The control socket answers while the service still loads its identity.
	waitFor(t, "the lite member in the group", func() bool {
		_, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil
	})
	st := lite.status(t)
	if st.Group != pi.status(t).Group || st.Role != "lite" {
		t.Fatalf("lite status %+v, want the group %s", st, pi.status(t).Group)
	}
	waitFor(t, "the lite member connected", func() bool { return len(lite.status(t).Peers) == 3 })
	if _, err := lite.do(t, control.Header{Op: control.OpCopy}, "from the lite member"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*testService{pi, laptop, mac} {
		waitFor(t, s.name+" has the lite text", func() bool { return s.paste(t) == "from the lite member" })
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "from the laptop"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has the laptop text", func() bool { return lite.paste(t) == "from the laptop" })

	// The ZX Spectrum Next's front end: texts in the Spectrum character set,
	// with their length and CRC-32 (member/README.md, "ZX Spectrum Next").
	zx := []byte("ZX \x605\rnext")
	next := exec.Command(bin, "-socket", lite.socket, "next", "copy", strconv.Itoa(len(zx)), fmt.Sprintf("%08x", crc32.ChecksumIEEE(zx)))
	next.Stdin = bytes.NewReader(zx)
	if out, err := next.Output(); err != nil || string(out) != "CBBGO\rCBBOK\r" {
		t.Fatalf("cbb next copy: %v; %q", err, out)
	}
	waitFor(t, "the laptop has the Next's text", func() bool { return laptop.paste(t) == "ZX £5\nnext" })
	// .cbb text -s: a secret from the Next arrives as a secret.
	pw := []byte("hunter2")
	next = exec.Command(bin, "-socket", lite.socket, "next", "copy", "-secret", strconv.Itoa(len(pw)), fmt.Sprintf("%08x", crc32.ChecksumIEEE(pw)))
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
	waitFor(t, "the lite member has the laptop text for the Next", func() bool { return strings.HasPrefix(lite.paste(t), "to the") })
	zxOut, err := exec.Command(bin, "-socket", lite.socket, "next", "paste").Output()
	if wantOut := fmt.Sprintf("CBB1 %d %08x\r%s\rCBBOK\r", len(want), crc32.ChecksumIEEE(want), want); err != nil || string(zxOut) != wantOut {
		t.Fatalf("cbb next paste: %v; %q, want %q", err, zxOut, wantOut)
	}

	// Every member lists it as a lite device, not an admin.
	for _, s := range []*testService{pi, laptop, lite} {
		waitFor(t, s.name+" lists the lite member", func() bool {
			for _, d := range s.devices(t) {
				if d.ID == st.Device {
					return d.Role == group.RoleLite && !d.Admin && d.Name == "lite"
				}
			}
			return false
		})
	}

	// A new lite member keeps its clipboard to itself and says so in its
	// hello; the root sets its mode with a command, and it keeps it.
	if m := lite.status(t).Mode; m != "own" {
		t.Errorf("a new lite member's mode is %q, want own", m)
	}
	waitFor(t, "the laptop sees the lite member's mode", func() bool {
		for _, d := range laptop.devices(t) {
			if d.ID == st.Device {
				return d.Mode == "own"
			}
		}
		return false
	})
	// The lite member offers its key for sealed messages, and the root
	// records it, so the command below is sealed to it.
	waitFor(t, "the root records the lite member's key for sealed messages", func() bool {
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
	if _, err := pi.do(t, control.Header{Op: control.OpMode, Device: st.Device, Name: "receive"}, ""); err != nil {
		t.Fatal(err)
	}
	if m := lite.status(t).Mode; m != "receive" {
		t.Errorf("after the root's command the lite member's mode is %q, want receive", m)
	}
	if !lite.logged("opened a sealed mode command") {
		t.Error("the lite member did not open the command sealed to it")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "mode")); err != nil || string(b) != "receive\n" {
		t.Errorf("the lite member's mode file: %q, %v", b, err)
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpMode, Device: st.Device, Name: "own"}, ""); err == nil {
		t.Error("a device that is no admin set the lite member's mode")
	}
	if _, err := lite.do(t, control.Header{Op: control.OpMode, Name: "shared"}, ""); err != nil || lite.status(t).Mode != "shared" {
		t.Errorf("cbb mode shared on the lite member: %v", err)
	}

	// The lite member dials a Mac as it dials every full member; with the
	// other computers off the two still sync.
	publishLite(&h, st.Device, st.Group, port)
	waitFor(t, "the Mac connected to all three", func() bool { return len(mac.status(t).Peers) == 3 })
	pi.stop()
	laptop.stop()
	waitFor(t, "the Mac and the lite member alone", func() bool {
		return len(mac.status(t).Peers) == 1 && len(lite.status(t).Peers) == 1
	})
	if _, err := mac.do(t, control.Header{Op: control.OpCopy}, "from the Mac"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has the Mac text", func() bool { return lite.paste(t) == "from the Mac" })
	if _, err := lite.do(t, control.Header{Op: control.OpCopy}, "back from the lite member"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Mac has the lite text", func() bool { return mac.paste(t) == "back from the lite member" })
}

// TestLiteRemotePaste: an admin's paste reaches the lite member's tmux
// target, played here by the test, once the lite member's own user turned
// remote paste on; the lite member keeps the full member's rules and log,
// and any admin turns it off there.
func TestLiteRemotePaste(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	pa := pi.addr()
	lite := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the lite member connected", func() bool {
		m, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(m.Status.Peers) == 1
	})
	// pi sends to the lite member, so it must see the connection too: under
	// qemu it can come a moment after the lite member's side.
	waitFor(t, "pi has the lite member", func() bool { return len(pi.status(t).Peers) == 1 })
	paste := func(text string, h control.Header) error {
		h.Op, h.Device = control.OpPasteOn, "lite"
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
	if m, err := lite.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil || m.Status == nil || m.Status.Paste == nil || !m.Status.Paste.On {
		t.Fatalf("paste-receive on: %+v, %v", m, err)
	}
	wantRefused("no target", "ls", control.Header{}, "nothing on this device can paste")

	// The tmux helper offers to paste.
	w := lite.dial(t)
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
	waitFor(t, "the lite member offers tmux", func() bool {
		p := lite.status(t).Paste
		return p != nil && len(p.Targets) == 1 && p.Targets[0] == targetTmux
	})
	out, err := exec.Command(bin, "-socket", lite.socket, "paste-receive").Output()
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
	if _, err := pi.do(t, control.Header{Op: control.OpReceive, Name: "off", Device: "lite"}, ""); err != nil {
		t.Fatal(err)
	}
	if p := lite.status(t).Paste; p == nil || p.On {
		t.Errorf("after paste-off: %+v", p)
	}
	if set, err := remotepaste.Load(dir); err != nil || set.On {
		t.Errorf("the lite member's settings: %+v, %v", set, err)
	}
}

// TestLiteQuickActions: the lite member runs only the presets its own user
// turned on, for the signers they allow, and restarts at an admin's request by ending with an error, after which
// systemd starts it again. A reboot is not run here.
func TestLiteQuickActions(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	pa := pi.addr()
	lite := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the lite member connected", func() bool {
		m, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(m.Status.Peers) == 1
	})
	// pi sends to the lite member, so it must see the connection too: under
	// qemu it can come a moment after the lite member's side.
	waitFor(t, "pi has the lite member", func() bool { return len(pi.status(t).Peers) == 1 })
	run := func(name string) error {
		time.Sleep(time.Second) // one action a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "lite", Name: name}, "")
		return err
	}
	set := func(a control.Action) {
		t.Helper()
		if _, err := lite.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{a}}, ""); err != nil {
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
	wantRefused(actions.Lock, "this device has no action")
	if _, err := lite.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{{Name: actions.Lock, On: true}}}, ""); err == nil {
		t.Error("the lite member turned lock on")
	}
	// pi's keys are in files: reboot takes it only with any key, which this
	// test leaves off.
	set(control.Action{Name: actions.Reboot, On: true})
	wantRefused(actions.Reboot, "keys are in hardware")
	set(control.Action{Name: actions.Restart, On: true, By: []string{actions.ByPhone}})
	wantRefused(actions.Restart, "only for phone")
	set(control.Action{Name: actions.Restart, On: true})
	st := lite.status(t)
	if len(st.Actions) != 3 || st.Actions[0].Name != actions.Reboot || !st.Actions[0].On || st.Actions[1].On || !st.Actions[2].On {
		t.Errorf("the lite member's actions: %+v", st.Actions)
	}
	out, err := exec.Command(bin, "-socket", lite.socket, "action").Output()
	if err != nil || !strings.Contains(string(out), "reboot           on, for every admin, keys in hardware only\n") {
		t.Errorf("cbb action: %v; %s", err, out)
	}
	if err := run(actions.Restart); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-lite.done:
		lite.cancel = nil
		if err == nil {
			t.Error("the lite member ended without an error, so systemd would not start it again")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the lite member did not restart")
	}

	// The log keeps who asked and how it ended, in the full member's file.
	log, err := actions.ReadLog(dir)
	if err != nil || len(log) != 5 {
		t.Fatalf("the log: %+v, %v", log, err)
	}
	if e := log[4]; e.Action != actions.Restart || e.Result != "done" || e.Name != "pi" {
		t.Errorf("the restart's entry: %+v", e)
	}

	// Started again, it keeps them, and any admin turns them off.
	lite = startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the lite member connected again", func() bool {
		m, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(m.Status.Peers) == 1
	})
	// pi may still hold the connection from before the restart a moment,
	// so the first try can find no lite member to send to.
	waitFor(t, "pi turned the quick actions off", func() bool {
		_, err := pi.do(t, control.Header{Op: control.OpActionOff, Device: "lite"}, "")
		if err != nil {
			t.Logf("actions-off: %v", err)
		}
		return err == nil
	})
	if set, err := actions.Load(dir); err != nil || len(set.On()) != 0 {
		t.Errorf("after actions-off: %+v, %v", set, err)
	}
}

// TestLiteMemberAway: once sync away from home is on, the lite member
// offers its tunnel key to the group's hub at home and keeps the hub's
// offer; away from home it reaches the hub only through the WireGuard
// tunnel (GotaTun and smoltcp in the lite member, the Go hub's netstack),
// and syncs there.
func TestLiteMemberAway(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
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
	home := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pa)
	waitFor(t, "the lite member at home", func() bool {
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
	waitFor(t, "the lite member keeps the hub's offer", func() bool {
		a := home.status(t).Away
		return a != nil && a.HubDevice == piID && !a.Through
	})
	home.stop()

	// Away: no address of the hub but its tunnel's.
	away := startLite(t, bin, dir, "-no-mdns", "-no-listen")
	waitUpTo(t, 30*time.Second, "the lite member reaches the hub through the tunnel", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "from the lite member, away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the lite member, away" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the lite member, away"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has it", func() bool { return away.paste(t) == "to the lite member, away" })
	away.stop()

	// Through a local UDP port that leads to the hub (cbb next link -udp
	// on the ZX Spectrum Next): -tunnel-via sends the tunnel's packets
	// there instead of the hub's address.
	relayed := udpRelay(t, port)
	away = startLite(t, bin, dir, "-no-mdns", "-no-listen", "-tunnel-via", relayed.addr)
	waitUpTo(t, 30*time.Second, "the lite member reaches the hub through the local UDP port", func() bool {
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
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "off", Device: "lite"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tunnel.json")); !os.IsNotExist(err) {
		t.Errorf("tunnel.json after the away-off command: %v", err)
	}
	waitFor(t, "the lite member syncs at home only", func() bool {
		st := away.status(t)
		return st.Away == nil && len(st.Peers) == 0
	})
	if _, err := away.do(t, control.Header{Op: control.OpAway, Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}
}

// TestLiteMemberAwayObfuscated syncs the lite member away from home with a
// hub that hides its tunnel with AmneziaWG: the lite member keeps the
// offer's settings and speaks AmneziaWG to the Go hub (member/src/awg.rs
// around GotaTun, amneziawg-go on the hub). CBB_LITE names the binary.
func TestLiteMemberAwayObfuscated(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	port := freeUDP(t)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}, Obfuscate: true}, ""); err != nil {
		t.Fatal(err)
	}
	piID := pi.status(t).Device
	home := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pi.addr())
	waitFor(t, "the lite member at home", func() bool {
		st, err := home.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(st.Status.Peers) == 1
	})
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member keeps the obfuscated hub's offer", func() bool {
		a := home.status(t).Away
		return a != nil && a.HubDevice == piID
	})
	home.stop()
	raw, err := os.ReadFile(filepath.Join(dir, "tunnel.json"))
	if err != nil || !strings.Contains(string(raw), "header_protection_key") {
		t.Fatalf("tunnel.json keeps no AmneziaWG settings (%v): %s", err, raw)
	}

	// The hub speaks AmneziaWG only: a lite member that reaches it speaks
	// it too.
	away := startLite(t, bin, dir, "-no-mdns", "-no-listen")
	waitUpTo(t, 30*time.Second, "the lite member reaches the obfuscated hub through the tunnel", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "from the lite member, hidden"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the lite member, hidden" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the lite member, hidden"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has it", func() bool { return away.paste(t) == "to the lite member, hidden" })
}

// TestLiteMemberAwayXHTTP checks the lite member's way over VLESS with
// XHTTP: the hub is reached only through a forwarder whose VLESS sits
// behind a TLS web server with an RSA certificate from a CA, which the lite
// member trusts through SSL_CERT_FILE. The offer's UDP address leads
// nowhere, so the lite member tries it, then VLESS, and copies go both
// ways inside it. CBB_LITE names the binary.
func TestLiteMemberAwayXHTTP(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
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
	dir := joinLite(t, bin, pi)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(),
		ForwarderKey: forward.Pin(cert.Leaf), VLESS: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub registers with the forwarder", func() bool {
		a := pi.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered
	})
	piID := pi.status(t).Device
	home := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", pi.addr())
	waitFor(t, "the lite member at home", func() bool {
		st, err := home.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && len(st.Status.Peers) == 1
	})
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member keeps the hub's offer with VLESS", func() bool {
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

	away := startLiteEnv(t, bin, dir, []string{"SSL_CERT_FILE=" + roots}, "-no-mdns", "-no-listen")
	waitUpTo(t, 60*time.Second, "the lite member reaches the hub over VLESS", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through && len(m.Status.Peers) == 1
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "from the lite member, over VLESS"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the hub has it", func() bool { return pi.paste(t) == "from the lite member, over VLESS" })
	if _, err := pi.do(t, control.Header{Op: control.OpCopy}, "to the lite member, over VLESS"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member has it", func() bool { return away.paste(t) == "to the lite member, over VLESS" })
}

// TestLiteRootless runs the lite member as a rootless install (D-79): its
// hello says so, the root records it as rootless, and it refuses the
// console and the reboot, which need root. CBB_LITE names the binary.
func TestLiteRootless(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	var h hub
	pi := startService(t, &h, "pi")
	if _, err := pi.do(t, control.Header{Op: control.OpNew}, ""); err != nil {
		t.Fatal(err)
	}
	dir := joinLite(t, bin, pi)
	pa := pi.addr()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	lite := startLiteEnv(t, bin, dir, []string{"CBB_ROOTLESS=1"}, "-no-mdns", "-port", strconv.Itoa(port), "-peer", pa)
	waitFor(t, "lite recorded as rootless", func() bool {
		for _, d := range pi.devices(t) {
			if d.Name == "lite" {
				return d.Store == group.StoreRootless && d.Role == group.RoleLite
			}
		}
		return false
	})
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bin, append([]string{"-socket", lite.socket}, args...)...)
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
