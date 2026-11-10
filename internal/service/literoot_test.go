// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/phone"
	"github.com/HunterEwok/cbb/internal/relay"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

// adminOn makes the device name an admin on the root, once it is connected
// there to get its admin CA.
func adminOn(t *testing.T, cli string, root *testService, name string) {
	t.Helper()
	var out string
	var err error
	waitFor(t, name+" connected to "+root.name+" for cbb admin", func() bool {
		out, err = runCLI(cli, root.socket, "", "admin", "-allow-file-key", name)
		return err == nil || !strings.Contains(out, "is not connected")
	})
	if err != nil {
		t.Fatalf("cbb admin %s on %s: %v\n%s", name, root.name, err, out)
	}
}

// cbbCLI is the command line the tests run against the services: the Rust
// cbb's, which CBB_TEST_RUST_SERVICE names.
func cbbCLI(t *testing.T) string {
	t.Helper()
	bin := rustService()
	if bin == "" {
		t.Skip("CBB_TEST_RUST_SERVICE is not set: the command line is the Rust cbb's")
	}
	return bin
}

// runCLI runs the command line cli against the service at socket, with
// stdin, and returns what it wrote.
func runCLI(cli, socket, stdin string, args ...string) (string, error) {
	cmd := exec.Command(cli, args...)
	cmd.Env = append(os.Environ(), "CBB_SOCKET="+socket)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// TestLiteRoot: the Rust service makes a group with cbb new and is its
// root (docs/design.md, "The service and its helper"): it admits a Go
// computer by the QR code that computer shows (cbb pair -qr), syncs with
// it, renames it, makes it an admin, freezes and unfreezes it, sets the key
// level and removes it, each through the Go command line, and the Go
// computer takes each record. CBB_LITE names the Rust member's binary.
func TestLiteRoot(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	dir := t.TempDir()
	root := startLite(t, bin, dir, "-no-mdns")
	cbb := func(stdin string, args ...string) (string, error) {
		t.Helper()
		return runCLI(cli, root.socket, stdin, args...)
	}
	must := func(stdin string, args ...string) string {
		t.Helper()
		out, err := cbb(stdin, args...)
		if err != nil {
			t.Fatalf("cbb %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}

	out := must("", "new")
	if !strings.Contains(out, "Created the group") || !strings.Contains(out, "key level is files") {
		t.Fatalf("cbb new:\n%s", out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil || !strings.Contains(string(raw), `"group_ca_key"`) {
		t.Fatalf("the identity file keeps no root key: %v", err)
	}
	if out, err := cbb("", "new"); err == nil || !strings.Contains(out, "already in a group") {
		t.Errorf("a second cbb new: %v\n%s", err, out)
	}
	waitFor(t, "the Rust root in its group", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && st.Status.Group != "" && st.Status.Role == "member"
	})

	// A Go computer shows its QR code and waits; the Rust root admits it.
	var h hub
	laptop := startService(t, &h, "laptop")
	jc := laptop.dial(t)
	defer jc.Close()
	code := newCode(t)
	m, err := jc.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: code, Expires: 300, Listen: true}})
	if err != nil || len(m.Addrs) == 0 {
		t.Fatalf("the laptop's listening join: %v, %+v", err, m)
	}
	qr := phone.JoinQR(phone.JoinCode{Code: code, Addrs: m.Addrs, Fingerprint: m.Fingerprint})
	if out := must(qr+"\n", "pair", "-qr"); !strings.Contains(out, "laptop joined the group") {
		t.Fatalf("cbb pair -qr:\n%s", out)
	}
	if m, err := jc.Receive(); err != nil || m.Error != "" {
		t.Fatalf("the laptop's join ended with %+v, %v", m, err)
	}
	waitFor(t, "the laptop in the group", func() bool { return laptop.status(t).Group != "" })

	// The root dials the laptop, which listens now.
	root.stop()
	root = startLite(t, bin, dir, "-no-mdns", "-peer", laptop.addr())
	waitFor(t, "the root and the laptop connected", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1
	})
	for _, mode := range []*testService{root, laptop} {
		if _, err := mode.do(t, control.Header{Op: control.OpSync, On: control.Bool(true)}, ""); err != nil {
			t.Fatal(err)
		}
	}
	must("from the root", "copy")
	waitFor(t, "the laptop has the root's text", func() bool { return laptop.paste(t) == "from the root" })

	// The root turns the laptop's sync off and on again with signed mode
	// commands.
	if _, err := root.do(t, control.Header{Op: control.OpSync, Device: laptop.status(t).Device, On: control.Bool(false)}, ""); err != nil {
		t.Fatalf("turning the laptop's sync off: %v", err)
	}
	waitFor(t, "the laptop's sync off", func() bool { return laptop.status(t).Mode == "own" })
	if _, err := root.do(t, control.Header{Op: control.OpSync, Device: laptop.status(t).Device, On: control.Bool(true)}, ""); err != nil {
		t.Fatalf("turning the laptop's sync on: %v", err)
	}
	waitFor(t, "the laptop's sync on", func() bool { return laptop.status(t).Mode == "shared" })

	listed := func(name string, admin bool) func() bool {
		return func() bool {
			m, err := laptop.do(t, control.Header{Op: control.OpDevices}, "")
			if err != nil {
				return false
			}
			for _, d := range m.Devices {
				if d.Name == name && d.Admin == admin {
					return true
				}
			}
			return false
		}
	}
	must("", "rename", "laptop", "desk")
	waitFor(t, "the laptop renamed", listed("desk", false))

	// A mute and its end: each reaches the root in a presence message,
	// without the laptop connecting again, so the connection is still up for
	// the freeze and the removal at the end.
	must("", "mute", "-on", "desk")
	waitFor(t, "the laptop muted", func() bool { return laptop.status(t).Muted })
	must("", "unmute", "-on", "desk")
	waitFor(t, "the laptop unmuted", func() bool { return !laptop.status(t).Muted })
	laptopID := laptop.status(t).Device
	waitFor(t, "the root sees the laptop unmuted", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		if err != nil || st.Status == nil || len(st.Status.Peers) != 1 {
			return false
		}
		return st.Status.Peers[0].ID == laptopID && !st.Status.Peers[0].Muted
	})
	root.logMu.Lock()
	for _, l := range root.lines {
		if strings.Contains(l, laptopID) && strings.Contains(l, "said goodbye") {
			t.Errorf("the laptop's connection closed for its mute: %s", l)
		}
	}
	root.logMu.Unlock()

	if out, err := cbb("", "admin", "desk"); err == nil || !strings.Contains(out, "allow-file-key") {
		t.Errorf("cbb admin of a computer whose keys are in a file: %v\n%s", err, out)
	}
	if out := must("", "admin", "-allow-file-key", "desk"); !strings.Contains(out, "desk is an admin now") {
		t.Errorf("cbb admin:\n%s", out)
	}
	waitFor(t, "the laptop an admin", func() bool { return listed("desk", true)() && laptop.isAdmin(t) })

	must("", "freeze", "desk")
	waitFor(t, "the laptop frozen", listed("desk", false))
	if out, err := cbb("", "freeze", "desk"); err == nil || !strings.Contains(out, "frozen already") {
		t.Errorf("a second freeze: %v\n%s", err, out)
	}
	root.stop()
	root = startLite(t, bin, dir, "-no-mdns", "-peer", laptop.addr())
	// The control socket answers while the service still loads its group.
	waitFor(t, "the root back in its group", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && st.Status.Group != ""
	})
	must("", "unfreeze", "desk")
	waitFor(t, "the laptop unfrozen", listed("desk", true))

	// The root's own keys are in a file, so the level stays files.
	if out, err := cbb("", "keys", "hardware"); err == nil || !strings.Contains(out, "the group's root, keeps its keys in a file") {
		t.Errorf("cbb keys hardware on a root whose keys are in a file: %v\n%s", err, out)
	}
	if out := must("", "keys", "files"); !strings.Contains(out, "Key level files") {
		t.Errorf("cbb keys files:\n%s", out)
	}
	if out := must("", "keys"); !strings.Contains(out, "Key level files") {
		t.Errorf("cbb keys:\n%s", out)
	}
	if out, err := cbb("", "resolve"); err == nil || !strings.Contains(out, "no key of the group signed two histories") {
		t.Errorf("cbb resolve with nothing to resolve: %v\n%s", err, out)
	}
	if out, err := cbb("", "remove", "nobody"); err == nil || !strings.Contains(out, `no device "nobody"`) {
		t.Errorf("cbb remove of an unknown device: %v\n%s", err, out)
	}
	// The group's settings and a handover.
	must("", "incoming", "2m")
	waitFor(t, "the laptop takes the incoming time", func() bool { return laptop.status(t).IncomingMS == 120000 })
	if out := must("", "takeover", "-delay", "0s"); !strings.Contains(out, "now waits 0s") {
		t.Errorf("cbb takeover -delay:\n%s", out)
	}
	if out, err := cbb("", "takeover", "-delay", "200h"); err == nil || !strings.Contains(out, "from 0s to 168h") {
		t.Errorf("a takeover delay too long: %v\n%s", err, out)
	}
	if out := must("", "handover", "desk"); !strings.Contains(out, "Handed the group over to desk") {
		t.Errorf("cbb handover:\n%s", out)
	}

	must("", "remove", "desk")
	waitFor(t, "the laptop removed", func() bool { return laptop.status(t).Removed })
}

// TestLiteRootWindow: the Rust root opens a pairing window with cbb pair,
// as Go's root does, and a Go computer joins it with the code it shows:
// a wrong code counts and leaves the window open, a second window waits
// for the first, the right code admits the computer, which then connects
// to the root on the same port, and a window that closed refuses.
func TestLiteRootWindow(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	root := startLite(t, bin, t.TempDir(), "-no-mdns", "-port", strconv.Itoa(port))
	if out, err := runCLI(cli, root.socket, "", "new"); err != nil {
		t.Fatalf("cbb new: %v\n%s", err, out)
	}
	waitFor(t, "the Rust root in its group", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && st.Status.Group != ""
	})

	// cbb pair shows the code and waits.
	cmd := exec.Command(cli, "pair")
	cmd.Env = append(os.Environ(), "CBB_SOCKET="+root.socket)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	codeLine := regexp.MustCompile(`^Pairing code: (\d{3}) (\d{3})$`)
	var code string
	timeout := time.After(20 * time.Second)
	for code == "" {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("cbb pair ended without a code: %s", stderr.String())
			}
			if m := codeLine.FindStringSubmatch(l); m != nil {
				code = m[1] + m[2]
			}
		case <-timeout:
			t.Fatal("cbb pair showed no code")
		}
	}

	// A second window waits for this one.
	if out, err := runCLI(cli, root.socket, "", "pair"); err == nil || !strings.Contains(out, "already open") {
		t.Errorf("a second cbb pair: %v\n%s", err, out)
	}

	var h hub
	laptop := startService(t, &h, "laptop")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpJoin, Code: wrong, Address: address}, ""); err == nil || !strings.Contains(err.Error(), "wrong code") {
		t.Fatalf("a join with a wrong code: %v", err)
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpJoin, Code: code, Address: address}, ""); err != nil {
		t.Fatalf("the join: %v", err)
	}
	joined := false
	for l := range lines {
		if strings.Contains(l, "laptop joined the group") {
			joined = true
			break
		}
	}
	if !joined {
		t.Fatalf("cbb pair did not say the laptop joined: %s", stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("cbb pair: %v\n%s", err, stderr.String())
	}
	// The laptop dials the root at the address it joined by, on the port
	// that took the pairing.
	waitFor(t, "the root and the laptop connected", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1 && len(laptop.status(t).Peers) == 1
	})

	// No window is open now.
	desk := startService(t, &h, "desk")
	if _, err := desk.do(t, control.Header{Op: control.OpJoin, Code: code, Address: address}, ""); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a join without a window: %v", err)
	}
}

// isAdmin reports whether the records list the service as an admin and it
// holds its admin CA: the records may reach it before the admin message
// does, and until it has taken the CA it acts as no admin (slow under the
// MIPS emulator, TestLiteTakeover).
func (s *testService) isAdmin(t *testing.T) bool {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpDevices}, "")
	if err != nil {
		return false
	}
	for _, d := range m.Devices {
		if d.Self {
			if !d.Admin {
				return false
			}
			id, err := group.Load(s.dir)
			return err == nil && id.AdminCA != nil
		}
	}
	return false
}

// TestLiteTakeover: the Rust service joins a Go computer's group as a
// member (cbb pair), offers an admin key, and the Go root makes
// it an admin; with the root lost, it takes the group over (cbb takeover)
// after the root's delay of 0s, becomes the root, and a Go computer of the
// group follows it.
func TestLiteTakeover(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)

	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	rust := startLite(t, bin, dir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", desk.addr(), "-peer", laptop.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2 && st.Status.Role == "member"
	})

	adminOn(t, cli, desk, "rust")
	waitFor(t, "the Rust member an admin", func() bool { return rust.isAdmin(t) })
	// The laptop gets its admin CA over its connection to the desk, which
	// the desk's new admin may have just made it open again.
	laptopID := laptop.status(t).Device
	waitFor(t, "the desk connected to the laptop", func() bool {
		return slices.ContainsFunc(desk.status(t).Peers, func(p control.Device) bool { return p.ID == laptopID })
	})
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "laptop"); err != nil {
		t.Fatalf("cbb admin laptop on the desk: %v\n%s", err, out)
	}
	waitFor(t, "the laptop an admin", func() bool { return laptop.isAdmin(t) })
	if out, err := runCLI(cli, desk.socket, "", "takeover", "-delay", "0s"); err != nil {
		t.Fatalf("cbb takeover -delay on the desk: %v\n%s", err, out)
	}
	waitFor(t, "the Rust member has the delay", func() bool { return recordsHold(dir, "takeover_delay_ms") })

	// The desk is lost; the Rust admin takes the group over.
	desk.stop()
	if out, err := runCLI(cli, rust.socket, "", "takeover", "laptop"); err == nil || !strings.Contains(out, "not the group's root") {
		t.Errorf("a takeover from a device that is not the root: %v\n%s", err, out)
	}
	if out, err := runCLI(cli, rust.socket, "", "takeover", "desk"); err != nil {
		t.Fatalf("cbb takeover: %v\n%s", err, out)
	}
	waitFor(t, "the Rust member the root", rootIs(t, rust, "rust"))
	waitFor(t, "the laptop follows the new root", rootIs(t, laptop, "rust"))
	// The laptop's admin CA was the lost root's; the new root gives it one.
	waitFor(t, "the laptop's admin CA from the new root", func() bool {
		id, err := group.Load(laptop.dir)
		return err == nil && id.AdminCA != nil && len(id.Roots) > 0 && !id.StaleAdminCA()
	})
	raw, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil || !strings.Contains(string(raw), `"root_key"`) || strings.Contains(string(raw), `"claim"`) {
		t.Errorf("the identity file after the takeover: %v\n%s", err, raw)
	}
	must := func(args ...string) {
		t.Helper()
		if out, err := runCLI(cli, rust.socket, "", args...); err != nil {
			t.Fatalf("cbb %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	// As the root it renames the laptop, which takes the record.
	must("rename", "laptop", "notebook")
	waitFor(t, "the laptop renamed under the new root", func() bool {
		m, err := laptop.do(t, control.Header{Op: control.OpDevices}, "")
		if err != nil {
			return false
		}
		for _, d := range m.Devices {
			if d.Self {
				return d.Name == "notebook"
			}
		}
		return false
	})
}

// recordsHold reports whether a body of the records file in dir holds text.
func recordsHold(dir, text string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "records.json"))
	if err != nil {
		return false
	}
	var f struct {
		Records []struct {
			Body []byte `json:"body"`
		} `json:"records"`
	}
	if json.Unmarshal(raw, &f) != nil {
		return false
	}
	for _, r := range f.Records {
		if bytes.Contains(r.Body, []byte(text)) {
			return true
		}
	}
	return false
}

// TestLiteRecovery: a Rust member that is no admin claims the group with
// its recovery key when the root is lost (cbb recovery, with the text of
// the sheet's QR code), becomes the root, and the Go computer follows.
func TestLiteRecovery(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)

	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	rust := startLite(t, bin, dir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", desk.addr(), "-peer", laptop.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2
	})
	if out, err := runCLI(cli, desk.socket, "", "takeover", "-delay", "0s"); err != nil {
		t.Fatalf("cbb takeover -delay on the desk: %v\n%s", err, out)
	}
	waitFor(t, "the Rust member has the delay", func() bool { return recordsHold(dir, "takeover_delay_ms") })

	recover := func(text string) (string, error) { return runCLI(cli, rust.socket, text+"\n", "recovery") }
	if out, err := recover("cbb://recover?g=0&k=AA&c=AA"); err == nil {
		t.Errorf("a broken sheet: %s", out)
	}
	desk.stop()
	sheet := addRecovery(t, desk)
	desk = restartService(t, &h, desk)
	waitFor(t, "the Rust member holds the recovery key's record", func() bool { return recordsHold(dir, `"recovery"`) })
	qr := func(group string) string {
		k, err := sheet.Key.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		enc := base64.RawURLEncoding.EncodeToString
		return "cbb://recover?g=" + group + "&k=" + enc(k) + "&c=" + enc(sheet.Cert)
	}
	if out, err := recover(qr("0123456789abcdef")); err == nil || !strings.Contains(out, "another group") {
		t.Errorf("a sheet of another group: %v\n%s", err, out)
	}
	desk.stop()
	if out, err := recover(qr(sheet.Group)); err != nil {
		t.Fatalf("cbb recovery: %v\n%s", err, out)
	}
	waitFor(t, "the Rust member the root", rootIs(t, rust, "rust"))
	waitFor(t, "the laptop follows the new root", rootIs(t, laptop, "rust"))
	if out, err := recover(qr(sheet.Group)); err == nil {
		t.Errorf("the new root claimed the group again: %s", out)
	}
}

// rootIs reports whether s lists name as the group's root.
func rootIs(t *testing.T, s *testService, name string) func() bool {
	return func() bool {
		m, err := s.do(t, control.Header{Op: control.OpDevices}, "")
		if err != nil {
			return false
		}
		for _, d := range m.Devices {
			if d.Root {
				return d.Name == name
			}
		}
		return false
	}
}

// TestLiteHub: an admin Rust service is the group's hub (cbb global hub,
// docs/protocol.md, section 11): a Go computer keeps its offer at home,
// then reaches it only through the tunnel and syncs, and cbb global hub off
// refuses to stop the only hub without -yes, then stops it.
func TestLiteHub(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)
	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	rust := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2 && st.Status.Role == "member"
	})
	port := freeUDP(t)
	hubAt := []string{fmt.Sprintf("127.0.0.1:%d", port)}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: hubAt, Consent: true}, ""); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Errorf("a hub that is no admin: %v", err)
	}
	adminOn(t, cli, desk, "rust")
	// It is an admin once its admin CA came.
	var m *control.Message
	waitFor(t, "the Rust member a hub", func() bool {
		var err error
		m, err = rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: hubAt, Consent: true}, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub on the Rust member: %v", err)
		}
		return err == nil
	})
	if a := m.Status.Away; a == nil || !a.Hub || a.Port != port {
		t.Fatalf("the Rust hub's status: %+v", a)
	}
	rustID := rust.status(t).Device
	if _, err := laptop.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop keeps the Rust hub's offer", func() bool {
		a := laptop.status(t).Away
		return a != nil && a.HubDevice == rustID
	})

	// The laptop leaves home: it reaches the Rust hub only through the
	// tunnel, which the hub admitted its key for.
	rust.stop()
	rust = startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr())
	laptopID := laptop.status(t).Device
	laptop.stop()
	h.hide(laptopID)
	laptop = restartService(t, &h, laptop)
	waitUpTo(t, 30*time.Second, "the laptop reaches the Rust hub through the tunnel", func() bool {
		st := laptop.status(t)
		return st.Away != nil && st.Away.Through && slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == rustID })
	})
	if a := rust.status(t).Away; a == nil || !a.Hub || a.Clients != 1 {
		t.Errorf("the Rust hub's status with its client: %+v", a)
	}
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "through the Rust hub"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust hub has it", func() bool { return rust.paste(t) == "through the Rust hub" })

	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub-off"}, ""); err == nil || !strings.Contains(err.Error(), "no other hub") {
		t.Errorf("stopping the only hub: %v", err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Force: true}, ""); err != nil {
		t.Fatalf("cbb global hub off -yes: %v", err)
	}
	if a := rust.status(t).Away; a == nil || a.Hub {
		t.Errorf("the Rust member after hub off: %+v", a)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tunnel.json"))
	if err != nil || !strings.Contains(string(raw), `"retired": true`) || strings.Contains(string(raw), `"is_hub"`) {
		t.Errorf("tunnel.json after hub off: %v\n%s", err, raw)
	}
}

// TestLiteHubs runs the Rust service as the second of two hubs, below the
// Go root's: it waits as the root's client while the root serves, learns
// the laptop's keys from what the root shares, serves the laptop when the
// root is off, and gives way when the root serves again
// (docs/protocol.md, section 11, "Several hubs").
func TestLiteHubs(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)
	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	deskAddr := desk.addr()
	env := []string{"CBB_STANDBY_GRACE=2"}
	rust := startLiteEnv(t, bin, dir, env, "-no-mdns", "-no-listen", "-peer", deskAddr, "-peer", laptop.addr())
	adminOn(t, cli, desk, "rust")
	deskPort, rustPort := freeUDP(t), freeUDP(t)
	for _, s := range []*testService{desk, laptop} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: deskPort, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", deskPort)}}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust member a hub", func() bool {
		_, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: rustPort, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", rustPort)}, Consent: true}, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub on the Rust member: %v", err)
		}
		return err == nil
	})
	deskID, rustID, laptopID := desk.status(t).Device, rust.status(t).Device, laptop.status(t).Device
	waitUpTo(t, 30*time.Second, "the laptop keeps both hubs' offers", func() bool {
		st := tunnelState(t, laptop)
		return st.Hub(deskID) != nil && st.Hub(rustID) != nil && st.PSK == st.Hub(rustID).PresharedKey
	})
	waitUpTo(t, 30*time.Second, "the Rust hub waits as the desk's client", func() bool {
		a := rust.status(t).Away
		return a != nil && a.Hub && a.Standby && a.HubDevice == deskID
	})
	if a := desk.status(t).Away; a == nil || a.Standby {
		t.Errorf("the desk, the first hub, does not serve: %+v", a)
	}
	waitUpTo(t, 30*time.Second, "the desk keeps the Rust hub's offer and the Rust hub the laptop", func() bool {
		raw, err := os.ReadFile(filepath.Join(dir, "tunnel.json"))
		return tunnelState(t, desk).Hub(rustID) != nil && err == nil && strings.Contains(string(raw), laptopID)
	})

	// The laptop leaves home and reaches the desk through the tunnel.
	laptop.stop()
	h.hide(laptopID)
	laptop = restartService(t, &h, laptop)
	through := func(hub string) func() bool {
		return func() bool {
			st := laptop.status(t)
			return st.Away != nil && st.Away.Through && st.Away.HubDevice == hub &&
				slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == hub })
		}
	}
	waitUpTo(t, 30*time.Second, "the laptop reaches the desk through the tunnel", through(deskID))

	// The desk stops: the Rust hub serves, and the laptop reaches it.
	desk.stop()
	waitUpTo(t, 60*time.Second, "the Rust hub serves", func() bool {
		a := rust.status(t).Away
		return a != nil && a.Hub && !a.Standby
	})
	waitUpTo(t, 90*time.Second, "the laptop reaches the Rust hub through the tunnel", through(rustID))
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "while the desk is off"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust hub has it", func() bool { return rust.paste(t) == "while the desk is off" })

	// The desk comes back where the Rust member dials it: the Rust hub
	// gives way, and the laptop moves back.
	desk = startIn(t, &h, &testService{name: desk.name, dir: desk.dir, os: desk.os, port: portOf(t, deskAddr)})
	waitUpTo(t, 60*time.Second, "the Rust hub gives way to the desk", func() bool {
		a := rust.status(t).Away
		return a != nil && a.Standby
	})
	waitUpTo(t, 90*time.Second, "the laptop reaches the desk again", through(deskID))
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "the desk is back"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the desk has it", func() bool { return desk.paste(t) == "the desk is back" })
}

// TestLiteHubCommands runs the hub commands both ways between the Rust
// service and a Go root: the Rust hub moves the hub to the Go root, the root
// makes the Rust service a hub again, and each stops the other being one
// (docs/protocol.md, section 11, "Moving the hub", "Several hubs",
// "Stopping a hub").
func TestLiteHubCommands(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)
	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	rust := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	adminOn(t, cli, desk, "rust")
	for _, s := range []*testService{desk, laptop} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatal(err)
		}
	}
	deskAt, rustAt := []string{fmt.Sprintf("127.0.0.1:%d", freeUDP(t))}, []string{fmt.Sprintf("127.0.0.1:%d", freeUDP(t))}
	waitFor(t, "the Rust member a hub", func() bool {
		_, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Addrs: rustAt, Consent: true}, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub on the Rust member: %v", err)
		}
		return err == nil
	})
	deskID, rustID := desk.status(t).Device, rust.status(t).Device
	waitUpTo(t, 30*time.Second, "the laptop keeps the Rust hub's offer", func() bool {
		return tunnelState(t, laptop).Hub(rustID) != nil
	})

	waitFor(t, "the Rust hub connected to both again", func() bool { return len(rust.status(t).Peers) == 2 })
	// The Rust hub moves the hub to the desk and becomes its client; the
	// laptop gets the desk's offer in place of the Rust hub's.
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "move", Device: "desk", Addrs: deskAt}, ""); err != nil {
		t.Fatalf("cbb global move desk on the Rust hub: %v", err)
	}
	if a := desk.status(t).Away; a == nil || !a.Hub {
		t.Errorf("the desk after the move: %+v", a)
	}
	if a := rust.status(t).Away; a == nil || a.Hub || a.HubDevice != deskID {
		t.Errorf("the Rust member after the move: %+v", a)
	}
	waitFor(t, "the laptop keeps the desk's offer only", func() bool {
		st := tunnelState(t, laptop)
		return st.Hub(deskID) != nil && st.Hub(rustID) == nil
	})

	// The Rust member stops the desk, the only hub, being one.
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Device: "desk", Force: true}, ""); err != nil {
		t.Fatalf("cbb global hub off -on desk -yes on the Rust member: %v", err)
	}
	waitFor(t, "the desk is no hub", func() bool {
		a := desk.status(t).Away
		return a != nil && !a.Hub
	})

	// The desk makes the Rust member a hub again, and keeps its offer.
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "rust", Addrs: rustAt}, ""); err != nil {
		t.Fatalf("cbb global hub -on rust on the desk: %v", err)
	}
	if a := rust.status(t).Away; a == nil || !a.Hub {
		t.Errorf("the Rust member after hub -on: %+v", a)
	}
	if tunnelState(t, desk).Hub(rustID) == nil {
		t.Error("the desk keeps no offer of the Rust hub")
	}

	// The desk stops the Rust hub being one.
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Device: "rust"}, ""); err == nil || !strings.Contains(err.Error(), "no other hub") {
		t.Errorf("stopping the only hub from the desk: %v", err)
	}
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "hub-off", Device: "rust", Force: true}, ""); err != nil {
		t.Fatalf("cbb global hub off -on rust -yes on the desk: %v", err)
	}
	waitFor(t, "the Rust member is no hub", func() bool {
		a := rust.status(t).Away
		return a != nil && !a.Hub
	})

	// The Rust admin signs the table of main hubs, which puts it first.
	if _, err := rust.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"rust", "rust"}}, ""); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a hub named twice: %v", err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpHubs, Hubs: []string{"rust", "desk"}}, ""); err != nil {
		t.Fatalf("cbb global hubs on the Rust member: %v", err)
	}
	waitFor(t, "the desk puts the Rust member first", func() bool {
		order := hubOrderIn(desk.dir)
		return len(order) == 2 && string(order[0]) == rustID
	})

	// It turns sync away from home off on the laptop.
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "off", Device: "laptop"}, ""); err != nil {
		t.Fatalf("cbb global off -on laptop on the Rust member: %v", err)
	}
	waitFor(t, "sync away from home is off on the laptop", func() bool { return laptop.status(t).Away == nil })
}

// TestLiteHubForwarder runs the Rust hub behind Go's forwarder only: it
// registers with its member certificate and the group's records, and the
// laptop away from home reaches it through the forwarder (docs/protocol.md,
// section 13).
func TestLiteHubForwarder(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf, StateFile: filepath.Join(t.TempDir(), "state.json")})
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

	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)
	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	rust := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	adminOn(t, cli, desk, "rust")
	req := control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(), ForwarderKey: forward.Pin(cert.Leaf), Consent: true}
	waitFor(t, "the Rust member a hub", func() bool {
		_, err := rust.do(t, req, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub on the Rust member: %v", err)
		}
		return err == nil
	})
	waitFor(t, "the Rust hub registers with the forwarder", func() bool {
		a := rust.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered && a.Forwarder.Seen != ""
	})
	rustID := rust.status(t).Device
	if _, err := laptop.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the laptop keeps the Rust hub's offer at the forwarder", func() bool {
		hl := tunnelState(t, laptop).Hub(rustID)
		return hl != nil && len(hl.Endpoints) == 1 && hl.Endpoints[0].String() == f.Addr().String()
	})

	laptopID := laptop.status(t).Device
	laptop.stop()
	h.hide(laptopID)
	laptop = restartService(t, &h, laptop)
	waitUpTo(t, 30*time.Second, "the laptop reaches the Rust hub through the forwarder", func() bool {
		st := laptop.status(t)
		return st.Away != nil && st.Away.Through && slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == rustID })
	})
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "through the forwarder"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust hub has it", func() bool { return rust.paste(t) == "through the forwarder" })
}

// TestLiteHubCredential: a Rust admin's hub registers with the Go
// forwarder with the group's hubs' credential that the Go root signs
// (docs/protocol.md, section 18), as Go's hubCredentials, serves with a key
// of its own for the period (section 11, "The hub's key"), and a Go laptop
// away from home reaches it through the forwarder.
func TestLiteHubCredential(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf, StateFile: filepath.Join(t.TempDir(), "state.json")})
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

	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)
	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	rust := startLiteEnv(t, bin, dir, []string{"CBB_HUB_KEY_AHEAD=2"}, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	adminOn(t, cli, desk, "rust")
	req := control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(), ForwarderKey: forward.Pin(cert.Leaf), Consent: true}
	waitFor(t, "the Rust member a hub", func() bool {
		_, err := rust.do(t, req, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub on the Rust member: %v", err)
		}
		return err == nil
	})
	// The desk, the root, lists the Rust admin's server key in the hubs'
	// credential; the Rust hub then registers with it in place of its
	// member certificate and the records.
	waitUpTo(t, 60*time.Second, "the Rust hub registers with the hubs' credential", func() bool {
		return rust.logged("registered with the forwarder with the group's hubs' credential")
	})
	// The period gives the hub a key of its own for its clients, which it
	// serves with CBB_HUB_KEY_AHEAD later, registering again with it.
	waitUpTo(t, 30*time.Second, "the Rust hub serves with its key for the period", func() bool {
		return rust.logged("the hub serves with its key for the new period from now on")
	})
	waitFor(t, "the Rust hub registered with the forwarder", func() bool {
		a := rust.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered && a.Forwarder.Seen != ""
	})
	rustID := rust.status(t).Device
	if _, err := laptop.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the laptop keeps the Rust hub's offer at the forwarder", func() bool {
		hl := tunnelState(t, laptop).Hub(rustID)
		return hl != nil && len(hl.Endpoints) == 1 && hl.Endpoints[0].String() == f.Addr().String()
	})

	laptopID := laptop.status(t).Device
	laptop.stop()
	h.hide(laptopID)
	laptop = restartService(t, &h, laptop)
	waitUpTo(t, 30*time.Second, "the laptop reaches the Rust hub through the forwarder", func() bool {
		st := laptop.status(t)
		return st.Away != nil && st.Away.Through && slices.ContainsFunc(st.Peers, func(p control.Device) bool { return p.ID == rustID })
	})
	if _, err := laptop.do(t, control.Header{Op: control.OpCopy}, "through the forwarder, credentialed"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust hub has it", func() bool { return rust.paste(t) == "through the forwarder, credentialed" })
}

// TestLiteForwardOnly has a Rust admin make another Rust member, no admin,
// a hub that only passes copies on: it signs the member's record with
// forward_only, which the Go root takes, and the hub command makes it a
// hub that then makes no copies (docs/protocol.md, section 11, "Two kinds
// of hub").
func TestLiteForwardOnly(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	// A device's record from the root counts before an admin's, so the
	// Rust admin admits the board itself, and its records then count.
	join := func(admin *testService, at, name string) string {
		// A new admin's records say so before its renewed certificate
		// arrives, and only the certificate opens a window.
		var c *control.Client
		var code string
		waitFor(t, "a pairing window on "+admin.name, func() bool {
			if admin.status(t).Group == "" {
				c, code = openWindow(t, admin)
				return true
			}
			c = admin.dial(t)
			m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair}})
			if err != nil {
				c.Close()
				return false
			}
			code = m.Code
			return true
		})
		if at == "" {
			// A Go service listens once it is in a group.
			at = admin.addr()
		}
		dir := t.TempDir()
		cmd := exec.Command(bin, "-state", dir, "pair", "-name", name, "-code", at)
		cmd.Stdin = strings.NewReader(code + "\n")
		cmd.Stderr = testWriter{t, name + " join: ", nil}
		if out, err := cmd.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
			t.Fatalf("cbb pair: %v; %s", err, out)
		}
		if m, err := c.Receive(); err != nil || m.Name != name {
			t.Fatalf("pair on %s ended with %+v, %v", admin.name, m, err)
		}
		c.Close()
		return dir
	}
	rustDir := join(desk, "", "rust")
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rustAt := free.Addr().String()
	free.Close()
	rust := startLite(t, bin, rustDir, "-no-mdns", "-port", strings.TrimPrefix(rustAt, "127.0.0.1:"), "-peer", desk.addr())
	adminOn(t, cli, desk, "rust")
	waitFor(t, "the Rust member an admin", func() bool { return rust.isAdmin(t) })
	boardDir := join(rust, rustAt, "board")
	board := startLite(t, bin, boardDir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", rustAt)
	if _, err := board.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	boardID := board.status(t).Device
	waitFor(t, "the board connected to both", func() bool { return len(board.status(t).Peers) == 2 })
	hubAt := []string{fmt.Sprintf("127.0.0.1:%d", freeUDP(t))}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "board", Addrs: hubAt}, ""); err == nil || !strings.Contains(err.Error(), "may not be a hub") {
		t.Errorf("a hub -on a member that is no admin: %v", err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "board", Addrs: hubAt, ForwardOnly: true}, ""); err != nil {
		t.Fatalf("cbb global hub -on board -forward-only on the Rust admin: %v", err)
	}
	if a := board.status(t).Away; a == nil || !a.Hub {
		t.Errorf("the board after the hub command: %+v", a)
	}
	waitFor(t, "the desk takes the board's record", func() bool {
		return slices.Contains(hubOrderIn(desk.dir), group.DeviceID(boardID))
	})
	if _, err := board.do(t, control.Header{Op: control.OpCopy}, "from a hub that only passes copies on"); err == nil || !strings.Contains(err.Error(), "only passes the copies on") {
		t.Errorf("a copy on the board: %v", err)
	}
}

// TestLiteHubVLESS has a Rust hub's clients come over VLESS with XHTTP:
// the admin Rust service is the hub with a forwarder and VLESS, registers
// the group's VLESS user ID, keeps the forwarder's VLESS settings, and the
// lite member, whose offer's UDP address then leads nowhere, reaches it
// through the forwarder's VLESS behind a TLS web server.
func TestLiteHubVLESS(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
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

	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	c, code := openWindow(t, desk)
	rustDir := t.TempDir()
	join := exec.Command(bin, "-state", rustDir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	free, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rustAt := free.Addr().String()
	free.Close()
	rust := startLite(t, bin, rustDir, "-no-mdns", "-port", strings.TrimPrefix(rustAt, "127.0.0.1:"), "-peer", desk.addr())
	adminOn(t, cli, desk, "rust")
	req := control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(),
		ForwarderKey: forward.Pin(cert.Leaf), Consent: true}
	waitFor(t, "the Rust member a hub", func() bool {
		_, err := rust.do(t, req, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub at a forwarder with VLESS on the Rust member: %v", err)
		}
		return err == nil
	})
	waitFor(t, "the Rust hub registers with the forwarder", func() bool {
		a := rust.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered
	})
	rustID := rust.status(t).Device
	waitFor(t, "the Rust hub keeps the forwarder's VLESS settings", func() bool {
		var st struct {
			Forwarder *struct {
				VLESSID string          `json:"vless_id"`
				VLESS   json.RawMessage `json:"vless"`
			} `json:"forwarder"`
		}
		raw, err := os.ReadFile(filepath.Join(rustDir, "tunnel.json"))
		return err == nil && json.Unmarshal(raw, &st) == nil && st.Forwarder != nil && st.Forwarder.VLESSID != "" && len(st.Forwarder.VLESS) > 0
	})

	dir := joinLite(t, bin, desk)
	home := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", rustAt)
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the lite member keeps the Rust hub's offer with VLESS", func() bool {
		type kept struct {
			Device string          `json:"device"`
			VLESS  json.RawMessage `json:"vless"`
		}
		var st struct {
			Hubs []kept `json:"hubs"`
		}
		raw, err := os.ReadFile(filepath.Join(dir, "tunnel.json"))
		return err == nil && json.Unmarshal(raw, &st) == nil &&
			slices.ContainsFunc(st.Hubs, func(h kept) bool { return h.Device == rustID && len(h.VLESS) > 0 })
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
	waitUpTo(t, 60*time.Second, "the lite member reaches the Rust hub over VLESS", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through &&
			slices.ContainsFunc(m.Status.Peers, func(p control.Device) bool { return p.ID == rustID })
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "to the Rust hub, over VLESS"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust hub has it", func() bool { return rust.paste(t) == "to the Rust hub, over VLESS" })
}

// TestLiteNetwork runs cbb network against the Rust service, which keeps
// the known networks as Go's networks.go does (member/src/networks.rs has
// the rules' tests, with Go's network IDs): the member port and mDNS then
// work on the networks this device is on now.
func TestLiteNetwork(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	root := startLite(t, bin, t.TempDir(), "-no-mdns", "-no-listen")
	if out, err := runCLI(cli, root.socket, "", "new"); err != nil {
		t.Fatalf("cbb new: %v\n%s", err, out)
	}
	waitFor(t, "the Rust root in its group", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && st.Status.Group != ""
	})
	out, err := runCLI(cli, root.socket, "", "network")
	if err != nil || !strings.Contains(out, "publishes itself and takes connections here") {
		t.Fatalf("cbb network: %v\n%s", err, out)
	}
}

// TestLiteRelay runs the Rust service in a group without a hub: it meets
// the Go desk at a blind relay, and once it is away from home they sync
// through it (docs/design.md, "Blind relay").
func TestLiteRelay(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	var h hub
	desk := startService(t, &h, "desk")
	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair: %v; %s", err, out)
	}
	if m, err := c.Receive(); err != nil || m.Name != "rust" {
		t.Fatalf("pair on the desk ended with %+v, %v", m, err)
	}
	c.Close()
	rust := startLite(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr())
	waitFor(t, "the Rust member connected to the desk", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1
	})
	r, keys := startRelay(t, desk.status(t).Group)
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: "nope", Consent: true}, ""); err == nil {
		t.Error("a relay with a bad key")
	}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin()}, ""); err == nil || !strings.Contains(err.Error(), "learns") {
		t.Errorf("a relay without consent: %v", err)
	}
	for _, s := range []*testService{desk, rust} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin(), Consent: true}, ""); err != nil {
			t.Fatalf("cbb global relay on the %s: %v", s.name, err)
		}
	}
	deskID, rustID := desk.status(t).Device, rust.status(t).Device
	waitUpTo(t, 60*time.Second, "both meet at the relay", func() bool {
		a, b := desk.status(t).Away, rust.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected && slices.Equal(a.Relay.Online, []string{rustID}) &&
			b != nil && b.Relay != nil && b.Relay.Connected && slices.Equal(b.Relay.Online, []string{deskID})
	})
	raw, err := os.ReadFile(filepath.Join(dir, "tunnel.json"))
	if err != nil || !strings.Contains(string(raw), r.Addr().String()) {
		t.Errorf("tunnel.json with the relay: %v\n%s", err, raw)
	}

	// Away from home the Rust member knows no address of the desk: the
	// relay joins them.
	rust.stop()
	rust = startLite(t, bin, dir, "-no-mdns", "-no-listen")
	waitUpTo(t, 30*time.Second, "the Rust member reaches the desk through the relay", func() bool {
		st := rust.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == deskID
	})
	if _, err := rust.do(t, control.Header{Op: control.OpCopy}, "via the relay"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the desk has it", func() bool { return desk.paste(t) == "via the relay" })
	if _, err := desk.do(t, control.Header{Op: control.OpCopy}, "back home"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust member has it", func() bool { return rust.paste(t) == "back home" })

	// Turning sync away from home off leaves the relay.
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the relay drops the Rust member", func() bool {
		_, n := r.Stats()
		return n == 1
	})
}

// startRelay runs a blind relay for the group of tag until the test ends.
func startRelay(t *testing.T, tag string) (*relay.Relay, relay.Keys) {
	t.Helper()
	keys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen(relay.Config{Listen: "127.0.0.1:0", Keys: keys, Groups: []string{tag}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return r, keys
}

// TestLiteRelayRoot runs the Rust service as the root of a group that meets
// at a blind relay: it starts the period and signs the hubs' and the
// members' credentials (docs/protocol.md, section 18), with which both
// devices register there, and the Go laptop and it sync through the relay.
func TestLiteRelayRoot(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	dir := t.TempDir()
	root := startLite(t, bin, dir, "-no-mdns")
	if out, err := runCLI(cli, root.socket, "", "new"); err != nil {
		t.Fatalf("cbb new: %v\n%s", err, out)
	}
	waitFor(t, "the Rust root in its group", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && st.Status.Group != "" && st.Status.Role == "member"
	})
	var h hub
	laptop := startService(t, &h, "laptop")
	jc := laptop.dial(t)
	defer jc.Close()
	code := newCode(t)
	m, err := jc.Do(&control.Message{Header: control.Header{Op: control.OpJoin, Code: code, Expires: 300, Listen: true}})
	if err != nil || len(m.Addrs) == 0 {
		t.Fatalf("the laptop's listening join: %v, %+v", err, m)
	}
	qr := phone.JoinQR(phone.JoinCode{Code: code, Addrs: m.Addrs, Fingerprint: m.Fingerprint})
	if out, err := runCLI(cli, root.socket, qr+"\n", "pair", "-qr"); err != nil || !strings.Contains(out, "laptop joined the group") {
		t.Fatalf("cbb pair -qr: %v\n%s", err, out)
	}
	if m, err := jc.Receive(); err != nil || m.Error != "" {
		t.Fatalf("the laptop's join ended with %+v, %v", m, err)
	}
	root.stop()
	root = startLite(t, bin, dir, "-no-mdns", "-peer", laptop.addr())
	laptopID, rootID := laptop.status(t).Device, root.status(t).Device
	waitFor(t, "the Rust root connected to the laptop", func() bool {
		p := root.status(t).Peers
		return len(p) == 1 && p[0].ID == laptopID
	})
	r, keys := startRelay(t, laptop.status(t).Group)
	for _, s := range []*testService{root, laptop} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin(), Consent: true}, ""); err != nil {
			t.Fatalf("cbb global relay on the %s: %v", s.name, err)
		}
	}
	// The root's credentials: the period, both server keys, the hubs' and
	// the members' credential.
	waitUpTo(t, 30*time.Second, "the Rust root signs the group's credentials", func() bool {
		raw, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
		var all []json.RawMessage
		return err == nil && json.Unmarshal(raw, &all) == nil && len(all) == 5
	})
	waitUpTo(t, 60*time.Second, "both meet at the relay with the credentials", func() bool {
		a, b := root.status(t).Away, laptop.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected && slices.Equal(a.Relay.Online, []string{laptopID}) &&
			b != nil && b.Relay != nil && b.Relay.Connected && slices.Equal(b.Relay.Online, []string{rootID})
	})

	root.stop()
	root = startLite(t, bin, dir, "-no-mdns")
	waitUpTo(t, 30*time.Second, "the Rust root reaches the laptop through the relay", func() bool {
		st := root.status(t)
		return st.Away != nil && st.Away.Through && len(st.Peers) == 1 && st.Peers[0].ID == laptopID
	})
	if _, err := root.do(t, control.Header{Op: control.OpCopy}, "from the root"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop has it", func() bool { return laptop.paste(t) == "from the root" })
}

// TestLiteRelayProject sets the Rust service to the project's relay,
// whose key the signed keys.json gives, then changes the relay's key: once
// a newer keys.json names the new key, the device registers again by
// itself. Then the relay moves, and entries.json says where to, as
// TestProjectRelayNewKey does with a Go device.
func TestLiteRelayProject(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	signer := newReleaseSigner(t)
	var h hub
	pi := startEnv(t, &h, "pi", signer.rootsEnv(t))
	dir := joinLite(t, bin, pi)
	pemFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: signer.roots(t)[0]}), 0o644); err != nil {
		t.Fatal(err)
	}
	lite := startLiteEnv(t, bin, dir, []string{"CBB_RELEASE_ROOTS=" + pemFile, "CBB_TEST_RESOLVE=relay.example.org=127.0.0.1"}, "-no-mdns", "-no-listen", "-peer", pi.addr())
	group := pi.status(t).Group
	serve := func(keys relay.Keys, at string) (*relay.Relay, func()) {
		r, err := relay.Listen(relay.Config{Listen: at, Keys: keys, Groups: []string{group}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		served := make(chan struct{})
		go func() {
			defer close(served)
			r.Serve(ctx)
		}()
		return r, func() {
			cancel()
			<-served
		}
	}
	oldKeys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, stop := serve(oldKeys, "127.0.0.1:0")
	at := r.Addr().String()

	if _, err := lite.do(t, control.Header{Op: control.OpEntries}, signer.signRelayKeys(t, 1, oldKeys)); err != nil {
		t.Fatal(err)
	}
	if _, err := lite.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: at, RelayKey: relay.Project, Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	connected := func() bool {
		a := lite.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected
	}
	waitUpTo(t, 60*time.Second, "the Rust member registers with the relay's listed key", connected)

	// The relay changes its key; the device refuses the new one until
	// keys.json names it, then takes it without being set again.
	stop()
	_, stop = serve(newKeys, at)
	waitUpTo(t, 60*time.Second, "the Rust member says the key is unknown", func() bool {
		a := lite.status(t).Away
		return a != nil && a.Relay != nil && !a.Relay.Connected && a.Relay.Error != "" && a.Relay.Detail != ""
	})
	if _, err := lite.do(t, control.Header{Op: control.OpEntries}, signer.signRelayKeys(t, 2, oldKeys, newKeys)); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 90*time.Second, "the Rust member registers with the new key", connected)
	if a := lite.status(t).Away; a.Relay.Error != "" {
		t.Errorf("an error left in status: %q", a.Relay.Error)
	}

	// It moves to another port under a name of its own.
	stop()
	moved, stop := serve(newKeys, "127.0.0.1:0")
	defer stop()
	_, port, _ := net.SplitHostPort(moved.Addr().String())
	if _, err := lite.do(t, control.Header{Op: control.OpEntries}, signer.signRelay(t, 3, []string{"relay.example.org:" + port}, newKeys)); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 90*time.Second, "the Rust member registers where the relay moved", func() bool {
		a := lite.status(t).Away
		return connected() && a.Relay.Endpoint == moved.Addr().String()
	})
	raw, err := os.ReadFile(filepath.Join(dir, "tunnel.json"))
	if err != nil || !strings.Contains(string(raw), moved.Addr().String()) {
		t.Errorf("tunnel.json after the move: %v\n%s", err, raw)
	}
}
