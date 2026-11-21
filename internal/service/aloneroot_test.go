// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	"sync"
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

// keptHubEndpoints gives the endpoints of the offer of hub id that s keeps
// in its tunnel.json, read as it is: a device of 0.6 derives its keys
// toward each hub, which Go's tunnel.State does not read.
func keptHubEndpoints(s *testService, id string) []string {
	var st struct {
		Hubs []struct {
			Device    string   `json:"device"`
			Endpoints []string `json:"endpoints"`
		} `json:"hubs"`
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "tunnel.json"))
	if err != nil || json.Unmarshal(raw, &st) != nil {
		return nil
	}
	for _, h := range st.Hubs {
		if h.Device == id {
			return h.Endpoints
		}
	}
	return nil
}

// forwardHub names the device name the group's hub (cbb hubs) and makes it
// a hub at its own UDP port, then has the root order it to the forwarder at
// addr with the key of pin (cbb global hub -on): the root signs the
// forwarder's pin in the hub command and gives the forwarder a face of its
// own, whose hubs' credential the hub registers with (docs/protocol.md,
// section 13).
func forwardHub(t *testing.T, cli string, root, s *testService, name, addr, pin string) {
	t.Helper()
	// The hubs' credential lists the hubs of the root's hubs record.
	if _, err := root.do(t, control.Header{Op: control.OpHubs, Hubs: []string{name}}, ""); err != nil {
		t.Fatalf("cbb hubs %s on %s: %v", name, root.name, err)
	}
	port := freeUDP(t)
	req := control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: []string{fmt.Sprintf("127.0.0.1:%d", port)}, Consent: true}
	waitFor(t, name+" a hub", func() bool {
		_, err := s.do(t, req, "")
		if err != nil && !strings.Contains(err.Error(), "admin") && !strings.Contains(err.Error(), "records do not make") {
			t.Fatalf("cbb global hub on %s: %v", name, err)
		}
		return err == nil
	})
	if out, err := runCLI(cli, root.socket, "", "global", "hub", "-on", name, "-forwarder", addr, "-forwarder-key", pin); err != nil {
		t.Fatalf("cbb global hub -on %s on %s: %v\n%s", name, root.name, err, out)
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

// TestAloneRoot: the Rust service makes a group with cbb new and is its
// root (docs/design.md, "The service and its helper"): it admits a Go
// computer by the QR code that computer shows (cbb pair -qr), syncs with
// it, renames it, makes it an admin, freezes and unfreezes it, sets the key
// level and removes it, each through the Go command line, and the Go
// computer takes each record. CBB_TEST_ALONE names the Rust member's binary.
func TestAloneRoot(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	dir := t.TempDir()
	root := startAlone(t, bin, dir, "-no-mdns")
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
	root = startAlone(t, bin, dir, "-no-mdns", "-peer", laptop.addr())
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
	root = startAlone(t, bin, dir, "-no-mdns", "-peer", laptop.addr())
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

// TestAloneRootWindow: the Rust root opens a pairing window with cbb pair,
// as Go's root does, and a Go computer joins it with the code it shows:
// a wrong code counts and leaves the window open, a second window waits
// for the first, the right code admits the computer, which then connects
// to the root on the same port, and a window that closed refuses.
func TestAloneRootWindow(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
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
	root := startAlone(t, bin, t.TempDir(), "-no-mdns", "-port", strconv.Itoa(port))
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

// isAdmin reports whether the records list the service as an admin and,
// in an old group, it holds its admin CA: the records may reach it before
// the admin message does, and until it has taken the CA it acts as no
// admin (slow under the MIPS emulator, TestAloneTakeover). A group of 0.6
// has no CA: the admin record is all.
func (s *testService) isAdmin(t *testing.T) bool {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpDevices}, "")
	if err != nil {
		return false
	}
	for _, d := range m.Devices {
		if d.Self {
			if !d.Admin || s.on06() {
				return d.Admin
			}
			id, err := group.Load(s.dir)
			return err == nil && id.AdminCA != nil
		}
	}
	return false
}

// TestAloneTakeover: the Rust service joins a group of 0.6 as a member
// (cbb pair) with an admin key it offers the root, and the root makes it an
// admin with that key (D-118), as it makes the laptop one; no admin CA
// travels. The root changes only with the recovery key (D-117): a claim's
// delay on the root, a handover and a takeover by an admin of the lost root
// are each refused with the way that is left, cbb recovery
// (TestAloneRecovery), and the admin stays an admin.
func TestAloneTakeover(t *testing.T) {
	bin := aloneBin(t)
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)

	dir := joinAloneAs(t, bin, desk, "rust", nil)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	rust := startAlone(t, bin, dir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", desk.addr(), "-peer", laptop.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2 && st.Status.Role == "member"
	})
	if !rust.on06() || !desk.on06() {
		t.Fatal("the group is not on the records of 0.6")
	}

	adminOn(t, cli, desk, "rust")
	waitFor(t, "the Rust member an admin", func() bool { return rust.isAdmin(t) })
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "laptop"); err != nil {
		t.Fatalf("cbb admin laptop on the desk: %v\n%s", err, out)
	}
	waitFor(t, "the laptop an admin", func() bool { return laptop.isAdmin(t) })

	refused := func(s *testService, what string, args ...string) {
		t.Helper()
		out, err := runCLI(cli, s.socket, "", args...)
		if err == nil || !strings.Contains(out, "cbb recovery") {
			t.Errorf("%s: %v\n%s", what, err, out)
		}
	}
	refused(desk, "cbb takeover -delay on the root", "takeover", "-delay", "0s")
	refused(desk, "cbb handover on the root", "handover", "rust")

	// The desk is lost; its admin cannot take the group over by itself.
	desk.stop()
	refused(rust, "cbb takeover on an admin", "takeover", "desk")
	if !rust.isAdmin(t) || !laptop.isAdmin(t) {
		t.Error("an admin lost its rights with the refused takeover")
	}
	waitFor(t, "the desk is still the root", rootIs(t, rust, "desk"))
}

// TestAloneRecovery: a Rust member that is no admin claims the group with
// its recovery key when the root is lost (cbb recovery, with the text of
// the sheet's QR code that cbb new showed once, D-117), leaves the lost
// root out, becomes the root, and the laptop follows. A broken sheet,
// another group's sheet and a claim by the root itself are refused.
func TestAloneRecovery(t *testing.T) {
	bin := aloneBin(t)
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	sheetOf := func(s *testService) string {
		t.Helper()
		m, err := s.do(t, control.Header{Op: control.OpNew}, "")
		if err != nil {
			t.Fatalf("new on %s: %v", s.name, err)
		}
		var sheet struct {
			Sheet string `json:"sheet"`
			QR    string `json:"qr"`
		}
		if err := json.Unmarshal(m.Payload, &sheet); err != nil || sheet.QR == "" || sheet.Sheet == "" {
			t.Fatalf("the recovery sheet of cbb new on %s: %v, %q", s.name, err, m.Payload)
		}
		return sheet.QR
	}
	qr := sheetOf(desk)
	pairWith(t, desk, laptop)

	dir := joinAloneAs(t, bin, desk, "rust", nil)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	rust := startAlone(t, bin, dir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", desk.addr(), "-peer", laptop.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2
	})

	recover := func(s *testService, text string, args ...string) (string, error) {
		return runCLI(cli, s.socket, text+"\n", append([]string{"recovery"}, args...)...)
	}
	if out, err := recover(rust, "cbb://recover?g=0&k=AA&c=AA"); err == nil || !strings.Contains(out, "sheet") {
		t.Errorf("a broken sheet: %v\n%s", err, out)
	}
	other := startService(t, &h, "other")
	if out, err := recover(rust, sheetOf(other)); err == nil || !strings.Contains(out, "another group") {
		t.Errorf("a sheet of another group: %v\n%s", err, out)
	}
	if out, err := recover(desk, qr); err == nil || !strings.Contains(out, "root already") {
		t.Errorf("the root claimed its own group: %v\n%s", err, out)
	}

	desk.stop()
	if out, err := recover(rust, qr, "-leave", "desk"); err != nil {
		t.Fatalf("cbb recovery: %v\n%s", err, out)
	}
	waitFor(t, "the Rust member the root", rootIs(t, rust, "rust"))
	waitFor(t, "the laptop follows the new root", rootIs(t, laptop, "rust"))
	waitFor(t, "the lost root left the laptop's group", func() bool {
		m, err := laptop.do(t, control.Header{Op: control.OpDevices}, "")
		return err == nil && !slices.ContainsFunc(m.Devices, func(d control.Device) bool { return d.Name == "desk" })
	})
	if out, err := recover(rust, qr); err == nil || !strings.Contains(out, "root already") {
		t.Errorf("the new root claimed the group again: %v\n%s", err, out)
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

// TestAloneHubForwarder runs the Rust hub behind Go's forwarder only: it
// registers with its member certificate and the group's records, and the
// laptop away from home reaches it through the forwarder (docs/protocol.md,
// section 13).
func TestAloneHubForwarder(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
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
	dir := joinAloneAs(t, bin, desk, "rust", nil)
	rust := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	adminOn(t, cli, desk, "rust")
	forwardHub(t, cli, desk, rust, "rust", f.Addr().String(), forward.Pin(cert.Leaf))
	waitFor(t, "the Rust hub registers with the forwarder", func() bool {
		a := rust.status(t).Away
		return a != nil && a.Forwarder != nil && a.Forwarder.Registered && a.Forwarder.Seen != ""
	})
	rustID := rust.status(t).Device
	if _, err := laptop.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the laptop keeps the Rust hub's offer at the forwarder", func() bool {
		return slices.Equal(keptHubEndpoints(laptop, rustID), []string{f.Addr().String()})
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

// TestAloneHubCredential: a Rust admin's hub registers with the Go
// forwarder with the group's hubs' credential that the Go root signs
// (docs/protocol.md, section 18), as Go's hubCredentials, serves with a key
// of its own for the period (section 11, "The hub's key"), and a Go laptop
// away from home reaches it through the forwarder.
func TestAloneHubCredential(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
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
	dir := joinAloneAs(t, bin, desk, "rust", nil)
	rust := startAloneEnv(t, bin, dir, []string{"CBB_TEST_HUB_KEY_AHEAD=2"}, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	adminOn(t, cli, desk, "rust")
	forwardHub(t, cli, desk, rust, "rust", f.Addr().String(), forward.Pin(cert.Leaf))
	// The desk, the root, lists the Rust admin's server key in the hubs'
	// credential; the Rust hub then registers with it in place of its
	// member certificate and the records.
	waitUpTo(t, 60*time.Second, "the Rust hub registers with the hubs' credential", func() bool {
		return rust.logged("registered with the forwarder with the group's hubs' credential")
	})
	// The period gives the hub a key of its own for its clients, which it
	// serves with CBB_TEST_HUB_KEY_AHEAD later, registering again with it.
	waitUpTo(t, 30*time.Second, "the Rust hub serves with its key for the period", func() bool {
		return rust.logged("the hub serves with its key and settings for the new period from now on")
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
		return slices.Equal(keptHubEndpoints(laptop, rustID), []string{f.Addr().String()})
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

// TestAloneForwardOnly has the root make a Rust member, no admin, a hub
// that only passes copies on: its record keeps the right to be a hub and
// loses those to read and send, the hubs record names it, and the hub
// command makes it a hub, where it refuses to make a copy. A Rust admin may
// not: the records of 0.6 let an admin give base rights only.
func TestAloneForwardOnly(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	rustDir := joinAloneAs(t, bin, desk, "rust", nil)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rustAt := free.Addr().String()
	free.Close()
	rust := startAlone(t, bin, rustDir, "-no-mdns", "-port", strings.TrimPrefix(rustAt, "127.0.0.1:"), "-peer", desk.addr())
	adminOn(t, cli, desk, "rust")
	waitFor(t, "the Rust member an admin", func() bool { return rust.isAdmin(t) })
	boardDir := joinAloneAs(t, bin, desk, "board", nil)
	board := startAlone(t, bin, boardDir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", rustAt)
	if _, err := board.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	boardID := board.status(t).Device
	waitFor(t, "the board connected to both", func() bool { return len(board.status(t).Peers) == 2 })
	hubAt := []string{fmt.Sprintf("127.0.0.1:%d", freeUDP(t))}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "board", Addrs: hubAt}, ""); err == nil || !strings.Contains(err.Error(), "do not make board a hub") {
		t.Errorf("a hub -on a member that is no admin: %v", err)
	}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "board", Addrs: hubAt, ForwardOnly: true}, ""); err == nil || !strings.Contains(err.Error(), "the group's root does it") {
		t.Errorf("cbb global hub -on board -forward-only on the Rust admin: %v", err)
	}
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "board", Addrs: hubAt, ForwardOnly: true}, ""); err != nil {
		t.Fatalf("cbb global hub -on board -forward-only on the root: %v", err)
	}
	if a := board.status(t).Away; a == nil || !a.Hub {
		t.Errorf("the board after the hub command: %+v", a)
	}
	waitFor(t, "the Rust admin takes the board's record", func() bool {
		m, err := rust.do(t, control.Header{Op: control.OpDevices}, "")
		return err == nil && slices.ContainsFunc(m.Devices, func(d control.Device) bool { return d.ID == boardID && d.ForwardOnly && d.Hub })
	})
	if _, err := board.do(t, control.Header{Op: control.OpCopy}, "from a hub that only passes copies on"); err == nil || !strings.Contains(err.Error(), "only passes the copies on") {
		t.Errorf("a copy on the board: %v", err)
	}
}

// TestAloneHubVLESS has a Rust hub's clients come over VLESS with XHTTP:
// the admin Rust service is the hub with a forwarder and VLESS, registers
// the group's VLESS user ID, keeps the forwarder's VLESS settings, and the
// small device, whose offer's UDP address then leads nowhere, reaches it
// through the forwarder's VLESS behind a TLS web server.
func TestAloneHubVLESS(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
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
	rustDir := joinAloneAs(t, bin, desk, "rust", nil)
	free, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rustAt := free.Addr().String()
	free.Close()
	rust := startAlone(t, bin, rustDir, "-no-mdns", "-port", strings.TrimPrefix(rustAt, "127.0.0.1:"), "-peer", desk.addr())
	adminOn(t, cli, desk, "rust")
	forwardHub(t, cli, desk, rust, "rust", f.Addr().String(), forward.Pin(cert.Leaf))
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

	dir := joinAlone(t, bin, desk)
	home := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr(), "-peer", rustAt)
	if _, err := home.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 30*time.Second, "the small device keeps the Rust hub's offer with VLESS", func() bool {
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

	away := startAloneEnv(t, bin, dir, []string{"SSL_CERT_FILE=" + roots}, "-no-mdns", "-no-listen")
	waitUpTo(t, 60*time.Second, "the small device reaches the Rust hub over VLESS", func() bool {
		m, err := away.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status.Away != nil && m.Status.Away.Through &&
			slices.ContainsFunc(m.Status.Peers, func(p control.Device) bool { return p.ID == rustID })
	})
	if _, err := away.do(t, control.Header{Op: control.OpCopy}, "to the Rust hub, over VLESS"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust hub has it", func() bool { return rust.paste(t) == "to the Rust hub, over VLESS" })
}

// TestAloneNetwork runs cbb network against the Rust service, which keeps
// the known networks as Go's networks.go does (member/src/networks.rs has
// the rules' tests, with Go's network IDs): the member port and mDNS then
// work on the networks this device is on now.
func TestAloneNetwork(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	root := startAlone(t, bin, t.TempDir(), "-no-mdns", "-no-listen")
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

// TestAloneRelay runs the Rust service in a group without a hub: it meets
// the Go desk at a blind relay, and once it is away from home they sync
// through it (docs/design.md, "Blind relay").
func TestAloneRelay(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	var h hub
	desk := startService(t, &h, "desk")
	dir := joinAloneAs(t, bin, desk, "rust", nil)
	rust := startAlone(t, bin, dir, "-no-mdns", "-no-listen", "-peer", desk.addr())
	waitFor(t, "the Rust member connected to the desk", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1
	})
	r, keys := startRelay(t, desk.status(t).RelayGroup)
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: "nope", Consent: true}, ""); err == nil {
		t.Error("a relay with a bad key")
	}
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin()}, ""); err == nil || !strings.Contains(err.Error(), "learns") {
		t.Errorf("a relay without consent: %v", err)
	}
	// In a group of 0.6 the relay is the group's setting: only the root
	// names it, and every member takes it from the group's settings.
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin(), Consent: true}, ""); err == nil || !strings.Contains(err.Error(), "only the group's root") {
		t.Errorf("a member naming the group's relay: %v", err)
	}
	if _, err := desk.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin(), Consent: true}, ""); err != nil {
		t.Fatalf("cbb global relay on the root: %v", err)
	}
	for _, s := range []*testService{desk, rust} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatalf("cbb global on on the %s: %v", s.name, err)
		}
	}
	deskID, rustID := desk.status(t).Device, rust.status(t).Device
	waitUpTo(t, 60*time.Second, "both meet at the relay", func() bool {
		a, b := desk.status(t).Away, rust.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected && slices.Equal(a.Relay.Online, []string{rustID}) &&
			b != nil && b.Relay != nil && b.Relay.Connected && slices.Equal(b.Relay.Online, []string{deskID})
	}, func() string {
		a, _ := json.Marshal(desk.status(t).Away)
		b, _ := json.Marshal(rust.status(t).Away)
		return fmt.Sprintf("the desk away %s, the Rust member away %s", a, b)
	})
	// The member holds the relay from the group's settings (D-121), not
	// from a file of its own.
	if a := rust.status(t).Away; a == nil || a.Relay == nil || a.Relay.Endpoint != r.Addr().String() {
		t.Errorf("the Rust member's relay: %+v", a)
	}

	// Away from home the Rust member knows no address of the desk: the
	// relay joins them.
	rust.stop()
	rust = startAlone(t, bin, dir, "-no-mdns", "-no-listen")
	// It has neither mDNS nor the desk's address: the relay is its only
	// way, which Through (a hub's way) does not count on 0.6.
	waitUpTo(t, 30*time.Second, "the Rust member reaches the desk through the relay", func() bool {
		st := rust.status(t)
		return st.Away != nil && st.Away.Relay != nil && st.Away.Relay.Connected &&
			slices.Equal(st.Away.Relay.Online, []string{deskID}) && len(st.Peers) == 1 && st.Peers[0].ID == deskID
	}, func() string {
		st := rust.status(t)
		raw, _ := json.Marshal(st.Away)
		return fmt.Sprintf("away %s, peers %+v", raw, st.Peers)
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

// startRelay runs a blind relay, the Rust cbb-relay, for the group (its
// status's RelayGroup) until the test ends.
func startRelay(t *testing.T, group string) (*relay.Process, relay.Keys) {
	t.Helper()
	r, _ := runRelay(t, relay.Keys{}, "", group)
	return r, r.Keys
}

// runRelay runs cbb-relay with keys (new ones when zero) at the address at
// (a port of its own when empty) for the group (its status's RelayGroup),
// and returns it and how to stop it, which the end of the test does too.
// The test skips
// without a cbb-relay (relay.Binary).
func runRelay(t *testing.T, keys relay.Keys, at, group string) (*relay.Process, func()) {
	t.Helper()
	bin := relay.Binary()
	if bin == "" {
		t.Skip("no cbb-relay beside cbb, nor CBB_TEST_RUST_RELAY")
	}
	r, err := relay.Start(bin, relay.Config{Listen: at, Keys: keys, Groups: []string{group}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(r.Close) }
	t.Cleanup(stop)
	return r, stop
}

// TestAloneRelayRoot runs the Rust service as the root of a group that meets
// at a blind relay: it starts the period and signs the servers' credentials
// of the relay's face (docs/protocol.md, section 18), with which both
// devices register there, and the laptop and it sync through the relay.
func TestAloneRelayRoot(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	cli := cbbCLI(t)
	dir := t.TempDir()
	root := startAlone(t, bin, dir, "-no-mdns")
	if out, err := runCLI(cli, root.socket, "", "new"); err != nil {
		t.Fatalf("cbb new: %v\n%s", err, out)
	}
	waitFor(t, "the Rust root in its group", func() bool {
		st, err := root.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && st.Status.Group != "" && st.Status.Role == "member"
	})
	// The laptop joins at the root's window (D-119: cbb pair -qr is gone).
	laptopDir := joinAloneAs(t, bin, root, "laptop", nil)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	laptop := startAlone(t, bin, laptopDir, "-no-mdns", "-port", strconv.Itoa(port), "-peer", root.addr())
	laptop.name = "laptop"
	root.stop()
	root = startAlone(t, bin, dir, "-no-mdns", "-peer", laptop.addr())
	laptopID, rootID := laptop.status(t).Device, root.status(t).Device
	waitFor(t, "the Rust root connected to the laptop", func() bool {
		p := root.status(t).Peers
		return len(p) == 1 && p[0].ID == laptopID
	})
	group := root.status(t).RelayGroup
	if out, err := runCLI(cli, root.socket, "", "status", "-relay"); err != nil || strings.TrimSpace(out) != group || strings.Count(group, ":") != 2 {
		t.Fatalf("cbb status -relay: %v\n%s, status %q", err, out, group)
	}
	r, keys := startRelay(t, group)
	if _, err := root.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin(), Consent: true}, ""); err != nil {
		t.Fatalf("cbb global relay on the root: %v", err)
	}
	for _, s := range []*testService{root, laptop} {
		if _, err := s.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
			t.Fatalf("cbb global on on the %s: %v", s.name, err)
		}
	}
	// The root's credentials: the period key and the servers' credentials
	// it signed with it.
	waitUpTo(t, 30*time.Second, "the Rust root signs the group's credentials", func() bool {
		_, err1 := os.Stat(filepath.Join(dir, "period-key"))
		_, err2 := os.Stat(filepath.Join(dir, "server-credentials.cbor"))
		return err1 == nil && err2 == nil
	})
	waitUpTo(t, 60*time.Second, "both meet at the relay with the credentials", func() bool {
		a, b := root.status(t).Away, laptop.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected && slices.Equal(a.Relay.Online, []string{laptopID}) &&
			b != nil && b.Relay != nil && b.Relay.Connected && slices.Equal(b.Relay.Online, []string{rootID})
	})

	// Without the laptop's address the relay is the root's only way.
	root.stop()
	root = startAlone(t, bin, dir, "-no-mdns")
	waitUpTo(t, 30*time.Second, "the Rust root reaches the laptop through the relay", func() bool {
		st := root.status(t)
		return st.Away != nil && st.Away.Relay != nil && st.Away.Relay.Connected &&
			slices.Equal(st.Away.Relay.Online, []string{laptopID}) && len(st.Peers) == 1 && st.Peers[0].ID == laptopID
	})
	if _, err := root.do(t, control.Header{Op: control.OpCopy}, "from the root"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the laptop has it", func() bool { return laptop.paste(t) == "from the root" })
}

// TestAloneRelayProject has the group's root choose the project's relay,
// whose address the signed entry points and whose key the signed keys.json
// give, then changes the relay's key: once a newer keys.json names the new
// key, the member registers again by itself, with no new settings. Then
// the relay moves, and entries.json says where to, as
// TestProjectRelayNewKey does.
func TestAloneRelayProject(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	signer := newReleaseSigner(t)
	var h hub
	pi := startEnv(t, &h, "pi", signer.rootsEnv(t))
	dir := joinAlone(t, bin, pi)
	pemFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(pemFile, signer.rootsPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	// The project relay's own name resolves to nothing, as offline (see
	// TestProjectRelayNewKey): with a network, the device would look the
	// relay up again when the test's relay drops it, and reach the live one.
	small := startAloneEnv(t, bin, dir, []string{"CBB_RELEASE_ROOTS=" + pemFile, "CBB_TEST_RESOLVE=relay.example.org=127.0.0.1,cbb.tools=none"}, "-no-mdns", "-no-listen", "-peer", pi.addr())
	group := pi.status(t).RelayGroup
	serve := func(keys relay.Keys, at string) (*relay.Process, func()) {
		return runRelay(t, keys, at, group)
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
	_, port, _ := net.SplitHostPort(at)
	// Both hold the same entry points: the root makes the relay's face
	// for each key listed, the member meets it where they say.
	entries := func(seq uint64, endpoint string, keys ...relay.Keys) {
		t.Helper()
		e := signer.signRelay(t, seq, []string{endpoint}, keys...)
		for _, s := range []*testService{pi, small} {
			if _, err := s.do(t, control.Header{Op: control.OpEntries}, e); err != nil {
				t.Fatalf("entries on the %s: %v", s.name, err)
			}
		}
	}
	entries(1, "relay.example.org:"+port, oldKeys)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "relay", RelayKey: projectRelay, Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := small.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	connected := func() bool {
		a := small.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected
	}
	waitUpTo(t, 60*time.Second, "the Rust member registers with the relay's listed key", connected)
	if a := small.status(t).Away; a.Relay.Endpoint != at {
		t.Errorf("the Rust member meets the project's relay at %q, not %q", a.Relay.Endpoint, at)
	}

	// The relay changes its key; the device refuses the new one until
	// keys.json names it, then takes it without being set again.
	stop()
	_, stop = serve(newKeys, at)
	waitUpTo(t, 60*time.Second, "the Rust member says the key is unknown", func() bool {
		a := small.status(t).Away
		return a != nil && a.Relay != nil && !a.Relay.Connected && a.Relay.Error != "" && a.Relay.Detail != ""
	})
	entries(2, "relay.example.org:"+port, oldKeys, newKeys)
	waitUpTo(t, 90*time.Second, "the Rust member registers with the new key", connected)
	if a := small.status(t).Away; a.Relay.Error != "" {
		t.Errorf("an error left in status: %q", a.Relay.Error)
	}

	// It moves to another port under a name of its own.
	stop()
	moved, stop := serve(newKeys, "127.0.0.1:0")
	defer stop()
	_, port, _ = net.SplitHostPort(moved.Addr().String())
	entries(3, "relay.example.org:"+port, newKeys)
	waitUpTo(t, 90*time.Second, "the Rust member registers where the relay moved", func() bool {
		a := small.status(t).Away
		return connected() && a.Relay.Endpoint == moved.Addr().String()
	})
}
