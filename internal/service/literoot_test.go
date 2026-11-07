// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/phone"
)

// goCLI builds the Go command line for the tests that run it against the
// Rust service.
func goCLI(t *testing.T) string {
	t.Helper()
	cli := filepath.Join(t.TempDir(), "cbb")
	if out, err := exec.Command("go", "build", "-o", cli, "github.com/HunterEwok/cbb/cmd/cbb").CombinedOutput(); err != nil {
		t.Fatalf("go build cbb: %v\n%s", err, out)
	}
	return cli
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
	cli := goCLI(t)
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
		return err == nil && st.Status != nil && st.Status.Group != "" && st.Status.Role == "full"
	})

	// A Go computer shows its QR code and waits; the Rust root admits it.
	var h hub
	laptop := startService(t, &h, "laptop")
	jc := laptop.dial(t)
	defer jc.Close()
	code := pair.NewCode()
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
		if _, err := mode.do(t, control.Header{Op: control.OpMode, Name: "shared"}, ""); err != nil {
			t.Fatal(err)
		}
	}
	must("from the root", "copy")
	waitFor(t, "the laptop has the root's text", func() bool { return laptop.paste(t) == "from the root" })

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
	// The group's settings, a mute and a handover.
	must("", "incoming", "2m")
	waitFor(t, "the laptop takes the incoming time", func() bool { return laptop.status(t).IncomingMS == 120000 })
	if out := must("", "takeover", "-delay", "0s"); !strings.Contains(out, "now waits 0s") {
		t.Errorf("cbb takeover -delay:\n%s", out)
	}
	if out, err := cbb("", "takeover", "-delay", "200h"); err == nil || !strings.Contains(out, "from 0s to 168h") {
		t.Errorf("a takeover delay too long: %v\n%s", err, out)
	}
	must("", "mute", "-on", "desk")
	waitFor(t, "the laptop muted", func() bool { return laptop.status(t).Muted })
	must("", "unmute", "-on", "desk")
	waitFor(t, "the laptop unmuted", func() bool { return !laptop.status(t).Muted })
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
	cli := goCLI(t)
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

// isAdmin reports whether the service holds an admin CA by its status.
func (s *testService) isAdmin(t *testing.T) bool {
	t.Helper()
	m, err := s.do(t, control.Header{Op: control.OpDevices}, "")
	if err != nil {
		return false
	}
	for _, d := range m.Devices {
		if d.Self {
			return d.Admin
		}
	}
	return false
}

// TestLiteTakeover: the Rust service joins a Go computer's group as a
// full member (cbb pair -full), offers an admin key, and the Go root makes
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
	cli := goCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	laptop := startService(t, &h, "laptop")
	pairWith(t, desk, laptop)

	c, code := openWindow(t, desk)
	dir := t.TempDir()
	join := exec.Command(bin, "-state", dir, "pair", "-full", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair -full: %v; %s", err, out)
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
	rust := startLite(t, bin, dir, "-no-mdns", "-full", "-port", strconv.Itoa(port), "-peer", desk.addr(), "-peer", laptop.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2 && st.Status.Role == "full"
	})

	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "rust"); err != nil {
		t.Fatalf("cbb admin on the desk: %v\n%s", err, out)
	}
	waitFor(t, "the Rust member an admin", func() bool { return rust.isAdmin(t) })
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
	cli := goCLI(t)
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
		k := sheet.Key.D.FillBytes(make([]byte, 32))
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
