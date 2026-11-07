// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
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
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/phone"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
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
	rust := startLite(t, bin, dir, "-no-mdns", "-full", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	waitFor(t, "the Rust member connected to both", func() bool {
		st, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 2 && st.Status.Role == "full"
	})
	port := freeUDP(t)
	hubAt := []string{fmt.Sprintf("127.0.0.1:%d", port)}
	if _, err := rust.do(t, control.Header{Op: control.OpAway, Name: "hub", Port: port, Addrs: hubAt, Consent: true}, ""); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Errorf("a hub that is no admin: %v", err)
	}
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "rust"); err != nil {
		t.Fatalf("cbb admin on the desk: %v\n%s", err, out)
	}
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
	rust = startLite(t, bin, dir, "-no-mdns", "-full", "-no-listen", "-peer", desk.addr())
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
	deskAddr := desk.addr()
	env := []string{"CBB_STANDBY_GRACE=2"}
	rust := startLiteEnv(t, bin, dir, env, "-no-mdns", "-full", "-no-listen", "-peer", deskAddr, "-peer", laptop.addr())
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "rust"); err != nil {
		t.Fatalf("cbb admin on the desk: %v\n%s", err, out)
	}
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
	back := &testService{name: desk.name, dir: desk.dir, os: desk.os}
	back.cfg = func(c *Config) {
		c.listen = func() (net.Listener, error) {
			ln, err := net.Listen("tcp", deskAddr)
			if err == nil {
				back.mu.Lock()
				back.memberAddr = ln.Addr().String()
				back.mu.Unlock()
			}
			return ln, err
		}
	}
	desk = startIn(t, &h, back)
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
	rust := startLite(t, bin, dir, "-no-mdns", "-full", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "rust"); err != nil {
		t.Fatalf("cbb admin on the desk: %v\n%s", err, out)
	}
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
	rust := startLite(t, bin, dir, "-no-mdns", "-full", "-no-listen", "-peer", desk.addr(), "-peer", laptop.addr())
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "rust"); err != nil {
		t.Fatalf("cbb admin on the desk: %v\n%s", err, out)
	}
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
	cli := goCLI(t)
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
		cmd := exec.Command(bin, "-state", dir, "pair", "-full", "-name", name, "-code", at)
		cmd.Stdin = strings.NewReader(code + "\n")
		cmd.Stderr = testWriter{t, name + " join: ", nil}
		if out, err := cmd.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
			t.Fatalf("cbb pair -full: %v; %s", err, out)
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
	rust := startLite(t, bin, rustDir, "-no-mdns", "-full", "-port", strings.TrimPrefix(rustAt, "127.0.0.1:"), "-peer", desk.addr())
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "rust"); err != nil {
		t.Fatalf("cbb admin on the desk: %v\n%s", err, out)
	}
	waitFor(t, "the Rust member an admin", func() bool { return rust.isAdmin(t) })
	boardDir := join(rust, rustAt, "board")
	board := startLite(t, bin, boardDir, "-no-mdns", "-full", "-no-listen", "-peer", desk.addr(), "-peer", rustAt)
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
// the admin Rust service is the hub with a forwarder and -vless, registers
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

	cli := goCLI(t)
	var h hub
	desk := startService(t, &h, "desk")
	c, code := openWindow(t, desk)
	rustDir := t.TempDir()
	join := exec.Command(bin, "-state", rustDir, "pair", "-full", "-name", "rust", "-code", desk.addr())
	join.Stdin = strings.NewReader(code + "\n")
	join.Stderr = testWriter{t, "rust join: ", nil}
	if out, err := join.Output(); err != nil || !strings.Contains(string(out), "Joined the group") {
		t.Fatalf("cbb pair -full: %v; %s", err, out)
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
	rust := startLite(t, bin, rustDir, "-no-mdns", "-full", "-port", strings.TrimPrefix(rustAt, "127.0.0.1:"), "-peer", desk.addr())
	if out, err := runCLI(cli, desk.socket, "", "admin", "-allow-file-key", "rust"); err != nil {
		t.Fatalf("cbb admin on the desk: %v\n%s", err, out)
	}
	req := control.Header{Op: control.OpAway, Name: "hub", Port: freeUDP(t), Forwarder: f.Addr().String(),
		ForwarderKey: forward.Pin(cert.Leaf), VLESS: true, Consent: true}
	waitFor(t, "the Rust member a hub", func() bool {
		_, err := rust.do(t, req, "")
		if err != nil && !strings.Contains(err.Error(), "admin") {
			t.Fatalf("cbb global hub -vless on the Rust member: %v", err)
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
