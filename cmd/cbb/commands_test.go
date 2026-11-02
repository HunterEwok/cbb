// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// fakeService answers every request on a control socket with answer and
// records the requests.
func fakeService(t *testing.T, answers ...control.Message) chan *control.Message {
	t.Helper()
	return fakeHandler(t, func(_ *control.Message, _ *control.Reader, c net.Conn) {
		for _, a := range answers {
			a.Op = control.OpReply
			control.Write(c, &a)
		}
	})
}

// fakeHandler is fakeService with a handler that answers each request.
// Like the service, it listens on a control socket and an admin socket, and
// refuses an operation that changes the group on the control socket; each
// connection carries one request.
func fakeHandler(t *testing.T, handle func(m *control.Message, r *control.Reader, c net.Conn)) chan *control.Message {
	t.Helper()
	dir, err := os.MkdirTemp("", "cb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	t.Setenv("CBB_SOCKET", socket)
	t.Setenv("CBB_ADMIN_SOCKET", control.AdminSocketFor(socket))
	got := make(chan *control.Message, 8)
	for _, path := range []string{socket, control.AdminSocketFor(socket)} {
		admin := path != socket
		// On Windows the admin socket is in a directory of its own.
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				r := control.NewReader(c)
				m, err := r.Read()
				switch {
				case err != nil:
				case control.IsAdmin(m.Op) && !admin:
					answer(c, control.Message{Header: control.Header{Error: m.Op + " changes the group, so the service takes it only on its admin socket", Done: true}})
				default:
					got <- m
					handle(m, r, c)
				}
				c.Close()
			}
		}()
	}
	return got
}

// answer writes the answer a on c.
func answer(c net.Conn, a control.Message) {
	a.Op = control.OpReply
	control.Write(c, &a)
}

// inGroup answers a status request: in the group g, or in none when g is
// empty.
func inGroup(c net.Conn, g string) {
	answer(c, control.Message{Header: control.Header{Status: &control.Status{Role: "full", OS: "linux", Group: g}, Done: true}})
}

func request(t *testing.T, got chan *control.Message) *control.Message {
	t.Helper()
	select {
	case m := <-got:
		return m
	default:
		t.Fatal("the command sent no request")
		return nil
	}
}

func TestCopy(t *testing.T) {
	got := fakeService(t, control.Message{Header: control.Header{Done: true}})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"copy", "-secret"}, strings.NewReader("hunter2"), &stdout, &stderr); code != 0 {
		t.Fatalf("copy -secret: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Op != control.OpCopy || m.Kind != control.KindSecret || string(m.Payload) != "hunter2" {
		t.Errorf("copy -secret sent %+v %q", m.Header, m.Payload)
	}
	if code := run([]string{"copy"}, strings.NewReader("plain"), &stdout, &stderr); code != 0 {
		t.Fatalf("copy: %d", code)
	}
	if m := request(t, got); m.Kind != control.KindText {
		t.Errorf("copy sent kind %q", m.Kind)
	}
	stderr.Reset()
	// An argument is a file to send, never a text.
	if code := run([]string{"copy", "-secret", "hello"}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "not for files") {
		t.Errorf("copy -secret FILE: %d, %q", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"copy", "-type", "png"}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "go with FILE") {
		t.Errorf("copy -type without a file: %d, %q", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"copy", "no-such-file"}, strings.NewReader(""), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "no-such-file") {
		t.Errorf("copy of a missing file: %d, %q", code, stderr.String())
	}
}

func TestPairWithACode(t *testing.T) {
	got := fakeService(t, control.Message{Header: control.Header{Done: true}})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pair", "-code", "192.168.1.5:4000"}, strings.NewReader("123 456\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("pair -code: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Op != control.OpJoin || m.Code != "123456" || m.Address != "192.168.1.5:4000" {
		t.Errorf("pair -code sent %+v", m.Header)
	}
	// The code is never taken from the command line.
	for _, args := range [][]string{{"pair", "-code", "123456"}, {"pair", "-code", "123", "456"}, {"pair", "192.168.1.5:4000"},
		{"pair", "-phone", "-code"}, {"pair", "-invite", "x", "-code"}} {
		stderr.Reset()
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage") {
			t.Errorf("%v: %d, %q", args, code, stderr.String())
		}
	}
	// A bad code fails before the service is asked.
	stderr.Reset()
	if code := run([]string{"pair", "-code"}, strings.NewReader("12345\n"), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "six digits") {
		t.Errorf("pair -code with five digits: %d, %q", code, stderr.String())
	}
	select {
	case m := <-got:
		t.Errorf("a bad code reached the service: %+v", m.Header)
	default:
	}
}

func TestNew(t *testing.T) {
	got := fakeHandler(t, func(_ *control.Message, _ *control.Reader, c net.Conn) { inGroup(c, "g1") })
	var stdout, stderr bytes.Buffer
	if code := run([]string{"new"}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "group g1") {
		t.Fatalf("new: %d, %q, %q", code, stdout.String(), stderr.String())
	}
	if m := request(t, got); m.Op != control.OpNew {
		t.Errorf("new sent %+v", m.Header)
	}
	if code := run([]string{"new", "x"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Errorf("new with an argument: %d", code)
	}
}

// TestPairInAGroup checks that cbb pair in a group opens a window.
func TestPairInAGroup(t *testing.T) {
	got := fakeHandler(t, func(m *control.Message, _ *control.Reader, c net.Conn) {
		if m.Op == control.OpStatus {
			inGroup(c, "g1")
			return
		}
		answer(c, control.Message{Header: control.Header{Code: "123456", Expires: 300, Address: "192.168.1.5:8764"}})
		answer(c, control.Message{Header: control.Header{Name: "deck", Done: true}})
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pair"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("pair: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Op != control.OpStatus {
		t.Errorf("pair asked first %+v", m.Header)
	}
	if m := request(t, got); m.Op != control.OpPair {
		t.Errorf("pair sent %+v", m.Header)
	}
	if out := stdout.String(); !strings.Contains(out, "Pairing code: 123 456") || !strings.Contains(out, "cbb pair -code 192.168.1.5:8764") ||
		!strings.Contains(out, "deck joined") {
		t.Errorf("pair printed:\n%s", out)
	}
}

// TestPairTypedWhileWaiting checks that a code typed while cbb pair waits
// for the phone ends that wait and joins with the code.
func TestPairTypedWhileWaiting(t *testing.T) {
	got := fakeHandler(t, func(m *control.Message, r *control.Reader, c net.Conn) {
		switch {
		case m.Op == control.OpStatus:
			inGroup(c, "")
		case m.Listen:
			answer(c, control.Message{Header: control.Header{Addrs: []string{"192.168.1.20:40123"}, Fingerprint: "q83vEjRWeJA"}})
			r.Read() // the client gave up on the phone
			answer(c, control.Message{Header: control.Header{Error: "cancelled", Done: true}})
		default:
			answer(c, control.Message{Header: control.Header{Done: true}})
		}
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pair"}, strings.NewReader("12345\n654 321\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("pair: %d, %s", code, stderr.String())
	}
	request(t, got) // status
	if m := request(t, got); !m.Listen {
		t.Errorf("pair did not listen for the phone first: %+v", m.Header)
	}
	if m := request(t, got); m.Op != control.OpJoin || m.Listen || m.Code != "654321" {
		t.Errorf("pair joined with %+v", m.Header)
	}
	if !strings.Contains(stderr.String(), "six digits") || !strings.Contains(stdout.String(), "Joined the group") {
		t.Errorf("pair printed %q, %q", stdout.String(), stderr.String())
	}
}

func TestStatus(t *testing.T) {
	for _, tt := range []struct {
		st   control.Status
		want string
	}{
		{control.Status{Role: "full", OS: "linux"}, "Run cbb new here to start one"},
		{control.Status{Role: "full", OS: "macos"}, "Run cbb new here to start one"},
		{control.Status{Role: "full", OS: "windows", Device: "d1", Group: "g1", Holder: true}, "Device d1 (Windows, full), group g1"},
		{control.Status{Role: "full", OS: "macos", Device: "d2", Group: "g1", Removed: true}, "This device was removed from the group"},
		{control.Status{Role: "full", OS: "linux", Device: "d2", Group: "g1", Frozen: true}, "froze this computer's admin key"},
		{control.Status{Role: "full", OS: "linux", Device: "d3", Group: "g1", CertEndsMS: time.Now().Add(-time.Hour).UnixMilli()}, "This device's certificate ended on"},
		{control.Status{Role: "full", OS: "linux", Device: "d3", Group: "g1", CertEndsMS: time.Now().Add(certWarning / 2).UnixMilli()}, "no admin has renewed it"},
	} {
		st := tt.st
		fakeService(t, control.Message{Header: control.Header{Status: &st, Done: true}})
		var stdout, stderr bytes.Buffer
		if code := run([]string{"status"}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), tt.want) {
			t.Errorf("status of %+v: %d, %q", tt.st, code, stdout.String())
		}
	}
}

// brokenWriter fails every write, like a full disk.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

func TestPasteWriteError(t *testing.T) {
	fakeService(t, control.Message{Header: control.Header{Done: true}, Payload: []byte("text")})
	var stderr bytes.Buffer
	if code := run([]string{"paste"}, strings.NewReader(""), brokenWriter{}, &stderr); code != 1 || !strings.Contains(stderr.String(), "no space") {
		t.Errorf("paste to a full disk: %d, %q", code, stderr.String())
	}
}

func TestPairWithThePhone(t *testing.T) {
	// In no group pair asks the service to listen, shows a QR code with
	// its code, address and fingerprint, and waits for the member to dial.
	listen := func(addrs []string) chan *control.Message {
		return fakeHandler(t, func(m *control.Message, _ *control.Reader, c net.Conn) {
			if m.Op == control.OpStatus {
				inGroup(c, "")
				return
			}
			answer(c, control.Message{Header: control.Header{Addrs: addrs, Fingerprint: "q83vEjRWeJA"}})
			answer(c, control.Message{Header: control.Header{Done: true}})
		})
	}
	got := listen([]string{"192.168.1.20:40123"})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pair"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("pair: %d, %s", code, stderr.String())
	}
	request(t, got) // status
	m := request(t, got)
	if m.Op != control.OpJoin || len(m.Code) != 6 || m.Expires != 300 || m.Address != "" || !m.Listen {
		t.Errorf("pair sent %+v", m.Header)
	}
	if !strings.Contains(stdout.String(), "Connect a new device") || !strings.Contains(stdout.String(), "\x1b[") ||
		!strings.Contains(stdout.String(), "paste this into the app: clipboardbridge://") ||
		!strings.Contains(stdout.String(), "Joined the group") {
		t.Errorf("pair printed:\n%s", stdout.String())
	}
	// Without an address on the home network there is nothing to show.
	listen(nil)
	stdout.Reset()
	if code := run([]string{"pair"}, strings.NewReader(""), &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "no address") {
		t.Errorf("pair without an address: %d, %s", code, stderr.String())
	}
}

func TestWriteDevices(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	writeDevices(&b, []control.Device{
		{ID: "a1", Name: "pi", Role: "full", OS: "linux", Admin: true, Root: true, Online: true, Self: true, Listed: true, Version: "0.6.1"},
		{ID: "b2", Name: "mac", Role: "full", OS: "macos", LastSeenMS: now.Add(-5 * time.Minute).UnixMilli(), Listed: true, Version: "0.6.0"},
		{ID: "c3", Name: "deck", Role: "full", OS: "windows", Admin: true, Online: true, Mode: "send"},
	}, []control.Device{{ID: "c3", SkewMS: 9000}}, "0.6.1", now)
	out := b.String()
	for _, want := range []string{"pi (this device)", "online", "5 min ago", "deck *", "not in the devices list yet",
		"Linux", "macOS", "Windows", "root", "admin", "off by 9s", "MODE", "VERSION", "0.6.0 (old)", "below Clipboard Bridge 0.6.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "c3") && !strings.Contains(line, "send") {
			t.Errorf("deck's line lacks its mode: %q", line)
		}
		if strings.Contains(line, "a1") && strings.Contains(line, "(old)") {
			t.Errorf("the newest version is marked old: %q", line)
		}
	}
}

func TestWriteAway(t *testing.T) {
	a := &control.Away{HubDevice: "abc", Endpoints: []string{"203.0.113.7:8764"}, KeysInFile: true,
		Error: "the hub did not answer at 203.0.113.7:8764", Detail: "i/o timeout"}
	for _, tc := range []struct {
		debug  string
		detail bool
	}{{"1", true}, {"0", false}} {
		t.Setenv("CBB_DEBUG", tc.debug)
		var b strings.Builder
		writeAway(&b, a)
		out := b.String()
		// The status does not repeat where the keys are: cbb global on says it once.
		if !strings.Contains(out, "Problem: the hub did not answer") || strings.Contains(out, "keys in files") {
			t.Errorf("CBB_DEBUG=%s: %q", tc.debug, out)
		}
		if got := strings.Contains(out, "i/o timeout"); got != tc.detail {
			t.Errorf("CBB_DEBUG=%s: detail shown %v, want %v: %q", tc.debug, got, tc.detail, out)
		}
	}
	var b strings.Builder
	writeAway(&b, nil)
	if !strings.Contains(b.String(), "off") {
		t.Errorf("off: %q", b.String())
	}
	// A hub that stands by for one above it says so, not that it is the
	// hub with a forwarder that its hub does not run for.
	b.Reset()
	writeAway(&b, &control.Away{Hub: true, Standby: true, HubDevice: "deck", Port: 8764,
		Forwarder: &control.Forwarder{Endpoint: "198.51.100.9:8764", Error: "the hub is not running"}})
	if out := b.String(); !strings.Contains(out, "stands by as its client") || strings.Contains(out, "this device is the hub") || strings.Contains(out, "not running") {
		t.Errorf("standby: %q", out)
	}
}

func TestTakeover(t *testing.T) {
	fakeService(t, control.Message{Header: control.Header{Name: "pi", Done: true}})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"takeover", "pi"}, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "Claimed the group from pi") {
		t.Errorf("takeover: %d, %q, %q", code, stdout.String(), stderr.String())
	}
	if code := run([]string{"takeover"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Errorf("takeover without a device: %d", code)
	}
}

func TestTerminalText(t *testing.T) {
	for _, c := range []struct {
		in, want string
		all      bool
		dropped  int
	}{
		{in: "ls -l\n", want: "ls -l"},
		{in: "a\tb", want: "a\tb"},
		{in: "echo \x1b[201~; rm -rf ~\n", want: "echo [201~; rm -rf ~"},
		{in: "x\u009b31my\x7f\x00", want: "x31my"},
		{in: "one\r\ntwo\nthree\n", want: "one", dropped: 2},
		{in: "one\r\ntwo\nthree\n", want: "one\ntwo\nthree", all: true},
		{in: "\n\nfirst\n", want: "first"},
		{in: "bad \xff byte", want: "bad  byte"},
		{in: "line\rover", want: "lineover"},
	} {
		got, dropped := terminalText(c.in, c.all)
		if got != c.want || dropped != c.dropped {
			t.Errorf("terminalText(%q, %v) = %q, %d; want %q, %d", c.in, c.all, got, dropped, c.want, c.dropped)
		}
	}
}

func TestPasteTerminal(t *testing.T) {
	secret := control.Message{Header: control.Header{Kind: control.KindSecret, Done: true}, Payload: []byte("hunter2\n")}
	fakeService(t, secret)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"paste", "-terminal"}, strings.NewReader(""), &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Errorf("a secret without -secret: %d, %q, %q", code, stdout.String(), stderr.String())
	}
	fakeService(t, secret)
	stdout.Reset()
	if code := run([]string{"paste", "-terminal", "-secret"}, strings.NewReader(""), &stdout, &stderr); code != 0 || stdout.String() != "hunter2" {
		t.Errorf("a secret with -secret: %d, %q", code, stdout.String())
	}
	fakeService(t, control.Message{Header: control.Header{Done: true}, Payload: []byte("cd /tmp\nrm -rf *\n")})
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"paste", "-terminal"}, strings.NewReader(""), &stdout, &stderr); code != 0 || stdout.String() != "cd /tmp" || !strings.Contains(stderr.String(), "1 more") {
		t.Errorf("two lines: %d, %q, %q", code, stdout.String(), stderr.String())
	}
	if code := run([]string{"paste", "-lines"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Errorf("-lines without -terminal: %d", code)
	}
}

func TestFailDetails(t *testing.T) {
	err := &control.DialError{Msg: "the Clipboard Bridge service is not running; start it", Err: errors.New("dial unix /run/x: connect: no such file or directory")}
	for _, c := range []struct {
		debug  string
		detail bool
	}{{"0", false}, {"1", true}} {
		t.Setenv("CBB_DEBUG", c.debug)
		var b strings.Builder
		if fail(&b, err) != 1 {
			t.Fatal("fail did not return 1")
		}
		out := b.String()
		if strings.Contains(out, "dial unix") != c.detail || strings.Contains(out, "Detail:") != c.detail {
			t.Errorf("CBB_DEBUG=%s: %q", c.debug, out)
		}
	}
}

func TestCertLine(t *testing.T) {
	now := time.Now()
	if l := certLine(now.Add(365*24*time.Hour).UnixMilli(), now); l != "" {
		t.Errorf("a certificate with a year left: %q", l)
	}
	if l := certLine(0, now); l != "" {
		t.Errorf("no certificate: %q", l)
	}
}

func TestPasteReceiveFlags(t *testing.T) {
	got := fakeService(t, control.Message{Header: control.Header{Done: true, Status: &control.Status{Paste: &control.Paste{On: true}}}})
	var stdout, stderr bytes.Buffer
	// The usage's order, on before its flags, and the flags first.
	for _, args := range [][]string{{"on", "-console", "-enter"}, {"-console", "-enter", "on"}} {
		if code := run(append([]string{"paste-receive"}, args...), strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("paste-receive %v: %d, %s", args, code, stderr.String())
		}
		if m := request(t, got); m.Op != control.OpReceive || m.Name != "on" || !m.Console || !m.Enter {
			t.Errorf("paste-receive %v sent %+v", args, m.Header)
		}
	}
	if code := run([]string{"paste-receive", "off", "-on", "deck"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("paste-receive off -on deck: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Name != "off" || m.Device != "deck" {
		t.Errorf("paste-receive off -on deck sent %+v", m.Header)
	}
	for _, args := range [][]string{{"on", "off"}, {"-console"}, {"on", "-console", "x"}} {
		stderr.Reset()
		if code := run(append([]string{"paste-receive"}, args...), strings.NewReader(""), &stdout, &stderr); code != 2 {
			t.Errorf("paste-receive %v: %d, want the usage", args, code)
		}
	}
}
