// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package forward

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// lockedBuffer is a bytes.Buffer the forwarder's goroutines may write to.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// TestCommandRuns: cbb forward listens, deletes the group files of earlier
// versions, takes VLESS behind a web server, and stops on SIGINT.
func TestCommandRuns(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "forward.pem")
	groups := filepath.Join(dir, "groups")
	os.Mkdir(groups, 0o700)
	os.WriteFile(filepath.Join(groups, "0123456789abcdef.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(groups, "other"), []byte("kept"), 0o600)
	t.Setenv("CBB_DEBUG", "1")
	var stdout bytes.Buffer
	var stderr lockedBuffer
	code := make(chan int, 1)
	go func() {
		code <- Command([]string{"-key", key, "-listen", "127.0.0.1:0", "-state", filepath.Join(dir, "state.json"),
			"-vless-xhttp", "cbb.example", "-vless-listen", "127.0.0.1:0", "-vless-mirror", "127.0.0.1:443"}, &stdout, &stderr, "")
	}()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(stderr.String(), "reach the mirror") {
		select {
		case c := <-code:
			t.Fatalf("ended with %d: %s", c, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not start: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case c := <-code:
		if c != 0 {
			t.Errorf("ended with %d: %s", c, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("did not stop on SIGINT")
	}
	out := stderr.String()
	for _, want := range []string{"listening on UDP and TCP port", "deleted the 1 group files", "VLESS over XHTTP on", "cbb.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in %s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(groups, "other")); err != nil {
		t.Errorf("deleted a file that is not a group's: %v", err)
	}
}

// TestCommandRefuses: the flags that go together, and an address it
// cannot listen on.
func TestCommandRefuses(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "forward.pem")
	notDir := filepath.Join(dir, "file")
	os.WriteFile(notDir, nil, 0o600)
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-vless-xhttp", "x", "-vless-port", "0"}, 2, "not a TCP port"},
		{[]string{"-vless-xhttp", "x", "-vless-port", "70000"}, 2, "not a TCP port"},
		{[]string{"-vless-mirror", "127.0.0.1:443"}, 2, "goes with -vless-xhttp"},
		{[]string{"-vless-xhttp", "x", "-vless-path", "/p", "-vless-mirror", "nowhere"}, 2, "host:port"},
		{[]string{"-listen", "256.0.0.1:1"}, 1, "cbb:"},
		{[]string{"-refused", filepath.Join(notDir, "x")}, 1, "cbb:"},
		{[]string{"-nonsense"}, 2, "nonsense"},
	} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"-key", key, "-state", "none", "-records", filepath.Join(notDir, "groups"), "-listen", "127.0.0.1:0"}, c.args...)
		if code := Command(args, &stdout, &stderr, ""); code != c.code || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%v: %d, %q", c.args, code, stderr.String())
		}
	}
}

// TestListenRefuses: an address it cannot take, a port in use and a
// state file it cannot read stop it; both ways of picking a port give one
// for UDP and TCP.
func TestListenRefuses(t *testing.T) {
	dir := t.TempDir()
	cert, err := LoadCert(filepath.Join(dir, "forward.pem"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if st := f.Stats(); st != (Stats{}) {
		t.Errorf("a new forwarder holds %+v", st)
	}
	used := f.Addr().String()
	for _, addr := range []string{"nohost", "127.0.0.1:x", used} {
		if _, err := Listen(Config{Listen: addr, Cert: cert}); err == nil {
			t.Errorf("listened on %s", addr)
		}
	}
	os.Mkdir(filepath.Join(dir, "state"), 0o700)
	os.WriteFile(filepath.Join(dir, "state", "x"), nil, 0o600)
	if _, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert, StateFile: filepath.Join(dir, "state")}); err == nil {
		t.Error("took a folder for its state file")
	}
	udp, tcp, err := udpFirst("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if udp.LocalAddr().(*net.UDPAddr).Port != tcp.Addr().(*net.TCPAddr).Port {
		t.Errorf("UDP %v and TCP %v", udp.LocalAddr(), tcp.Addr())
	}
	udp.Close()
	tcp.Close()
	if _, _, err := udpFirst("256.0.0.1"); err == nil {
		t.Error("listened on no address")
	}
}
