// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config says how Start runs cbb-relay.
type Config struct {
	Listen string // the address of its port, the same for UDP and TCP; 127.0.0.1:0 when empty
	Keys   Keys   // its keys; new ones when zero

	// Groups are the tags of the groups the relay serves (-group). Open
	// serves any group that registers in their place (-open), within
	// Limits.
	Groups []string
	Open   bool
	Limits Limits

	Logf    func(format string, args ...any) // its log lines; none when nil
	Verbose bool                             // CBB_DEBUG=1
}

// Limits are an open relay's limits, which Start hands cbb-relay in
// CBB_RELAY_LIMITS; a zero field keeps the relay's default
// (member/src/relayd/limits.rs).
type Limits struct {
	Groups           int     `json:"groups"`
	PerAddress       int     `json:"per_address"`
	PerNetwork       int     `json:"per_network"`
	PerWide          int     `json:"per_wide"`
	PerProvider      int     `json:"per_provider"`
	ByteRate         float64 `json:"byte_rate"`
	GroupRecordBytes int     `json:"group_record_bytes"`
	RecordBytes      int     `json:"record_bytes"`
}

// StatsInterval is how often a relay that Start runs logs its counts.
const StatsInterval = 20 * time.Millisecond

// Binary returns the cbb-relay the tests run: CBB_TEST_RUST_RELAY, or the
// one beside the cbb of CBB_TEST_ALONE or CBB_TEST_RUST_SERVICE, or "" when
// there is none.
func Binary() string {
	if bin := os.Getenv("CBB_TEST_RUST_RELAY"); bin != "" {
		return bin
	}
	name := "cbb-relay"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, env := range []string{"CBB_TEST_ALONE", "CBB_TEST_RUST_SERVICE"} {
		if cbb := os.Getenv(env); cbb != "" {
			bin := filepath.Join(filepath.Dir(cbb), name)
			if _, err := os.Stat(bin); err == nil {
				return bin
			}
		}
	}
	return ""
}

// Process is cbb-relay running in a process of its own.
type Process struct {
	Keys Keys
	Link Link // its address on 127.0.0.1 and its pin

	cmd     *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	changed *sync.Cond
	lines   int // counts read so far
	groups  int
	devices int
	exited  bool
}

// Start runs the binary bin (cbb-relay) as cfg says, and returns once it
// listens. Close stops it.
func Start(bin string, cfg Config) (*Process, error) {
	if cfg.Keys.Cert.Leaf == nil {
		k, err := NewKeys()
		if err != nil {
			return nil, err
		}
		cfg.Keys = k
	}
	dir, err := os.MkdirTemp("", "cbb-relay-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir) // the relay reads its keys before it listens
	key := filepath.Join(dir, "relay.pem")
	if err := cfg.Keys.Write(key); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	args := []string{"-listen", cfg.Listen, "-key", key}
	if cfg.Open {
		args = append(args, "-open")
	}
	if len(cfg.Groups) > 0 {
		args = append(args, "-group", strings.Join(cfg.Groups, ","))
	}
	limits, err := json.Marshal(cfg.Limits)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	debug := ""
	if cfg.Verbose {
		debug = "1"
	}
	cmd.Env = append(os.Environ(), "CBB_RELAY_LIMITS="+string(limits),
		"CBB_RELAY_STATS_MS="+strconv.Itoa(int(StatsInterval/time.Millisecond)), "CBB_DEBUG="+debug)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	p := &Process{Keys: cfg.Keys, cmd: cmd, done: make(chan struct{})}
	p.changed = sync.NewCond(&p.mu)
	listening := make(chan string, 1)
	var refused []string
	go func() {
		defer close(p.done)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			var g, d int
			if n, _ := fmt.Sscanf(line, "cbb relay: %d groups, %d devices", &g, &d); n == 2 {
				p.mu.Lock()
				p.groups, p.devices = g, d
				p.lines++
				p.mu.Unlock()
				p.changed.Broadcast()
				continue
			}
			if strings.HasPrefix(line, "cbb relay: listening on") {
				select {
				case listening <- line:
				default:
				}
			} else if len(refused) < 8 {
				refused = append(refused, line)
			}
			logf("%s", line)
		}
		p.mu.Lock()
		p.exited = true
		p.mu.Unlock()
		p.changed.Broadcast()
	}()
	var line string
	select {
	case line = <-listening:
	case <-p.done:
		_ = cmd.Wait()
		return nil, fmt.Errorf("cbb-relay exited before it listened: %s", strings.Join(refused, "; "))
	case <-time.After(30 * time.Second):
		p.Close()
		return nil, errors.New("cbb-relay does not listen")
	}
	var port uint16
	i := strings.Index(line, "port ")
	if i < 0 {
		p.Close()
		return nil, fmt.Errorf("no port in %q", line)
	}
	if _, err := fmt.Sscanf(line[i:], "port %d", &port); err != nil {
		p.Close()
		return nil, fmt.Errorf("no port in %q: %v", line, err)
	}
	if pin := line[strings.LastIndex(line, " ")+1:]; pin != cfg.Keys.Pin() {
		p.Close()
		return nil, fmt.Errorf("cbb-relay's key is %s, the file's %s", pin, cfg.Keys.Pin())
	}
	p.Link = Link{Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Pin: cfg.Keys.Pin()}
	return p, nil
}

// Addr returns the relay's address, host and port.
func (p *Process) Addr() net.Addr { return net.TCPAddrFromAddrPort(p.Link.Endpoint) }

// Stats returns the groups and devices the relay holds now: the counts it
// logs wholly after the call. They are zero once it exited (Exited).
func (p *Process) Stats() (groups, devices int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// The second line after the call was counted wholly after it.
	want := p.lines + 2
	for p.lines < want && !p.exited {
		p.changed.Wait()
	}
	if p.exited {
		return 0, 0
	}
	return p.groups, p.devices
}

// Exited tells whether the relay's process ended.
func (p *Process) Exited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exited
}

// Close stops the relay and waits for it.
func (p *Process) Close() {
	// SIGTERM first, which cbb-relay takes as an exit, so that a build with
	// instrument-coverage writes what it ran; a kill if it does not end, or
	// where there is no SIGTERM (Windows).
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	_ = p.cmd.Wait()
}
