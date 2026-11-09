// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testRelay is a relay a test checks from outside: this package's, or the
// Rust cbb-relay when CBB_TEST_RUST_RELAY names its binary. The tests that
// look inside a relay run against this package's only.
type testRelay interface {
	// Stats returns the groups and devices the relay holds now.
	Stats() (groups, devices int)
}

// goRelay returns r as this package's relay, or nil for the Rust one.
func goRelay(r testRelay) *Relay {
	g, _ := r.(*Relay)
	return g
}

// startAny runs the relay of cfg: the Rust cbb-relay when
// CBB_TEST_RUST_RELAY names its binary, this package's otherwise.
func startAny(t *testing.T, cfg Config) (testRelay, Link) {
	t.Helper()
	if bin := os.Getenv("CBB_TEST_RUST_RELAY"); bin != "" {
		return startRust(t, bin, cfg)
	}
	return startWith(t, cfg)
}

// rustRelay is cbb-relay running in a process of its own. It logs its
// counts every few milliseconds, and Stats waits for a line logged after
// it was called.
type rustRelay struct {
	t       *testing.T
	mu      sync.Mutex
	changed *sync.Cond
	lines   int // stats lines read so far
	groups  int
	devices int
	exited  bool
}

const rustStatsMS = 20

func (r *rustRelay) Stats() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// The second line after the call was counted wholly after it.
	want := r.lines + 2
	for r.lines < want && !r.exited {
		r.changed.Wait()
	}
	if r.exited {
		r.t.Error("cbb-relay exited")
	}
	return r.groups, r.devices
}

// startRust runs the binary bin as cfg says on a port of its own, with keys
// this package wrote, so that it reads a relay.pem cbb's Go relay made.
func startRust(t *testing.T, bin string, cfg Config) (testRelay, Link) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.pem")
	keys, err := LoadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-listen", "127.0.0.1:0", "-key", path}
	if cfg.Open {
		args = append(args, "-open")
	}
	if len(cfg.Groups) > 0 {
		args = append(args, "-group", strings.Join(cfg.Groups, ","))
	}
	limits, err := json.Marshal(map[string]any{
		"groups": cfg.Limits.Groups, "per_address": cfg.Limits.PerAddress, "per_network": cfg.Limits.PerNetwork,
		"per_wide": cfg.Limits.PerWide, "per_provider": cfg.Limits.PerProvider, "byte_rate": cfg.Limits.ByteRate,
		"group_record_bytes": cfg.Limits.GroupRecordBytes, "record_bytes": cfg.Limits.RecordBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "CBB_RELAY_LIMITS="+string(limits), "CBB_RELAY_STATS_MS="+strconv.Itoa(rustStatsMS), "CBB_DEBUG=")
	if cfg.Verbose {
		cmd.Env = append(cmd.Env, "CBB_DEBUG=1")
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	logf := cfg.Logf
	if logf == nil {
		logf = t.Logf
	}
	r := &rustRelay{t: t}
	r.changed = sync.NewCond(&r.mu)
	listening := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			var g, d int
			if n, _ := fmt.Sscanf(line, "cbb relay: %d groups, %d devices", &g, &d); n == 2 {
				r.mu.Lock()
				r.groups, r.devices = g, d
				r.lines++
				r.mu.Unlock()
				r.changed.Broadcast()
				continue
			}
			if strings.HasPrefix(line, "cbb relay: listening on") {
				select {
				case listening <- line:
				default:
				}
			}
			logf("%s", line)
		}
		r.mu.Lock()
		r.exited = true
		r.mu.Unlock()
		r.changed.Broadcast()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		_ = cmd.Wait()
	})
	var line string
	select {
	case line = <-listening:
	case <-done:
		t.Fatal("cbb-relay exited before it listened")
	case <-time.After(30 * time.Second):
		t.Fatal("cbb-relay does not listen")
	}
	var port uint16
	if _, err := fmt.Sscanf(line[strings.Index(line, "port "):], "port %d", &port); err != nil {
		t.Fatalf("no port in %q: %v", line, err)
	}
	pin := line[strings.LastIndex(line, " ")+1:]
	if pin != keys.Pin() {
		t.Fatalf("cbb-relay's key is %s, the file's %s", pin, keys.Pin())
	}
	return r, Link{Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Pin: pin}
}
