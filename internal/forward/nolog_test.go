// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HunterEwok/cbb/internal/tunnel"
)

// TestNoLogs checks that a forwarder logs no address while a hub registers
// and a client reaches it through the forwarder, and keeps no file but its
// state, which holds no address either.
func TestNoLogs(t *testing.T) {
	var (
		mu    sync.Mutex
		lines []string
	)
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	dir := t.TempDir()
	f, pin := startForwarderWith(t, Config{StateFile: filepath.Join(dir, "state.json"), Logf: logf})
	key, peer := newClient(t)
	hs := startHub(t, f, pin, []tunnel.Peer{peer}, nil)
	if err := roundTrip(t, f, hs, key, peer); err != nil {
		t.Fatal(err)
	}
	// Each line is checked through the forwarder's own logf, as an error
	// from the network would come.
	f.logf("cbb forward: a test error: write udp %v->%v: refused", f.Addr(), netip.AddrPortFrom(hs.addr, 51820))
	mu.Lock()
	for _, line := range lines {
		if strings.Contains(line, "127.0.0.1") || strings.Contains(line, hs.addr.String()) {
			t.Errorf("the log holds an address: %s", line)
		}
	}
	mu.Unlock()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if d.Name() != "state.json" {
			t.Errorf("the forwarder keeps %s", p)
		}
		b, err := os.ReadFile(p)
		if strings.Contains(string(b), "127.0.0.1") {
			t.Errorf("%s holds an address: %s", p, b)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
