// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import "testing"

// running is cbb-relay as a test runs it.
type running struct {
	*Process
	t *testing.T
}

// Stats returns the groups and devices the relay holds now, and fails the
// test once the relay exited.
func (r running) Stats() (groups, devices int) {
	groups, devices = r.Process.Stats()
	if r.Exited() {
		r.t.Error("cbb-relay exited")
	}
	return groups, devices
}

// startWith runs cbb-relay (Binary) as cfg says until the test ends; the
// test skips without one.
func startWith(t *testing.T, cfg Config) (running, Link) {
	t.Helper()
	bin := Binary()
	if bin == "" {
		t.Skip("no cbb-relay: CBB_TEST_RUST_RELAY is not set")
	}
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	p, err := Start(bin, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return running{p, t}, p.Link
}
