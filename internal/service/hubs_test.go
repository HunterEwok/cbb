// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// slowClient plays a tunnel client on a slow way: the hub answers every
// `every` (never when it is zero), and the connection is set up after
// `after` (never when it is zero).
type slowClient struct {
	start        time.Time
	every, after time.Duration
}

func (c *slowClient) SetEndpoint(netip.AddrPort) error { return nil }

func (c *slowClient) Received() uint64 {
	if c.every == 0 {
		return 0
	}
	return uint64(time.Since(c.start) / c.every)
}

func (c *slowClient) Dial(ctx context.Context) (net.Conn, error) {
	var ready <-chan time.Time
	if c.after != 0 {
		ready = time.After(c.after - time.Since(c.start))
	}
	select {
	case <-ready:
		a, b := net.Pipe()
		b.Close()
		return a, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestDialAnyFollowsTheHub(t *testing.T) {
	w := 100 * time.Millisecond
	defer func(w time.Duration, n int) { dialWindow, dialWindows = w, n }(dialWindow, dialWindows)
	dialWindow, dialWindows = w, 6
	ep := netip.MustParseAddrPort("192.0.2.1:8764")

	// The hub answers all along and the connection takes three windows:
	// the try waits for it.
	slow := &slowClient{start: time.Now(), every: w / 4, after: 3 * w}
	conn, won, err := dialAny(context.Background(), []*slowClient{slow}, ep, w)
	if err != nil || won != slow {
		t.Fatalf("a hub that answers slowly: %v", err)
	}
	conn.Close()

	// A hub that never answers ends the try in one window.
	silent := &slowClient{start: time.Now()}
	if _, _, err := dialAny(context.Background(), []*slowClient{silent}, ep, w); err == nil {
		t.Fatal("a connection through a client the hub never answers")
	}
	if d := time.Since(silent.start); d < w || d > 2*w {
		t.Errorf("a hub that never answers held the try for %v, want one window of %v", d, w)
	}

	// The first window over VLESS is longer: the try waits it out.
	late := &slowClient{start: time.Now()}
	if _, _, err := dialAny(context.Background(), []*slowClient{late}, ep, 3*w); err == nil {
		t.Fatal("a connection through a client the hub never answers, with a long first window")
	}
	if d := time.Since(late.start); d < 3*w || d > 4*w {
		t.Errorf("a long first window held the try for %v, want %v", d, 3*w)
	}

	// One that answers but never lets the connection through ends it after
	// dialWindows windows.
	stuck := &slowClient{start: time.Now(), every: w / 4}
	if _, _, err := dialAny(context.Background(), []*slowClient{stuck}, ep, w); err == nil {
		t.Fatal("a connection that was never set up")
	}
	if d := time.Since(stuck.start); d < 6*w || d > 7*w {
		t.Errorf("a hub that answers but never connects held the try for %v, want %v", d, 6*w)
	}

	// The first connection wins and the other tries end.
	fast := &slowClient{start: time.Now(), every: w / 4, after: w / 2}
	other := &slowClient{start: time.Now(), every: w / 4}
	conn, won, err = dialAny(context.Background(), []*slowClient{other, fast}, ep, w)
	if err != nil || won != fast {
		t.Fatalf("two clients: won %p, want %p: %v", won, fast, err)
	}
	conn.Close()
	// Left alone the other try would end only after its six windows; ended
	// with the win, it takes no more than the scheduling of a few
	// goroutines, which on a loaded machine can be far from instant, so
	// the bound is the windows it must not wait out.
	if d := time.Since(fast.start); d >= 6*w {
		t.Errorf("the other try held dialAny for %v, its windows", d)
	}
}
