// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// A device that asks the relay to join it to an address, not to a device
// of its group, reaches nothing: the relay only joins two of a group's
// registered devices and never dials anywhere.
func TestRelayDialsNothing(t *testing.T) {
	var hits atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	g := newGroup(t)
	_, link := startRelay(t, g)
	cl, stop := rawTunnel(t, link, newDevice(t, g))
	defer stop()
	for _, to := range []string{ln.Addr().String(), "1.1.1.1:443", "example.com:443", "[::1]:22"} {
		conn, err := cl.Dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := writeLine(conn, request{Dial: to}, noteTimeout); err != nil {
			t.Fatal(err)
		}
		var n note
		if err := readLine(conn, &n, noteTimeout); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if n.OK || !strings.Contains(n.Error, "not on the relay") {
			t.Errorf("a dial to %s: %+v", to, n)
		}
	}
	if k := hits.Load(); k != 0 {
		t.Errorf("%d connections reached an address a device asked for", k)
	}
}
