// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestControlIdleConnection checks that the service closes a control
// connection that sends no request within its first 30 seconds, so idle
// connections do not hold the room of a user (member/src/service.rs).
func TestControlIdleConnection(t *testing.T) {
	var h hub
	pi := startService(t, &h, "pi")
	c, err := net.Dial("unix", pi.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(45 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read from an idle connection: %v, want it closed", err)
	}
}
