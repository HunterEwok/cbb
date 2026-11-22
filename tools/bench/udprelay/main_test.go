// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// A connection's frames reach the UDP port as datagrams, and the port's
// answers come back as frames.
func TestServe(t *testing.T) {
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	go func() {
		b := make([]byte, 100)
		for {
			n, from, err := u.ReadFrom(b)
			if err != nil {
				return
			}
			u.WriteTo(append([]byte("re:"), b[:n]...), from)
		}
	}()
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
			go serve(c, u.LocalAddr().String())
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	for _, m := range []string{"one", "two"} {
		if err := writeFrame(c, []byte(m)); err != nil {
			t.Fatal(err)
		}
		d, err := readFrame(r)
		if err != nil || string(d) != "re:"+m {
			t.Fatalf("answer to %s: %q, %v", m, d, err)
		}
	}
}
