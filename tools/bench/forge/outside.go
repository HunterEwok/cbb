// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// outsideCase tells whether c is the stand-in for the internet (W44).
func outsideCase(c string) bool { return strings.HasPrefix(c, "outside-server:") }

// runOutside stands in for the internet and for whatever lies beyond the
// group's servers: on addr it answers each TCP stream and UDP packet, and
// writes a line for each to the file the case names, so that the bench
// counts what reached it (W44).
//
//	forge -addr :7000 outside-server:/tmp/hits
func runOutside(addr, c string) error {
	file := strings.TrimPrefix(c, "outside-server:")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	hit := func(kind string, from net.Addr) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(f, "%s from %s\n", kind, from)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		b := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			hit("udp", from)
			pc.WriteTo([]byte("the internet"), from)
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		hit("tcp", c.RemoteAddr())
		c.Write([]byte("the internet\n"))
		c.Close()
	}
}
