// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// The writes a member makes (Y15): forge [-socket PATH] watch:SECONDS
// watches the service's clipboard as a desktop connector does, for SECONDS,
// and prints a line "write TEXT" for each text the service has it write.

func watchCase(arg string) bool { return strings.HasPrefix(arg, "watch:") }

func runWatch(path, arg string) error {
	secs, err := strconv.Atoi(strings.TrimPrefix(arg, "watch:"))
	if err != nil {
		return fmt.Errorf("watch:SECONDS, not %q", arg)
	}
	if path == "" {
		path = control.SocketPath()
	}
	c, err := control.Dial(path)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpWatch}}); err != nil {
		return err
	}
	fmt.Println("watch: watching")
	c.SetDeadline(time.Now().Add(time.Duration(secs) * time.Second))
	for {
		m, err := c.Receive()
		if err != nil {
			return nil // the time is up
		}
		if m.Op == control.OpWrite {
			fmt.Printf("write %s\n", m.Payload)
		}
	}
}
