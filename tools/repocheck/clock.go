// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"strings"
)

// clockReaders are the files of the Rust service that may read the system's
// wall clock themselves: the one clock (uptime.rs, which the tests move),
// the bench's clock, and reads that decide no rule (a scratch file's name, a
// trace line's time of day, the Next's link that sets the system clock, the
// relay server, tests). Every other file asks uptime::wall_ms(), so that a
// test that moves the clock moves it everywhere (docs/testing.md, "Time").
var clockReaders = map[string]bool{
	"member/src/uptime.rs":          true,
	"member/src/benchtime.rs":       true,
	"member/src/files.rs":           true,
	"member/src/discovery.rs":       true,
	"member/src/nextlink/link.rs":   true,
	"member/src/relayd/register.rs": true,
}

// checkClock reports a file of the Rust service that reads the wall clock
// past the service's one clock.
func checkClock(name string, data []byte) []string {
	if !strings.HasPrefix(name, "member/src/") || !strings.HasSuffix(name, ".rs") || clockReaders[name] ||
		strings.HasSuffix(name, "/tests.rs") || strings.HasSuffix(name, "_tests.rs") {
		return nil
	}
	var problems []string
	inTests := false
	for i, line := range strings.Split(string(data), "\n") {
		// A file's test module comes last: what follows it is the tests'.
		if strings.TrimSpace(line) == "#[cfg(test)]" {
			inTests = true
		}
		if !inTests && strings.Contains(line, "SystemTime::now(") {
			problems = append(problems, fmt.Sprintf("%s:%d: reads the wall clock itself; ask crate::uptime::wall_ms(), the clock the tests move", name, i+1))
		}
	}
	return problems
}
