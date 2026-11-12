// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import "testing"

func TestCheckClock(t *testing.T) {
	read := []byte("fn f() {\n    let t = std::time::SystemTime::now();\n}\n")
	if got := checkClock("member/src/node.rs", read); len(got) != 1 {
		t.Errorf("a wall clock read past uptime: %q", got)
	}
	for _, name := range []string{"member/src/uptime.rs", "member/src/relayd/tests.rs", "core/src/x.rs", "member/src/a.go"} {
		if got := checkClock(name, read); len(got) != 0 {
			t.Errorf("%s: %q", name, got)
		}
	}
	inTest := []byte("fn f() {}\n\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = SystemTime::now(); }\n}\n")
	if got := checkClock("member/src/node.rs", inTest); len(got) != 0 {
		t.Errorf("a read in the tests: %q", got)
	}
}
