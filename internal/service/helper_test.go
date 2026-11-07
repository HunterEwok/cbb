// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestLiteHelper: the Rust member starts cbb-helper as its child, which
// says hello over its inherited pipes, and the helper ends with the member
// (docs/design.md, "The service and its helper"). CBB_LITE names the Rust
// member's binary.
func TestLiteHelper(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	helper := filepath.Join(t.TempDir(), "cbb-helper")
	if out, err := exec.Command("go", "build", "-o", helper, "github.com/HunterEwok/cbb/cmd/cbb-helper").CombinedOutput(); err != nil {
		t.Fatalf("go build cbb-helper: %v\n%s", err, out)
	}
	s := startLiteEnv(t, bin, t.TempDir(), []string{"CBB_HELPER=" + helper})
	deadline := time.Now().Add(20 * time.Second)
	for !s.logged("cbb-helper runs: cbb ") {
		if time.Now().After(deadline) {
			t.Fatal("the Rust member never said that cbb-helper runs")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !running(helper) {
		t.Fatal("cbb-helper does not run beside the Rust member")
	}
	s.stop()
	deadline = time.Now().Add(10 * time.Second)
	for running(helper) {
		if time.Now().After(deadline) {
			t.Fatal("cbb-helper kept running after the Rust member stopped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// running says whether a process runs the program at path.
func running(path string) bool {
	procs, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, p := range procs {
		if exe, err := os.Readlink(p); err == nil && exe == path {
			return true
		}
	}
	return false
}
