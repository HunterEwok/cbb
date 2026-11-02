// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestPhoneResults reads the JUnit file as Gradle's connected tests write
// it, a <testsuite> inside <testsuites>, and the bare <testsuite> too.
func TestPhoneResults(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "connected", "debug", "flavors", "full")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	gradle := `<?xml version='1.0' encoding='UTF-8' ?>
<testsuites tests="2" failures="1">
  <testsuite name="io.github.hunterewok.clipboardbridge.GroupTest" tests="2" failures="1">
    <testcase name="a1_admitComputer" classname="io.github.hunterewok.clipboardbridge.GroupTest" time="9.6">
      <failure>java.lang.RuntimeException: boom
	at somewhere</failure>
    </testcase>
    <testcase name="a2_sendToComputer" classname="io.github.hunterewok.clipboardbridge.GroupTest" time="1.5" />
  </testsuite>
</testsuites>`
	bare := `<testsuite name="X"><testcase name="skipped" classname="a.b.Other"><skipped/></testcase></testsuite>`
	if err := os.WriteFile(filepath.Join(nested, "TEST-bench(AVD) - 15.xml"), []byte(gradle), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "TEST-old.xml"), []byte(bare), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewReport("phone", io.Discard, false)
	n, err := phoneResults(r, dir)
	if err != nil || n != 3 {
		t.Fatalf("phoneResults = %d, %v; want 3 cases", n, err)
	}
	got := map[string]Case{}
	for _, c := range r.cases {
		got[c.Name] = c
	}
	if c := got["phone/GroupTest/a1_admitComputer"]; c.Failure != "java.lang.RuntimeException: boom" {
		t.Errorf("a1 failure = %q", c.Failure)
	}
	if c, ok := got["phone/GroupTest/a2_sendToComputer"]; !ok || c.Failure != "" || c.Skipped != "" {
		t.Errorf("a2 = %+v, want passed", c)
	}
	if c := got["phone/Other/skipped"]; c.Skipped == "" {
		t.Errorf("skipped = %+v, want skipped", c)
	}
}
