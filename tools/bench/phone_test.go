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
  <testsuite name="tools.cbb.GroupTest" tests="2" failures="1">
    <testcase name="a1_admitComputer" classname="tools.cbb.GroupTest" time="9.6">
      <failure>java.lang.RuntimeException: boom
	at somewhere</failure>
    </testcase>
    <testcase name="a2_sendToComputer" classname="tools.cbb.GroupTest" time="1.5" />
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

// TestPhoneUDPPorts reads the app's uid from pm and its UDP ports from
// /proc/net/udp and udp6: every address but the loopback, each port once,
// only the app's sockets.
func TestPhoneUDPPorts(t *testing.T) {
	pm := "package:tools.cbb.other uid:10200\npackage:tools.cbb uid:10190\n"
	if got := appUID(pm, "tools.cbb"); got != 10190 {
		t.Fatalf("appUID = %d, want 10190", got)
	}
	if got := appUID("", "tools.cbb"); got != -1 {
		t.Fatalf("appUID of nothing = %d, want -1", got)
	}
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000 10190        0 1 2 0000000000000000 0
  2: 0100007F:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000 10190        0 1 2 0000000000000000 0
  3: 0F02000A:C350 00000000:0000 07 00000000:00000000 00:00000000 00000000 10190        0 1 2 0000000000000000 0
  4: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1 2 0000000000000000 0
  5: 0F02000A:D431 0202000A:2234 01 00000000:00000000 00:00000000 00000000 10190        0 1 2 0000000000000000 0
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  6: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 10190        0 1 2 0000000000000000 0
  7: 00000000000000000000000001000000:2710 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 10190        0 1 2 0000000000000000 0
  8: 00000000000000000000000000000000:8CA1 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 10190        0 1 2 0000000000000000 0
`
	got := udpPorts(table, 10190)
	want := []int{0x14E9, 0xC350, 0x8CA1}
	if len(got) != len(want) {
		t.Fatalf("udpPorts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("udpPorts = %v, want %v", got, want)
		}
	}
}
