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

// TestPhoneAddrs reads the phone's IPv4 addresses from ip -4 -o addr:
// wlan0's on a recent emulator image, eth0's on an older one, never the
// loopback's, each once.
func TestPhoneAddrs(t *testing.T) {
	out := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
3: wlan0    inet 10.0.2.16/24 brd 10.0.2.255 scope global wlan0\       valid_lft forever preferred_lft forever
4: eth0    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\       valid_lft forever preferred_lft forever
5: eth1    inet 10.0.2.15/24 scope global eth1
`
	got := ipv4Addrs(out)
	if len(got) != 2 || got[0] != "10.0.2.16" || got[1] != "10.0.2.15" {
		t.Fatalf("ipv4Addrs = %v, want [10.0.2.16 10.0.2.15]", got)
	}
	if got := ipv4Addrs("1: lo    inet 127.0.0.1/8 scope host lo\n"); len(got) != 0 {
		t.Fatalf("ipv4Addrs of the loopback alone = %v", got)
	}
}

func TestSlirpDev(t *testing.T) {
	wifi := `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
3: wlan0    inet 10.0.2.16/24 brd 10.0.2.255 scope global wlan0\       valid_lft forever preferred_lft forever
`
	if dev, addr := slirpDev(wifi); dev != "wlan0" || addr != "10.0.2.16" {
		t.Fatalf("slirpDev of Wi-Fi alone = %q %q, want wlan0 10.0.2.16", dev, addr)
	}
	both := wifi + "3: wlan0    inet 10.0.2.15/32 scope global wlan0\n"
	if dev, addr := slirpDev(both); dev != "wlan0" || addr != slirpAddr {
		t.Fatalf("slirpDev once the address is there = %q %q, want wlan0 %s", dev, addr, slirpAddr)
	}
	if dev, _ := slirpDev("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.168.1.5/24 scope global eth0\n"); dev != "" {
		t.Fatalf("slirpDev off the emulator's network = %q, want none", dev)
	}
}
