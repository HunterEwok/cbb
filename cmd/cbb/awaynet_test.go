// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// fakeUnit points the away drop-in at a temporary unit and records the
// systemctl calls.
func fakeUnit(t *testing.T, root bool) *[]string {
	t.Helper()
	dir := t.TempDir()
	unit := filepath.Join(dir, "clipboardbridge.service")
	if err := os.WriteFile(unit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	fakeLimit(t, &linuxLimit, root)
	oldUnit, oldDropIn, oldCtl := serviceUnit, awayDropIn, systemctl
	t.Cleanup(func() { serviceUnit, awayDropIn, systemctl = oldUnit, oldDropIn, oldCtl })
	serviceUnit, awayDropIn = unit, filepath.Join(dir, "clipboardbridge.service.d", "away.conf")
	systemctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	return &calls
}

// fakeLimit makes l this computer's limit, with or without privileges.
func fakeLimit(t *testing.T, l *netLimit, root bool) {
	t.Helper()
	oldLimit, oldElevated := limit, elevated
	t.Cleanup(func() { limit, elevated = oldLimit, oldElevated })
	limit, elevated = l, func() bool { return root }
}

var (
	hubAddr = netip.MustParseAddr("203.0.113.7")
	fwdAddr = netip.MustParseAddr("198.51.100.9")
)

func TestGrantFor(t *testing.T) {
	if g := grantFor(nil); g.on {
		t.Fatalf("off: %+v", g)
	}
	client := grantFor(&control.Away{HubDevice: "hub", Endpoints: []string{"203.0.113.7:8764"}, Allow: []string{"203.0.113.7", "198.51.100.9", "203.0.113.7"}})
	if want := (grant{on: true, addrs: []netip.Addr{fwdAddr, hubAddr}}); !client.equal(want) {
		t.Fatalf("client: %+v, want %+v", client, want)
	}
	hub := grantFor(&control.Away{Hub: true, Port: 9000, Endpoints: []string{"203.0.113.7:9000"}, Allow: []string{"198.51.100.9"}})
	if want := (grant{on: true, addrs: []netip.Addr{fwdAddr}, hubPort: 9000}); !hub.equal(want) {
		t.Fatalf("hub: %+v, want %+v", hub, want)
	}
	// A hub reached only through its forwarder answers nobody else.
	if g := grantFor(&control.Away{Hub: true, Port: 8764, Allow: []string{"198.51.100.9"}}); g.hubPort != 0 {
		t.Fatalf("hub behind a forwarder: %+v", g)
	}
}

func TestAwayNet(t *testing.T) {
	calls := fakeUnit(t, true)
	if err := checkAwayNet(); err != nil {
		t.Fatal(err)
	}
	client := grant{on: true, addrs: []netip.Addr{fwdAddr, hubAddr}}
	changed, restarted, err := setAwayNet(client)
	if err != nil || !changed || !restarted {
		t.Fatalf("on: changed %v, restarted %v, %v", changed, restarted, err)
	}
	data, err := os.ReadFile(awayDropIn)
	if err != nil || !strings.Contains(string(data), "\nIPAddressAllow=198.51.100.9 203.0.113.7\n") {
		t.Fatalf("drop-in %q, %v", data, err)
	}
	if want := []string{"daemon-reload", "restart clipboardbridge.service"}; !slices.Equal(*calls, want) {
		t.Fatalf("systemctl %q, want %q", *calls, want)
	}
	if g := linuxLimit.granted(); !g.equal(client) {
		t.Fatalf("read back %+v", g)
	}
	if changed, _, err := setAwayNet(client); err != nil || changed {
		t.Fatalf("on again: changed %v, %v", changed, err)
	}
	// Before the hub's offer: on, and nothing beyond the home network.
	if _, _, err := setAwayNet(grant{on: true}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(awayDropIn); strings.Contains(string(data), "IPAddressAllow") {
		t.Fatalf("drop-in without servers %q", data)
	}
	if g := linuxLimit.granted(); !g.equal(grant{on: true}) {
		t.Fatalf("read back %+v", g)
	}
	// A hub at its own address: systemd cannot allow one port only.
	hub := grant{on: true, addrs: []netip.Addr{fwdAddr}, hubPort: 9000}
	if _, _, err := setAwayNet(hub); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(awayDropIn); !strings.Contains(string(data), "\nIPAddressAllow=any\n") {
		t.Fatalf("hub drop-in %q", data)
	}
	if g := linuxLimit.granted(); g.hubPort != 9000 || !g.on {
		t.Fatalf("read back %+v", g)
	}
	if changed, _, err := setAwayNet(grant{}); err != nil || !changed {
		t.Fatalf("off: changed %v, %v", changed, err)
	}
	if _, err := os.Stat(awayDropIn); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the drop-in is still there: %v", err)
	}
	// A drop-in that is not this grant's is replaced.
	if err := os.WriteFile(awayDropIn, []byte("[Service]\nIPAddressAllow=any\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := setAwayNet(client); err != nil || !changed || !linuxLimit.granted().equal(client) {
		t.Fatalf("replacing it: changed %v, %v", changed, err)
	}
	if _, _, err := setAwayNet(grant{}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 12 {
		t.Fatalf("systemctl %q", *calls)
	}
}

func TestAwayNetNeedsRoot(t *testing.T) {
	calls := fakeUnit(t, false)
	if err := checkAwayNet(); !errors.Is(err, errNeedRoot) {
		t.Fatalf("without root: %v", err)
	}
	if changed, _, err := setAwayNet(grant{}); err != nil || changed {
		t.Fatalf("off without root, nothing to change: %v, %v", changed, err)
	}
	if _, _, err := setAwayNet(grant{on: true}); !errors.Is(err, errNeedRoot) {
		t.Fatalf("on without root: %v", err)
	}
	if _, err := os.Stat(awayDropIn); !errors.Is(err, os.ErrNotExist) || len(*calls) != 0 {
		t.Fatalf("something changed: %v, systemctl %q", err, *calls)
	}
}

func TestAwayNetNotConfined(t *testing.T) {
	calls := fakeUnit(t, false)
	serviceUnit = filepath.Join(t.TempDir(), "missing.service")
	if err := checkAwayNet(); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := setAwayNet(grant{on: true}); err != nil || changed || len(*calls) != 0 {
		t.Fatalf("changed %v, %v, systemctl %q", changed, err, *calls)
	}
	limit = nil // a system without a limit
	if confined() || checkAwayNet() != nil || !granted(grant{on: true}).on {
		t.Fatal("no limit, yet confined")
	}
}

func TestBlocked(t *testing.T) {
	if got := blocked(nil, false); len(got) != len(outside) || got[0] != "0.0.0.0-9.255.255.255" {
		t.Fatalf("home only: %q", got)
	}
	got := blocked([]netip.Addr{hubAddr, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("11.0.0.0")}, false)
	for _, want := range []string{"192.169.0.0-203.0.113.6", "203.0.113.8-223.255.255.255", "::2-2001:db8::", "2001:db8::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "11.0.0.1-126.255.255.255"} {
		if !slices.Contains(got, want) {
			t.Errorf("blocked lacks %s: %q", want, got)
		}
	}
	if len(got) != len(outside)+2 {
		t.Errorf("blocked: %q", got)
	}
	for _, r := range got {
		if strings.Contains(r, "203.0.113.7") && !strings.Contains(r, "-") {
			t.Errorf("the hub is still blocked: %q", got)
		}
	}
	// CBB_HOME_CGNAT=1: 100.64.0.0/10 is home, its neighbours are not.
	got = blocked([]netip.Addr{hubAddr}, true)
	for _, want := range []string{"11.0.0.0-100.63.255.255", "100.128.0.0-126.255.255.255"} {
		if !slices.Contains(got, want) {
			t.Errorf("with cgnat, blocked lacks %s: %q", want, got)
		}
	}
	if len(got) != len(outside)+2 {
		t.Errorf("with cgnat: %q", got)
	}
}

// On Windows the firewall rules are the limit, and the service's key keeps
// what they allow.
func TestAwayNetWindows(t *testing.T) {
	fakeLimit(t, &windowsLimit, false)
	oldPS := powershell
	t.Cleanup(func() { powershell = oldPS })
	rule, kept := "no", ""
	var scripts []string
	powershell = func(script string) (string, error) {
		switch {
		case strings.Contains(script, "New-NetFirewallRule"):
			scripts = append(scripts, script)
			kept = ""
			if i := strings.Index(script, "-Name AwayAllow -PropertyType String -Value '"); i >= 0 {
				v := script[i+len("-Name AwayAllow -PropertyType String -Value '"):]
				kept = v[:strings.Index(v, "'")]
			}
			return "", nil
		case rule == "error":
			return "", errors.New("access denied")
		case strings.Contains(script, "AwayAllow"):
			return kept, nil
		}
		return rule, nil
	}
	if confined() || checkAwayNet() != nil {
		t.Fatal("confined without the rule")
	}
	rule = "yes"
	if err := checkAwayNet(); !errors.Is(err, errNeedRoot) {
		t.Fatalf("without an administrator: %v", err)
	}
	rule = "error" // a lookup that fails asks for an administrator
	if err := checkAwayNet(); !errors.Is(err, errNeedRoot) {
		t.Fatalf("after a failed lookup: %v", err)
	}
	rule = "yes"
	elevated = func() bool { return true }
	client := grant{on: true, addrs: []netip.Addr{fwdAddr, hubAddr}}
	changed, restarted, err := setAwayNet(client)
	if err != nil || !changed || restarted || !windowsLimit.granted().equal(client) {
		t.Fatalf("on: changed %v, restarted %v, granted %+v, %v", changed, restarted, windowsLimit.granted(), err)
	}
	for _, line := range strings.Split(scripts[0], "\n") {
		if strings.Count(line, "'")%2 != 0 {
			t.Fatalf("an unmatched quote in PowerShell: %s", line)
		}
	}
	if s := scripts[0]; !strings.Contains(s, "'203.0.113.8-223.255.255.255'") || strings.Contains(s, "-Protocol") || strings.Contains(s, firewallRule+"-udp") {
		t.Fatalf("client script %s", s)
	}
	hub := grant{on: true, addrs: []netip.Addr{fwdAddr}, hubPort: 8764}
	if _, _, err := setAwayNet(hub); err != nil || !windowsLimit.granted().equal(hub) {
		t.Fatalf("hub: %+v, %v", windowsLimit.granted(), err)
	}
	if s := scripts[1]; !strings.Contains(s, "-Protocol TCP") || !strings.Contains(s, "-LocalPort @('1-8763', '8765-65535')") {
		t.Fatalf("hub script %s", s)
	}
	if changed, _, err := setAwayNet(grant{}); err != nil || !changed || windowsLimit.granted().on {
		t.Fatalf("off: changed %v, %v", changed, err)
	}
	if s := scripts[2]; !strings.Contains(s, "Remove-ItemProperty") || !strings.Contains(s, "'0.0.0.0-9.255.255.255'") {
		t.Fatalf("off script %s", s)
	}
	// CBB_HOME_CGNAT=1 in the service's environment: the rule leaves
	// 100.64.0.0/10 to it, AwayAllow says so, and a grant without it
	// differs, so cbb global allow writes the rule again.
	oldCGNAT := homeCGNAT
	t.Cleanup(func() { homeCGNAT = oldCGNAT })
	homeCGNAT = func() bool { return true }
	cg := grant{on: true, addrs: []netip.Addr{fwdAddr, hubAddr}, cgnat: true}
	if cg.equal(client) {
		t.Fatal("a grant with cgnat equals one without")
	}
	if _, _, err := setAwayNet(cg); err != nil || !windowsLimit.granted().equal(cg) || !strings.HasSuffix(kept, " cgnat") {
		t.Fatalf("cgnat: %+v %q, %v", windowsLimit.granted(), kept, err)
	}
	if s := scripts[3]; !strings.Contains(s, "'100.128.0.0-126.255.255.255'") || strings.Contains(s, "'11.0.0.0-126.255.255.255'") {
		t.Fatalf("cgnat script %s", s)
	}
	if _, _, err := setAwayNet(grant{}); err != nil || !strings.Contains(scripts[4], "'11.0.0.0-100.63.255.255'") {
		t.Fatalf("off with cgnat: %v %s", err, scripts[4])
	}
}

func TestResolveAddrPort(t *testing.T) {
	var out strings.Builder
	for in, want := range map[string]string{
		"203.0.113.9:8764":   "203.0.113.9:8764",
		"[2001:db8::1]:8764": "[2001:db8::1]:8764",
	} {
		got, err := resolveAddrPort(in, &out)
		if err != nil || got != want {
			t.Errorf("resolveAddrPort(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// A name; some systems know localhost only as ::1.
	if got, err := resolveAddrPort("localhost:8764", &out); err != nil || (got != "127.0.0.1:8764" && got != "[::1]:8764") {
		t.Errorf("resolveAddrPort(localhost:8764) = %q, %v", got, err)
	}
	for _, in := range []string{"cbb.tools", ":8764", "203.0.113.9"} {
		if got, err := resolveAddrPort(in, &out); err == nil {
			t.Errorf("resolveAddrPort(%q) = %q, want an error", in, got)
		}
	}
}
