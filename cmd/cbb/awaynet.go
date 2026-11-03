// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// On Linux and Windows the installer lets the service reach only the home
// network from outside the program: on Linux its systemd unit
// (packaging/linux/clipboardbridge.service), on Windows an outbound rule of
// Windows Firewall (packaging/windows/install.ps1). Sync away from home
// reaches the group's own servers on the internet, its hub, forwarder and
// relay, so cbb global lets the service reach those addresses and nothing
// else, and cbb global off takes them away again. Both need root or an
// administrator. A hub reached at its own address answers its clients
// wherever they are: on Windows its UDP port is left open, and on Linux,
// whose unit cannot tell ports apart, the unit allows every address and the
// program's own limit holds. On a Mac, and everywhere as well, the service
// keeps its own connections to the same addresses (internal/netguard); a
// Network Extension of the Mac app will add the system's limit there.

// A grant is what the system lets the service reach beyond the home
// network.
type grant struct {
	on      bool         // sync away from home is on
	addrs   []netip.Addr // the group's hub, forwarder and relay
	hubPort int          // a hub reached at its own address: its UDP port; 0 otherwise
	// cgnat leaves 100.64.0.0/10 to the home network (CBB_HOME_CGNAT=1) in
	// the Windows rule; on Linux the installer's own drop-in does it.
	cgnat bool
}

// equal reports whether two grants allow the same; without sync away from
// home the installer's rule is all there is, so off equals off.
func (g grant) equal(o grant) bool {
	if !g.on || !o.on {
		return g.on == o.on
	}
	return g.hubPort == o.hubPort && g.cgnat == o.cgnat && slices.Equal(g.addrs, o.addrs)
}

// String lists what the grant allows, for the user.
func (g grant) String() string {
	if !g.on {
		return "the home network only"
	}
	var parts []string
	for _, a := range g.addrs {
		parts = append(parts, a.String())
	}
	if g.hubPort != 0 {
		parts = append(parts, fmt.Sprintf("any address on the hub's UDP port %d", g.hubPort))
	}
	if len(parts) == 0 {
		return "the home network only, as the group's servers are not known yet"
	}
	return "the home network and " + strings.Join(parts, ", ")
}

// grantFor is the grant that the service's state asks for.
func grantFor(a *control.Away) grant {
	if a == nil {
		return grant{}
	}
	g := grant{on: true, cgnat: homeCGNAT()}
	for _, s := range a.Allow {
		if ad, err := netip.ParseAddr(s); err == nil && !slices.Contains(g.addrs, ad.Unmap()) {
			g.addrs = append(g.addrs, ad.Unmap())
		}
	}
	slices.SortFunc(g.addrs, netip.Addr.Compare)
	if a.Hub && len(a.Endpoints) > 0 {
		g.hubPort = a.Port
	}
	return g
}

// A netLimit is one system's way of keeping the service on the home network
// and the group's servers.
type netLimit struct {
	present  func() bool         // the installer set the limit up
	granted  func() grant        // what it lets the service reach now
	set      func(g grant) error // lets the service reach g
	restarts bool                // changing it restarts the service
}

var (
	limit = map[string]*netLimit{"linux": &linuxLimit, "windows": &windowsLimit}[runtime.GOOS]
	// elevated reports whether this process may change the limit: root,
	// or an administrator's elevated process on Windows.
	elevated = isElevated
)

// errNeedRoot is what a user sees who changes sync away from home without
// root or an administrator on a computer whose service is confined to the
// home network.
var errNeedRoot = errors.New(needRootText)

// confined reports whether this computer's service is confined by its
// installer.
func confined() bool {
	return limit != nil && limit.present()
}

// granted returns what the system lets the service reach now; without a
// limit, whatever the service asks for.
func granted(want grant) grant {
	if !confined() {
		return want
	}
	return limit.granted()
}

// checkAwayNet fails before anything changes when this command will have
// to change the limit but may not.
func checkAwayNet() error {
	if !confined() || elevated() {
		return nil
	}
	return errNeedRoot
}

// setAwayNet lets the service reach g. It reports whether that changed and
// whether the service restarted for it; the caller waits for its socket
// with waitService.
func setAwayNet(g grant) (changed, restarted bool, err error) {
	if !confined() || limit.granted().equal(g) {
		return false, false, nil
	}
	if !elevated() {
		return false, false, errNeedRoot
	}
	return true, limit.restarts, limit.set(g)
}

// Linux: a systemd drop-in that adds the group's servers to the unit's
// IPAddressAllow, and a restart, since systemd applies it when the service
// starts.
var (
	serviceUnit = "/etc/systemd/system/clipboardbridge.service"
	awayDropIn  = "/etc/systemd/system/clipboardbridge.service.d/away.conf"
	systemctl   = func(args ...string) error { return runCmd("systemctl", args...) }
)

func awayDropInText(g grant) string {
	var b strings.Builder
	b.WriteString(`# Written by cbb global; cbb global off removes it, and cbb global allow
# writes it again when the group's servers change. With sync away from home
# on, the service may reach the group's hub, forwarder and relay beyond the
# home network, and nothing else.
`)
	if g.hubPort != 0 {
		fmt.Fprintf(&b, `# This device is a hub reached at its own address, which answers its
# clients wherever they are; systemd cannot allow one port only, so the
# service's own limit keeps every other connection to the addresses above.
# hub-port %d
`, g.hubPort)
	}
	b.WriteString("[Service]\n")
	switch {
	case g.hubPort != 0:
		b.WriteString("IPAddressAllow=any\n")
	case len(g.addrs) > 0:
		var as []string
		for _, a := range g.addrs {
			as = append(as, a.String())
		}
		b.WriteString("IPAddressAllow=" + strings.Join(as, " ") + "\n")
	}
	return b.String()
}

// parseDropIn reads a grant back from the drop-in.
func parseDropIn(text string) grant {
	g := grant{on: true}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "# hub-port "); ok {
			g.hubPort, _ = strconv.Atoi(v)
		}
		if v, ok := strings.CutPrefix(line, "IPAddressAllow="); ok {
			for _, f := range strings.Fields(v) {
				if a, err := netip.ParseAddr(f); err == nil {
					g.addrs = append(g.addrs, a)
				}
			}
		}
	}
	return g
}

var linuxLimit = netLimit{
	present: func() bool { return exists(serviceUnit) },
	granted: func() grant {
		data, err := os.ReadFile(awayDropIn)
		if err != nil {
			return grant{}
		}
		return parseDropIn(string(data))
	},
	restarts: true,
	set: func(g grant) error {
		if g.on {
			if err := os.MkdirAll(filepath.Dir(awayDropIn), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(awayDropIn, []byte(awayDropInText(g)), 0o644); err != nil {
				return err
			}
		} else if err := os.Remove(awayDropIn); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
		return systemctl("restart", "clipboardbridge.service")
	},
}

// Windows: an outbound rule of Windows Firewall blocks the service from
// every address outside the home network but the group's servers; for a
// hub reached at its own address it blocks TCP, and a second rule blocks
// UDP on every local port but the hub's. A change applies at once, so
// nothing restarts. What the rules allow is kept beside them in the
// service's registry key (AwayAllow), so a reinstall keeps it.
const (
	firewallRule = "clipboardbridge-home-only"
	serviceKey   = `HKLM:\SYSTEM\CurrentControlSet\Services\clipboardbridge`
)

var powershell = func(script string) (string, error) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// outside is every address outside the home network, as the installer's
// rule lists it: all but loopback, private IPv4, link-local, multicast and
// broadcast, and unique-local, link-local and multicast IPv6.
var outside = [][2]string{
	{"0.0.0.0", "9.255.255.255"}, {"11.0.0.0", "126.255.255.255"}, {"128.0.0.0", "169.253.255.255"},
	{"169.255.0.0", "172.15.255.255"}, {"172.32.0.0", "192.167.255.255"}, {"192.169.0.0", "223.255.255.255"},
	{"::2", "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}, {"fe00::", "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	{"fec0::", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
}

// blocked returns the ranges of outside without the addresses allowed, and
// with cgnat without 100.64.0.0/10.
func blocked(allowed []netip.Addr, cgnat bool) []string {
	type span struct{ lo, hi netip.Addr }
	var spans []span
	for _, r := range outside {
		spans = append(spans, span{netip.MustParseAddr(r[0]), netip.MustParseAddr(r[1])})
	}
	var holes []span
	for _, a := range allowed {
		holes = append(holes, span{a.Unmap(), a.Unmap()})
	}
	if cgnat {
		holes = append(holes, span{netip.MustParseAddr("100.64.0.0"), netip.MustParseAddr("100.127.255.255")})
	}
	for _, h := range holes {
		for i, s := range spans {
			if h.hi.Less(s.lo) || s.hi.Less(h.lo) {
				continue
			}
			var parts []span
			if s.lo.Less(h.lo) {
				parts = append(parts, span{s.lo, h.lo.Prev()})
			}
			if h.hi.Less(s.hi) {
				parts = append(parts, span{h.hi.Next(), s.hi})
			}
			spans = slices.Replace(spans, i, i+1, parts...)
			break
		}
	}
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		if s.lo == s.hi {
			out = append(out, s.lo.String())
		} else {
			out = append(out, s.lo.String()+"-"+s.hi.String())
		}
	}
	return out
}

// windowsScript writes the rules for g and keeps g in the service's key.
func windowsScript(g grant) string {
	quote := func(ss []string) string {
		q := make([]string, len(ss))
		for i, s := range ss {
			q[i] = "'" + s + "'"
		}
		return "@(" + strings.Join(q, ", ") + ")"
	}
	var allowed []string
	for _, a := range g.addrs {
		allowed = append(allowed, a.String())
	}
	block := quote(blocked(g.addrs, g.cgnat))
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	fmt.Fprintf(&b, "$prog = (Get-NetFirewallRule -Name '%s' | Get-NetFirewallApplicationFilter).Program\n", firewallRule)
	b.WriteString("Get-NetFirewallRule -Group 'clipboardbridge' | Where-Object { [string]$_.Direction -eq 'Outbound' } | Remove-NetFirewallRule\n")
	common := "-Group 'clipboardbridge' -Direction Outbound -Action Block -Program $prog -Service 'clipboardbridge' -Profile Any"
	// PowerShell doubles a quote inside single quotes.
	desc := "The CBB service reaches only the home network and its group''s servers; cbb global changes this rule."
	if g.hubPort == 0 {
		fmt.Fprintf(&b, "New-NetFirewallRule -Name '%s' -DisplayName 'clipboardbridge: only the home network' %s -RemoteAddress %s -Description '%s' | Out-Null\n",
			firewallRule, common, block, desc)
	} else {
		var ports []string
		if g.hubPort > 1 {
			ports = append(ports, fmt.Sprintf("1-%d", g.hubPort-1))
		}
		if g.hubPort < 65535 {
			ports = append(ports, fmt.Sprintf("%d-65535", g.hubPort+1))
		}
		fmt.Fprintf(&b, "New-NetFirewallRule -Name '%s' -DisplayName 'clipboardbridge: only the home network' %s -Protocol TCP -RemoteAddress %s -Description '%s' | Out-Null\n",
			firewallRule, common, block, desc)
		fmt.Fprintf(&b, "New-NetFirewallRule -Name '%s-udp' -DisplayName 'clipboardbridge: only the home network, UDP but the hub''s port' %s -Protocol UDP -LocalPort %s -RemoteAddress %s -Description '%s' | Out-Null\n",
			firewallRule, common, quote(ports), block, desc)
	}
	if g.on {
		v := strings.Join(append([]string{"on"}, allowed...), " ")
		if g.hubPort != 0 {
			v += fmt.Sprintf(" hub-port:%d", g.hubPort)
		}
		if g.cgnat {
			v += " cgnat"
		}
		fmt.Fprintf(&b, "New-ItemProperty -Path '%s' -Name AwayAllow -PropertyType String -Value '%s' -Force | Out-Null\n", serviceKey, v)
	} else {
		fmt.Fprintf(&b, "Remove-ItemProperty -Path '%s' -Name AwayAllow -ErrorAction SilentlyContinue\n", serviceKey)
	}
	return b.String()
}

// parseAwayAllow reads a grant back from the service's key.
func parseAwayAllow(v string) grant {
	f := strings.Fields(v)
	if len(f) == 0 || f[0] != "on" {
		return grant{}
	}
	g := grant{on: true}
	for _, s := range f[1:] {
		if p, ok := strings.CutPrefix(s, "hub-port:"); ok {
			g.hubPort, _ = strconv.Atoi(p)
		} else if s == "cgnat" {
			g.cgnat = true
		} else if a, err := netip.ParseAddr(s); err == nil {
			g.addrs = append(g.addrs, a)
		}
	}
	return g
}

var windowsLimit = netLimit{
	present: func() bool {
		out, err := powershell("if (Get-NetFirewallRule -Name '" + firewallRule + "' -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }")
		// A failed lookup counts as a limit, so that a change asks for an
		// administrator rather than doing nothing.
		return err != nil || out == "yes"
	},
	granted: func() grant {
		out, err := powershell("[string](Get-ItemProperty -Path '" + serviceKey + "' -Name AwayAllow -ErrorAction SilentlyContinue).AwayAllow")
		if err != nil {
			return grant{}
		}
		return parseAwayAllow(out)
	},
	set: func(g grant) error {
		// Off too, the rule leaves 100.64.0.0/10 to the home network
		// when the service counts it as home.
		g.cgnat = homeCGNAT()
		_, err := powershell(windowsScript(g))
		return err
	},
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// waitService waits until the restarted service answers on the socket
// that takes op.
func waitService(op string) (*control.Client, error) {
	var err error
	for deadline := time.Now().Add(15 * time.Second); ; {
		var c *control.Client
		if c, err = control.DialFor(op); err == nil {
			return c, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the service did not come back after its restart: %w", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
