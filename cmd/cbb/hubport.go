// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/openwrt"
	"github.com/HunterEwok/clipboardbridge/internal/steamos"
)

// A hub reached at its own address takes its clients on a UDP port from the
// internet, which a firewall at home drops. The installers open only the
// ports the home network needs, so cbb global hub lists that one rule and
// asks before it opens it, as the installers ask for theirs: it faces the
// internet, so it is asked for on its own. The port stays open while this
// device is a hub reached at its own address, and cbb closes it when that
// ends (another port, a forwarder, cbb global off). The rule cbb opened is
// remembered by the system's way (Linux: /etc/clipboardbridge/firewall.hub
// through firewall.sh; Windows: the rule clipboardbridge-hub); the Mac's
// application firewall allows a listed program on every port already.
type hubFirewall struct {
	name     string                  // the firewall, for the messages
	active   func() bool             // a firewall filters incoming packets here
	opened   func() int              // the port cbb opened, or 0
	open     func(port int) error    // opens it
	close    func() error            // closes what cbb opened
	commands func(port int) []string // what opens it by hand
}

var hubFW = map[string]*hubFirewall{"linux": &linuxHubFW, "freebsd": &linuxHubFW, "windows": &windowsHubFW}[runtime.GOOS]

// firewallScript is the installer's firewall.sh: under /usr/local/share,
// /usr/share on OpenWrt, which has no /usr/local, or /opt on SteamOS.
var firewallScript = func() string {
	if openwrt.Is() {
		return "/usr/share/clipboardbridge/firewall.sh"
	}
	if steamos.Is() {
		return steamos.Share + "/firewall.sh"
	}
	return "/usr/local/share/clipboardbridge/firewall.sh"
}()

func firewallSh(args ...string) (string, error) {
	out, err := exec.Command("sh", append([]string{firewallScript}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

var linuxHubFW = hubFirewall{
	name: "the firewall",
	active: func() bool {
		out, err := firewallSh("kind")
		return err == nil && out != "none"
	},
	opened: func() int {
		out, err := firewallSh("hub-port")
		if err != nil {
			return 0
		}
		p, _ := strconv.Atoi(out)
		return p
	},
	open: func(port int) error {
		_, err := firewallSh("hub-open", strconv.Itoa(port))
		return err
	},
	close: func() error {
		_, err := firewallSh("hub-close")
		return err
	},
	commands: func(port int) []string {
		out, err := firewallSh("hub-commands", strconv.Itoa(port))
		if err != nil || out == "" {
			return nil
		}
		return strings.Split(out, "\n")
	},
}

const hubRule = "clipboardbridge-hub"

var windowsHubFW = hubFirewall{
	name:   "Windows Firewall",
	active: func() bool { return true },
	opened: func() int {
		out, err := powershell("[string](Get-NetFirewallRule -Name '" + hubRule + "' -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter).LocalPort")
		if err != nil {
			return 0
		}
		p, _ := strconv.Atoi(out)
		return p
	},
	open: func(port int) error {
		_, err := powershell(windowsHubScript(port))
		return err
	},
	close: func() error {
		_, err := powershell("Remove-NetFirewallRule -Name '" + hubRule + "' -ErrorAction SilentlyContinue")
		return err
	},
	commands: func(port int) []string {
		return []string{"  " + windowsHubRule(port)}
	},
}

func windowsHubRule(port int) string {
	return fmt.Sprintf("New-NetFirewallRule -Name '%s' -Group 'clipboardbridge' -DisplayName 'CBB hub (UDP %d)' -Direction Inbound -Action Allow -Protocol UDP -LocalPort %d -Program \"$env:ProgramFiles\\clipboardbridge\\cbb.exe\" -Profile Any", hubRule, port, port)
}

func windowsHubScript(port int) string {
	return "$ErrorActionPreference = 'Stop'\n" +
		"Remove-NetFirewallRule -Name '" + hubRule + "' -ErrorAction SilentlyContinue\n" +
		windowsHubRule(port) + " -Description 'The group''s devices away from home reach the CBB hub here, through its WireGuard tunnel.' | Out-Null\n"
}

// hubPortFor is the UDP port a hub reached at its own address takes its
// clients on, or 0.
func hubPortFor(a *control.Away) int {
	if a == nil || !a.Hub || len(a.Endpoints) == 0 {
		return 0
	}
	return a.Port
}

// syncHubPort opens the hub's port in the firewall or closes it, as the
// state a says; mode is "ask", "yes" (-firewall yes) or "no".
func syncHubPort(stdin io.Reader, stdout io.Writer, a *control.Away, mode string) {
	if hubFW == nil {
		return
	}
	want, have := hubPortFor(a), hubFW.opened()
	if want == have {
		return
	}
	if have != 0 {
		if !elevated() {
			fmt.Fprintf(stdout, "The firewall still lets the internet reach UDP port %d, which this device no longer needs; %s, or run cbb global again as %s.\n", have, closeHint, adminName)
		} else if err := hubFW.close(); err != nil {
			fmt.Fprintf(stdout, "Closing UDP port %d in %s failed: %v\n", have, hubFW.name, err)
		}
	}
	if want == 0 || !hubFW.active() {
		return
	}
	fmt.Fprintf(stdout, "Firewall: the hub's clients reach this device from the internet. CBB requires this rule:\n")
	fmt.Fprintf(stdout, "  1. Allow incoming UDP %d from any address. Purpose: the group's WireGuard tunnel; it answers only the group's devices.\n", want)
	yes := mode == "yes"
	how := " (-firewall yes)"
	if mode == "ask" {
		how = ""
		if !elevated() {
			fmt.Fprintf(stdout, "Only %s can add it.\n", adminName)
		} else {
			fmt.Fprint(stdout, "With Yes, CBB adds it now and removes it when this device stops being the hub.\nAdd this rule now? [y/N] ")
			line, err := readLine(stdin)
			if err != nil {
				fmt.Fprintln(stdout, "\nNo answer; taken as No.")
			}
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				yes = true
			}
		}
	}
	if yes && elevated() {
		if err := hubFW.open(want); err == nil {
			fmt.Fprintf(stdout, "Added the rule above%s.\n", how)
			fmt.Fprintf(stdout, "A router in front of this device must forward UDP %d to it as well.\n", want)
			return
		}
	}
	fmt.Fprintln(stdout, "No firewall rule was added. The hub's clients reach it only while the firewall allows the rule above.")
	if cmds := hubFW.commands(want); len(cmds) > 0 {
		fmt.Fprintln(stdout, "To add it by hand, run:")
		for _, c := range cmds {
			fmt.Fprintln(stdout, c)
		}
	}
	fmt.Fprintf(stdout, "To let CBB add it, run cbb global hub again with -firewall yes as %s.\n", adminName)
	fmt.Fprintf(stdout, "A router in front of this device must forward UDP %d to it as well.\n", want)
}
