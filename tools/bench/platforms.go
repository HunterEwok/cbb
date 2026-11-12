// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import "strings"

// The bench reaches an OpenWrt router as root, which has no sudo; on
// FreeBSD, as on Linux, it runs sudo without a password (docs/testbench.md,
// section 13).

// serviceCmd is the command that stops, starts or restarts the device's
// service (action: stop, start, restart), or "" where the bench has none.
func serviceCmd(d *Device, action string) string {
	switch d.OS {
	case "linux":
		return "sudo -n systemctl " + action + " cbb"
	case "openwrt":
		return "/etc/init.d/cbb " + action
	case "freebsd":
		return "sudo -n service cbb " + action
	case "netns":
		return "sudo -n systemctl " + action + " " + netnsUnit(d)
	}
	return ""
}

// netnsDir is where setup-netns.sh keeps a namespace member's binary,
// state, socket and the cbb that reaches it.
func netnsDir(d *Device) string { return "/opt/cbbbench-netns/" + d.Name }

// netnsUnit is the systemd unit of a namespace member's service.
func netnsUnit(d *Device) string { return "cbbbench-" + d.Name }

// rootPrefix runs a command as root on the device: sudo, or nothing for
// the router's root and a fleet member, which run as root.
func rootPrefix(d *Device) string {
	if d.OS == "openwrt" || d.OS == "fleet" {
		return ""
	}
	return "sudo -n "
}

// stageBase is where the bench keeps the builds it sends: the router keeps
// them in RAM, not on its flash.
func stageBase(d *Device) string {
	if d.OS == "openwrt" {
		return "/tmp/cbbbench"
	}
	return stateBase
}

// machineCmd prints what archiveFor takes: the CPU from uname -m, and on
// OpenWrt its package architecture, which also tells the byte order of a
// MIPS router.
func machineCmd(d *Device) string {
	switch d.OS {
	case "windows":
		return "$env:PROCESSOR_ARCHITECTURE"
	case "openwrt":
		return ". /etc/openwrt_release && echo \"$DISTRIB_ARCH\""
	}
	return "uname -m"
}

// openwrtArch maps OpenWrt's package architecture (aarch64_cortex-a53,
// arm_cortex-a7_neon-vfpv4, mipsel_24kc, x86_64, ...) to the release's.
func openwrtArch(distribArch string) string {
	cpu, _, _ := strings.Cut(distribArch, "_")
	switch {
	case distribArch == "x86_64":
		return "amd64"
	case cpu == "aarch64":
		return "arm64"
	case cpu == "mipsel":
		return "mipsle"
	case cpu == "mips":
		return "mips"
	case cpu == "arm":
		// Go's arm builds need a hardware FPU: ARMv7 cores are named
		// cortex-a*, the older ones with a VFP take armv6.
		fpu := strings.Contains(distribArch, "vfp") || strings.Contains(distribArch, "neon")
		switch {
		case fpu && strings.HasPrefix(distribArch, "arm_cortex-a"):
			return "armv7"
		case fpu:
			return "armv6"
		}
	}
	return ""
}

// installedPaths are what uninstall.sh --purge removes on the device.
func installedPaths(d *Device) []string {
	switch d.OS {
	case "openwrt":
		return []string{"/usr/bin/cbb", "/usr/share/cbb", "/etc/cbb", "/etc/config/cbb",
			"/etc/init.d/cbb", "/etc/hotplug.d/ntp/50-cbb", "/lib/upgrade/keep.d/cbb"}
	case "freebsd":
		return []string{"/usr/local/bin/cbb", "/usr/local/share/cbb", "/usr/local/etc/cbb",
			"/usr/local/etc/rc.d/cbb", "/var/db/cbb"}
	}
	return []string{"/var/lib/cbb", "/etc/cbb", "/usr/local/bin/cbb", "/usr/local/share/cbb",
		"/etc/systemd/system/cbb.service", "/etc/systemd/system/cbb.service.d",
		"/etc/xdg/autostart/cbb-desktop.desktop"}
}

// uninstallScript is where the installer put uninstall.sh.
func uninstallScript(d *Device) string {
	if d.OS == "openwrt" {
		return "/usr/share/cbb/uninstall.sh"
	}
	return "/usr/local/share/cbb/uninstall.sh"
}

// coarseDate reports whether the device's date prints whole seconds only.
func coarseDate(d *Device) bool {
	return d.OS == "darwin" || d.OS == "freebsd" || d.OS == "openwrt"
}
