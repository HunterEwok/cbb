// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package sysinfo tells what this computer is, for the hello's device
// (docs/protocol.md, section 4, "Device"): its form, its system's version
// and the MAC address of its network card on the home network.
package sysinfo

import (
	"net"
	"strings"

	"github.com/HunterEwok/cbb/internal/group"
)

// Device describes this computer, with version as its own version. A field
// it cannot find is left empty.
func Device(version string) group.DeviceInfo {
	return group.DeviceInfo{Form: form(), OSVersion: osVersion(), Version: version, MAC: mac()}.Clean()
}

// virtual are the prefixes of the names of interfaces that are no network
// card: bridges, containers, tunnels, virtual machines.
var virtual = []string{"docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "wg", "tun", "tap", "utun", "tailscale", "zt", "awdl", "llw", "bridge", "lxc", "cbb"}

// mac is the MAC address of the first network card that is up and has a
// private IPv4 address: the one on the home network.
func mac() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	return pickMAC(ifs, func(i net.Interface) []net.Addr {
		addrs, _ := i.Addrs()
		return addrs
	})
}

func pickMAC(ifs []net.Interface, addrs func(net.Interface) []net.Addr) string {
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) != 6 || isVirtual(i.Name) {
			continue
		}
		for _, a := range addrs(i) {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
				return strings.ToLower(i.HardwareAddr.String())
			}
		}
	}
	return ""
}

func isVirtual(name string) bool {
	name = strings.ToLower(name)
	for _, p := range virtual {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
