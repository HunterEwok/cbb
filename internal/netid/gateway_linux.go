// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package netid

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// gateways reads the default routes from /proc/net/route and their
// gateways' addresses from /proc/net/arp.
func gateways() (map[int]string, error) {
	routes, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer routes.Close()
	gw := map[string]netip.Addr{} // by interface name
	sc := bufio.NewScanner(routes)
	sc.Scan() // the header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		// The kernel prints the address's four bytes as a number in the
		// host's byte order, so on a big-endian router they read as written.
		var ip [4]byte
		binary.NativeEndian.PutUint32(ip[:], binary.BigEndian.Uint32(b))
		if _, ok := gw[f[0]]; !ok {
			gw[f[0]] = netip.AddrFrom4(ip)
		}
	}
	return arp("/proc/net/arp", gw)
}

// arp finds the gateways in the ARP table at path.
func arp(path string, gw map[string]netip.Addr) (map[int]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[int]string{}
	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	for sc.Scan() {
		// IP address, HW type, Flags, HW address, Mask, Device
		r := strings.Fields(sc.Text())
		if len(r) < 6 || r[2] == "0x0" {
			continue
		}
		ip, err := netip.ParseAddr(r[0])
		if err != nil || gw[r[5]] != ip {
			continue
		}
		mac, err := net.ParseMAC(r[3])
		if err != nil {
			continue
		}
		if ifc, err := net.InterfaceByName(r[5]); err == nil {
			out[ifc.Index] = mac.String()
		}
	}
	return out, nil
}
