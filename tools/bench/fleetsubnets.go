// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// unprotected is the option of docker network create that lets a router
// container pass packets between two of the fleet's networks.
const unprotected = "com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected"

// netSubnet is the IPv4 subnet of the fleet's network name.
func netSubnet(ctx context.Context, name string) (string, error) {
	out, err := docker(ctx, "network", "inspect", "-f", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", name)
	if err != nil {
		return "", err
	}
	for _, s := range strings.Fields(out) {
		if strings.Contains(s, ".") {
			return s, nil
		}
	}
	return "", fmt.Errorf("the network %s has no IPv4 subnet: %q", name, out)
}

// acrossSubnets (D9, the fleet's part): a small device on another subnet
// than the computer, with a router between the two that runs avahi, as a
// Pi on an IoT subnet behind the home router. With the router's mDNS
// reflector off the small device does not find the computer, and syncs
// with it once -peer names its address; with the reflector on it finds
// the computer by mDNS without -peer. The reflector goes first, while the
// computer knows no address of the small device on the IoT subnet to dial.
func acrossSubnets(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D9-subnets/"
	// Docker drops a packet for a container that comes from another of its
	// networks, even through a router container, unless the networks are
	// unprotected (Docker 28 or later).
	var home, iot string
	if r.Do(p+"networks", func() error {
		var err error
		if home, err = f.Network(ctx, "-o", unprotected); err != nil {
			return err
		}
		iot, err = f.Network(ctx, "-o", unprotected)
		return err
	}) != nil {
		return
	}
	g := fleetGroupOn(ctx, r, f, home, "fleet/D9-subnets", 1)
	if g == nil || len(g.members) != 1 {
		return
	}
	hub := g.hub
	var small, router *Device
	var hubIP string
	// reflector turns the router's mDNS reflector on or off.
	reflector := func(on bool) error {
		v := "no"
		if on {
			v = "yes"
		}
		_, err := Run(ctx, router, `sed -i -e '/^\[reflector\]/,/^\[/{s/^#\?enable-reflector=.*/enable-reflector=`+v+`/}' /etc/avahi/avahi-daemon.conf && grep -q '^enable-reflector=`+v+`' /etc/avahi/avahi-daemon.conf && systemctl restart avahi-daemon`, "")
		return err
	}
	if r.Do(p+"setup", func() error {
		var err error
		// The small device joins on the home network, then moves.
		if small, err = f.AddSmall(ctx); err != nil {
			return err
		}
		if err := moveTo(ctx, small, home); err != nil {
			return err
		}
		if err := joinSmall(ctx, hub, small); err != nil {
			return err
		}
		if hubIP, err = fleetIPOn(ctx, hub, home); err != nil {
			return err
		}
		near, err := netSubnet(ctx, home)
		if err != nil {
			return err
		}
		far, err := netSubnet(ctx, iot)
		if err != nil {
			return err
		}
		// The router: systemd and avahi, on both networks, forwarding.
		if router, err = f.AddSystemd(ctx, home); err != nil {
			return err
		}
		if _, err := docker(ctx, "network", "connect", iot, router.Container); err != nil {
			return err
		}
		if _, err := Run(ctx, router, "sysctl -qw net.ipv4.ip_forward=1", ""); err != nil {
			return err
		}
		if err := reflector(false); err != nil {
			return err
		}
		routerHome, err := fleetIPOn(ctx, router, home)
		if err != nil {
			return err
		}
		routerIoT, err := fleetIPOn(ctx, router, iot)
		if err != nil {
			return err
		}
		// The small device moves to the IoT subnet, the computer stays home.
		if err := moveTo(ctx, small, iot); err != nil {
			return err
		}
		if _, err := Run(ctx, hub, "ip route replace "+far+" via "+routerHome, ""); err != nil {
			return err
		}
		if _, err := Run(ctx, small, "ip route replace "+near+" via "+routerIoT, ""); err != nil {
			return err
		}
		if !listens(ctx, small, net.JoinHostPort(hubIP, "8764")) {
			return fmt.Errorf("the small device on %s does not reach %s's member port through the router", far, hub.Name)
		}
		return smallRestart(ctx, small, "")
	}) != nil {
		return
	}
	defer smallRestart(context.WithoutCancel(ctx), small, "")
	r.Do(p+"no-reflector", func() error {
		// Neither side's mDNS crosses the router: nothing reaches the small
		// member, whose old address the computer no longer reaches.
		return refusedSync(ctx, g, hub, small, "D9 across subnets without -peer or a reflector", 30*time.Second)
	})
	r.Do(p+"reflector", func() error {
		if err := reflector(true); err != nil {
			return err
		}
		defer reflector(false)
		if err := smallRestart(ctx, small, ""); err != nil {
			return err
		}
		// mDNS announces repeat; give the small device a minute to find
		// the computer through the reflector.
		if err := syncs(ctx, g, hub, small, "D9 to the IoT subnet through the reflector", time.Minute+timeout); err != nil {
			return err
		}
		return syncs(ctx, g, small, hub, "D9 from the IoT subnet through the reflector", timeout)
	})
	r.Do(p+"peer", func() error {
		if err := smallRestart(ctx, small, "-peer "+net.JoinHostPort(hubIP, "8764")); err != nil {
			return err
		}
		if err := syncs(ctx, g, hub, small, "D9 to the IoT subnet with -peer", timeout); err != nil {
			return err
		}
		return syncs(ctx, g, small, hub, "D9 from the IoT subnet with -peer", timeout)
	})
}
