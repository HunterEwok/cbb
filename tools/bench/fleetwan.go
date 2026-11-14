// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// wanSide (D10, the fleet's part): a member limited to its home interface
// (CBB_INTERFACES, as the OpenWrt package sets it to the router's LAN
// zones) with a second, internet-side network and no firewall at all
// takes member TLS from its home network only: a device on the other
// network that reaches the member port gets no handshake, even once the
// member takes that network as one where it met its group (cbb network),
// so that the interface limit alone keeps it out.
func wanSide(ctx context.Context, r *Report, f *Fleet) {
	const p = "fleet/D10-wan/"
	g := fleetGroup(ctx, r, f, "fleet/D10-wan", 1, "CBB_INTERFACES=eth0")
	if g == nil || len(g.members) < 1 {
		return
	}
	rt := g.hub
	var wan string
	var inside, outside *Device
	if r.Do(p+"setup", func() error {
		var err error
		if wan, err = f.Network(ctx); err != nil {
			return err
		}
		if _, err := docker(ctx, "network", "connect", wan, rt.Container); err != nil {
			return err
		}
		// The group counts the other network as one it met on, as when a
		// router's WAN is another home network, so that only the interface
		// limit stands between it and the member port.
		if _, err := Run(ctx, rt, "cbb network", ""); err != nil {
			return err
		}
		if inside, err = f.Add(ctx); err != nil {
			return err
		}
		outside, err = f.AddOn(ctx, wan)
		return err
	}) != nil {
		return
	}
	id, _, _ := statusIDs(ctx, rt)
	// handshake tries member TLS from d to addr and tells whether the
	// member answered with TLS 1.3.
	handshake := func(d *Device, ip string) (bool, string) {
		out, _ := runOut(ctx, d, "openssl s_client -tls1_3 -connect "+ip+":8764 -servername cb-"+id+".local -alpn cbb/4 </dev/null 2>&1", time.Minute)
		return strings.Contains(out, "New, TLSv1.3,"), out
	}
	r.Do(p+"home-answers", func() error {
		ip, err := fleetIPOn(ctx, rt, f.net)
		if err != nil {
			return err
		}
		return eventually(ctx, 30*time.Second, func() error {
			if ok, out := handshake(inside, ip); !ok {
				return fmt.Errorf("the member does not answer member TLS from its home network: %q", lastLines(out, 4))
			}
			return nil
		})
	})
	r.Do(p+"wan-refused", func() error {
		ip, err := fleetIPOn(ctx, rt, wan)
		if err != nil {
			return err
		}
		// The port is reachable: the connection opens, and is closed.
		if _, err := Run(ctx, outside, "bash -c 'exec 3<>/dev/tcp/"+ip+"/8764'", ""); err != nil {
			return fmt.Errorf("the member port is not even reachable from the other network, so this proves nothing: %w", err)
		}
		if ok, out := handshake(outside, ip); ok {
			return fmt.Errorf("the member answered member TLS from the internet side: %q", lastLines(out, 4))
		}
		return nil
	})
}
