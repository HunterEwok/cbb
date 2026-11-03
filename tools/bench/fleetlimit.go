// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// systemLimit (W2, Linux): a computer installed by install.sh, whose unit
// keeps the service on the home network, joins a group away from home by
// invitation; the drop-in then lets it reach exactly the hub and the
// forwarder, and it syncs. When the hub's address changes, cbb global and
// cbb status say the limit lags, and the client sends nothing to the new
// address until sudo cbb global allow writes the drop-in again.
func systemLimit(ctx context.Context, r *Report, f *Fleet, archive string, timeout time.Duration) {
	const p = "fleet/W2-limit/"
	a := newAwayGroup(ctx, r, f, "fleet/W2-limit", 2)
	if a == nil {
		return
	}
	hub := a.hub
	dropIn := func(d *Device) string {
		out, _ := Run(ctx, d, "cat /etc/systemd/system/cbb.service.d/away.conf 2>/dev/null; true", "")
		return out
	}
	allowLine := func(d *Device) string {
		for _, l := range strings.Split(dropIn(d), "\n") {
			if strings.HasPrefix(l, "IPAddressAllow=") {
				return l
			}
		}
		return ""
	}
	var d *Device
	if r.Do(p+"join", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, a.away); err != nil {
			return err
		}
		if _, err := installArchive(ctx, d, archive, "--no-firewall --auto-update off"); err != nil {
			return err
		}
		if err := a.in.reach(ctx, d); err != nil {
			return err
		}
		if out, err := Run(ctx, d, "systemctl show -p IPAddressDeny cbb.service", ""); err != nil || !strings.Contains(out, "IPAddressDeny=") || strings.TrimSpace(out) == "IPAddressDeny=" {
			return fmt.Errorf("the installed unit does not keep the service on the home network: %q %v", out, err)
		}
		if err := inviteJoin(ctx, a.benchGroup, d); err != nil {
			return err
		}
		a.members = append(a.members, d)
		return nil
	}) != nil {
		return
	}
	r.Do(p+"allows-the-servers", func() error {
		if err := eventually(ctx, time.Minute, func() error {
			got := allowLine(d)
			if got != "IPAddressAllow="+hubPublic+" "+fwdPublic {
				return fmt.Errorf("away.conf allows %q, not exactly the hub and the forwarder", got)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := connected(ctx, d, 3*time.Minute); err != nil {
			return err
		}
		for _, pair := range [][2]*Device{{hub, d}, {d, hub}} {
			if err := syncs(ctx, a.benchGroup, pair[0], pair[1], "through the limit from "+pair[0].Name, 2*timeout); err != nil {
				return err
			}
		}
		return nil
	})
	const lags = "but the group's servers are now"
	// toNew counts, on the internet's router, what the client sends to the
	// hub's new address before it is passed on.
	toNew := func() (int, error) {
		out, err := Run(ctx, a.in.router, "iptables -t mangle -L cbbw2 -v -x -n | tail -1", "")
		if err != nil {
			return 0, err
		}
		fs := strings.Fields(out)
		if len(fs) == 0 {
			return 0, fmt.Errorf("no counter on the router: %q", out)
		}
		var n int
		_, err = fmt.Sscan(fs[0], &n)
		return n, err
	}
	r.Do(p+"address-changed", func() error {
		ip, err := fleetIP(ctx, d)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, a.in.router, "iptables -t mangle -N cbbw2 && iptables -t mangle -A cbbw2 -s "+ip+" -d "+hubPublic2+" && iptables -t mangle -I PREROUTING -j cbbw2", ""); err != nil {
			return err
		}
		if err := a.in.publish(ctx, hubPublic2, hub); err != nil {
			return err
		}
		if err := succeeds(ctx, hub, a.hubCmd(hubPublic2, a.fwdKey), "", "Reached at "+hubPublic2); err != nil {
			return err
		}
		// The offer reaches the client before the old address goes.
		time.Sleep(5 * time.Second)
		if err := a.in.block(ctx, hubPublic, ""); err != nil {
			return err
		}
		for _, cmd := range []string{"cbb global", "cbb status"} {
			if err := eventually(ctx, 2*time.Minute, func() error {
				return showsAll(ctx, d, cmd, lags, hubPublic2, "sudo cbb global allow")
			}); err != nil {
				return err
			}
		}
		// The unit's limit keeps the new address out, though the client
		// knows it (it may still reach the hub through the forwarder).
		time.Sleep(20 * time.Second)
		n, err := toNew()
		if err == nil && n > 0 {
			err = fmt.Errorf("the client sent %d packets to the hub's new address before cbb global allow", n)
		}
		return err
	})
	r.Do(p+"allow", func() error {
		if err := showsAll(ctx, d, "cbb global allow", "This computer's service may now reach", hubPublic2, "it restarted for that"); err != nil {
			return err
		}
		if got := allowLine(d); !strings.Contains(got, hubPublic2) {
			return fmt.Errorf("after cbb global allow away.conf allows %q, without %s", got, hubPublic2)
		}
		if err := connected(ctx, d, 3*time.Minute); err != nil {
			return err
		}
		if err := eventually(ctx, 2*time.Minute, func() error {
			n, err := toNew()
			if err == nil && n == 0 {
				err = fmt.Errorf("after cbb global allow the client still sends nothing to the hub's new address")
			}
			return err
		}); err != nil {
			return err
		}
		if out, _ := Run(ctx, d, "cbb global", ""); strings.Contains(out, lags) {
			return fmt.Errorf("cbb global still says the limit lags: %q", out)
		}
		return syncs(ctx, a.benchGroup, hub, d, "after cbb global allow", 2*timeout)
	})
}

// showsAll runs cmd on d and checks that it succeeds and prints each of
// wants.
func showsAll(ctx context.Context, d *Device, cmd string, wants ...string) error {
	out, err := Run(ctx, d, cmd, "")
	if err != nil {
		return err
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			return fmt.Errorf("%s on %s printed %q, without %q", cmd, d.Name, out, w)
		}
	}
	return nil
}
