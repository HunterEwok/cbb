// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"time"
)

// joinMatrix (G41, Y6 in part): each kind of admitter the fleet has (the
// root, an admin computer) admits a full member by each path of the LAN
// (the code alone, found by mDNS; the code with the admitter's address,
// across subnets with -peer), and a member on another subnet syncs through
// -peer; each new member syncs both ways, is removed by its admitter, and
// is then refused. The invitation's path is the away cases' (W4, G13); the
// phones, small devices and the other systems are the real devices..
func joinMatrix(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G41-matrix/"
	g := fleetGroup(ctx, r, f, "fleet/G41-matrix", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, admin, witness := g.members[0], g.members[1], g.members[2]
	if r.Do(p+"admin", func() error {
		return succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now")
	}) != nil {
		return
	}
	for _, by := range []*Device{root, admin} {
		for _, path := range []string{"mdns", "address"} {
			name := fmt.Sprintf("%sby-%s-%s/", p, map[bool]string{true: "root", false: "admin"}[by == root], path)
			var d *Device
			if r.Do(name+"join", func() error {
				var err error
				if d, err = f.Add(ctx); err != nil {
					return err
				}
				if path == "address" {
					ip, err := fleetIP(ctx, by)
					if err != nil {
						return err
					}
					// addrFor takes the admitter's address from here.
					by.Address = ip + ":8764"
					defer func() { by.Address = "" }()
				}
				// A window a failed join left open would take the next.
				defer Run(context.WithoutCancel(ctx), by, "pkill -f 'cbb pair' || true", "")
				if _, err := pairOne(ctx, by, d); err != nil {
					return err
				}
				return eventually(ctx, 10*time.Second, func() error { return shareClipboard(ctx, d) })
			}) != nil {
				continue
			}
			r.Do(name+"syncs", func() error {
				if err := eventually(ctx, time.Minute, func() error { return syncs(ctx, g, d, witness, "from "+d.Name, timeout) }); err != nil {
					return err
				}
				return syncs(ctx, g, witness, d, "to "+d.Name, timeout)
			})
			r.Do(name+"removed", func() error {
				if _, err := Run(ctx, by, "cbb remove "+d.Name, ""); err != nil {
					return err
				}
				return listsAs(ctx, []*Device{root, admin, witness}, d.Name, "", true, timeout)
			})
			r.Do(name+"refused", func() error {
				text := "cbb-bench " + g.run + " from the removed " + d.Name
				if err := Copy(ctx, d, text); err != nil {
					return err
				}
				for _, m := range []*Device{root, admin, witness} {
					if err := staysAway(ctx, m, text); err != nil {
						return err
					}
				}
				return nil
			})
		}
	}
	// Y6: across subnets, a member on another network syncs through -peer.
	r.Do("fleet/Y6-subnets", func() error {
		other, err := f.Network(ctx)
		if err != nil {
			return err
		}
		d, err := f.AddOn(ctx, other)
		if err != nil {
			return err
		}
		if _, err := docker(ctx, "network", "connect", other, root.Container); err != nil {
			return err
		}
		ip, err := fleetIPOn(ctx, root, other)
		if err != nil {
			return err
		}
		root.Address = ip + ":8764"
		defer func() { root.Address = "" }()
		defer Run(context.WithoutCancel(ctx), root, "pkill -f 'cbb pair' || true", "")
		if _, err := pairOne(ctx, root, d); err != nil {
			return err
		}
		if err := eventually(ctx, 10*time.Second, func() error { return shareClipboard(ctx, d) }); err != nil {
			return err
		}
		if err := eventually(ctx, time.Minute, func() error { return syncs(ctx, g, d, witness, "across subnets", timeout) }); err != nil {
			return err
		}
		return syncs(ctx, g, witness, d, "back across subnets", timeout)
	})
}
