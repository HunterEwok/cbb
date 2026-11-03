// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// besideAvahi (D1, the fleet's part): two computers with systemd and
// avahi-daemon, each in a group of its own. cbb publishes and
// browses beside avahi, which keeps publishing its host and finds the
// member's service, and a member never connects to the other group's
// member it finds.
func besideAvahi(ctx context.Context, r *Report, f *Fleet, archive string) {
	const p = "fleet/D1-avahi/"
	var ds []*Device
	if r.Do(p+"setup", func() error {
		for range 2 {
			d, err := f.AddSystemd(ctx, f.net)
			if err != nil {
				return err
			}
			if _, err := installArchive(ctx, d, archive, "--no-firewall --auto-update off"); err != nil {
				return err
			}
			if _, err := Run(ctx, d, "cbb new", ""); err != nil {
				return err
			}
			ds = append(ds, d)
		}
		return nil
	}) != nil {
		return
	}
	a, b := ds[0], ds[1]
	r.Do(p+"both-publish", func() error {
		_, tag, err := statusIDs(ctx, a)
		if err != nil {
			return err
		}
		return eventually(ctx, 30*time.Second, func() error {
			for _, d := range ds {
				if out, err := Run(ctx, d, "systemctl is-active avahi-daemon", ""); err != nil || strings.TrimSpace(out) != "active" {
					return fmt.Errorf("avahi-daemon on %s is %q beside cbb", d.Name, strings.TrimSpace(out))
				}
			}
			// avahi on b finds a's member, with its group in the TXT
			// record, and a's own host, which avahi on a publishes.
			out, err := Run(ctx, b, "avahi-browse -rtp _cbb._tcp", "")
			if err != nil {
				return err
			}
			if !strings.Contains(out, "=;") || !strings.Contains(out, ";8764;") || !strings.Contains(out, "g="+tag) {
				return fmt.Errorf("avahi on %s does not find %s's member (group %s): %q", b.Name, a.Name, tag, out)
			}
			host, err := Run(ctx, a, "hostname", "")
			if err != nil {
				return err
			}
			if out, err := Run(ctx, b, "avahi-resolve -4 -n "+strings.TrimSpace(host)+".local", ""); err != nil || !strings.Contains(out, ".local") {
				return fmt.Errorf("avahi on %s does not resolve %s's host beside cbb: %q %v", b.Name, a.Name, out, err)
			}
			return nil
		})
	})
	r.Do(p+"other-group-ignored", func() error {
		// Each has found the other by now; neither dials.
		time.Sleep(20 * time.Second)
		for _, pair := range [][2]*Device{{a, b}, {b, a}} {
			dialled, taken, err := memberConns(ctx, pair[0], pair[1])
			if err != nil {
				return err
			}
			if dialled+taken > 0 {
				return fmt.Errorf("%s holds %d member connections with %s of another group", pair[0].Name, dialled+taken, pair[1].Name)
			}
		}
		return nil
	})
}
