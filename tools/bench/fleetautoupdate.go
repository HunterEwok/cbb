// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// timerState is what systemd says of the update timer on d: enabled or
// disabled.
func timerState(ctx context.Context, d *Device) string {
	out, _ := Run(ctx, d, "systemctl is-enabled cbb-update.timer 2>/dev/null || true", "")
	return strings.TrimSpace(out)
}

// groupUpdate (I12): install.sh without a terminal leaves automatic updates
// unanswered and says how to turn them on; cbb update -auto on and off turn
// the timer on and off; in a group of two, the member that updates first
// hands the archive to its service, and the other takes it from that
// member, from a feed that holds the signed files but not the archive.
func groupUpdate(ctx context.Context, r *Report, f *Fleet, fd *feed, builds map[string]string) {
	const p = "fleet/I12-auto/"
	var ds [2]*Device
	if r.Do(p+"install", func() error {
		for i := range ds {
			d, err := f.AddSystemd(ctx, f.net)
			if err != nil {
				return err
			}
			ds[i] = d
			out, err := installArchive(ctx, d, builds["0.6.0"], "--express")
			if err != nil {
				return err
			}
			if !strings.Contains(out, "No terminal to answer on; not now. Later: sudo cbb update -auto on") {
				return fmt.Errorf("install.sh without a terminal printed %q, without how to turn automatic updates on", out)
			}
			if s := timerState(ctx, d); s == "enabled" {
				return fmt.Errorf("the update timer is %s with no answer", s)
			}
			// The service checks the group's releases with the feed's
			// roots, as cbb update does: a drop-in of its own, which
			// install.sh keeps across the update (it writes
			// cbb.env anew).
			if _, err := Run(ctx, d, "mkdir -p /feed /etc/systemd/system/cbb.service.d && printf '[Service]\\nEnvironment=CBB_RELEASE_ROOTS=/feed/roots.pem\\n' >/etc/systemd/system/cbb.service.d/bench-roots.conf && systemctl daemon-reload", ""); err != nil {
				return err
			}
			if err := fd.rootsTo(ctx, d); err != nil {
				return err
			}
			if _, err := Run(ctx, d, "systemctl restart cbb", ""); err != nil {
				return err
			}
			if err := runsVersion(ctx, d, "0.6.0"); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	r.Do(p+"switch", func() error {
		d := ds[1]
		// Off removes the timer or disables it; either way it is not enabled.
		for _, c := range []struct{ auto, want string }{{"on", "enabled"}, {"off", ""}} {
			if _, err := Run(ctx, d, "cbb update -auto "+c.auto, ""); err != nil {
				return err
			}
			if s := timerState(ctx, d); (c.want != "" && s != c.want) || (c.want == "" && s == "enabled") {
				return fmt.Errorf("after cbb update -auto %s the timer is %q", c.auto, s)
			}
			out, err := Run(ctx, d, "cbb update -auto", "")
			if err != nil {
				return err
			}
			if strings.TrimSpace(out) != c.auto {
				return fmt.Errorf("cbb update -auto says %q after it was turned %s", out, c.auto)
			}
		}
		return nil
	})
	ds[0].Roles = []string{"member", "hub"}
	g := formGroup(ctx, r, p+"group", ds[:])
	if g == nil || len(g.members) != 2 {
		return
	}
	defer g.undoAll()
	r.Do(p+"shared", func() error {
		dir, err := fd.publish(ctx, builds["0.6.1"], "group", "0.6.1", releaseOpts{})
		if err != nil {
			return err
		}
		at, err := fd.toDevice(ctx, ds[0], dir)
		if err != nil {
			return err
		}
		if out, err := runOut(ctx, ds[0], feedEnv(at)+"cbb update", 5*time.Minute); err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		if err := runsVersion(ctx, ds[0], "0.6.1"); err != nil {
			return err
		}
		// The first member restarted on the new release: the second takes
		// the archive only once they are connected again.
		if err := syncs(ctx, g, ds[0], ds[1], "after the update", time.Minute); err != nil {
			return err
		}
		// The second member's feed holds only the signed files: the
		// archive can come only from the first member.
		signed := filepath.Join(fd.dir, "feed-group-signed")
		if err := os.MkdirAll(signed, 0o755); err != nil {
			return err
		}
		for _, name := range []string{"keys.json", "release.json", "stable.json"} {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(signed, name), data, 0o644); err != nil {
				return err
			}
		}
		at, err = fd.toDevice(ctx, ds[1], signed)
		if err != nil {
			return err
		}
		out, err := runOut(ctx, ds[1], feedEnv(at)+"cbb update", 15*time.Minute)
		fmt.Fprintf(r.out, "I12 shared: %s\n", strings.Join(strings.Fields(out), " "))
		if err != nil {
			return fmt.Errorf("the second member did not take the archive from the first: %w", err)
		}
		if strings.Contains(out, "No device of the group could hand it over") {
			return fmt.Errorf("the second member found no member to hand the archive over: %q", out)
		}
		return runsVersion(ctx, ds[1], "0.6.1")
	})
}
