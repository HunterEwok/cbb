// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"time"
)

// liteAway (W17): the lite member as a client of the hub's tunnel. It meets
// the hub at home, takes its plain WireGuard offer, and syncs through the
// tunnel once it is away; when the hub hides its tunnel (AmneziaWG), the
// lite member takes the new offer at home and reaches the hub away from home
// with AmneziaWG.
func liteAway(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W17-lite-client/"
	a := newAwayGroup(ctx, r, f, "fleet/W17-lite-client", 1)
	if a == nil {
		return
	}
	hub := a.hub
	var lite *Device
	if r.Do(p+"meets-hub", func() error {
		var err error
		if lite, err = f.AddLite(ctx); err != nil {
			return err
		}
		if err := joinLite(ctx, hub, lite); err != nil {
			return err
		}
		if _, err := Run(ctx, lite, "cbb global on", "yes\n"); err != nil {
			return err
		}
		return globalShows(ctx, lite, "the hub is", 2*time.Minute)
	}) != nil {
		return
	}
	wait := 3 * time.Minute
	if r.Do(p+"plain", func() error {
		if err := moveTo(ctx, lite, a.away); err != nil {
			return err
		}
		if err := a.in.reach(ctx, lite); err != nil {
			return err
		}
		if err := globalShows(ctx, lite, "connected to the hub", wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, lite, "lite away", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, lite, hub, "from the lite member away", 2*timeout)
	}) != nil {
		return
	}
	if r.Do(p+"obfuscated-at-home", func() error {
		if _, err := Run(ctx, hub, a.hubCmd(hubPublic, a.fwdKey, "-obfuscate"), ""); err != nil {
			return err
		}
		// At home it gets the hub's new offer, with AmneziaWG's settings.
		if err := moveTo(ctx, lite, f.net); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, hub, lite, "lite at home", 2*time.Minute)
	}) != nil {
		return
	}
	r.Do(p+"obfuscated-away", func() error {
		if err := moveTo(ctx, lite, a.away); err != nil {
			return err
		}
		if err := a.in.reach(ctx, lite); err != nil {
			return err
		}
		if err := globalShows(ctx, lite, "connected to the hub", wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, lite, "lite away, obfuscated", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, lite, hub, "from the lite member away, obfuscated", 2*timeout)
	})
}

// refusedSync checks that a copy on from does not reach to within wait.
func refusedSync(ctx context.Context, g *benchGroup, from, to *Device, what string, wait time.Duration) error {
	text := "cbb-bench " + g.run + " " + what
	if err := Copy(ctx, from, text); err != nil {
		return err
	}
	time.Sleep(wait)
	got, err := Paste(ctx, to)
	if err != nil {
		return err
	}
	if got == text {
		return fmt.Errorf("%s reached %s", what, to.Name)
	}
	return nil
}
