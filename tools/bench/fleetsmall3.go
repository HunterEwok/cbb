// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"time"
)

// smallAway (W17): the small device as a client of the hub's tunnel. It meets
// the hub at home, takes its plain WireGuard offer, and syncs through the
// tunnel once it is away; when the hub hides its tunnel (AmneziaWG), the
// small device takes the new offer at home and reaches the hub away from home
// with AmneziaWG.
func smallAway(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W17-small-client/"
	a := newAwayGroup(ctx, r, f, "fleet/W17-small-client", 1)
	if a == nil {
		return
	}
	hub := a.hub
	var small *Device
	if r.Do(p+"meets-hub", func() error {
		var err error
		if small, err = f.AddSmall(ctx); err != nil {
			return err
		}
		if err := joinSmall(ctx, hub, small); err != nil {
			return err
		}
		if _, err := Run(ctx, small, "cbb global on", "yes\n"); err != nil {
			return err
		}
		return globalShows(ctx, small, "the hub is", 2*time.Minute)
	}) != nil {
		return
	}
	wait := 3 * time.Minute
	if r.Do(p+"plain", func() error {
		if err := moveTo(ctx, small, a.away); err != nil {
			return err
		}
		if err := a.in.reach(ctx, small); err != nil {
			return err
		}
		if err := globalShows(ctx, small, "connected to the hub", wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, small, "small device away", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, small, hub, "from the small device away", 2*timeout)
	}) != nil {
		return
	}
	if r.Do(p+"obfuscated-at-home", func() error {
		if _, err := Run(ctx, hub, a.hubCmd(hubPublic, a.fwdKey, "-no-vless"), ""); err != nil {
			return err
		}
		// At home it gets the hub's new offer, with AmneziaWG's settings.
		if err := moveTo(ctx, small, f.net); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, hub, small, "small device at home", 2*time.Minute)
	}) != nil {
		return
	}
	r.Do(p+"obfuscated-away", func() error {
		if err := moveTo(ctx, small, a.away); err != nil {
			return err
		}
		if err := a.in.reach(ctx, small); err != nil {
			return err
		}
		if err := globalShows(ctx, small, "connected to the hub", wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, small, "small device away, obfuscated", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, small, hub, "from the small device away, obfuscated", 2*timeout)
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
