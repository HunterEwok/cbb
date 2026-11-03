// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// resolvePhoneName asks for cbb.local from the prober and
// returns the addresses that answered.
func resolvePhoneName(ctx context.Context, prober *Device) ([]string, error) {
	out, err := RunFor(ctx, prober, "cbbbench-forge mdns-resolve:cbb.local", "", 20*time.Second)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 3 && f[0] == "A" {
			ips = append(ips, f[2])
		}
	}
	return ips, nil
}

// holdsName waits until cbb.local answers with d's address
// alone, and d's cbb holder says it answers.
func holdsName(ctx context.Context, prober, d *Device, within time.Duration) error {
	ip, err := fleetIP(ctx, d)
	if err != nil {
		return err
	}
	return eventually(ctx, within, func() error {
		ips, err := resolvePhoneName(ctx, prober)
		if err != nil {
			return err
		}
		if len(ips) != 1 || ips[0] != ip {
			return fmt.Errorf("cbb.local answers with %v, not %s of %s alone", ips, ip, d.Name)
		}
		return succeeds(ctx, d, "cbb holder", "", holdingLine)
	})
}

// holdingLine starts cbb holder's line on the member that answers for
// cbb.local now.
const holdingLine = "Answers for cbb.local ("

// answers tells whether d answers for cbb.local now.
func answers(ctx context.Context, d *Device) bool {
	out, err := Run(ctx, d, "cbb holder", "")
	return err == nil && strings.Contains(out, holdingLine)
}

// holder (D4, D5): of a group's members, those that hold the iPhone CA key
// (the root computer and its admins) elect one to answer for
// cbb.local: a machine without a battery first, a laptop or a
// member set to fallback only when no other is there, never one set to
// never. When the holder stops, it says goodbye and another takes the name
// at once; when it loses power, another takes it within 20 s.
func holder(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D4-holder/"
	g := fleetGroup(ctx, r, f, "fleet/D4-holder", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, admin, member := g.members[0], g.members[1], g.members[2]
	var prober *Device
	if r.Do(p+"setup", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		var err error
		prober, err = forgeServer(ctx, f, f.net, "-addr /tmp/mdns mdns-browse")
		return err
	}) != nil {
		return
	}
	r.Do(p+"member-never", func() error {
		// An ordinary member holds no iPhone CA key and takes no part.
		return succeeds(ctx, member, "cbb holder", "", "it does not hold the group's iPhone key")
	})
	r.Do(p+"one-holder", func() error {
		return eventually(ctx, 30*time.Second, func() error {
			ips, err := resolvePhoneName(ctx, prober)
			if err != nil {
				return err
			}
			if len(ips) != 1 {
				return fmt.Errorf("cbb.local answers with %v, not one address", ips)
			}
			n := 0
			for _, d := range []*Device{root, admin} {
				if answers(ctx, d) {
					n++
				}
			}
			if n != 1 {
				return fmt.Errorf("%d of the root and the admin say they answer for cbb.local", n)
			}
			return succeeds(ctx, root, "cbb holder", "", "auto, no battery")
		})
	})
	r.Do(p+"first-over-fallback", func() error {
		if err := succeeds(ctx, root, "cbb holder fallback", "", "setting fallback"); err != nil {
			return err
		}
		if err := succeeds(ctx, admin, "cbb holder first", "", "first"); err != nil {
			return err
		}
		return holdsName(ctx, prober, admin, 30*time.Second)
	})
	r.Do(p+"fallback-alone", func() error {
		if err := succeeds(ctx, admin, "cbb holder never", "", "Never holds cbb.local (setting never)"); err != nil {
			return err
		}
		return holdsName(ctx, prober, root, 30*time.Second)
	})
	fails(ctx, r, p+"bad-setting", root, errorCase{cmd: "cbb holder sometimes", want: []string{"auto"}})
	r.Do(p+"back-to-auto", func() error {
		for _, d := range []*Device{root, admin} {
			if err := succeeds(ctx, d, "cbb holder auto", "", "setting auto"); err != nil {
				return err
			}
		}
		return nil
	})

	// D5: the holder stops and says goodbye; the other takes the name at
	// once.
	var held, other *Device
	if r.Do("fleet/D5-handover/who", func() error {
		return eventually(ctx, 30*time.Second, func() error {
			for _, d := range []*Device{root, admin} {
				if answers(ctx, d) {
					held = d
				}
			}
			if held == nil {
				return fmt.Errorf("neither %s nor %s answers for cbb.local", root.Name, admin.Name)
			}
			other = root
			if held == root {
				other = admin
			}
			return nil
		})
	}) != nil {
		return
	}
	r.Do("fleet/D5-handover/goodbye", func() error {
		// The container's loop is held, so the service stays stopped
		// until the check is done.
		if _, err := docker(ctx, "kill", "-s", "STOP", held.Container); err != nil {
			return err
		}
		defer docker(context.WithoutCancel(ctx), "kill", "-s", "CONT", held.Container)
		if _, err := Run(ctx, held, strings.ReplaceAll(fleetKill, "-KILL", "-TERM"), ""); err != nil {
			return err
		}
		start := time.Now()
		if err := holdsName(ctx, prober, other, 10*time.Second); err != nil {
			return err
		}
		if d := time.Since(start); d > 5*time.Second {
			return fmt.Errorf("%s took cbb.local %s after the holder said goodbye, not at once", other.Name, d.Round(time.Second))
		}
		return nil
	})
	r.Do("fleet/D5-handover/power-loss", func() error {
		// Whoever holds it now is frozen whole, without a goodbye, as when
		// it loses power.
		var now, next *Device
		if err := eventually(ctx, 30*time.Second, func() error {
			for _, d := range []*Device{root, admin} {
				if answers(ctx, d) {
					now = d
					return nil
				}
			}
			return fmt.Errorf("neither %s nor %s answers for cbb.local", root.Name, admin.Name)
		}); err != nil {
			return err
		}
		next = root
		if now == root {
			next = admin
		}
		if _, err := docker(ctx, "pause", now.Container); err != nil {
			return err
		}
		defer docker(context.WithoutCancel(ctx), "unpause", now.Container)
		ip, err := fleetIP(ctx, next)
		if err != nil {
			return err
		}
		// The frozen holder cannot be asked; only the name's answers count.
		return eventually(ctx, 20*time.Second, func() error {
			ips, err := resolvePhoneName(ctx, prober)
			if err != nil {
				return err
			}
			if len(ips) != 1 || ips[0] != ip {
				return fmt.Errorf("cbb.local answers with %v, not %s of %s", ips, ip, next.Name)
			}
			return nil
		})
	})
}
