// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// hubCases runs P37 and P36 with an admin computer next to the hub: the hub
// moves to it and the away devices follow (P37); then the root is a hub
// again, and the admin serves while the root's service is stopped and gives
// way when it is back (P36).
func hubCases(ctx context.Context, r *Report, g *benchGroup, fwd *Host, joined []*Device, timeout time.Duration) {
	// The admin computer: the Mac, as in docs/maintainers/testbench-cases.md, or else
	// a Linux member at home.
	var admin *Device
	for _, d := range g.members[1:] {
		if slices.Contains(joined, d) {
			continue
		}
		if d.OS == "darwin" {
			admin = d
			break
		}
		if d.OS == "linux" && admin == nil {
			admin = d
		}
	}
	if admin == nil {
		r.Skip("away/P37", "needs a Linux or Mac member at home besides the hub")
		r.Skip("away/P36", "needs a Linux or Mac member at home besides the hub")
		return
	}
	hub := g.hub
	if r.Do("away/P37/"+admin.Name+"/admin", func() error {
		id, err := deviceOf(ctx, admin)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, hub, adminCmd(hub)+" admin -allow-file-key "+id, ""); err != nil {
			return noSudo(hub, err)
		}
		if _, err := Run(ctx, admin, adminCmd(admin)+" global on", "yes\n"); err != nil {
			return noSudo(admin, err)
		}
		g.undo = append(g.undo, func() { globalOff(context.WithoutCancel(ctx), r, g.suite, admin) })
		return globalShows(ctx, admin, "the hub is", 2*time.Minute)
	}) != nil {
		r.Skip("away/P36", "the admin computer of P37 is not set up")
		return
	}

	// P37: the lite member and the container cannot be the hub; the admin
	// computer can, and the away devices follow it.
	for _, d := range g.members[1:] {
		if d.OS != "linux-lite" && d.OS != "docker" {
			continue
		}
		r.Do("away/P37/move-"+d.Name+"/refused", func() error {
			id, err := deviceOf(ctx, d)
			if err != nil {
				return err
			}
			_, err = Run(ctx, hub, adminCmd(hub)+" global move "+id, "")
			var re *RunError
			switch {
			case err == nil:
				return fmt.Errorf("the hub moved to %s, which cannot be the hub", d.Name)
			case !errors.As(err, &re):
				return err
			case strings.TrimSpace(re.Output) == "":
				return errors.New("the refusal says nothing")
			}
			return nil
		})
	}
	if r.Do("away/P37/move-"+admin.Name, func() error {
		id, err := deviceOf(ctx, admin)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, hub, adminCmd(hub)+" global move "+id, ""); err != nil {
			return err
		}
		if err := globalShows(ctx, admin, "this device is the hub", 2*time.Minute); err != nil {
			return err
		}
		return globalShows(ctx, hub, "the hub is", 2*time.Minute)
	}) != nil {
		return
	}
	for _, d := range joined {
		if r.Do("away/P37/"+d.Name+"/follows", func() error { return globalShows(ctx, d, "connected to the hub", 3*time.Minute) }) == nil {
			awayHub := *g
			awayHub.hub = admin
			bothWays(ctx, r, &awayHub, "away/P37/"+d.Name+"/sync/", d, timeout)
		}
	}

	// P36: the root is a hub again beside the admin; the root serves, and
	// the admin only while the root's service is stopped.
	if r.Do("away/P36/"+hub.Name+"/hub", func() error {
		if _, err := Run(ctx, hub, adminCmd(hub)+" global hub -firewall no -forwarder "+fwd.Address+" -forwarder-key "+fwd.Key, ""); err != nil {
			return err
		}
		if err := globalShows(ctx, hub, "this device is the hub", 2*time.Minute); err != nil {
			return err
		}
		// The admin stands by as the root's client: cbb global says so.
		return globalShows(ctx, admin, "stands by as its client", 3*time.Minute)
	}) != nil {
		return
	}
	if r.Do("away/P36/"+hub.Name+"/stop", func() error {
		_, err := Run(ctx, hub, serviceCmd(hub, "stop"), "")
		return err
	}) != nil {
		return
	}
	stopped := time.Now()
	if r.Do("away/P36/"+admin.Name+"/serves", func() error {
		return globalShows(ctx, admin, "this device is the hub", 3*time.Minute)
	}) == nil {
		fmt.Fprintf(r.out, "     %s serves %v after the root stopped\n", admin.Name, time.Since(stopped).Round(time.Second))
		for _, d := range joined {
			if r.Do("away/P36/"+d.Name+"/to-"+admin.Name, func() error { return globalShows(ctx, d, "connected to the hub", 3*time.Minute) }) == nil {
				awayHub := *g
				awayHub.hub = admin
				bothWays(ctx, r, &awayHub, "away/P36/"+d.Name+"/while-stopped/", d, timeout)
			}
		}
	}
	r.Do("away/P36/"+hub.Name+"/start", func() error {
		_, err := Run(context.WithoutCancel(ctx), hub, serviceCmd(hub, "start"), "")
		return err
	})
	started := time.Now()
	if r.Do("away/P36/"+admin.Name+"/gives-way", func() error {
		return globalShows(ctx, admin, "stands by as its client", 6*time.Minute)
	}) == nil {
		fmt.Fprintf(r.out, "     %s gave way %v after the root came back\n", admin.Name, time.Since(started).Round(time.Second))
	}
	for _, d := range joined {
		if r.Do("away/P36/"+d.Name+"/back", func() error { return globalShows(ctx, d, "connected to the hub", 5*time.Minute) }) == nil {
			bothWays(ctx, r, g, "away/P36/"+d.Name+"/after/", d, timeout)
		}
	}
}
