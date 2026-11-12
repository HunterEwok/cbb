// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

var fingerprintRE = regexp.MustCompile(`fingerprint:\s+(\S.*\S)`)

// awayOnly returns the devices that are only away from home.
func awayOnly(devices []*Device) []*Device {
	var out []*Device
	for _, d := range devices {
		if d.Has("away") && !slices.Contains(atHome(devices), d) {
			out = append(out, d)
		}
	}
	return out
}

// globalShows waits until cbb global on the device prints want.
func globalShows(ctx context.Context, d *Device, want string, timeout time.Duration) error {
	return eventually(ctx, timeout, func() error {
		out, err := Run(ctx, d, cbbCmd(d)+" global", "")
		if err != nil {
			return err
		}
		if !strings.Contains(out, want) {
			return fmt.Errorf("cbb global on %s says %q, not %q", d.Name, strings.Join(strings.Fields(out), " "), want)
		}
		return nil
	})
}

// Away runs sync away from home (docs/testbench-cases.md): the hub serves
// through the forwarder, each away device joins by invitation (P11) and
// syncs both ways, also after cbb global off and on; with the hub's service
// stopped it says so and sends nothing another way (F6). Then the hub moves
// to an admin computer (P37), and both serve as several hubs (P36). F7 stops
// the forwarder, a server others use too, so it runs only with
// stopForwarder.
func Away(ctx context.Context, r *Report, inv *Inventory, devices []*Device, timeout time.Duration, stopForwarder bool) {
	away := awayOnly(devices)
	fwd := inv.Forwarder
	switch {
	case len(away) == 0:
		r.Skip("away/setup", "needs a device with only the role away in the inventory")
		return
	case fwd == nil || fwd.Address == "" || fwd.Key == "":
		r.Skip("away/setup", "needs [forwarder] with address and key in the inventory")
		return
	}
	g := formGroup(ctx, r, "away", devices)
	if g == nil {
		return
	}
	defer g.end(ctx, r)
	hub := g.hub

	if r.Do("away/P11/"+hub.Name+"/hub", func() error {
		if _, err := Run(ctx, hub, adminCmd(hub)+" global on", "yes\n"); err != nil {
			return noSudo(hub, err)
		}
		g.undo = append(g.undo, func() { globalOff(context.WithoutCancel(ctx), r, g.suite, hub) })
		if _, err := Run(ctx, hub, adminCmd(hub)+" global hub -firewall no -forwarder "+fwd.Address+" -forwarder-key "+fwd.Key, ""); err != nil {
			return err
		}
		return globalShows(ctx, hub, "Registered with the forwarder at", time.Minute)
	}) != nil {
		return
	}

	var joined []*Device
	for _, d := range away {
		if r.Do("away/P11/"+d.Name+"/invite", func() error { return inviteJoin(ctx, g, d) }) != nil {
			continue
		}
		g.members = append(g.members, d)
		g.undo = append(g.undo, func() { globalOff(context.WithoutCancel(ctx), r, g.suite, d) })
		if r.Do("away/P11/"+d.Name+"/shared", func() error { return shareClipboard(ctx, d) }) == nil {
			joined = append(joined, d)
		}
	}
	// The cases below need an away device that syncs; one that does not
	// would only make each of them wait out its time.
	var synced []*Device
	for _, d := range joined {
		if !bothWays(ctx, r, g, "away/P11/"+d.Name+"/sync/", d, timeout) {
			r.Skip("away/"+d.Name+"/rest", "it did not sync away from home (P11), so F6, P37, P36 and F7 leave it out")
			continue
		}
		synced = append(synced, d)
	}
	joined = synced
	if len(joined) == 0 {
		return
	}

	// F6: the hub's service stops; the away devices say the hub is
	// unreachable, and sync comes back once it runs again.
	if r.Do("away/F6/"+hub.Name+"/stop", func() error {
		_, err := Run(ctx, hub, serviceCmd(hub, "stop"), "")
		return err
	}) == nil {
		for _, d := range joined {
			r.Do("away/F6/"+d.Name+"/says", func() error {
				return eventually(ctx, 2*time.Minute, func() error {
					out, err := Run(ctx, d, cbbCmd(d)+" global", "")
					if err != nil {
						return err
					}
					if strings.Contains(out, "connected to the hub") {
						return fmt.Errorf("cbb global on %s still says it is connected: %q", d.Name, firstLine(out))
					}
					return nil
				})
			})
		}
		r.Do("away/F6/"+hub.Name+"/start", func() error {
			_, err := Run(context.WithoutCancel(ctx), hub, serviceCmd(hub, "start"), "")
			return err
		})
		for _, d := range joined {
			if r.Do("away/F6/"+d.Name+"/back", func() error { return globalShows(ctx, d, "connected to the hub", 3*time.Minute) }) == nil {
				bothWays(ctx, r, g, "away/F6/"+d.Name+"/sync/", d, timeout)
			}
		}
	}

	hubCases(ctx, r, g, fwd, joined, timeout)

	if stopForwarder {
		forwarderDown(ctx, r, g, fwd, joined, timeout)
	} else {
		r.Skip("away/F7", "stops the forwarder that others use; run with -stop-forwarder")
	}
	// Last, since it cuts the away devices off.
	for _, d := range joined {
		offAway(ctx, r, d)
	}
}

// offAway (P11, step 5): on a device that meets the hub only through the
// tunnel, cbb global off asks first, since its new keys would reach the
// hub only on the home network; turned off anyway and on again, it says it
// waits for the hub at home.
func offAway(ctx context.Context, r *Report, d *Device) {
	prefix := "away/P11/" + d.Name + "/off-on/"
	r.Do(prefix+"asks", func() error {
		_, err := Run(ctx, d, adminCmd(d)+" global off", "no\n")
		var re *RunError
		switch {
		case err == nil:
			return errors.New("cbb global off cut the device off without asking")
		case !errors.As(err, &re):
			return err
		case !strings.Contains(re.Output, "only through the tunnel"):
			return fmt.Errorf("cbb global off refused without saying why: %q", firstLine(re.Output))
		}
		return globalShows(ctx, d, "connected to the hub", 10*time.Second)
	})
	if r.Do(prefix+"off", func() error {
		_, err := Run(ctx, d, adminCmd(d)+" global off", "yes\n")
		return err
	}) != nil {
		return
	}
	r.Do(prefix+"on-waits", func() error {
		if _, err := Run(ctx, d, adminCmd(d)+" global on", "yes\n"); err != nil {
			return err
		}
		return globalShows(ctx, d, "on the home network", time.Minute)
	})
}

// forwarderDown (F7): with the forwarder stopped, the away devices say so
// and sync comes back once it runs again.
func forwarderDown(ctx context.Context, r *Report, g *benchGroup, fwd *Host, joined []*Device, timeout time.Duration) {
	if fwd.SSH == "" || fwd.Service == "" {
		r.Skip("away/F7", "needs ssh and service for [forwarder] in the inventory")
		return
	}
	host := &Device{Name: "forwarder", OS: "linux", SSH: fwd.SSH}
	if r.Do("away/F7/stop", func() error {
		_, err := Run(ctx, host, "sudo -n systemctl stop "+shellQuote(fwd.Service), "")
		return err
	}) != nil {
		return
	}
	for _, d := range joined {
		r.Do("away/F7/"+d.Name+"/says", func() error {
			return eventually(ctx, 3*time.Minute, func() error {
				out, err := Run(ctx, d, cbbCmd(d)+" global", "")
				if err != nil {
					return err
				}
				if !strings.Contains(out, "Problem:") && !strings.Contains(out, "not connected") {
					return fmt.Errorf("cbb global on %s does not say the hub is out of reach: %q", d.Name, firstLine(out))
				}
				return nil
			})
		})
	}
	r.Do("away/F7/start", func() error {
		_, err := Run(context.WithoutCancel(ctx), host, "sudo -n systemctl start "+shellQuote(fwd.Service), "")
		return err
	})
	for _, d := range joined {
		if r.Do("away/F7/"+d.Name+"/back", func() error { return globalShows(ctx, d, "connected to the hub", 3*time.Minute) }) == nil {
			bothWays(ctx, r, g, "away/F7/"+d.Name+"/sync/", d, timeout)
		}
	}
}

// bothWays copies on the hub and on d, and waits for each on the other. It
// reports whether both arrived.
func bothWays(ctx context.Context, r *Report, g *benchGroup, prefix string, d *Device, timeout time.Duration) bool {
	ok := true
	for _, p := range [][2]*Device{{g.hub, d}, {d, g.hub}} {
		from, to := p[0], p[1]
		text := fmt.Sprintf("cbb-bench %s %s from %s", g.run, strings.TrimSuffix(prefix, "/"), from.Name)
		if r.Do(prefix+from.Name+"/copy", func() error { return Copy(ctx, from, text) }) != nil ||
			r.Do(prefix+from.Name+"->"+to.Name, func() error { return arrives(ctx, to, seen(text, from, to), 2*timeout) }) != nil {
			ok = false
		}
	}
	return ok
}

func globalOff(ctx context.Context, r *Report, suite string, d *Device) {
	r.Do(suite+"/"+d.Name+"/global-off", func() error {
		_, err := Run(ctx, d, adminCmd(d)+" global off", "yes\n")
		return noSudo(d, err)
	})
}

// inviteJoin admits d from afar: cbb invite on the hub, the file copied to
// d over the controller, cbb pair -invite there, and yes on the hub once
// both sides show the same fingerprint.
func inviteJoin(ctx context.Context, g *benchGroup, d *Device) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	file := "/tmp/cbbbench-invite-" + g.run
	// cbb invite deletes the file when it ends, but not when the bench's
	// SSH session is cut.
	defer Run(context.WithoutCancel(ctx), g.hub, rootPrefix(g.hub)+"rm -f "+file, "")
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	var hubPrint string
	go func() {
		// The hub reads yes when the device asks; the answer waits on its
		// standard input until then.
		done <- StreamIn(ctx, g.hub, adminCmd(g.hub)+" invite -for 10m -o "+file, "yes\n", func(line string) {
			if strings.Contains(line, "cbb pair -invite") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
			if m := fingerprintRE.FindStringSubmatch(line); m != nil {
				hubPrint = m[1]
			}
		})
	}()
	select {
	case <-ready:
	case err := <-done:
		if err == nil {
			err = errors.New("cbb invite ended without an invitation")
		}
		return err
	case <-ctx.Done():
		return errors.New("cbb invite wrote no invitation")
	}
	invitation, err := Run(ctx, g.hub, rootPrefix(g.hub)+"cat "+file, "")
	if err != nil {
		return err
	}
	if _, err := Run(ctx, d, "umask 077 && cat > "+file, invitation); err != nil {
		return err
	}
	out, err := Run(ctx, d, adminCmd(d)+" pair -invite "+file, "yes\n")
	Run(context.WithoutCancel(ctx), d, "rm -f "+file, "")
	if err != nil {
		return noSudo(d, err)
	}
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("cbb invite on %s: %w", g.hub.Name, err)
		}
	case <-time.After(30 * time.Second):
		return fmt.Errorf("cbb invite on %s did not end after %s joined", g.hub.Name, d.Name)
	}
	if hubPrint == "" {
		return fmt.Errorf("cbb invite on %s showed no fingerprint", g.hub.Name)
	}
	if !strings.Contains(out, hubPrint) {
		return fmt.Errorf("%s does not show the fingerprint the hub showed (%s): %q", d.Name, hubPrint, firstLine(out))
	}
	return nil
}

// Relay (P12) meets the group at the blind relay instead of a hub: each
// member that can turns it on, sees the others there and syncs; a wrong key
// is refused and says so.
func Relay(ctx context.Context, r *Report, inv *Inventory, devices []*Device, timeout time.Duration) {
	rel := inv.Relay
	if rel == nil || rel.Address == "" || rel.Key == "" {
		r.Skip("relay/setup", "needs [relay] with address and key in the inventory")
		return
	}
	g := formGroup(ctx, r, "relay", devices)
	if g == nil {
		return
	}
	defer g.end(ctx, r)
	var met []*Device
	for _, d := range g.members {
		// The container has no sync away from home without keys in files,
		// and a build without the tunnel (MIPS) has none at all.
		if d.OS == "docker" || noTunnel(ctx, d) {
			continue
		}
		if r.Do("relay/P12/"+d.Name+"/on", func() error {
			// cbb global relay turns sync away from home on too; -yes agrees
			// to both.
			_, err := Run(ctx, d, adminCmd(d)+" global relay "+rel.Address+" -key "+rel.Key+" -yes", "")
			if err == nil {
				g.undo = append(g.undo, func() { globalOff(context.WithoutCancel(ctx), r, g.suite, d) })
			}
			return noSudo(d, err)
		}) == nil {
			met = append(met, d)
		}
	}
	if len(met) < 2 {
		r.Skip("relay/P12/meet", "needs two members that reach the relay")
		return
	}
	for _, d := range met {
		r.Do("relay/P12/"+d.Name+"/meets", func() error {
			return globalShows(ctx, d, "other devices of the group there", 2*time.Minute)
		})
	}
	for _, d := range met[1:] {
		g := *g
		g.hub = met[0]
		bothWays(ctx, r, &g, "relay/P12/sync/", d, timeout)
	}
	last := met[len(met)-1]
	r.Do("relay/P12/"+last.Name+"/wrong-key", func() error {
		wrong := strings.Repeat("A", 43) + "="
		if _, err := Run(ctx, last, adminCmd(last)+" global relay "+rel.Address+" -key "+wrong+" -yes", ""); err != nil {
			var re *RunError
			if errors.As(err, &re) && strings.Contains(strings.ToLower(re.Output), "key") {
				return nil
			}
			return err
		}
		return globalShows(ctx, last, "key", time.Minute)
	})
}
