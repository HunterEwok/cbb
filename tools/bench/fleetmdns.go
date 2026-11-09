// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// statusIDs is the device ID and the group tag that cbb status shows on d.
func statusIDs(ctx context.Context, d *Device) (id, tag string, err error) {
	out, err := Run(ctx, d, "cbb status", "")
	if err != nil {
		return "", "", err
	}
	m, g := deviceRE.FindStringSubmatch(out), groupRE.FindStringSubmatch(out)
	if m == nil || g == nil {
		return "", "", fmt.Errorf("cbb status on %s names no device or group: %q", d.Name, firstLine(out))
	}
	return m[1], g[1], nil
}

// mdnsRecords (D17, D3): what each member publishes and how the members
// take a record they browse. The forge browses beside them and publishes
// a member of its own: the members dial one of their group with the
// highest device ID, one with the lowest that publishes r=listen at once
// but one with the lowest that dials only after the fallback (D2), and
// neither a phone, which dials them, nor one of another group.
func mdnsRecords(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D17-mdns/"
	g := fleetGroup(ctx, r, f, "fleet/D17-mdns", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	var browser *Device
	var aID, bID, tag string
	if r.Do(p+"browser", func() error {
		var err error
		if aID, tag, err = statusIDs(ctx, a); err != nil {
			return err
		}
		if bID, _, err = statusIDs(ctx, b); err != nil {
			return err
		}
		browser, err = forgeServer(ctx, f, f.net, "-addr /tmp/mdns mdns-browse")
		return err
	}) != nil {
		return
	}
	// peers is what the forge's browsing found.
	peers := func() string {
		out, _ := Run(ctx, browser, "cat /tmp/mdns/peers 2>/dev/null; true", "")
		return out
	}
	lineOf := func(id string) string {
		for _, l := range strings.Split(peers(), "\n") {
			if strings.HasPrefix(l, id+" ") {
				return l
			}
		}
		return ""
	}
	r.Do("fleet/D17-txt", func() error {
		return eventually(ctx, 20*time.Second, func() error {
			for _, id := range []string{aID, bID} {
				l := lineOf(id)
				if l == "" {
					return fmt.Errorf("the browser does not find %s: %q", id, peers())
				}
				fields := strings.Fields(l)
				if fields[1] != "8764" {
					return fmt.Errorf("%s publishes the port %s, not 8764", id, fields[1])
				}
				if !strings.Contains(l, " v=1") || !strings.Contains(l, " g="+tag) {
					return fmt.Errorf("%s publishes %q, without v=1 and g=%s", id, l, tag)
				}
			}
			return nil
		})
	})
	events := func(what string) int {
		out, _ := Run(ctx, browser, "grep -c '^"+what+"$' /tmp/mdns/events; true", "")
		n := 0
		fmt.Sscan(out, &n)
		return n
	}
	r.Do("fleet/D17-goodbye-and-announce", func() error {
		// A stopped service says goodbye: its records go at once, not when
		// their time to live runs out. The container's loop, held until
		// then, starts it again, and it announces itself.
		gone, found := events("gone "+bID), events("found "+bID)
		if _, err := docker(ctx, "kill", "-s", "STOP", b.Container); err != nil {
			return err
		}
		defer docker(context.WithoutCancel(ctx), "kill", "-s", "CONT", b.Container)
		if _, err := Run(ctx, b, strings.ReplaceAll(fleetKill, "-KILL", "-TERM"), ""); err != nil {
			return err
		}
		if err := eventually(ctx, 5*time.Second, func() error {
			if events("gone "+bID) == gone {
				return fmt.Errorf("the browser did not lose %s when its service stopped", b.Name)
			}
			return nil
		}); err != nil {
			return err
		}
		if _, err := docker(ctx, "kill", "-s", "CONT", b.Container); err != nil {
			return err
		}
		return eventually(ctx, 10*time.Second, func() error {
			if events("found "+bID) == found {
				return fmt.Errorf("the browser did not find %s again after its service started", b.Name)
			}
			return nil
		})
	})
	// publish publishes the forge's member with txt for secs seconds and
	// returns the addresses that dialed it.
	publish := func(txt string, secs int) (string, error) {
		return RunFor(ctx, browser, fmt.Sprintf("cbbbench-forge mdns:%d:%s", secs, txt), "", time.Duration(secs+20)*time.Second)
	}
	// publishLow publishes it with the lowest device ID instead.
	publishLow := func(txt string, secs int) (string, error) {
		return RunFor(ctx, browser, fmt.Sprintf("cbbbench-forge mdns-low:%d:%s", secs, txt), "", time.Duration(secs+20)*time.Second)
	}
	dialedBy := func(out string, d *Device) (bool, error) {
		ip, err := fleetIP(ctx, d)
		return strings.Contains(out, "dialed from "+ip+"\n"), err
	}
	r.Do("fleet/D3-full-dialed", func() error {
		out, err := publish("v=1,g="+tag, 20)
		if err != nil {
			return err
		}
		for _, d := range []*Device{a, b} {
			if ok, err := dialedBy(out, d); err != nil || !ok {
				return fmt.Errorf("%s did not dial a full member of its group that it should dial (%v): %q", d.Name, err, out)
			}
		}
		return nil
	})
	// The forge's member has the lowest device ID here, so a member that
	// dials waits 30 s for it to dial (D2) unless it publishes r=listen:
	// within 15 s the members dial the listening one and not the other.
	r.Do("fleet/D3-listen-dialed", func() error {
		txt := "v=1,g=" + tag + ",r=listen"
		out, err := publishLow(txt, 15)
		if err != nil {
			return err
		}
		for _, d := range []*Device{a, b} {
			if ok, err := dialedBy(out, d); err != nil || !ok {
				return fmt.Errorf("%s did not dial a member of its group that publishes %s (%v): %q", d.Name, txt, err, out)
			}
		}
		return nil
	})
	r.Do("fleet/D3-low-dialing-waits", func() error {
		txt := "v=1,g=" + tag
		out, err := publishLow(txt, 15)
		if err != nil {
			return err
		}
		for _, d := range []*Device{a, b} {
			if ok, err := dialedBy(out, d); err != nil || ok {
				return fmt.Errorf("%s dialed a member with a lower device ID that publishes %s before the fallback (%v)", d.Name, txt, err)
			}
		}
		return nil
	})
	for _, c := range []struct{ name, txt string }{
		{"D3-phone-not-dialed", "v=1,g=" + tag + ",r=phone"},
		{"D17-other-group", "v=1,g=0123456789abcdef"},
	} {
		r.Do("fleet/"+c.name, func() error {
			out, err := publish(c.txt, 15)
			if err != nil {
				return err
			}
			for _, d := range []*Device{a, b} {
				if ok, err := dialedBy(out, d); err != nil || ok {
					return fmt.Errorf("%s dialed a member that publishes %s (%v)", d.Name, c.txt, err)
				}
			}
			return nil
		})
	}
}
