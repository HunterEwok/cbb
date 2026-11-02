// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The fleet's cases on the group's servers away from home: obfuscation, two
// groups on one forwarder, the blind relay and the servers' limits.

// comeHome connects the away device d to the home network as well, and
// leaveHome takes it off again.
func comeHome(ctx context.Context, f *Fleet, d *Device) error {
	_, err := docker(ctx, "network", "connect", f.net, d.Container)
	return err
}

func leaveHome(ctx context.Context, f *Fleet, d *Device) error {
	_, err := docker(context.WithoutCancel(ctx), "network", "disconnect", f.net, d.Container)
	return err
}

// moveTo moves d from its network to net for good, as a computer taken
// from home to another place.
func moveTo(ctx context.Context, d *Device, net string) error {
	if _, err := docker(ctx, "network", "connect", net, d.Container); err != nil {
		return err
	}
	if _, err := docker(ctx, "network", "disconnect", d.Network, d.Container); err != nil {
		return err
	}
	d.Network = net
	return nil
}

// countWireGuard makes the router count, among the UDP packets it passes,
// those that start like a WireGuard message (a type of 1 to 4 and three
// zero bytes) and those of the size of a WireGuard handshake (W35).
func (in *internet) countWireGuard(ctx context.Context) error {
	_, err := Run(ctx, in.router, strings.Join([]string{
		"iptables -N cbbwg",
		// Rules with no target only count.
		// The word, read big-endian, is exactly one of WireGuard's four
		// types in little-endian: a range would also take a random first
		// word now and then.
		`iptables -A cbbwg -p udp -m u32 --u32 "0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000"`,
		"iptables -A cbbwg -p udp -m length --length 176",
		"iptables -A cbbwg -p udp -m length --length 120",
		"iptables -I FORWARD -j cbbwg",
	}, " && "), "")
	return err
}

// wireGuardSeen returns what countWireGuard counted since zeroWireGuard:
// the packets that start like WireGuard, and those of a handshake's size.
func (in *internet) wireGuardSeen(ctx context.Context) (starts, sized int, err error) {
	out, err := Run(ctx, in.router, "iptables -L cbbwg -v -x -n --line-numbers", "")
	if err != nil {
		return 0, 0, err
	}
	var n []int
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if _, err := strconv.Atoi(f0(f)); err == nil && len(f) > 1 {
			v, err := strconv.Atoi(f[1])
			if err != nil {
				return 0, 0, err
			}
			n = append(n, v)
		}
	}
	if len(n) != 3 {
		return 0, 0, fmt.Errorf("the router's counters: %q", out)
	}
	return n[0], n[1] + n[2], nil
}

func f0(f []string) string {
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func (in *internet) zeroWireGuard(ctx context.Context) error {
	_, err := Run(ctx, in.router, "iptables -Z cbbwg", "")
	return err
}

// noWireGuard fails when the router saw anything that starts like
// WireGuard. The handshake's sizes count only in plain WireGuard: an
// obfuscated data message can have them by chance, its padding being one
// fixed size for the group.
func (in *internet) noWireGuard(ctx context.Context) error {
	starts, _, err := in.wireGuardSeen(ctx)
	if err == nil && starts > 0 {
		out, _ := Run(ctx, in.router, "iptables -L cbbwg -v -x -n", "")
		err = fmt.Errorf("the router passed %d packets that start like WireGuard: %s", starts, out)
	}
	return err
}

// obfuscation (W18, W35): plain WireGuard is seen on the wire, which shows
// the count works; once the hub obfuscates its tunnel, a client that has
// not met it since cannot reach it away from home until it comes home, and
// after that nothing on the wire starts or is sized like WireGuard,
// directly and through the forwarder.
func obfuscation(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W18-obfuscation/"
	a := newAwayGroup(ctx, r, f, "fleet/W18-obfuscation", 1)
	if a == nil {
		return
	}
	hub := a.hub
	// Counting from before the client's first handshake.
	if r.Do(p+"count", func() error { return a.in.countWireGuard(ctx) }) != nil {
		return
	}
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	wait := 3 * time.Minute
	if r.Do("fleet/W35-plain-seen", func() error {
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, c, "plain", 2*timeout); err != nil {
			return err
		}
		starts, sized, err := a.in.wireGuardSeen(ctx)
		if err == nil && (starts == 0 || sized == 0) {
			err = fmt.Errorf("the router saw %d packets that start like WireGuard and %d of a handshake's size in plain WireGuard; the count does not work", starts, sized)
		}
		return err
	}) != nil {
		return
	}
	r.Do("fleet/W18-not-away", func() error {
		if _, err := Run(ctx, hub, a.hubCmd(hubPublic, a.fwdKey, "-obfuscate"), ""); err != nil {
			return err
		}
		if err := cutOff(ctx, c, wait); err != nil {
			return err
		}
		// It keeps trying the hub's old way, which no longer answers.
		time.Sleep(90 * time.Second)
		out, err := Run(ctx, c, "cbb global", "")
		if err == nil && strings.Contains(out, "connected to the hub") {
			err = fmt.Errorf("%s reached the obfuscated hub without coming home: %q", c.Name, firstLine(out))
		}
		return err
	})
	if r.Do("fleet/W18-home", func() error {
		if err := comeHome(ctx, f, c); err != nil {
			return err
		}
		// A network where it never met its group: it finds the hub there
		// before it shows itself.
		err := syncs(ctx, a.benchGroup, hub, c, "at home", 2*time.Minute)
		// The hub's offer comes with the connection at home.
		time.Sleep(10 * time.Second)
		if err := a.in.zeroWireGuard(ctx); err != nil {
			return err
		}
		if err := leaveHome(ctx, f, c); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, c, hub, "obfuscated", 2*timeout)
	}) != nil {
		return
	}
	r.Do("fleet/W35-direct", func() error { return a.in.noWireGuard(ctx) })
	r.Do("fleet/W35-forwarder", func() error {
		if err := a.in.block(ctx, hubPublic, "udp"); err != nil {
			return err
		}
		defer a.in.unblock(ctx, hubPublic, "udp")
		if err := cutOff(ctx, c, wait); err != nil {
			return err
		}
		if err := a.in.zeroWireGuard(ctx); err != nil {
			return err
		}
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, c, "obfuscated through the forwarder", 2*timeout); err != nil {
			return err
		}
		return a.in.noWireGuard(ctx)
	})
}

// twoGroupsAway (W33, S8): two groups whose hubs register with one
// forwarder sync each on its own; a member of one, with the other group's
// offer, gets no answer from that hub, directly or through the forwarder;
// the forwarder keeps no name, device ID or tag of either.
func twoGroupsAway(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W33-two-groups/"
	a := newAwayGroup(ctx, r, f, "fleet/W33-a", 1)
	if a == nil {
		return
	}
	b := a.another(ctx, r, "fleet/W33-b", 1, hubPublic2)
	if b == nil {
		return
	}
	ca := a.join(ctx, r, p+"a-invited")
	cb := b.join(ctx, r, p+"b-invited")
	if ca == nil || cb == nil {
		return
	}
	wait := 3 * time.Minute
	r.Do("fleet/W33-each-syncs", func() error {
		for _, c := range []*Device{ca, cb} {
			if err := connected(ctx, c, wait); err != nil {
				return err
			}
		}
		if err := syncs(ctx, b.benchGroup, b.hub, cb, "in b", 2*timeout); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, ca, a.hub, "in a", 2*timeout); err != nil {
			return err
		}
		time.Sleep(5 * time.Second)
		got, err := Paste(ctx, cb)
		if err == nil && strings.Contains(got, "in a") {
			err = fmt.Errorf("%s of the other group got %q", cb.Name, got)
		}
		return err
	})
	r.Do("fleet/W33-apart", func() error {
		h, err := forgeHostOn(ctx, f, a.away, ca, cb)
		if err != nil {
			return err
		}
		defer a.start(context.WithoutCancel(ctx), ca)
		if err := a.in.reach(ctx, h); err != nil {
			return err
		}
		forge := func(args string) (string, error) {
			return RunFor(ctx, h, "cbbbench-forge -state /tmp/"+ca.Name+" "+args, "", 3*time.Minute)
		}
		// The probe reaches its own hub, which shows that it works.
		if out, err := forge("member"); err != nil || !strings.Contains(out, "member: answered") {
			return fmt.Errorf("the forge did not reach its own hub: %q: %v", out, err)
		}
		var errs []error
		for _, ep := range []string{"", "-endpoint " + fwdPublic + ":8764 "} {
			out, err := forge(ep + "-hub-state /tmp/" + cb.Name + " member")
			if err != nil || !strings.Contains(out, "member: no answer") {
				errs = append(errs, fmt.Errorf("a member of a with b's offer (%s): %q: %v", strings.TrimSpace(ep), out, err))
			}
		}
		return errors.Join(errs...)
	})
	r.Do("fleet/S8-forwarder-learns-little", func() error {
		var secrets []string
		for _, g := range []*awayGroup{a, b} {
			secrets = append(secrets, g.tag)
			for _, d := range g.members {
				id, err := deviceOf(ctx, d)
				if err != nil {
					return err
				}
				secrets = append(secrets, id)
			}
		}
		var errs []error
		for _, s := range secrets {
			if s == "" {
				continue
			}
			if out, _ := Run(ctx, a.fwd, "grep -rlF "+shellQuote(s)+" "+fwdState+" || true", ""); strings.TrimSpace(out) != "" {
				errs = append(errs, fmt.Errorf("the forwarder keeps %s in %s", s, strings.TrimSpace(out)))
			}
		}
		return errors.Join(errs...)
	})
}

// relayState is where the fleet's relay keeps its keys and log.
const relayState = "/var/lib/cbbrelay"

// startRelay starts cbb relay with flags on the network net and returns it
// and its key.
func startRelay(ctx context.Context, f *Fleet, net, flags string) (*Device, string, error) {
	keyFile := relayState + "/relay.pem"
	d, err := f.addServer(ctx, net, nil, "mkdir -p "+relayState+" && exec cbb relay -key "+keyFile+" "+flags+" >>"+relayState+"/log 2>&1")
	if err != nil {
		return nil, "", err
	}
	var key string
	err = eventually(ctx, 20*time.Second, func() error {
		out, err := Run(ctx, d, "test -s "+keyFile+" && cbb relay -key "+keyFile+" -show-key", "")
		key = strings.TrimSpace(out)
		return err
	})
	return d, key, err
}

// relayAway (W36, W37): a group without a hub meets at the blind relay, one
// member at home and two on networks of their own; it syncs, also after the
// relay and a member restart; a wrong key is refused and says so; a removed
// device's copies reach nobody.
func relayAway(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W36-relay/"
	g := fleetGroup(ctx, r, f, "fleet/W36-relay", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	home, m2, m3 := g.members[0], g.members[1], g.members[2]
	var rel *Device
	var key string
	var relIn *internet
	if r.Do(p+"setup", func() error {
		var nets []string
		for range 3 {
			n, err := f.Network(ctx)
			if err != nil {
				return err
			}
			nets = append(nets, n)
		}
		in, err := newInternet(ctx, f, append([]string{f.net}, nets...)...)
		if err != nil {
			return err
		}
		// The relay logs the most with CBB_DEBUG=1, which only adds
		// counts; a restart keeps it.
		f.serverEnv = []string{"CBB_DEBUG=1"}
		rel, key, err = startRelay(ctx, f, nets[2], "-group "+g.tag)
		f.serverEnv = nil
		if err != nil {
			return err
		}
		relIn = in
		if err := in.publish(ctx, relayPublic, rel); err != nil {
			return err
		}
		for i, d := range []*Device{m2, m3} {
			if err := moveTo(ctx, d, nets[i]); err != nil {
				return err
			}
		}
		for _, d := range g.members {
			if err := in.reach(ctx, d); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	on := func(d *Device, key string) error {
		_, err := Run(ctx, d, "cbb global relay "+relayPublic+":8764 -key "+key+" -yes", "")
		return err
	}
	meet := func() error {
		for _, d := range g.members {
			if err := globalShows(ctx, d, "; connected to the relay", 2*time.Minute); err != nil {
				return err
			}
		}
		return nil
	}
	if r.Do("fleet/W36-meet", func() error {
		for _, d := range g.members {
			if err := on(d, key); err != nil {
				return err
			}
		}
		return meet()
	}) != nil {
		return
	}
	r.Do("fleet/W36-sync", func() error {
		for _, pair := range [][2]*Device{{m2, m3}, {m3, home}, {home, m2}} {
			if err := syncs(ctx, g, pair[0], pair[1], "through the relay from "+pair[0].Name, 2*timeout); err != nil {
				return err
			}
		}
		return nil
	})
	r.Do("fleet/W36-relay-restarted", func() error {
		if _, err := docker(ctx, "restart", "-t", "1", rel.Container); err != nil {
			return err
		}
		if err := meet(); err != nil {
			return err
		}
		return syncs(ctx, g, m3, m2, "after the relay restarted", 2*timeout)
	})
	r.Do("fleet/W36-member-restarted", func() error {
		if _, err := Run(ctx, m2, fleetKill, ""); err != nil {
			return err
		}
		time.Sleep(3 * time.Second)
		if err := globalShows(ctx, m2, "; connected to the relay", 2*time.Minute); err != nil {
			return err
		}
		return syncs(ctx, g, m2, m3, "after the member restarted", 2*timeout)
	})
	r.Do("fleet/W36-wrong-key", func() error {
		err := on(m3, strings.Repeat("A", 43)+"=")
		var re *RunError
		switch {
		case err != nil && errors.As(err, &re) && strings.Contains(strings.ToLower(re.Output), "key"):
		case err != nil:
			return err
		default:
			if err := globalShows(ctx, m3, "key", time.Minute); err != nil {
				return err
			}
		}
		if err := on(m3, key); err != nil {
			return err
		}
		return globalShows(ctx, m3, "; connected to the relay", 2*time.Minute)
	})
	r.Do("fleet/W37-removed", func() error {
		if _, err := Run(ctx, home, "cbb remove "+m3.Name, ""); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{m2}, m3.Name, "", true, timeout); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " from a removed device"
		if err := Copy(ctx, m3, text); err != nil {
			return err
		}
		time.Sleep(15 * time.Second)
		got, err := Paste(ctx, m2)
		if err == nil && strings.Contains(got, text) {
			err = fmt.Errorf("%s got the removed device's copy", m2.Name)
		}
		return err
	})
	r.Do("fleet/S18-relay-keeps-nothing", func() error {
		words := []string{g.run, g.tag}
		for _, d := range g.members {
			id, _, err := statusIDs(ctx, d)
			if err != nil {
				return err
			}
			ip, err := fleetIP(ctx, d)
			if err != nil {
				return err
			}
			words = append(words, id, ip)
		}
		for _, ip := range relIn.ips {
			words = append(words, ip)
		}
		return serverKeepsNothing(ctx, rel, relayState, []string{"relay.pem"}, words)
	})
}

// relayLimits (W38): an open relay takes 16 registrations from one
// address; the group's 17th device, behind the same router, is refused and
// says so.
func relayLimits(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W38-relay-limits/"
	const n = 17
	g := fleetGroup(ctx, r, f, "fleet/W38-relay-limits", n)
	if g == nil || len(g.members) < n {
		return
	}
	var key string
	if r.Do(p+"setup", func() error {
		servers, err := f.Network(ctx)
		if err != nil {
			return err
		}
		in, err := newInternet(ctx, f, f.net, servers)
		if err != nil {
			return err
		}
		var rel *Device
		if rel, key, err = startRelay(ctx, f, servers, "-open"); err != nil {
			return err
		}
		if err := in.publish(ctx, relayPublic, rel); err != nil {
			return err
		}
		for _, d := range g.members {
			if err := in.reach(ctx, d); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	r.Do("fleet/W38-per-address", func() error {
		for _, d := range g.members {
			if _, err := Run(ctx, d, "cbb global relay "+relayPublic+":8764 -key "+key+" -yes", ""); err != nil {
				return err
			}
		}
		return eventually(ctx, 3*time.Minute, func() error {
			var on, refused int
			var last string
			for _, d := range g.members {
				out, err := Run(ctx, d, "cbb global", "")
				if err != nil {
					return err
				}
				switch {
				case strings.Contains(out, "; connected to the relay"):
					on++
				case strings.Contains(out, "not connected to the relay"):
					refused++
					last = firstLine(out)
				}
			}
			if on != 16 || refused != 1 {
				return fmt.Errorf("%d devices are connected to the relay and %d say why not (%q), not 16 and 1", on, refused, last)
			}
			return nil
		})
	})
}

// hubLoad (E6, W32): 16 clients away, each copying in turn, and the hub's
// CPU and memory meanwhile; with the hub's own address blocked they all
// come in through the forwarder, which takes 16 clients of a group and no
// 17th.
func hubLoad(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/E6-hub-load/"
	a := newAwayGroup(ctx, r, f, "fleet/E6-hub-load", 1)
	if a == nil {
		return
	}
	hub := a.hub
	var clients []*Device
	for i := range 17 {
		c := a.join(ctx, r, fmt.Sprintf("%sc%02d-invited", p, i+1))
		if c == nil {
			return
		}
		clients = append(clients, c)
	}
	extra, clients := clients[16], clients[:16]
	wait := 3 * time.Minute
	if r.Do("fleet/E6-sixteen-copy", func() error {
		if err := f.stop(ctx, extra); err != nil {
			return err
		}
		for _, c := range clients {
			if err := connected(ctx, c, wait); err != nil {
				return err
			}
		}
		for i, c := range clients {
			text := fmt.Sprintf("cbb-bench %s load %d from %s", a.run, i, c.Name)
			if err := Copy(ctx, c, text); err != nil {
				return err
			}
			if err := arrives(ctx, hub, text, 2*timeout); err != nil {
				return err
			}
		}
		// The last copy reaches every other client.
		last := fmt.Sprintf("cbb-bench %s load %d from %s", a.run, len(clients)-1, clients[len(clients)-1].Name)
		for _, c := range clients[:len(clients)-1] {
			if err := arrives(ctx, c, last, 2*timeout); err != nil {
				return err
			}
		}
		out, err := docker(ctx, "stats", "--no-stream", "--format", "{{.CPUPerc}} CPU, {{.MemUsage}}", hub.Container)
		if err == nil {
			fmt.Fprintf(r.out, "E6: the hub with 16 clients: %s\n", strings.TrimSpace(out))
		}
		return err
	}) != nil {
		return
	}
	r.Do("fleet/W32-sixteen-through-forwarder", func() error {
		if err := a.in.block(ctx, hubPublic, "udp"); err != nil {
			return err
		}
		for _, c := range clients {
			if err := cutOff(ctx, c, wait); err != nil {
				return err
			}
		}
		for _, c := range clients {
			if err := connected(ctx, c, wait); err != nil {
				return err
			}
		}
		return syncs(ctx, a.benchGroup, hub, clients[0], "16 through the forwarder", 2*timeout)
	})
	r.Do("fleet/W32-no-seventeenth", func() error {
		if err := a.start(ctx, extra); err != nil {
			return err
		}
		time.Sleep(2 * time.Minute)
		out, err := Run(ctx, extra, "cbb global", "")
		if err == nil && strings.Contains(out, "connected to the hub") {
			err = fmt.Errorf("a 17th client came in through the forwarder: %q", firstLine(out))
		}
		return err
	})
}

// vlessAway (W34): a forwarder that takes VLESS with REALITY too, borrowing
// the TLS of a stand-in for a well-known site; once the hub says its
// clients reach it only over VLESS, a client away syncs with every UDP
// packet from its network to the internet dropped, and anyone who is not a client gets the
// borrowed site.
func vlessAway(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W34-vless/"
	a := newAwayGroupWith(ctx, r, f, "fleet/W34-vless", 1, true)
	if a == nil {
		return
	}
	hub := a.hub
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	wait := 3 * time.Minute
	if r.Do("fleet/W34-vless-only", func() error {
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		if err := succeeds(ctx, hub, a.hubCmd(hubPublic, a.fwdKey, "-vless"), "", "VLESS"); err != nil {
			return err
		}
		// The new offer reaches the client through the tunnel.
		if err := globalShows(ctx, c, "VLESS", wait); err != nil {
			return err
		}
		for _, pub := range []string{hubPublic, fwdPublic} {
			// From the client's network: the hub and the forwarder still
			// talk over UDP.
			if err := a.in.blockFrom(ctx, a.away, pub, "udp"); err != nil {
				return err
			}
		}
		// With the offer the client goes over VLESS alone: the tunnel
		// stays up, or comes back, with no UDP between it and the
		// servers.
		time.Sleep(30 * time.Second)
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, c, hub, "over VLESS", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, hub, c, "back over VLESS", 2*timeout)
	}) != nil {
		return
	}
	r.Do("fleet/W34-borrowed-site", func() error {
		v, err := f.AddOn(ctx, a.away)
		if err != nil {
			return err
		}
		if err := a.in.reach(ctx, v); err != nil {
			return err
		}
		out, err := Run(ctx, v, "curl -sk --max-time 10 --resolve "+siteName+":443:"+fwdPublic+" https://"+siteName+"/", "")
		if err == nil && !strings.Contains(out, "cbb-bench borrowed site") {
			err = fmt.Errorf("a visitor of the forwarder's port got %q, not the borrowed site", firstLine(out))
		}
		return err
	})
}
