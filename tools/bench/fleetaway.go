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

// Sync away from home in the fleet (W, S3–S5, S8): the group's home
// network, an away network and a network of servers, joined only by a
// router that stands in for the internet.

// The public addresses of the fleet's internet, from TEST-NET-3.
const (
	publicNet   = "203.0.113.0/24"
	hubPublic   = "203.0.113.10"
	hubPublic2  = "203.0.113.11"
	fwdPublic   = "203.0.113.20"
	relayPublic = "203.0.113.30"
)

// internet stands in for the internet between the fleet's networks: a
// router on each of them that owns the public addresses, passes each to a
// container behind it as a home router forwards a port, and masquerades
// whatever it passes, so that each side sees only the router. Docker drops
// a packet for a container's address that comes from another network,
// which a router of the fleet's own avoids.
type internet struct {
	router *Device
	ips    map[string]string // the router's address on each network
}

// newInternet starts the router on the networks nets.
func newInternet(ctx context.Context, f *Fleet, nets ...string) (*internet, error) {
	rt, err := f.addServer(ctx, nets[0], []string{"--sysctl", "net.ipv4.ip_forward=1"}, "exec sleep infinity")
	if err != nil {
		return nil, err
	}
	in := &internet{router: rt, ips: map[string]string{}}
	for i, n := range nets {
		if i > 0 {
			if _, err := docker(ctx, "network", "connect", n, rt.Container); err != nil {
				return nil, err
			}
		}
		if in.ips[n], err = fleetIPOn(ctx, rt, n); err != nil {
			return nil, err
		}
	}
	_, err = Run(ctx, rt, "iptables -t nat -A POSTROUTING -j MASQUERADE", "")
	return in, err
}

// reach lets d reach the public addresses through the router on d's
// network.
func (in *internet) reach(ctx context.Context, d *Device) error {
	ip, ok := in.ips[d.Network]
	if !ok {
		return fmt.Errorf("the internet's router is not on %s's network", d.Name)
	}
	_, err := Run(ctx, d, "ip route replace "+publicNet+" via "+ip, "")
	return err
}

// publish passes the public address pub to d, in place of whatever it
// passed it to before.
func (in *internet) publish(ctx context.Context, pub string, d *Device) error {
	ip, err := fleetIPOn(ctx, d, d.Network)
	if err != nil {
		return err
	}
	if _, err := Run(ctx, in.router, "iptables -t nat -I PREROUTING -d "+pub+" -j DNAT --to-destination "+ip, ""); err != nil {
		return err
	}
	return in.reach(ctx, d)
}

// block drops every packet to the public address pub, or only those of
// proto (udp, tcp), as a network that blocks it; unblock takes it back.
// It drops them before the address is passed on, so that a flow already
// passed stops too.
func (in *internet) block(ctx context.Context, pub, proto string) error {
	_, err := Run(ctx, in.router, "iptables -t mangle -I PREROUTING "+blockRule(pub, proto, ""), "")
	return err
}

func (in *internet) unblock(ctx context.Context, pub, proto string) error {
	_, err := Run(context.WithoutCancel(ctx), in.router, "iptables -t mangle -D PREROUTING "+blockRule(pub, proto, ""), "")
	return err
}

// blockFrom is block for the packets that come from the network net only,
// as the network of a place away from home that blocks them.
func (in *internet) blockFrom(ctx context.Context, net, pub, proto string) error {
	subnet, err := docker(ctx, "network", "inspect", "-f", "{{(index .IPAM.Config 0).Subnet}}", net)
	if err != nil {
		return err
	}
	_, err = Run(ctx, in.router, "iptables -t mangle -I PREROUTING "+blockRule(pub, proto, strings.TrimSpace(subnet)), "")
	return err
}

func blockRule(pub, proto, from string) string {
	rule := "-d " + pub
	if from != "" {
		rule = "-s " + from + " " + rule
	}
	if proto != "" {
		rule += " -p " + proto
	}
	return rule + " -j DROP"
}

// awayGroup is a group whose hub is reached from the fleet's internet,
// directly and through a forwarder on the servers' network.
type awayGroup struct {
	*benchGroup
	f      *Fleet
	in     *internet
	away   string // the away network
	fwd    *Device
	fwdKey string
}

// fwdState is where the fleet's forwarder keeps its key.
const fwdState = "/var/lib/cbbforward"

// newAwayGroup forms a group of n members at home, the first its hub, the
// internet, and a forwarder the hub registers with.
func newAwayGroup(ctx context.Context, r *Report, f *Fleet, suite string, n int) *awayGroup {
	return newAwayGroupWith(ctx, r, f, suite, n, noVLESS)
}

// siteName is the well-known site whose TLS the fleet's forwarder borrows
// for VLESS; the forge plays it on the servers' network.
const siteName = "www.example.com"

// The ways a fleet's forwarder takes VLESS: none, with REALITY borrowing
// the site's TLS, or over XHTTP behind a web server of its own.
const (
	noVLESS = iota
	realityVLESS
	xhttpVLESS
)

// The XHTTP forwarder's site, the path its web server passes, and where
// that web server keeps its CA, on the forwarder.
const (
	xhttpName = "xhttp.bench.example"
	xhttpPath = "/cbbbenchxhttp01"
	xhttpCA   = "/tmp/web-ca.pem"
	// The mirror of the releases on the forwarder's server, which its
	// VLESS clients reach for their updates, and its counts.
	mirrorAddr = "127.0.0.1:8443"
	mirrorHits = "/tmp/mirror.hits"
	xhttpHits  = "/tmp/web.hits"
)

// newAwayGroupWith is newAwayGroup, with a forwarder that takes VLESS too
// in the way vless names.
func newAwayGroupWith(ctx context.Context, r *Report, f *Fleet, suite string, n int, vless int) *awayGroup {
	a := &awayGroup{f: f}
	if r.Do(suite+"/internet", func() error {
		var err error
		if a.away, err = f.Network(ctx); err != nil {
			return err
		}
		servers, err := f.Network(ctx)
		if err != nil {
			return err
		}
		if a.in, err = newInternet(ctx, f, f.net, a.away, servers); err != nil {
			return err
		}
		var run []string
		flags := ""
		switch vless {
		case xhttpVLESS:
			flags = "-vless-xhttp " + xhttpName + " -vless-path " + xhttpPath + " -vless-mirror " + mirrorAddr
		case realityVLESS:
			site, err := forgeServer(ctx, f, servers, "-addr :443 site:"+siteName)
			if err != nil {
				return err
			}
			ip, err := fleetIPOn(ctx, site, servers)
			if err != nil {
				return err
			}
			run, flags = []string{"--add-host", siteName + ":" + ip}, "-vless-site "+siteName
		}
		if a.fwd, a.fwdKey, err = startForwarder(ctx, f, servers, run, flags); err != nil {
			return err
		}
		if vless == xhttpVLESS {
			if _, err := forgeOn(ctx, a.fwd); err != nil {
				return err
			}
			if err := a.startWeb(ctx); err != nil {
				return err
			}
		}
		return a.in.publish(ctx, fwdPublic, a.fwd)
	}) != nil {
		return nil
	}
	return a.another(ctx, r, suite, n, hubPublic)
}

// startWeb starts the web server of the XHTTP forwarder, at its address,
// which passes the path to it, and the stand-in for the mirror of the
// releases (dl.cbb.tools) beside it, with the same CA; forgeOn must have
// put forge there.
func (a *awayGroup) startWeb(ctx context.Context) error {
	for _, args := range [][]string{
		{"-addr", ":443", "web:" + xhttpName + "," + xhttpPath + ",127.0.0.1:3276," + xhttpCA + "," + xhttpHits},
		{"-addr", mirrorAddr, "web:dl.cbb.tools,/,-," + xhttpCA + "," + mirrorHits},
	} {
		if _, err := docker(ctx, append([]string{"exec", "-d", a.fwd.Container, "/usr/local/bin/cbbbench-forge"}, args...)...); err != nil {
			return err
		}
		// The second takes the CA the first made.
		if err := eventually(ctx, 20*time.Second, func() error {
			_, err := Run(ctx, a.fwd, "test -s "+xhttpCA, "")
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// another forms another group of n members at home whose hub is reached
// at the public address pub, on the same internet and forwarder as a.
func (a *awayGroup) another(ctx context.Context, r *Report, suite string, n int, pub string, more ...string) *awayGroup {
	g := fleetGroup(ctx, r, a.f, suite, n)
	if g == nil || len(g.members) < n {
		return nil
	}
	b := *a
	b.benchGroup = g
	if r.Do(suite+"/hub", func() error {
		if err := b.in.publish(ctx, pub, g.hub); err != nil {
			return err
		}
		if _, err := Run(ctx, g.hub, "cbb global on", "yes\n"); err != nil {
			return err
		}
		if _, err := Run(ctx, g.hub, b.hubCmd(pub, b.fwdKey, more...), ""); err != nil {
			return err
		}
		return globalShows(ctx, g.hub, "Registered with the forwarder at "+fwdPublic, time.Minute)
	}) != nil {
		return nil
	}
	return &b
}

// hubCmd is cbb global hub at the public address pub, with the forwarder
// pinned by key.
func (a *awayGroup) hubCmd(pub, key string, more ...string) string {
	return strings.Join(append([]string{"cbb global hub -firewall no -forwarder", fwdPublic + ":8764", "-forwarder-key", key}, append(more, pub+":8764")...), " ")
}

// startForwarder starts cbb forward on the network net, with more
// arguments for docker run and more flags,
// and returns it and its key.
func startForwarder(ctx context.Context, f *Fleet, net string, run []string, flags string) (*Device, string, error) {
	d, err := f.addServer(ctx, net, run, "mkdir -p "+fwdState+" && exec cbb forward -key "+fwdState+"/forwarder.pem "+flags+" >>"+fwdState+"/log 2>&1")
	if err != nil {
		return nil, "", err
	}
	var key string
	err = eventually(ctx, 20*time.Second, func() error {
		if _, err := Run(ctx, d, "grep -q 'listening on' "+fwdState+"/log", ""); err != nil {
			return errors.New("cbb forward did not start")
		}
		out, err := Run(ctx, d, "cbb forward -key "+fwdState+"/forwarder.pem -show-key", "")
		key = strings.TrimSpace(out)
		return err
	})
	return d, key, err
}

// join admits a new member on the away network by invitation, as P11 does
// on the real devices.
func (a *awayGroup) join(ctx context.Context, r *Report, name string) *Device {
	var d *Device
	if r.Do(name, func() error {
		var err error
		if d, err = a.f.AddOn(ctx, a.away); err != nil {
			return err
		}
		if err := a.in.reach(ctx, d); err != nil {
			return err
		}
		if err := inviteJoin(ctx, a.benchGroup, d); err != nil {
			return err
		}
		a.members = append(a.members, d)
		return shareClipboard(ctx, d)
	}) != nil {
		return nil
	}
	return d
}

// start starts a stopped member again: its container's network comes back
// without the route to the internet, which it gets again.
func (a *awayGroup) start(ctx context.Context, d *Device) error {
	if err := a.f.start(ctx, d); err != nil {
		return err
	}
	return a.in.reach(ctx, d)
}

// connected waits until d says it is connected to the hub through the
// tunnel.
func connected(ctx context.Context, d *Device, timeout time.Duration) error {
	return globalShows(ctx, d, "connected to the hub", timeout)
}

// cutOff waits until d no longer says it is connected to the hub.
func cutOff(ctx context.Context, d *Device, timeout time.Duration) error {
	return eventually(ctx, timeout, func() error {
		out, err := Run(ctx, d, "cbb global", "")
		if err != nil {
			return err
		}
		if strings.Contains(out, "connected to the hub") {
			return fmt.Errorf("cbb global on %s still says it is connected: %q", d.Name, firstLine(out))
		}
		return nil
	})
}

// watchOut counts on d each packet that leaves for anywhere but its own
// network, multicast and the group's servers, which are the public
// addresses here (W3).
func watchOut(ctx context.Context, d *Device) error {
	subnet, err := docker(ctx, "network", "inspect", "-f", "{{(index .IPAM.Config 0).Subnet}}", d.Network)
	if err != nil {
		return err
	}
	_, err = Run(ctx, d, strings.Join([]string{
		"iptables -N cbbout",
		"iptables -A cbbout -o lo -j RETURN",
		"iptables -A cbbout -d " + publicNet + " -j RETURN",
		"iptables -A cbbout -d " + strings.TrimSpace(subnet) + " -j RETURN",
		"iptables -A cbbout -d 224.0.0.0/4 -j RETURN",
		"iptables -A cbbout -d 255.255.255.255 -j RETURN",
		"iptables -A cbbout -j RETURN",
		"iptables -I OUTPUT -j cbbout",
	}, " && "), "")
	return err
}

// outElsewhere is the number of packets watchOut counted.
func outElsewhere(ctx context.Context, d *Device) (int, error) {
	out, err := Run(ctx, d, "iptables -L cbbout -v -x -n | tail -1", "")
	if err != nil {
		return 0, err
	}
	f := strings.Fields(out)
	if len(f) == 0 {
		return 0, fmt.Errorf("no counter on %s: %q", d.Name, out)
	}
	return strconv.Atoi(f[0])
}

// forgeTunnel runs the forge's tunnel cases on h as m, whose state it
// holds, to m's hub at endpoint, or at the hub's first address when it is
// empty.
func forgeTunnel(ctx context.Context, h, m *Device, endpoint string, cases ...string) (string, error) {
	cmd := "cbbbench-forge -state /tmp/" + m.Name
	if endpoint != "" {
		cmd += " -endpoint " + endpoint
	}
	return RunFor(ctx, h, cmd+" "+strings.Join(cases, " "), "", 3*time.Minute)
}

// awayHub (W3, W4, W10, W11, W13, W19, W20, W31, S3, S4, S5): two members
// away from home join by invitation and sync through the hub, directly and
// through the forwarder; a client's tunnel reaches only the hub's member
// port, a stranger's key gets no answer; the hub's address changes, the hub
// hangs and stops, the forwarder restarts and is pinned with a wrong key;
// meanwhile nothing leaves a client for anywhere but the group's servers.
func awayHub(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W4-away/"
	a := newAwayGroup(ctx, r, f, "fleet/W4-away", 2)
	if a == nil {
		return
	}
	hub, m := a.hub, a.members[1]
	c1 := a.join(ctx, r, p+"c1-invited")
	c2 := a.join(ctx, r, p+"c2-invited")
	if c1 == nil || c2 == nil {
		return
	}
	wait := 3 * time.Minute
	if r.Do("fleet/W10-direct", func() error {
		for _, c := range []*Device{c1, c2} {
			if err := connected(ctx, c, wait); err != nil {
				return err
			}
		}
		if err := syncs(ctx, a.benchGroup, c1, m, "from away to home", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, m, c2, "from home to away", 2*timeout)
	}) != nil {
		return
	}
	r.Do("fleet/W3-watch", func() error { return watchOut(ctx, c1) })

	// The tunnel's cases, with c2's keys and c2 itself off meanwhile.
	r.Do("fleet/W19-tunnel", func() error {
		h, err := forgeHostOn(ctx, f, a.away, c2)
		if err != nil {
			return err
		}
		defer a.start(context.WithoutCancel(ctx), c2)
		if err := a.in.reach(ctx, h); err != nil {
			return err
		}
		ids := map[string]string{}
		for _, d := range []*Device{c1, m} {
			if ids[d.Name], err = deviceOf(ctx, d); err != nil {
				return err
			}
		}
		out, err := forgeTunnel(ctx, h, c2, "", "ports", "reach:"+ids[c1.Name]+","+ids[m.Name], "stranger")
		if err != nil {
			return err
		}
		var errs []error
		want := []string{"ports: open 8764", "reach " + ids[c1.Name] + ": no answer", "reach " + ids[m.Name] + ": no answer", "stranger: no answer"}
		for _, w := range want {
			if !strings.Contains(out, w+"\n") {
				errs = append(errs, fmt.Errorf("the forge did not print %q: %q", w, out))
			}
		}
		// S5 through the forwarder too.
		if out, err := forgeTunnel(ctx, h, c2, fwdPublic+":8764", "stranger"); err != nil || !strings.Contains(out, "stranger: no answer") {
			errs = append(errs, fmt.Errorf("a stranger through the forwarder: %q: %v", out, err))
		}
		return errors.Join(errs...)
	})
	r.Do(p+"c2-back", func() error {
		if err := connected(ctx, c2, wait); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, hub, c2, "after the forge", 2*timeout)
	})

	// W10: with the hub's own address blocked, the clients come in through
	// the forwarder.
	if r.Do("fleet/W10-forwarder", func() error {
		if err := a.in.block(ctx, hubPublic, "udp"); err != nil {
			return err
		}
		if err := cutOff(ctx, c1, wait); err != nil {
			return err
		}
		if err := connected(ctx, c1, wait); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, c1, m, "through the forwarder", 2*timeout)
	}) == nil {
		// W31: the forwarder restarts; the hub registers again by itself.
		r.Do("fleet/W31-forwarder-restarted", func() error {
			if _, err := docker(ctx, "restart", "-t", "1", a.fwd.Container); err != nil {
				return err
			}
			if err := globalShows(ctx, hub, "Registered with the forwarder at "+fwdPublic, wait); err != nil {
				return err
			}
			if err := connected(ctx, c1, wait); err != nil {
				return err
			}
			return syncs(ctx, a.benchGroup, hub, c1, "after the forwarder restarted", 3*timeout)
		})
	}
	r.Do(p+"unblock", func() error { return a.in.unblock(ctx, hubPublic, "udp") })

	// W11: the hub's address changes. The connected client learns the new
	// one through the tunnel; the client that was off comes in through the
	// forwarder and then moves to the new address.
	r.Do("fleet/W11-new-address", func() error {
		if err := connected(ctx, c1, wait); err != nil {
			return err
		}
		if err := f.stop(ctx, c2); err != nil {
			return err
		}
		if err := a.in.publish(ctx, hubPublic2, hub); err != nil {
			return err
		}
		if err := succeeds(ctx, hub, a.hubCmd(hubPublic2, a.fwdKey), "", "Reached at "+hubPublic2); err != nil {
			return err
		}
		// The offer reaches c1 before the old address goes.
		time.Sleep(5 * time.Second)
		if err := a.in.block(ctx, hubPublic, ""); err != nil {
			return err
		}
		if err := cutOff(ctx, c1, wait); err != nil {
			return err
		}
		if err := connected(ctx, c1, wait); err != nil {
			return err
		}
		// With the old address blocked, the sync shows the new one is used.
		return syncs(ctx, a.benchGroup, hub, c1, "at the new address", 2*timeout)
	})
	r.Do("fleet/W11-offline-client", func() error {
		if err := a.start(ctx, c2); err != nil {
			return err
		}
		if err := connected(ctx, c2, wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, c2, "through the forwarder after the move", 2*timeout); err != nil {
			return err
		}
		if err := a.in.block(ctx, fwdPublic, ""); err != nil {
			return err
		}
		defer a.in.unblock(ctx, fwdPublic, "")
		// Moved to the new address already, or cut off and back there:
		// either way, after the time a dead link takes to notice, it syncs
		// directly.
		time.Sleep(90 * time.Second)
		if err := connected(ctx, c2, wait); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, c2, hub, "directly at the new address", 2*timeout)
	})

	// W13: the hub hangs, then stops; the clients say so and come back.
	for _, how := range []struct{ name, down, up string }{
		{"fleet/W13-hub-hung", "pause", "unpause"},
		{"fleet/W13-hub-stopped", "stop", "start"},
	} {
		r.Do(how.name, func() error {
			if _, err := docker(ctx, how.down, hub.Container); err != nil {
				return err
			}
			cutErr := cutOff(ctx, c1, wait)
			if _, err := docker(context.WithoutCancel(ctx), how.up, hub.Container); err != nil {
				return err
			}
			if how.up == "start" {
				// Its address may change with the container's network.
				if err := a.in.publish(ctx, hubPublic2, hub); err != nil {
					return err
				}
			}
			if cutErr != nil {
				return cutErr
			}
			if err := connected(ctx, c1, wait); err != nil {
				return err
			}
			return syncs(ctx, a.benchGroup, c1, hub, "after "+how.down, 2*timeout)
		})
	}

	// W31: a wrong key pinned for the forwarder.
	r.Do("fleet/W31-wrong-key", func() error {
		wrong := strings.Repeat("A", 43) + "="
		if _, err := Run(ctx, hub, a.hubCmd(hubPublic2, wrong), ""); err != nil {
			var re *RunError
			if errors.As(err, &re) && strings.Contains(strings.ToLower(re.Output), "key") {
				return nil
			}
			return err
		}
		defer Run(context.WithoutCancel(ctx), hub, a.hubCmd(hubPublic2, a.fwdKey), "")
		return globalShows(ctx, hub, "Not registered with the forwarder", wait)
	})
	r.Do("fleet/W3-nothing-elsewhere", func() error {
		n, err := outElsewhere(ctx, c1)
		if err == nil && n > 0 {
			out, _ := Run(ctx, c1, "iptables -L cbbout -v -x -n", "")
			err = fmt.Errorf("%s sent %d packets elsewhere: %s", c1.Name, n, out)
		}
		return err
	})
}

// hubMoves (W14, W15): the hub moves to an admin computer and a client away
// follows without coming home; then the root is a hub again beside the
// admin, serves while the admin stands by, the admin serves while the root
// is off, and gives way once it is back; a copy made meanwhile reaches the
// root.
func hubMoves(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W15-move/"
	a := newAwayGroup(ctx, r, f, "fleet/W15-move", 2)
	if a == nil {
		return
	}
	root, admin := a.hub, a.members[1]
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	wait := 3 * time.Minute
	var rootID, adminID string
	if r.Do(p+"admin", func() error {
		var err error
		if rootID, err = deviceOf(ctx, root); err != nil {
			return err
		}
		if adminID, err = deviceOf(ctx, admin); err != nil {
			return err
		}
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{admin}, admin.Name, "admin", false, timeout); err != nil {
			return err
		}
		if _, err := Run(ctx, admin, "cbb global on", "yes\n"); err != nil {
			return err
		}
		if err := a.in.publish(ctx, hubPublic2, admin); err != nil {
			return err
		}
		return connected(ctx, c, wait)
	}) != nil {
		return
	}
	if r.Do("fleet/W15-move", func() error {
		if _, err := Run(ctx, root, "cbb global move "+adminID+" "+hubPublic2+":8764", ""); err != nil {
			return err
		}
		if err := globalShows(ctx, admin, "this device is the hub", wait); err != nil {
			return err
		}
		if err := globalShows(ctx, root, "the hub is "+adminID, wait); err != nil {
			return err
		}
		if err := globalShows(ctx, c, "connected to the hub "+adminID, wait); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, admin, c, "from the new hub", 2*timeout)
	}) != nil {
		return
	}
	if r.Do("fleet/W14-root-serves", func() error {
		if _, err := Run(ctx, root, a.hubCmd(hubPublic, a.fwdKey), ""); err != nil {
			return err
		}
		if err := globalShows(ctx, root, "this device is the hub", wait); err != nil {
			return err
		}
		if err := globalShows(ctx, admin, "stands by as its client", wait); err != nil {
			return err
		}
		return globalShows(ctx, c, "connected to the hub "+rootID, wait)
	}) != nil {
		return
	}
	text := "cbb-bench " + a.run + " while the root was off"
	r.Do("fleet/W14-failover", func() error {
		if err := f.stop(ctx, root); err != nil {
			return err
		}
		stopped := time.Now()
		if err := globalShows(ctx, admin, "this device is the hub", 2*time.Minute); err != nil {
			return err
		}
		fmt.Fprintf(r.out, "     W14: %s serves %v after the root stopped\n", admin.Name, time.Since(stopped).Round(time.Second))
		if err := globalShows(ctx, c, "connected to the hub "+adminID, wait); err != nil {
			return err
		}
		if err := Copy(ctx, c, text); err != nil {
			return err
		}
		return arrives(ctx, admin, text, 2*timeout)
	})
	r.Do("fleet/W14-back", func() error {
		if err := a.f.start(ctx, root); err != nil {
			return err
		}
		// Its address may change with the container's network.
		if err := a.in.publish(ctx, hubPublic, root); err != nil {
			return err
		}
		started := time.Now()
		if err := globalShows(ctx, admin, "stands by as its client", 6*time.Minute); err != nil {
			return err
		}
		fmt.Fprintf(r.out, "     W14: %s gave way %v after the root came back\n", admin.Name, time.Since(started).Round(time.Second))
		if err := arrives(ctx, root, text, 2*timeout); err != nil {
			return err
		}
		if err := globalShows(ctx, c, "connected to the hub "+rootID, 6*time.Minute); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, root, c, "after the root came back", 2*timeout)
	})
}
