// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// outsidePublic is the internet's address of the fleet's stand-in for the
// internet, beyond the group's servers.
const outsidePublic = "203.0.113.99"

// onlyCBB (W44): the ways out carry only cbb. A hostile client, with a
// member's keys and a WireGuard that sends everything to the hub, directly
// and through the forwarder, asks for the internet, the hub's own home
// network and the hub's loopback, TCP and UDP, IPv4 and IPv6: nothing
// answers, and nothing reaches the stand-in for the internet; the member
// port still does. Unit tests check VLESS, the relay, the phones' hub and
// the lite member's tunnel the same way (docs/roadmap.md, item 61).
func onlyCBB(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W44-only-cbb/"
	a := newAwayGroup(ctx, r, f, "fleet/W44-only-cbb", 2)
	if a == nil || len(a.members) < 2 {
		return
	}
	home := a.members[1]
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	var outside *Device
	var homeIP string
	if r.Do(p+"outside", func() error {
		var err error
		// One on the servers' network, as the internet beyond the
		// forwarder, with a public address.
		if outside, err = forgeServer(ctx, f, a.fwd.Network, "-addr :7000 outside-server:/tmp/hits"); err != nil {
			return err
		}
		if err := a.in.publish(ctx, outsidePublic, outside); err != nil {
			return err
		}
		if homeIP, err = fleetIPOn(ctx, home, home.Network); err != nil {
			return err
		}
		return connected(ctx, c, 3*time.Minute)
	}) != nil {
		return
	}
	r.Do("fleet/W44-only-cbb", func() error {
		h, err := forgeHostOn(ctx, f, a.away, c)
		if err != nil {
			return err
		}
		defer a.start(context.WithoutCancel(ctx), c)
		if err := a.in.reach(ctx, h); err != nil {
			return err
		}
		targets := strings.Join([]string{
			outsidePublic + ":7000",       // the internet
			homeIP + ":8764",              // a member on the hub's home network
			"127.0.0.1:8764",              // the hub's loopback
			"[::1]:8764",                  // the same in IPv6
			"[2606:4700:4700::1111]:7000", // the internet in IPv6
		}, ",")
		var errs []error
		for _, ep := range []string{"", fwdPublic + ":8764"} {
			out, err := forgeTunnel(ctx, h, c, ep, "outside:"+targets)
			if err != nil {
				return err
			}
			for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
				if strings.HasPrefix(l, "outside ") && !strings.HasSuffix(l, ": no answer") {
					errs = append(errs, fmt.Errorf("through %q: %s", ep, l))
				}
			}
			if n := strings.Count(out, ": no answer"); n != 10 {
				errs = append(errs, fmt.Errorf("through %q the forge tried %d of 10: %q", ep, n, out))
			}
		}
		hits, err := Run(ctx, outside, "cat /tmp/hits 2>/dev/null; true", "")
		if err != nil {
			return err
		}
		if hits = strings.TrimSpace(hits); hits != "" {
			errs = append(errs, fmt.Errorf("the stand-in for the internet was reached: %s", hits))
		}
		// The stand-in answers what does reach it.
		if out, err := Run(ctx, h, "timeout 5 bash -c 'cat </dev/tcp/"+outsidePublic+"/7000' || true", ""); err != nil || !strings.Contains(out, "the internet") {
			errs = append(errs, fmt.Errorf("the stand-in for the internet does not answer a direct stream: %q, %v", out, err))
		}
		return errors.Join(errs...)
	})
	r.Do(p+"back", func() error {
		if err := connected(ctx, c, 3*time.Minute); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, home, c, "after the ways out were tried", 2*timeout)
	})
}

// hubOverVLESS (W45): a hub on a network that lets only HTTPS through: with
// UDP and the forwarder's TCP port blocked from the hub's network, the hub
// registers inside VLESS, as the forwarder told it at its last
// registration, and its client away still syncs both ways.
func hubOverVLESS(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W45-hub-vless/"
	a := newAwayGroupWith(ctx, r, f, "fleet/W45-hub-vless", 1, xhttpVLESS)
	if a == nil {
		return
	}
	hub := a.hub
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	wait := 3 * time.Minute
	if r.Do(p+"vless", func() error {
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		// The forwarder's web server has a certificate from a CA of its
		// own, which the members must trust.
		if err := a.trustWeb(ctx, hub, c); err != nil {
			return err
		}
		if err := connected(ctx, c, wait); err != nil {
			return fmt.Errorf("after the web server's CA: %w", err)
		}
		if err := succeeds(ctx, hub, a.hubCmdWith(hubPublic, a.fwdKey), "", "VLESS"); err != nil {
			return err
		}
		// VLESS turns AmneziaWG on too: the client gets the new offer at
		// home (W18).
		if err := learnAtHome(ctx, f, a, c); err != nil {
			return err
		}
		return globalShows(ctx, c, "VLESS", wait)
	}) != nil {
		return
	}
	subnet, err := docker(ctx, "network", "inspect", "-f", "{{(index .IPAM.Config 0).Subnet}}", hub.Network)
	if err != nil {
		r.Do(p+"block", func() error { return err })
		return
	}
	rules := []string{
		"-s " + strings.TrimSpace(subnet) + " -d " + fwdPublic + " -p udp -j DROP",
		"-s " + strings.TrimSpace(subnet) + " -d " + fwdPublic + " -p tcp --dport 8764 -j DROP",
	}
	defer func() {
		for _, rule := range rules {
			Run(context.WithoutCancel(ctx), a.in.router, "iptables -t mangle -D PREROUTING "+rule, "")
		}
	}()
	r.Do("fleet/W45-hub-vless", func() error {
		for _, rule := range rules {
			if _, err := Run(ctx, a.in.router, "iptables -t mangle -I PREROUTING "+rule, ""); err != nil {
				return err
			}
		}
		// The forwarder restarts, so the hub registers again, now with
		// only HTTPS through.
		if _, err := docker(ctx, "restart", "-t", "1", a.fwd.Container); err != nil {
			return err
		}
		want := "registered with the forwarder at " + fwdPublic + ":8764 over VLESS"
		if err := eventually(ctx, wait, func() error {
			out, err := docker(ctx, "logs", hub.Container)
			if err == nil && !strings.Contains(out, want) {
				err = fmt.Errorf("%s's log does not say %q", hub.Name, want)
			}
			return err
		}); err != nil {
			return err
		}
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, c, hub, "while the hub has only HTTPS", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, a.benchGroup, hub, c, "back while the hub has only HTTPS", 2*timeout)
	})
}

// webCA is where a member keeps the XHTTP web server's CA, which the
// time-scaled build's VLESS trusts (CBB_TEST_XHTTP_CA).
const webCA = "/etc/cbbbench-web-ca.pem"

// xhttpEnv is the environment of the fleet's servers and members for
// W46: the time-scaled build at the real times, its VLESS trusting the web
// server's CA.
var xhttpEnv = []string{"CBB_TEST_SCALE=1", "CBB_TEST_XHTTP_CA=" + webCA}

// trustWeb puts the XHTTP forwarder's web server's CA on each of ds, for
// its VLESS and among the system's for the mirror's TLS, and starts its
// service again, which reads it when it starts.
func (a *awayGroup) trustWeb(ctx context.Context, ds ...*Device) error {
	ca, err := Run(ctx, a.fwd, "cat "+xhttpCA, "")
	if err != nil {
		return err
	}
	for _, d := range ds {
		if _, err := Run(ctx, d, "cat >"+webCA+" && mkdir -p /etc/ssl/certs && cat "+webCA+" >>/etc/ssl/certs/ca-certificates.crt", ca); err != nil {
			return err
		}
		if _, err := Run(ctx, d, fleetKill, ""); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		if err := eventually(ctx, 20*time.Second, func() error {
			_, err := Run(ctx, d, "cbb status", "")
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// hubOverXHTTP (W46): a forwarder whose VLESS runs over XHTTP behind the
// web server of its site, which ends the TLS and passes only its path:
// with UDP and the forwarder's TCP port blocked for everyone, the hub
// registers inside it and its client away syncs through it both ways; the
// web server passed the requests, and gives anyone else the site. W47:
// cbb update on that client asks the mirror on the forwarder's server
// inside VLESS. It runs in the time suite at the real times: only the
// time-scaled build's VLESS trusts a web server whose certificate no public
// CA signs.
func hubOverXHTTP(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W46-xhttp/"
	a := newAwayGroupWith(ctx, r, f, "fleet/W46-xhttp", 1, xhttpVLESS)
	if a == nil {
		return
	}
	hub := a.hub
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	wait := 3 * time.Minute
	if r.Do(p+"vless", func() error {
		if err := connected(ctx, c, wait); err != nil {
			return fmt.Errorf("before the web server's CA: %w", err)
		}
		if err := a.trustWeb(ctx, hub, c); err != nil {
			return err
		}
		if err := connected(ctx, c, wait); err != nil {
			return fmt.Errorf("after the web server's CA: %w", err)
		}
		if err := succeeds(ctx, hub, a.hubCmdWith(hubPublic, a.fwdKey), "", "VLESS"); err != nil {
			return err
		}
		if err := learnAtHome(ctx, f, a, c); err != nil {
			return err
		}
		return globalShows(ctx, c, "VLESS", wait)
	}) != nil {
		return
	}
	rules := []string{
		"-d " + fwdPublic + " -p udp -j DROP",
		"-d " + fwdPublic + " -p tcp --dport 8764 -j DROP",
		"-d " + hubPublic + " -p udp -j DROP",
	}
	defer func() {
		for _, rule := range rules {
			Run(context.WithoutCancel(ctx), a.in.router, "iptables -t mangle -D PREROUTING "+rule, "")
		}
	}()
	r.Do("fleet/W46-xhttp", func() error {
		for _, rule := range rules {
			if _, err := Run(ctx, a.in.router, "iptables -t mangle -I PREROUTING "+rule, ""); err != nil {
				return err
			}
		}
		// The forwarder restarts, so the hub registers again, now only
		// through the web server; the web server comes back with it.
		if _, err := docker(ctx, "restart", "-t", "1", a.fwd.Container); err != nil {
			return err
		}
		if err := a.startWeb(ctx); err != nil {
			return err
		}
		want := "registered with the forwarder at " + fwdPublic + ":8764 over VLESS"
		if err := eventually(ctx, wait, func() error {
			out, err := docker(ctx, "logs", hub.Container)
			if err == nil && !strings.Contains(out, want) {
				err = fmt.Errorf("%s's log does not say %q", hub.Name, want)
			}
			return err
		}); err != nil {
			return err
		}
		if err := connected(ctx, c, wait); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, c, hub, "through the web server", 2*timeout); err != nil {
			return err
		}
		if err := syncs(ctx, a.benchGroup, hub, c, "back through the web server", 2*timeout); err != nil {
			return err
		}
		hits, err := Run(ctx, a.fwd, "cat "+xhttpHits, "")
		if err != nil || strings.TrimSpace(hits) == "" || strings.TrimSpace(hits) == "0" {
			return fmt.Errorf("the web server passed no request to the forwarder: %q, %v", strings.TrimSpace(hits), err)
		}
		out, err := Run(ctx, c, "curl -sk --max-time 10 --resolve "+xhttpName+":443:"+fwdPublic+" https://"+xhttpName+"/", "")
		if err == nil && !strings.Contains(out, "cbb-bench borrowed site") {
			err = fmt.Errorf("a visitor of the site got %q, not the site", firstLine(out))
		}
		return err
	})
	r.Do("fleet/W47-mirror", func() error {
		// cbb update on the client away asks the mirror only inside VLESS,
		// through the forwarder, whose server has the mirror; the
		// stand-in's TLS is checked on the way, and it serves no release,
		// so the check itself fails.
		out, _ := runOut(ctx, c, "cbb update -check", 3*time.Minute)
		hits, err := Run(ctx, a.fwd, "cat "+mirrorHits+" 2>/dev/null; true", "")
		if err != nil {
			return err
		}
		if !strings.Contains(hits, ".json") {
			return fmt.Errorf("the mirror on the forwarder's server was not asked for a release (%q); cbb update printed %q", strings.TrimSpace(hits), strings.TrimSpace(out))
		}
		if !strings.Contains(out, "over VLESS") {
			return fmt.Errorf("cbb update does not say it asked the mirror over VLESS: %q", strings.TrimSpace(out))
		}
		return nil
	})
}
