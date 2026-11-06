// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// countStrings adds a chain named chain to d's table and hooks it into
// hooks, counting the packets that match filter and carry one of words in
// the clear (iptables' string match, as a capture searched for them).
func countStrings(ctx context.Context, d *Device, chain, filter string, hooks []string, words []string) error {
	cmds := []string{"iptables -N " + chain}
	for _, w := range words {
		cmds = append(cmds, fmt.Sprintf("iptables -A %s %s -m string --algo bm --string %q", chain, filter, w))
	}
	for _, h := range hooks {
		cmds = append(cmds, "iptables -I "+h+" -j "+chain)
	}
	_, err := Run(ctx, d, strings.Join(cmds, " && "), "")
	return err
}

// stringsSeen returns, for each word countStrings counts in chain, the
// packets that carried it.
func stringsSeen(ctx context.Context, d *Device, chain string, words []string) (map[string]int, error) {
	out, err := Run(ctx, d, "iptables -L "+chain+" -v -x -n", "")
	if err != nil {
		return nil, err
	}
	seen := map[string]int{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		for _, w := range words {
			if strings.Contains(l, fmt.Sprintf("STRING match  %q", w)) || strings.Contains(l, "\""+w+"\"") {
				seen[w] += n
			}
		}
	}
	return seen, nil
}

// leaks is an error naming each word seen in packets, or nil.
func leaks(where string, seen map[string]int) error {
	var hits []string
	for w, n := range seen {
		if n > 0 {
			hits = append(hits, fmt.Sprintf("%q in %d packets", w, n))
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return fmt.Errorf("%s carried in the clear: %s", where, strings.Join(hits, ", "))
}

// canary is sent in the clear past each counter, so that a count of none
// shows that nothing else carried a word, not that the counter saw nothing.
const canary = "cbb-bench-canary"

// captures (S1, S2): what someone watching the wire learns. On the
// internet's router between an away client and the group's servers, no
// packet carries the copied text, the run's marker, the group's tag or a
// device ID in the clear, and the client sends nothing to anyone but the
// hub and the forwarder. At home, member connections speak only TLS 1.3
// and carry no copied text in the clear; the device IDs and the group's
// tag are public there by design (mDNS names them, and the TLS server
// name is cb-<ID>.local), so only the run's marker is looked for.
func captures(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/S1-internet-path/"
	// The forwarder logs the most with CBB_DEBUG=1, which only adds counts.
	f.serverEnv = []string{"CBB_DEBUG=1"}
	a := newAwayGroup(ctx, r, f, "fleet/S1-internet-path", 2)
	f.serverEnv = nil
	if a == nil {
		return
	}
	hub, home := a.hub, a.members[1]
	var words []string
	if r.Do(p+"setup", func() error {
		_, tag, err := statusIDs(ctx, hub)
		if err != nil {
			return err
		}
		words = append(words, a.run, tag)
		for _, d := range []*Device{hub, home} {
			id, _, err := statusIDs(ctx, d)
			if err != nil {
				return err
			}
			words = append(words, id)
		}
		if err := countStrings(ctx, a.in.router, "cbbleak", "", []string{"FORWARD"}, append(words, canary)); err != nil {
			return err
		}
		return countStrings(ctx, home, "cbbleak", "-p tcp -m multiport --ports 8764", []string{"INPUT", "OUTPUT"}, []string{a.run, canary})
	}) != nil {
		return
	}
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	if r.Do(p+"syncs", func() error {
		id, _, err := statusIDs(ctx, c)
		if err != nil {
			return err
		}
		if err := countStrings(ctx, a.in.router, "cbbleak2", "", []string{"FORWARD"}, []string{id}); err != nil {
			return err
		}
		if err := watchOut(ctx, c); err != nil {
			return err
		}
		if err := connected(ctx, c, 3*time.Minute); err != nil {
			return err
		}
		for i, pair := range [][2]*Device{{hub, c}, {c, hub}, {home, c}, {c, home}, {hub, home}} {
			if err := syncs(ctx, a.benchGroup, pair[0], pair[1], fmt.Sprintf("watched %d", i), 2*timeout); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	r.Do(p+"nothing-in-clear", func() error {
		// The canary to the hub's WireGuard port, which drops it.
		if _, err := Run(ctx, c, "bash -c 'echo "+canary+" > /dev/udp/"+hubPublic+"/51820'", ""); err != nil {
			return err
		}
		seen, err := stringsSeen(ctx, a.in.router, "cbbleak", append(words, canary))
		if err != nil {
			return err
		}
		if seen[canary] == 0 {
			return fmt.Errorf("the internet's router did not count the canary sent in the clear; the counters see nothing")
		}
		delete(seen, canary)
		if err := leaks("the internet's router saw packets that", seen); err != nil {
			return err
		}
		id, _, _ := statusIDs(ctx, c)
		seen, err = stringsSeen(ctx, a.in.router, "cbbleak2", []string{id})
		if err != nil {
			return err
		}
		if err := leaks("the internet's router saw packets that", seen); err != nil {
			return err
		}
		n, err := outElsewhere(ctx, c)
		if err == nil && n > 0 {
			err = fmt.Errorf("the away client sent %d packets to neither the hub nor the forwarder", n)
		}
		return err
	})
	r.Do("fleet/S2-lan", func() error {
		ip, err := fleetIP(ctx, home)
		if err != nil {
			return err
		}
		id, _, err := statusIDs(ctx, home)
		if err != nil {
			return err
		}
		addr := ip + ":8764 -servername cb-" + id + ".local -alpn cbb/3"
		if out, _ := runOut(ctx, hub, "openssl s_client -tls1_2 -connect "+addr+" </dev/null 2>&1", time.Minute); !strings.Contains(out, "alert protocol version") {
			return fmt.Errorf("the member port at home did not refuse TLS 1.2 by its version: %q", out)
		}
		if out, _ := runOut(ctx, hub, "openssl s_client -tls1_3 -connect "+addr+" </dev/null 2>&1", time.Minute); !strings.Contains(out, "New, TLSv1.3,") {
			return fmt.Errorf("the member port at home does not speak TLS 1.3: %q", out)
		}
		// The canary in the clear to the member port, which drops it.
		if _, err := Run(ctx, hub, "bash -c 'exec 3<>/dev/tcp/"+ip+"/8764; echo "+canary+" >&3; sleep 1'", ""); err != nil {
			return err
		}
		seen, err := stringsSeen(ctx, home, "cbbleak", []string{a.run, canary})
		if err != nil {
			return err
		}
		if seen[canary] == 0 {
			return fmt.Errorf("the member at home did not count the canary sent in the clear; the counters see nothing")
		}
		delete(seen, canary)
		return leaks("member connections at home", seen)
	})
	failClosed(ctx, r, a, c, words)
	awayLimit(ctx, r, a, c, timeout)
	r.Do("fleet/S18-forwarder-keeps-nothing", func() error {
		id, _, err := statusIDs(ctx, c)
		if err != nil {
			return err
		}
		secret := append(append([]string{}, words...), id)
		for _, d := range []*Device{hub, home, c} {
			ip, err := fleetIP(ctx, d)
			if err != nil {
				return err
			}
			secret = append(secret, ip)
		}
		for _, ip := range a.in.ips {
			secret = append(secret, ip)
		}
		return serverKeepsNothing(ctx, a.fwd, fwdState, []string{"forwarder.pem", "forward-state.json"}, secret)
	})
}

// serverKeepsNothing (S18, the fleet's part) checks that a forwarder or relay
// d keeps in dir, its state directory, only the files keep and its log,
// and that none of them, nor anything under /var/log, holds one of words:
// the group's tag, device IDs, the run's marker, addresses.
func serverKeepsNothing(ctx context.Context, d *Device, dir string, keep, words []string) error {
	out, err := Run(ctx, d, "ls -A "+dir, "")
	if err != nil {
		return err
	}
	allowed := map[string]bool{"log": true}
	for _, k := range keep {
		allowed[k] = true
	}
	for _, name := range strings.Fields(out) {
		if !allowed[name] {
			return fmt.Errorf("%s keeps %s in %s, besides its keys and log: %q", d.Name, name, dir, out)
		}
	}
	if n, err := Run(ctx, d, "wc -l < "+dir+"/log", ""); err != nil || strings.TrimSpace(n) == "0" {
		return fmt.Errorf("%s's log is empty or unreadable (%v), so a search of it proves nothing", d.Name, err)
	}
	var hits []string
	for _, w := range words {
		if w == "" {
			continue
		}
		// grep -F with the word as data; exit 1 means no match.
		got, err := runOut(ctx, d, "grep -rlF -e '"+w+"' "+dir+" /var/log", time.Minute)
		if err == nil {
			hits = append(hits, fmt.Sprintf("%q in %s", w, strings.Join(strings.Fields(got), ", ")))
		}
	}
	if len(hits) > 0 {
		return fmt.Errorf("%s keeps %s", d.Name, strings.Join(hits, "; "))
	}
	return nil
}

// failClosed (S9): with the hub's WireGuard port blocked on the way, the
// away client, given a copy, sends for two minutes nothing to anyone but
// the hub and the forwarder, and nothing of the group in the clear. The
// router drops the blocked packets before it forwards them, so the client
// counts what it sends itself.
func failClosed(ctx context.Context, r *Report, a *awayGroup, c *Device, words []string) {
	r.Do("fleet/S9-fail-closed", func() error {
		id, _, err := statusIDs(ctx, c)
		if err != nil {
			return err
		}
		words := append(append([]string{}, words...), id)
		if err := countStrings(ctx, c, "cbbleak3", "", []string{"OUTPUT"}, append(words, canary)); err != nil {
			return err
		}
		before, err := outElsewhere(ctx, c)
		if err != nil {
			return err
		}
		if err := a.in.block(ctx, hubPublic, "udp"); err != nil {
			return err
		}
		defer a.in.unblock(ctx, hubPublic, "udp")
		if err := Copy(ctx, c, "cbb-bench "+a.run+" fail closed"); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Minute):
		}
		if _, err := Run(ctx, c, "bash -c 'echo "+canary+" > /dev/udp/"+hubPublic+"/51820'", ""); err != nil {
			return err
		}
		seen, err := stringsSeen(ctx, c, "cbbleak3", append(words, canary))
		if err != nil {
			return err
		}
		if seen[canary] == 0 {
			return fmt.Errorf("the away client did not count the canary sent in the clear; the counters see nothing")
		}
		delete(seen, canary)
		if err := leaks("with the tunnel broken, the away client sent packets that", seen); err != nil {
			return err
		}
		after, err := outElsewhere(ctx, c)
		if err == nil && after > before {
			err = fmt.Errorf("with the tunnel broken, the away client sent %d packets to neither the hub nor the forwarder", after-before)
		}
		return err
	})
}

// awayLimit (O10, the fleet's part): the away client takes a file copied
// at home through the hub while it is within its max-copy-away, and one
// over it stays at home, where the hub has it, while the client's status
// says so and it saves nothing.
func awayLimit(ctx context.Context, r *Report, a *awayGroup, c *Device, timeout time.Duration) {
	hub, home := a.hub, a.members[1]
	r.Do("fleet/O10-away-limit", func() error {
		if err := succeeds(ctx, c, "cbb config max-copy-away 2MiB", "", "2 MiB"); err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), c, "cbb config max-copy-away 25MiB", "")
		sum, err := fileOn(ctx, home, "/tmp/one", 1)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, home, "cbb copy /tmp/one", ""); err != nil {
			return err
		}
		if err := eventually(ctx, 2*timeout, func() error {
			got, err := pastedFile(ctx, c, time.Minute)
			if err == nil && got != sum {
				err = fmt.Errorf("%s has another file than the 1 MiB one", c.Name)
			}
			return err
		}); err != nil {
			return fmt.Errorf("a copy within the away limit: %w", err)
		}
		if sum, err = fileOn(ctx, home, "/tmp/three", 3); err != nil {
			return err
		}
		if _, err := Run(ctx, home, "cbb copy /tmp/three", ""); err != nil {
			return err
		}
		if err := eventually(ctx, 2*timeout, func() error {
			got, err := pastedFile(ctx, hub, time.Minute)
			if err == nil && got != sum {
				err = fmt.Errorf("%s at home has another file than the 3 MiB one", hub.Name)
			}
			return err
		}); err != nil {
			return err
		}
		if err := eventually(ctx, timeout, func() error {
			return succeeds(ctx, c, "cbb status", "", "is over this device's limit of 2 MiB away from home")
		}); err != nil {
			return err
		}
		if got, err := pastedFile(ctx, c, time.Minute); err == nil && got == sum {
			return fmt.Errorf("%s saved the copy over its away limit", c.Name)
		}
		return nil
	})
}
