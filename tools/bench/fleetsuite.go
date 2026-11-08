// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
)

// FleetSuite runs the catalogue's cases that need many devices or faults the
// real devices must not see, on members in containers on the controller
// (fleet.go). Every group it makes is thrown away with its containers, so
// nothing is revoked at the end. size is the number of members of the "many
// members" case (E3).
func FleetSuite(ctx context.Context, r *Report, cbb string, size int, timeout time.Duration) {
	cleanFleet(ctx)
	var f *Fleet
	if r.Do("fleet/setup", func() error {
		var err error
		f, err = NewFleet(ctx, cbb)
		return err
	}) != nil {
		return
	}
	defer f.Close(ctx)

	for _, s := range []struct {
		name string
		run  func()
	}{
		{"G5-window", func() { pairingWindow(ctx, r, f) }},
		{"G20-roles", func() { roles(ctx, r, f, timeout) }},
		{"G26-takeover", func() { takeover(ctx, r, f, timeout) }},
		{"G42-rejoin", func() { rejoin(ctx, r, f, timeout) }},
		{"G43-two-groups", func() { sideBySide(ctx, r, f, timeout) }},
		{"Y12-partition", func() { partition(ctx, r, f, timeout) }},
		{"Y16-line", func() { line(ctx, r, f, timeout) }},
		{"M6-own", func() { modes(ctx, r, f, timeout) }},
		{"D15-junk", func() { junk(ctx, r, f, timeout) }},
		{"E5-local-clients", func() { localClients(ctx, r, f) }},
		{"E9-restarts", func() { restarts(ctx, r, f, timeout) }},
		{"T2-tmux", func() { tmuxPaste(ctx, r, f, timeout) }},
		{"G25-offline", func() { offline(ctx, r, f, timeout) }},
		{"G27-takeover-undone", func() { takeoverUndone(ctx, r, f, timeout) }},
		{"G33-admins-at-once", func() { concurrentAdmins(ctx, r, f, timeout) }},
		{"S24-stolen-admin", func() { stolenAdmin(ctx, r, f, timeout) }},
		{"M4-mode-kept", func() { modeKept(ctx, r, f, timeout) }},
		{"M8-sync-off", func() { syncOffHere(ctx, r, f, timeout) }},
		{"M9-admin-mute", func() { muteByAdmin(ctx, r, f, timeout) }},
		{"M10-incoming", func() { incoming(ctx, r, f, timeout) }},
		{"G4-paths", func() { joinPaths(ctx, r, f, timeout) }},
		{"G7-two-windows", func() { twoWindows(ctx, r, f) }},
		{"D2-who-dials", func() { whoDials(ctx, r, f, timeout) }},
		{"D6-networks", func() { knownNetworks(ctx, r, f, timeout) }},
		{"D12-heartbeats", func() { heartbeats(ctx, r, f, timeout) }},
		{"I19-no-network", func() { noNetworkAtStart(ctx, r, f, timeout) }},
		{"U8-disk-full", func() { diskFull(ctx, r, f, timeout) }},
		{"U13-second-instance", func() { secondInstance(ctx, r, f, timeout) }},
		{"Q6-actions", func() { quickActions(ctx, r, f, timeout) }},
		{"S17-commands", func() { forgedCommands(ctx, r, f, timeout) }},
		{"G31-converge", func() { converge(ctx, r, f, timeout) }},
		{"G32-limits", func() { recordLimits(ctx, r, f, timeout) }},
		{"K14-admin-chain", func() { adminChain(ctx, r, f, timeout) }},
		{"W4-away", func() { awayHub(ctx, r, f, timeout) }},
		{"W18-obfuscation", func() { obfuscation(ctx, r, f, timeout) }},
		{"W17-lite-away", func() { liteAway(ctx, r, f, timeout) }},
		{"S1-captures", func() { captures(ctx, r, f, timeout) }},
		{"Y34-secret-memory", func() { secretMemory(ctx, r, f, timeout) }},
		{"D10-wan", func() { wanSide(ctx, r, f) }},
		{"W33-two-groups", func() { twoGroupsAway(ctx, r, f, timeout) }},
		{"W36-relay", func() { relayAway(ctx, r, f, timeout) }},
		{"W38-relay-limits", func() { relayLimits(ctx, r, f, timeout) }},
		{"E6-hub-load", func() { hubLoad(ctx, r, f, timeout) }},
		{"W34-vless", func() { vlessAway(ctx, r, f, timeout) }},
		{"W15-move", func() { hubMoves(ctx, r, f, timeout) }},
		{"W44-only-cbb", func() { onlyCBB(ctx, r, f, timeout) }},
		{"W45-hub-vless", func() { hubOverVLESS(ctx, r, f, timeout) }},
		{"W48-project-relay", func() { projectRelayFollows(ctx, r, f, timeout) }},
		{"S25-forward-only", func() { forwardOnlyHub(ctx, r, f, timeout) }},
		{"Y36-joined-later", func() { joinedLater(ctx, r, f, timeout) }},
		{"E1-latency", func() { latency(ctx, r, f, timeout) }},
		{"E2-throughput", func() { throughput(ctx, r, f, timeout) }},
		{"E4-big", func() { bigTransfers(ctx, r, f, timeout) }},
		{"O2-files", func() { files(ctx, r, f, timeout) }},
		{"U2-cli", func() { commandLine(ctx, r, f) }},
		{"Y20-fresh", func() { freshness(ctx, r, f, timeout) }},
		{"W21-removed", func() { removedAway(ctx, r, f, timeout) }},
		{"G35-system", func() { otherSystem(ctx, r, f, timeout) }},
		{"U11-socket", func() { controlSocket(ctx, r, f) }},
		{"T17-tv", func() { tvRemote(ctx, r, f, timeout) }},
		{"G13-invitations", func() { invitations(ctx, r, f, timeout) }},
		{"D17-mdns", func() { mdnsRecords(ctx, r, f, timeout) }},
		{"D14-queue", func() { slowPeer(ctx, r, f, timeout) }},
		{"D13-handshakes", func() { handshakeSlots(ctx, r, f, timeout) }},
		{"Y15-duplicates", func() { duplicates(ctx, r, f, timeout) }},
		{"G16-killed-joiner", func() { killedJoiner(ctx, r, f, timeout) }},
		{"G40-random-walk", func() { randomWalk(ctx, r, f, timeout) }},
		{"K3-renewals", func() { renewalChecks(ctx, r, f, timeout) }},
		{"D11-dial-back", func() { dialBack(ctx, r, f, timeout) }},
		{"S21-stranger", func() { stranger(ctx, r, f, timeout) }},
		{"W30-forwarder", func() { forwarderRules(ctx, r, f, timeout) }},
		{"S20-fuzz", func() { fuzzing(ctx, r, f, timeout) }},
		{"K11-file-keys", func() { fileKeys(ctx, r, f, timeout) }},
		{"G41-matrix", func() { joinMatrix(ctx, r, f, timeout) }},
		{"I8-update", func() { updates(ctx, r, f, timeout) }},
		{"O9-cache", func() { cache(ctx, r, f, timeout) }},
		{"O15-fetch-limits", func() { fetchLimits(ctx, r, f, timeout) }},
		{"G17-joiner-listens", func() { joinerListens(ctx, r, f, timeout) }},
		{"G8-relay", func() { pairRelay(ctx, r, f, timeout) }},
		{"U9-lite", func() { liteMember(ctx, r, f, timeout) }},
		{"D9-subnets", func() { acrossSubnets(ctx, r, f, timeout) }},
		{"O14-router", func() { routerMedia(ctx, r, f, timeout) }},
		{"E3-many", func() { manyMembers(ctx, r, f, size, timeout) }},
		{"E10-soak", func() { soak(ctx, r, f, timeout) }},
	} {
		if ctx.Err() == nil && scenario(s.name) {
			s.run()
		}
	}
}

// scenarios limits the fleet and time suites to the scenarios that
// -scenario names; none given runs them all.
var scenarios map[string]bool

// scenario reports whether the scenario name runs.
func scenario(name string) bool { return len(scenarios) == 0 || scenarios[name] }

// fleetGroup starts n new members and forms a group of them, the first as
// its root, every one in the sync mode shared (R2).
func fleetGroup(ctx context.Context, r *Report, f *Fleet, suite string, n int, env ...string) *benchGroup {
	return fleetGroupOn(ctx, r, f, f.net, suite, n, env...)
}

// fleetGroupOn is fleetGroup on the network net.
func fleetGroupOn(ctx context.Context, r *Report, f *Fleet, net, suite string, n int, env ...string) *benchGroup {
	ds := make([]*Device, n)
	if r.Do(suite+"/start", func() error {
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ds[i], errs[i] = f.AddOn(ctx, net, env...)
			}()
		}
		wg.Wait()
		return errors.Join(errs...)
	}) != nil {
		return nil
	}
	ds[0].Roles = []string{"member", "hub"}
	return formGroup(ctx, r, suite, ds)
}

// fails runs a command that must fail and checks its message as R6 says.
func fails(ctx context.Context, r *Report, name string, d *Device, ec errorCase) {
	r.Do(name, func() error { return errorShown(ctx, d, ec) })
}

// succeeds runs a command that must succeed and print want.
func succeeds(ctx context.Context, d *Device, cmd, stdin, want string) error {
	out, err := Run(ctx, d, cmd, stdin)
	if err != nil {
		return err
	}
	if !strings.Contains(out, want) {
		return fmt.Errorf("%s printed %q, not %q", firstLine(cmd), firstLine(out), want)
	}
	return nil
}

// statusRow is the line of a device in cbb status on d.
func statusRow(ctx context.Context, d *Device, name string) (string, error) {
	out, err := Run(ctx, d, "cbb status", "")
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, name+" ") {
			return l, nil
		}
	}
	return "", fmt.Errorf("%s does not list %s", d.Name, name)
}

// listsAs waits until every member lists the device name with the mark (an
// empty mark: listed at all), or, with gone, no longer lists it.
func listsAs(ctx context.Context, members []*Device, name, mark string, gone bool, timeout time.Duration) error {
	for _, m := range members {
		if err := eventually(ctx, timeout, func() error {
			row, err := statusRow(ctx, m, name)
			if gone {
				if err == nil {
					return fmt.Errorf("%s still lists %s: %s", m.Name, name, row)
				}
				return nil
			}
			if err == nil && !strings.Contains(row, mark) {
				err = fmt.Errorf("%s lists %s as %q, without %q", m.Name, name, row, mark)
			}
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// pairingWindow (G5, G6, G9): wrong codes close the window after three; a
// code is good for one device; a member that is no admin names who admits.
func pairingWindow(ctx context.Context, r *Report, f *Fleet) {
	const p = "fleet/G5-window/"
	g := fleetGroup(ctx, r, f, "fleet/G5-window", 2)
	if g == nil {
		return
	}
	var joiner *Device
	if r.Do(p+"joiner", func() error {
		var err error
		joiner, err = f.Add(ctx)
		return err
	}) != nil {
		return
	}
	r.Do(p+"three-wrong", func() error {
		done := make(chan error, 1)
		out := make(chan string, 1)
		go func() {
			var all strings.Builder
			done <- Stream(ctx, g.hub, "cbb pair", func(l string) { all.WriteString(l + "\n") })
			out <- all.String()
		}()
		if err := eventually(ctx, 10*time.Second, func() error {
			_, err := Run(ctx, g.hub, "cbb status | grep -qi 'pairing'", "")
			return err
		}); err != nil {
			time.Sleep(2 * time.Second)
		}
		// errorShown tries twice, once in each mode: the first two
		// attempts; the third is a plain one.
		if err := errorShown(ctx, joiner, errorCase{cmd: "cbb pair -code", stdin: "000000\n", want: []string{"wrong code"}}); err != nil {
			return fmt.Errorf("wrong codes 1 and 2: %w", err)
		}
		if out, err := Run(ctx, joiner, "cbb pair -code", "000000\n"); err == nil {
			return fmt.Errorf("a wrong code was taken: %s", out)
		}
		if err := <-done; err == nil {
			return errors.New("cbb pair went on after three wrong codes")
		}
		if s := <-out; !strings.Contains(s, "three failed attempts") {
			return fmt.Errorf("cbb pair did not say why it closed: %q", s)
		}
		return errorShown(ctx, joiner, errorCase{cmd: "cbb pair -code", stdin: "000000\n", want: []string{"no member with an open pairing window"}})
	})
	r.Do(p+"code-once", func() error {
		code, err := pairOne(ctx, g.hub, joiner)
		if err != nil {
			return err
		}
		other, err := f.Add(ctx)
		if err != nil {
			return err
		}
		return errorShown(ctx, other, errorCase{cmd: "cbb pair -code", stdin: code + "\n", want: []string{"no member with an open pairing window", "wrong code"}})
	})
	r.Do(p+"G9-not-admin", func() error {
		return errorShown(ctx, g.members[1], errorCase{cmd: "cbb pair", want: []string{"only the group's root or an admin", g.hub.Name}})
	})
}

// roles (G20 to G23, G30, M5): admins of a computer's group, what each may
// do, freezing, removal and names.
func roles(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G20-roles/"
	g := fleetGroup(ctx, r, f, "fleet/G20-roles", 5)
	if g == nil || len(g.members) < 5 {
		return
	}
	root, admin, m1, m2, m3 := g.members[0], g.members[1], g.members[2], g.members[3], g.members[4]
	fails(ctx, r, "fleet/G34-file-key-refused", root, errorCase{cmd: "cbb admin " + admin.Name, want: []string{"-allow-file-key"}})
	r.Do(p+"admin", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		return listsAs(ctx, g.members, admin.Name, "admin", false, timeout)
	})
	r.Do("fleet/K9-keys-shown", func() error {
		// The containers have no TPM: every key is in a file, and every
		// devices list says so.
		for _, d := range []*Device{root, admin, m1} {
			if err := listsAs(ctx, []*Device{m2}, d.Name, "in a file", false, timeout); err != nil {
				return err
			}
		}
		return nil
	})
	fails(ctx, r, p+"G21-admin-makes-no-admin", admin, errorCase{cmd: "cbb admin -allow-file-key " + m1.Name, want: []string{"only the group's root"}})
	fails(ctx, r, p+"G21-admin-keeps-root", admin, errorCase{cmd: "cbb remove " + root.Name, want: []string{"holds the group's root", "takeover"}})
	fails(ctx, r, p+"G21-member-removes-none", m1, errorCase{cmd: "cbb remove " + m2.Name, want: []string{"admin"}})
	fails(ctx, r, p+"M5-member-sets-no-mode", m1, errorCase{cmd: "cbb sync -on " + m2.Name + " off", want: []string{"only an admin"}})
	r.Do(p+"M5-mode-on", func() error {
		if err := succeeds(ctx, root, "cbb sync -on "+m2.Name+" off", "", "Sync is off"); err != nil {
			return err
		}
		return succeeds(ctx, m2, "cbb sync", "", "Sync is off")
	})
	r.Do(p+"G21-admin-admits", func() error {
		d, err := f.Add(ctx)
		if err != nil {
			return err
		}
		if _, err := pairOne(ctx, admin, d); err != nil {
			return err
		}
		g.members = append(g.members, d)
		return listsAs(ctx, []*Device{root, m1}, d.Name, "", false, timeout)
	})
	r.Do(p+"G23-admin-removes-by-id", func() error {
		id, err := deviceOf(ctx, m3)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, admin, "cbb remove "+id, ""); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{root, m1, m2}, m3.Name, "", true, timeout)
	})
	r.Do(p+"G23-removed-gets-nothing", func() error {
		text := "cbb-bench " + g.run + " after the removal"
		if err := Copy(ctx, root, text); err != nil {
			return err
		}
		if err := arrives(ctx, m1, text, timeout); err != nil {
			return err
		}
		time.Sleep(3 * time.Second)
		if got, _ := Paste(ctx, m3); strings.Contains(got, text) {
			return fmt.Errorf("%s got a copy after its removal", m3.Name)
		}
		return nil
	})
	r.Do(p+"G22-freeze", func() error {
		if err := succeeds(ctx, root, "cbb freeze "+admin.Name, "", "Froze"); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{root, m1}, admin.Name, "frozen", false, timeout)
	})
	fails(ctx, r, p+"G22-frozen-admits-none", admin, errorCase{cmd: "cbb remove " + m1.Name, want: []string{"admin", "frozen"}})
	r.Do(p+"G22-unfreeze", func() error {
		if err := succeeds(ctx, root, "cbb unfreeze "+admin.Name, "", "Unfroze"); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root, m1}, admin.Name, "admin", false, timeout); err != nil {
			return err
		}
		// Back in the group: the root reaches it again within the
		// fallback dial.
		return eventually(ctx, 45*time.Second, func() error {
			_, err := Run(ctx, root, "cbb sync -on "+admin.Name+" on", "")
			return err
		})
	})
	r.Do(p+"G30-rename", func() error {
		for _, name := range []string{"\u041a\u0443\u0445\u043d\u044f \U0001F373", strings.Repeat("n", 64)} {
			if _, err := Run(ctx, root, "cbb rename "+m2.Name+" "+shellQuote(name), ""); err != nil {
				return err
			}
			if err := listsAs(ctx, []*Device{root, m1, m2}, name, "", false, timeout); err != nil {
				return err
			}
			if _, err := Run(ctx, root, "cbb rename "+shellQuote(name)+" "+m2.Name, ""); err != nil {
				return err
			}
		}
		return nil
	})
	for _, bad := range []string{"", strings.Repeat("n", 65), "a\tb"} {
		fails(ctx, r, fmt.Sprintf("%sG30-rename-refused/%d", p, len(bad)), root, errorCase{cmd: "cbb rename " + m2.Name + " " + shellQuote(bad), want: []string{"1 to 64 characters"}})
	}
}

// takeover (G26): the root is lost; an admin takes the group over, admits
// with it, and the old root, back, is refused.
func takeover(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G26-takeover/"
	g := fleetGroup(ctx, r, f, "fleet/G26-takeover", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, admin, m := g.members[0], g.members[1], g.members[2]
	if r.Do(p+"admin", func() error {
		return succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now")
	}) != nil {
		return
	}
	if r.Do(p+"root-lost", func() error { return f.stop(ctx, root) }) != nil {
		return
	}
	r.Do(p+"takeover", func() error {
		if _, err := Run(ctx, admin, "cbb takeover "+root.Name, ""); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{admin, m}, admin.Name, "root", false, timeout)
	})
	r.Do(p+"new-root-admits", func() error {
		d, err := f.Add(ctx)
		if err == nil {
			_, err = pairOne(ctx, admin, d)
		}
		return err
	})
	r.Do(p+"old-root-refused", func() error {
		if err := f.start(ctx, root); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " from the old root"
		if err := Copy(ctx, root, text); err != nil {
			return err
		}
		time.Sleep(5 * time.Second)
		if got, _ := Paste(ctx, m); strings.Contains(got, text) {
			return errors.New("a member took a copy from the removed root")
		}
		return listsAs(ctx, []*Device{admin, m}, root.Name, "", true, timeout)
	})
}

// rejoin (G42): a removed device, reset, joins again under its name with a
// new device ID; the old ID stays removed.
func rejoin(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G42-rejoin/"
	g := fleetGroup(ctx, r, f, "fleet/G42-rejoin", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, d := g.members[0], g.members[2]
	var old string
	r.Do(p+"remove", func() error {
		var err error
		if old, err = deviceOf(ctx, d); err != nil {
			return err
		}
		_, err = Run(ctx, root, "cbb remove "+old, "")
		return err
	})
	r.Do(p+"reset", func() error {
		if _, err := Run(ctx, d, "rm -rf /var/lib/cbb/*", ""); err != nil {
			return err
		}
		if _, err := docker(ctx, "restart", "-t", "1", d.Container); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			tag, err := groupOf(ctx, d)
			if err == nil && tag != "" {
				err = fmt.Errorf("still in group %s", tag)
			}
			return err
		})
	})
	r.Do(p+"join-again", func() error {
		if _, err := pairOne(ctx, root, d); err != nil {
			return err
		}
		id, err := deviceOf(ctx, d)
		if err != nil {
			return err
		}
		if id == old {
			return fmt.Errorf("%s joined again with its old device ID", d.Name)
		}
		if err := setMode(ctx, d, "shared"); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " after joining again"
		if err := Copy(ctx, d, text); err != nil {
			return err
		}
		return arrives(ctx, g.members[1], text, timeout)
	})
}

// sideBySide (G43, S13): two groups on one network keep apart.
func sideBySide(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G43-two-groups/"
	a := fleetGroup(ctx, r, f, "fleet/G43-a", 2)
	b := fleetGroup(ctx, r, f, "fleet/G43-b", 2)
	if a == nil || b == nil || len(a.members) < 2 || len(b.members) < 2 {
		return
	}
	r.Do(p+"apart", func() error {
		ta := "cbb-bench " + a.run + " group a"
		tb := "cbb-bench " + b.run + " group b"
		if err := Copy(ctx, a.members[0], ta); err != nil {
			return err
		}
		if err := Copy(ctx, b.members[0], tb); err != nil {
			return err
		}
		if err := arrives(ctx, a.members[1], ta, timeout); err != nil {
			return err
		}
		if err := arrives(ctx, b.members[1], tb, timeout); err != nil {
			return err
		}
		if _, err := statusRow(ctx, a.members[0], b.members[0].Name); err == nil {
			return errors.New("group a lists a device of group b")
		}
		return nil
	})
}

// partition (Y12): the group split in two halves that each copy, then
// joined again: every member ends on one text.
func partition(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/Y12-partition/"
	g := fleetGroup(ctx, r, f, "fleet/Y12-partition", 4)
	if g == nil || len(g.members) < 4 {
		return
	}
	left, right := g.members[:2], g.members[2:]
	if r.Do(p+"split", func() error {
		for _, a := range left {
			for _, b := range right {
				if err := cut(ctx, a, b); err != nil {
					return err
				}
			}
		}
		return nil
	}) != nil {
		heal(ctx, g.members...)
		return
	}
	r.Do(p+"each-half", func() error {
		if err := Copy(ctx, left[0], "cbb-bench "+g.run+" left"); err != nil {
			return err
		}
		time.Sleep(time.Second)
		if err := Copy(ctx, right[0], "cbb-bench "+g.run+" right"); err != nil {
			return err
		}
		if err := arrives(ctx, left[1], "cbb-bench "+g.run+" left", timeout); err != nil {
			return err
		}
		return arrives(ctx, right[1], "cbb-bench "+g.run+" right", timeout)
	})
	r.Do(p+"heal", func() error { return heal(ctx, g.members...) })
	r.Do(p+"converge", func() error { return sameText(ctx, g.members, 60*time.Second) })
}

// sameText waits until every member holds one text.
func sameText(ctx context.Context, members []*Device, timeout time.Duration) error {
	return eventually(ctx, timeout, func() error {
		var first string
		for i, m := range members {
			got, err := Paste(ctx, m)
			if err != nil {
				return err
			}
			if i == 0 {
				first = got
			} else if got != first {
				return fmt.Errorf("%s has %s, %s has %s", members[0].Name, describe(first), m.Name, describe(got))
			}
		}
		return nil
	})
}

// line (Y16): five members where each reaches only its neighbours; a copy at
// one end reaches the other by forwarding.
func line(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/Y16-line/"
	g := fleetGroup(ctx, r, f, "fleet/Y16-line", 5)
	if g == nil || len(g.members) < 5 {
		return
	}
	ms := g.members
	defer heal(ctx, ms...)
	if r.Do(p+"cut", func() error {
		for i := range ms {
			for j := i + 2; j < len(ms); j++ {
				if err := cut(ctx, ms[i], ms[j]); err != nil {
					return err
				}
			}
		}
		return nil
	}) != nil {
		return
	}
	text := "cbb-bench " + g.run + " along the line"
	r.Do(p+"end-to-end", func() error {
		if err := Copy(ctx, ms[0], text); err != nil {
			return err
		}
		return arrives(ctx, ms[len(ms)-1], text, 2*timeout)
	})
}

// modes (M3, M6): a new member keeps its clipboard (own), and cbb paste there
// prints the group's text.
func modes(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/M6-own/"
	g := fleetGroup(ctx, r, f, "fleet/M6-own", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	var d *Device
	r.Do(p+"new-is-own", func() error {
		var err error
		if d, err = f.Add(ctx); err != nil {
			return err
		}
		if _, err := pairOne(ctx, g.hub, d); err != nil {
			return err
		}
		return succeeds(ctx, d, "cbb sync", "", "Sync is off")
	})
	if d == nil {
		return
	}
	r.Do(p+"M3-paste-prints-group", func() error {
		text := "cbb-bench " + g.run + " to an own member"
		if err := Copy(ctx, g.hub, text); err != nil {
			return err
		}
		return arrives(ctx, d, text, timeout)
	})
}

// junk (D15, S14): garbage on the member port leaves the service unharmed.
func junk(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D15-junk/"
	g := fleetGroup(ctx, r, f, "fleet/D15-junk", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	var stranger *Device
	if r.Do(p+"stranger", func() error {
		var err error
		stranger, err = f.Add(ctx)
		return err
	}) != nil {
		return
	}
	ip, err := fleetIP(ctx, g.hub)
	if err != nil {
		r.Do(p+"address", func() error { return err })
		return
	}
	for name, cmd := range map[string]string{
		"random-bytes": "head -c 65536 /dev/urandom >&3",
		"plain-http":   `printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' >&3`,
		"tls-hello":    `printf '\026\003\001\002\000\001\000\001\374\003\003' >&3; head -c 600 /dev/zero >&3`,
		"huge-frame":   `printf '\377\377\377\377' >&3; head -c 1048576 /dev/zero >&3`,
	} {
		r.Do(p+name, func() error {
			// bash's /dev/tcp; a refused or reset connection is what
			// the case expects, so only the member's health counts.
			Run(ctx, stranger, "timeout 10 bash -c "+shellQuote("exec 3<>/dev/tcp/"+ip+"/8764; "+cmd+"; sleep 1"), "")
			if _, err := Run(ctx, g.hub, "cbb status", ""); err != nil {
				return err
			}
			text := fmt.Sprintf("cbb-bench %s after %s", g.run, name)
			if err := Copy(ctx, g.members[1], text); err != nil {
				return err
			}
			return arrives(ctx, g.hub, text, timeout)
		})
	}
}

// localClients (E5): a hundred cbb status at once on one member all answer.
func localClients(ctx context.Context, r *Report, f *Fleet) {
	r.Do("fleet/E5-local-clients", func() error {
		d, err := f.Add(ctx)
		if err != nil {
			return err
		}
		out, err := RunFor(ctx, d, `fail=0; for i in $(seq 100); do cbb status >/dev/null 2>&1 & done; for j in $(jobs -p); do wait $j || fail=$((fail+1)); done; echo failed $fail`, "", 2*time.Minute)
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "failed 0" {
			return fmt.Errorf("of 100 cbb status at once, %s", strings.TrimSpace(out))
		}
		return nil
	})
}

// restarts (E9): members killed at random while the others copy; the group
// ends on one text.
func restarts(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/E9-restarts/"
	g := fleetGroup(ctx, r, f, "fleet/E9-restarts", 5)
	if g == nil || len(g.members) < 5 {
		return
	}
	ms := g.members
	r.Do(p+"chaos", func() error {
		stop := time.Now().Add(60 * time.Second)
		var wg sync.WaitGroup
		var errs []error
		var mu sync.Mutex
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				d := ms[1+rand.IntN(len(ms)-1)]
				Run(ctx, d, fleetKill, "")
				time.Sleep(10 * time.Second)
			}
		}()
		for i := 0; time.Now().Before(stop); i++ {
			d := ms[rand.IntN(len(ms))]
			if err := Copy(ctx, d, fmt.Sprintf("cbb-bench %s chaos %d", g.run, i)); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			time.Sleep(time.Second)
		}
		wg.Wait()
		// Copies on a member being killed may fail; the group must not.
		if len(errs) > 20 {
			return fmt.Errorf("%d copies failed: %w", len(errs), errs[0])
		}
		return nil
	})
	r.Do(p+"converge", func() error {
		for _, d := range ms {
			if err := eventually(ctx, 30*time.Second, func() error {
				_, err := Run(ctx, d, "cbb status", "")
				return err
			}); err != nil {
				return err
			}
		}
		text := "cbb-bench " + g.run + " after the chaos"
		if err := Copy(ctx, ms[0], text); err != nil {
			return err
		}
		for _, d := range ms[1:] {
			if err := arrives(ctx, d, text, 2*timeout); err != nil {
				return err
			}
		}
		return nil
	})
}

// manyMembers (E3): one group of size members; all join, a copy reaches all,
// half are removed and the rest still sync.
func manyMembers(ctx context.Context, r *Report, f *Fleet, size int, timeout time.Duration) {
	const p = "fleet/E3-many/"
	if size < 4 {
		r.Skip(p, "-fleet-size is under 4")
		return
	}
	g := fleetGroup(ctx, r, f, "fleet/E3-many", size)
	if g == nil || len(g.members) < size {
		return
	}
	text := "cbb-bench " + g.run + " to many"
	r.Do(p+"copy", func() error { return Copy(ctx, g.members[1], text) })
	spread(ctx, r, p+"arrives/", g.members, g.members[1], text, 3*timeout)
	half := g.members[size/2:]
	r.Do(p+"remove-half", func() error {
		for _, d := range half {
			if _, err := Run(ctx, g.hub, "cbb remove "+d.Name, ""); err != nil {
				return err
			}
		}
		return nil
	})
	rest := g.members[:size/2]
	text2 := "cbb-bench " + g.run + " to the rest"
	r.Do(p+"copy-rest", func() error { return Copy(ctx, rest[len(rest)-1], text2) })
	spread(ctx, r, p+"rest/", rest, rest[len(rest)-1], text2, 2*timeout)
}
