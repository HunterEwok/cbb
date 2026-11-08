// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// buildForge builds tools/bench/forge, a static Linux program the
// containers run, from the source the bench runs from (go run ./tools/bench
// at the repository's top).
func buildForge(ctx context.Context, dir string) (string, error) {
	if _, err := os.Stat(filepath.Join("tools", "bench", "forge", "main.go")); err != nil {
		return "", fmt.Errorf("run the bench at the repository's top, where tools/bench/forge is: %v", err)
	}
	out := filepath.Join(dir, "forge")
	c := exec.CommandContext(ctx, "go", "build", "-o", out, "./tools/bench/forge")
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if b, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build ./tools/bench/forge: %v: %s", err, b)
	}
	return out, nil
}

// forgeHost starts a container that runs tools/bench/forge as the member
// m, with the state of m and of each signer under /tmp/NAME; m itself goes
// off, so that only the copy connects as it.
func forgeHost(ctx context.Context, f *Fleet, m *Device, signers ...*Device) (*Device, error) {
	return forgeHostOn(ctx, f, f.net, m, signers...)
}

// forgeHostOn is forgeHost with the container on the network net.
func forgeHostOn(ctx context.Context, f *Fleet, net string, m *Device, signers ...*Device) (*Device, error) {
	dir, err := os.MkdirTemp("", "cbbfleet-forge")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bin, err := buildForge(ctx, dir)
	if err != nil {
		return nil, err
	}
	h, err := f.AddOn(ctx, net)
	if err != nil {
		return nil, err
	}
	for _, d := range append([]*Device{m}, signers...) {
		sd := filepath.Join(dir, d.Name)
		if err := os.Mkdir(sd, 0o700); err != nil {
			return nil, err
		}
		if _, err := docker(ctx, "cp", d.Container+":/var/lib/cbb/.", sd); err != nil {
			return nil, err
		}
		if _, err := docker(ctx, "cp", sd, h.Container+":/tmp/"+d.Name); err != nil {
			return nil, err
		}
	}
	if err := f.stop(ctx, m); err != nil {
		return nil, err
	}
	if _, err := docker(ctx, "cp", bin, h.Container+":/usr/local/bin/cbbbench-forge"); err != nil {
		return nil, err
	}
	return h, nil
}

// forgeServer starts a container on the network net that runs forge with
// args, such as the stand-in for a well-known site.
func forgeServer(ctx context.Context, f *Fleet, net, args string) (*Device, error) {
	dir, err := os.MkdirTemp("", "cbbfleet-forge")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bin, err := buildForge(ctx, dir)
	if err != nil {
		return nil, err
	}
	d, err := f.addServer(ctx, net, nil, "while [ ! -x /usr/local/bin/cbbbench-forge ]; do sleep 0.2; done; exec cbbbench-forge "+args)
	if err != nil {
		return nil, err
	}
	_, err = docker(ctx, "cp", bin, d.Container+":/usr/local/bin/cbbbench-forge")
	return d, err
}

// forgeOn copies forge into the member d and returns its name there.
func forgeOn(ctx context.Context, d *Device) (string, error) {
	dir, err := os.MkdirTemp("", "cbbfleet-forge")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	bin, err := buildForge(ctx, dir)
	if err != nil {
		return "", err
	}
	_, err = docker(ctx, "cp", bin, d.Container+":/usr/local/bin/cbbbench-forge")
	return "cbbbench-forge", err
}

// runForge runs forge on h as m, with signer's key, against target.
func runForge(ctx context.Context, h, m, signer, target *Device, cases ...string) (string, error) {
	id, err := deviceOf(ctx, target)
	if err != nil {
		return "", err
	}
	ip, err := fleetIP(ctx, target)
	if err != nil {
		return "", err
	}
	return Run(ctx, h, fmt.Sprintf("cbbbench-forge -state /tmp/%s -signer /tmp/%s -to %s -addr %s:8764 %s", m.Name, signer.Name, id, ip, strings.Join(cases, " ")), "")
}

// forgedCommands (T8, S17, S23): a member that is no admin, with an admin's
// signed commands, sends a target one twice, one it changed, one for
// another group and one for another device; the target carries out only
// the first.
func forgedCommands(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/S17-commands/"
	g := fleetGroup(ctx, r, f, "fleet/S17-commands", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, m, t := g.members[0], g.members[1], g.members[2]
	var out string
	if r.Do(p+"forge", func() error {
		h, err := forgeHost(ctx, f, m, root)
		if err != nil {
			return err
		}
		out, err = runForge(ctx, h, m, root, t, "replay", "altered", "other-group", "other-target")
		return err
	}) != nil {
		return
	}
	line := func(name string) string {
		for _, l := range strings.Split(out, "\n") {
			if rest, ok := strings.CutPrefix(l, name+": "); ok {
				return rest
			}
		}
		return "missing"
	}
	expect := func(name, want string) error {
		if got := line(name); !strings.HasPrefix(got, want) {
			return fmt.Errorf("%s: %q, want %q", name, got, want)
		}
		return nil
	}
	r.Do("fleet/S17-replayed", func() error {
		if err := expect("replay 1", "done"); err != nil {
			return err
		}
		if err := expect("replay 2", "refused: this command was carried out already"); err != nil {
			return err
		}
		return succeeds(ctx, t, "cbb sync", "", "Sync is off")
	})
	r.Do("fleet/S23-changed", func() error { return expect("altered 1", "refused: group: the record's signature is not valid") })
	r.Do("fleet/T8-other-group", func() error { return expect("other-group 1", "refused: group: the command is for another group") })
	r.Do("fleet/T8-other-target", func() error {
		if got := line("other-target 1"); strings.HasPrefix(got, "done") {
			return fmt.Errorf("a command for another device was carried out: %q", got)
		}
		return succeeds(ctx, t, "cbb sync", "", "Sync is off")
	})
}

// devicesList is d's devices list as cbb status shows it, a line of name
// and device ID for each device.
func devicesList(ctx context.Context, d *Device) ([]string, error) {
	out, err := Run(ctx, d, "cbb status", "")
	if err != nil {
		return nil, err
	}
	var list []string
	table := false
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) > 0 && f[0] == "NAME":
			table = true
		case table && len(f) >= 2:
			list = append(list, f[0]+" "+f[len(f)-1])
		case table:
			table = false
		}
	}
	slices.Sort(list)
	return list, nil
}

// converge (G31): 200 renames signed by the root and an admin at times out
// of order, sent to every member in an order of its own, leave every member
// with one devices list.
func converge(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G31-converge/"
	g := fleetGroup(ctx, r, f, "fleet/G31-converge", 10)
	if g == nil || len(g.members) < 10 {
		return
	}
	root, admin, m := g.members[0], g.members[1], g.members[2]
	others := g.members[3:]
	if r.Do(p+"admin", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		return listsAs(ctx, g.members, admin.Name, "admin", false, timeout)
	}) != nil {
		return
	}
	var h *Device
	if r.Do(p+"records", func() error {
		var err error
		if h, err = forgeHost(ctx, f, m, root, admin); err != nil {
			return err
		}
		if _, err := runForge(ctx, h, m, root, others[0], "make:100:/tmp/root.json"); err != nil {
			return err
		}
		_, err = runForge(ctx, h, m, admin, others[0], "make:100:/tmp/admin.json")
		return err
	}) != nil {
		return
	}
	live := append([]*Device{root, admin}, others...)
	r.Do(p+"sent-in-any-order", func() error {
		// Each member apart from the others while it takes them.
		for i, t := range others {
			for _, o := range live {
				if o != t && o != m {
					if err := cut(ctx, t, o); err != nil {
						return err
					}
				}
			}
			if _, err := runForge(ctx, h, m, root, t, fmt.Sprintf("send:/tmp/root.json:%d", i+1), fmt.Sprintf("send:/tmp/admin.json:%d", 100+i)); err != nil {
				return err
			}
			if err := heal(ctx, live...); err != nil {
				return err
			}
		}
		return nil
	})
	r.Do(p+"one-list", func() error {
		return eventually(ctx, 3*timeout, func() error {
			first, err := devicesList(ctx, live[0])
			if err != nil {
				return err
			}
			if !strings.Contains(strings.Join(first, "\n"), "make-") {
				return fmt.Errorf("%s lists none of the renames: %v", live[0].Name, first)
			}
			for _, d := range live[1:] {
				l, err := devicesList(ctx, d)
				if err != nil {
					return err
				}
				if !slices.Equal(l, first) {
					return fmt.Errorf("%s lists %v, %s lists %v", live[0].Name, first, d.Name, l)
				}
			}
			return nil
		})
	})
}

// recordLimits (G32): an admin signs at most 1024 records; with the set
// full, the root's removal of an admin still counts everywhere.
func recordLimits(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G32-limits/"
	g := fleetGroup(ctx, r, f, "fleet/G32-limits", 7)
	if g == nil || len(g.members) < 7 {
		return
	}
	root, m, t := g.members[0], g.members[1], g.members[2]
	admins := g.members[3:]
	if r.Do(p+"admins", func() error {
		for _, a := range admins {
			if err := succeeds(ctx, root, "cbb admin -allow-file-key "+a.Name, "", "is an admin now"); err != nil {
				return err
			}
		}
		return listsAs(ctx, g.members, admins[len(admins)-1].Name, "admin", false, timeout)
	}) != nil {
		return
	}
	var h *Device
	if r.Do(p+"forge", func() error {
		var err error
		h, err = forgeHost(ctx, f, m, admins...)
		return err
	}) != nil {
		return
	}
	r.Do(p+"per-admin", func() error {
		if _, err := runForge(ctx, h, m, admins[0], t, "flood:1024:"+t.Name); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root, t}, "flood-1023", "", false, 2*timeout); err != nil {
			return err
		}
		// One more from the same admin, later, is not taken.
		if _, err := runForge(ctx, h, m, admins[0], t, "flood:1:"+t.Name); err != nil {
			return err
		}
		time.Sleep(quiet)
		return listsAs(ctx, []*Device{root, t}, "flood-1023", "", false, timeout)
	})
	r.Do(p+"set-full", func() error {
		for _, a := range admins[1:] {
			if _, err := runForge(ctx, h, m, a, t, "flood:1024:"+t.Name); err != nil {
				return err
			}
		}
		return nil
	})
	r.Do(p+"root-still-removes", func() error {
		if _, err := Run(ctx, root, "cbb remove "+admins[0].Name, ""); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{root, t, admins[1]}, admins[0].Name, "", true, 3*timeout)
	})
}

// adminChain (K14): a device an admin computer admitted presents the admin
// CA in TLS and every member takes it; removing that admin keeps it.
func adminChain(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/K14-admin-chain/"
	g := fleetGroup(ctx, r, f, "fleet/K14-admin-chain", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, admin, m := g.members[0], g.members[1], g.members[2]
	var d *Device
	if r.Do(p+"admitted", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		if err := listsAs(ctx, g.members, admin.Name, "admin", false, timeout); err != nil {
			return err
		}
		var err error
		if d, err = f.Add(ctx); err != nil {
			return err
		}
		ip, err := fleetIP(ctx, admin)
		if err != nil {
			return err
		}
		a := *admin
		a.Address = ip + ":8764"
		if _, err := pairOne(ctx, &a, d); err != nil {
			return err
		}
		g.members = append(g.members, d)
		return setMode(ctx, d, "shared")
	}) != nil {
		return
	}
	r.Do(p+"chain-presented", func() error {
		// Its certificate is the admin CA's, not the root's.
		out, err := Run(ctx, d, "cat /var/lib/cbb/identity.json", "")
		if err == nil && !strings.Contains(out, "issuer") {
			err = fmt.Errorf("the identity of a device an admin admitted names no issuer: %.200s", out)
		}
		return err
	})
	r.Do(p+"every-member", func() error {
		for _, to := range []*Device{root, m} {
			if err := syncs(ctx, g, d, to, "from a device an admin admitted to "+to.Name, timeout); err != nil {
				return err
			}
		}
		return syncs(ctx, g, m, d, "to a device an admin admitted", timeout)
	})
	r.Do(p+"kept-after-removal", func() error {
		if _, err := Run(ctx, root, "cbb remove "+admin.Name, ""); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root, m}, admin.Name, "", true, timeout); err != nil {
			return err
		}
		return syncs(ctx, g, d, m, "after its admin was removed", timeout)
	})
}
