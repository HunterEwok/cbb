// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// walkSteps is how many steps the random walk takes.
const walkSteps = 200

// deviceIDRE matches a device ID, the last column of cbb status.
var deviceIDRE = regexp.MustCompile(`^[0-9a-f]{8,}$`)

// walker is a member of the walk's group as the walk expects every member
// to list it.
type walker struct {
	d        *Device
	id, name string
	mark     string // the ADMIN column: "root", "admin", "frozen" or ""
	text     string // the last text copied since it joined
	frozenBy *walker
}

// randomWalk (G40): steps chosen at random among join, remove, rename, make
// admin, freeze, unfreeze, takeover, restart, sleep, network cut and copy;
// after each step every member that syncs lists the same devices, with the
// names and admin marks the steps gave them, and holds the last text copied
// since it joined. The seed is printed, and CBB_BENCH_SEED repeats a walk.
func randomWalk(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G40-random-walk/"
	g := fleetGroup(ctx, r, f, "fleet/G40-random-walk", 4)
	if g == nil || len(g.members) < 4 {
		return
	}
	var spares []*Device
	if r.Do(p+"spares", func() error {
		var err error
		spares, err = f.AddN(ctx, 2)
		return err
	}) != nil {
		return
	}
	seed := uint64(time.Now().UnixNano())
	if s, err := strconv.ParseUint(os.Getenv("CBB_BENCH_SEED"), 10, 64); err == nil {
		seed = s
	}
	fmt.Fprintf(r.out, "G40: seed %d\n", seed)
	rng := rand.New(rand.NewPCG(seed, seed))

	var live []*walker
	if r.Do(p+"members", func() error {
		for i, d := range g.members {
			id, err := deviceOf(ctx, d)
			if err != nil {
				return err
			}
			w := &walker{d: d, id: id, name: d.Name}
			if i == 0 {
				w.mark = "root"
			}
			live = append(live, w)
		}
		return nil
	}) != nil {
		return
	}
	// syncing are the members that must agree: a frozen admin's
	// connections are refused.
	syncing := func() []*walker {
		return slices.DeleteFunc(slices.Clone(live), func(w *walker) bool { return w.mark == "frozen" })
	}
	with := func(mark string) []*walker {
		return slices.DeleteFunc(slices.Clone(live), func(w *walker) bool { return w.mark != mark })
	}
	pick := func(ws []*walker) *walker { return ws[rng.IntN(len(ws))] }
	root := func() *walker { return with("root")[0] }
	// actors sign for the group: the root and the admins not frozen.
	actors := func() []*walker { return append(with("root"), with("admin")...) }
	copyFrom := func(step int, w *walker) error {
		// A device that joins later keeps its own clipboard: the group's
		// text is too old for it (Y20).
		text := fmt.Sprintf("cbb-bench G40 step %d from %s", step, w.name)
		for _, x := range live {
			x.text = text
		}
		return Copy(ctx, w.d, text)
	}
	// wipe takes a container out of the group for good: no state, its
	// service started again in no group, as a spare.
	wipe := func(d *Device) error {
		if _, err := Run(ctx, d, fleetKill+"; rm -rf /var/lib/cbb/*", ""); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			tag, err := groupOf(ctx, d)
			if err == nil && tag != "" {
				err = fmt.Errorf("%s is still in group %s", d.Name, tag)
			}
			return err
		})
	}
	drop := func(w *walker) {
		live = slices.DeleteFunc(live, func(x *walker) bool { return x == w })
		spares = append(spares, w.d)
		// Removing the admin that froze one ends its freezes
		// (docs/protocol.md, section 10, "Removals and freezes keep what the author saw"); a lost root's stay
		// after a takeover, until the new root unfreezes.
		for _, x := range live {
			if x.frozenBy == w && w.mark != "root" {
				x.mark, x.frozenBy = "admin", nil
			}
		}
	}
	isolate := func(d *Device) error {
		_, err := Run(ctx, d, "iptables -I INPUT -i eth0 -j DROP && iptables -I OUTPUT -o eth0 -j DROP", "")
		return err
	}
	// settle waits until every syncing member lists the devices as the
	// walk expects and holds the last text copied since it joined.
	settle := func() error {
		want := map[string]string{}
		for _, w := range live {
			want[w.id] = w.name + " | " + w.mark
		}
		for _, w := range syncing() {
			if err := eventually(ctx, 3*timeout, func() error {
				got, online, err := devicesView(ctx, w.d)
				if err != nil {
					return err
				}
				if !maps.Equal(got, want) {
					return fmt.Errorf("%s (%s) lists %v, not %v", w.name, w.d.Name, got, want)
				}
				// Connected to every other member that syncs, as the next
				// step may need: an admin's CA goes over its connection.
				for _, x := range syncing() {
					if x != w && !online[x.id] {
						return fmt.Errorf("%s (%s) is not connected to %s", w.name, w.d.Name, x.name)
					}
				}
				return nil
			}); err != nil {
				return err
			}
			if w.text != "" {
				if err := arrives(ctx, w.d, w.text, timeout); err != nil {
					return err
				}
			}
		}
		return nil
	}

	type action struct {
		name   string
		weight int
		can    func() bool
		do     func(step int) (string, error)
	}
	plain := func() []*walker { return with("") }
	acts := []action{
		{"copy", 6, func() bool { return true }, func(step int) (string, error) {
			w := pick(syncing())
			return w.name, copyFrom(step, w)
		}},
		{"join", 3, func() bool { return len(spares) > 0 }, func(int) (string, error) {
			d, by := spares[0], pick(actors())
			if _, err := pairOne(ctx, by.d, d); err != nil {
				return "", err
			}
			spares = spares[1:]
			if err := setMode(ctx, d, "shared"); err != nil {
				return "", err
			}
			id, err := deviceOf(ctx, d)
			if err != nil {
				return "", err
			}
			live = append(live, &walker{d: d, id: id, name: d.Name})
			return d.Name + " by " + by.name, nil
		}},
		{"remove", 3, func() bool { return len(live) > 3 }, func(int) (string, error) {
			w := pick(slices.DeleteFunc(slices.Clone(live), func(x *walker) bool { return x.mark == "root" }))
			// The root removes admins; any admin removes the others.
			by := root()
			if w.mark == "" {
				by = pick(actors())
			}
			if _, err := Run(ctx, by.d, "cbb remove "+w.id, ""); err != nil {
				return "", err
			}
			drop(w)
			return w.name + " by " + by.name, wipe(w.d)
		}},
		{"rename", 3, func() bool { return true }, func(step int) (string, error) {
			w := pick(live)
			by := root()
			if w.mark == "" {
				by = pick(actors())
			}
			name := fmt.Sprintf("w%03d", step)
			if _, err := Run(ctx, by.d, "cbb rename "+w.id+" "+name, ""); err != nil {
				return "", err
			}
			old := w.name
			w.name = name
			return old + " to " + name + " by " + by.name, nil
		}},
		{"admin", 2, func() bool { return len(plain()) > 0 && len(with("admin"))+len(with("frozen")) < 3 }, func(int) (string, error) {
			w := pick(plain())
			if err := succeeds(ctx, root().d, "cbb admin -allow-file-key "+w.id, "", "is an admin now"); err != nil {
				return "", err
			}
			w.mark = "admin"
			return w.name, nil
		}},
		{"freeze", 3, func() bool { return len(with("admin")) > 1 }, func(int) (string, error) {
			w := pick(with("admin"))
			by := pick(slices.DeleteFunc(actors(), func(x *walker) bool { return x == w }))
			if _, err := Run(ctx, by.d, "cbb freeze "+w.id, ""); err != nil {
				return "", err
			}
			w.mark, w.frozenBy = "frozen", by
			return w.name + " by " + by.name, nil
		}},
		{"unfreeze", 2, func() bool { return len(with("frozen")) > 0 }, func(int) (string, error) {
			w := pick(with("frozen"))
			if _, err := Run(ctx, root().d, "cbb unfreeze "+w.id, ""); err != nil {
				return "", err
			}
			w.mark, w.frozenBy = "admin", nil
			return w.name, nil
		}},
		{"takeover", 1, func() bool { return len(with("admin")) > 0 }, func(int) (string, error) {
			// The root is lost: cut off, then gone for good once an admin
			// took the group over. Back, it would undo the takeover (G27).
			old, w := root(), pick(with("admin"))
			if err := isolate(old.d); err != nil {
				return "", err
			}
			if _, err := Run(ctx, w.d, "cbb takeover "+old.id, ""); err != nil {
				heal(ctx, old.d)
				return "", err
			}
			w.mark = "root"
			drop(old)
			if err := wipe(old.d); err != nil {
				return "", err
			}
			return old.name + " by " + w.name, heal(ctx, old.d)
		}},
		{"restart", 3, func() bool { return true }, func(int) (string, error) {
			w := pick(live)
			// Without a desktop clipboard the text lives in the service
			// alone: a member with no one to sync with comes back empty.
			if w.d.Clipboard == "none" && !slices.ContainsFunc(syncing(), func(x *walker) bool { return x != w }) {
				w.text = ""
			}
			return w.name, signalService(ctx, w.d, "KILL")
		}},
		{"sleep", 2, func() bool { return len(syncing()) > 1 }, func(step int) (string, error) {
			w := pick(live)
			if _, err := docker(ctx, "pause", w.d.Container); err != nil {
				return "", err
			}
			from := pick(slices.DeleteFunc(syncing(), func(x *walker) bool { return x == w }))
			err := copyFrom(step, from)
			time.Sleep(time.Duration(rng.IntN(20)) * time.Second)
			if _, uerr := docker(ctx, "unpause", w.d.Container); uerr != nil {
				return "", uerr
			}
			return w.name + ", copied on " + from.name, err
		}},
		{"cut", 2, func() bool { return len(syncing()) > 1 }, func(step int) (string, error) {
			w := pick(live)
			if err := isolate(w.d); err != nil {
				return "", err
			}
			from := pick(slices.DeleteFunc(syncing(), func(x *walker) bool { return x == w }))
			err := copyFrom(step, from)
			time.Sleep(time.Duration(rng.IntN(40)) * time.Second)
			return w.name + ", copied on " + from.name, errors.Join(err, heal(ctx, w.d))
		}},
	}
	total := 0
	for _, a := range acts {
		total += a.weight
	}
	counts := map[string]int{}
	r.Do(p+"walk", func() error {
		for step := range walkSteps {
			var a action
			for {
				n := rng.IntN(total)
				for _, x := range acts {
					if n -= x.weight; n < 0 {
						a = x
						break
					}
				}
				if a.can() {
					break
				}
			}
			what, err := a.do(step)
			fmt.Fprintf(r.out, "G40: step %d: %s %s\n", step, a.name, what)
			if err != nil {
				return fmt.Errorf("step %d, %s %s: %w", step, a.name, what, err)
			}
			if err := settle(); err != nil {
				// What each member said, for the cause.
				for _, w := range live {
					st, _ := Run(context.WithoutCancel(ctx), w.d, "cbb status", "")
					logs, _ := docker(context.WithoutCancel(ctx), "logs", "--tail", "40", w.d.Container)
					fmt.Fprintf(r.out, "G40: %s (%s, %s):\n%s\n%s\n", w.name, w.d.Name, w.id, st, logs)
				}
				return fmt.Errorf("after step %d, %s %s (seed %d): %w", step, a.name, what, seed, err)
			}
			counts[a.name]++
		}
		fmt.Fprintf(r.out, "G40: %d steps: %v\n", walkSteps, counts)
		return nil
	})
}

// devicesView is the devices list cbb status shows on d: for each device
// ID its name and its ADMIN column, "name | mark", with " *" kept on the
// name of a device not in the devices list yet; and the devices it is
// connected to.
func devicesView(ctx context.Context, d *Device) (map[string]string, map[string]bool, error) {
	out, err := Run(ctx, d, "cbb status", "")
	if err != nil {
		return nil, nil, err
	}
	lines := strings.Split(out, "\n")
	head := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "NAME ") && strings.Contains(l, " ADMIN ") })
	if head < 0 {
		return nil, nil, fmt.Errorf("%s shows no devices list", d.Name)
	}
	h := lines[head]
	sys, adm, keys := strings.Index(h, "SYSTEM"), strings.Index(h, "ADMIN"), strings.Index(h, "KEYS")
	seen, clock := strings.Index(h, "SEEN"), strings.Index(h, "CLOCK")
	view, online := map[string]string{}, map[string]bool{}
	for _, l := range lines[head+1:] {
		fs := strings.Fields(l)
		if len(l) < clock || len(fs) == 0 || !deviceIDRE.MatchString(fs[len(fs)-1]) {
			break
		}
		id := fs[len(fs)-1]
		name := strings.TrimSpace(l[:sys])
		name = strings.Replace(name, " (this device)", "", 1)
		view[id] = name + " | " + strings.TrimSpace(l[adm:keys])
		online[id] = strings.TrimSpace(l[seen:clock]) == "online"
	}
	return view, online, nil
}
