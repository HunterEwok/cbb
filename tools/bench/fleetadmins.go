// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// offline (G25): a device that was off during a removal hears of it from
// the first member it meets; a removed device that was off reaches nobody.
func offline(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G25-offline/"
	g := fleetGroup(ctx, r, f, "fleet/G25-offline", 4)
	if g == nil || len(g.members) < 4 {
		return
	}
	root, m, gone, late := g.members[0], g.members[1], g.members[2], g.members[3]
	if r.Do(p+"off", func() error {
		if err := f.stop(ctx, late); err != nil {
			return err
		}
		return f.stop(ctx, gone)
	}) != nil {
		return
	}
	r.Do(p+"remove", func() error {
		if _, err := Run(ctx, root, "cbb remove "+gone.Name, ""); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{root, m}, gone.Name, "", true, timeout)
	})
	// The root goes away, so the late device can hear of the removal only
	// from the member.
	r.Do(p+"from-a-member", func() error {
		if err := f.stop(ctx, root); err != nil {
			return err
		}
		if err := f.start(ctx, late); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{late}, gone.Name, "", true, 2*timeout)
	})
	r.Do(p+"removed-reaches-nobody", func() error {
		if err := f.start(ctx, root); err != nil {
			return err
		}
		if err := f.start(ctx, gone); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " from a removed device"
		if err := Copy(ctx, gone, text); err != nil {
			return err
		}
		for _, d := range []*Device{root, m, late} {
			if err := staysAway(ctx, d, text); err != nil {
				return err
			}
		}
		return nil
	})
}

// takeoverUndone (G27): an admin takes the group over while the root is
// cut off but still there; the root removes that admin, and once the
// network is whole again the takeover counts for nothing.
func takeoverUndone(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G27-takeover-undone/"
	g := fleetGroup(ctx, r, f, "fleet/G27-takeover-undone", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, admin, m := g.members[0], g.members[1], g.members[2]
	defer heal(ctx, g.members...)
	if r.Do(p+"admin", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		return listsAs(ctx, g.members, admin.Name, "admin", false, timeout)
	}) != nil {
		return
	}
	if r.Do(p+"root-cut-off", func() error {
		if err := cut(ctx, root, admin); err != nil {
			return err
		}
		return cut(ctx, root, m)
	}) != nil {
		return
	}
	r.Do(p+"takeover", func() error {
		if _, err := Run(ctx, admin, "cbb takeover "+root.Name, ""); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{admin, m}, admin.Name, "root", false, timeout)
	})
	r.Do(p+"root-removes-it", func() error {
		_, err := Run(ctx, root, "cbb remove "+admin.Name, "")
		return err
	})
	r.Do(p+"undone", func() error {
		if err := heal(ctx, g.members...); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root, m}, root.Name, "root", false, 3*timeout); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root, m}, admin.Name, "", true, timeout); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " from the root after the takeover"
		if err := Copy(ctx, root, text); err != nil {
			return err
		}
		return arrives(ctx, m, text, timeout)
	})
	// Again with m as the admin, and the root back before it removes it:
	// it hears of the takeover, says so, and undoes it then.
	if r.Do(p+"second-admin", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+m.Name, "", "is an admin now"); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root, m}, m.Name, "admin", false, timeout); err != nil {
			return err
		}
		return cut(ctx, root, m)
	}) != nil {
		return
	}
	r.Do(p+"second-takeover", func() error {
		if _, err := Run(ctx, m, "cbb takeover "+root.Name, ""); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{m}, m.Name, "root", false, timeout)
	})
	r.Do(p+"root-told", func() error {
		if err := heal(ctx, root, m); err != nil {
			return err
		}
		return eventually(ctx, 3*timeout, func() error {
			return succeeds(ctx, root, "cbb status", "", m.Name+", an admin, took the group over from this computer")
		})
	})
	r.Do(p+"undone-after", func() error {
		if _, err := Run(ctx, root, "cbb remove "+m.Name, ""); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root}, root.Name, "root", false, 3*timeout); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{root}, m.Name, "", true, timeout)
	})
}

// concurrentAdmins (G33): admins acting at once on the same devices; every
// member ends with the same devices list.
func concurrentAdmins(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G33-admins-at-once/"
	g := fleetGroup(ctx, r, f, "fleet/G33-admins-at-once", 6)
	if g == nil || len(g.members) < 6 {
		return
	}
	root, a1, a2, x, y, z := g.members[0], g.members[1], g.members[2], g.members[3], g.members[4], g.members[5]
	if r.Do(p+"admins", func() error {
		for _, a := range []*Device{a1, a2} {
			if err := succeeds(ctx, root, "cbb admin -allow-file-key "+a.Name, "", "is an admin now"); err != nil {
				return err
			}
		}
		return listsAs(ctx, g.members, a2.Name, "admin", false, timeout)
	}) != nil {
		return
	}
	// at runs the commands at once, one on each device, and returns the
	// first error of a command that must not fail.
	at := func(cmds map[*Device]string) error {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var errs []error
		for d, cmd := range cmds {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := Run(ctx, d, cmd, ""); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		return errors.Join(errs...)
	}
	r.Do(p+"two-remove-one", func() error {
		// One of the two may find the device gone already.
		at(map[*Device]string{a1: "cbb remove " + x.Name, a2: "cbb remove " + x.Name})
		return listsAs(ctx, []*Device{root, a1, a2, y, z}, x.Name, "", true, timeout)
	})
	r.Do(p+"two-rename-one", func() error {
		id, err := deviceOf(ctx, y)
		if err != nil {
			return err
		}
		if err := at(map[*Device]string{a1: "cbb rename " + id + " y-by-a1", a2: "cbb rename " + id + " y-by-a2"}); err != nil {
			return err
		}
		live := []*Device{root, a1, a2, y, z}
		return eventually(ctx, 2*timeout, func() error {
			var first string
			for _, d := range live {
				out, err := Run(ctx, d, "cbb status", "")
				if err != nil {
					return err
				}
				name := ""
				switch {
				case strings.Contains(out, "y-by-a1"):
					name = "y-by-a1"
				case strings.Contains(out, "y-by-a2"):
					name = "y-by-a2"
				}
				if name == "" {
					return fmt.Errorf("%s lists neither new name", d.Name)
				}
				if first == "" {
					first = name
				} else if name != first {
					return fmt.Errorf("the members disagree on the name: %s and %s", first, name)
				}
			}
			return nil
		})
	})
	r.Do(p+"admit-while-removing", func() error {
		d, err := f.Add(ctx)
		if err != nil {
			return err
		}
		errc := make(chan error, 1)
		go func() {
			_, err := pairOne(ctx, a1, d)
			errc <- err
		}()
		if _, err := Run(ctx, a2, "cbb remove "+z.Name, ""); err != nil {
			return err
		}
		if err := <-errc; err != nil {
			return err
		}
		live := []*Device{root, a1, a2, d}
		if err := listsAs(ctx, live, d.Name, "", false, timeout); err != nil {
			return err
		}
		return listsAs(ctx, live, z.Name, "", true, timeout)
	})
	r.Do(p+"freeze-each-other", func() error {
		// Whichever freeze a device hears of first, the other admin then
		// refuses to sign (it is frozen) or is refused by the members: at
		// least one ends frozen, and every member agrees on which.
		at(map[*Device]string{a1: "cbb freeze " + a2.Name, a2: "cbb freeze " + a1.Name})
		live := []*Device{root, y}
		var frozen []*Device
		if err := eventually(ctx, 2*timeout, func() error {
			frozen = nil
			for _, a := range []*Device{a1, a2} {
				marks := map[bool]bool{}
				for _, d := range live {
					row, err := statusRow(ctx, d, a.Name)
					if err != nil {
						return err
					}
					marks[strings.Contains(row, "frozen")] = true
				}
				if len(marks) > 1 {
					return fmt.Errorf("the members disagree whether %s is frozen", a.Name)
				}
				if marks[true] {
					frozen = append(frozen, a)
				}
			}
			if len(frozen) == 0 {
				return errors.New("neither admin is frozen")
			}
			return nil
		}); err != nil {
			return err
		}
		// The root decides.
		for _, a := range frozen {
			if _, err := Run(ctx, root, "cbb unfreeze "+a.Name, ""); err != nil {
				return err
			}
			if err := listsAs(ctx, live, a.Name, "admin", false, timeout); err != nil {
				return err
			}
		}
		return nil
	})
}

// stolenAdmin (S24): an admin computer's state copied to another machine
// acts as that admin until any admin freezes it; after that nothing it
// signs counts.
func stolenAdmin(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/S24-stolen-admin/"
	g := fleetGroup(ctx, r, f, "fleet/S24-stolen-admin", 4)
	if g == nil || len(g.members) < 4 {
		return
	}
	root, admin, m1, m2 := g.members[0], g.members[1], g.members[2], g.members[3]
	if r.Do(p+"admin", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		return listsAs(ctx, g.members, admin.Name, "admin", false, timeout)
	}) != nil {
		return
	}
	var thief *Device
	if r.Do(p+"copied", func() error {
		var err error
		if thief, err = f.Add(ctx); err != nil {
			return err
		}
		// The admin's state, as a thief would copy it from the disk, on
		// a machine of its own; the owner's computer goes off.
		dir, err := os.MkdirTemp("", "cbbfleet-stolen")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		if _, err := docker(ctx, "cp", admin.Container+":/var/lib/cbb/.", dir); err != nil {
			return err
		}
		if err := f.stop(ctx, admin); err != nil {
			return err
		}
		if err := f.stop(ctx, thief); err != nil {
			return err
		}
		if _, err := docker(ctx, "cp", dir+"/.", thief.Container+":/var/lib/cbb/"); err != nil {
			return err
		}
		return f.start(ctx, thief)
	}) != nil {
		return
	}
	r.Do(p+"acts", func() error {
		return eventually(ctx, 2*timeout, func() error {
			if _, err := Run(ctx, thief, "cbb sync -on "+m1.Name+" off", ""); err != nil {
				return err
			}
			return succeeds(ctx, m1, "cbb sync", "", "Sync is off")
		})
	})
	r.Do(p+"frozen", func() error {
		if _, err := Run(ctx, root, "cbb freeze "+admin.Name, ""); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{root, m1, m2}, admin.Name, "frozen", false, timeout)
	})
	r.Do(p+"counts-for-nothing", func() error {
		// What it signs now is refused: a removal and a mode.
		Run(ctx, thief, "cbb remove "+m2.Name, "")
		Run(ctx, thief, "cbb sync -on "+m1.Name+" on", "")
		time.Sleep(quiet)
		if err := listsAs(ctx, []*Device{root, m1}, m2.Name, "", false, timeout); err != nil {
			return err
		}
		return succeeds(ctx, m1, "cbb sync", "", "Sync is off")
	})
}

// modeKept (M4): sync off survives a restart of the service and of the
// machine, and every devices list shows it.
func modeKept(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/M4-mode-kept/"
	g := fleetGroup(ctx, r, f, "fleet/M4-mode-kept", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	d := g.members[2]
	if r.Do(p+"set", func() error { return setMode(ctx, d, "own") }) != nil {
		return
	}
	r.Do(p+"service-restart", func() error {
		if _, err := Run(ctx, d, fleetKill, ""); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error { return succeeds(ctx, d, "cbb sync", "", "Sync is off") })
	})
	r.Do(p+"reboot", func() error {
		if err := f.stop(ctx, d); err != nil {
			return err
		}
		if err := f.start(ctx, d); err != nil {
			return err
		}
		return succeeds(ctx, d, "cbb sync", "", "Sync is off")
	})
	r.Do(p+"lists", func() error { return listsAs(ctx, g.members, d.Name, " off ", false, timeout) })
}
