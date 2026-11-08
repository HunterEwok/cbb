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

// notArrives checks that to's clipboard never holds text for timeout.
func notArrives(ctx context.Context, to *Device, text string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got, err := Paste(ctx, to)
		if err != nil {
			return err
		}
		if strings.TrimRight(got, "\r\n") == text {
			return fmt.Errorf("%s got %q", to.Name, text)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil
}

// gone waits until d no longer lists name online.
func gone(ctx context.Context, d *Device, name string, timeout time.Duration) error {
	return eventually(ctx, timeout, func() error {
		row, err := statusRow(ctx, d, name)
		if err == nil && strings.Contains(row, "online") {
			err = fmt.Errorf("%s still lists %s online", d.Name, name)
		}
		return err
	})
}

// copyMaybe copies text on d, which may refuse it (a muted device sends
// nothing, not even a deliberate copy); any other failure is an error.
func copyMaybe(ctx context.Context, d *Device, text string) error {
	err := Copy(ctx, d, text)
	var re *RunError
	if errors.As(err, &re) {
		return nil
	}
	return err
}

// mutedRow waits until every member's row for name shows it muted, or
// with muted false no longer does.
func mutedRow(ctx context.Context, members []*Device, name string, muted bool, timeout time.Duration) error {
	for _, m := range members {
		if err := eventually(ctx, timeout, func() error {
			row, err := statusRow(ctx, m, name)
			if err == nil && strings.Contains(row, "muted") != muted {
				err = fmt.Errorf("%s lists %s as %q; muted: want %v", m.Name, name, row, muted)
			}
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// syncOffHere (M8): cbb sync off on a device: cbb status says so, it
// lasts across a restart, cbb copy there still sends, cbb sync on ends it
// and the group's copies come again, and with -for it ends by itself.
// The fleet's members are headless, where cbb paste prints the group's
// text with sync off too, so the cases read cbb status.
func syncOffHere(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/M8-sync-off/"
	g := fleetGroup(ctx, r, f, "fleet/M8-sync-off", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	a, b, c := g.members[0], g.members[1], g.members[2]
	if r.Do(p+"before", func() error { return syncs(ctx, g, a, b, "before sync off", timeout) }) != nil {
		return
	}
	if r.Do("fleet/M8-sync-off", func() error {
		if err := succeeds(ctx, b, "cbb sync off", "", "Sync is off until cbb sync on"); err != nil {
			return err
		}
		if err := succeeds(ctx, b, "cbb status", "", "Sync is off until cbb sync on"); err != nil {
			return err
		}
		// cbb copy still sends.
		return syncs(ctx, g, b, c, "cbb copy with sync off", timeout)
	}) != nil {
		return
	}
	r.Do("fleet/M8-restart", func() error {
		if err := f.stop(ctx, b); err != nil {
			return err
		}
		if err := f.start(ctx, b); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error { return succeeds(ctx, b, "cbb status", "", "Sync is off") })
	})
	r.Do("fleet/M8-sync-on", func() error {
		if err := succeeds(ctx, b, "cbb sync on", "", "Sync is on"); err != nil {
			return err
		}
		return syncs(ctx, g, a, b, "after cbb sync on", timeout)
	})
	r.Do("fleet/M8-for", func() error {
		if err := succeeds(ctx, b, "cbb sync off -for 8s", "", "Sync is off until"); err != nil {
			return err
		}
		time.Sleep(10 * time.Second)
		if err := succeeds(ctx, b, "cbb status", "", "Sync is on"); err != nil {
			return err
		}
		return syncs(ctx, g, a, b, "after the time ran out", timeout)
	})
}

// muteByAdmin (M9): an admin mutes a device for the whole group: its copies
// reach no one, every devices list says it is muted, its own user, no
// admin, cannot end it, another admin can (the last command counts), a mute
// for a time ends by itself, and a device that is no admin mutes no one; a
// mute of a device that cannot be reached is refused with why; of two
// admins' mutes the later stands, even a shorter one.
func muteByAdmin(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/M9-admin-mute/"
	g := fleetGroup(ctx, r, f, "fleet/M9-admin-mute", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, admin, b := g.members[0], g.members[1], g.members[2]
	quiet := 10 * time.Second
	text := func(what string) string { return "cbb-bench " + g.run + " " + what }
	var rootID, bID string
	if r.Do(p+"setup", func() error {
		var err error
		if rootID, err = deviceOf(ctx, root); err != nil {
			return err
		}
		if bID, err = deviceOf(ctx, b); err != nil {
			return err
		}
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{admin}, admin.Name, "admin", false, timeout); err != nil {
			return err
		}
		return syncs(ctx, g, b, root, "before the mute", timeout)
	}) != nil {
		return
	}
	// silent copies what on b and checks that neither admin gets it.
	silent := func(what string) error {
		if err := copyMaybe(ctx, b, text(what)); err != nil {
			return err
		}
		if err := notArrives(ctx, root, text(what), quiet); err != nil {
			return err
		}
		return notArrives(ctx, admin, text(what), 2*time.Second)
	}
	if r.Do("fleet/M9-admin-mute", func() error {
		if err := succeeds(ctx, root, "cbb mute -on "+bID, "", "is muted until an admin unmutes it"); err != nil {
			return err
		}
		if err := mutedRow(ctx, []*Device{root, admin, b}, b.Name, true, timeout); err != nil {
			return err
		}
		if err := succeeds(ctx, b, "cbb status", "", "An admin muted this device"); err != nil {
			return err
		}
		return silent("from the muted device")
	}) != nil {
		return
	}
	r.Do("fleet/M9-own-user", func() error {
		// cbb unmute on b ends only its own pause, not the admin's mute.
		if _, err := Run(ctx, b, "cbb unmute", ""); err != nil {
			var re *RunError
			if !errors.As(err, &re) {
				return err
			}
		}
		return silent("after its own cbb unmute")
	})
	fails(ctx, r, "fleet/M9-not-admin", b, errorCase{cmd: "cbb mute -on " + rootID, want: []string{"only an admin mutes a device"}})
	r.Do("fleet/M9-other-admin", func() error {
		if err := succeeds(ctx, admin, "cbb unmute -on "+bID, "", "is no longer muted"); err != nil {
			return err
		}
		if err := mutedRow(ctx, []*Device{root, admin}, b.Name, false, timeout); err != nil {
			return err
		}
		return syncs(ctx, g, b, root, "after the other admin unmuted it", timeout)
	})
	r.Do("fleet/M9-for", func() error {
		if err := succeeds(ctx, root, "cbb mute -on "+bID+" -for 15s", "", "is muted until"); err != nil {
			return err
		}
		start := time.Now()
		if err := silent("during the mute for a time"); err != nil {
			return err
		}
		time.Sleep(time.Until(start.Add(18 * time.Second)))
		return eventually(ctx, timeout, func() error {
			return syncs(ctx, g, b, root, "after the mute's time ran out", 10*time.Second)
		})
	})
	r.Do("fleet/M9-offline", func() error {
		// The mute is a command to the device: one that cannot be reached
		// is refused with why, and stays as it was when it is back.
		for _, d := range []*Device{root, admin} {
			if err := cut(ctx, b, d); err != nil {
				return err
			}
		}
		defer heal(ctx, root, admin, b)
		if err := gone(ctx, root, b.Name, timeout); err != nil {
			return err
		}
		out, err := Run(ctx, root, "cbb mute -on "+bID, "")
		var re *RunError
		if !errors.As(err, &re) {
			return fmt.Errorf("a mute of a device that cannot be reached was not refused: %q, %v", strings.TrimSpace(out), err)
		}
		if !strings.Contains(re.Output, "did not answer in time") {
			return fmt.Errorf("refused with %q, not because the device did not answer", strings.TrimSpace(re.Output))
		}
		if err := heal(ctx, root, admin, b); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root}, b.Name, "online", false, timeout); err != nil {
			return err
		}
		return mutedRow(ctx, []*Device{root, admin, b}, b.Name, false, timeout)
	})
	r.Do("fleet/M9-last-counts", func() error {
		// Two admins one after the other, before either's record has
		// reached the other: the later command stands everywhere, even when
		// it shortens the mute.
		if err := succeeds(ctx, admin, "cbb unmute -on "+bID, "", "is no longer muted"); err != nil {
			return err
		}
		if err := mutedRow(ctx, []*Device{root, admin, b}, b.Name, false, timeout); err != nil {
			return err
		}
		if err := succeeds(ctx, root, "cbb mute -on "+bID+" -for 1h", "", "is muted until"); err != nil {
			return err
		}
		if err := succeeds(ctx, admin, "cbb mute -on "+bID+" -for 15s", "", "is muted until"); err != nil {
			return err
		}
		start := time.Now()
		if err := silent("between the two admins' mutes"); err != nil {
			return err
		}
		time.Sleep(time.Until(start.Add(18 * time.Second)))
		if err := mutedRow(ctx, []*Device{root, admin, b}, b.Name, false, timeout); err != nil {
			return err
		}
		return syncs(ctx, g, b, root, "after the later, shorter mute ran out", timeout)
	})
}

// incoming (M10): the group's copies setting: the root sets how long a copy
// from another device stays live, every member shows it, a value out of
// 5s to 1h and a device that is no admin are refused; a device cut off for
// 10 seconds writes the copy made meanwhile with a window of 1m, and not
// with one of 5s.
func incoming(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/M10-incoming/"
	g := fleetGroup(ctx, r, f, "fleet/M10-incoming", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	root, b := g.members[0], g.members[1]
	shows := func(d *Device, want string) error {
		return eventually(ctx, timeout, func() error {
			return succeeds(ctx, d, "cbb incoming", "", "goes into the clipboard for "+want+" after it arrives")
		})
	}
	r.Do(p+"default", func() error { return shows(b, "1m") })
	r.Do("fleet/M10-incoming", func() error {
		if err := succeeds(ctx, root, "cbb incoming 5s", "", "for 5s after it arrives"); err != nil {
			return err
		}
		if err := shows(b, "5s"); err != nil {
			return err
		}
		return syncs(ctx, g, root, b, "after the setting changed", timeout)
	})
	for _, v := range []string{"4s", "2h"} {
		fails(ctx, r, p+"bounds-"+v, root, errorCase{cmd: "cbb incoming " + v, want: []string{"from 5s to 1h"}})
	}
	fails(ctx, r, p+"not-admin", b, errorCase{cmd: "cbb incoming 10s", want: []string{"only the group's root or an admin"}})
	// late cuts b off, copies on the root, waits 10 seconds and brings b
	// back, which then writes the copy only within the live window.
	late := func(what string, live bool) error {
		if err := cut(ctx, root, b); err != nil {
			return err
		}
		defer heal(ctx, root, b)
		// Only once the connection is gone: a copy sent into one that
		// stalls arrives with the age it had when it was sent.
		if err := gone(ctx, b, root.Name, timeout); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " " + what
		if err := Copy(ctx, root, text); err != nil {
			return err
		}
		time.Sleep(10 * time.Second)
		if err := heal(ctx, root, b); err != nil {
			return err
		}
		if live {
			return arrives(ctx, b, text, timeout)
		}
		if err := notArrives(ctx, b, text, 20*time.Second); err != nil {
			return fmt.Errorf("%w after the window of 5s had passed", err)
		}
		return syncs(ctx, g, root, b, "after the late copy", timeout)
	}
	r.Do("fleet/M10-window", func() error {
		if err := succeeds(ctx, root, "cbb incoming 5s", "", "for 5s after it arrives"); err != nil {
			return err
		}
		if err := shows(b, "5s"); err != nil {
			return err
		}
		return late("past the window", false)
	})
	r.Do(p+"back", func() error {
		if err := succeeds(ctx, root, "cbb incoming 1m", "", "for 1m after it arrives"); err != nil {
			return err
		}
		if err := shows(b, "1m"); err != nil {
			return err
		}
		return late("within the window", true)
	})
}
