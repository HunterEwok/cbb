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

// actionRefused runs cbb action -on target name on from, which must fail
// with reason.
func actionRefused(ctx context.Context, from, target *Device, name, reason string) error {
	out, err := Run(ctx, from, "cbb action -on "+target.Name+" "+name, "")
	var re *RunError
	switch {
	case err == nil:
		return fmt.Errorf("%s ran %s on %s, which should be refused: %s", from.Name, name, target.Name, firstLine(out))
	case !errors.As(err, &re):
		return err
	case !strings.Contains(re.Output, reason):
		return fmt.Errorf("refused with %q, not %q", strings.TrimSpace(re.Output), reason)
	}
	return nil
}

// quickActions (Q1, Q2, Q4, Q5, Q6, Q7): the quick actions a device's user
// turns on and the group's admins run on it, the restart of the service
// among them; the others need a session or a real system (Q3) and run on
// the real devices.
func quickActions(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/Q6-actions/"
	g := fleetGroup(ctx, r, f, "fleet/Q6-actions", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, admin, t := g.members[0], g.members[1], g.members[2]
	if r.Do(p+"admin", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		return listsAs(ctx, g.members, admin.Name, "admin", false, timeout)
	}) != nil {
		return
	}
	r.Do("fleet/Q1-all-off", func() error {
		out, err := Run(ctx, t, "cbb action", "")
		if err != nil {
			return err
		}
		for _, a := range []string{"lock", "sleep", "reboot", "shutdown", "cancel-shutdown", "restart"} {
			found := false
			for _, l := range strings.Split(out, "\n") {
				if f := strings.Fields(l); len(f) == 2 && f[0] == a && f[1] == "off" {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("cbb action does not list %s as off: %q", a, out)
			}
		}
		return nil
	})
	r.Do(p+"off-says-how", func() error {
		return actionRefused(ctx, root, t, "lock", "sudo cbb action enable lock")
	})
	// Q2: enabling writes the polkit rule for what is on, disabling takes
	// it back.
	const rule = "/etc/polkit-1/rules.d/60-cbb.rules"
	r.Do("fleet/Q2-polkit", func() error {
		if err := succeeds(ctx, t, "cbb action enable reboot -yes", "", "reboot: on"); err != nil {
			return err
		}
		if err := succeeds(ctx, t, "cat "+rule, "", "org.freedesktop.login1.reboot"); err != nil {
			return err
		}
		if err := succeeds(ctx, t, "cbb action disable reboot", "", "reboot: off"); err != nil {
			return err
		}
		out, _ := Run(ctx, t, "cat "+rule+" 2>/dev/null", "")
		if strings.Contains(out, "login1.reboot") {
			return fmt.Errorf("the polkit rule still allows reboot: %q", out)
		}
		return nil
	})
	// Q4: reboot only for keys in hardware unless -any-key; -by limits the
	// kinds of admins.
	r.Do("fleet/Q4-file-keys", func() error {
		if err := succeeds(ctx, t, "cbb action enable reboot -yes", "", "keys in hardware only"); err != nil {
			return err
		}
		defer Run(ctx, t, "cbb action disable reboot", "")
		return actionRefused(ctx, root, t, "reboot", "-any-key")
	})
	r.Do("fleet/Q4-by", func() error {
		if err := succeeds(ctx, t, "cbb action enable restart -yes -by root", "", "restart: on, for root"); err != nil {
			return err
		}
		if err := actionRefused(ctx, admin, t, "restart", "root"); err != nil {
			return err
		}
		return succeeds(ctx, root, "cbb action -on "+t.Name+" restart", "", "ran restart")
	})
	// Q6: the restart runs, and the device is back in the group.
	r.Do(p+"restart-runs", func() error {
		if err := succeeds(ctx, t, "cbb action enable restart -yes", "", "restart: on, for every admin"); err != nil {
			return err
		}
		pid := func() string {
			out, _ := Run(ctx, t, "pgrep -f '^cbb service' || true", "")
			return strings.TrimSpace(out)
		}
		before := pid()
		if err := succeeds(ctx, admin, "cbb action -on "+t.Name+" restart", "", "ran restart"); err != nil {
			return err
		}
		// The service restarts a moment after its result went out: wait for
		// the new one before the sync, so the restart does not land in the
		// cases after.
		if err := eventually(ctx, timeout, func() error {
			if now := pid(); now == "" || now == before {
				return fmt.Errorf("%s's service has not restarted", t.Name)
			}
			_, err := Run(ctx, t, "cbb status", "")
			return err
		}); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error { return syncs(ctx, g, root, t, "after the restart", timeout) })
	})
	r.Do(p+"member-refused", func() error {
		_, err := Run(ctx, t, "cbb action -on "+admin.Name+" restart", "")
		if err == nil {
			return errors.New("a member that is no admin ran an action")
		}
		return nil
	})
	// Q5: an action of the user's own takes a full path and runs in the
	// user's session, which a container has not.
	fails(ctx, r, "fleet/Q5-relative-path", t, errorCase{cmd: "cbb action add mine -yes -- bin/true", want: []string{"full path"}})
	r.Do("fleet/Q5-no-session", func() error {
		if err := succeeds(ctx, t, "cbb action add mine -yes -- /bin/true", "", "mine: on"); err != nil {
			return err
		}
		defer Run(ctx, t, "cbb action remove mine", "")
		return actionRefused(ctx, root, t, "mine", "nobody is signed in")
	})
	// Q7: off from afar, on one device and on all; only the device's user
	// turns them on again.
	r.Do("fleet/Q7-off-one", func() error {
		if _, err := Run(ctx, admin, "cbb action off -on "+t.Name, ""); err != nil {
			return err
		}
		if err := eventually(ctx, timeout, func() error {
			return actionRefused(ctx, root, t, "restart", "off")
		}); err != nil {
			return err
		}
		return succeeds(ctx, t, "cbb action enable restart -yes", "", "restart: on")
	})
	r.Do("fleet/Q7-off-all", func() error {
		if err := succeeds(ctx, admin, "cbb action enable restart -yes", "", "restart: on"); err != nil {
			return err
		}
		if _, err := Run(ctx, root, "cbb action off -all", ""); err != nil {
			return err
		}
		for _, d := range []*Device{t, admin} {
			if err := eventually(ctx, timeout, func() error {
				return succeeds(ctx, d, "cbb action", "", "restart          off")
			}); err != nil {
				return err
			}
		}
		return nil
	})
	// A frozen admin runs nothing.
	r.Do(p+"frozen-refused", func() error {
		if err := succeeds(ctx, t, "cbb action enable restart -yes", "", "restart: on"); err != nil {
			return err
		}
		if _, err := Run(ctx, root, "cbb freeze "+admin.Name, ""); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{t}, admin.Name, "frozen", false, timeout); err != nil {
			return err
		}
		_, err := Run(ctx, admin, "cbb action -on "+t.Name+" restart", "")
		if err == nil {
			return errors.New("a frozen admin ran an action")
		}
		return nil
	})
}
