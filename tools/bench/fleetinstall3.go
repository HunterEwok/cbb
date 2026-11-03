// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// exitCode is the exit status of the command a Run error stands for, or -1.
func exitCode(err error) int {
	var re *RunError
	if errors.As(err, &re) {
		err = re.Err
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// installerErrors (I25, Linux): a step of install.sh or uninstall.sh that
// fails ends the script with that step's exit status and says it, with how
// to see more; CBB_ERROR_DETAILS=1 shows every command as it runs, the
// failed one too, instead. A command of the scripts is made to fail by a
// stand-in that comes first on the PATH of that run only.
func installerErrors(ctx context.Context, r *Report, f *Fleet, archive string) {
	const p = "fleet/I25-installer-errors/"
	var d *Device
	if r.Do(p+"setup", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, f.net); err != nil {
			return err
		}
		if _, err := installArchive(ctx, d, archive, "--no-firewall --auto-update off"); err != nil {
			return err
		}
		// Stand-ins: install fails with 7, rm with 5.
		_, err = Run(ctx, d, `mkdir -p /tmp/fail && printf '#!/bin/sh\nexit 7\n' >/tmp/fail/install && printf '#!/bin/sh\nexit 5\n' >/tmp/fail/rm && chmod +x /tmp/fail/install /tmp/fail/rm`, "")
		return err
	}) != nil {
		return
	}
	const hint = "For every command it ran: CBB_ERROR_DETAILS=1, and run it again."
	// fails runs script with env and a stand-in for one command first on
	// its PATH, and checks how the failure shows.
	fails := func(script, env string, status int, want, wantNot []string) error {
		cmd := "cd /tmp && " + env + " PATH=/tmp/fail:$PATH sh " + script + " 2>&1"
		out, err := runOut(ctx, d, cmd, 3*time.Minute)
		if err == nil {
			return fmt.Errorf("%s with a failing step succeeded: %q", script, lastLines(out, 5))
		}
		if exitCode(err) != status {
			return fmt.Errorf("%s with a failing step ended with %v, not exit status %d: %q", script, err, status, lastLines(out, 5))
		}
		for _, w := range want {
			if !strings.Contains(out, w) {
				return fmt.Errorf("%s's failure does not show %q: %q", script, w, lastLines(out, 8))
			}
		}
		for _, w := range wantNot {
			if strings.Contains(out, w) {
				return fmt.Errorf("%s's failure shows %q: %q", script, w, lastLines(out, 8))
			}
		}
		return nil
	}
	install := "cbb/packaging/linux/install.sh --no-firewall --auto-update off cbb/cbb"
	r.Do(p+"install-status", func() error {
		return fails(install, "", 7, []string{"install.sh: failed (exit status 7). " + hint}, []string{"+ install "})
	})
	r.Do(p+"install-details", func() error {
		return fails(install, "CBB_ERROR_DETAILS=1", 7, []string{"+ install ", "+ failed 7"}, []string{hint})
	})
	uninstall := "/usr/local/share/cbb/uninstall.sh"
	r.Do(p+"uninstall-status", func() error {
		return fails(uninstall, "", 5, []string{"uninstall.sh: failed (exit status 5). " + hint}, []string{"+ sh "})
	})
	r.Do(p+"uninstall-details", func() error {
		return fails(uninstall, "CBB_ERROR_DETAILS=1", 5, []string{"+ sh /usr/local/share/cbb/firewall.sh close", "+ failed 5"}, []string{hint})
	})
	r.Do(p+"then-works", func() error {
		// Without the stand-ins both run through.
		if _, err := installArchive(ctx, d, archive, "--no-firewall --auto-update off"); err != nil {
			return err
		}
		if _, err := Run(ctx, d, "cbb status", ""); err != nil {
			return err
		}
		out, err := RunFor(ctx, d, "sh "+uninstall+" 2>&1", "", 3*time.Minute)
		if err != nil {
			return fmt.Errorf("uninstall.sh without a failing step: %w: %q", err, lastLines(out, 5))
		}
		return nil
	})
}
