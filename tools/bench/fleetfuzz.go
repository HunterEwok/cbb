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

// fuzzFor is how long the fuzzing case (S20) sends each kind of frame
// (-fuzz-for); the catalogue's hour is for a release's full run.
var fuzzFor = time.Minute

// serviceHealth is the service's process on d: its PID, its resident
// memory in KiB and its open descriptors.
func serviceHealth(ctx context.Context, d *Device) (pid string, rssKiB, fds int, err error) {
	out, err := Run(ctx, d, `for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = cbb ] && tr '\0' ' ' <$p/cmdline | grep -q 'cbb service' && { echo ${p#/proc/} $(awk '/^VmRSS/{print $2}' $p/status) $(ls $p/fd | wc -l); break; }; done`, "")
	if err != nil {
		return "", 0, 0, err
	}
	f := strings.Fields(out)
	if len(f) != 3 {
		return "", 0, 0, fmt.Errorf("no service running on %s: %q", d.Name, out)
	}
	rssKiB, _ = strconv.Atoi(f[1])
	fds, _ = strconv.Atoi(f[2])
	return f[0], rssKiB, fds, nil
}

// fuzzing (S20): a stranger sends random bytes and TLS records to the
// member port and to an open pairing window, and a local user fuzzes the
// control socket; the service neither crashes nor restarts, gives back its
// descriptors and memory, and still syncs.
func fuzzing(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/S20-fuzz/"
	g := fleetGroup(ctx, r, f, "fleet/S20-fuzz", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	target, other, insider := g.hub, g.members[1], g.members[2]
	var h *Device
	var pid0 string
	var rss0, fds0 int
	if r.Do(p+"setup", func() error {
		var err error
		if pid0, rss0, fds0, err = serviceHealth(ctx, target); err != nil {
			return err
		}
		// The forge takes the insider's state; the insider stops.
		h, err = forgeHost(ctx, f, insider)
		if err != nil {
			return err
		}
		_, err = forgeOn(ctx, target)
		return err
	}) != nil {
		return
	}
	ip, err := fleetIP(ctx, target)
	if err != nil {
		r.Do(p+"target", func() error { return err })
		return
	}
	secs := int(fuzzFor / time.Second)
	run := func(on *Device, cmd string) error {
		out, err := RunFor(ctx, on, cmd, "", fuzzFor+time.Minute)
		fmt.Fprintf(r.out, "%s\n", strings.TrimSpace(out))
		return err
	}
	r.Do(p+"raw-bytes", func() error {
		return run(h, fmt.Sprintf("cbbbench-forge -addr %s:8764 fuzz-raw:%d:%d", ip, secs, time.Now().UnixNano()))
	})
	r.Do(p+"pairing-window", func() error {
		code, stop, err := openWindow(ctx, target)
		if err != nil {
			return err
		}
		defer stop()
		_ = code
		return run(h, fmt.Sprintf("cbbbench-forge -addr %s:8764 fuzz-raw:%d:%d", ip, secs, time.Now().UnixNano()))
	})
	r.Do(p+"control-socket", func() error {
		return run(target, fmt.Sprintf("cbbbench-forge fuzz-control:%d:%d", secs, time.Now().UnixNano()))
	})
	r.Do(p+"healthy", func() error {
		// Connections the fuzzing left close within their timeouts.
		return eventually(ctx, time.Minute, func() error {
			pid, rss, fds, err := serviceHealth(ctx, target)
			if err != nil {
				return err
			}
			if pid != pid0 {
				return fmt.Errorf("the service on %s restarted (PID %s, then %s): it crashed", target.Name, pid0, pid)
			}
			if fds > fds0+16 {
				return fmt.Errorf("the service on %s holds %d descriptors, %d before the fuzzing", target.Name, fds, fds0)
			}
			if rss > 2*rss0+64<<10 {
				return fmt.Errorf("the service on %s holds %d KiB, %d before the fuzzing", target.Name, rss, rss0)
			}
			fmt.Fprintf(r.out, "%s after the fuzzing: %d KiB (%d before), %d descriptors (%d before)\n", target.Name, rss, rss0, fds, fds0)
			return nil
		})
	})
	r.Do(p+"still-syncs", func() error {
		return syncs(ctx, g, other, target, "after the fuzzing", timeout)
	})
	r.Do(p+"insider-back", func() error {
		if err := f.start(ctx, insider); err != nil {
			return err
		}
		return eventually(ctx, time.Minute, func() error {
			return syncs(ctx, g, target, insider, "to the insider again", timeout)
		})
	})
}
