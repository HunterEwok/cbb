// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"
	"time"
)

// A small device of the fleet (a Raspberry Pi, a router) runs the same cbb
// as the computers, as its service alone: no helper beside it, its options
// in /tmp/cbb-run-opts, and no admin or hub role.

// AddSmall starts a small device in no group on the fleet's network; its
// sh stands in for the service manager as for a computer.
func (f *Fleet) AddSmall(ctx context.Context) (*Device, error) {
	return f.AddSmallWith(ctx, nil)
}

// smallLoop is what a small device's container runs: its service,
// started again when it ends.
const smallLoop = "mkdir -p /run/cbb /var/lib/cbb; while :; do cbb service $(cat /tmp/cbb-run-opts 2>/dev/null); sleep 1; done"

// smallStarted marks d a small device and waits for its service to answer.
func smallStarted(ctx context.Context, d *Device) error {
	d.Roles = []string{"small"}
	if err := eventually(ctx, 20*time.Second, func() error {
		_, err := groupOf(ctx, d)
		return err
	}); err != nil {
		return fmt.Errorf("%s did not start: %w", d.Name, err)
	}
	return nil
}

// joinSmall joins the small device d to hub's group with the code of cbb
// pair, as member/README.md tells, and shares its clipboard.
func joinSmall(ctx context.Context, hub, d *Device) error {
	ip, err := fleetIP(ctx, hub)
	if err != nil {
		return err
	}
	code, stop, err := openWindow(ctx, hub)
	if err != nil {
		return err
	}
	// Under systemd the join runs as the service's user, as member/README.md
	// tells, so that the service reads what it saves.
	join := "cbb pair -name small -code " + net.JoinHostPort(ip, "8764")
	if out, _ := Run(ctx, d, "id -u cbb 2>/dev/null; true", ""); strings.TrimSpace(out) != "" {
		join = "su -s /bin/sh cbb -c '" + join + "'"
	}
	out, err := RunFor(ctx, d, join, code+"\n", time.Minute)
	stop()
	if err != nil {
		return err
	}
	if !strings.Contains(out, "Joined the group") {
		return fmt.Errorf("cbb pair on the small device said %q", out)
	}
	want, err := groupOf(ctx, hub)
	if err != nil {
		return err
	}
	if err := eventually(ctx, 30*time.Second, func() error {
		got, err := groupOf(ctx, d)
		if err == nil && got != want {
			err = fmt.Errorf("the small device is in the group %q, not %q", got, want)
		}
		return err
	}); err != nil {
		return err
	}
	_, err = Run(ctx, d, "cbb sync on", "")
	return err
}

// smallDevice (U9, O6): a small device in a group of computers. cbb watch
// prints each text it takes on a line of its own, watch -0 ends each with
// a zero byte; cbb next speaks the ZX Next's frames both ways; a copy of
// a file gives its programs the text that goes with the copy, or leaves
// its last text, and the file stays in the service's content cache.
func smallDevice(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/U9-small/"
	g := fleetGroup(ctx, r, f, "fleet/U9-small", 1)
	if g == nil || len(g.members) != 1 {
		return
	}
	hub := g.hub
	var small *Device
	if r.Do(p+"join", func() error {
		var err error
		if small, err = f.AddSmall(ctx); err != nil {
			return err
		}
		if err := joinSmall(ctx, hub, small); err != nil {
			return err
		}
		return syncs(ctx, g, hub, small, "to the small device", timeout)
	}) != nil {
		return
	}

	r.Do(p+"watch", func() error {
		if _, err := Run(ctx, small, "rm -f /tmp/w /tmp/w0; setsid sh -c 'timeout 120 cbb watch >/tmp/w' >/dev/null 2>&1 </dev/null & setsid sh -c 'timeout 120 cbb watch -0 >/tmp/w0' >/dev/null 2>&1 </dev/null &", ""); err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), small, "pkill -f 'cbb watch' || true", "")
		if err := eventually(ctx, 10*time.Second, func() error {
			out, err := Run(ctx, small, "pgrep -fc '^cbb watch' || true", "")
			if err == nil && strings.TrimSpace(out) != "2" {
				err = fmt.Errorf("%s runs %s cbb watch, not 2", small.Name, strings.TrimSpace(out))
			}
			return err
		}); err != nil {
			return err
		}
		time.Sleep(time.Second) // both have asked the service by now
		for _, text := range []string{"one", "two\nlines"} {
			if err := Copy(ctx, hub, text); err != nil {
				return err
			}
			if err := arrives(ctx, small, text, timeout); err != nil {
				return err
			}
		}
		// The text that arrived while no watcher was there may come first:
		// the service hands such a write to the first watcher, as to a
		// desktop agent that starts after it.
		missed := "cbb-bench " + g.run + " to the small device"
		for file, want := range map[string]string{"/tmp/w": "one\ntwo\nlines\n", "/tmp/w0": "one\x00two\nlines\x00"} {
			if err := eventually(ctx, 10*time.Second, func() error {
				got, err := Run(ctx, small, "cat "+file, "")
				if rest, ok := strings.CutPrefix(got, missed); ok && len(rest) > 0 && (rest[0] == '\n' || rest[0] == 0) {
					got = rest[1:]
				}
				if err == nil && got != want {
					err = fmt.Errorf("%s printed %q, want %q", file[5:], got, want)
				}
				return err
			}); err != nil {
				return err
			}
		}
		return nil
	})

	r.Do(p+"next", func() error {
		// Texts in the Spectrum character set with their length and
		// CRC-32 (member/README.md, "ZX Spectrum Next").
		zx := "ZX \x605\rnext"
		out, err := Run(ctx, small, fmt.Sprintf("cbb next copy %d %08x", len(zx), crc32.ChecksumIEEE([]byte(zx))), zx)
		if err != nil {
			return err
		}
		if out != "CBBGO\rCBBOK\r" {
			return fmt.Errorf("cbb next copy answered %q", out)
		}
		if err := arrives(ctx, hub, "ZX £5\nnext", timeout); err != nil {
			return err
		}
		// A frame whose CRC does not match is refused, and nothing is sent.
		bad := "a damaged frame"
		if out, err := Run(ctx, small, "cbb next copy "+strconv.Itoa(len(bad))+" 00000000", bad); err == nil && strings.Contains(out, "CBBOK") {
			return fmt.Errorf("cbb next copy took a frame with a wrong CRC: %q", out)
		}
		if got, err := Paste(ctx, hub); err != nil || got != "ZX £5\nnext" {
			return fmt.Errorf("after a damaged frame %s holds %q (%v)", hub.Name, got, err)
		}
		if err := Copy(ctx, hub, "to the `Next` £\nαβγδ"); err != nil {
			return err
		}
		if err := arrives(ctx, small, "to the `Next` £\nαβγδ", timeout); err != nil {
			return err
		}
		want := "to the ?Next? \x60\r????"
		out, err = Run(ctx, small, "cbb next paste", "")
		if err != nil {
			return err
		}
		if wantOut := fmt.Sprintf("CBB1 %d %08x\r%s\rCBBOK\r", len(want), crc32.ChecksumIEEE([]byte(want)), want); out != wantOut {
			return fmt.Errorf("cbb next paste gave %q, want %q", out, wantOut)
		}
		return nil
	})

	r.Do("fleet/O6-text-only", func() error {
		if _, err := Run(ctx, small, "touch /tmp/o6.start", ""); err != nil {
			return err
		}
		if _, err := Run(ctx, hub, "head -c 300000 /dev/urandom >/tmp/o6.bin", ""); err != nil {
			return err
		}
		beside := "cbb-bench " + g.run + " the words beside the file"
		if _, err := RunFor(ctx, hub, "cbb copy -text '"+beside+"' /tmp/o6.bin", "", time.Minute); err != nil {
			return err
		}
		if err := arrives(ctx, small, beside, timeout); err != nil {
			return fmt.Errorf("the text that goes with a copy: %w", err)
		}
		if _, err := RunFor(ctx, hub, "cbb copy /tmp/o6.bin", "", time.Minute); err != nil {
			return err
		}
		// The small device takes the event but keeps its last text; the
		// file is only in its service's content cache (O9), which serves
		// it on to the group, and nowhere else.
		time.Sleep(5 * time.Second)
		if got, err := Paste(ctx, small); err != nil || got != beside {
			return fmt.Errorf("after a copy of a file with no text %s holds %q (%v), not its last text", small.Name, got, err)
		}
		out, err := Run(ctx, small, "find / -xdev -type f -size +100k -newer /tmp/o6.start ! -path '/proc/*' ! -path '/usr/*' ! -path '/var/lib/cbb/content/*' 2>/dev/null", "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "" {
			return fmt.Errorf("%s keeps file data outside its content cache: %s", small.Name, out)
		}
		return nil
	})
	smallOptions(ctx, r, f, g, hub, small, timeout)
	smallRelease(ctx, r, small)
}

// smallRelease (S22): the small device checks a signed release's envelope
// itself: cbb update -check takes a release that the test roots sign and
// refuses one whose channel or keys no known key signed.
func smallRelease(ctx context.Context, r *Report, small *Device) {
	const p = "fleet/S22-small-release/"
	var fd *feed
	var built string
	defer func() { fd.remove() }()
	if r.Do(p+"feed", func() error {
		var err error
		if fd, err = newFeed(ctx); err != nil {
			return err
		}
		built, err = fd.build(ctx, "0.9.0", goarchOf(), goarchOf())
		return err
	}) != nil {
		return
	}
	check := func(name string, o releaseOpts) (string, error) {
		dir, err := fd.publish(ctx, built, name, "0.9.0", o)
		if err != nil {
			return "", err
		}
		at, err := fd.toDevice(ctx, small, dir)
		if err != nil {
			return "", err
		}
		out, err := runOut(ctx, small, feedEnv(at)+"cbb update -check", time.Minute)
		fmt.Fprintf(r.out, "S22 %s: %s\n", name, strings.Join(strings.Fields(out), " "))
		return out, err
	}
	r.Do(p+"signed", func() error {
		out, err := check("signed", releaseOpts{})
		if err != nil {
			return err
		}
		if !strings.Contains(out, "0.9.0") {
			return fmt.Errorf("cbb update -check on the small device printed %q", out)
		}
		return nil
	})
	for _, c := range []struct {
		name string
		o    releaseOpts
		want string
	}{
		{"unknown-release-key", releaseOpts{relBy: "other"}, "stable.json"},
		{"keys-by-no-root", releaseOpts{keysBy: "other"}, "keys.json"},
	} {
		r.Do(p+c.name, func() error {
			out, err := check(c.name, c.o)
			if err == nil {
				return fmt.Errorf("the small device took a release that is %s: %q", c.name, out)
			}
			if !strings.Contains(out, c.want) {
				return fmt.Errorf("the small device refused a release that is %s with %q, which does not name %s", c.name, out, c.want)
			}
			return nil
		})
	}
}
