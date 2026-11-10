// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// smallOptions (H5): the small device's options (cbb pair -name, which
// names the device in the group, every join runs): cbb service -port moves the
// member port, -no-listen opens none,
// -no-mdns publishes nothing on UDP 5353 and -peer dials a computer at its
// address, so that the small device syncs with mDNS off; cbb pair -addr puts
// the address given in the phone's QR code.
func smallOptions(ctx context.Context, r *Report, f *Fleet, g *benchGroup, hub, small *Device, timeout time.Duration) {
	const p = "fleet/H5-small-options/"
	// with restarts the small device's service with opts and waits until
	// it answers.
	with := func(opts string) error { return smallRestart(ctx, small, opts) }
	defer with("")
	listening := func(proto string) (string, error) {
		return Run(ctx, small, "ss -"+proto+"lnpH | grep cbb || true", "")
	}
	r.Do(p+"port", func() error {
		if err := with("-name small-hello -port 8800"); err != nil {
			return err
		}
		// The service answers cbb status before it binds the member port.
		if err := eventually(ctx, 20*time.Second, func() error {
			if out, err := listening("t"); err != nil || !strings.Contains(out, ":8800 ") || strings.Contains(out, ":8764 ") {
				return fmt.Errorf("with -port 8800 the small device listens on %q (%v)", out, err)
			}
			return nil
		}); err != nil {
			return err
		}
		return syncs(ctx, g, hub, small, "with -port 8800", timeout)
	})
	r.Do(p+"no-listen", func() error {
		if err := with("-no-listen"); err != nil {
			return err
		}
		if out, err := listening("t"); err != nil || strings.TrimSpace(out) != "" {
			return fmt.Errorf("with -no-listen the small device listens on %q (%v)", out, err)
		}
		// It still dials the computers.
		return syncs(ctx, g, hub, small, "with -no-listen", timeout)
	})
	r.Do(p+"no-mdns-peer", func() error {
		ip, err := fleetIP(ctx, hub)
		if err != nil {
			return err
		}
		if err := with("-no-mdns -peer " + net.JoinHostPort(ip, "8764")); err != nil {
			return err
		}
		if out, err := listening("u"); err != nil || strings.Contains(out, ":5353 ") {
			return fmt.Errorf("with -no-mdns the small device holds UDP 5353: %q (%v)", out, err)
		}
		return syncs(ctx, g, hub, small, "with -no-mdns and -peer", timeout)
	})
	r.Do(p+"join-addr", func() error {
		fresh, err := f.AddSmall(ctx)
		if err != nil {
			return err
		}
		out, _ := RunFor(ctx, fresh, "timeout 5 cbb pair -name fresh -addr 198.51.100.9:8800; true", "", 30*time.Second)
		if !strings.Contains(out, "198.51.100.9") {
			return fmt.Errorf("cbb pair -addr did not put the address in what it shows: %q", lastLines(out, 3))
		}
		return nil
	})
}

// smallRestart restarts the small device's service in a fleet container with
// the options opts of cbb service and waits until it answers.
func smallRestart(ctx context.Context, small *Device, opts string) error {
	if _, err := Run(ctx, small, "echo '"+opts+"' >/tmp/cbb-run-opts && pkill -f '^cbb service' ; true", ""); err != nil {
		return err
	}
	return eventually(ctx, 20*time.Second, func() error {
		out, err := Run(ctx, small, "pgrep -af '^cbb service'; cbb status", "")
		if err == nil && !strings.Contains(out, strings.TrimSpace("cbb service "+opts)) {
			err = fmt.Errorf("the small device runs %q, not with %s", firstLine(out), opts)
		}
		return err
	})
}
