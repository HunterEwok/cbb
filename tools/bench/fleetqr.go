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

// listens reports whether something on d's network takes a TCP connection
// to addr.
func listens(ctx context.Context, from *Device, addr string) bool {
	host, port, _ := strings.Cut(addr, ":")
	_, err := Run(ctx, from, fmt.Sprintf("timeout 3 bash -c '</dev/tcp/%s/%s'", host, port), "")
	return err == nil
}

// pairRelay (G8): the forge, with an insider's member certificate, sits
// between a joiner and the root's pairing window and passes every frame
// between the two TLS sessions; CPace's channel binding fails the join,
// which costs the window one guess, and the joiner then joins directly
// with the same code.
func pairRelay(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G8-relay/"
	g := fleetGroup(ctx, r, f, "fleet/G8-relay", 2)
	if g == nil || len(g.members) != 2 {
		return
	}
	root, insider := g.hub, g.members[1]
	var h, joiner *Device
	var rootAddr, relayAddr string
	if r.Do(p+"setup", func() error {
		var err error
		if h, err = forgeHost(ctx, f, insider); err != nil {
			return err
		}
		if joiner, err = f.Add(ctx); err != nil {
			return err
		}
		ip, err := fleetIP(ctx, root)
		if err != nil {
			return err
		}
		rootAddr = ip + ":8764"
		hip, err := fleetIP(ctx, h)
		relayAddr = hip + ":8764"
		return err
	}) != nil {
		return
	}
	code, stop, err := openWindow(ctx, root)
	if r.Do(p+"window", func() error { return err }) != nil {
		return
	}
	defer stop()
	r.Do(p+"refused", func() error {
		ready := make(chan struct{}, 1)
		done := make(chan error, 1)
		var lines []string
		go func() {
			done <- Stream(ctx, h, fmt.Sprintf("cbbbench-forge -state /tmp/%s -addr :8764 relay:%s", insider.Name, rootAddr), func(line string) {
				lines = append(lines, line)
				if strings.Contains(line, "relay: listening") {
					ready <- struct{}{}
				}
			})
		}()
		select {
		case <-ready:
		case err := <-done:
			return fmt.Errorf("the relay ended: %v %v", err, lines)
		case <-time.After(30 * time.Second):
			return errors.New("the relay did not listen")
		}
		out, err := RunFor(ctx, joiner, "cbb pair -code "+relayAddr, code+"\n", time.Minute)
		if err == nil {
			return fmt.Errorf("%s joined through the relay: %s", joiner.Name, out)
		}
		var rerr error
		select {
		case rerr = <-done:
		case <-time.After(time.Minute):
			return errors.New("the relay did not end")
		}
		fmt.Fprintf(r.out, "%s\n", strings.Join(lines, "\n"))
		if rerr != nil {
			return fmt.Errorf("the relay: %v", rerr)
		}
		if tag, err := groupOf(ctx, joiner); err != nil || tag != "" {
			return fmt.Errorf("%s is in the group %q after the relay (%v)", joiner.Name, tag, err)
		}
		return nil
	})
	r.Do(p+"one-guess", func() error {
		// The window is still open with the same code.
		if _, err := RunFor(ctx, joiner, "cbb pair -code "+rootAddr, code+"\n", time.Minute); err != nil {
			return fmt.Errorf("joining directly after the relay: %w", err)
		}
		want, err := groupOf(ctx, root)
		if err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			got, err := groupOf(ctx, joiner)
			if err == nil && got != want {
				err = fmt.Errorf("%s is in %q, not %q", joiner.Name, got, want)
			}
			return err
		})
	})
}
