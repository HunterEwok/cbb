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

// killedJoiner (G16): the joiner's service killed at moments through a
// join, from before the welcome to after it stored its certificate, leaves
// the joiner either in the group, with its identity and syncing, or in no
// group with no identity: never half joined. After each attempt it joins
// again.
func killedJoiner(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G16-killed-joiner/"
	var hub, joiner *Device
	var addr string
	if r.Do(p+"start", func() error {
		var err error
		if hub, err = f.Add(ctx); err != nil {
			return err
		}
		if _, err := Run(ctx, hub, "cbb new", ""); err != nil {
			return err
		}
		if err := setMode(ctx, hub, "shared"); err != nil {
			return err
		}
		ip, err := fleetIP(ctx, hub)
		addr = net.JoinHostPort(ip, "8764")
		if err != nil {
			return err
		}
		joiner, err = f.Add(ctx)
		return err
	}) != nil {
		return
	}
	// reset takes the joiner out of the group, if it is in, and back to no
	// state, as before the first attempt.
	reset := func() error {
		if id, err := deviceOf(ctx, joiner); err == nil && id != "" {
			Run(ctx, hub, "cbb remove "+id, "yes\n")
		}
		if _, err := Run(ctx, joiner, "rm -rf /var/lib/clipboardbridge/*", ""); err != nil {
			return err
		}
		if err := signalService(ctx, joiner, "KILL"); err != nil {
			return err
		}
		// Back when its service answers in no group.
		return eventually(ctx, 20*time.Second, func() error {
			tag, err := groupOf(ctx, joiner)
			if err == nil && tag != "" {
				err = fmt.Errorf("%s is still in group %s", joiner.Name, tag)
			}
			return err
		})
	}
	// state is the joiner's group and whether its identity file is there,
	// once its service answers again.
	state := func() (tag string, stored bool, err error) {
		err = eventually(ctx, 20*time.Second, func() error {
			var err error
			tag, err = groupOf(ctx, joiner)
			return err
		})
		if err != nil {
			return "", false, err
		}
		out, err := Run(ctx, joiner, "test -e /var/lib/clipboardbridge/identity.json && echo yes || echo no", "")
		return tag, strings.TrimSpace(out) == "yes", err
	}
	want, _ := groupOf(ctx, hub)
	// How long a join takes here, so that the kills spread over it.
	var took time.Duration
	if r.Do(p+"timed-join", func() error {
		code, stop, err := openWindow(ctx, hub)
		if err != nil {
			return err
		}
		defer stop()
		start := time.Now()
		if _, err := RunFor(ctx, joiner, "cbb pair -code "+addr, code+"\n", time.Minute); err != nil {
			return err
		}
		took = time.Since(start)
		return reset()
	}) != nil {
		return
	}
	var joined, refused int
	for i := range 12 {
		ms := int(took.Milliseconds()) * i / 10
		r.Do(fmt.Sprintf("fleet/G16-killed-at-%d0pc", i), func() error {
			code, stop, err := openWindow(ctx, hub)
			if err != nil {
				return err
			}
			defer stop()
			done := make(chan string, 1)
			go func() {
				out, err := RunFor(ctx, joiner, "cbb pair -code "+addr, code+"\n", time.Minute)
				if err != nil {
					out += err.Error()
				}
				done <- out
			}()
			time.Sleep(time.Duration(ms) * time.Millisecond)
			if err := signalService(ctx, joiner, "KILL"); err != nil {
				return err
			}
			select {
			case <-done:
			case <-time.After(time.Minute):
				return fmt.Errorf("cbb pair did not end after its service was killed")
			}
			stop()
			tag, stored, err := state()
			if err != nil {
				return err
			}
			switch {
			case tag == "" && stored:
				return fmt.Errorf("%s keeps an identity file but is in no group", joiner.Name)
			case tag != "" && !stored:
				return fmt.Errorf("%s says it is in group %s without an identity file", joiner.Name, tag)
			case tag != "" && tag != want:
				return fmt.Errorf("%s is in group %s, not %s", joiner.Name, tag, want)
			case tag != "":
				joined++
				if err := setMode(ctx, joiner, "shared"); err != nil {
					return err
				}
				text := fmt.Sprintf("cbb-bench G16 %dms", ms)
				if err := Copy(ctx, hub, text); err != nil {
					return err
				}
				if err := arrives(ctx, joiner, text, timeout); err != nil {
					return fmt.Errorf("joined but does not sync: %v", err)
				}
			default:
				refused++
			}
			return reset()
		})
	}
	r.Do("fleet/G16-both-outcomes", func() error {
		// The moments span the join: some kills come before it is stored,
		// some after.
		if joined == 0 || refused == 0 {
			return fmt.Errorf("of the attempts %d ended joined and %d not; the moments miss a side of the join", joined, refused)
		}
		return nil
	})
	r.Do("fleet/G16-joins-after", func() error {
		if _, _, err := state(); err != nil {
			return err
		}
		if _, err := pairOne(ctx, hub, joiner); err != nil {
			return err
		}
		if tag, stored, err := state(); err != nil || tag != want || !stored {
			return fmt.Errorf("after the attempts %s did not join (group %q, identity %v, %v); %d of them ended joined, %d not", joiner.Name, tag, stored, err, joined, refused)
		}
		return nil
	})
}
