// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// duplicates (Y15): an event that reaches a member by several paths, from
// its sender and from each member that passes it on, is written once. The
// forge watches the members' clipboards as a desktop connector does and
// counts the writes.
func duplicates(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/Y15-duplicates/"
	g := fleetGroup(ctx, r, f, "fleet/Y15-duplicates", 4)
	if g == nil || len(g.members) < 4 {
		return
	}
	a, b, c, d := g.members[0], g.members[1], g.members[2], g.members[3]
	watchers := []*Device{b, c, d}
	names := map[*Device]string{}
	if r.Do(p+"connected", func() error {
		for _, m := range watchers {
			if err := syncs(ctx, g, a, m, "before", timeout); err != nil {
				return err
			}
			name, err := forgeOn(ctx, m)
			if err != nil {
				return err
			}
			names[m] = name
		}
		return nil
	}) != nil {
		return
	}
	// writes watches each of ws for secs seconds while act runs, and returns
	// how many times each wrote text.
	writes := func(ws []*Device, secs int, text string, act func() error) (map[*Device]int, error) {
		outs := make([]string, len(ws))
		errs := make(chan error, len(ws))
		for i, m := range ws {
			go func() {
				var err error
				outs[i], err = RunFor(ctx, m, fmt.Sprintf("%s watch:%d", names[m], secs), "", time.Duration(secs+20)*time.Second)
				errs <- err
			}()
		}
		time.Sleep(2 * time.Second)
		err := act()
		for range ws {
			if werr := <-errs; err == nil {
				err = werr
			}
		}
		n := map[*Device]int{}
		for i, m := range ws {
			n[m] = strings.Count(outs[i], "write "+text+"\n")
		}
		return n, err
	}
	r.Do("fleet/Y15-three-paths-written-once", func() error {
		text := "cbb-bench-" + g.run + "-paths"
		n, err := writes(watchers, 12, text, func() error { return Copy(ctx, a, text) })
		if err != nil {
			return err
		}
		for _, m := range watchers {
			if n[m] != 1 {
				return fmt.Errorf("%s wrote the text %d times, not once", m.Name, n[m])
			}
		}
		return nil
	})
}
