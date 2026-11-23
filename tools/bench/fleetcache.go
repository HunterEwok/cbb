// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// cacheKeep is how long the service keeps the parts of a replaced copy
// (design.md, "Images and files", "Storage").
const cacheKeep = 10 * time.Minute

// cacheFiles lists the parts in d's content cache with their modes.
func cacheFiles(ctx context.Context, d *Device) ([]string, error) {
	out, err := Run(ctx, d, "find /var/lib/cbb/content -type f ! -name '*.part' -printf '%m %f\\n' 2>/dev/null; true", "")
	if err != nil {
		return nil, err
	}
	return strings.Fields(strings.ReplaceAll(out, "\n", " ")), nil
}

// cache (O9): a copied file's part is in the sender's cache, readable only
// by the service; it stays while the copy that replaced it is young,
// goes within cacheKeep and a little after the replacement with no further
// copy, and a restart empties the cache.
func cache(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/O9-cache/"
	g := fleetGroup(ctx, r, f, "fleet/O9-cache", 2)
	if g == nil || len(g.members) != 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	parts := func(d *Device) (int, error) {
		fs, err := cacheFiles(ctx, d)
		return len(fs) / 2, err
	}
	if r.Do(p+"held", func() error {
		if _, err := Run(ctx, a, "mkdir -p /tmp/o9 && head -c 300000 /dev/urandom >/tmp/o9/one", ""); err != nil {
			return err
		}
		if _, err := RunFor(ctx, a, "cbb copy /tmp/o9/one", "", time.Minute); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			fs, err := cacheFiles(ctx, a)
			if err != nil {
				return err
			}
			if len(fs) == 0 {
				return fmt.Errorf("%s's cache holds no part of the file it copied", a.Name)
			}
			for i := 0; i < len(fs); i += 2 {
				if fs[i] != "600" {
					return fmt.Errorf("a part in %s's cache has the mode %s, not 600", a.Name, fs[i])
				}
			}
			return nil
		})
	}) != nil {
		return
	}
	r.Do(p+"replaced", func() error {
		if err := syncs(ctx, g, a, b, "replaces the file", timeout); err != nil {
			return err
		}
		n, err := parts(a)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%s dropped the replaced file's part at once, not after %s", a.Name, cacheKeep)
		}
		// No copy follows: the parts must still go on time.
		return eventually(ctx, cacheKeep+90*time.Second, func() error {
			n, err := parts(a)
			if err == nil && n != 0 {
				err = fmt.Errorf("%s still holds %d parts of a copy replaced over %s ago", a.Name, n, cacheKeep)
			}
			return err
		})
	})
	r.Do(p+"restart", func() error {
		if _, err := Run(ctx, a, "head -c 300000 /dev/urandom >/tmp/o9/two", ""); err != nil {
			return err
		}
		if _, err := RunFor(ctx, a, "cbb copy /tmp/o9/two", "", time.Minute); err != nil {
			return err
		}
		if err := eventually(ctx, 20*time.Second, func() error {
			n, err := parts(a)
			if err == nil && n == 0 {
				err = fmt.Errorf("%s's cache holds no part of the file it copied", a.Name)
			}
			return err
		}); err != nil {
			return err
		}
		if _, err := Run(ctx, a, fleetKill, ""); err != nil {
			return err
		}
		return eventually(ctx, 30*time.Second, func() error {
			if _, err := Run(ctx, a, "cbb status", ""); err != nil {
				return err
			}
			n, err := parts(a)
			if err == nil && n != 0 {
				err = fmt.Errorf("%s holds %d parts after a restart", a.Name, n)
			}
			return err
		})
	})
}
