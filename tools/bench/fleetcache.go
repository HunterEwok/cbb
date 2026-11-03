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

// fetchLimits (O15): a member that asks a part's holder for more than the
// protocol allows is refused: a get of 1 MiB comes back in chunks padded
// to 16 KiB, a get of a byte more is dropped while the connection keeps
// serving, and 80 gets at once close it. (The 4 MiB a fetch keeps ahead
// is the fetcher's own bound, which internal/node's tests check.)
func fetchLimits(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/O15-fetch-limits/"
	g := fleetGroup(ctx, r, f, "fleet/O15-fetch", 2)
	if g == nil || len(g.members) != 2 {
		return
	}
	holder, asker := g.members[0], g.members[1]
	var sum string
	if r.Do(p+"part", func() error {
		if _, err := Run(ctx, holder, "head -c 3000000 /dev/urandom >/tmp/o15.bin", ""); err != nil {
			return err
		}
		if _, err := RunFor(ctx, holder, "cbb copy /tmp/o15.bin", "", time.Minute); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			out, err := Run(ctx, holder, "find /var/lib/cbb/content -type f -size +1100k ! -name '*.part' -printf '%f\\n' | head -1", "")
			sum = strings.TrimSpace(out)
			if err == nil && len(sum) != 64 {
				err = fmt.Errorf("%s holds no part over 1 MiB", holder.Name)
			}
			return err
		})
	}) != nil {
		return
	}
	var h *Device
	if r.Do(p+"forge", func() error {
		var err error
		h, err = forgeHost(ctx, f, asker)
		return err
	}) != nil {
		return
	}
	id, err := deviceOf(ctx, holder)
	ip, err2 := fleetIP(ctx, holder)
	if r.Do(p+"target", func() error { return errors.Join(err, err2) }) != nil {
		return
	}
	var out string
	if r.Do(p+"run", func() error {
		var err error
		out, err = RunFor(ctx, h, fmt.Sprintf("cbbbench-forge -state /tmp/%s -to %s -addr %s:8764 fetch:%s", asker.Name, id, ip, sum), "", 3*time.Minute)
		fmt.Fprintf(r.out, "%s\n", strings.TrimSpace(out))
		return err
	}) != nil {
		return
	}
	for _, c := range []struct{ name, want string }{
		{"window", "window: 4 chunks, 1048576 bytes, padded"},
		{"over", "over: no answer"},
		{"after-over", "after-over: answered"},
		{"flood", "flood: closed after"},
	} {
		r.Do(p+c.name, func() error {
			if !strings.Contains(out, c.want) {
				return fmt.Errorf("want %q", c.want)
			}
			return nil
		})
	}
}
