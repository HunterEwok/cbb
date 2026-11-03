// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// footprint lists what an install can leave on d: the files under /etc,
// /usr/local and /var/lib (systemd's own state left out), the firewall's
// rules and the units.
func footprint(ctx context.Context, d *Device) (string, error) {
	return Run(ctx, d, `find /etc /usr/local /var/lib -xdev -path /var/lib/systemd -prune -o -print 2>/dev/null | sort
echo '--- rules'; nft -s list ruleset 2>/dev/null; iptables-save 2>/dev/null | grep -v '^#' | sed 's/ \[[0-9:]*\]$//'
echo '--- units'; systemctl list-unit-files --no-legend 'cbb*' 2>/dev/null; true`, "")
}

// footprintDiff says which lines a and b do not share, at most a few.
func footprintDiff(a, b string) string {
	in := map[string]int{}
	for _, l := range strings.Split(a, "\n") {
		in[l]++
	}
	var only []string
	for _, l := range strings.Split(b, "\n") {
		if in[l] > 0 {
			in[l]--
			continue
		}
		only = append(only, "+"+l)
	}
	for l, n := range in {
		if n > 0 {
			only = append(only, "-"+l)
		}
	}
	if len(only) > 12 {
		only = append(only[:12], fmt.Sprintf("and %d more", len(only)-12))
	}
	return strings.Join(only, "\n")
}

// stateFiles is the hash of the device's identity on d (its keys and
// certificates), which an uninstall without --purge, an upgrade and a
// downgrade keep.
func stateFiles(ctx context.Context, d *Device) (string, error) {
	return Run(ctx, d, "sha256sum /var/lib/cbb/identity.json", "")
}

// installers (I2, I4, I6, I7): install.sh's options on a computer with
// systemd and a bare nftables firewall: --no-firewall adds no rule,
// --express prints the rules for the port (install.sh leaves bare nftables
// to the user), --port N moves the member port and a run without it keeps
// it, --port 8764 moves it back; uninstall
// leaves only the state, and --purge nothing, of what install.sh added; in
// a group of two, each member upgraded in turn from the previous release
// keeps its state and copies with the other after each step; and the
// previous release installed over the new state starts or refuses clearly,
// with no key lost.
func installers(ctx context.Context, r *Report, f *Fleet, builds map[string]string) {
	const p = "fleet/I2-install/"
	var d *Device
	var clean string
	if r.Do(p+"setup", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, f.net); err != nil {
			return err
		}
		// A bare nftables firewall that drops input, which install.sh
		// finds and adds its rules to.
		if _, err := Run(ctx, d, `nft add table inet filter && nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }' && nft add rule inet filter input iif lo accept && nft add rule inet filter input ct state established,related accept`, ""); err != nil {
			return err
		}
		clean, err = footprint(ctx, d)
		return err
	}) != nil {
		return
	}
	rules := func() (string, error) {
		return Run(ctx, d, "nft -s list ruleset 2>/dev/null; iptables-save 2>/dev/null | grep -v '^#' | sed 's/ \\[[0-9:]*\\]$//'", "")
	}
	listens := func(port string) error {
		return eventually(ctx, 20*time.Second, func() error {
			out, err := Run(ctx, d, "ss -ltnH", "")
			if err != nil {
				return err
			}
			if !strings.Contains(out, ":"+port+" ") {
				return fmt.Errorf("nothing listens on %s:\n%s", port, out)
			}
			return nil
		})
	}
	r.Do(p+"no-firewall", func() error {
		before, err := rules()
		if err != nil {
			return err
		}
		if _, err := installArchive(ctx, d, builds["0.6.0"], "--no-firewall --auto-update off"); err != nil {
			return err
		}
		after, err := rules()
		if err != nil {
			return err
		}
		if before != after {
			return fmt.Errorf("--no-firewall changed the rules:\n%s", footprintDiff(before, after))
		}
		// The member port opens once the device is in a group.
		if _, err := Run(ctx, d, "cbb new", ""); err != nil {
			return err
		}
		return listens("8764")
	})
	// A bare nftables setup is not install.sh's to change: --express
	// prints the rules for it to add by hand, with the port, and adds none.
	expressed := func(flags, port string) error {
		before, err := rules()
		if err != nil {
			return err
		}
		out, err := installArchive(ctx, d, builds["0.6.0"], flags)
		if err != nil {
			return err
		}
		after, err := rules()
		if err != nil {
			return err
		}
		if before != after {
			return fmt.Errorf("install.sh %s changed bare nftables rules:\n%s", flags, footprintDiff(before, after))
		}
		for _, want := range []string{"Firewall: nftables (active)", "nft insert rule inet filter input ip saddr", "tcp dport " + port + " accept", "udp dport 5353 accept"} {
			if !strings.Contains(out, want) {
				return fmt.Errorf("install.sh %s did not print %q: %q", flags, want, out)
			}
		}
		return nil
	}
	r.Do(p+"express", func() error { return expressed("--express --auto-update off", "8764") })
	r.Do(p+"port", func() error {
		if err := expressed("--express --port 8800 --auto-update off", "8800"); err != nil {
			return err
		}
		if err := listens("8800"); err != nil {
			return err
		}
		if out, err := Run(ctx, d, "cat /etc/cbb/cbb.env", ""); err != nil || !strings.Contains(out, "CBB_PORT=8800") {
			return fmt.Errorf("the port is not kept: %q %v", out, err)
		}
		// A run without --port keeps it; --port 8764 moves it back.
		if _, err := installArchive(ctx, d, builds["0.6.0"], "--express --auto-update off"); err != nil {
			return err
		}
		if err := listens("8800"); err != nil {
			return fmt.Errorf("a run without --port did not keep 8800: %w", err)
		}
		if err := expressed("--express --port 8764 --auto-update off", "8764"); err != nil {
			return err
		}
		return listens("8764")
	})
	installedCases(ctx, r, d, builds["0.6.0"])

	const q = "fleet/I4-uninstall/"
	r.Do(q+"keeps-state", func() error {
		keys, err := stateFiles(ctx, d)
		if err != nil {
			return err
		}
		if strings.TrimSpace(keys) == "" {
			return fmt.Errorf("found no key files in the state to compare")
		}
		if _, err := RunFor(ctx, d, "sh /usr/local/share/cbb/uninstall.sh", "", 2*time.Minute); err != nil {
			return err
		}
		left, err := footprint(ctx, d)
		if err != nil {
			return err
		}
		var other []string
		for _, l := range strings.Split(footprintDiff(clean, left), "\n") {
			if l != "" && !strings.HasPrefix(l, "+/var/lib/cbb") {
				other = append(other, l)
			}
		}
		if len(other) > 0 {
			return fmt.Errorf("uninstall left more than the state:\n%s", strings.Join(other, "\n"))
		}
		if after, err := stateFiles(ctx, d); err != nil || after != keys {
			return fmt.Errorf("uninstall without --purge changed the keys: %v", err)
		}
		return nil
	})
	r.Do(q+"purge", func() error {
		if _, err := installArchive(ctx, d, builds["0.6.0"], "--express --auto-update off"); err != nil {
			return err
		}
		if _, err := RunFor(ctx, d, "sh /usr/local/share/cbb/uninstall.sh --purge", "", 2*time.Minute); err != nil {
			return err
		}
		left, err := footprint(ctx, d)
		if err != nil {
			return err
		}
		if diff := footprintDiff(clean, left); diff != "" {
			return fmt.Errorf("uninstall --purge left:\n%s", diff)
		}
		return nil
	})

	const s = "fleet/I7-downgrade/"
	r.Do(s+"previous", func() error {
		if _, err := installArchive(ctx, d, builds["0.6.1"], "--express --auto-update off"); err != nil {
			return err
		}
		if err := runsVersion(ctx, d, "0.6.1"); err != nil {
			return err
		}
		if _, err := Run(ctx, d, "cbb new", ""); err != nil {
			return err
		}
		if err := listens("8764"); err != nil {
			return err
		}
		tag, err := groupOf(ctx, d)
		if err != nil {
			return err
		}
		keys, err := stateFiles(ctx, d)
		if err != nil {
			return err
		}
		out, err := installArchive(ctx, d, builds["0.6.0"], "--express --auto-update off")
		fmt.Fprintf(r.out, "I7: %s\n", strings.Join(strings.Fields(out), " "))
		if err == nil {
			if err := runsVersion(ctx, d, "0.6.0"); err != nil {
				return fmt.Errorf("install.sh of 0.6.0 succeeded but: %w", err)
			}
			if got, err := groupOf(ctx, d); err != nil || got != tag {
				return fmt.Errorf("0.6.0 over 0.6.1's state is in group %q, not %q (%v)", got, tag, err)
			}
		} else if !strings.Contains(out, "newer") && !strings.Contains(out, "0.6.1") {
			return fmt.Errorf("install.sh of 0.6.0 failed without saying why: %q", out)
		}
		if after, err := stateFiles(ctx, d); err != nil || after != keys {
			return fmt.Errorf("the downgrade changed the keys: %v", err)
		}
		return nil
	})

	const u = "fleet/I6-upgrade/"
	var ds [2]*Device
	if r.Do(u+"install", func() error {
		for i := range ds {
			var err error
			if ds[i], err = f.AddSystemd(ctx, f.net); err != nil {
				return err
			}
			if _, err := installArchive(ctx, ds[i], builds["0.6.0"], "--express --auto-update off"); err != nil {
				return err
			}
			if err := runsVersion(ctx, ds[i], "0.6.0"); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	ds[0].Roles = []string{"member", "hub"}
	g := formGroup(ctx, r, u+"group", ds[:])
	if g == nil || len(g.members) != 2 {
		return
	}
	defer g.undoAll()
	for i, d := range ds {
		r.Do(fmt.Sprintf("%sstep%d", u, i+1), func() error {
			keys, err := stateFiles(ctx, d)
			if err != nil {
				return err
			}
			if _, err := installArchive(ctx, d, builds["0.6.1"], "--express --auto-update off"); err != nil {
				return err
			}
			if err := runsVersion(ctx, d, "0.6.1"); err != nil {
				return err
			}
			if after, err := stateFiles(ctx, d); err != nil || after != keys {
				return fmt.Errorf("the upgrade changed the keys of %s: %v", d.Name, err)
			}
			if got, err := groupOf(ctx, d); err != nil || got != g.tag {
				return fmt.Errorf("%s is in group %q after the upgrade, not %q (%v)", d.Name, got, g.tag, err)
			}
			other := ds[1-i]
			if err := syncs(ctx, g, d, other, fmt.Sprintf("upgraded %d", i+1), time.Minute); err != nil {
				return err
			}
			return syncs(ctx, g, other, d, fmt.Sprintf("back %d", i+1), time.Minute)
		})
	}
}
