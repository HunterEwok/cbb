// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// renewalChecks (K3): a member takes a renewed certificate only from a
// valid admin. The forge, connected as another member, sends the target
// certificates for another device, for another key, ending earlier, not
// for client authentication and from an admin that is frozen; the target
// keeps its own and logs each, and then takes a valid renewal from the
// root.
func renewalChecks(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/K3-renewals/"
	g := fleetGroup(ctx, r, f, "fleet/K3-renewals", 4)
	if g == nil || len(g.members) < 4 {
		return
	}
	root, admin, m, t := g.members[0], g.members[1], g.members[2], g.members[3]
	var h *Device
	if r.Do(p+"forge", func() error {
		if err := succeeds(ctx, root, "cbb admin -allow-file-key "+admin.Name, "", "is an admin now"); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{t}, admin.Name, "admin", false, timeout); err != nil {
			return err
		}
		var err error
		h, err = forgeHost(ctx, f, m, root, admin, t)
		return err
	}) != nil {
		return
	}
	before, err := memberCert(ctx, t)
	if err != nil {
		r.Do(p+"certificate", func() error { return err })
		return
	}
	// Each in a connection of its own, so that a certificate taken names
	// its case.
	for _, c := range []struct{ name, arg string }{
		{"other-device", "cert:other-device"},
		{"other-key", "cert:other-key"},
		{"ending-earlier", "cert:earlier"},
		{"server-only", "cert:server-only"},
	} {
		r.Do("fleet/K3-"+c.name, func() error {
			if _, err := runForge(ctx, h, m, root, t, "-target-state", "/tmp/"+t.Name, c.arg); err != nil {
				return err
			}
			now, err := memberCert(ctx, t)
			if err != nil {
				return err
			}
			if !now.Equal(before) {
				before = now
				return fmt.Errorf("%s took the certificate, valid until %s", t.Name, now.NotAfter.Format(time.DateOnly))
			}
			logs, err := docker(ctx, "logs", "--tail", "20", t.Container)
			if err != nil {
				return err
			}
			if !strings.Contains(logs, "a renewed certificate from") {
				return fmt.Errorf("%s did not log the certificate it refused", t.Name)
			}
			return nil
		})
	}
	// takes sends a renewal signed by signer's CA and checks that the
	// target took it.
	takes := func(signer *Device) error {
		if _, err := runForge(ctx, h, m, signer, t, "-target-state", "/tmp/"+t.Name, "cert:valid"); err != nil {
			return err
		}
		return eventually(ctx, 10*time.Second, func() error {
			now, err := memberCert(ctx, t)
			if err == nil && !now.NotAfter.After(before.NotAfter) {
				err = fmt.Errorf("%s did not take a valid renewal from %s", t.Name, signer.Name)
			}
			if err == nil {
				before = now
			}
			return err
		})
	}
	r.Do("fleet/K3-frozen-admin-renews-listed", func() error {
		// A frozen admin's certificates hold for the devices the records
		// list (docs/protocol.md, section 10): it renews them, and brings
		// in none.
		if err := succeeds(ctx, root, "cbb freeze "+admin.Name, "", "Froze"); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{t}, admin.Name, "frozen", false, timeout); err != nil {
			return err
		}
		return takes(admin)
	})
	r.Do("fleet/K3-renewed-by-removed-admin", func() error {
		// The admin that renewed the target's certificate is removed: the
		// target stays in the group.
		if _, err := Run(ctx, root, "cbb remove "+admin.Name, "yes\n"); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root}, admin.Name, "", true, timeout); err != nil {
			return err
		}
		// A new connection, whose handshake checks the certificate.
		if err := signalService(ctx, t, "KILL"); err != nil {
			return err
		}
		return syncs(ctx, g, root, t, "after the admin that renewed it was removed", 2*timeout)
	})
	r.Do("fleet/K3-removed-admin", func() error {
		if _, err := runForge(ctx, h, m, root, t, "-target-state", "/tmp/"+t.Name, "cert:valid:/tmp/"+admin.Name); err != nil {
			return err
		}
		now, err := memberCert(ctx, t)
		if err == nil && !now.Equal(before) {
			err = fmt.Errorf("%s took a certificate from a removed admin", t.Name)
		}
		return err
	})
	r.Do("fleet/K3-valid-taken", func() error { return takes(root) })
}
