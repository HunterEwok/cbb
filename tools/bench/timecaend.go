// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"
)

// certsOf reads d's member certificate and its group CA from its identity
// file.
func certsOf(ctx context.Context, d *Device) (cert, ca *x509.Certificate, err error) {
	out, err := Run(ctx, d, "cat /var/lib/cbb/identity.json", "")
	if err != nil {
		return nil, nil, err
	}
	var f struct {
		Cert    []byte `json:"cert"`
		GroupCA []byte `json:"group_ca"`
	}
	if err := json.Unmarshal([]byte(out), &f); err != nil {
		return nil, nil, fmt.Errorf("%s: identity.json: %w", d.Name, err)
	}
	if cert, err = x509.ParseCertificate(f.Cert); err != nil {
		return nil, nil, err
	}
	ca, err = x509.ParseCertificate(f.GroupCA)
	return cert, ca, err
}

// caEnd (K5): at the end of the group CA's 20 years, with every clock moved
// there at the real pace, a certificate ends no later than its CA, and one
// that already ends with it is not renewed again, while the group keeps
// syncing. (Replacing the CA itself works as after a removal, which the
// takeover cases run.)
func caEnd(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "time/K5-ca-end/"
	env := []string{"CBB_TEST_SCALE=1", "CBB_TEST_CLOCK_FILE=" + clockFile}
	g := fleetGroup(ctx, r, f, "time/K5-ca-end", 1, env...)
	if g == nil || len(g.members) != 1 {
		return
	}
	root := g.hub
	var end time.Time
	var m *Device
	// endsWithCA waits until d's certificate ends with the CA.
	endsWithCA := func(d *Device) (*x509.Certificate, error) {
		var cert *x509.Certificate
		err := eventually(ctx, timeout, func() error {
			c, ca, err := certsOf(ctx, d)
			if err != nil {
				return err
			}
			if !c.NotAfter.Equal(ca.NotAfter) {
				return fmt.Errorf("%s's certificate ends %s, not with its CA on %s", d.Name, c.NotAfter.Format(time.DateOnly), ca.NotAfter.Format(time.DateOnly))
			}
			cert = c
			return nil
		})
		return cert, err
	}
	if r.Do(p+"near-the-end", func() error {
		_, ca, err := certsOf(ctx, root)
		if err != nil {
			return err
		}
		end = ca.NotAfter
		if err := setClock(ctx, root, end.Add(-300*24*time.Hour).Format(time.RFC3339)); err != nil {
			return err
		}
		// The root renews its own certificate, which ends with the CA.
		if _, err := endsWithCA(root); err != nil {
			return err
		}
		// A computer that joins now gets a certificate that ends with the CA.
		if m, err = f.Add(ctx, env...); err != nil {
			return err
		}
		if err := setClock(ctx, m, end.Add(-300*24*time.Hour).Format(time.RFC3339)); err != nil {
			return err
		}
		if _, err := pairOne(ctx, root, m); err != nil {
			return err
		}
		if err := setMode(ctx, m, "shared"); err != nil {
			return err
		}
		if _, err := endsWithCA(m); err != nil {
			return err
		}
		return syncs(ctx, g, root, m, "near the CA's end", timeout)
	}) != nil {
		return
	}
	r.Do(p+"not-renewed", func() error {
		before := map[*Device]*x509.Certificate{}
		for _, d := range []*Device{root, m} {
			c, _, err := certsOf(ctx, d)
			if err != nil {
				return err
			}
			before[d] = c
		}
		// 100 days before the end, well within the renewal window.
		for _, d := range []*Device{root, m} {
			if err := setClock(ctx, d, end.Add(-100*24*time.Hour).Format(time.RFC3339)); err != nil {
				return err
			}
		}
		if err := syncs(ctx, g, m, root, "within the renewal window", timeout); err != nil {
			return err
		}
		if err := syncs(ctx, g, root, m, "and back", timeout); err != nil {
			return err
		}
		time.Sleep(10 * time.Second)
		for _, d := range []*Device{root, m} {
			c, _, err := certsOf(ctx, d)
			if err != nil {
				return err
			}
			if !c.Equal(before[d]) {
				return fmt.Errorf("%s's certificate, which ended with its CA, was renewed (now %s to %s)", d.Name, c.NotBefore.Format(time.DateOnly), c.NotAfter.Format(time.DateOnly))
			}
		}
		return nil
	})
}
