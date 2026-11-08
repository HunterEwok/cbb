// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The time-scaled build (`go build -tags benchtime`, internal/benchtime)
// runs every long time of the product benchScale times faster: a member
// certificate lasts about ten minutes and is renewed in its last three and
// a half, a credential period lasts half a minute. The time suite runs that
// build in the fleet (docs/testbench-catalogue.md, section 0.1, "time").
const benchScale = 100000

// scaled is d as the time-scaled build runs it.
func scaled(d time.Duration) time.Duration { return d / benchScale }

// TimeSuite runs the cases that wait for certificates and credential
// periods to end, on fleet members of the time-scaled build cbb.
func TimeSuite(ctx context.Context, r *Report, cbb string, timeout time.Duration) {
	cleanFleet(ctx)
	var f *Fleet
	if r.Do("time/setup", func() error {
		var err error
		if f, err = NewFleet(ctx, cbb); err != nil {
			return err
		}
		out, err := exec1(ctx, f.cbb, "version")
		if err == nil && !strings.Contains(out, "time-scaled") {
			err = fmt.Errorf("%s is not the time-scaled build (go build -tags benchtime): %s", cbb, firstLine(out))
		}
		return err
	}) != nil {
		if f != nil {
			f.Close(ctx)
		}
		return
	}
	defer f.Close(ctx)

	if scenario("K1-renewal") {
		certificates(ctx, r, f, timeout)
	}
	if ctx.Err() == nil && scenario("K6-clock") {
		clocks(ctx, r, f, timeout)
	}
	if ctx.Err() == nil && scenario("W12-hub-key") {
		hubKeys(ctx, r, f, timeout)
	}
	if ctx.Err() == nil && scenario("K5-ca-end") {
		caEnd(ctx, r, f, timeout)
	}
	if ctx.Err() == nil && scenario("W46-xhttp") {
		f.serverEnv, f.memberEnv = xhttpEnv, xhttpEnv
		hubOverXHTTP(ctx, r, f, timeout)
		f.serverEnv, f.memberEnv = nil, nil
	}
}

// certificates (K1, K2, K4, K7, W39): renewal, credential periods and a
// certificate that ends while no admin is on.
func certificates(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	// Both groups start now, so that their certificates age together: in
	// the second the root is away through the member's renewal window.
	renewed := fleetGroup(ctx, r, f, "time/K1-renewal", 3)
	lapsed := fleetGroup(ctx, r, f, "time/K4-lapse", 2)
	if lapsed != nil {
		r.Do("time/K4-lapse/root-away", func() error { return f.stop(ctx, lapsed.hub) })
	}
	if renewed != nil {
		renewal(ctx, r, renewed, timeout)
		periods(ctx, r, renewed)
	}
	if lapsed != nil {
		lapse(ctx, r, f, lapsed, timeout)
	}
}

// exec1 runs a program on the controller.
func exec1(ctx context.Context, name string, args ...string) (string, error) {
	return docker(ctx, append([]string{"run", "--rm", "-v", name + ":/cbb:ro", fleetImage, "/cbb"}, args...)...)
}

// memberCert reads a fleet member's member certificate from its state.
func memberCert(ctx context.Context, d *Device) (*x509.Certificate, error) {
	out, err := Run(ctx, d, "cat /var/lib/cbb/identity.json", "")
	if err != nil {
		return nil, err
	}
	var f struct {
		Cert []byte `json:"cert"`
	}
	if err := json.Unmarshal([]byte(out), &f); err != nil {
		return nil, fmt.Errorf("%s: identity.json: %w", d.Name, err)
	}
	return x509.ParseCertificate(f.Cert)
}

// renewal (K1, K7): the root renews the members' certificates in their
// renewal window over connections that stay up, and its own; the group
// keeps syncing across it.
func renewal(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const p = "time/K1-renewal/"
	first := map[string]time.Time{}
	if r.Do(p+"certificates", func() error {
		for _, m := range g.members {
			c, err := memberCert(ctx, m)
			if err != nil {
				return err
			}
			first[m.Name] = c.NotAfter
		}
		return nil
	}) != nil {
		return
	}
	// A member certificate lasts two scaled years and is renewed when less
	// than 240 scaled days remain.
	life := scaled(2 * 365 * 24 * time.Hour)
	for _, m := range g.members {
		r.Do(p+"renewed/"+m.Name, func() error {
			return eventually(ctx, life, func() error {
				c, err := memberCert(ctx, m)
				if err != nil {
					return err
				}
				if !c.NotAfter.After(first[m.Name]) {
					return fmt.Errorf("%s still has its certificate until %s", m.Name, c.NotAfter.Format(time.TimeOnly))
				}
				return nil
			})
		})
	}
	r.Do(p+"K7-still-syncing", func() error {
		text := "cbb-bench " + g.run + " after the renewal"
		if err := Copy(ctx, g.members[1], text); err != nil {
			return err
		}
		for _, m := range []*Device{g.members[0], g.members[2]} {
			if err := arrives(ctx, m, text, timeout); err != nil {
				return err
			}
		}
		return nil
	})
}

// periods (W39): the root starts a new credential period when the last is
// 30 scaled days old, and every member takes it.
func periods(ctx context.Context, r *Report, g *benchGroup) {
	const p = "time/W39-periods/"
	sum := func(d *Device) (string, error) {
		out, err := Run(ctx, d, "cat /var/lib/cbb/credentials.json", "")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(out) == "" {
			return "", fmt.Errorf("%s keeps no credentials", d.Name)
		}
		return fmt.Sprintf("%x", sha256.Sum256([]byte(out))), nil
	}
	before := map[string]string{}
	if r.Do(p+"credentials", func() error {
		for _, m := range g.members {
			s, err := sum(m)
			if err != nil {
				return err
			}
			before[m.Name] = s
		}
		return nil
	}) != nil {
		return
	}
	for _, m := range g.members {
		r.Do(p+"new-period/"+m.Name, func() error {
			return eventually(ctx, 3*scaled(35*24*time.Hour), func() error {
				s, err := sum(m)
				if err == nil && s == before[m.Name] {
					err = fmt.Errorf("%s keeps the same credentials", m.Name)
				}
				return err
			})
		})
	}
}

// lapse (K4): the member's certificate ends while no admin is on; it can
// no longer connect, says so, and pairs again.
func lapse(ctx context.Context, r *Report, f *Fleet, g *benchGroup, timeout time.Duration) {
	const p = "time/K4-lapse/"
	m := g.members[1]
	var end time.Time
	if r.Do(p+"certificate", func() error {
		c, err := memberCert(ctx, m)
		end = c.NotAfter
		return err
	}) != nil {
		return
	}
	if wait := time.Until(end) + 5*time.Second; wait > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
	r.Do(p+"root-back", func() error { return f.start(ctx, g.hub) })
	r.Do(p+"refused", func() error {
		time.Sleep(timeout)
		out, err := Run(ctx, m, "cbb status", "")
		if err == nil && !strings.Contains(out, "certificate ended on") {
			err = fmt.Errorf("%s does not say that its certificate ended: %q", m.Name, out)
		}
		return err
	})
	r.Do(p+"pairs-again", func() error {
		id, err := deviceOf(ctx, m)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, g.hub, "cbb remove "+id, ""); err != nil {
			return err
		}
		if _, err := Run(ctx, m, "rm -rf /var/lib/cbb/*", ""); err != nil {
			return err
		}
		if _, err := docker(ctx, "restart", "-t", "1", m.Container); err != nil {
			return err
		}
		if err := eventually(ctx, 20*time.Second, func() error {
			_, err := Run(ctx, m, "cbb status", "")
			return err
		}); err != nil {
			return err
		}
		if _, err := pairOne(ctx, g.hub, m); err != nil {
			return err
		}
		if err := setMode(ctx, m, "shared"); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " after pairing again"
		if err := Copy(ctx, g.hub, text); err != nil {
			return err
		}
		return arrives(ctx, m, text, timeout)
	})
}

// clockFile is where a fleet member of the clock cases reads how far its
// clock is off (CBB_TEST_CLOCK_FILE), when its service starts.
const clockFile = "/etc/cbb-test-clock"

// setClock moves a member's clock: a duration from the real time, an RFC
// 3339 time, or "" for the real time; its service starts again with it.
func setClock(ctx context.Context, d *Device, clock string) error {
	cmd := "rm -f " + clockFile
	if clock != "" {
		cmd = "echo " + clock + " >" + clockFile
	}
	if _, err := Run(ctx, d, cmd+" && "+fleetKill, ""); err != nil {
		return err
	}
	return eventually(ctx, 20*time.Second, func() error {
		_, err := Run(ctx, d, "cbb status", "")
		return err
	})
}

// clocks (K6, Y13): members whose clocks are wrong. They run at the real
// pace (CBB_TEST_SCALE=1), so that a clock hours or days off leaves the
// certificates valid.
func clocks(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "time/K6-clock/"
	g := fleetGroup(ctx, r, f, "time/K6-clock", 4, "CBB_TEST_SCALE=1", "CBB_TEST_CLOCK_FILE="+clockFile)
	if g == nil || len(g.members) < 4 {
		return
	}
	a, b, c, d := g.members[0], g.members[1], g.members[2], g.members[3]
	n := 0
	text := func(what string) string {
		n++
		return fmt.Sprintf("cbb-bench %s %d %s", g.run, n, what)
	}
	// both copies a text on from and waits for it on every other member.
	both := func(from *Device, what string) error {
		t := text(what)
		if err := Copy(ctx, from, t); err != nil {
			return err
		}
		for _, m := range g.members {
			if m != from {
				if err := arrives(ctx, m, t, timeout); err != nil {
					return err
				}
			}
		}
		return nil
	}
	// skewShown waits until a's devices list shows c's clock off by want.
	skewShown := func(want string) error {
		return eventually(ctx, timeout, func() error {
			out, err := Run(ctx, a, "cbb status", "")
			if err == nil && !strings.Contains(out, "off by "+want) {
				err = fmt.Errorf("%s does not show a clock off by %s: %q", a.Name, want, out)
			}
			return err
		})
	}

	// A board that boots with its clock in 1970 still takes and sends.
	r.Do(p+"behind-1970", func() error {
		if err := setClock(ctx, b, "1970-01-01T00:00:00Z"); err != nil {
			return err
		}
		if err := both(a, "to a clock in 1970"); err != nil {
			return err
		}
		return both(b, "from a clock in 1970")
	})
	r.Do(p+"behind-back", func() error { return setClock(ctx, b, "") })

	// Clocks an hour and three hours ahead: the group works, and the
	// devices list says the clock is off.
	for _, ahead := range []time.Duration{time.Hour, 3 * time.Hour} {
		r.Do(p+"ahead-"+ahead.String(), func() error {
			if err := setClock(ctx, c, ahead.String()); err != nil {
				return err
			}
			if err := both(c, "from a clock ahead"); err != nil {
				return err
			}
			if err := both(a, "to a clock ahead"); err != nil {
				return err
			}
			return skewShown(ahead.String())
		})
	}

	// Y13: a clock two days ahead moves the others' hybrid clocks with
	// its copy; a copy made later elsewhere still wins everywhere.
	r.Do("time/Y13-ahead/later-wins", func() error {
		if err := setClock(ctx, c, "48h"); err != nil {
			return err
		}
		if err := both(c, "two days ahead"); err != nil {
			return err
		}
		return both(d, "after the copy from two days ahead")
	})
	// An event more than 7 days ahead of the others' clocks is refused,
	// and both sides show the clock off.
	r.Do("time/Y13-ahead/refused", func() error {
		if err := setClock(ctx, c, "240h"); err != nil {
			return err
		}
		t := text("ten days ahead")
		if err := Copy(ctx, c, t); err != nil {
			return err
		}
		for _, m := range []*Device{a, b, d} {
			if err := staysAway(ctx, m, t); err != nil {
				return fmt.Errorf("an event 10 days ahead: %w", err)
			}
		}
		if err := skewShown("240h0m0s"); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			out, err := Run(ctx, c, "cbb status", "")
			if err == nil && !strings.Contains(out, "off by -240h0m0s; check its time") {
				err = fmt.Errorf("%s does not show the others' clocks off: %q", c.Name, out)
			}
			return err
		})
	})

	// A clock past the end of the certificates (2 years): the member
	// refuses the group and says when its certificate ended by its clock.
	r.Do(p+"ahead-3y", func() error {
		if err := setClock(ctx, c, fmt.Sprint(3*365*24*time.Hour)); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			out, err := Run(ctx, c, "cbb status", "")
			if err == nil && !strings.Contains(out, "certificate ended on") {
				err = fmt.Errorf("%s does not say that its certificate ended: %q", c.Name, out)
			}
			return err
		})
	})

	// Its clock set right, the member is back in the group both ways.
	r.Do(p+"set-right", func() error {
		if err := setClock(ctx, c, ""); err != nil {
			return err
		}
		if err := both(a, "to a clock set right"); err != nil {
			return err
		}
		return both(c, "from a clock set right")
	})

	// Y14: a member killed right after a copy and started again with its
	// clock an hour back still issues a later timestamp: its next copy wins
	// over the one before.
	r.Do("time/Y14-mark", func() error {
		first := text("before the crash")
		if err := Copy(ctx, d, first); err != nil {
			return err
		}
		if err := setClock(ctx, d, "-1h"); err != nil {
			return err
		}
		defer setClock(ctx, d, "")
		for _, m := range []*Device{a, b, c} {
			if err := arrives(ctx, m, first, timeout); err != nil {
				return err
			}
		}
		return both(d, "after the crash, an hour back")
	})

	// T8: a command is refused, with its reason, when it reached its target
	// after it expired by the target's clock, was signed more than a minute
	// ahead of it, or the target's clock is not set.
	command := func(name string, from, to, clock *Device, at, reason string) {
		r.Do("time/T8-"+name, func() error {
			if err := setClock(ctx, clock, at); err != nil {
				return err
			}
			defer setClock(ctx, clock, "")
			return eventually(ctx, timeout, func() error {
				return errorShown(ctx, from, errorCase{cmd: "cbb sync -on " + to.Name + " off", want: []string{reason}})
			})
		})
	}
	command("expired", a, b, b, "2m", "expired")
	command("ahead", a, b, a, "2m", "signed in the future")
	command("clock-not-set", a, b, b, "1970-01-01T00:00:00Z", "signed in the future")
}
