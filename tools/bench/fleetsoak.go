// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// soakFor (-soak-for) is how long the soak (E10) runs; 0 leaves it out, a
// release's run takes 24h.
var soakFor time.Duration

// The soak's pace and how much its samples may grow. A shorter run than
// a day keeps four faults and twelve samples at least, so that a check of
// the soak itself goes through every part.
const (
	soakCopyEvery   = 30 * time.Second
	soakFaultEvery  = time.Hour
	soakSampleEvery = 5 * time.Minute
	soakRSSGrowth   = 1.5      // the last part's mean RSS against the first's
	soakRSSSlackKiB = 16 << 10 // and a fixed margin over it
	soakFDSlack     = 8        // descriptors over the first part's most
)

// soakSample is one member's service at one time.
type soakSample struct {
	at       time.Duration
	rss, fds int
}

// soak (E10): a group of four runs for -soak-for with a copy every 30 s from
// a random member, which must reach every other one, and a fault every
// hour (a cut between two members, a frozen member, a killed service), each
// followed by sync again. Every 5 minutes it samples each service's memory
// and descriptors: at the end they must be flat (the last sixth against the
// first) and no service may have restarted but the one a fault killed.
func soak(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/E10-soak/"
	if soakFor <= 0 {
		r.Skip(p+"run", "a soak run: give -soak-for, such as 24h for a release")
		return
	}
	g := fleetGroup(ctx, r, f, "fleet/E10-soak", 4)
	if g == nil || len(g.members) != 4 {
		return
	}
	ms := g.members
	pids := map[*Device]string{}
	samples := map[*Device][]soakSample{}
	start := time.Now()
	sample := func() error {
		for _, m := range ms {
			pid, rss, fds, err := serviceHealth(ctx, m)
			if err != nil {
				return err
			}
			if old, ok := pids[m]; ok && old != pid {
				return fmt.Errorf("the service on %s restarted with no fault (pid %s, then %s)", m.Name, old, pid)
			}
			pids[m] = pid
			samples[m] = append(samples[m], soakSample{time.Since(start), rss, fds})
		}
		return nil
	}
	if r.Do(p+"start", sample) != nil {
		return
	}
	var copies, faults int
	var missed []string
	// fault breaks something for a while and waits until the group syncs
	// again; a killed service's new PID is taken as its own.
	fault := func(n int) error {
		a, b := ms[rand.IntN(len(ms))], ms[rand.IntN(len(ms))]
		for b == a {
			b = ms[rand.IntN(len(ms))]
		}
		switch n % 3 {
		case 0:
			if err := cut(ctx, a, b); err != nil {
				return err
			}
			time.Sleep(2 * time.Minute)
			if err := heal(ctx, a, b); err != nil {
				return err
			}
		case 1:
			if _, err := docker(ctx, "pause", a.Container); err != nil {
				return err
			}
			time.Sleep(time.Minute)
			if _, err := docker(ctx, "unpause", a.Container); err != nil {
				return err
			}
		case 2:
			if _, err := Run(ctx, a, fleetKill, ""); err != nil {
				return err
			}
			if err := eventually(ctx, 30*time.Second, func() error {
				pid, _, _, err := serviceHealth(ctx, a)
				if err == nil && pid == pids[a] {
					err = fmt.Errorf("the service on %s is still the killed one", a.Name)
				}
				if err == nil {
					pids[a] = pid
				}
				return err
			}); err != nil {
				return err
			}
		}
		return syncs(ctx, g, b, a, fmt.Sprintf("E10 after fault %d", n), 2*time.Minute)
	}
	r.Do(p+"run", func() error {
		end := start.Add(soakFor)
		faultEvery, sampleEvery := min(soakFaultEvery, soakFor/4), min(soakSampleEvery, soakFor/12)
		nextFault := start.Add(faultEvery)
		nextSample := start.Add(sampleEvery)
		for time.Now().Before(end) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if time.Now().After(nextFault) {
				faults++
				if err := fault(faults); err != nil {
					return fmt.Errorf("fault %d: %w", faults, err)
				}
				nextFault = nextFault.Add(faultEvery)
			}
			if time.Now().After(nextSample) {
				if err := sample(); err != nil {
					return err
				}
				nextSample = nextSample.Add(sampleEvery)
			}
			copies++
			from := ms[rand.IntN(len(ms))]
			text := fmt.Sprintf("cbb-bench %s E10 copy %d from %s", g.run, copies, from.Name)
			if err := Copy(ctx, from, text); err != nil {
				return err
			}
			for _, to := range ms {
				if to != from {
					if err := arrives(ctx, to, text, timeout); err != nil {
						missed = append(missed, fmt.Sprintf("copy %d from %s on %s", copies, from.Name, to.Name))
					}
				}
			}
			time.Sleep(time.Until(time.Now().Add(soakCopyEvery).Truncate(soakCopyEvery)))
		}
		r.Note(p+"run", fmt.Sprintf("%d copies and %d faults over %s", copies, faults, time.Since(start).Round(time.Minute)))
		if len(missed) > 0 {
			return fmt.Errorf("%d of %d copies did not arrive everywhere, first %s", len(missed), copies, missed[0])
		}
		return nil
	})
	r.Do(p+"flat", func() error {
		if err := sample(); err != nil {
			return err
		}
		var errs []error
		most := 0
		for _, m := range ms {
			for _, x := range samples[m] {
				most = max(most, x.rss)
			}
			msg, err := soakFlat(samples[m])
			r.Note(p+"flat", m.Name+": "+msg)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", m.Name, err))
			}
		}
		r.Metric("E10/rss-most", "KiB", float64(most))
		return errors.Join(errs...)
	})
}

// soakFlat compares the last sixth of a service's samples with the first
// sixth (or the last and first sample when there are few): the mean
// resident memory may grow by soakRSSGrowth and soakRSSSlackKiB, the most
// descriptors by soakFDSlack.
func soakFlat(s []soakSample) (string, error) {
	if len(s) < 2 {
		return "too few samples", nil
	}
	n := max(len(s)/6, 1)
	first, last := s[:n], s[len(s)-n:]
	mean := func(ss []soakSample) (rss float64, fds int) {
		for _, x := range ss {
			rss += float64(x.rss)
			fds = max(fds, x.fds)
		}
		return rss / float64(len(ss)), fds
	}
	r0, f0 := mean(first)
	r1, f1 := mean(last)
	msg := fmt.Sprintf("RSS %.0f then %.0f MiB, descriptors %d then %d", r0/1024, r1/1024, f0, f1)
	var bad []string
	if r1 > r0*soakRSSGrowth+soakRSSSlackKiB {
		bad = append(bad, "its memory grew")
	}
	if f1 > f0+soakFDSlack {
		bad = append(bad, "its descriptors grew")
	}
	if len(bad) > 0 {
		return msg, fmt.Errorf("%s: %s", strings.Join(bad, " and "), msg)
	}
	return msg, nil
}
