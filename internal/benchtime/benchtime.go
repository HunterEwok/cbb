// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package benchtime is the clock of the bench's time-scaled build
// (docs/maintainers/testbench-catalogue.md, section 0.1, "time"). Built with
// `-tags benchtime`, never for a release, every long time of the product
// that goes through D runs Scale times faster, so expiry, renewal and every
// rule that waits for time play out in minutes, and CBB_TEST_CLOCK moves
// the member's wall clock (CBB_TEST_SCALE sets the scale, 1 to move only
// the clock). In every other build D returns its argument and
// Now is time.Now.
package benchtime

import (
	"fmt"
	"strings"
	"time"
)

// D returns d as this build runs it: d itself, or d divided by Scale in
// the time-scaled build.
func D(d time.Duration) time.Duration { return d / Scale }

// Years returns the time t plus years years: the calendar years of
// t.AddDate, or years of 365 days divided by Scale in the time-scaled
// build.
func Years(t time.Time, years int) time.Time {
	if Scale == 1 {
		return t.AddDate(years, 0, 0)
	}
	return t.Add(D(time.Duration(years) * 365 * 24 * time.Hour))
}

// Now returns the member's wall clock: time.Now, moved by CBB_TEST_CLOCK in
// the time-scaled build.
func Now() time.Time { return time.Now().Add(offset) }

// Enabled reports whether this is the time-scaled build.
func Enabled() bool { return enabled }

// parseClock reads CBB_TEST_CLOCK: a Go duration to add to the wall clock,
// such as "3h" or "-1h30m", or an RFC 3339 time the clock reads at start,
// such as 1970-01-01T00:00:00Z.
func parseClock(s string, now time.Time) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("benchtime: CBB_TEST_CLOCK %q is neither a duration nor an RFC 3339 time", s)
	}
	return t.Sub(now), nil
}
