// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A device class's budget (E12, docs/testbench.md "Budgets"): the
// container's cap, which stands in for the device's memory and CPU, and
// the most the lite member may use there. A run records each number as a
// metric too, so that -baseline also catches a slow drift under the
// budget.
type budget struct {
	class      string
	cpus, mem  string  // docker run's --cpus and --memory
	idleRSS    float64 // KiB, the service's resident memory a minute after joining
	idleCPU    float64 // percent of one core, over 30 s with nothing copied
	p95        float64 // ms, the time a copy takes to arrive
	copiesRSS  float64 // KiB, resident memory after 200 copies
	peakMemory float64 // KiB, the container's peak, its cgroup's
}

// budgets are the classes the lite member runs on that are smaller than a
// computer: a Raspberry Pi Zero (512 MiB, one slow core) and a router (128
// MiB). A quarter of the controller's core is about a Pi Zero's ARM11 at 1
// GHz. The first run (2026-11) measured about 8 MiB at rest and after the
// copies, a 6 MiB peak and 140 ms; the budgets leave room for that and
// only go down.
var budgets = []budget{
	{class: "pi-zero", cpus: "0.25", mem: "512m", idleRSS: 16 << 10, idleCPU: 2, p95: 1000, copiesRSS: 20 << 10, peakMemory: 48 << 10},
	{class: "router", cpus: "0.25", mem: "128m", idleRSS: 16 << 10, idleCPU: 2, p95: 1000, copiesRSS: 20 << 10, peakMemory: 48 << 10},
}

// AddLiteWith starts a lite member as AddLite does, with docker run's
// options run.
func (f *Fleet) AddLiteWith(ctx context.Context, run []string) (*Device, error) {
	abs, err := liteBinary()
	if err != nil {
		return nil, err
	}
	d, err := f.containerOf(ctx, abs, f.net, run, nil, liteLoop)
	if err != nil {
		return nil, err
	}
	if err := liteStarted(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// cpuTicks is the CPU time of process pid on d in clock ticks (user and
// system, /proc/PID/stat's fields 14 and 15) and the ticks in a second.
func cpuTicks(ctx context.Context, d *Device, pid string) (ticks, hz int64, err error) {
	out, err := Run(ctx, d, "getconf CLK_TCK; awk '{print $14+$15}' /proc/"+pid+"/stat", "")
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("the CPU time of %s on %s: %q", pid, d.Name, out)
	}
	if hz, err = strconv.ParseInt(f[0], 10, 64); err == nil && hz <= 0 {
		err = fmt.Errorf("CLK_TCK %d", hz)
	}
	if err == nil {
		ticks, err = strconv.ParseInt(f[1], 10, 64)
	}
	return ticks, hz, err
}

// within adds the case NAME under p that fails when got is over limit,
// and records got as the metric E12/CLASS/NAME.
func (b budget) within(r *Report, p, name, unit string, got, limit float64) {
	r.Metric("E12/"+b.class+"/"+name, unit, got)
	r.Do(p+name, func() error {
		if got > limit {
			return fmt.Errorf("%s on a %s is %.1f %s, over its budget of %.1f %s", name, b.class, got, unit, limit, unit)
		}
		return nil
	})
}

// budgetsCase (E12): a lite member in the cap of each class joins a full
// member's group; its memory and CPU at rest, the time 20 copies take to
// reach it, its memory after 200 more and the container's peak stay
// within the class's budget.
func budgetsCase(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const name = "fleet/E12-budgets"
	if fleetLite == "" {
		r.Skip(name, "give -cbb-lite FILE, the lite member's cbb for Linux, to measure the small devices' budgets")
		return
	}
	g := fleetGroup(ctx, r, f, name, 1)
	if g == nil || len(g.members) != 1 {
		return
	}
	hub := g.hub
	for _, b := range budgets {
		p := name + "/" + b.class + "/"
		var d *Device
		if r.Do(p+"join", func() error {
			var err error
			if d, err = f.AddLiteWith(ctx, []string{"--cpus", b.cpus, "--memory", b.mem, "--memory-swap", b.mem}); err != nil {
				return err
			}
			if err := joinLite(ctx, hub, d); err != nil {
				return err
			}
			return syncs(ctx, g, hub, d, "to the "+b.class, timeout)
		}) != nil {
			continue
		}
		budgetOf(ctx, r, g, hub, d, b, p, timeout)
	}
}

// budgetOf measures the lite member d against b.
func budgetOf(ctx context.Context, r *Report, g *benchGroup, hub, d *Device, b budget, p string, timeout time.Duration) {
	time.Sleep(time.Minute) // the join's work done
	pid, rss, _, err := serviceUse(ctx, d)
	if err != nil {
		r.Do(p+"service", func() error { return err })
		return
	}
	b.within(r, p, "idle-rss", "KiB", float64(rss), b.idleRSS)
	r.Do(p+"idle-cpu-measured", func() error {
		t0, hz, err := cpuTicks(ctx, d, pid)
		if err != nil {
			return err
		}
		const span = 30 * time.Second
		time.Sleep(span)
		t1, _, err := cpuTicks(ctx, d, pid)
		if err != nil {
			return err
		}
		b.within(r, p, "idle-cpu", "%", float64(t1-t0)/float64(hz)/span.Seconds()*100, b.idleCPU)
		return nil
	})

	const file = "/tmp/cbbbench-seen"
	var took []time.Duration
	if r.Do(p+"copies", func() error {
		if err := watchClipboard(ctx, d, file); err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), d, "pkill -f cbbbench-seen || true", "")
		sent := map[string]int64{}
		for i := range 20 {
			text := fmt.Sprintf("cbb-bench %s e12 %s %d", g.run, b.class, i)
			t, err := nowNS(ctx, hub)
			if err != nil {
				return err
			}
			if err := Copy(ctx, hub, text); err != nil {
				return err
			}
			sent[text] = t
			time.Sleep(time.Second)
		}
		time.Sleep(5 * time.Second)
		seen, err := seenAt(ctx, d, file)
		if err != nil {
			return err
		}
		for text, t := range sent {
			at, ok := seen[text]
			if !ok {
				return fmt.Errorf("%q never reached the %s", text, b.class)
			}
			took = append(took, time.Duration(at-t))
		}
		return nil
	}) == nil {
		b.within(r, p, "p95", "ms", float64(percentile(took, 95).Milliseconds()), b.p95)
	}

	if r.Do(p+"many-copies", func() error {
		for i := range 200 {
			if err := Copy(ctx, hub, fmt.Sprintf("cbb-bench %s e12 many %d", g.run, i)); err != nil {
				return err
			}
			time.Sleep(50 * time.Millisecond)
		}
		last := fmt.Sprintf("cbb-bench %s e12 many 199", g.run)
		return arrives(ctx, d, last, timeout)
	}) == nil {
		time.Sleep(10 * time.Second)
		now, rss, _, err := serviceUse(ctx, d)
		if err == nil && now != pid {
			err = fmt.Errorf("the %s's service restarted (pid %s, then %s)", b.class, pid, now)
		}
		if err != nil {
			r.Do(p+"copies-rss", func() error { return err })
		} else {
			b.within(r, p, "copies-rss", "KiB", float64(rss), b.copiesRSS)
		}
	}
	kills, peak, err := cgroupOOM(ctx, d)
	if err == nil && kills > 0 {
		err = fmt.Errorf("the memory cap killed %d processes on the %s", kills, b.class)
	}
	if err != nil {
		r.Do(p+"peak", func() error { return err })
	} else if peak > 0 {
		b.within(r, p, "peak", "KiB", float64(peak>>10), b.peakMemory)
	} else {
		r.Note(p+"peak", "the kernel keeps no peak for the container's cgroup")
	}
}
