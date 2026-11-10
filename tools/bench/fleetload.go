// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The fleet's load: latency, throughput and big transfers (E1, E2, E4) and
// the faults of a transfer (O7).

// watchClipboard starts a loop on d that writes each new text of its
// clipboard, with the time it saw it in nanoseconds, to file.
func watchClipboard(ctx context.Context, d *Device, file string) error {
	_, err := docker(ctx, "exec", "-d", d.Container, "sh", "-c",
		`last=""; while :; do t=$(cbb paste 2>/dev/null); if [ "$t" != "$last" ]; then echo "$(date +%s%N) $t" >>`+file+`; last="$t"; fi; sleep 0.05; done`)
	return err
}

// seenAt reads what watchClipboard wrote: the time each text was first
// seen.
func seenAt(ctx context.Context, d *Device, file string) (map[string]int64, error) {
	out, err := Run(ctx, d, "cat "+file, "")
	if err != nil {
		return nil, err
	}
	at := map[string]int64{}
	for _, l := range strings.Split(out, "\n") {
		ts, text, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			continue
		}
		if _, seen := at[text]; !seen {
			at[text] = n
		}
	}
	return at, nil
}

// nowNS is the time on d in nanoseconds; the containers share the
// controller's clock.
func nowNS(ctx context.Context, d *Device) (int64, error) {
	out, err := Run(ctx, d, "date +%s%N", "")
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(out), 10, 64)
}

// percentile returns the p-th percentile of ds.
func percentile(ds []time.Duration, p int) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[min(len(s)-1, len(s)*p/100)]
}

// latency (E1): 200 copies from the members in turn, a second apart; at
// each receiver p50 and p95 of the time to arrive, at most 2 s at home and
// 5 s for a client through the tunnel.
func latency(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/E1-latency/"
	a := newAwayGroup(ctx, r, f, "fleet/E1-latency", 4)
	if a == nil {
		return
	}
	c := a.join(ctx, r, p+"away-invited")
	if c == nil {
		return
	}
	const file = "/tmp/cbbbench-seen"
	if r.Do(p+"watch", func() error {
		if err := connected(ctx, c, 3*time.Minute); err != nil {
			return err
		}
		for _, d := range a.members {
			if err := watchClipboard(ctx, d, file); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	senders := a.members[:4]
	sent := map[string]int64{}
	from := map[string]*Device{}
	if r.Do(p+"copies", func() error {
		for i := range 200 {
			d := senders[i%len(senders)]
			text := fmt.Sprintf("cbb-bench %s e1 %d", a.run, i)
			t, err := nowNS(ctx, d)
			if err != nil {
				return err
			}
			if err := Copy(ctx, d, text); err != nil {
				return err
			}
			sent[text], from[text] = t, d
			time.Sleep(time.Second)
		}
		time.Sleep(10 * time.Second)
		return nil
	}) != nil {
		return
	}
	// The worst receiver's times at home and the away client's, for the
	// run's trend (trend.go).
	worst := map[string][2]time.Duration{}
	defer func() {
		for _, where := range []string{"home", "away"} {
			if w, ok := worst[where]; ok {
				r.Metric("E1/"+where+"-p50", "ms", float64(w[0].Milliseconds()))
				r.Metric("E1/"+where+"-p95", "ms", float64(w[1].Milliseconds()))
			}
		}
	}()
	for _, d := range a.members {
		limit := 2 * time.Second
		where := "home"
		if d == c {
			limit = 5 * time.Second
			where = "away"
		}
		r.Do(fmt.Sprintf("fleet/E1-%s", d.Name), func() error {
			at, err := seenAt(ctx, d, file)
			if err != nil {
				return err
			}
			var ds []time.Duration
			missed := 0
			for text, t := range sent {
				if from[text] == d {
					continue
				}
				got, ok := at[text]
				if !ok {
					missed++
					continue
				}
				ds = append(ds, time.Duration(got-t))
			}
			p50, p95 := percentile(ds, 50), percentile(ds, 95)
			w := worst[where]
			worst[where] = [2]time.Duration{max(w[0], p50), max(w[1], p95)}
			fmt.Fprintf(r.out, "     E1: %s got %d copies, p50 %v, p95 %v, %d not seen\n", d.Name, len(ds), p50.Round(time.Millisecond), p95.Round(time.Millisecond), missed)
			switch {
			case missed > len(sent)/20:
				return fmt.Errorf("%s never saw %d of the copies", d.Name, missed)
			case p95 > limit:
				return fmt.Errorf("p95 on %s is %v, over %v", d.Name, p95, limit)
			}
			return nil
		})
	}
}

// serviceUse is the service's process on d: its PID, resident memory in
// KiB and open descriptors.
func serviceUse(ctx context.Context, d *Device) (pid string, rssKiB, fds int, err error) {
	out, err := Run(ctx, d, `for p in /proc/[0-9]*; do if [ "$(cat $p/comm 2>/dev/null)" = cbb ] && tr '\0' ' ' <$p/cmdline | grep -q 'cbb service'; then echo ${p#/proc/} $(awk '/VmRSS/{print $2}' $p/status) $(ls $p/fd | wc -l); fi; done`, "")
	if err != nil {
		return "", 0, 0, err
	}
	f := strings.Fields(out)
	if len(f) != 3 {
		return "", 0, 0, fmt.Errorf("no service on %s: %q", d.Name, out)
	}
	rssKiB, _ = strconv.Atoi(f[1])
	fds, _ = strconv.Atoi(f[2])
	return f[0], rssKiB, fds, nil
}

// throughput (E2): every member copies every 100 ms for 3 minutes; all end
// on one text, no service restarted, and memory and descriptors go back to
// about where they started.
func throughput(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/E2-throughput/"
	g := fleetGroup(ctx, r, f, "fleet/E2-throughput", 5)
	if g == nil || len(g.members) < 5 {
		return
	}
	type use struct {
		pid      string
		rss, fds int
	}
	before := map[*Device]use{}
	if r.Do(p+"before", func() error {
		for _, d := range g.members {
			pid, rss, fds, err := serviceUse(ctx, d)
			if err != nil {
				return err
			}
			before[d] = use{pid, rss, fds}
		}
		return nil
	}) != nil {
		return
	}
	r.Do(p+"copies", func() error {
		for _, d := range g.members {
			if _, err := docker(ctx, "exec", "-d", d.Container, "sh", "-c",
				fmt.Sprintf(`i=0; while [ $i -lt 1800 ]; do echo "cbb-bench %s e2 %s $i" | cbb copy; i=$((i+1)); sleep 0.1; done; touch /tmp/e2-done`, g.run, d.Name)); err != nil {
				return err
			}
		}
		return eventually(ctx, 6*time.Minute, func() error {
			for _, d := range g.members {
				if _, err := Run(ctx, d, "test -f /tmp/e2-done", ""); err != nil {
					return fmt.Errorf("%s is still copying", d.Name)
				}
			}
			return nil
		})
	})
	r.Do("fleet/E2-one-text", func() error {
		return eventually(ctx, time.Minute, func() error {
			first, err := Paste(ctx, g.members[0])
			if err != nil {
				return err
			}
			for _, d := range g.members[1:] {
				got, err := Paste(ctx, d)
				if err != nil {
					return err
				}
				if got != first {
					return fmt.Errorf("%s has %q, %s has %q", g.members[0].Name, first, d.Name, got)
				}
			}
			return nil
		})
	})
	r.Do("fleet/E2-no-restarts", func() error {
		// The runtime gives memory back a few minutes after the load.
		time.Sleep(time.Minute)
		var errs []error
		mostRSS, mostFDs, grew := 0, 0, 0
		defer func() {
			r.Metric("E2/rss-after", "KiB", float64(mostRSS))
			r.Metric("E2/rss-growth", "KiB", float64(grew))
			r.Metric("E2/fds-after", "fds", float64(mostFDs))
		}()
		for _, d := range g.members {
			pid, rss, fds, err := serviceUse(ctx, d)
			if err != nil {
				return err
			}
			b := before[d]
			mostRSS, mostFDs, grew = max(mostRSS, rss), max(mostFDs, fds), max(grew, rss-b.rss)
			fmt.Fprintf(r.out, "     E2: %s memory %d to %d KiB, descriptors %d to %d\n", d.Name, b.rss, rss, b.fds, fds)
			switch {
			case pid != b.pid:
				errs = append(errs, fmt.Errorf("%s's service restarted", d.Name))
			case fds > b.fds+8:
				errs = append(errs, fmt.Errorf("%s holds %d descriptors, %d before", d.Name, fds, b.fds))
			case rss > 2*b.rss+32*1024:
				errs = append(errs, fmt.Errorf("%s uses %d KiB, %d before", d.Name, rss, b.rss))
			}
		}
		return errors.Join(errs...)
	})
}

// fileOn makes a file of mb MiB of random bytes on d and returns its
// SHA-256.
func fileOn(ctx context.Context, d *Device, file string, mb int) (string, error) {
	out, err := RunFor(ctx, d, fmt.Sprintf("head -c %dM /dev/urandom >%s && sha256sum %s", mb, file, file), "", time.Minute)
	if err != nil {
		return "", err
	}
	return firstField(out), nil
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// pastedFile saves d's clipboard file and returns its SHA-256.
func pastedFile(ctx context.Context, d *Device, timeout time.Duration) (string, error) {
	out, err := RunFor(ctx, d, "rm -rf /tmp/cbbbench-o && mkdir /tmp/cbbbench-o && cbb paste -o /tmp/cbbbench-o >/dev/null && sha256sum /tmp/cbbbench-o/*", "", timeout)
	if err != nil {
		return "", err
	}
	return firstField(out), nil
}

// bigTransfers (E4, O7): three members send 50 MiB files at once and every
// other member ends with the newest whole; a text sent right after the
// files arrives on time; on a slow link a fetch cut in the middle, and one
// whose sender restarts, still ends whole, and a newer copy stops a fetch.
func bigTransfers(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/E4-big/"
	g := fleetGroup(ctx, r, f, "fleet/E4-big", 5)
	if g == nil || len(g.members) < 5 {
		return
	}
	senders, receivers := g.members[:3], g.members[3:]
	sums := map[string]bool{}
	if r.Do(p+"files", func() error {
		for i, d := range senders {
			sum, err := fileOn(ctx, d, fmt.Sprintf("/tmp/big-%d", i), 50)
			if err != nil {
				return err
			}
			sums[sum] = true
		}
		return nil
	}) != nil {
		return
	}
	sendAll := func() error {
		errs := make(chan error, len(senders))
		for i, d := range senders {
			go func() {
				_, err := RunFor(ctx, d, fmt.Sprintf("cbb copy /tmp/big-%d", i), "", time.Minute)
				errs <- err
			}()
		}
		var all []error
		for range senders {
			all = append(all, <-errs)
		}
		return errors.Join(all...)
	}
	r.Do("fleet/E4-whole", func() error {
		start := time.Now()
		if err := sendAll(); err != nil {
			return err
		}
		var first string
		for _, d := range append(slices.Clone(receivers), senders...) {
			var sum string
			err := eventually(ctx, 2*time.Minute, func() error {
				var err error
				sum, err = pastedFile(ctx, d, time.Minute)
				if err == nil && !sums[sum] {
					err = fmt.Errorf("%s saved a file that none sent: %s", d.Name, sum)
				}
				return err
			})
			if err != nil {
				return err
			}
			if first == "" {
				first = sum
			} else if sum != first {
				return fmt.Errorf("%s ended with another file than the others", d.Name)
			}
		}
		r.Metric("E4/three-50MiB", "s", time.Since(start).Seconds())
		return nil
	})
	r.Do("fleet/E4-text-on-time", func() error {
		if err := sendAll(); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " text after the files"
		if err := Copy(ctx, receivers[0], text); err != nil {
			return err
		}
		for _, d := range append([]*Device{receivers[1]}, senders...) {
			if err := arrives(ctx, d, text, 5*time.Second); err != nil {
				return err
			}
		}
		return nil
	})

	// O7 on a slow link: 50 MiB at 40 Mbit/s take about ten seconds.
	from, to := senders[0], receivers[0]
	slow := func() error {
		_, err := Run(ctx, to, "tc qdisc replace dev eth0 root tbf rate 40mbit burst 64kb latency 400ms", "")
		return err
	}
	fast := func() { Run(context.WithoutCancel(ctx), to, "tc qdisc del dev eth0 root || true", "") }
	sum0 := ""
	r.Do(p+"slow", func() error {
		var err error
		if sum0, err = fileOn(ctx, from, "/tmp/big-0", 50); err != nil {
			return err
		}
		return slow()
	})
	defer fast()
	r.Do("fleet/O7-cut-resumes", func() error {
		if _, err := RunFor(ctx, from, "cbb copy /tmp/big-0", "", time.Minute); err != nil {
			return err
		}
		time.Sleep(4 * time.Second)
		if err := cut(ctx, from, to); err != nil {
			return err
		}
		time.Sleep(5 * time.Second)
		if err := heal(ctx, from, to); err != nil {
			return err
		}
		sum, err := pastedFile(ctx, to, 3*time.Minute)
		if err == nil && sum != sum0 {
			err = fmt.Errorf("%s saved %s, not the file sent (%s)", to.Name, sum, sum0)
		}
		return err
	})
	r.Do("fleet/O7-sender-restarts", func() error {
		sum, err := fileOn(ctx, from, "/tmp/big-0", 50)
		if err != nil {
			return err
		}
		if _, err := RunFor(ctx, from, "cbb copy /tmp/big-0", "", time.Minute); err != nil {
			return err
		}
		time.Sleep(4 * time.Second)
		if _, err := Run(ctx, from, fleetKill, ""); err != nil {
			return err
		}
		got, err := pastedFile(ctx, to, 3*time.Minute)
		// The member's loop starts the service again; the next case copies
		// on it, so wait until it answers.
		if up := eventually(ctx, time.Minute, func() error {
			_, err := Run(ctx, from, "cbb status", "")
			return err
		}); up != nil {
			return up
		}
		switch {
		case err != nil:
			// The copy may be gone with the sender's memory; the receiver
			// must then say so, not hang.
			var re *RunError
			if errors.As(err, &re) && strings.TrimSpace(re.Output) != "" && !strings.Contains(re.Output, "no answer within") {
				fmt.Fprintf(r.out, "     O7: after the sender restarted: %s\n", firstLine(re.Output))
				return nil
			}
			return err
		case got != sum:
			return fmt.Errorf("%s saved %s, not the file sent (%s)", to.Name, got, sum)
		}
		return nil
	})
	r.Do("fleet/O7-newer-stops-fetch", func() error {
		if _, err := fileOn(ctx, from, "/tmp/big-0", 50); err != nil {
			return err
		}
		if _, err := RunFor(ctx, from, "cbb copy /tmp/big-0", "", time.Minute); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		text := "cbb-bench " + g.run + " newer than the file"
		if err := Copy(ctx, senders[1], text); err != nil {
			return err
		}
		return arrives(ctx, to, text, 5*time.Second)
	})
}
