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

// Faults makes a group as smoke does and breaks it in the ways of
// docs/testbench-catalogue.md, each with a timer on the device that
// takes the change back even if the controller is lost: a bad network on the
// hub (E7), a member's port blocked (E8), a damaged group file (U7), a
// service that hangs (E11, U6) and one that is stopped (U5). After each the
// group must sync again, and every error must read as R6 says.
func Faults(ctx context.Context, r *Report, devices []*Device, timeout time.Duration) {
	g := formGroup(ctx, r, "faults", devices)
	if g == nil {
		return
	}
	defer g.end(ctx, r)
	badNetwork(ctx, r, g, timeout)
	portBlocked(ctx, r, g, timeout)
	hungService(ctx, r, g, timeout)
	stoppedService(ctx, r, g, timeout)
	damagedState(ctx, r, g, timeout)
}

// revertAfter runs undo on a Linux device after the delay by a transient
// systemd timer, so a change of the bench never outlives a lost controller;
// cancel stops the timer once the bench took the change back itself.
func revertAfter(ctx context.Context, d *Device, unit string, delay time.Duration, undo string) (cancel func(), err error) {
	cmd := fmt.Sprintf("sudo -n systemd-run --quiet --collect --unit %s --on-active=%ds sh -c %s",
		unit, int(delay.Seconds()), shellQuote(undo))
	if _, err := Run(ctx, d, cmd, ""); err != nil {
		return nil, noSudo(d, err)
	}
	return func() {
		Run(context.WithoutCancel(ctx), d, "sudo -n systemctl stop "+unit+".timer "+unit+".service 2>/dev/null; true", "")
	}, nil
}

// linuxMember picks a Linux member with the service, not the hub when there
// is another, for a fault that should not take the group's root down.
func linuxMember(g *benchGroup) *Device {
	var pick *Device
	for _, d := range g.members {
		if d.OS != "linux" {
			continue
		}
		if d != g.hub {
			return d
		}
		pick = d
	}
	return pick
}

// lastWins copies n texts from the members in turn and checks every member
// ends on the last one within wait.
func lastWins(ctx context.Context, r *Report, g *benchGroup, prefix string, n int, gap, wait time.Duration) {
	var last string
	var from *Device
	for i := 1; i <= n; i++ {
		from = g.members[i%len(g.members)]
		last = fmt.Sprintf("cbb-bench %s %s %d", g.run, strings.TrimSuffix(prefix, "/"), i)
		if r.Do(fmt.Sprintf("%scopy/%d", prefix, i), func() error { return Copy(ctx, from, last) }) != nil {
			return
		}
		time.Sleep(gap)
	}
	for _, d := range g.members {
		r.Do(prefix+"last/"+d.Name, func() error { return arrives(ctx, d, seen(last, from, d), wait) })
	}
}

// badNetwork (E7): 30% loss, 300 ms delay and reordering on the hub's
// interface; twenty copies from the members in turn, and the last one wins
// everywhere.
func badNetwork(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const prefix = "faults/E7-netem/"
	if g.hub.OS != "linux" || len(g.members) < 2 {
		r.Skip(prefix, "needs a Linux hub and another member")
		return
	}
	var dev string
	if r.Do(prefix+"interface", func() error {
		out, err := Run(ctx, g.hub, "ip -o route get 1.1.1.1 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'", "")
		dev = strings.TrimSpace(out)
		if err == nil && dev == "" {
			err = errors.New("no default route on the hub")
		}
		return err
	}) != nil {
		return
	}
	del := "tc qdisc del dev " + dev + " root 2>/dev/null; true"
	var cancel func()
	if r.Do(prefix+"apply", func() error {
		var err error
		if cancel, err = revertAfter(ctx, g.hub, "cbbbench-netem", 10*time.Minute, del); err != nil {
			return err
		}
		_, err = Run(ctx, g.hub, "sudo -n tc qdisc add dev "+dev+" root netem loss 30% delay 300ms reorder 25% 50%", "")
		return noSudo(g.hub, err)
	}) != nil {
		if cancel != nil {
			cancel()
		}
		return
	}
	lastWins(ctx, r, g, prefix, 20, 500*time.Millisecond, 6*timeout)
	r.Do(prefix+"remove", func() error {
		_, err := Run(context.WithoutCancel(ctx), g.hub, "sudo -n "+del, "")
		cancel()
		return err
	})
	lastWins(ctx, r, g, prefix+"after/", 2, time.Second, timeout)
}

// portBlocked (E8): a member's port is closed both ways for a minute while
// the others copy; once it opens, the member ends on the last copy.
func portBlocked(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const prefix = "faults/E8-port/"
	d := linuxMember(g)
	if d == nil || len(g.members) < 2 {
		r.Skip(prefix, "needs a Linux member and another member")
		return
	}
	var open func() error
	if r.Do(prefix+d.Name+"/block", func() error {
		var err error
		open, err = blockPort(ctx, d)
		return err
	}) != nil {
		return
	}
	var others []*Device
	for _, m := range g.members {
		if m != d {
			others = append(others, m)
		}
	}
	var last string
	for i := 1; i <= 3; i++ {
		from := others[i%len(others)]
		last = fmt.Sprintf("cbb-bench %s E8 while %s is cut off %d", g.run, d.Name, i)
		r.Do(fmt.Sprintf("%scopy/%d", prefix, i), func() error { return Copy(ctx, from, last) })
		time.Sleep(15 * time.Second)
	}
	r.Do(prefix+d.Name+"/kept-out", func() error { return staysAway(ctx, d, last) })
	r.Do(prefix+d.Name+"/open", open)
	// The member's dials back off up to a minute after failures.
	r.Do(prefix+d.Name+"/catches-up", func() error { return arrives(ctx, d, last, 90*time.Second) })
}

// blockPort closes a Linux member's port both ways, with a timer on the
// device that opens it again within five minutes; open opens it at once.
func blockPort(ctx context.Context, d *Device) (open func() error, err error) {
	rules := []string{"INPUT -p tcp --dport 8764 -j DROP", "OUTPUT -p tcp --dport 8764 -j DROP"}
	var undo, block []string
	for _, rule := range rules {
		block = append(block, "iptables -I "+rule)
		undo = append(undo, "iptables -D "+rule+" 2>/dev/null")
	}
	undoAll := strings.Join(undo, "; ") + "; true"
	cancel, err := revertAfter(ctx, d, "cbbbench-port", 5*time.Minute, undoAll)
	if err != nil {
		return nil, err
	}
	if _, err := Run(ctx, d, "sudo -n sh -c "+shellQuote(strings.Join(block, " && ")), ""); err != nil {
		cancel()
		return nil, noSudo(d, err)
	}
	done := false
	return func() error {
		if done {
			return nil
		}
		done = true
		_, err := Run(context.WithoutCancel(ctx), d, "sudo -n sh -c "+shellQuote(undoAll), "")
		cancel()
		return err
	}, nil
}

// hungService (E11, U6): the hub's service stops answering but keeps its
// sockets (SIGSTOP); cbb there must fail within its time with a clear
// message, not hang, and the service catches up once it runs again.
func hungService(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const prefix = "faults/E11-hung/"
	d := linuxMember(g)
	if d == nil {
		r.Skip(prefix, "needs a Linux member")
		return
	}
	cont := "systemctl kill -s CONT cbb"
	cancel, err := revertAfter(ctx, d, "cbbbench-cont", 3*time.Minute, cont)
	if r.Do(prefix+d.Name+"/stop", func() error {
		if err != nil {
			return err
		}
		_, err := Run(ctx, d, "sudo -n systemctl kill -s STOP cbb", "")
		return noSudo(d, err)
	}) != nil {
		if cancel != nil {
			cancel()
		}
		return
	}
	r.Do(prefix+d.Name+"/status-answers", func() error {
		start := time.Now()
		_, err := RunFor(ctx, d, cbbCmd(d)+" status", "", time.Minute)
		took := time.Since(start)
		var re *RunError
		switch {
		case err == nil:
			return errors.New("cbb status answered for a stopped service")
		case took > 20*time.Second:
			return fmt.Errorf("cbb status waited %v for a service that does not answer; it should give up within seconds and say so", took.Round(time.Second))
		case errors.As(err, &re):
			return checkMessage(re.Output, errorCase{want: []string{"not answer", "not respond", "timed out", "time"}}, "0")
		}
		return err
	})
	if len(g.members) > 2 {
		var others []*Device
		for _, m := range g.members {
			if m != d {
				others = append(others, m)
			}
		}
		text := fmt.Sprintf("cbb-bench %s E11 while %s hangs", g.run, d.Name)
		if r.Do(prefix+"others/copy", func() error { return Copy(ctx, others[0], text) }) == nil {
			spread(ctx, r, prefix+"others/", others, others[0], text, timeout)
		}
	}
	text := fmt.Sprintf("cbb-bench %s E11 after %s hung", g.run, d.Name)
	r.Do(prefix+d.Name+"/cont", func() error {
		_, err := Run(context.WithoutCancel(ctx), d, "sudo -n "+cont, "")
		cancel()
		return err
	})
	from := g.hub
	if from == d {
		from = g.members[len(g.members)-1]
	}
	if from != d && r.Do(prefix+"copy", func() error { return Copy(ctx, from, text) }) == nil {
		r.Do(prefix+d.Name+"/catches-up", func() error { return arrives(ctx, d, seen(text, from, d), 2*timeout) })
	}
}

// stopCmd and startCmd stop and start the device's service, or are "" where
// the bench may not.
func stopCmd(d *Device) (stop, start string) {
	switch d.OS {
	case "linux", "linux-lite":
		return "sudo -n systemctl stop cbb", "sudo -n systemctl start cbb"
	case "windows":
		return "Stop-Service cbb", "Start-Service cbb"
	case "docker":
		return "docker stop " + d.Container, "docker start " + d.Container
	case "netns":
		return "sudo -n systemctl stop " + netnsUnit(d), "sudo -n systemctl start " + netnsUnit(d)
	}
	return "", ""
}

// stoppedService (U5): with a member's service stopped, cbb there says the
// service is not running and how to start it, with the cause only in debug
// mode (R6); it comes back in the group and syncs once started.
func stoppedService(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const prefix = "faults/U5-stopped/"
	for _, d := range g.members {
		if d.OS == "docker" {
			// cbb runs inside the container: with it stopped there is no
			// cbb to ask.
			continue
		}
		stop, start := stopCmd(d)
		if stop == "" {
			r.Skip(prefix+d.Name, "the bench cannot stop this device's service without the owner's password")
			continue
		}
		p := prefix + d.Name + "/"
		if r.Do(p+"stop", func() error {
			_, err := Run(ctx, d, stop, "")
			return noSudo(d, err)
		}) != nil {
			continue
		}
		want := []string{"not running", "is not answering", "service"}
		for _, c := range []struct{ name, cmd, stdin string }{
			{"status", cbbCmd(d) + " status", ""},
			{"copy", cbbCmd(d) + " copy", "cbb-bench " + g.run + " U5"},
			{"paste", cbbCmd(d) + " paste", ""},
		} {
			r.Do(p+c.name, func() error { return errorShown(ctx, d, errorCase{cmd: c.cmd, stdin: c.stdin, want: want}) })
		}
		r.Do(p+"start", func() error {
			_, err := Run(context.WithoutCancel(ctx), d, start, "")
			return err
		})
		if r.Do(p+"back", func() error {
			return eventually(ctx, 30*time.Second, func() error {
				tag, err := groupOf(ctx, d)
				if err == nil && tag != g.tag {
					err = fmt.Errorf("%s came back in group %q, not %s", d.Name, tag, g.tag)
				}
				return err
			})
		}) == nil {
			from := g.hub
			if from == d {
				from = g.members[len(g.members)-1]
			}
			text := fmt.Sprintf("cbb-bench %s U5 after %s started", g.run, d.Name)
			if r.Do(p+"copy-after", func() error { return Copy(ctx, from, text) }) == nil {
				r.Do(p+"sync", func() error { return arrives(ctx, d, seen(text, from, d), 2*timeout) })
			}
		}
	}
}

// damagedState (U7): a member's group file is cut short while its
// service is stopped. The service starts, refuses to work on the damaged
// file, and says which file and what to do, with the cause in debug mode;
// with the file restored the device is in the group again and syncs.
func damagedState(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const prefix = "faults/U7-damaged/"
	d := linuxMember(g)
	if d == nil {
		r.Skip(prefix, "needs a Linux member")
		return
	}
	const file = "/var/lib/cbb/identity.json"
	const keep = file + ".cbbbench"
	restore := "systemctl stop cbb; if [ -f " + keep + " ]; then mv -f " + keep + " " + file + "; fi; systemctl start cbb"
	cancel, err := revertAfter(ctx, d, "cbbbench-state", 5*time.Minute, restore)
	p := prefix + d.Name + "/"
	if r.Do(p+"damage", func() error {
		if err != nil {
			return err
		}
		_, err := Run(ctx, d, "sudo -n sh -c "+shellQuote("systemctl stop cbb && cp -p "+file+" "+keep+" && truncate -s 40 "+file+" && systemctl start cbb"), "")
		return noSudo(d, err)
	}) != nil {
		if cancel != nil {
			cancel()
			Run(context.WithoutCancel(ctx), d, "sudo -n sh -c "+shellQuote(restore), "")
		}
		return
	}
	r.Do(p+"says", func() error {
		return eventually(ctx, 20*time.Second, func() error {
			return errorShown(ctx, d, errorCase{cmd: cbbCmd(d) + " status", want: []string{"identity.json"}, detail: true})
		})
	})
	r.Do(p+"copy-refused", func() error {
		return errorShown(ctx, d, errorCase{cmd: cbbCmd(d) + " copy", stdin: "cbb-bench " + g.run + " U7", want: []string{"identity.json", "damaged"}, detail: true})
	})
	r.Do(p+"restore", func() error {
		_, err := Run(context.WithoutCancel(ctx), d, "sudo -n sh -c "+shellQuote(restore), "")
		cancel()
		return err
	})
	if r.Do(p+"back", func() error {
		return eventually(ctx, 30*time.Second, func() error {
			tag, err := groupOf(ctx, d)
			if err == nil && tag != g.tag {
				err = fmt.Errorf("%s came back in group %q, not %s", d.Name, tag, g.tag)
			}
			return err
		})
	}) == nil {
		from := g.hub
		if from == d {
			from = g.members[len(g.members)-1]
		}
		text := fmt.Sprintf("cbb-bench %s U7 after the restore", g.run)
		if r.Do(p+"copy-after", func() error { return Copy(ctx, from, text) }) == nil {
			r.Do(p+"sync", func() error { return arrives(ctx, d, seen(text, from, d), 2*timeout) })
		}
	}
}
