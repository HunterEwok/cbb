// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// openWindow runs cbb pair on hub until stop, and returns the code it
// shows.
func openWindow(ctx context.Context, hub *Device) (code string, stop func(), err error) {
	ctx, cancel := context.WithCancel(ctx)
	got := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		var c string
		done <- Stream(ctx, hub, "cbb pair", func(line string) {
			if m := codeRE.FindStringSubmatch(line); m != nil {
				c = m[1] + m[2]
			}
			if strings.HasPrefix(line, "Waiting up to") && c != "" {
				select {
				case got <- c:
				default:
				}
			}
		})
	}()
	stop = func() {
		cancel()
		// docker exec leaves the command running when its client goes.
		Run(context.WithoutCancel(ctx), hub, "pkill -f 'cbb pair' || true", "")
	}
	select {
	case code = <-got:
		return code, stop, nil
	case err = <-done:
		stop()
		if err == nil {
			err = errors.New("cbb pair ended without a code")
		}
		return "", nil, err
	case <-time.After(30 * time.Second):
		stop()
		return "", nil, errors.New("cbb pair showed no code in 30 s")
	}
}

// twoWindows (G7): with two windows announced at once, the joiner asks for
// the address that cbb pair showed, and joins with it.
func twoWindows(ctx context.Context, r *Report, f *Fleet) {
	const p = "fleet/G7-two-windows/"
	var hubs [2]*Device
	var joiner *Device
	if r.Do(p+"groups", func() error {
		for i := range hubs {
			var err error
			if hubs[i], err = f.Add(ctx); err != nil {
				return err
			}
			if _, err := Run(ctx, hubs[i], "cbb new", ""); err != nil {
				return err
			}
		}
		var err error
		joiner, err = f.Add(ctx)
		return err
	}) != nil {
		return
	}
	var codes [2]string
	for i, h := range hubs {
		code, stop, err := openWindow(ctx, h)
		if r.Do(fmt.Sprintf("%swindow-%d", p, i+1), func() error { return err }) != nil {
			return
		}
		defer stop()
		codes[i] = code
	}
	r.Do(p+"asks-for-address", func() error {
		// The user reads the code and types it: the windows have been
		// announced for a moment, past the second an mDNS record waits
		// before it is sent again.
		time.Sleep(3 * time.Second)
		return errorShown(ctx, joiner, errorCase{cmd: "cbb pair -code", stdin: codes[0] + "\n",
			want: []string{"2 devices announce a pairing window"}})
	})
	r.Do(p+"joins-by-address", func() error {
		ip, err := fleetIP(ctx, hubs[1])
		if err != nil {
			return err
		}
		if _, err := Run(ctx, joiner, "cbb pair -code "+net.JoinHostPort(ip, "8764"), codes[1]+"\n"); err != nil {
			return err
		}
		want, err := groupOf(ctx, hubs[1])
		if err != nil {
			return err
		}
		if got, _ := groupOf(ctx, joiner); got != want {
			return fmt.Errorf("the joiner is in group %q, not %q", got, want)
		}
		return nil
	})
}

// memberConns are d's member connections with peer: those it dialled
// and those it took.
func memberConns(ctx context.Context, d, peer *Device) (dialled, taken int, err error) {
	ip, err := fleetIP(ctx, peer)
	if err != nil {
		return 0, 0, err
	}
	out, err := Run(ctx, d, "ss -tnH state established dst "+ip, "")
	if err != nil {
		return 0, 0, err
	}
	for _, l := range strings.Split(out, "\n") {
		fs := strings.Fields(l)
		if len(fs) < 4 {
			continue
		}
		switch {
		case strings.HasSuffix(fs[3], ":8764"):
			dialled++
		case strings.HasSuffix(fs[2], ":8764"):
			taken++
		}
	}
	return dialled, taken, nil
}

// whoDials (D2): of two full members the one with the lower device ID
// dials; when that is blocked, the other dials after 30 s; one connection
// joins them either way.
func whoDials(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D2-who-dials/"
	g := fleetGroup(ctx, r, f, "fleet/D2-who-dials", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	lo, hi := g.members[0], g.members[1]
	if r.Do(p+"ids", func() error {
		a, err := deviceOf(ctx, lo)
		if err != nil {
			return err
		}
		b, err := deviceOf(ctx, hi)
		if err == nil && b < a {
			lo, hi = hi, lo
		}
		return err
	}) != nil {
		return
	}
	// one waits until the dialer holds the only connection between them.
	one := func(dialer, other *Device, within time.Duration) error {
		return eventually(ctx, within, func() error {
			d, t, err := memberConns(ctx, dialer, other)
			if err == nil && (d != 1 || t != 0) {
				err = fmt.Errorf("%s dialled %d and took %d connections from %s, not dialled one", dialer.Name, d, t, other.Name)
			}
			return err
		})
	}
	r.Do(p+"lower-dials", func() error { return one(lo, hi, timeout) })
	r.Do(p+"other-after-30s", func() error {
		ip, err := fleetIP(ctx, hi)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, lo, "iptables -I OUTPUT -p tcp --syn -d "+ip+" --dport 8764 -j DROP && "+fleetKill, ""); err != nil {
			return err
		}
		defer heal(ctx, lo)
		start := time.Now()
		if err := one(hi, lo, 30*time.Second+2*timeout); err != nil {
			return err
		}
		if took := time.Since(start); took < 20*time.Second {
			return fmt.Errorf("%s dialled after %v, before the 30 s it leaves the lower ID", hi.Name, took.Round(time.Second))
		}
		return syncs(ctx, g, lo, hi, "the higher ID dialled", timeout)
	})
}

// knownNetworks (D6): on a network where it has not met its group a member
// keeps quiet and says so; it learns the network from cbb network or from
// a member connection there.
func knownNetworks(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D6-networks/"
	g := fleetGroup(ctx, r, f, "fleet/D6-networks", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	a, b, c := g.members[0], g.members[1], g.members[2]
	var n string
	if r.Do(p+"new-network", func() error {
		var err error
		if n, err = f.Network(ctx); err != nil {
			return err
		}
		for _, d := range []*Device{a, b} {
			if _, err := docker(ctx, "network", "connect", n, d.Container); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	quiet := func(d *Device, want bool) error {
		return eventually(ctx, timeout, func() error {
			out, err := Run(ctx, d, "cbb status", "")
			if err == nil && strings.Contains(out, "Quiet on ") != want {
				err = fmt.Errorf("%s: quiet on a network %v, want %v: %q", d.Name, !want, want, out)
			}
			return err
		})
	}
	r.Do(p+"quiet-shown", func() error {
		if err := quiet(a, true); err != nil {
			return err
		}
		return quiet(b, true)
	})
	// Apart on the old network and with c gone, a and b have only the new
	// one, where both keep quiet.
	if r.Do(p+"apart", func() error {
		if err := cut(ctx, a, b); err != nil {
			return err
		}
		if _, err := docker(ctx, "pause", c.Container); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " on a quiet network"
		if err := Copy(ctx, a, text); err != nil {
			return err
		}
		return staysAway(ctx, b, text)
	}) != nil {
		heal(ctx, a, b)
		docker(ctx, "unpause", c.Container)
		return
	}
	r.Do(p+"cbb-network", func() error {
		if err := succeeds(ctx, b, "cbb network", "", "publishes itself"); err != nil {
			return err
		}
		if err := quiet(b, false); err != nil {
			return err
		}
		// a finds b there and connects, and so learns the network too.
		if err := syncs(ctx, g, a, b, "over the network learnt", 2*timeout); err != nil {
			return err
		}
		return quiet(a, false)
	})
	heal(ctx, a, b)
	docker(ctx, "unpause", c.Container)
}

// heartbeats (D12): a connection that goes silent is closed at 15 s, and
// a large frame over a slow link gets its time.
func heartbeats(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/D12-heartbeats/"
	g := fleetGroup(ctx, r, f, "fleet/D12-heartbeats", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	r.Do(p+"silent-closed", func() error {
		if err := listsAs(ctx, []*Device{a}, b.Name, "online", false, timeout); err != nil {
			return err
		}
		if err := cut(ctx, a, b); err != nil {
			return err
		}
		defer heal(ctx, a, b)
		start := time.Now()
		time.Sleep(4 * time.Second)
		if row, err := statusRow(ctx, a, b.Name); err != nil || !strings.Contains(row, "online") {
			return fmt.Errorf("closed within 4 s of silence: %q %v", row, err)
		}
		if err := eventually(ctx, 30*time.Second, func() error {
			row, err := statusRow(ctx, a, b.Name)
			if err == nil && strings.Contains(row, "online") {
				err = fmt.Errorf("%s still lists %s online: %q", a.Name, b.Name, row)
			}
			return err
		}); err != nil {
			return err
		}
		if took := time.Since(start); took < 12*time.Second {
			return fmt.Errorf("a silent connection was closed after %v, before 15 s", took.Round(time.Second))
		}
		return nil
	})
	r.Do(p+"slow-large-frame", func() error {
		if err := listsAs(ctx, []*Device{a}, b.Name, "online", false, 2*timeout); err != nil {
			return err
		}
		// 20 KB a second, a little above the 16 KiB a frame is given.
		if _, err := Run(ctx, a, "tc qdisc add dev eth0 root tbf rate 160kbit burst 16kb latency 2s", ""); err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), a, "tc qdisc del dev eth0 root", "")
		// Text that does not compress, near the largest the group takes.
		rnd := rand.New(rand.NewPCG(1, 2))
		var sb strings.Builder
		sb.WriteString("cbb-bench " + g.run + " large ")
		for sb.Len() < 900<<10 {
			sb.WriteByte(byte('a' + rnd.IntN(26)))
		}
		text := sb.String()
		if err := Copy(ctx, a, text); err != nil {
			return err
		}
		return arrives(ctx, b, text, 3*time.Minute)
	})
}

// noNetworkAtStart (I19): a member started with no network finds its group
// once the network comes.
func noNetworkAtStart(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/I19-no-network/"
	g := fleetGroup(ctx, r, f, "fleet/I19-no-network", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	r.Do(p+"start-without", func() error {
		if err := f.stop(ctx, b); err != nil {
			return err
		}
		if _, err := docker(ctx, "network", "disconnect", b.Network, b.Container); err != nil {
			return err
		}
		return f.start(ctx, b)
	})
	r.Do(p+"network-comes", func() error {
		if _, err := docker(ctx, "network", "connect", b.Network, b.Container); err != nil {
			return err
		}
		if err := syncs(ctx, g, a, b, "after the network came", 2*timeout); err != nil {
			return err
		}
		return syncs(ctx, g, b, a, "from the member that started alone", timeout)
	})
}

// diskFull (U8): with the state directory full, a change says why it
// failed; once there is room again, the member's state is whole.
func diskFull(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/U8-disk-full/"
	g := fleetGroup(ctx, r, f, "fleet/U8-disk-full", 1)
	if g == nil {
		return
	}
	var d *Device
	if r.Do(p+"join", func() error {
		var err error
		if d, err = f.AddWith(ctx, f.net, []string{"--tmpfs", "/var/lib/cbb:size=512k"}); err != nil {
			return err
		}
		if _, err := pairOne(ctx, g.hub, d); err != nil {
			return err
		}
		g.members = append(g.members, d)
		_, err = Run(ctx, d, "dd if=/dev/zero of=/var/lib/cbb/fill bs=1k 2>/dev/null; true", "")
		return err
	}) != nil {
		return
	}
	fails(ctx, r, p+"error-shown", d, errorCase{cmd: "cbb sync on", want: []string{"no space left on device"}})
	r.Do(p+"group-goes-on", func() error {
		if _, err := Run(ctx, g.hub, "cbb rename "+d.Name+" u8-renamed", ""); err != nil {
			return err
		}
		return syncs(ctx, g, g.hub, d, "to a full disk", timeout)
	})
	r.Do(p+"room-again", func() error {
		if _, err := Run(ctx, d, "rm /var/lib/cbb/fill && "+fleetKill, ""); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{d}, "u8-renamed", "", false, timeout); err != nil {
			return err
		}
		if err := succeeds(ctx, d, "cbb sync on", "", "Sync is on"); err != nil {
			return err
		}
		return syncs(ctx, g, d, g.hub, "after the disk had room", timeout)
	})
}

// secondInstance (U13): a second full member on the same machine, with
// its own state, socket and port, reached with CBB_SOCKET.
func secondInstance(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/U13-second-instance/"
	g := fleetGroup(ctx, r, f, "fleet/U13-second", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	host := g.members[1]
	two := *host
	two.Name += "-2"
	two.Env = []string{"CBB_SOCKET=/run/cbb2.sock"}
	if r.Do(p+"start", func() error {
		_, err := docker(ctx, "exec", "-d", "-e", "CBB_PORT=8770", host.Container, "sh", "-c",
			"mkdir -p /var/lib/cbb2 && exec cbb service -state /var/lib/cbb2 -socket /run/cbb2.sock >/tmp/cbb2.log 2>&1")
		if err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			return succeeds(ctx, &two, "cbb status", "", "Not in a group")
		})
	}) != nil {
		return
	}
	r.Do(p+"joins", func() error {
		if _, err := pairOne(ctx, g.hub, &two); err != nil {
			return err
		}
		if err := setMode(ctx, &two, "shared"); err != nil {
			return err
		}
		if err := syncs(ctx, g, g.hub, &two, "to the second instance", timeout); err != nil {
			return err
		}
		return syncs(ctx, g, &two, host, "from the second instance to the first", timeout)
	})
}
