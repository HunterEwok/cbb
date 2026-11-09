// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var joinQRRE = regexp.MustCompile(`(cbb://join\?\S+)`)

// listens reports whether something on d's network takes a TCP connection
// to addr.
func listens(ctx context.Context, from *Device, addr string) bool {
	host, port, _ := strings.Cut(addr, ":")
	_, err := Run(ctx, from, fmt.Sprintf("timeout 3 bash -c '</dev/tcp/%s/%s'", host, port), "")
	return err == nil
}

// joinerListens (G17): a computer in no group runs cbb pair and listens
// for the phone that scans its QR code: nothing listens before, the code is
// good only against the certificate the QR code names, a wrong code does
// not spend it, the right one admits the computer, and the listener goes
// with the join or when cbb pair is stopped. The forge has the root's
// service admit it, as the phone that scanned the code would.
func joinerListens(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G17-joiner-listens/"
	g := fleetGroup(ctx, r, f, "fleet/G17-listen", 1)
	if g == nil || len(g.members) != 1 {
		return
	}
	hub := g.hub
	var joiner, other *Device
	var addr string
	if r.Do(p+"quiet", func() error {
		var err error
		if joiner, err = f.Add(ctx); err != nil {
			return err
		}
		if other, err = f.Add(ctx); err != nil {
			return err
		}
		if _, err := forgeOn(ctx, hub); err != nil {
			return err
		}
		ip, err := fleetIP(ctx, joiner)
		if err != nil {
			return err
		}
		addr = ip + ":8764"
		if listens(ctx, hub, addr) {
			return fmt.Errorf("%s in no group takes connections on %s before cbb pair", joiner.Name, addr)
		}
		return nil
	}) != nil {
		return
	}
	// pairOn runs cbb pair on d until it ends and hands its QR code over.
	pairOn := func(d *Device) (qr string, done chan error, err error) {
		got := make(chan string, 1)
		done = make(chan error, 1)
		go func() {
			done <- Stream(ctx, d, "timeout 300 cbb pair", func(line string) {
				if m := joinQRRE.FindStringSubmatch(line); m != nil {
					select {
					case got <- m[1]:
					default:
					}
				}
			})
		}()
		select {
		case qr = <-got:
			return qr, done, nil
		case err = <-done:
			return "", nil, fmt.Errorf("cbb pair ended without a QR code: %v", err)
		case <-time.After(30 * time.Second):
			return "", nil, errors.New("cbb pair showed no QR code in 30 s")
		}
	}
	scan := func(how, qr string) (string, error) {
		out, err := RunFor(ctx, hub, fmt.Sprintf("cbbbench-forge %s", shellQuote("qr:"+how+":"+qr)), "", 2*time.Minute)
		fmt.Fprintf(r.out, "%s\n", strings.TrimSpace(out))
		return out, err
	}
	var qr string
	var done chan error
	if r.Do(p+"listening", func() error {
		var err error
		if qr, done, err = pairOn(joiner); err != nil {
			return err
		}
		if !strings.Contains(qr, "addr="+strings.ReplaceAll(addr, ":", "%3A")) {
			return fmt.Errorf("the QR code %q does not name %s", qr, addr)
		}
		return eventually(ctx, 10*time.Second, func() error {
			if !listens(ctx, hub, addr) {
				return fmt.Errorf("%s does not listen on %s during cbb pair", joiner.Name, addr)
			}
			return nil
		})
	}) != nil {
		return
	}
	for _, how := range []string{"fp", "code"} {
		r.Do(p+"wrong-"+how, func() error {
			out, err := scan(how, qr)
			if err != nil {
				return err
			}
			if !strings.Contains(out, "qr "+how+": refused") {
				return fmt.Errorf("a phone with the wrong %s: %s", how, out)
			}
			select {
			case err := <-done:
				return fmt.Errorf("cbb pair ended after a wrong %s: %v", how, err)
			default:
			}
			return nil
		})
	}
	r.Do(p+"joined", func() error {
		out, err := scan("right", qr)
		if err != nil {
			return err
		}
		if !strings.Contains(out, "qr right: joined") {
			return fmt.Errorf("the phone with the QR code: %s", out)
		}
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			return errors.New("cbb pair did not end after the join")
		}
		want, err := groupOf(ctx, hub)
		if err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			got, err := groupOf(ctx, joiner)
			if err == nil && got != want {
				err = fmt.Errorf("%s is in the group %q, not %q", joiner.Name, got, want)
			}
			return err
		})
	})
	r.Do(p+"used", func() error {
		// The member port takes no pairing: the same QR code again fails.
		out, err := scan("right", qr)
		if err != nil {
			return err
		}
		if !strings.Contains(out, "qr right: refused") {
			return fmt.Errorf("the QR code worked twice: %s", out)
		}
		return nil
	})
	r.Do(p+"stopped", func() error {
		ip, err := fleetIP(ctx, other)
		if err != nil {
			return err
		}
		oaddr := ip + ":8764"
		if _, _, err := pairOn(other); err != nil {
			return err
		}
		if err := eventually(ctx, 10*time.Second, func() error {
			if !listens(ctx, hub, oaddr) {
				return fmt.Errorf("%s does not listen during cbb pair", other.Name)
			}
			return nil
		}); err != nil {
			return err
		}
		if _, err := Run(ctx, other, "pkill -INT -f '^cbb pair' || true", ""); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			if listens(ctx, hub, oaddr) {
				return fmt.Errorf("%s still listens on %s after cbb pair stopped", other.Name, oaddr)
			}
			return nil
		})
	})
}

// pairRelay (G8): the forge, with an insider's member certificate, sits
// between a joiner and the root's pairing window and passes every frame
// between the two TLS sessions; CPace's channel binding fails the join,
// which costs the window one guess, and the joiner then joins directly
// with the same code.
func pairRelay(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G8-relay/"
	g := fleetGroup(ctx, r, f, "fleet/G8-relay", 2)
	if g == nil || len(g.members) != 2 {
		return
	}
	root, insider := g.hub, g.members[1]
	var h, joiner *Device
	var rootAddr, relayAddr string
	if r.Do(p+"setup", func() error {
		var err error
		if h, err = forgeHost(ctx, f, insider); err != nil {
			return err
		}
		if joiner, err = f.Add(ctx); err != nil {
			return err
		}
		ip, err := fleetIP(ctx, root)
		if err != nil {
			return err
		}
		rootAddr = ip + ":8764"
		hip, err := fleetIP(ctx, h)
		relayAddr = hip + ":8764"
		return err
	}) != nil {
		return
	}
	code, stop, err := openWindow(ctx, root)
	if r.Do(p+"window", func() error { return err }) != nil {
		return
	}
	defer stop()
	r.Do(p+"refused", func() error {
		ready := make(chan struct{}, 1)
		done := make(chan error, 1)
		var lines []string
		go func() {
			done <- Stream(ctx, h, fmt.Sprintf("cbbbench-forge -state /tmp/%s -addr :8764 relay:%s", insider.Name, rootAddr), func(line string) {
				lines = append(lines, line)
				if strings.Contains(line, "relay: listening") {
					ready <- struct{}{}
				}
			})
		}()
		select {
		case <-ready:
		case err := <-done:
			return fmt.Errorf("the relay ended: %v %v", err, lines)
		case <-time.After(30 * time.Second):
			return errors.New("the relay did not listen")
		}
		out, err := RunFor(ctx, joiner, "cbb pair -code "+relayAddr, code+"\n", time.Minute)
		if err == nil {
			return fmt.Errorf("%s joined through the relay: %s", joiner.Name, out)
		}
		var rerr error
		select {
		case rerr = <-done:
		case <-time.After(time.Minute):
			return errors.New("the relay did not end")
		}
		fmt.Fprintf(r.out, "%s\n", strings.Join(lines, "\n"))
		if rerr != nil {
			return fmt.Errorf("the relay: %v", rerr)
		}
		if tag, err := groupOf(ctx, joiner); err != nil || tag != "" {
			return fmt.Errorf("%s is in the group %q after the relay (%v)", joiner.Name, tag, err)
		}
		return nil
	})
	r.Do(p+"one-guess", func() error {
		// The window is still open with the same code.
		if _, err := RunFor(ctx, joiner, "cbb pair -code "+rootAddr, code+"\n", time.Minute); err != nil {
			return fmt.Errorf("joining directly after the relay: %w", err)
		}
		want, err := groupOf(ctx, root)
		if err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			got, err := groupOf(ctx, joiner)
			if err == nil && got != want {
				err = fmt.Errorf("%s is in %q, not %q", joiner.Name, got, want)
			}
			return err
		})
	})
}
