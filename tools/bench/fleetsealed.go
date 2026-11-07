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

// memHas reports whether the memory of d's service holds text, through
// forge memscan (forge/memscan.go); forgeOn must have put forge on d.
func memHas(ctx context.Context, d *Device, text string) (bool, error) {
	out, err := docker(ctx, "exec", "--privileged", d.Container, "/usr/local/bin/cbbbench-forge", "memscan", text)
	switch {
	case err != nil:
		return false, fmt.Errorf("memscan on %s: %v: %s", d.Name, err, strings.TrimSpace(out))
	case strings.Contains(out, "memscan: none"):
		return false, nil
	case strings.Contains(out, "memscan: found"):
		return true, nil
	}
	return false, fmt.Errorf("memscan on %s printed %q", d.Name, strings.TrimSpace(out))
}

// readsNone checks that neither the memory of d's service nor its state
// directory holds text.
func readsNone(ctx context.Context, d *Device, text, what string) error {
	has, err := memHas(ctx, d, text)
	if err != nil {
		return err
	}
	if has {
		return fmt.Errorf("the memory of %s holds %s in the clear", d.Name, what)
	}
	if out, err := Run(ctx, d, "grep -rlF -- "+shellQuote(text)+" /var/lib/cbb; true", ""); err != nil {
		return err
	} else if out = strings.TrimSpace(out); out != "" {
		return fmt.Errorf("%s keeps %s in the clear in %s", d.Name, what, out)
	}
	return nil
}

// readsIt checks that the memory of d's service holds text: the check
// that memscan sees what a reader holds, before trusting its "none".
func readsIt(ctx context.Context, d *Device, text string) error {
	return eventually(ctx, 30*time.Second, func() error {
		has, err := memHas(ctx, d, text)
		if err == nil && !has {
			err = fmt.Errorf("memscan does not find on %s the text it pastes", d.Name)
		}
		return err
	})
}

// forwardOnlyHub (S25, S26, W43): a computer that is no admin is made a
// hub that only passes the copies on (cbb global hub -on DEVICE
// -forward-only); the devices list says so; the root stops being a hub
// and the client away moves to it; copies and a file pass both ways
// through it, sealed, and neither its memory nor its disk ever holds them
// in the clear, while a member that reads them does; a paste command to
// the client passes through it sealed; it takes no paste itself.
func forwardOnlyHub(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/S25-forward-only/"
	a := newAwayGroup(ctx, r, f, "fleet/S25-forward-only", 3)
	if a == nil || len(a.members) < 3 {
		return
	}
	root, hub, home := a.hub, a.members[1], a.members[2]
	c := a.join(ctx, r, p+"invited")
	if c == nil {
		return
	}
	wait := 3 * time.Minute
	var hubID, cID string
	if r.Do(p+"setup", func() error {
		var err error
		if hubID, err = deviceOf(ctx, hub); err != nil {
			return err
		}
		if cID, err = deviceOf(ctx, c); err != nil {
			return err
		}
		for _, d := range []*Device{hub, home} {
			if _, err := forgeOn(ctx, d); err != nil {
				return err
			}
		}
		// Only the computer's own user turns sync away from home on.
		if _, err := Run(ctx, hub, "cbb global on", "yes\n"); err != nil {
			return err
		}
		if err := a.in.publish(ctx, hubPublic2, hub); err != nil {
			return err
		}
		return connected(ctx, c, wait)
	}) != nil {
		return
	}
	if r.Do("fleet/W43-forward-only-hub", func() error {
		cmd := "cbb global hub -on " + hubID + " -forward-only -forwarder " + fwdPublic + ":8764 -forwarder-key " + a.fwdKey + " " + hubPublic2 + ":8764"
		if err := succeeds(ctx, root, cmd, "", "passes the copies on, sealed, and reads none"); err != nil {
			return err
		}
		if err := globalShows(ctx, hub, "this device is the hub", wait); err != nil {
			return err
		}
		if err := listsAs(ctx, []*Device{root, home, hub}, hub.Name, "hub that only passes copies on", false, timeout); err != nil {
			return err
		}
		// The root stops being a hub; its client goes to the next one.
		if err := succeeds(ctx, root, "cbb global hub off", "", "no hub of the group any more"); err != nil {
			return err
		}
		if err := globalShows(ctx, c, "connected to the hub "+hubID, wait); err != nil {
			return err
		}
		// The client takes the new hub's own offers too, as it will its
		// next key's.
		out, err := docker(ctx, "logs", c.Container)
		if err != nil {
			return err
		}
		if strings.Contains(out, "can be its hub; the offer is ignored") {
			return fmt.Errorf("%s ignored an offer of the hub: %s", c.Name, firstLine(out[strings.Index(out, "a tunnel offer"):]))
		}
		return nil
	}) != nil {
		return
	}
	r.Do("fleet/S25-text", func() error {
		text := "cbb-bench " + a.run + " sealed through the hub"
		if err := Copy(ctx, c, text); err != nil {
			return err
		}
		if err := arrives(ctx, home, text, 2*timeout); err != nil {
			return err
		}
		if err := readsIt(ctx, home, text); err != nil {
			return err
		}
		if err := readsNone(ctx, hub, text, "the copy"); err != nil {
			return err
		}
		back := "cbb-bench " + a.run + " sealed back"
		if err := Copy(ctx, home, back); err != nil {
			return err
		}
		if err := arrives(ctx, c, back, 2*timeout); err != nil {
			return err
		}
		return readsNone(ctx, hub, back, "the copy sent back")
	})
	r.Do("fleet/S25-file", func() error {
		// A file whose every line is the marker, sent as a sealed blob in
		// 64 KiB segments, arrives whole and is never clear on the hub.
		marker := "cbb-bench-" + a.run + "-sealed-file"
		mk := "rm -rf /tmp/s && mkdir /tmp/s && for i in $(seq 1 20000); do echo " + marker + "; done >/tmp/s/sealed.txt && sha256sum </tmp/s/sealed.txt"
		want, err := RunFor(ctx, c, mk, "", time.Minute)
		if err != nil {
			return err
		}
		if _, err := RunFor(ctx, c, "cbb copy /tmp/s/sealed.txt", "", time.Minute); err != nil {
			return err
		}
		if err := eventually(ctx, wait, func() error {
			if err := pasteInto(ctx, home, "/tmp/o", time.Minute); err != nil {
				return err
			}
			got, err := Run(ctx, home, "sha256sum </tmp/o/sealed.txt", "")
			if err == nil && got != want {
				err = fmt.Errorf("%s saved another file than %s sent", home.Name, c.Name)
			}
			return err
		}); err != nil {
			return err
		}
		return readsNone(ctx, hub, marker, "the file")
	})
	r.Do("fleet/S26-sealed-paste", func() error {
		// The client has remote paste off, so its refusal comes back
		// through the hub: the command reached it, sealed on the way.
		text := "cbb-bench-" + a.run + "-sealed-paste"
		out, err := Run(ctx, root, "cbb paste -on "+cID, text)
		var re *RunError
		switch {
		case errors.As(err, &re):
			out = re.Output
		case err != nil:
			return err
		}
		if !strings.Contains(out, "remote paste is off on this device") {
			return fmt.Errorf("the paste through the hub got %q, not the client's refusal", strings.TrimSpace(out))
		}
		return readsNone(ctx, hub, text, "the paste command's text")
	})
	r.Do("fleet/S25-takes-no-paste", func() error {
		out, err := Run(ctx, root, "cbb paste -on "+hubID, "cbb-bench "+a.run)
		var re *RunError
		if !errors.As(err, &re) {
			return fmt.Errorf("a paste on the hub that only passes copies on was not refused: %q, %v", strings.TrimSpace(out), err)
		}
		if !strings.Contains(re.Output, "only passes the copies on") {
			return fmt.Errorf("refused with %q, not because it only passes the copies on", strings.TrimSpace(re.Output))
		}
		return nil
	})
}

// joinedLater (Y36): a device that joins reads copies from the next one on:
// the copy made before it joined is sealed to the devices then in the group,
// so it never has its text, while the next copy reaches it.
func joinedLater(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/Y36-joined-later/"
	g := fleetGroup(ctx, r, f, "fleet/Y36-joined-later", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	a, b := g.members[0], g.members[1]
	before := "cbb-bench " + g.run + " before it joined"
	if r.Do(p+"before", func() error { return syncs(ctx, g, a, b, "before it joined", timeout) }) != nil {
		return
	}
	var d *Device
	if r.Do(p+"join", func() error {
		var err error
		if d, err = f.Add(ctx); err != nil {
			return err
		}
		if _, err := pairOne(ctx, a, d); err != nil {
			return err
		}
		g.members = append(g.members, d)
		if err := shareClipboard(ctx, d); err != nil {
			return err
		}
		if _, err := forgeOn(ctx, d); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{d}, a.Name, "online", false, timeout)
	}) != nil {
		return
	}
	r.Do("fleet/Y36-joined-later", func() error {
		// The hellos have passed the copy's mark by now.
		time.Sleep(15 * time.Second)
		got, err := Paste(ctx, d)
		if err != nil {
			return err
		}
		if strings.TrimRight(got, "\r\n") == before {
			return fmt.Errorf("%s has the copy made before it joined", d.Name)
		}
		if err := readsNone(ctx, d, before, "the copy made before it joined"); err != nil {
			return err
		}
		next := "cbb-bench " + g.run + " after it joined"
		if err := Copy(ctx, a, next); err != nil {
			return err
		}
		if err := arrives(ctx, d, next, timeout); err != nil {
			return err
		}
		return readsIt(ctx, d, next)
	})
}
