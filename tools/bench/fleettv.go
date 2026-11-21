// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// tvOn starts the forge as a TV of kind (androidtv, roku or roku-off) in
// a container of the fleet's network and returns it with its address.
func tvOn(ctx context.Context, f *Fleet, kind string) (*Device, string, error) {
	tv, err := forgeServer(ctx, f, f.net, "-addr /tmp/tv tv:"+kind)
	if err != nil {
		return nil, "", err
	}
	ip, err := fleetIPOn(ctx, tv, f.net)
	return tv, ip, err
}

// tvSaw waits until the TV's text field holds want.
func tvSaw(ctx context.Context, tv *Device, want string, timeout time.Duration) error {
	return eventually(ctx, timeout, func() error {
		got, _ := Run(ctx, tv, "cat /tmp/tv/text 2>/dev/null; true", "")
		if got != want {
			return fmt.Errorf("the TV's text field has %q, not %q", got, want)
		}
		return nil
	})
}

// tvRemote (T17, T19): a member as the remote of TVs on the network, played
// by the forge: an Android TV paired with the code it shows and typed on
// over TLS, and a Roku over plain HTTP that needs the user's consent and
// says so when it takes no keys; remote pastes from an admin go to the TV
// the member sends them to.
func tvRemote(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/T17-tv/"
	g := fleetGroup(ctx, r, f, "fleet/T17-tv", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	root, m := g.members[0], g.members[1]
	var atv, roku *Device
	var atvIP, rokuIP, offIP string
	if r.Do(p+"tvs", func() error {
		var err error
		if atv, atvIP, err = tvOn(ctx, f, "androidtv"); err != nil {
			return err
		}
		if roku, rokuIP, err = tvOn(ctx, f, "roku"); err != nil {
			return err
		}
		_, offIP, err = tvOn(ctx, f, "roku-off")
		return err
	}) != nil {
		return
	}
	if r.Do("fleet/T17-pair", func() error {
		if err := succeeds(ctx, m, "cbb remote add -name Lounge "+atvIP, "", "shows a code"); err != nil {
			return err
		}
		var code string
		if err := eventually(ctx, 20*time.Second, func() error {
			out, err := Run(ctx, atv, "cat /tmp/tv/code", "")
			if code = strings.TrimSpace(out); err == nil && code == "" {
				err = fmt.Errorf("the TV shows no code")
			}
			return err
		}); err != nil {
			return err
		}
		return succeeds(ctx, m, "cbb remote code", code+"\n", "Lounge (Android TV) at "+atvIP)
	}) != nil {
		return
	}
	fails(ctx, r, "fleet/T17-wrong-code", m, errorCase{cmd: "cbb remote code", stdin: "000000\n", want: []string{"no TV is pairing"}})
	r.Do("fleet/T17-type", func() error {
		text := "cbb-bench " + g.run + " on the TV"
		if err := succeeds(ctx, m, "cbb remote type "+shellQuote(text), "", "Typed."); err != nil {
			return err
		}
		return tvSaw(ctx, atv, text, timeout)
	})
	r.Do("fleet/T17-paste-from-admin", func() error {
		if _, err := Run(ctx, m, "cbb paste-receive on", ""); err != nil {
			return err
		}
		if err := succeeds(ctx, m, "cbb remote pastes Lounge on", "", "remote pastes go to it"); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " pasted on the TV"
		if _, err := Run(ctx, root, "cbb paste -on "+m.Name, text); err != nil {
			return err
		}
		return tvSaw(ctx, atv, text, timeout)
	})
	// A member takes at most one paste a second from a sender.
	fails(ctx, r, "fleet/T17-paste-line-break", root, errorCase{cmd: "sleep 1.5; cbb paste -on " + m.Name, stdin: "two\nlines", want: []string{"line break", "Lounge"}})

	fails(ctx, r, "fleet/T19-roku-consent", m, errorCase{cmd: "cbb remote add -roku " + rokuIP, want: []string{"plain HTTP", "-consent"}})
	r.Do("fleet/T19-roku", func() error {
		if err := succeeds(ctx, m, "cbb remote add -roku -consent "+rokuIP, "", "Bench Roku (Roku, plain HTTP) at "+rokuIP); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " on a Roku: ü & ?"
		if err := succeeds(ctx, m, "cbb remote type -tv 'Bench Roku' "+shellQuote(text), "", "Typed."); err != nil {
			return err
		}
		return tvSaw(ctx, roku, text, timeout)
	})
	fails(ctx, r, "fleet/T19-roku-off", m, errorCase{cmd: "cbb remote add -roku -consent " + offIP, want: []string{"Control by mobile apps"}})
	fails(ctx, r, "fleet/T19-public-address", m, errorCase{cmd: "cbb remote add -roku -consent 8.8.8.8", want: []string{"home network", "local network", "private"}})
	r.Do("fleet/T17-remove", func() error {
		for _, name := range []string{"Lounge", "'Bench Roku'"} {
			if _, err := Run(ctx, m, "cbb remote remove "+name, ""); err != nil {
				return err
			}
		}
		return succeeds(ctx, m, "cbb remote", "", "the remote of no TV")
	})
}
