// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/invite"
)

// invitation is a cbb invite running on a group's hub.
type invitation struct {
	hub  *Device
	file string
	text string
	done chan error // cbb invite ended

	mu  sync.Mutex
	out strings.Builder
}

// openInvitation runs cbb invite with flags on a's hub, answering the
// devices that use it with answers, and returns once the invitation is
// written.
func openInvitation(ctx context.Context, a *awayGroup, name, flags, answers string) (*invitation, error) {
	inv := &invitation{hub: a.hub, file: "/tmp/cbbbench-invite-" + a.run + "-" + name, done: make(chan error, 1)}
	ready := make(chan struct{}, 1)
	go func() {
		inv.done <- StreamIn(ctx, a.hub, "cbb invite "+flags+" -o "+inv.file, answers, func(line string) {
			inv.mu.Lock()
			inv.out.WriteString(line + "\n")
			inv.mu.Unlock()
			if strings.Contains(line, "cbb pair -invite") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		})
	}()
	select {
	case <-ready:
	case err := <-inv.done:
		if err == nil {
			err = errors.New("cbb invite ended without an invitation")
		}
		return nil, err
	case <-time.After(time.Minute):
		return nil, errors.New("cbb invite wrote no invitation")
	}
	out, err := Run(ctx, a.hub, "cat "+inv.file, "")
	inv.text = strings.TrimSpace(out)
	return inv, err
}

// output is what cbb invite printed so far.
func (inv *invitation) output() string {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return inv.out.String()
}

// cancel stops cbb invite as Ctrl+C does.
func (inv *invitation) cancel(ctx context.Context) {
	Run(context.WithoutCancel(ctx), inv.hub, "pkill -INT -f 'cbb invite' ; true", "")
}

// ended waits until cbb invite ends and checks that it left nothing on the
// hub: its file is deleted and the hub's log says the invitation ended or
// the device joined.
func (inv *invitation) ended(ctx context.Context, timeout time.Duration) error {
	select {
	case <-inv.done:
	case <-time.After(timeout):
		return fmt.Errorf("cbb invite on %s did not end", inv.hub.Name)
	}
	if _, err := Run(ctx, inv.hub, "test ! -e "+inv.file, ""); err != nil {
		return fmt.Errorf("cbb invite left its file %s on %s", inv.file, inv.hub.Name)
	}
	return nil
}

// use joins d with the invitation's text and returns what cbb pair said.
func useInvitation(ctx context.Context, d *Device, text string) (string, error) {
	file := "/tmp/cbbbench-invitation"
	if _, err := Run(ctx, d, "umask 077 && cat > "+file, text+"\n"); err != nil {
		return "", err
	}
	defer Run(context.WithoutCancel(ctx), d, "rm -f "+file, "")
	// A hub that does not answer is tried at each of its addresses.
	return RunFor(ctx, d, "cbb pair -invite "+file, "yes\n", 3*time.Minute)
}

// refusedJoin checks that d's join with text failed with one of want and
// left d in no group.
func refusedJoin(ctx context.Context, d *Device, text string, want ...string) error {
	out, err := useInvitation(ctx, d, text)
	var re *RunError
	if err == nil {
		return fmt.Errorf("%s joined: %q", d.Name, firstLine(out))
	}
	if !errors.As(err, &re) {
		return err
	}
	if !containsAny(re.Output, want) {
		return fmt.Errorf("%s was refused with %q, which says none of %q", d.Name, lastLine(re.Output), want)
	}
	tag, err := groupOf(ctx, d)
	if err == nil && tag != "" {
		err = fmt.Errorf("%s is in group %s after a refused join", d.Name, tag)
	}
	return err
}

func containsAny(s string, want []string) bool {
	for _, w := range want {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// wrongSecret is the invitation's text with another secret: a device that
// guesses.
func wrongSecret(text string) (string, error) {
	in, err := invite.Parse(text)
	if err != nil {
		return "", err
	}
	for i := range in.Secret {
		in.Secret[i] ^= 0x5a
	}
	return in.String(), nil
}

// invitations (G13): an invitation refused in every way the catalogue
// names, each leaving nothing behind on the hub.
func invitations(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G13-invitations/"
	a := newAwayGroup(ctx, r, f, "fleet/G13-invitations", 2)
	if a == nil {
		return
	}
	joiner := func() (*Device, error) {
		d, err := f.AddOn(ctx, a.away)
		if err == nil {
			err = a.in.reach(ctx, d)
		}
		return d, err
	}
	var d *Device
	if r.Do(p+"joiner", func() (err error) {
		d, err = joiner()
		return err
	}) != nil {
		return
	}
	fails(ctx, r, "fleet/G13-more-than-a-day", a.hub, errorCase{cmd: "cbb invite -for 25h -o /tmp/never", want: []string{"up to 24h"}})
	r.Do("fleet/G13-a-day", func() error {
		inv, err := openInvitation(ctx, a, "day", "-for 24h", "")
		if err != nil {
			return err
		}
		in, err := invite.Parse(inv.text)
		inv.cancel(ctx)
		if err != nil {
			return err
		}
		if left := time.Until(in.Expires); left < 23*time.Hour || left > 24*time.Hour+time.Minute {
			return fmt.Errorf("an invitation for 24h expires in %s", left.Round(time.Minute))
		}
		return inv.ended(ctx, 20*time.Second)
	})
	r.Do("fleet/G13-default-hour", func() error {
		inv, err := openInvitation(ctx, a, "hour", "", "")
		if err != nil {
			return err
		}
		in, err := invite.Parse(inv.text)
		inv.cancel(ctx)
		if err != nil {
			return err
		}
		if left := time.Until(in.Expires); left < 59*time.Minute || left > 61*time.Minute {
			return fmt.Errorf("an invitation by default expires in %s, not an hour", left.Round(time.Minute))
		}
		return inv.ended(ctx, 20*time.Second)
	})
	r.Do("fleet/G13-answered-no", func() error {
		inv, err := openInvitation(ctx, a, "no", "", "no\n")
		if err != nil {
			return err
		}
		defer inv.cancel(ctx)
		if err := refusedJoin(ctx, d, inv.text, "did not confirm"); err != nil {
			return err
		}
		if !strings.Contains(inv.output(), "Not admitted") {
			return fmt.Errorf("cbb invite did not say it did not admit the device: %q", lastLine(inv.output()))
		}
		inv.cancel(ctx)
		return inv.ended(ctx, 20*time.Second)
	})
	r.Do("fleet/G13-cancelled", func() error {
		inv, err := openInvitation(ctx, a, "cancelled", "", "")
		if err != nil {
			return err
		}
		inv.cancel(ctx)
		if err := inv.ended(ctx, 20*time.Second); err != nil {
			return err
		}
		return refusedJoin(ctx, d, inv.text, "the hub did not answer", "closed")
	})
	r.Do("fleet/G13-expired", func() error {
		inv, err := openInvitation(ctx, a, "expired", "-for 3s", "yes\n")
		if err != nil {
			return err
		}
		defer inv.cancel(ctx)
		if err := inv.ended(ctx, 30*time.Second); err != nil {
			return err
		}
		return refusedJoin(ctx, d, inv.text, "expired")
	})
	r.Do("fleet/G13-three-failures", func() error {
		inv, err := openInvitation(ctx, a, "guesses", "", "yes\n")
		if err != nil {
			return err
		}
		defer inv.cancel(ctx)
		guess, err := wrongSecret(inv.text)
		if err != nil {
			return err
		}
		for i := range 3 {
			if err := refusedJoin(ctx, d, guess, "wrong code", "three failed attempts"); err != nil {
				return fmt.Errorf("guess %d: %w", i+1, err)
			}
		}
		// The window is closed: the right secret is refused too.
		if err := inv.ended(ctx, 30*time.Second); err != nil {
			return err
		}
		return refusedJoin(ctx, d, inv.text, "the hub did not answer", "closed", "three failed")
	})
	r.Do("fleet/G13-in-a-group", func() error {
		inv, err := openInvitation(ctx, a, "member", "", "yes\n")
		if err != nil {
			return err
		}
		defer inv.cancel(ctx)
		m := a.members[1]
		before, err := groupOf(ctx, m)
		if err != nil {
			return err
		}
		out, err := useInvitation(ctx, m, inv.text)
		if err == nil {
			return fmt.Errorf("%s, already in a group, joined with an invitation: %q", m.Name, firstLine(out))
		}
		if after, err := groupOf(ctx, m); err != nil || after != before {
			return fmt.Errorf("%s is in group %q after the refusal, not %q (%v)", m.Name, after, before, err)
		}
		return nil
	})
	r.Do("fleet/G13-used-twice", func() error {
		inv, err := openInvitation(ctx, a, "twice", "", "yes\n")
		if err != nil {
			return err
		}
		defer inv.cancel(ctx)
		first, err := joiner()
		if err != nil {
			return err
		}
		if _, err := useInvitation(ctx, first, inv.text); err != nil {
			return err
		}
		if err := inv.ended(ctx, 30*time.Second); err != nil {
			return err
		}
		return refusedJoin(ctx, d, inv.text, "pairing window is closed")
	})
	// S7: the invitation file is a secret: only its owner reads it on the
	// hub, the joiner's copy is deleted once used, the hub's once cbb invite
	// ends, and its text joins no one after.
	r.Do("fleet/S7-invitation-file", func() error {
		inv, err := openInvitation(ctx, a, "secret", "", "yes\n")
		if err != nil {
			return err
		}
		defer inv.cancel(ctx)
		if mode, err := Run(ctx, a.hub, "stat -c %a "+inv.file, ""); err != nil || strings.TrimSpace(mode) != "600" {
			return fmt.Errorf("the invitation file on %s has mode %q, not 600 (%v)", a.hub.Name, strings.TrimSpace(mode), err)
		}
		m, err := joiner()
		if err != nil {
			return err
		}
		file := "/tmp/cbbbench-secret-invitation"
		if _, err := Run(ctx, m, "umask 077 && cat > "+file, inv.text+"\n"); err != nil {
			return err
		}
		if _, err := RunFor(ctx, m, "cbb pair -invite "+file, "yes\n", 3*time.Minute); err != nil {
			return err
		}
		if left, _ := Run(ctx, m, "ls "+file+" 2>/dev/null; true", ""); strings.TrimSpace(left) != "" {
			return fmt.Errorf("%s kept the used invitation file", m.Name)
		}
		if err := inv.ended(ctx, 30*time.Second); err != nil {
			return err
		}
		return refusedJoin(ctx, d, inv.text, "pairing window is closed")
	})
	r.Do("fleet/G13-hub-off", func() error {
		inv, err := openInvitation(ctx, a, "off", "", "yes\n")
		if err != nil {
			return err
		}
		other, err := joiner()
		if err != nil {
			return err
		}
		if err := f.stop(ctx, a.hub); err != nil {
			return err
		}
		<-inv.done
		if err := refusedJoin(ctx, other, inv.text, "the hub did not answer"); err != nil {
			return err
		}
		// Back on, the hub keeps nothing of the invitation: its window
		// and guest were in memory only. The file cbb invite wrote stays
		// where a hub that lost power left it, a secret no longer good.
		if err := a.start(ctx, a.hub); err != nil {
			return err
		}
		if err := globalShows(ctx, a.hub, "Registered with the forwarder at "+fwdPublic, time.Minute); err != nil {
			return err
		}
		Run(ctx, a.hub, "rm -f "+inv.file, "")
		return refusedJoin(ctx, other, inv.text, "the hub did not answer")
	})
}
