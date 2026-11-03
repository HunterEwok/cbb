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

// tmuxPaste (T1, T2, T6, T7, T9, T10, T13, T14): remote paste into root's tmux on a fleet
// member, with the helper tmux starts from cbb's tmux.conf, and
// each refusal with its reason sent back to the admin.
func tmuxPaste(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/T2-tmux/"
	g := fleetGroup(ctx, r, f, "fleet/T2-tmux", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	admin, b, member := g.members[0], g.members[1], g.members[2]
	var id string
	if r.Do(p+"helper", func() error {
		var err error
		if id, err = deviceOf(ctx, b); err != nil {
			return err
		}
		// The line of cbb.conf that starts the helper.
		_, err = Run(ctx, b, "tmux new-session -d -s cbb -x 120 -y 30 && tmux run-shell -b 'cbb paste-helper tmux >/tmp/cbb-helper.log 2>&1 || true'", "")
		return err
	}) != nil {
		return
	}
	// paste sends text from the admin with the flags, at most one a second
	// as the receiver allows, and returns the refusal's message, "" if it
	// was pasted.
	last := time.Time{}
	paste := func(flags, text string) (string, error) {
		if wait := time.Until(last.Add(1100 * time.Millisecond)); wait > 0 {
			time.Sleep(wait)
		}
		defer func() { last = time.Now() }()
		out, err := Run(ctx, admin, "cbb paste -on "+id+" "+flags, text)
		var re *RunError
		if errors.As(err, &re) {
			return re.Output, nil
		}
		if err == nil && !strings.Contains(out, "Pasted on") {
			err = fmt.Errorf("cbb paste -on printed %q", firstLine(out))
		}
		return "", err
	}
	refused := func(flags, text, reason string) error {
		return eventually(ctx, timeout, func() error {
			msg, err := paste(flags, text)
			switch {
			case err != nil:
				return err
			case msg == "":
				return fmt.Errorf("pasted %q with %q, which should be refused: %s", text, flags, reason)
			case !strings.Contains(msg, reason):
				return fmt.Errorf("refused with %q, not %q", strings.TrimSpace(msg), reason)
			}
			return nil
		})
	}
	inPane := func(text string) error {
		return eventually(ctx, timeout, func() error {
			out, err := Run(ctx, b, "tmux capture-pane -p -J -t cbb", "")
			if err == nil && !strings.Contains(out, text) {
				err = fmt.Errorf("the pane does not show %q: %q", text, strings.TrimSpace(out))
			}
			return err
		})
	}
	text := "cbb-bench-" + g.run

	r.Do(p+"T1-off-by-default", func() error {
		return refused("", text, "remote paste is off on this device")
	})
	// Root's tmux is held to the console's rule.
	r.Do(p+"T6-console-not-allowed", func() error {
		if _, err := Run(ctx, b, "cbb paste-receive on", ""); err != nil {
			return err
		}
		return refused("", text, "did not allow consoles")
	})
	r.Do(p+"T6-no-client", func() error {
		if _, err := Run(ctx, b, "cbb paste-receive on -console", ""); err != nil {
			return err
		}
		return refused("", text, "no one is attached to tmux here")
	})
	// A client attached on a terminal of its own.
	if r.Do(p+"attach", func() error {
		_, err := docker(ctx, "exec", "-d", "-e", "TERM=xterm", b.Container, "sh", "-c", `sleep infinity | script -qfc "tmux attach -t cbb" /dev/null`)
		if err != nil {
			return err
		}
		return eventually(ctx, 10*time.Second, func() error {
			out, err := Run(ctx, b, "tmux list-clients", "")
			if err == nil && strings.TrimSpace(out) == "" {
				err = errors.New("no tmux client attached")
			}
			return err
		})
	}) != nil {
		return
	}
	r.Do(p+"paste", func() error {
		if err := eventually(ctx, timeout, func() error {
			msg, err := paste("", text+"-pasted")
			if err == nil && msg != "" {
				err = fmt.Errorf("refused: %s", strings.TrimSpace(msg))
			}
			return err
		}); err != nil {
			return err
		}
		return inPane(text + "-pasted")
	})
	r.Do(p+"type", func() error {
		msg, err := paste("-type", text+"-typed")
		if err == nil && msg != "" {
			err = fmt.Errorf("refused: %s", strings.TrimSpace(msg))
		}
		if err != nil {
			return err
		}
		return inPane(text + "-typed")
	})
	// T7: a member that is no admin cannot paste.
	r.Do(p+"T7-not-admin", func() error {
		_, err := Run(ctx, member, "cbb paste -on "+id, text+"-member")
		if err == nil {
			return errors.New("a member that is no admin pasted")
		}
		return nil
	})
	// T9: at most one paste a second from one sender.
	r.Do(p+"T9-rate", func() error {
		if _, err := paste("", text+"-first"); err != nil {
			return err
		}
		_, err := Run(ctx, admin, "cbb paste -on "+id, text+"-second")
		last = time.Now()
		var re *RunError
		switch {
		case err == nil:
			return errors.New("two pastes within a second were both taken")
		case !errors.As(err, &re):
			return err
		case !strings.Contains(re.Output, "too many pastes"):
			return fmt.Errorf("refused with %q, not too many pastes", strings.TrimSpace(re.Output))
		}
		return nil
	})
	r.Do(p+"T6-line-break", func() error {
		return refused("", "true\n"+text, "the text has a line break, which may run what comes before it")
	})
	r.Do(p+"T6-enter-not-allowed", func() error {
		return refused("-enter", text, "takes pastes without Enter only")
	})
	// With Enter allowed, a pasted command runs in the pane's shell.
	r.Do(p+"enter", func() error {
		if _, err := Run(ctx, b, "cbb paste-receive on -console -enter", ""); err != nil {
			return err
		}
		// A new line first, so that the command does not follow the
		// texts pasted before it on the shell's line.
		if _, err := Run(ctx, b, "tmux send-keys -t cbb C-u", ""); err != nil {
			return err
		}
		msg, err := paste("-enter", "echo "+text+" >/tmp/cbb-ran")
		if err == nil && msg != "" {
			err = fmt.Errorf("refused: %s", strings.TrimSpace(msg))
		}
		if err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			out, err := Run(ctx, b, "cat /tmp/cbb-ran", "")
			if err == nil && strings.TrimSpace(out) != text {
				err = fmt.Errorf("the pasted command wrote %q", out)
			}
			return err
		})
	})
	// T10: an escape sequence and bytes that are not UTF-8 never reach the
	// keys; the rest of the text does.
	r.Do(p+"T10-cleaned", func() error {
		if _, err := Run(ctx, b, "tmux send-keys -t cbb C-u", ""); err != nil {
			return err
		}
		msg, err := paste("", "t10a\x1b[201~\xffb-"+g.run)
		if err == nil && msg != "" {
			err = fmt.Errorf("refused: %s", strings.TrimSpace(msg))
		}
		if err != nil {
			return err
		}
		if err := inPane("t10ab-" + g.run); err != nil {
			return err
		}
		out, err := Run(ctx, b, "tmux capture-pane -p -J -t cbb", "")
		if err == nil && strings.Contains(out, "201~") {
			err = fmt.Errorf("the escape sequence reached the pane: %q", out)
		}
		return err
	})
	// T13: with the admin and the target apart, the paste and its result
	// go through an admin both reach.
	r.Do(p+"T13-through-a-member", func() error {
		// A command goes only through the group's hubs, the root and the
		// admins (docs/protocol.md, section 15): the member in between is
		// made one.
		if err := succeeds(ctx, admin, "cbb admin -allow-file-key "+member.Name, "", "is an admin now"); err != nil {
			return err
		}
		if err := cut(ctx, admin, b); err != nil {
			return err
		}
		defer heal(ctx, admin, b)
		if _, err := Run(ctx, b, "tmux send-keys -t cbb C-u", ""); err != nil {
			return err
		}
		if err := eventually(ctx, 2*timeout, func() error {
			msg, err := paste("", text+"-routed")
			if err == nil && msg != "" {
				err = fmt.Errorf("refused: %s", strings.TrimSpace(msg))
			}
			return err
		}); err != nil {
			return err
		}
		return inPane(text + "-routed")
	})
	// An admin turns remote paste off there from afar.
	r.Do(p+"off-from-afar", func() error {
		if _, err := Run(ctx, admin, "cbb paste-receive off -on "+id, ""); err != nil {
			return err
		}
		return refused("", text, "remote paste is off on this device")
	})
	// T14: off on every device at once; only the device's own user turns
	// it on again.
	r.Do(p+"T14-off-all", func() error {
		if _, err := Run(ctx, b, "cbb paste-receive on -console", ""); err != nil {
			return err
		}
		if _, err := Run(ctx, admin, "cbb paste-receive off -all", ""); err != nil {
			return err
		}
		if err := refused("", text, "remote paste is off on this device"); err != nil {
			return err
		}
		if err := succeeds(ctx, b, "cbb paste-receive", "", "Remote paste is off"); err != nil {
			return err
		}
		if _, err := Run(ctx, b, "cbb paste-receive on -console", ""); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			msg, err := paste("", text+"-again")
			if err == nil && msg != "" {
				err = fmt.Errorf("refused: %s", strings.TrimSpace(msg))
			}
			return err
		})
	})
}
