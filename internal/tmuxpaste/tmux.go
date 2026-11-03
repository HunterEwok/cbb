// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package tmuxpaste is the paste target in tmux (design.md, "Remote
// paste"): cbb paste-helper tmux, which tmux starts from cbb's
// tmux.conf, runs a connector with it and no clipboard. A paste goes to the
// active pane of the client the user used last, as tmux's own paste-buffer
// puts it there, bracketed when the program asked for it; typing sends the
// keys literally. With no client attached, or the client locked, it
// refuses: a detached session is not where anyone looks.
package tmuxpaste

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/HunterEwok/cbb/internal/connector"
)

// Tmux pastes into a tmux server.
type Tmux struct {
	// Args go before each tmux command, such as -L and a socket name;
	// none uses the server in $TMUX, or the default one.
	Args []string
	// Console offers the target as "console": the tmux of root, whose
	// keys may run anything, is held to the console's rule.
	Console bool
}

// buffer is the paste buffer it loads, deleted by the paste.
const buffer = "cbb-remote"

// Target names the target (connector.Target).
func (t *Tmux) Target() string {
	if t.Console {
		return "console"
	}
	return "tmux"
}

// Inject pastes text into the active pane of the client used last
// (connector.Target).
func (t *Tmux) Inject(ctx context.Context, text, method string, enter, secret bool) error {
	pane, err := t.pane(ctx)
	if err != nil {
		return err
	}
	switch method {
	case "paste":
		if err := t.run(ctx, text, "load-buffer", "-b", buffer, "-"); err != nil {
			return err
		}
		if err := t.run(ctx, "", "paste-buffer", "-p", "-d", "-b", buffer, "-t", pane); err != nil {
			t.run(ctx, "", "delete-buffer", "-b", buffer)
			return err
		}
	case "type":
		// The keys go on standard input, as tmux commands, never in the
		// arguments, which any user here can read.
		if err := t.run(ctx, typeScript(pane, text), "source-file", "-"); err != nil {
			return err
		}
	default:
		return &connector.Refusal{Reason: fmt.Sprintf("tmux pastes or types, not %q", method)}
	}
	if enter {
		return t.run(ctx, "", "send-keys", "-t", pane, "Enter")
	}
	return nil
}

// typeScript is the tmux commands that type text into pane: each line
// sent literally, and Enter for each line break.
func typeScript(pane, text string) string {
	var b strings.Builder
	for i, line := range strings.Split(text, "\n") {
		if i > 0 {
			fmt.Fprintf(&b, "send-keys -t %s Enter\n", pane)
		}
		if line != "" {
			fmt.Fprintf(&b, "send-keys -l -t %s -- %s\n", pane, quote(line))
		}
	}
	return b.String()
}

// quote quotes s for tmux's command parser: in single quotes, which take
// everything literally, with each single quote in double quotes.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// pane returns the active pane of the attached client with the latest
// activity.
func (t *Tmux) pane(ctx context.Context) (string, error) {
	out, err := t.output(ctx, "list-clients", "-F", "#{client_activity} #{client_flags} #{pane_id}")
	if err != nil {
		return "", err
	}
	var best int64 = -1
	pane, locked := "", false
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		at, _ := strconv.ParseInt(f[0], 10, 64)
		if at > best {
			best, pane = at, f[2]
			locked = strings.Contains(","+f[1]+",", ",suspended,")
		}
	}
	switch {
	case pane == "":
		return "", &connector.Refusal{Reason: "no one is attached to tmux here"}
	case locked:
		return "", &connector.Refusal{Reason: "the tmux client is locked"}
	}
	return pane, nil
}

// Alive reports whether the tmux server still runs.
func (t *Tmux) Alive(ctx context.Context) bool {
	_, err := t.output(ctx, "list-sessions", "-F", "#{session_id}")
	return err == nil
}

func (t *Tmux) cmd(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "tmux", append(append([]string(nil), t.Args...), args...)...)
	c.Env = os.Environ()
	return c
}

func (t *Tmux) output(ctx context.Context, args ...string) (string, error) {
	var stderr bytes.Buffer
	c := t.cmd(ctx, args...)
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("tmux %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func (t *Tmux) run(ctx context.Context, stdin string, args ...string) error {
	c := t.cmd(ctx, args...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("tmux %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}
