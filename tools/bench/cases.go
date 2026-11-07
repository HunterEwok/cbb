// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// quiet is how long the bench waits before it says a text did not arrive:
// on the home network a text arrives within a second or two.
const quiet = 5 * time.Second

// staysAway checks that text has not reached the device's clipboard after
// the quiet time.
func staysAway(ctx context.Context, d *Device, text string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(quiet):
	}
	got, err := Paste(ctx, d)
	if err != nil {
		return err
	}
	if strings.TrimRight(got, "\r\n") == strings.TrimRight(text, "\r\n") {
		return fmt.Errorf("%s got the text, which its sync mode should have kept away", d.Name)
	}
	return nil
}

// syncModes (P34): sync on or off on the hub decides what moves between
// its clipboard and the group; it survives a restart, and the root turns
// another device's sync off with cbb sync -on.
func syncModes(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const prefix = "full/P34-modes/"
	if len(g.members) < 2 {
		r.Skip(prefix, "needs two members")
		return
	}
	hub := g.hub
	if hub.Clipboard == "none" {
		r.Skip(prefix, "the hub has no desktop clipboard")
		return
	}
	// The other end is a member in mode shared; one with a desktop when
	// there is one, so both clipboards are real.
	other := g.members[1]
	for _, d := range g.members[1:] {
		if d.Clipboard != "none" {
			other = d
			break
		}
	}
	text := func(step string) string { return fmt.Sprintf("cbb-bench %s P34 %s", g.run, step) }
	type step struct {
		name     string
		from, to *Device
		arrives  bool
	}
	for _, m := range []struct {
		mode  string
		steps []step
	}{
		{"own", []step{{"own-out", hub, other, false}, {"own-in", other, hub, false}}},
		{"shared", []step{{"shared-out", hub, other, true}, {"shared-in", other, hub, true}}},
	} {
		if r.Do(prefix+m.mode+"/set", func() error {
			if err := setMode(ctx, hub, m.mode); err != nil {
				return err
			}
			return modeIs(ctx, hub, m.mode)
		}) != nil {
			continue
		}
		for _, s := range m.steps {
			t := text(s.name)
			if r.Do(prefix+s.name+"/copy", func() error { return Copy(ctx, s.from, t) }) != nil {
				continue
			}
			r.Do(prefix+s.name, func() error {
				if s.arrives {
					return arrives(ctx, s.to, seen(t, s.from, s.to), timeout)
				}
				return staysAway(ctx, s.to, t)
			})
		}
		if m.mode == "own" {
			// In own, cbb paste prints the group's text: the other's copy.
			r.Do(prefix+"own/paste", func() error {
				out, err := Run(ctx, hub, cbbCmd(hub)+" paste", "")
				if err == nil && strings.TrimRight(out, "\r\n") != seen(text("own-in"), other, hub) {
					err = fmt.Errorf("cbb paste on %s printed %s, not the group's text", hub.Name, describe(out))
				}
				return err
			})
		}
		if m.mode == "own" {
			r.Do(prefix+"own/restart", func() error {
				if err := restartService(ctx, hub); err != nil {
					return err
				}
				return eventually(ctx, 30*time.Second, func() error { return modeIs(ctx, hub, "own") })
			})
			r.Do(prefix+"own/listed", func() error {
				return eventually(ctx, timeout, func() error {
					row, err := statusRow(ctx, other, hub.Name)
					if err == nil && !strings.Contains(row, " off ") {
						err = fmt.Errorf("cbb status on %s does not list %s with sync off: %s", other.Name, hub.Name, row)
					}
					return err
				})
			})
		}
	}

	// Each other member with sync off: cbb paste there prints the group's
	// text, and sync the root turns off with -on shows in the member's cbb
	// sync.
	for _, d := range g.members[1:] {
		p := prefix + d.Name + "/"
		if d.Clipboard == "none" {
			if r.Do(p+"own", func() error { return setMode(ctx, d, "own") }) == nil {
				t := text("own on " + d.Name)
				if r.Do(p+"own/copy", func() error { return Copy(ctx, hub, t) }) == nil {
					r.Do(p+"own/paste", func() error { return arrives(ctx, d, t, timeout) })
				}
			}
		}
		r.Do(p+"on-off", func() error {
			id, err := deviceOf(ctx, d)
			if err != nil {
				return err
			}
			if _, err := Run(ctx, hub, adminCmd(hub)+" sync -on "+id+" off", ""); err != nil {
				return noSudo(hub, err)
			}
			return eventually(ctx, timeout, func() error { return modeIs(ctx, d, "own") })
		})
		r.Do(p+"shared", func() error { return setMode(ctx, d, "shared") })
	}
}

// modeIs checks the device's cbb sync, which a full member shows to any
// member of the service's group; the lite member's cbb sync asks as root.
func modeIs(ctx context.Context, d *Device, mode string) error {
	cmd := cbbCmd(d)
	if d.OS == "linux-lite" {
		cmd = adminCmd(d)
	}
	out, err := Run(ctx, d, cmd+" sync", "")
	if err != nil {
		return noSudo(d, err)
	}
	if !strings.HasPrefix(out, "Sync is "+syncWord(mode)) {
		return fmt.Errorf("%s says %q, not sync %s", d.Name, firstLine(out), syncWord(mode))
	}
	return nil
}

func restartService(ctx context.Context, d *Device) error {
	var cmd string
	switch {
	case d.OS == "docker":
		cmd = "docker restart " + d.Container
	case serviceCmd(d, "restart") != "":
		cmd = serviceCmd(d, "restart")
	default:
		return Skipped("the bench restarts the service only on Linux, OpenWrt, FreeBSD and in the container")
	}
	_, err := Run(ctx, d, cmd, "")
	return noSudo(d, err)
}

// asRoot runs a shell command as root on the device, or in the case of a
// container, on its host over the container's state volume. ok is false
// where the bench cannot (Windows so far).
func asRoot(d *Device, cmd string) (string, bool) {
	switch d.OS {
	case "linux", "linux-lite", "docker", "netns", "openwrt", "freebsd":
		return rootPrefix(d) + "sh -c " + shellQuote(cmd), true
	}
	return "", false
}

// stateDir is where the service keeps its keys; in a container, the
// volume's directory on the host.
func stateDir(ctx context.Context, d *Device) (string, error) {
	switch d.OS {
	case "linux", "linux-lite":
		return "/var/lib/cbb", nil
	case "darwin":
		return "/Library/Application Support/cbb/state", nil
	case "openwrt":
		return "/etc/cbb/state", nil
	case "freebsd":
		return "/var/db/cbb", nil
	case "netns":
		return netnsDir(d) + "/state", nil
	case "docker":
		out, err := Run(ctx, d, "docker inspect -f '{{range .Mounts}}{{if eq .Destination \"/var/lib/cbb\"}}{{.Source}}{{end}}{{end}}' "+d.Container, "")
		if err != nil {
			return "", err
		}
		if dir := strings.TrimSpace(out); dir != "" {
			return dir, nil
		}
		return "", errors.New("the container has no volume at /var/lib/cbb")
	}
	return "", Skipped("the bench does not read this device's state directory yet")
}

// secretCopy (C6, S10): a secret copy arrives, never reaches a disk, and is
// gone 60 s after the copy; the Linux services cannot swap.
func secretCopy(ctx context.Context, r *Report, g *benchGroup, timeout time.Duration) {
	const prefix = "full/S10-secret/"
	marker := fmt.Sprintf("cbb-bench %s secret", g.run)
	if r.Do(prefix+"copy", func() error {
		_, err := Run(ctx, g.hub, cbbCmd(g.hub)+" copy -secret", marker)
		return err
	}) != nil {
		return
	}
	copied := time.Now()
	for _, d := range g.members[1:] {
		r.Do(prefix+d.Name+"/arrives", func() error { return arrives(ctx, d, marker, timeout) })
	}
	for _, d := range g.members {
		r.Do(prefix+d.Name+"/disk", func() error { return notOnDisk(ctx, d, g.run) })
		if d.OS == "linux" || d.OS == "linux-lite" {
			r.Do(prefix+d.Name+"/swap", func() error {
				out, err := Run(ctx, d, "systemctl show cbb -p MemorySwapMax --value", "")
				if err == nil && strings.TrimSpace(out) != "0" {
					err = fmt.Errorf("the service may swap: MemorySwapMax is %q", strings.TrimSpace(out))
				}
				return err
			})
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Until(copied.Add(65 * time.Second))):
	}
	for _, d := range g.members {
		r.Do(prefix+d.Name+"/gone", func() error {
			got, err := Paste(ctx, d)
			var re *RunError
			if errors.As(err, &re) && strings.Contains(re.Output, "the clipboard is empty") {
				return nil
			}
			if err == nil && strings.Contains(got, marker) {
				err = fmt.Errorf("%s still has the secret 65 s after the copy", d.Name)
			}
			return err
		})
	}
}

// notOnDisk checks that no file in the state directory or /tmp holds the
// run's ID, which every text of the run carries.
func notOnDisk(ctx context.Context, d *Device, run string) error {
	dir, err := stateDir(ctx, d)
	if err != nil {
		return err
	}
	cmd, ok := asRoot(d, "grep -r -l -F "+shellQuote(run)+" "+shellQuote(dir)+" /tmp 2>/dev/null; true")
	if d.OS == "darwin" {
		// On a Mac only the bench's helper runs as root.
		cmd, ok = "sudo -n "+macHelper+" grep "+shellQuote(run), true
	}
	if !ok {
		return Skipped("the bench cannot search this device's files")
	}
	out, err := RunFor(ctx, d, cmd, "", 2*time.Minute)
	if err != nil {
		return noSudo(d, err)
	}
	if files := strings.TrimSpace(out); files != "" {
		return fmt.Errorf("the run's text is in files on %s: %s", d.Name, strings.ReplaceAll(files, "\n", ", "))
	}
	return nil
}

// localAccess (S11): a user outside the cbb group cannot use
// the service, and a member of the group cannot change the group without
// root.
func localAccess(ctx context.Context, r *Report, g *benchGroup) {
	const prefix = "full/S11-access/"
	for _, d := range g.members {
		if d.OS != "linux" && d.OS != "linux-lite" && d.OS != "darwin" {
			continue
		}
		r.Do(prefix+d.Name+"/stranger", func() error {
			stranger := "cd / && sudo -n -u nobody " + cbbCmd(d) + " status"
			if d.OS == "darwin" {
				stranger = "sudo -n " + macHelper + " stranger"
			}
			_, err := Run(ctx, d, stranger, "")
			var re *RunError
			switch {
			case err == nil:
				return errors.New("a user outside the cbb group read the status")
			case sudoRefused(err):
				return noSudo(d, err)
			case !errors.As(err, &re):
				return err
			case !strings.Contains(re.Output, "group") && !strings.Contains(re.Output, "permission"):
				return fmt.Errorf("the refusal does not say why: %q", firstLine(re.Output))
			}
			return nil
		})
		r.Do(prefix+d.Name+"/admin", func() error {
			_, err := Run(ctx, d, cbbCmd(d)+" mode own", "")
			if err == nil {
				setMode(ctx, d, "shared")
				return errors.New("the bench user changed the sync mode without root")
			}
			return modeIs(ctx, d, "shared")
		})
	}
}

// logsClean (S15): no log of the run holds a text of the run or a pairing
// code.
func logsClean(ctx context.Context, r *Report, g *benchGroup, since time.Time) {
	const prefix = "full/S15-logs/"
	pattern := "-e " + shellQuote(g.run)
	for _, code := range g.codes {
		pattern += " -e " + shellQuote(code[:3]+" "+code[3:]) + " -e " + shellQuote(code)
	}
	at := strconv.FormatInt(since.Unix(), 10)
	for _, d := range g.members {
		var logs string
		switch d.OS {
		case "linux", "linux-lite":
			// The service's unit and the agent's process only: sudo logs
			// the bench's own commands, which name the run.
			logs = "{ sudo -n journalctl -u cbb --since @" + at + " --no-pager -o cat && { journalctl --user _COMM=cbb --since @" + at + " --no-pager -o cat 2>/dev/null || true; }; }"
		case "darwin":
			logs = "sudo -n " + macHelper + " logs"
		case "netns":
			logs = "{ sudo -n journalctl -u " + netnsUnit(d) + " --since @" + at + " --no-pager -o cat; }"
		case "docker":
			// The container's log is docker logs' standard error.
			logs = "{ docker logs --since " + at + " " + d.Container + " 2>&1; }"
		default:
			r.Skip(prefix+d.Name, "the bench does not read this device's logs yet")
			continue
		}
		r.Do(prefix+d.Name, func() error {
			// The logs go to a file first, so that a log the bench cannot
			// read fails the case instead of looking clean.
			out, err := Run(ctx, d, "f=$(mktemp) && "+logs+" >$f && { grep -F -w "+pattern+" $f | head -3; rm -f $f; }", "")
			if err != nil {
				return noSudo(d, err)
			}
			if hits := strings.TrimSpace(out); hits != "" {
				return fmt.Errorf("a log on %s holds a text or a pairing code of the run: %s", d.Name, firstLine(hits))
			}
			return nil
		})
	}
}

// filesAtRest (S16): the state directory gives no one but its owner any
// access.
func filesAtRest(ctx context.Context, r *Report, g *benchGroup) {
	const prefix = "full/S16-files/"
	for _, d := range g.members {
		r.Do(prefix+d.Name, func() error {
			dir, err := stateDir(ctx, d)
			if err != nil {
				return err
			}
			cmd, ok := asRoot(d, "find "+shellQuote(dir)+" -mindepth 1 \\( -perm -g=r -o -perm -g=w -o -perm -o=r -o -perm -o=w \\)")
			if d.OS == "darwin" {
				cmd, ok = "sudo -n "+macHelper+" perms", true
			}
			if !ok {
				return Skipped("the bench cannot list this device's files")
			}
			out, err := Run(ctx, d, cmd, "")
			if err != nil {
				return noSudo(d, err)
			}
			if files := strings.TrimSpace(out); files != "" {
				return fmt.Errorf("files in the state directory of %s are open to others: %s", d.Name, strings.ReplaceAll(files, "\n", ", "))
			}
			return nil
		})
	}
}
