// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Desktop runs the cases of the desktops' own clipboards on the Macs and
// Windows PCs of the inventory, in a group with a Linux member: a written
// text never sent back and a clipboard history's offer of it making no
// event (Y24, Y25), password managers' marks kept from the group (Y31), a
// received secret's marks and expiry (Y32), cbb copy with sync on and off
// (M2), the Linux member's agent and tmux (H2, H3), a fetch's progress
// (O13), remote paste on
// Windows (T3, T5, T11, T12), and the logs (I21).
func Desktop(ctx context.Context, r *Report, devices []*Device, timeout time.Duration) {
	// The logs first, while every device is in no group.
	deviceLogs(ctx, r, atHome(devices))
	g := formGroup(ctx, r, "desktop", devices)
	if g == nil {
		return
	}
	defer g.end(ctx, r)
	l := linuxMember(g)
	var desks []*Device
	for _, d := range g.members {
		if d.Clipboard == "macos" || d.Clipboard == "windows" {
			desks = append(desks, d)
		}
	}
	if l == nil {
		r.Skip("desktop", "needs a Linux member")
		return
	}
	linuxDesktop(ctx, r, g, l, desks, timeout)
	defer disruptiveCases(ctx, r, g, append([]*Device{l}, desks...), timeout)
	if len(desks) == 0 {
		r.Skip("desktop", "needs a Mac or a Windows PC with its clipboard beside the Linux member")
		return
	}
	for _, d := range desks {
		noEcho(ctx, r, g, l, d, timeout)
	}
	for _, d := range desks {
		marked(ctx, r, l, d, g.run, timeout)
	}
	for _, d := range desks {
		deliberate(ctx, r, l, d, g.run, timeout)
	}
	linuxAgent(ctx, r, l, desks[0], g.run, timeout)
	linuxTmux(ctx, r, l, desks[0], g.run, timeout)
	for _, d := range desks {
		progress(ctx, r, l, d, g.run)
	}
	for _, d := range desks {
		secretMarks(ctx, r, l, d, g.run, timeout)
	}
	for _, d := range desks {
		if d.Clipboard == "windows" {
			winPaste(ctx, r, g, d, timeout)
		} else {
			r.Skip("desktop/T3-paste/"+d.Name, "the Mac app's paste target needs Accessibility, granted by hand: it stays manual")
		}
	}
}

// noEcho (Y24, Y25): the desktop d writes a text its agent took late,
// after l, cut off from the group, copied a newer one; the clipboard
// history offers it again at once and 10 s later. Had d sent it back, its
// copy would be newer than l's and win; without an echo l's text wins
// everywhere once l is back. Then d's cbb copy of the text it already
// holds is a copy, newer than one l made cut off, and wins.
func noEcho(ctx context.Context, r *Report, g *benchGroup, l, d *Device, timeout time.Duration) {
	a := fmt.Sprintf("cbb-bench %s Y24 written late on %s", g.run, d.Name)
	b := fmt.Sprintf("cbb-bench %s Y24 from %s cut off", g.run, l.Name)
	if r.Do("desktop/Y24-no-echo/"+d.Name, func() error {
		resume, err := pauseAgent(ctx, d)
		if err != nil {
			return err
		}
		defer resume()
		if err := Copy(ctx, l, a); err != nil {
			return err
		}
		if err := serviceHas(ctx, d, seen(a, l, d), timeout); err != nil {
			return err
		}
		open, err := blockPort(ctx, l)
		if err != nil {
			return err
		}
		defer open()
		time.Sleep(time.Second)
		if err := Copy(ctx, l, b); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		if err := resume(); err != nil {
			return err
		}
		if err := arrives(ctx, d, seen(a, l, d), timeout); err != nil {
			return fmt.Errorf("the paused agent did not write the text: %w", err)
		}
		// A clipboard history, Windows' or a Mac app's, offers the text
		// again.
		for _, wait := range []time.Duration{2 * time.Second, 10 * time.Second} {
			time.Sleep(wait)
			if err := Copy(ctx, d, seen(a, l, d)); err != nil {
				return err
			}
		}
		time.Sleep(2 * time.Second)
		if err := open(); err != nil {
			return err
		}
		if err := arrives(ctx, d, seen(b, l, d), 90*time.Second); err != nil {
			return fmt.Errorf("%s sent the written text back: %w", d.Name, err)
		}
		return arrives(ctx, l, b, timeout)
	}) != nil {
		return
	}
	c := fmt.Sprintf("cbb-bench %s Y25 from %s cut off", g.run, l.Name)
	r.Do("desktop/Y25-copy-again/"+d.Name, func() error {
		open, err := blockPort(ctx, l)
		if err != nil {
			return err
		}
		defer open()
		if err := Copy(ctx, l, c); err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
		if _, err := Run(ctx, d, cbbCmd(d)+" copy", seen(b, l, d)); err != nil {
			return err
		}
		time.Sleep(time.Second)
		if err := open(); err != nil {
			return err
		}
		if err := arrives(ctx, l, b, 90*time.Second); err != nil {
			return fmt.Errorf("cbb copy of the text %s held made no copy: %w", d.Name, err)
		}
		return arrives(ctx, d, seen(b, l, d), timeout)
	})
}

// linuxAgent (H2): the Linux member's desktop runs one agent for its
// user; a second one leaves at once and says why; the agent's user unit
// restarted gives a new agent that links the clipboard again.
func linuxAgent(ctx context.Context, r *Report, l, other *Device, run string, timeout time.Duration) {
	p := "desktop/H2-agent/" + l.Name + "/"
	if l.Clipboard != "x11" && l.Clipboard != "wayland" {
		r.Skip(p[:len(p)-1], "the Linux member has no desktop clipboard")
		return
	}
	const user = "XDG_RUNTIME_DIR=/run/user/$(id -u) "
	agents := func() (string, error) {
		out, err := Run(ctx, l, "pgrep -u $(id -u) -f '[c]bb agent$' || true", "")
		return strings.Join(strings.Fields(out), " "), err
	}
	var first string
	if r.Do(p+"one", func() error {
		var err error
		if first, err = agents(); err != nil {
			return err
		}
		if n := len(strings.Fields(first)); n != 1 {
			return fmt.Errorf("%s runs %d agents for the user (%q), not one", l.Name, n, first)
		}
		return nil
	}) != nil {
		return
	}
	r.Do(p+"second-leaves", func() error {
		out, err := RunFor(ctx, l, "timeout 10 cbb agent 2>&1; echo exit=$?", "", 20*time.Second)
		if err != nil {
			return err
		}
		if !strings.Contains(out, "another agent links this session's clipboard already") || !strings.Contains(out, "exit=0") {
			return fmt.Errorf("a second agent printed %q", strings.TrimSpace(out))
		}
		if now, err := agents(); err != nil || now != first {
			return fmt.Errorf("after a second agent the agents are %q, not %q (%v)", now, first, err)
		}
		return nil
	})
	r.Do(p+"restarted", func() error {
		if out, _ := Run(ctx, l, user+"systemctl --user is-active cbb-agent 2>/dev/null || true", ""); strings.TrimSpace(out) != "active" {
			return Skipped("the agent runs from the autostart entry, not the user unit: this desktop has no graphical-session.target")
		}
		if _, err := Run(ctx, l, user+"systemctl --user restart cbb-agent", ""); err != nil {
			return err
		}
		if err := eventually(ctx, 20*time.Second, func() error {
			now, err := agents()
			if err == nil && (now == first || len(strings.Fields(now)) != 1) {
				err = fmt.Errorf("after the restart the agents are %q", now)
			}
			return err
		}); err != nil {
			return err
		}
		text := fmt.Sprintf("cbb-bench %s H2 after the agent's restart", run)
		if err := Copy(ctx, l, text); err != nil {
			return err
		}
		return arrives(ctx, other, seen(text, l, other), timeout)
	})
}

// deliberate (M2): cbb copy on d sends with sync on and with sync off,
// which keeps d's own copies from the group; d ends with sync on.
func deliberate(ctx context.Context, r *Report, l, d *Device, run string, timeout time.Duration) {
	p := "desktop/M2-every-mode/" + d.Name + "/"
	defer setMode(context.WithoutCancel(ctx), d, "shared")
	for _, mode := range []string{"own", "shared"} {
		r.Do(p+mode, func() error {
			if err := setMode(ctx, d, mode); err != nil {
				return err
			}
			if err := modeIs(ctx, d, mode); err != nil {
				return err
			}
			text := fmt.Sprintf("cbb-bench %s M2 cbb copy on %s in mode %s", run, d.Name, mode)
			if _, err := Run(ctx, d, cbbCmd(d)+" copy", text); err != nil {
				return err
			}
			return arrives(ctx, l, text, timeout)
		})
	}
}

// marked (Y31): a text that a password manager marks stays on d, and so
// does the same text put back without the mark, as a clipboard manager
// does; an unmarked text then still reaches l.
func marked(ctx context.Context, r *Report, l, d *Device, run string, timeout time.Duration) {
	type mark struct{ name, types string }
	var marks []mark
	switch d.Clipboard {
	case "macos":
		marks = []mark{
			{"concealed", "org.nspasteboard.ConcealedType"},
			{"transient", "org.nspasteboard.TransientType"},
			{"auto-generated", "org.nspasteboard.AutoGeneratedType"},
		}
	case "windows":
		marks = []mark{
			{"monitor", "ExcludeClipboardContentFromMonitorProcessing"},
			{"history", "CanIncludeInClipboardHistory=0"},
		}
	}
	p := "desktop/Y31-marked/" + d.Name + "/"
	for _, m := range marks {
		s := fmt.Sprintf("cbb-bench %s Y31 %s %s", run, d.Name, m.name)
		r.Do(p+m.name, func() error {
			if err := copyMarked(ctx, d, s, strings.Fields(m.types)); err != nil {
				return err
			}
			if err := notSent(ctx, l, s, "a text marked "+m.types); err != nil {
				return err
			}
			if err := Copy(ctx, d, s); err != nil {
				return err
			}
			return notSent(ctx, l, s, "a marked text put back without the mark")
		})
	}
	plain := fmt.Sprintf("cbb-bench %s Y31 %s plain", run, d.Name)
	r.Do(p+"plain", func() error {
		if err := Copy(ctx, d, plain); err != nil {
			return err
		}
		return arrives(ctx, l, plain, timeout)
	})
}

// secretMarks (Y32): a secret l sends reaches d's clipboard with the marks
// that keep it out of clipboard histories and the cloud clipboard, stays
// there for most of its minute, and is gone after it.
func secretMarks(ctx context.Context, r *Report, l, d *Device, run string, timeout time.Duration) {
	p := "desktop/Y32-secret/" + d.Name + "/"
	s := fmt.Sprintf("cbb-bench %s Y32 secret for %s", run, d.Name)
	var sent time.Time
	if r.Do(p+"arrives", func() error {
		if _, err := Run(ctx, l, cbbCmd(l)+" copy -secret", s); err != nil {
			return err
		}
		sent = time.Now()
		return arrives(ctx, d, s, timeout)
	}) != nil {
		return
	}
	r.Do(p+"marks", func() error {
		types, err := clipTypes(ctx, d)
		if err != nil {
			return err
		}
		var want []string
		switch d.Clipboard {
		case "macos":
			want = []string{"org.nspasteboard.ConcealedType"}
		case "windows":
			want = []string{"ExcludeClipboardContentFromMonitorProcessing", "Clipboard Viewer Ignore", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"}
		}
		for _, w := range want {
			if !strings.Contains("\n"+types+"\n", "\n"+w+"\n") {
				return fmt.Errorf("the secret on %s is not marked %s; its clipboard holds:\n%s", d.Name, w, types)
			}
		}
		return nil
	})
	r.Do(p+"expires", func() error {
		time.Sleep(time.Until(sent.Add(40 * time.Second)))
		if got, err := Paste(ctx, d); err != nil || got != s {
			return fmt.Errorf("40 s after the copy %s no longer holds the secret but %s (%v)", d.Name, describe(got), err)
		}
		time.Sleep(time.Until(sent.Add(60 * time.Second)))
		return eventually(ctx, 20*time.Second, func() error {
			got, err := Paste(ctx, d)
			if err == nil && got == s {
				err = fmt.Errorf("%s still holds the secret %v after the copy", d.Name, time.Since(sent).Round(time.Second))
			}
			return err
		})
	})
}

// notSent checks that text has not reached l after the quiet time.
func notSent(ctx context.Context, l *Device, text, what string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(quiet):
	}
	got, err := Paste(ctx, l)
	if err != nil {
		return err
	}
	if got == text {
		return fmt.Errorf("%s reached %s", what, l.Name)
	}
	return nil
}

// serviceHas waits until d's service holds text, which cbb paste prints
// whatever its clipboard holds.
func serviceHas(ctx context.Context, d *Device, text string, timeout time.Duration) error {
	return eventually(ctx, timeout, func() error {
		got, err := Run(ctx, d, cbbCmd(d)+" paste", "")
		if err == nil && strings.TrimRight(got, "\r\n") != text {
			err = fmt.Errorf("the service on %s did not get the text within %v; it has %s", d.Name, timeout, describe(got))
		}
		return err
	})
}

// pauseAgent stops d's clipboard agent where it is, so that what its
// service writes waits; resume lets it go on, and is safe to call again.
func pauseAgent(ctx context.Context, d *Device) (resume func() error, err error) {
	var stop, cont string
	switch d.Clipboard {
	case "macos":
		// The pattern does not match the shell that runs pkill.
		stop, cont = "pkill -STOP -u $(id -u) -f '[c]bb agent$'", "pkill -CONT -u $(id -u) -f '[c]bb agent$'"
	case "windows":
		nt := `Add-Type -Namespace CbbBench -Name Nt -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h); [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);'; $p = @(Get-Process cbbw -ErrorAction SilentlyContinue); if ($p.Count -eq 0) { throw 'no agent (cbbw.exe) runs' }; foreach ($x in $p) { [void][CbbBench.Nt]::%s($x.Handle) }`
		stop, cont = fmt.Sprintf(nt, "NtSuspendProcess"), fmt.Sprintf(nt, "NtResumeProcess")
	default:
		return nil, fmt.Errorf("the bench cannot pause the agent on %s", d.Name)
	}
	if _, err := Run(ctx, d, stop, ""); err != nil {
		return nil, fmt.Errorf("pausing the agent on %s: %w", d.Name, err)
	}
	done := false
	return func() error {
		if done {
			return nil
		}
		done = true
		_, err := Run(context.WithoutCancel(ctx), d, cont, "")
		return err
	}, nil
}

// macPut puts stdin's text on the pasteboard with an empty item of each
// type its arguments name, as a password manager marks a password.
const macPut = `ObjC.import("AppKit");
function run(argv) {
	var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
	var pb = $.NSPasteboard.generalPasteboard;
	pb.clearContents;
	pb.setStringForType($.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding), $.NSPasteboardTypeString);
	for (var i = 0; i < argv.length; i++) pb.setStringForType($(""), $(argv[i]));
}`

// macTypes prints the types of the pasteboard's item, one a line.
const macTypes = `ObjC.import("AppKit");
function run() { return ObjC.deepUnwrap($.NSPasteboard.generalPasteboard.types).join("\n"); }`

// copyMarked puts text on d's clipboard with the marks: on a Mac the
// pasteboard types, on Windows the clipboard formats, NAME with one byte
// or NAME=0 with the number 0.
func copyMarked(ctx context.Context, d *Device, text string, marks []string) error {
	switch d.Clipboard {
	case "macos":
		_, err := Run(ctx, d, "osascript -l JavaScript -e "+shellQuote(macPut)+" "+strings.Join(marks, " "), text)
		return err
	case "windows":
		var b strings.Builder
		fmt.Fprintf(&b, "Add-Type -AssemblyName System.Windows.Forms\n$o = New-Object Windows.Forms.DataObject\n")
		fmt.Fprintf(&b, "$o.SetData([Windows.Forms.DataFormats]::UnicodeText, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')))\n", base64.StdEncoding.EncodeToString([]byte(text)))
		for _, m := range marks {
			name, bytes := m, "0"
			if n, ok := strings.CutSuffix(m, "=0"); ok {
				name, bytes = n, "0,0,0,0"
			}
			fmt.Fprintf(&b, "$o.SetData('%s', (New-Object IO.MemoryStream(,[byte[]](%s))))\n", name, bytes)
		}
		b.WriteString("[Windows.Forms.Clipboard]::SetDataObject($o, $true)\n")
		_, err := inSession(ctx, d, b.String())
		return err
	}
	return fmt.Errorf("no way to mark the clipboard of %s", d.Name)
}

// clipTypes lists the types of what d's clipboard holds, one a line.
func clipTypes(ctx context.Context, d *Device) (string, error) {
	var out string
	var err error
	switch d.Clipboard {
	case "macos":
		out, err = Run(ctx, d, "osascript -l JavaScript -e "+shellQuote(macTypes), "")
	case "windows":
		out, err = inSession(ctx, d, "Add-Type -AssemblyName System.Windows.Forms\n[Windows.Forms.Clipboard]::GetDataObject().GetFormats() -join \"`n\"\n")
	default:
		return "", fmt.Errorf("no way to list the clipboard's types on %s", d.Name)
	}
	return strings.ReplaceAll(strings.TrimSpace(out), "\r\n", "\n"), err
}

// inSession runs a PowerShell script in the signed-in user's desktop
// session of a Windows device, through setup-windows.ps1's cbbbench-run
// task, and returns what it printed.
func inSession(ctx context.Context, d *Device, script string) (string, error) {
	// With a byte order mark, Windows PowerShell reads the file as UTF-8.
	b64 := base64.StdEncoding.EncodeToString(append([]byte("\xef\xbb\xbf"), script...))
	out, err := Run(ctx, d, fmt.Sprintf(`Remove-Item -ErrorAction SilentlyContinue '%[1]s\run.out'; [IO.File]::WriteAllBytes('%[1]s\run.ps1', [Convert]::FromBase64String('%[2]s')); schtasks /run /tn cbbbench-run | Out-Null; $n = 0; while (-not (Test-Path '%[1]s\run.out') -and $n -lt 80) { Start-Sleep -Milliseconds 250; $n++ }; if (-not (Test-Path '%[1]s\run.out')) { throw 'the cbbbench-run task wrote nothing: run tools/bench/setup-windows.ps1 again, and stay signed in' }; [IO.File]::ReadAllText('%[1]s\run.out')`, winBench, b64), "")
	if err != nil {
		return "", err
	}
	if rest, failed := strings.CutPrefix(out, "cbbbench-run failed: "); failed {
		return "", fmt.Errorf("the script in the session of %s failed: %s", d.Name, strings.TrimSpace(rest))
	}
	return out, nil
}

// linuxTmux (H3): in tmux with cbb's configuration on the
// Linux member, a selection copied in copy mode reaches the group, and the
// paste key, pressed by a client attached on a terminal, pastes the first
// line of the group's text and never a secret.
func linuxTmux(ctx context.Context, r *Report, l, other *Device, run string, timeout time.Duration) {
	p := "desktop/H3-tmux/" + l.Name + "/"
	const tm = "tmux -L cbbbench "
	if r.Do(p+"setup", func() error {
		out, err := Run(ctx, l, "command -v tmux >/dev/null || echo none", "")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) == "none" {
			return Skipped(l.Name + " has no tmux")
		}
		if _, err := Run(ctx, l, tm+"kill-server 2>/dev/null; rm -f /tmp/h3.out /tmp/h3.in; "+tm+"new-session -d -s h3 -x 120 -y 30 && "+tm+"new-session -d -s h3p -x 120 -y 30 'cat >/tmp/h3.out'", ""); err != nil {
			return err
		}
		out, err = Run(ctx, l, tm+"show -s copy-command", "")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "cbb copy") {
			return fmt.Errorf("tmux on %s does not read cbb's configuration from /etc/tmux.conf: copy-command is %q", l.Name, strings.TrimSpace(out))
		}
		return nil
	}) != nil {
		return
	}
	defer Run(context.WithoutCancel(ctx), l, tm+"kill-server 2>/dev/null; pkill -f '[s]leep 300' ; rm -f /tmp/h3.out /tmp/h3.in; true", "")
	mark := fmt.Sprintf("cbb-bench-%s-H3-copy-mode", run)
	r.Do(p+"copy-mode", func() error {
		if _, err := Run(ctx, l, tm+"send-keys -t h3 'echo "+mark+"' Enter", ""); err != nil {
			return err
		}
		time.Sleep(time.Second)
		if _, err := Run(ctx, l, tm+"copy-mode -t h3 \\; send-keys -t h3 -X search-backward '"+mark+"' \\; send-keys -t h3 -X begin-selection \\; send-keys -t h3 -X end-of-line \\; send-keys -t h3 -X copy-pipe-and-cancel", ""); err != nil {
			return err
		}
		return arrives(ctx, other, mark, timeout)
	})
	press := func() error {
		_, err := Run(ctx, l, "printf '\\002]' >/tmp/h3.in", "")
		return err
	}
	r.Do(p+"paste-key", func() error {
		// A client on a terminal of its own, whose keys come from a pipe.
		if _, err := Run(ctx, l, "mkfifo /tmp/h3.in && { setsid sh -c 'sleep 300 >/tmp/h3.in' >/dev/null 2>&1 </dev/null & } && { setsid sh -c \"TERM=xterm script -qfc '"+tm+"attach -t h3p' /dev/null </tmp/h3.in >/dev/null 2>&1\" >/dev/null 2>&1 </dev/null & }", ""); err != nil {
			return err
		}
		if err := eventually(ctx, 10*time.Second, func() error {
			out, err := Run(ctx, l, tm+"list-clients -t h3p", "")
			if err == nil && strings.TrimSpace(out) == "" {
				err = fmt.Errorf("no tmux client attached on %s", l.Name)
			}
			return err
		}); err != nil {
			return err
		}
		first := fmt.Sprintf("cbb-bench %s H3 first line", run)
		if _, err := Run(ctx, other, cbbCmd(other)+" copy", first+"\nsecond line"); err != nil {
			return err
		}
		if err := serviceHas(ctx, l, first+"\nsecond line", timeout); err != nil {
			return err
		}
		if err := press(); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			out, err := Run(ctx, l, "cat /tmp/h3.out", "")
			if err == nil && (!strings.Contains(out, first) || strings.Contains(out, "second line")) {
				err = fmt.Errorf("the paste key pasted %q, not only the first line", out)
			}
			return err
		})
	})
	r.Do(p+"no-secret", func() error {
		secret := fmt.Sprintf("cbb-bench %s H3 secret", run)
		if _, err := Run(ctx, other, cbbCmd(other)+" copy -secret", secret); err != nil {
			return err
		}
		if err := serviceHas(ctx, l, secret, timeout); err != nil {
			return err
		}
		if err := press(); err != nil {
			return err
		}
		time.Sleep(quiet)
		out, err := Run(ctx, l, "cat /tmp/h3.out", "")
		if err == nil && strings.Contains(out, secret) {
			err = fmt.Errorf("the paste key pasted a secret")
		}
		return err
	})
}

// progress (O13): while d fetches a large copy of a file from l, whose
// sending is slowed to 50 Mbit/s, cbb status on d shows how far it got,
// and stops once the copy is there.
func progress(ctx context.Context, r *Report, l, d *Device, run string) {
	p := "desktop/O13-progress/" + d.Name
	r.Do(p, func() error {
		out, err := Run(ctx, l, "ip -o route get 1.1.1.1 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'", "")
		if err != nil {
			return err
		}
		dev := strings.TrimSpace(out)
		if dev == "" {
			return fmt.Errorf("no default route on %s", l.Name)
		}
		del := "tc qdisc del dev " + dev + " root 2>/dev/null; true"
		cancel, err := revertAfter(ctx, l, "cbbbench-rate", 5*time.Minute, del)
		if err != nil {
			return err
		}
		defer func() {
			Run(context.WithoutCancel(ctx), l, "sudo -n sh -c "+shellQuote(del), "")
			cancel()
		}()
		if _, err := Run(ctx, l, "sudo -n tc qdisc add dev "+dev+" root tbf rate 50mbit burst 64kb latency 2s", ""); err != nil {
			return noSudo(l, err)
		}
		file := "/tmp/cbb-bench-" + run + "-O13.bin"
		defer Run(context.WithoutCancel(ctx), l, "rm -f "+file, "")
		if _, err := RunFor(ctx, l, "head -c 150000000 /dev/urandom >"+file+" && "+cbbCmd(l)+" copy "+file, "", 2*time.Minute); err != nil {
			return err
		}
		var shown []string
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			out, err := Run(ctx, d, cbbCmd(d)+" status", "")
			if err != nil {
				return err
			}
			line := ""
			for _, s := range strings.Split(out, "\n") {
				if strings.HasPrefix(s, "Fetching a copy of") {
					line = strings.TrimSpace(s)
				}
			}
			if line == "" && len(shown) > 0 {
				return nil // fetched, and the line is gone
			}
			if line != "" && (len(shown) == 0 || shown[len(shown)-1] != line) {
				shown = append(shown, line)
			}
			time.Sleep(500 * time.Millisecond)
		}
		if len(shown) == 0 {
			return fmt.Errorf("cbb status on %s never showed the fetch of a 150 MB copy", d.Name)
		}
		return fmt.Errorf("cbb status on %s still shows the fetch after 2 minutes: %s", d.Name, strings.Join(shown, " | "))
	})
}
