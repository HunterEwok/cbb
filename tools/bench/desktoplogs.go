// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// stamped is a line of a Windows log: the time, then the message.
var stamped = regexp.MustCompile(`(?m)^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d cbb: `)

// deviceLogs (I21): each device in no group logs where its system keeps
// logs. On Windows and a Mac the service's log, filled past 1 MiB, is moved
// to service.log.1 at the restarted service's first line and started
// again, each line after the time; the agent's log is in the user's
// LocalAppData or ~/Library/Logs. On Linux the unit's journal has the
// service's lines.
func deviceLogs(ctx context.Context, r *Report, devices []*Device) {
	const p = "desktop/I21-logs/"
	for _, d := range devices {
		switch d.OS {
		case "windows":
			r.Do(p+d.Name+"/rotated", func() error { return winRotated(ctx, d) })
			r.Do(p+d.Name+"/agent", func() error {
				out, err := Run(ctx, d, `$f = "$env:LOCALAPPDATA\cbb\agent.log"; if (Test-Path $f) { Get-Content -Raw $f } else { 'none' }`, "")
				if err != nil {
					return err
				}
				if strings.TrimSpace(out) == "none" {
					return nil // the agent has said nothing yet
				}
				if !stamped.MatchString(out) {
					return fmt.Errorf("the agent's log has no line that starts with the time: %q", firstLine(out))
				}
				return nil
			})
		case "linux":
			r.Do(p+d.Name+"/journal", func() error {
				out, err := Run(ctx, d, "sudo -n journalctl -u cbb -n 20 --no-pager -o cat", "")
				if err != nil {
					return noSudo(d, err)
				}
				if !strings.Contains(out, "cbb") {
					return fmt.Errorf("the journal of cbb.service has no line of the service: %q", firstLine(out))
				}
				return nil
			})
		case "darwin":
			r.Do(p+d.Name+"/rotated", func() error { return macRotated(ctx, d) })
			r.Do(p+d.Name+"/agent", func() error {
				out, err := Run(ctx, d, `f=~/Library/Logs/cbb/agent.log; if [ -f "$f" ]; then tail -n 20 "$f"; else echo none; fi`, "")
				if err != nil {
					return err
				}
				if strings.TrimSpace(out) == "none" {
					return nil // the agent has said nothing yet
				}
				if !stamped.MatchString(out) {
					return fmt.Errorf("the agent's log has no line that starts with the time: %q", firstLine(out))
				}
				return nil
			})
		}
	}
}

// winRotated fills the Windows service's log to just over 1 MiB with the
// service stopped and starts it: in no group, it says so at once, and that
// line moves the full log to service.log.1.
func winRotated(ctx context.Context, d *Device) error {
	const log = `$env:ProgramData\cbb\logs\service.log`
	filler := fmt.Sprintf(`$line = '2026-01-01 00:00:00 cbb: the bench fills the log to rotate it ' + ('x' * 60); $sb = New-Object Text.StringBuilder; while ($sb.Length -lt %d) { [void]$sb.AppendLine($line) }; [IO.File]::AppendAllText("%s", $sb.ToString())`, 1<<20+1024, log)
	if _, err := RunFor(ctx, d, "Stop-Service cbb; Remove-Item -ErrorAction SilentlyContinue \""+log+".1\"; "+filler+"; Start-Service cbb", "", 2*time.Minute); err != nil {
		return err
	}
	if err := eventually(ctx, 30*time.Second, func() error {
		_, err := groupOf(ctx, d)
		return err
	}); err != nil {
		return fmt.Errorf("the service did not answer after its start: %w", err)
	}
	return eventually(ctx, 30*time.Second, func() error {
		out, err := Run(ctx, d, `foreach ($f in "`+log+`", "`+log+`.1") { if (Test-Path $f) { (Get-Item $f).Length } else { -1 } }`, "")
		if err != nil {
			return err
		}
		f := strings.Fields(out)
		if len(f) != 2 {
			return fmt.Errorf("the sizes of the logs are %q", out)
		}
		now, _ := strconv.Atoi(f[0])
		old, _ := strconv.Atoi(f[1])
		if old < 1<<20 || now < 0 || now >= 64<<10 {
			return fmt.Errorf("after a start with a log of over 1 MiB, service.log has %d bytes and service.log.1 %d: not rotated", now, old)
		}
		body, err := Run(ctx, d, `Get-Content -Raw "`+log+`"`, "")
		if err == nil && !stamped.MatchString(body) {
			err = fmt.Errorf("the new log has no line that starts with the time: %q", firstLine(body))
		}
		return err
	})
}

// macRotated fills the Mac service's log past 1 MiB and restarts it through
// the bench's root helper: in no group, the service says so at once, and
// that line moves the full log to service.log.1.
func macRotated(ctx context.Context, d *Device) error {
	if _, err := RunFor(ctx, d, "sudo -n "+macHelper+" fill-log", "", 2*time.Minute); err != nil {
		return noSudo(d, err)
	}
	if err := eventually(ctx, 30*time.Second, func() error {
		_, err := groupOf(ctx, d)
		return err
	}); err != nil {
		return fmt.Errorf("the service did not answer after its restart: %w", err)
	}
	return eventually(ctx, 30*time.Second, func() error {
		out, err := Run(ctx, d, "sudo -n "+macHelper+" log-sizes", "")
		if err != nil {
			return noSudo(d, err)
		}
		f := strings.Fields(out)
		if len(f) != 2 {
			return fmt.Errorf("the sizes of the logs are %q", out)
		}
		now, _ := strconv.Atoi(f[0])
		old, _ := strconv.Atoi(f[1])
		if old < 1<<20 || now < 0 || now >= 64<<10 {
			return fmt.Errorf("after a restart with a log of over 1 MiB, service.log has %d bytes and service.log.1 %d: not rotated", now, old)
		}
		body, err := Run(ctx, d, "sudo -n "+macHelper+" logs", "")
		if err == nil && !stamped.MatchString(body) {
			err = fmt.Errorf("the new log has no line that starts with the time: %q", firstLine(body))
		}
		return err
	})
}
