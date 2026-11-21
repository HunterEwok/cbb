// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The Windows clipboard belongs to the signed-in desktop session, which an
// SSH session cannot reach. setup-windows.ps1 registers two scheduled tasks
// that run in that session: cbbbench-copy puts in.txt on the clipboard and
// deletes it, cbbbench-paste writes the clipboard to out.txt.
const winBench = `C:\ProgramData\cbbbench`

// x11Env reaches the X display of the signed-in session. On GNOME that is
// XWayland, whose cookie file mutter names afresh at each login.
const x11Env = `DISPLAY=${DISPLAY:-:0} XAUTHORITY=${XAUTHORITY:-$(ls /run/user/$(id -u)/.mutter-Xwaylandauth.* 2>/dev/null | head -n 1)} `

// cbbCmd is how the bench calls cbb, with or without its helper, on a
// device. In a container cbb runs as the image's user, the service's own,
// so it reaches the control socket; the bench user on the host is in the
// docker group.
func cbbCmd(d *Device) string {
	switch d.OS {
	case "windows":
		return `& "$env:ProgramFiles\cbb\cbb.exe"`
	case "docker":
		return "docker exec -i " + d.Container + " cbb"
	case "netns":
		// The service runs as root in its namespace, and its cbb reaches
		// it there by its own socket.
		return "sudo -n " + netnsDir(d) + "/cbb"
	}
	return "cbb"
}

// Copy puts text on the device's clipboard the way a user would: on the
// desktop clipboard where the device has one, else with cbb copy.
func Copy(ctx context.Context, d *Device, text string) error {
	var err error
	switch d.Clipboard {
	case "none":
		_, err = Run(ctx, d, cbbCmd(d)+" copy", text)
	case "wayland":
		// wl-copy stays in the background to serve the text; its output
		// must not keep the SSH session open.
		_, err = Run(ctx, d, `XDG_RUNTIME_DIR=/run/user/$(id -u) WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-wayland-0} wl-copy >/dev/null 2>&1`, text)
	case "x11":
		_, err = Run(ctx, d, x11Env+`xclip -selection clipboard -i >/dev/null 2>&1`, text)
	case "macos":
		_, err = Run(ctx, d, "LANG=en_US.UTF-8 pbcopy", text)
	case "windows":
		b64 := base64.StdEncoding.EncodeToString([]byte(text))
		_, err = Run(ctx, d, fmt.Sprintf(`[IO.File]::WriteAllBytes('%s\in.txt', [Convert]::FromBase64String('%s')); schtasks /run /tn cbbbench-copy | Out-Null`, winBench, b64), "")
		if err == nil {
			err = eventually(ctx, 10*time.Second, func() error {
				out, err := Run(ctx, d, fmt.Sprintf(`Test-Path '%s\in.txt'`, winBench), "")
				if err != nil {
					return err
				}
				if strings.TrimSpace(out) != "False" {
					return errors.New("the cbbbench-copy task did not take the text; is the user signed in?")
				}
				return nil
			})
		}
	default:
		err = fmt.Errorf("no clipboard driver for %q", d.Clipboard)
	}
	return err
}

// Paste reads the device's clipboard, from the same place Copy writes.
func Paste(ctx context.Context, d *Device) (string, error) {
	switch d.Clipboard {
	case "none":
		out, err := Run(ctx, d, cbbCmd(d)+" paste", "")
		var re *RunError
		if errors.As(err, &re) && strings.Contains(re.Output, "the clipboard is empty") {
			return "", nil
		}
		return out, err
	case "wayland":
		// wl-paste waits for a focused window on a compositor without
		// data-control (GNOME): give up on it soon, the case retries.
		return Run(ctx, d, `XDG_RUNTIME_DIR=/run/user/$(id -u) WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-wayland-0} timeout 5 wl-paste -n 2>/dev/null || true`, "")
	case "x11":
		return Run(ctx, d, x11Env+`timeout 5 xclip -selection clipboard -o 2>/dev/null || true`, "")
	case "macos":
		return Run(ctx, d, "LANG=en_US.UTF-8 pbpaste", "")
	case "windows":
		out, err := Run(ctx, d, fmt.Sprintf(`Remove-Item -ErrorAction SilentlyContinue '%[1]s\out.txt'; schtasks /run /tn cbbbench-paste | Out-Null; $n = 0; while (-not (Test-Path '%[1]s\out.txt') -and $n -lt 40) { Start-Sleep -Milliseconds 250; $n++ }; [Convert]::ToBase64String([IO.File]::ReadAllBytes('%[1]s\out.txt'))`, winBench), "")
		if err != nil {
			return "", err
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
		return string(b), err
	}
	return "", fmt.Errorf("no clipboard driver for %q", d.Clipboard)
}
