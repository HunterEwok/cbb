// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// winBox is a window with one text box, the focus of a remote paste on
// Windows: it writes what the box holds to box.out twice a second, empties
// the box when box.clear appears and closes when box.stop does.
const winBox = `Add-Type -AssemblyName System.Windows.Forms
$d = 'C:\ProgramData\cbbbench'
$f = New-Object Windows.Forms.Form
$f.Text = 'cbbbench paste target'
$f.TopMost = $true
$f.Width = 640
$f.Height = 400
$t = New-Object Windows.Forms.TextBox
$t.Multiline = $true
$t.AcceptsTab = $true
$t.AcceptsReturn = $true
$t.MaxLength = [int]::MaxValue
$t.Dock = 'Fill'
$f.Controls.Add($t)
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 500
$timer.Add_Tick({
	if (Test-Path "$d\box.clear") { $t.Clear(); Remove-Item "$d\box.clear"; $f.Activate(); $t.Focus() }
	[IO.File]::WriteAllText("$d\box.tmp", $t.Text, (New-Object Text.UTF8Encoding $false))
	Move-Item -Force "$d\box.tmp" "$d\box.out"
	if (Test-Path "$d\box.stop") { Remove-Item "$d\box.stop"; $f.Close() }
})
$f.Add_Shown({ $f.Activate(); $t.Focus() })
$timer.Start()
[void]$f.ShowDialog()
`

// winPaste (T3, T5, T11, T12): the group's root pastes and types into a
// window that has the focus on a Windows PC. Each text arrives exactly:
// Unicode, tabs and line breaks, 1 MiB pasted and 4 KiB typed; the
// clipboard holds its own text again after a paste, also after a secret,
// which the service's log never holds. The device's log of pastes lists
// each one with its sender, length, method and result, never the text.
func winPaste(ctx context.Context, r *Report, g *benchGroup, d *Device, timeout time.Duration) {
	const p = "desktop/T3-paste/"
	var id string
	if r.Do(p+d.Name+"/setup", func() error {
		var err error
		if id, err = deviceOf(ctx, d); err != nil {
			return err
		}
		if _, err := Run(ctx, d, adminCmd(d)+" paste-receive on", ""); err != nil {
			return err
		}
		b64 := base64.StdEncoding.EncodeToString(append([]byte("\xef\xbb\xbf"), winBox...))
		if _, err := Run(ctx, d, fmt.Sprintf(`Remove-Item -ErrorAction SilentlyContinue '%[1]s\box.out', '%[1]s\box.stop', '%[1]s\box.clear'; [IO.File]::WriteAllBytes('%[1]s\box.ps1', [Convert]::FromBase64String('%[2]s'))`, winBench, b64), ""); err != nil {
			return err
		}
		if _, err := inSession(ctx, d, `Start-Process powershell.exe -ArgumentList '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', 'C:\ProgramData\cbbbench\box.ps1'`); err != nil {
			return err
		}
		return eventually(ctx, 20*time.Second, func() error {
			_, err := boxText(ctx, d)
			return err
		})
	}) != nil {
		return
	}
	defer func() {
		Run(context.WithoutCancel(ctx), d, fmt.Sprintf(`New-Item -Force '%s\box.stop' | Out-Null`, winBench), "")
		Run(context.WithoutCancel(ctx), d, adminCmd(d)+" paste-receive off", "")
	}()

	own := fmt.Sprintf("cbb-bench %s T5 the clipboard's own text", g.run)
	if r.Do(p+d.Name+"/own-text", func() error {
		if err := Copy(ctx, d, own); err != nil {
			return err
		}
		return arrives(ctx, g.hub, own, timeout)
	}) != nil {
		return
	}
	last := time.Time{}
	paste := func(flags, text string) error {
		if err := clearBox(ctx, d); err != nil {
			return err
		}
		if wait := time.Until(last.Add(1100 * time.Millisecond)); wait > 0 {
			time.Sleep(wait)
		}
		defer func() { last = time.Now() }()
		out, err := RunFor(ctx, g.hub, adminCmd(g.hub)+" paste -on "+id+flags, text, time.Minute)
		if err == nil && !strings.Contains(out, "Pasted on") {
			err = fmt.Errorf("cbb paste -on printed %q", firstLine(out))
		}
		return err
	}
	inBox := func(text string) error {
		want := seen(text, g.hub, d)
		return eventually(ctx, timeout, func() error {
			got, err := boxText(ctx, d)
			if err == nil && got != want {
				err = fmt.Errorf("the window holds %s, not the %d bytes sent", describe(got), len(want))
			}
			return err
		})
	}
	ownBack := func() error {
		time.Sleep(1500 * time.Millisecond)
		got, err := Paste(ctx, d)
		if err == nil && got != own {
			err = fmt.Errorf("after the paste the clipboard holds %s, not its own text again", describe(got))
		}
		if err != nil {
			return err
		}
		// What a paste puts on the clipboard for a moment is no copy.
		if got, err = Paste(ctx, g.hub); err == nil && got != own {
			err = fmt.Errorf("after the paste %s holds %s, not the text copied before it", g.hub.Name, describe(got))
		}
		return err
	}
	exact := fmt.Sprintf("cbb-bench %s T5 \u041f\u0440\u0438\u0432\u0435\u0442 \U0001F44B\U0001F3FD e\u0301 \u05e9\u05dc\u05d5\u05dd \u65e5\u672c\u8a9e\n\ttabbed\nlast line", g.run)
	type sent struct {
		name, flags, text string
		secret            bool
	}
	cases := []sent{
		{"paste", "", exact, false},
		{"type", " -type", exact, false},
		{"paste-1MiB", "", fill("cbb-bench "+g.run+" T5 1 MiB pasted ", 1<<20-16), false},
		{"type-4KiB", " -type", fill("cbb-bench "+g.run+" T5 4 KiB typed ", 4<<10), false},
		{"T11-secret", " -secret", fmt.Sprintf("cbb-bench %s T11 secret pasted", g.run), true},
	}
	var done []sent
	for _, c := range cases {
		if r.Do(p+d.Name+"/"+c.name, func() error {
			if err := paste(c.flags, c.text); err != nil {
				return err
			}
			if err := inBox(c.text); err != nil {
				return err
			}
			if c.flags == " -type" {
				return nil
			}
			return ownBack()
		}) == nil {
			done = append(done, c)
		}
	}
	r.Do("desktop/T11-secret-not-logged/"+d.Name, func() error {
		secret := cases[len(cases)-1].text
		out, err := Run(ctx, d, `Get-Content -Raw -ErrorAction SilentlyContinue "$env:ProgramData\cbb\logs\service.log"; Get-Content -Raw -ErrorAction SilentlyContinue "$env:LOCALAPPDATA\cbb\agent.log"`, "")
		if err != nil {
			return err
		}
		if strings.Contains(out, secret) {
			return errors.New("a log holds the secret that was pasted")
		}
		return nil
	})
	r.Do("desktop/T12-log/"+d.Name, func() error {
		hubID, err := deviceOf(ctx, g.hub)
		if err != nil {
			return err
		}
		raw, err := Run(ctx, d, `[IO.File]::ReadAllText("$env:ProgramData\cbb\state\pastes.json")`, "")
		if err != nil {
			return err
		}
		for _, c := range cases {
			if strings.Contains(raw, strings.SplitN(c.text, "\n", 2)[0]) {
				return fmt.Errorf("the log of pastes holds the text of %s", c.name)
			}
		}
		var es []struct {
			By     string `json:"by"`
			Len    int    `json:"len"`
			Method string `json:"method"`
			Result string `json:"result"`
		}
		if err := json.Unmarshal([]byte(raw), &es); err != nil {
			return fmt.Errorf("pastes.json: %w", err)
		}
		if len(es) < len(done) {
			return fmt.Errorf("the log of pastes has %d entries, fewer than the %d pastes", len(es), len(done))
		}
		es = es[len(es)-len(done):]
		for i, c := range done {
			method := "paste"
			if c.flags == " -type" {
				method = "type"
			}
			e := es[i]
			if e.By != hubID || e.Len != len(c.text) || e.Method != method || e.Result != "done" {
				return fmt.Errorf("the log's entry for %s is %+v, not by %s, %d bytes, %s, done", c.name, e, hubID, len(c.text), method)
			}
		}
		return nil
	})
}

// fill repeats s and cuts it to n bytes, not in the middle of a line.
func fill(s string, n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, "%s%d\n", s, i)
	}
	return b.String()[:n-1] + "x"
}

// clearBox empties the paste target's window and waits until it is.
func clearBox(ctx context.Context, d *Device) error {
	if _, err := Run(ctx, d, fmt.Sprintf(`New-Item -Force '%s\box.clear' | Out-Null`, winBench), ""); err != nil {
		return err
	}
	return eventually(ctx, 10*time.Second, func() error {
		got, err := boxText(ctx, d)
		if err == nil && got != "" {
			err = fmt.Errorf("the paste target's window still holds %s", describe(got))
		}
		return err
	})
}

// boxText returns what the paste target's window holds.
func boxText(ctx context.Context, d *Device) (string, error) {
	out, err := Run(ctx, d, fmt.Sprintf(`[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s\box.out'))`, winBench), "")
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	return string(b), err
}
