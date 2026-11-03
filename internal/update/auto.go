// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/openwrt"
	"github.com/HunterEwok/cbb/internal/rootless"
)

// The timers that run cbb update -timer once a day, at a time of their
// own on each device, so that the update servers learn little from when a
// device asks.
const (
	systemdService = "/etc/systemd/system/cbb-update.service"
	systemdTimer   = "/etc/systemd/system/cbb-update.timer"
	launchdLabel   = "tools.cbb.update"
	launchdPlist   = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	cronFreeBSD    = "/usr/local/etc/cron.d/cbb-update"
	cronOpenWrt    = "/etc/crontabs/root"
	cronMark       = "# cbb-update"
	windowsTask    = "cbb update"
)

// SetTimer adds the timer that runs exe update -timer, or removes it.
func SetTimer(on bool, exe string) error {
	switch {
	case runtime.GOOS == "darwin":
		return launchdTimer(on, exe)
	case runtime.GOOS == "windows":
		return windowsTimer(on, exe)
	case runtime.GOOS == "freebsd":
		return freebsdTimer(on, exe)
	case openwrt.Is():
		return openwrtTimer(on, exe)
	case runtime.GOOS == "linux":
		return systemdTimers(on, exe)
	}
	return fmt.Errorf("automatic updates are not built for %s", runtime.GOOS)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeAll(paths ...string) error {
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// systemdTimers writes the system's units, or for a rootless install the
// user's own.
func systemdTimers(on bool, exe string) error {
	unit, timerUnit, systemctl := systemdService, systemdTimer, []string{}
	if rootless.Is() {
		unit = filepath.Join(rootless.UnitDir(), filepath.Base(systemdService))
		timerUnit = filepath.Join(rootless.UnitDir(), filepath.Base(systemdTimer))
		systemctl = []string{"--user"}
	}
	ctl := func(args ...string) error {
		return run("systemctl", append(append([]string{}, systemctl...), args...)...)
	}
	if !on {
		ctl("disable", "--now", filepath.Base(timerUnit))
		if err := removeAll(timerUnit, unit); err != nil {
			return err
		}
		return ctl("daemon-reload")
	}
	service := `# Written by cbb update -auto on; cbb update -auto off removes it.
[Unit]
Description=CBB automatic update
Documentation=https://github.com/HunterEwok/cbb/blob/main/docs/guide/install.md
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# No sandbox: it runs the new release's install.sh, which changes the
# system as installing does. cbb update connects only to the update servers.
ExecStart=` + exe + ` update -timer
`
	timer := `# Written by cbb update -auto on; cbb update -auto off removes it.
[Unit]
Description=Check for a CBB update once a day

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
`
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		return err
	}
	if err := atomicfile.Write(unit, []byte(service), 0o644); err != nil {
		return err
	}
	if err := atomicfile.Write(timerUnit, []byte(timer), 0o644); err != nil {
		return err
	}
	if err := ctl("daemon-reload"); err != nil {
		return err
	}
	return ctl("enable", "--now", filepath.Base(timerUnit))
}

// at returns a time of day of this device's own for cron and launchd, which
// have no random delay: between 01:00 and 06:59.
func at() (hour, minute int) { return 1 + rand.IntN(6), rand.IntN(60) }

func launchdTimer(on bool, exe string) error {
	exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	if !on {
		return removeAll(launchdPlist)
	}
	h, m := at()
	var b bytes.Buffer
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by cbb update -auto on; cbb update -auto off removes it. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>update</string>
		<string>-timer</string>
	</array>
	<key>StartCalendarInterval</key>
	<dict>
		<key>Hour</key>
		<integer>%d</integer>
		<key>Minute</key>
		<integer>%d</integer>
	</dict>
</dict>
</plist>
`, launchdLabel, xmlEscape(exe), h, m)
	if err := atomicfile.Write(launchdPlist, b.Bytes(), 0o644); err != nil {
		return err
	}
	return run("launchctl", "bootstrap", "system", launchdPlist)
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func freebsdTimer(on bool, exe string) error {
	if !on {
		return removeAll(cronFreeBSD)
	}
	h, m := at()
	line := fmt.Sprintf("# Written by cbb update -auto on; cbb update -auto off removes it.\n%d %d * * * root %s update -timer\n", m, h, exe)
	if err := os.MkdirAll(filepath.Dir(cronFreeBSD), 0o755); err != nil {
		return err
	}
	// cron reads the folder again by itself.
	return atomicfile.Write(cronFreeBSD, []byte(line), 0o644)
}

func openwrtTimer(on bool, exe string) error {
	data, err := os.ReadFile(cronOpenWrt)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if l != "" && !strings.HasSuffix(l, cronMark) {
			keep = append(keep, l)
		}
	}
	if on {
		h, m := at()
		keep = append(keep, fmt.Sprintf("%d %d * * * %s update -timer %s", m, h, exe, cronMark))
	}
	out := strings.Join(keep, "\n")
	if out != "" {
		out += "\n"
	}
	if err := os.MkdirAll(filepath.Dir(cronOpenWrt), 0o755); err != nil {
		return err
	}
	if err := atomicfile.Write(cronOpenWrt, []byte(out), 0o600); err != nil {
		return err
	}
	if on {
		exec.Command("/etc/init.d/cron", "enable").Run()
	}
	return run("/etc/init.d/cron", "restart")
}

func windowsTimer(on bool, exe string) error {
	// Unregister-ScheduledTask fails without the task, whatever its
	// ErrorAction says.
	script := "if (Get-ScheduledTask -TaskName '" + windowsTask + "' -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName '" + windowsTask + "' -Confirm:$false }"
	if on {
		// The windowless cbbw.exe beside cbb.exe: no console flashes up.
		w := filepath.Join(filepath.Dir(exe), "cbbw.exe")
		script = `$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute '` + strings.ReplaceAll(w, "'", "''") + `' -Argument 'update -timer'
$t = New-ScheduledTaskTrigger -Daily -At 1am -RandomDelay (New-TimeSpan -Hours 6)
$p = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName '` + windowsTask + `' -Description 'Checks for a CBB update once a day (cbb update -auto off removes it).' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null`
	}
	return run("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}
