// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fakeTimers moves the timers' files into a folder of the test and records
// the commands run instead of running them; fail makes a command fail.
func fakeTimers(t *testing.T) (dir string, ran *[]string, fail *string) {
	t.Helper()
	dir = t.TempDir()
	saved := []*string{&systemdService, &systemdTimer, &launchdPlist, &cronFreeBSD, &cronOpenWrt}
	old := make([]string, len(saved))
	for i, p := range saved {
		old[i] = *p
		*p = filepath.Join(dir, strings.TrimPrefix(*p, "/"))
	}
	oldRun := run
	var cmds []string
	var bad string
	run = func(name string, args ...string) error {
		c := strings.Join(append([]string{name}, args...), " ")
		cmds = append(cmds, c)
		if bad != "" && strings.Contains(c, bad) {
			return errors.New(c + ": failed")
		}
		return nil
	}
	t.Cleanup(func() {
		for i, p := range saved {
			*p = old[i]
		}
		run = oldRun
	})
	return dir, &cmds, &bad
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gone(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there: %v", p, err)
		}
	}
}

// TestSystemdTimer: on writes a oneshot service running cbb update -timer
// and a daily timer with a random delay, and enables the timer; off
// disables and removes both. A rootless install writes the user's units.
func TestSystemdTimer(t *testing.T) {
	_, ran, fail := fakeTimers(t)
	if err := systemdTimers(true, "/usr/local/bin/cbb"); err != nil {
		t.Fatal(err)
	}
	if s := read(t, systemdService); !strings.Contains(s, "ExecStart=/usr/local/bin/cbb update -timer") || !strings.Contains(s, "Type=oneshot") {
		t.Errorf("the service:\n%s", s)
	}
	if s := read(t, systemdTimer); !strings.Contains(s, "OnCalendar=daily") || !strings.Contains(s, "RandomizedDelaySec=6h") {
		t.Errorf("the timer:\n%s", s)
	}
	if want := []string{"systemctl daemon-reload", "systemctl enable --now cbb-update.timer"}; !slices.Equal(*ran, want) {
		t.Errorf("ran %q, want %q", *ran, want)
	}

	*ran = nil
	if err := systemdTimers(false, ""); err != nil {
		t.Fatal(err)
	}
	gone(t, systemdService, systemdTimer)
	if want := []string{"systemctl disable --now cbb-update.timer", "systemctl daemon-reload"}; !slices.Equal(*ran, want) {
		t.Errorf("ran %q, want %q", *ran, want)
	}
	// Off again, with nothing there, is fine.
	if err := systemdTimers(false, ""); err != nil {
		t.Errorf("off twice: %v", err)
	}

	// A failing enable is the answer.
	*fail = "enable"
	if err := systemdTimers(true, "/usr/local/bin/cbb"); err == nil || !strings.Contains(err.Error(), "enable") {
		t.Errorf("a failed enable: %v", err)
	}
}

// TestLaunchdTimer: on writes a launch daemon at a time between 01:00 and
// 06:59, its path escaped for XML, and bootstraps it; off removes it.
func TestLaunchdTimer(t *testing.T) {
	_, ran, fail := fakeTimers(t)
	if err := os.MkdirAll(filepath.Dir(launchdPlist), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := launchdTimer(true, "/Applications/R&D <cbb>/cbb"); err != nil {
		t.Fatal(err)
	}
	p := read(t, launchdPlist)
	if !strings.Contains(p, "<string>/Applications/R&amp;D &lt;cbb&gt;/cbb</string>") || !strings.Contains(p, "<string>"+launchdLabel+"</string>") {
		t.Errorf("the plist:\n%s", p)
	}
	m := regexp.MustCompile(`<key>Hour</key>\s*<integer>(\d+)</integer>\s*<key>Minute</key>\s*<integer>(\d+)</integer>`).FindStringSubmatch(p)
	if m == nil || m[1] < "1" || m[1] > "6" || len(m[1]) != 1 || len(m[2]) > 2 {
		t.Errorf("the time: %q", m)
	}
	if want := []string{"launchctl bootout system/" + launchdLabel, "launchctl bootstrap system " + launchdPlist}; !slices.Equal(*ran, want) {
		t.Errorf("ran %q, want %q", *ran, want)
	}
	if err := launchdTimer(false, ""); err != nil {
		t.Fatal(err)
	}
	gone(t, launchdPlist)
	*fail = "bootstrap"
	if err := launchdTimer(true, "/usr/local/bin/cbb"); err == nil {
		t.Error("a failed bootstrap passed")
	}
}

// TestFreeBSDTimer: on writes a line of cron.d at the device's own time;
// off removes it.
func TestFreeBSDTimer(t *testing.T) {
	_, ran, _ := fakeTimers(t)
	if err := freebsdTimer(true, "/usr/local/bin/cbb"); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^[0-5]?\d [1-6] \* \* \* root /usr/local/bin/cbb update -timer$`).MatchString(read(t, cronFreeBSD)) {
		t.Errorf("the cron line:\n%s", read(t, cronFreeBSD))
	}
	if len(*ran) != 0 {
		t.Errorf("ran %q: cron reads cron.d by itself", *ran)
	}
	if err := freebsdTimer(false, ""); err != nil {
		t.Fatal(err)
	}
	gone(t, cronFreeBSD)
}

// TestOpenWrtTimer: on adds one marked line to root's crontab beside the
// user's own lines, a second on replaces it, and off takes only it away.
func TestOpenWrtTimer(t *testing.T) {
	_, ran, fail := fakeTimers(t)
	if err := os.MkdirAll(filepath.Dir(cronOpenWrt), 0o755); err != nil {
		t.Fatal(err)
	}
	own := "0 4 * * * /sbin/reboot\n"
	if err := os.WriteFile(cronOpenWrt, []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := openwrtTimer(true, "/usr/bin/cbb"); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(read(t, cronOpenWrt)), "\n")
	if len(lines) != 2 || lines[0] != strings.TrimSpace(own) || !regexp.MustCompile(`^[0-5]?\d [1-6] \* \* \* /usr/bin/cbb update -timer # cbb-update$`).MatchString(lines[1]) {
		t.Errorf("the crontab: %q", lines)
	}
	if !slices.Contains(*ran, "/etc/init.d/cron enable") || (*ran)[len(*ran)-1] != "/etc/init.d/cron restart" {
		t.Errorf("ran %q", *ran)
	}
	if err := openwrtTimer(false, ""); err != nil {
		t.Fatal(err)
	}
	if got := read(t, cronOpenWrt); got != own {
		t.Errorf("after off the crontab is %q, not %q", got, own)
	}
	// Without a crontab, off leaves an empty one; a failing restart is the answer.
	os.Remove(cronOpenWrt)
	*fail = "restart"
	if err := openwrtTimer(false, ""); err == nil {
		t.Error("a failed restart passed")
	}
	if got := read(t, cronOpenWrt); got != "" {
		t.Errorf("off without a crontab wrote %q", got)
	}
}

// TestRemoveAll: missing files are fine, other failures are not.
func TestRemoveAll(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o644)
	if err := removeAll(f, filepath.Join(dir, "missing")); err != nil {
		t.Fatal(err)
	}
	gone(t, f)
	full := filepath.Join(dir, "full")
	os.MkdirAll(filepath.Join(full, "x"), 0o755)
	if err := removeAll(full); err == nil {
		t.Error("removing a folder with files in it passed")
	}
}
