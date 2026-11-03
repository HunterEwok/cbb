// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/openwrt"
	"github.com/HunterEwok/cbb/internal/rootless"
	"github.com/HunterEwok/cbb/internal/steamos"
)

// ArchiveName returns the release's archive for this system, as
// packaging/archive.sh names it.
func ArchiveName() string {
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7"
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "GOARM" && strings.HasPrefix(s.Value, "6") {
					arch = "armv6"
				}
			}
		}
	}
	if runtime.GOOS == "windows" {
		return "cbb-windows-" + arch + ".zip"
	}
	return "cbb-" + runtime.GOOS + "-" + arch + ".tar.gz"
}

// Programs returns the installed programs, the main one first: this cbb,
// and on Windows cbb.exe and the windowless cbbw.exe of its folder. exe is
// this program, os.Executable when "".
func Programs(exe string) ([]string, error) {
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, err
		}
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if runtime.GOOS == "windows" {
		dir := filepath.Dir(exe)
		return []string{filepath.Join(dir, "cbb.exe"), filepath.Join(dir, "cbbw.exe")}, nil
	}
	return []string{exe}, nil
}

// DetectMethod returns how this copy was installed: what the installer
// recorded, unless the program itself shows otherwise.
func DetectMethod(recorded, exe string) string {
	if os.Getenv("CBB_CONTAINER") != "" {
		return MethodDocker
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	p := strings.ReplaceAll(exe, `\`, "/")
	switch {
	case strings.Contains(p, "/Cellar/") || strings.Contains(p, "/linuxbrew/") || strings.Contains(p, "/homebrew/"):
		return MethodBrew
	case strings.Contains(strings.ToLower(p), "/microsoft/winget/"):
		return MethodWinget
	}
	if recorded != "" {
		return recorded
	}
	return MethodGet
}

// MethodCommands returns what to run to update an installation of method,
// which cbb update does not replace itself.
func MethodCommands(method string) []string {
	switch method {
	case MethodBrew:
		if runtime.GOOS == "darwin" {
			return []string{"brew upgrade cbb",
				`sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/macos/install.sh" --in-place "$(brew --prefix)/opt/cbb/bin/cbb"`}
		}
		return []string{"brew upgrade cbb",
			`sudo sh "$(brew --prefix)/opt/cbb/share/cbb/packaging/linux/install.sh" "$(brew --prefix)/opt/cbb/bin/cbb"`}
	case MethodWinget:
		return []string{"winget upgrade HunterEwok.cbb", "cbb install (in a terminal opened as administrator)"}
	case MethodDocker:
		return []string{"docker compose pull && docker compose up -d"}
	case MethodPackage:
		if openwrt.Is() {
			return []string{"apk update && apk upgrade cbb"}
		}
		return []string{"the package manager that installed it"}
	}
	return nil
}

// Healthy waits until the service answers on its socket with version,
// asking every second until ctx ends.
func Healthy(ctx context.Context, version string) error {
	want := " v" + version + " "
	var last error
	for {
		v, err := serviceVersion()
		switch {
		case err != nil:
			// Not the hint to start the service: the previous version
			// goes back in and starts. The cause stays for debug mode.
			var de *control.DialError
			if errors.As(err, &de) {
				err = &control.DialError{Msg: "it does not answer; the system's service log tells why", Denied: de.Denied, Err: de.Err}
			}
			last = err
		case strings.Contains(v+" ", want):
			return nil
		default:
			last = fmt.Errorf("it runs %s", v)
		}
		select {
		case <-ctx.Done():
			if last == nil {
				last = ctx.Err()
			}
			return last
		case <-time.After(time.Second):
		}
	}
}

func serviceVersion() (string, error) {
	c, err := control.DialFor(control.OpStatus)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err != nil {
		return "", err
	}
	if m.Status == nil {
		return "", errors.New("the service sent no status")
	}
	return m.Status.Version, nil
}

// Paths returns the updater's directories: Dir keeps update.json, which
// only root or SYSTEM may change, and Work the downloads. Neither is under
// the service's own folders, which its account may change.
func Paths() (dir, work string) {
	switch runtime.GOOS {
	case "darwin":
		dir = "/Library/Application Support/cbb-update"
	case "freebsd":
		dir = "/var/db/cbb-update"
	case "windows":
		// Not under Program Files\cbb: install.ps1 stops
		// every program there, and cbb update runs from this folder.
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		dir = filepath.Join(pf, "cbb-update")
	default:
		if openwrt.Is() {
			// /etc survives a sysupgrade; the downloads go to RAM.
			return "/etc/cbb-update", "/tmp/cbb-update"
		}
		if rootless.Is() {
			return rootless.UpdateDir(), rootless.UpdateDir()
		}
		if steamos.Is() {
			// /var is small on SteamOS; /opt lives in /home.
			return steamos.Dir + "-update", steamos.Dir + "-update"
		}
		dir = "/var/lib/cbb-update"
	}
	return dir, dir
}

// InstallScript returns the installer for this system in an unpacked
// archive's top folder.
func InstallScript(root string) string {
	switch {
	case runtime.GOOS == "windows":
		return filepath.Join(root, "packaging", "windows", "install.ps1")
	case runtime.GOOS == "darwin":
		return filepath.Join(root, "packaging", "macos", "install.sh")
	case runtime.GOOS == "freebsd":
		return filepath.Join(root, "packaging", "freebsd", "install.sh")
	case openwrt.Is():
		return filepath.Join(root, "packaging", "openwrt", "install.sh")
	}
	return filepath.Join(root, "packaging", "linux", "install.sh")
}

// Install runs the installer in the unpacked archive root on the program
// bin, with the environment of an update: no question but those never
// answered, and CBB_UPDATING set so that it does not ask about automatic
// updates. The installers keep the port and the other settings.
func Install(ctx context.Context, root, bin string) error {
	script := InstallScript(root)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Bin", bin)
	} else {
		args := []string{script, bin}
		if rootless.Is() {
			args = []string{script, "--rootless", bin}
		}
		cmd = exec.CommandContext(ctx, "sh", args...)
	}
	cmd.Env = append(os.Environ(), "CBB_UPDATING=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(script), err, installFailure(string(out), filepath.Base(script)))
	}
	return nil
}

// installFailure picks what an installer that failed says: its line
// "install.ps1: STEP failed: ...", or else its last lines, as an error's
// details may follow that line.
func installFailure(out, script string) string {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); strings.HasPrefix(l, script+": ") && strings.Contains(l, " failed: ") {
			return strings.TrimPrefix(l, script+": ")
		}
	}
	return strings.TrimSpace(lastLines(out, 5))
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
