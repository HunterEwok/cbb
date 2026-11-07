// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// macHelper is the root helper that tools/bench/setup-mac.sh installs on a
// Mac, the one program there besides cbb that the bench runs with sudo.
const macHelper = "/usr/local/libexec/cbbbench/cbbbench-root"

// stateBase is where the bench keeps the builds it copied to a device, one
// directory per archive's checksum, so that a second reset with the same
// build copies nothing.
const stateBase = "$HOME/.cache/cbbbench"

// winStateBase is stateBase on Windows, in PowerShell.
const winStateBase = "$env:LOCALAPPDATA\\cbbbench"

// Build is the build under test: the release archives in a directory, as
// the release workflow and CI make them (packaging/archive.sh,
// member/packaging/archive.sh), checked against its SHA256SUMS.
type Build struct {
	dir    string
	sums   map[string]string // archive name to its SHA-256
	signed bool              // SHA256SUMS.sig is there, for a Mac's helper
}

// LoadBuild reads the archives of dir and checks each one that SHA256SUMS
// names.
func LoadBuild(dir string) (*Build, error) {
	b := &Build{dir: dir, sums: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read the build: %w", err)
	}
	want := map[string]string{}
	if f, err := os.Open(filepath.Join(dir, "SHA256SUMS")); err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			if sum, name, ok := strings.Cut(strings.TrimSpace(s.Text()), "  "); ok {
				want[strings.TrimPrefix(name, "*")] = sum
			}
		}
		f.Close()
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tar.gz") && !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		sum, err := fileSum(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if w, ok := want[e.Name()]; ok && w != sum {
			return nil, fmt.Errorf("%s does not match SHA256SUMS", e.Name())
		}
		b.sums[e.Name()] = sum
	}
	if len(b.sums) == 0 {
		return nil, fmt.Errorf("the build %s has no .tar.gz or .zip archives", dir)
	}
	_, err = os.Stat(filepath.Join(dir, "SHA256SUMS.sig"))
	b.signed = err == nil
	return b, nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// archiveFor names the archive a device installs, for the CPU uname -m
// reports (on Windows, PROCESSOR_ARCHITECTURE).
func archiveFor(d *Device, machine string) (string, error) {
	machine = strings.ToLower(machine)
	arch := map[string]string{"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "armv7", "armv6l": "armv6"}[machine]
	if arch == "" && d.OS != "openwrt" {
		return "", fmt.Errorf("%s: no build for the CPU %q", d.Name, machine)
	}
	switch d.OS {
	case "openwrt":
		if arch = openwrtArch(machine); arch == "" {
			return "", fmt.Errorf("%s: no build for OpenWrt's architecture %q", d.Name, machine)
		}
		return "cbb-linux-" + arch + ".tar.gz", nil
	case "freebsd":
		if arch != "amd64" && arch != "arm64" {
			return "", fmt.Errorf("%s: no FreeBSD build for the CPU %q", d.Name, machine)
		}
		return "cbb-freebsd-" + arch + ".tar.gz", nil
	case "linux", "docker", "netns":
		return "cbb-linux-" + arch + ".tar.gz", nil
	case "linux-lite":
		return "cbb-lite-linux-" + arch + ".tar.gz", nil
	case "darwin":
		return "cbb-darwin-" + arch + ".tar.gz", nil
	case "windows":
		return "cbb-windows-" + arch + ".zip", nil
	}
	return "", fmt.Errorf("%s: the bench does not reset os %s yet", d.Name, d.OS)
}

// Reset (R1) puts every device in no group with the build under test, all
// at once: the archive goes to each device once per build, the old install
// is removed with its keys, the new one installed, and the bench waits until
// the service answers in no group. With quick and no build, each device
// keeps its install and only loses its state: the same build, a clean
// group, without checking the installer again.
func Reset(ctx context.Context, r *Report, devices []*Device, b *Build, quick bool) {
	if b == nil && !quick {
		r.Do("reset/setup", func() error { return errors.New("reset needs -build DIR with the release archives, or -quick") })
		return
	}
	var wg sync.WaitGroup
	for _, d := range devices {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.Do("reset/"+d.Name, func() error { return resetDevice(ctx, r, d, b, quick) }) != nil {
				return
			}
			r.Do("reset/"+d.Name+"/no-group", func() error {
				return eventually(ctx, 30*time.Second, func() error {
					tag, err := groupOf(ctx, d)
					if err == nil && tag != "" {
						err = fmt.Errorf("%s is still in group %s", d.Name, tag)
					}
					return err
				})
			})
		}()
	}
	wg.Wait()
}

func resetDevice(ctx context.Context, r *Report, d *Device, b *Build, quick bool) error {
	switch d.OS {
	case "linux", "linux-lite":
		if quick {
			_, err := Run(ctx, d, "sudo -n sh -c 'systemctl stop cbb && rm -rf /var/lib/cbb/* /etc/systemd/system/cbb.service.d && systemctl daemon-reload && systemctl start cbb'", "")
			if err != nil {
				return noSudo(d, err)
			}
			return nil
		}
		if d.Firewall != "yes" && d.Firewall != "no" {
			return fmt.Errorf("%s: set firewall = \"yes\" (the installer opens the member port) or \"no\" (it leaves the firewall alone) in the inventory", d.Name)
		}
		dir, err := stage(ctx, d, b)
		if err != nil {
			return err
		}
		if _, err := RunFor(ctx, d, "[ ! -f /usr/local/share/cbb/uninstall.sh ] || sudo -n sh /usr/local/share/cbb/uninstall.sh --purge", "", 2*time.Minute); err != nil {
			return noSudo(d, err)
		}
		r.Do("reset/"+d.Name+"/L10-clean", func() error { return uninstalled(ctx, d) })
		opt := "--express"
		if d.Firewall == "no" {
			opt = "--no-firewall"
		}
		if _, err := RunFor(ctx, d, "sudo -n env CBB_FIREWALL= sh "+dir+"/packaging/linux/install.sh "+opt+" "+dir+"/cbb", "", 2*time.Minute); err != nil {
			return err
		}
		return agentRuns(ctx, r, d)
	case "darwin":
		// Only the helper runs as root here; it installs only an archive
		// whose checksum is signed by the bench's key or trusted (setup-mac.sh).
		dir, err := stage(ctx, d, b)
		if err != nil {
			return err
		}
		install := macHelper + " install " + dir + "/archive.tar.gz"
		if b.signed {
			// The build's sums and their signature by the bench's key, so
			// a new build needs no password on the Mac.
			for _, f := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
				data, err := os.ReadFile(filepath.Join(b.dir, f))
				if err != nil {
					return err
				}
				if _, err := Run(ctx, d, "cat > "+dir+"/"+f, string(data)); err != nil {
					return err
				}
			}
			install += " " + dir + "/SHA256SUMS " + dir + "/SHA256SUMS.sig"
		}
		if _, err := RunFor(ctx, d, "sudo -n "+macHelper+" purge && sudo -n "+install, "", 2*time.Minute); err != nil {
			return noSudo(d, err)
		}
		// The pasteboard agent runs in the signed-in user's session; a
		// build without the pasteboard (no cgo) exits there at once.
		r.Do("reset/"+d.Name+"/agent", func() error {
			return eventually(ctx, 15*time.Second, func() error {
				out, err := Run(ctx, d, "launchctl print gui/$(id -u)/tools.cbb.agent 2>&1 | grep -m1 -E '^\\s*state = '; true", "")
				if err == nil && !strings.Contains(out, "running") {
					err = fmt.Errorf("the pasteboard agent does not run in the session: %s", strings.TrimSpace(out))
				}
				return err
			})
		})
		return nil
	case "docker":
		if quick {
			out, err := Run(ctx, d, "docker inspect -f '"+composeLabels+"' "+d.Container, "")
			if err != nil {
				return err
			}
			compose := composeCmd(strings.TrimSpace(out))
			if compose == "" {
				return errors.New("docker compose did not start the container")
			}
			// The volume goes with the container, and with it the state.
			_, err = RunFor(ctx, d, compose+" down -v && "+compose+" up -d", "", 2*time.Minute)
			return err
		}
		if d.Setup == "" {
			return fmt.Errorf("%s: set setup to the path of tools/bench/setup-docker.sh on its host in the inventory", d.Name)
		}
		dir, err := stage(ctx, d, b)
		if err != nil {
			return err
		}
		_, err = RunFor(ctx, d, "sh "+d.Setup+" up "+dir+"/cbb", "", 5*time.Minute)
		return err
	case "netns":
		if d.Setup == "" {
			return fmt.Errorf("%s: set setup to the path of tools/bench/setup-netns.sh on its host in the inventory", d.Name)
		}
		if quick {
			_, err := Run(ctx, d, "sudo -n sh "+d.Setup+" down "+d.Name+" && sudo -n systemctl start "+netnsUnit(d), "")
			return noSudo(d, err)
		}
		dir, err := stage(ctx, d, b)
		if err != nil {
			return err
		}
		_, err = RunFor(ctx, d, "sudo -n sh "+d.Setup+" up "+d.Name+" "+dir+"/cbb", "", 2*time.Minute)
		return noSudo(d, err)
	case "openwrt", "freebsd":
		return resetRouterOrBSD(ctx, r, d, b, quick)
	case "windows":
		return resetWindows(ctx, r, d, b, quick)
	}
	return Skipped("the bench does not reset os " + d.OS + " yet; reset it by hand (docs/testbench-cases.md, R1)")
}

// resetRouterOrBSD is R1 on OpenWrt and FreeBSD: uninstall.sh --purge, a
// check that it left nothing, and the platform's installer. A quick reset
// stops the service, empties its state and starts it again.
func resetRouterOrBSD(ctx context.Context, r *Report, d *Device, b *Build, quick bool) error {
	state, err := stateDir(ctx, d)
	if err != nil {
		return err
	}
	if quick {
		cmd := serviceCmd(d, "stop") + " && " + rootPrefix(d) + "rm -rf " + state + "/*"
		if d.OS == "openwrt" {
			cmd += " /etc/cbb/firewall.hub"
		}
		_, err := Run(ctx, d, cmd+" && "+serviceCmd(d, "start"), "")
		return noSudo(d, err)
	}
	if d.Firewall != "yes" && d.Firewall != "no" && d.OS == "freebsd" {
		return fmt.Errorf("%s: set firewall = \"yes\" (the installer opens the member port) or \"no\" (it leaves the firewall alone) in the inventory", d.Name)
	}
	dir, err := stage(ctx, d, b)
	if err != nil {
		return err
	}
	u := uninstallScript(d)
	if _, err := RunFor(ctx, d, "[ ! -f "+u+" ] || "+rootPrefix(d)+"sh "+u+" --purge", "", 2*time.Minute); err != nil {
		return noSudo(d, err)
	}
	r.Do("reset/"+d.Name+"/L10-clean", func() error { return uninstalled(ctx, d) })
	install := "sh " + dir + "/packaging/openwrt/install.sh " + dir + "/cbb"
	if d.OS == "freebsd" {
		opt := "--express"
		if d.Firewall == "no" {
			opt = "--no-firewall"
		}
		install = "sudo -n sh " + dir + "/packaging/freebsd/install.sh " + opt + " " + dir + "/cbb"
	}
	_, err = RunFor(ctx, d, install, "", 2*time.Minute)
	return err
}

// resetWindows is R1 on Windows: uninstall.ps1 -Purge, a check that it left
// nothing behind, and install.ps1 of the build. The bench user is an
// administrator, and an SSH session signed in with a key has the full token.
func resetWindows(ctx context.Context, r *Report, d *Device, b *Build, quick bool) error {
	if quick {
		// The keys and the group live in state; the folder keeps the
		// access list that install.ps1 gave it.
		_, err := RunFor(ctx, d, `Stop-Service cbb -Force
Get-ChildItem (Join-Path $env:ProgramData 'cbb\state') -Force | Remove-Item -Recurse -Force
Start-Service cbb`, "", 2*time.Minute)
		return err
	}
	if d.Firewall != "yes" && d.Firewall != "no" {
		return fmt.Errorf("%s: set firewall = \"yes\" (the installer adds its rules) or \"no\" (it leaves the firewall alone) in the inventory", d.Name)
	}
	dir, err := stage(ctx, d, b)
	if err != nil {
		return err
	}
	if _, err := RunFor(ctx, d, `$u = Join-Path $env:ProgramFiles 'cbb\uninstall.ps1'
if (Test-Path $u) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $u -Purge -Details }`, "", 2*time.Minute); err != nil {
		return err
	}
	r.Do("reset/"+d.Name+"/L10-clean", func() error { return uninstalledWindows(ctx, d) })
	opt := "-Express"
	if d.Firewall == "no" {
		opt = "-NoFirewall"
	}
	if _, err := RunFor(ctx, d, "Remove-Item Env:CBB_FIREWALL -ErrorAction SilentlyContinue; & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '"+dir+`\packaging\windows\install.ps1' `+opt+" -Details", "", 3*time.Minute); err != nil {
		return err
	}
	// install.ps1 starts the agent in the session of the user signed in
	// at the console, through a scheduled task.
	r.Do("reset/"+d.Name+"/agent", func() error {
		return eventually(ctx, 15*time.Second, func() error {
			out, err := Run(ctx, d, `@(Get-Process cbbw -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 }).Count`, "")
			if err == nil && strings.TrimSpace(out) == "0" {
				err = errors.New("the agent (cbbw.exe agent) does not run in the signed-in session")
			}
			return err
		})
	})
	return nil
}

// uninstalledWindows (L10) checks that uninstall.ps1 -Purge left nothing
// behind: the files, the data with the keys, the service, the group, the
// firewall rules, the sign-in and uninstaller entries and the PATH entry.
func uninstalledWindows(ctx context.Context, d *Device) error {
	out, err := Run(ctx, d, `$n = 'cbb'
$left = @()
foreach ($p in @((Join-Path $env:ProgramFiles $n), (Join-Path $env:ProgramData $n), "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$n")) { if (Test-Path $p) { $left += $p } }
if (Get-Service $n -ErrorAction SilentlyContinue) { $left += 'the service' }
if (Get-LocalGroup $n -ErrorAction SilentlyContinue) { $left += 'the group' }
if (Get-NetFirewallRule -Group $n -ErrorAction SilentlyContinue) { $left += 'firewall rules' }
if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $n -ErrorAction SilentlyContinue) { $left += 'the sign-in entry' }
if (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -contains (Join-Path $env:ProgramFiles $n)) { $left += 'the PATH entry' }
$left -join ', '`, "")
	if err != nil {
		return err
	}
	if left := strings.TrimSpace(out); left != "" {
		return fmt.Errorf("uninstall.ps1 -Purge left %s", left)
	}
	return nil
}

// stage copies the device's archive of the build to it, unless it is
// there from an earlier reset, and returns the directory that holds cbb
// and packaging/ (on a Mac, archive.tar.gz for the helper).
func stage(ctx context.Context, d *Device, b *Build) (string, error) {
	out, err := Run(ctx, d, machineCmd(d), "")
	if err != nil {
		return "", err
	}
	name, err := archiveFor(d, strings.TrimSpace(out))
	if err != nil {
		return "", err
	}
	sum, ok := b.sums[name]
	if !ok {
		return "", fmt.Errorf("the build has no %s for %s", name, d.Name)
	}
	if d.OS == "windows" {
		return stageWindows(ctx, d, b, name, sum)
	}
	base := stageBase(d)
	dir := base + "/" + sum[:16]
	unpack := "tar -xzf - -C " + dir
	if d.OS == "darwin" {
		unpack = "cat > " + dir + "/archive.tar.gz"
	}
	if _, err := Run(ctx, d, "test -f "+dir+"/ok", ""); err != nil {
		data, err := os.ReadFile(filepath.Join(b.dir, name))
		if err != nil {
			return "", err
		}
		// Keep the newest three builds on the device.
		cmd := "mkdir -p " + dir + " && " + unpack + " && touch " + dir + "/ok && cd " + base + " && ls -1t | tail -n +4 | xargs rm -rf"
		if _, err := RunFor(ctx, d, cmd, string(data), 10*time.Minute); err != nil {
			return "", err
		}
	}
	if d.OS == "darwin" {
		return dir, nil
	}
	// The archive holds one directory, cbb or
	// cbb-lite.
	out, err = Run(ctx, d, "ls -d "+dir+"/*/", "")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSpace(firstLine(out)), "/"), nil
}

// stageWindows is stage on Windows: the zip goes over with scp, as the
// standard input of a PowerShell command over Windows' OpenSSH stalls after
// a few megabytes, and is unpacked in the bench user's LOCALAPPDATA. It
// returns the directory that holds cbb.exe.
func stageWindows(ctx context.Context, d *Device, b *Build, name, sum string) (string, error) {
	dir := winStateBase + "\\" + sum[:16]
	if _, err := Run(ctx, d, "if (-not (Test-Path \""+dir+"\\ok\")) { exit 1 }", ""); err != nil {
		// A fresh directory, and its path as scp takes it: /C:/Users/...
		out, err := Run(ctx, d, `$d = "`+dir+`"
if (Test-Path $d) { Remove-Item -Recurse -Force $d }
'/' + (New-Item -ItemType Directory -Force $d).FullName.Replace('\', '/')`, "")
		if err != nil {
			return "", err
		}
		if err := CopyTo(ctx, d, filepath.Join(b.dir, name), strings.TrimSpace(out)+"/archive.zip", 10*time.Minute); err != nil {
			return "", err
		}
		// Keep the newest three builds on the device.
		cmd := `$d = "` + dir + `"
$zip = Join-Path $d 'archive.zip'
if ((Get-FileHash -Algorithm SHA256 $zip).Hash -ne '` + sum + `') { throw 'the archive arrived damaged' }
Expand-Archive -Path $zip -DestinationPath $d
Remove-Item $zip
New-Item -ItemType File (Join-Path $d 'ok') | Out-Null
Get-ChildItem "` + winStateBase + `" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 | Remove-Item -Recurse -Force`
		if _, err := RunFor(ctx, d, cmd, "", 5*time.Minute); err != nil {
			return "", err
		}
	}
	// The archive holds one directory, cbb.
	out, err := Run(ctx, d, "(Join-Path \""+dir+"\" cbb | Resolve-Path).Path", "")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(firstLine(out)), nil
}

// uninstalled (L10) checks that uninstall.sh --purge left nothing behind.
func uninstalled(ctx context.Context, d *Device) error {
	check := "ls -d " + strings.Join(installedPaths(d), " ") + " 2>/dev/null; "
	switch d.OS {
	case "linux", "linux-lite":
		check += "sudo -n ufw status 2>/dev/null | grep -i cbb; "
	case "openwrt":
		check += "ls /etc/rc.d | grep cbb; grep -l cbb /etc/config/firewall; "
	case "freebsd":
		check += "grep cbb /etc/rc.conf /etc/pf.conf 2>/dev/null; "
	}
	out, err := Run(ctx, d, check+"true", "")
	if err != nil {
		return err
	}
	if left := strings.TrimSpace(out); left != "" {
		return fmt.Errorf("uninstall --purge left %s", strings.ReplaceAll(left, "\n", ", "))
	}
	return nil
}

// agentRuns checks that the installer started the desktop agent in the
// signed-in session, so that nobody has to sign out and in after an install;
// when it did not, the case fails and the bench starts the agent itself, so
// the run can go on.
func agentRuns(ctx context.Context, r *Report, d *Device) error {
	if d.OS != "linux" || (d.Clipboard != "x11" && d.Clipboard != "wayland") {
		return nil
	}
	if r.Do("reset/"+d.Name+"/agent", func() error {
		return eventually(ctx, 10*time.Second, func() error {
			_, err := Run(ctx, d, `pgrep -x -u "$(id -u)" cbb >/dev/null`, "")
			if err != nil {
				return errors.New("the installer did not start the desktop agent in the signed-in session")
			}
			return nil
		})
	}) == nil {
		return nil
	}
	return restartAgent(ctx, d)
}

// restartAgent starts the desktop agent in the signed-in session. The SSH
// session has the cbb group that the installer gave the user.
func restartAgent(ctx context.Context, d *Device) error {
	_, err := Run(ctx, d, `id -nG | grep -qw cbb || { echo "the user is not in the cbb group; sign in again" >&2; exit 1; }
pkill -x -u "$(id -u)" cbb; sleep 0.5
env=$(systemctl --user show-environment | grep -E '^(DISPLAY|WAYLAND_DISPLAY|XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS|XAUTHORITY|XDG_SESSION_TYPE|XDG_CURRENT_DESKTOP)=')
echo "$env" | grep -q '^DISPLAY=\|^WAYLAND_DISPLAY=' || { echo "nobody is signed in on the desktop" >&2; exit 1; }
env $env setsid -f /usr/local/bin/cbb agent </dev/null >/dev/null 2>&1
sleep 1; pgrep -x -u "$(id -u)" cbb >/dev/null || { echo "the agent did not start" >&2; exit 1; }`, "")
	return err
}
