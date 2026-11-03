// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Members with systemd (the installer's and the feed's cases, I1 to I12): a
// container that boots systemd, as a Linux computer does, with no cbb until
// the case installs one from a release archive with install.sh or get.sh.
const systemdImage = "cbbbench-systemd:3"

const systemdDockerfile = `FROM debian:stable-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus iproute2 iptables nftables procps curl ca-certificates openssl tmux ufw avahi-daemon avahi-utils && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
`

// AddSystemd starts a container that boots systemd on the network net and
// waits until the system runs.
func (f *Fleet) AddSystemd(ctx context.Context, net string) (*Device, error) {
	if _, err := docker(ctx, "image", "inspect", systemdImage); err != nil {
		c := exec.CommandContext(ctx, "docker", "build", "-q", "-t", systemdImage, "-")
		c.Stdin = strings.NewReader(systemdDockerfile)
		if out, err := c.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("cannot build the image with systemd: %v: %s", err, out)
		}
	}
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	name := fmt.Sprintf("%s-%02d", f.run, n)
	args := []string{"run", "-d", "--name", name, "--hostname", fmt.Sprintf("m%02d", n),
		"--network", net, "--label", "cbbbench=fleet",
		// systemd as PID 1 needs the cgroups and a /run of its own.
		"--privileged", "--cgroupns=host", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"--tmpfs", "/run", "--tmpfs", "/run/lock"}
	if fleetCoverDir != "" {
		// The unit's environment does not reach the service; the case
		// that wants coverage adds GOCOVERDIR to cbb.env.
		args = append(args, "-v", fleetCoverDir+":/cover")
	}
	if _, err := docker(ctx, append(args, systemdImage)...); err != nil {
		return nil, err
	}
	d := &Device{Name: fmt.Sprintf("m%02d", n), OS: "fleet", Clipboard: "none", Container: name, Roles: []string{"member"}, Network: net}
	f.mu.Lock()
	f.members = append(f.members, d)
	f.mu.Unlock()
	err := eventually(ctx, time.Minute, func() error {
		out, _ := Run(ctx, d, "systemctl is-system-running", "")
		if s := strings.TrimSpace(out); s != "running" && s != "degraded" {
			return fmt.Errorf("systemd on %s is %q", d.Name, s)
		}
		return nil
	})
	return d, err
}

// installArchive copies the release archive in dir to d and runs its
// install.sh with flags, and returns what it printed.
func installArchive(ctx context.Context, d *Device, dir, flags string) (string, error) {
	if _, err := docker(ctx, "cp", dir+"/cbb-linux-"+goarchOf()+".tar.gz", d.Container+":/tmp/cbb.tar.gz"); err != nil {
		return "", err
	}
	return RunFor(ctx, d, "cd /tmp && rm -rf cbb && tar xzf cbb.tar.gz && sh cbb/packaging/linux/install.sh "+flags+" cbb/cbb", "", 3*time.Minute)
}

// runsVersion waits until the service on d answers with version.
func runsVersion(ctx context.Context, d *Device, version string) error {
	return eventually(ctx, 30*time.Second, func() error {
		out, err := Run(ctx, d, "cbb status", "")
		if err != nil {
			return err
		}
		if !strings.Contains(firstLine(out), " v"+version+" ") {
			return fmt.Errorf("%s runs %q, not %s", d.Name, firstLine(out), version)
		}
		return nil
	})
}

// goarchOf is the controller's CPU, which the fleet's containers share.
func goarchOf() string { return runtime.GOARCH }
