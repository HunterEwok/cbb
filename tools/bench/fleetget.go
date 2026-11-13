// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// clockAhead is a date(1) for get.sh that tells the time two days on, so
// that a file signed for a day reads as expired.
const clockAhead = `#!/bin/sh
if [ "$1" = +%s ]; then
	echo $(($(/bin/date +%s) + 2 * 86400))
else
	exec /bin/date "$@"
fi
`

// getScript (I3): get.sh on a computer with nothing installed, against the
// bench's feed: a tampered archive, before and after SHA256SUMS is made
// again, release.json from an unknown key, keys.json from no root, keys.json
// and stable.json expired, no openssl and a CBB_VERSION the release is not
// are each refused with their reason and install nothing; CBB_VERSION of the
// release, and then the latest, install it. get.ps1 is CI's (the windows
// installer job).
func getScript(ctx context.Context, r *Report, f *Fleet, fd *feed, builds map[string]string) {
	const p = "fleet/I3-get/"
	var d *Device
	if r.Do(p+"setup", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, f.net); err != nil {
			return err
		}
		if _, err := docker(ctx, "cp", "packaging/get.sh", d.Container+":/tmp/get.sh"); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(fd.dir, "date"), []byte(clockAhead), 0o755); err != nil {
			return err
		}
		if _, err := Run(ctx, d, "mkdir -p /tmp/ahead", ""); err != nil {
			return err
		}
		_, err = docker(ctx, "cp", filepath.Join(fd.dir, "date"), d.Container+":/tmp/ahead/date")
		return err
	}) != nil {
		return
	}
	// get runs get.sh with env against the feed's folder dir.
	get := func(dir, env string) (string, error) {
		at, err := fd.toDevice(ctx, d, dir)
		if err != nil {
			return "", err
		}
		return runOut(ctx, d, feedEnv(at)+env+" sh /tmp/get.sh --no-firewall", 3*time.Minute)
	}
	archive := "cbb-linux-" + goarchOf() + ".tar.gz"
	for _, c := range []struct {
		name  string
		o     releaseOpts
		spoil func(dir string) error
		env   string
		setup string // a command run before get.sh, and undo after it
		undo  string
		want  string
	}{
		{name: "tampered", spoil: func(dir string) error { return tamper(dir, archive) },
			want: archive + " does not match SHA256SUMS"},
		{name: "tampered-with-sums", spoil: func(dir string) error {
			if err := tamper(dir, archive); err != nil {
				return err
			}
			if out, err := exec.CommandContext(ctx, "sh", "-c", "cd "+dir+" && sha256sum -- *.tar.gz >SHA256SUMS").CombinedOutput(); err != nil {
				return fmt.Errorf("%v: %s", err, out)
			}
			return nil
		}, want: archive + " does not match the signed release.json"},
		{name: "unknown-release-key", o: releaseOpts{relBy: "other"}, want: "release.json is not signed by a release key"},
		{name: "keys-by-no-root", o: releaseOpts{keysBy: "other"}, want: "keys.json is not signed by the project's root key"},
		{name: "keys-expired", o: releaseOpts{keyDays: 1}, env: "PATH=/tmp/ahead:$PATH", want: "keys.json has expired"},
		{name: "channel-expired", o: releaseOpts{keyDays: 30, chanDays: 1}, env: "PATH=/tmp/ahead:$PATH", want: "stable.json has expired"},
		{name: "no-openssl", setup: `mv "$(command -v openssl)" /tmp/openssl.off`, undo: "mv /tmp/openssl.off /usr/bin/openssl",
			want: "openssl is required to check the release's signature"},
		{name: "other-version", env: "CBB_VERSION=v0.6.3", want: "release.json is for 0.6.1, not v0.6.3"},
	} {
		r.Do(p+"refused/"+c.name, func() error {
			dir, err := fd.publish(ctx, builds["0.6.1"], "get-"+c.name, "0.6.1", c.o)
			if err != nil {
				return err
			}
			if c.spoil != nil {
				if err := c.spoil(dir); err != nil {
					return err
				}
			}
			if c.setup != "" {
				if _, err := Run(ctx, d, c.setup, ""); err != nil {
					return err
				}
				defer Run(context.WithoutCancel(ctx), d, c.undo, "")
			}
			out, err := get(dir, c.env)
			fmt.Fprintf(r.out, "I3 %s: %s\n", c.name, strings.Join(strings.Fields(out), " "))
			if err == nil {
				return fmt.Errorf("get.sh installed a release that is %s: %q", c.name, out)
			}
			if !strings.Contains(out, c.want) {
				return fmt.Errorf("get.sh refused a release that is %s with %q, which does not name %q", c.name, out, c.want)
			}
			if out, err := Run(ctx, d, "command -v cbb || ls /usr/local/bin/cbb /usr/bin/cbb 2>/dev/null", ""); err == nil && strings.TrimSpace(out) != "" {
				return fmt.Errorf("a refused get.sh left %q installed", out)
			}
			return nil
		})
	}
	for _, c := range []struct{ name, env string }{{"version", "CBB_VERSION=v0.6.1"}, {"latest", ""}} {
		r.Do(p+"installs/"+c.name, func() error {
			dir, err := fd.publish(ctx, builds["0.6.1"], "get-good-"+c.name, "0.6.1", releaseOpts{})
			if err != nil {
				return err
			}
			out, err := get(dir, c.env)
			if err != nil {
				return err
			}
			if !strings.Contains(out, "The release's signature checks out (0.6.1).") {
				return fmt.Errorf("get.sh printed %q, without that the signature checks out", out)
			}
			return runsVersion(ctx, d, "0.6.1")
		})
	}
	getNoHelper(ctx, r, f, fd, builds)
}

// getNoHelper (I1): get.sh --no-helper on a computer with nothing
// installed takes the system's one archive, checks its signature and
// leaves cbb running alone under systemd: no cbb-helper beside it, and the
// installer's small.conf drop-in for a small device.
func getNoHelper(ctx context.Context, r *Report, f *Fleet, fd *feed, builds map[string]string) {
	const p = "fleet/I1-get-no-helper/"
	var d *Device
	if r.Do(p+"setup", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, f.net); err != nil {
			return err
		}
		_, err = docker(ctx, "cp", "packaging/get.sh", d.Container+":/tmp/get.sh")
		return err
	}) != nil {
		return
	}
	r.Do(p+"installs", func() error {
		dir, err := fd.publish(ctx, builds["0.6.1"], "get-no-helper", "0.6.1", releaseOpts{})
		if err != nil {
			return err
		}
		at, err := fd.toDevice(ctx, d, dir)
		if err != nil {
			return err
		}
		out, err := runOut(ctx, d, feedEnv(at)+" sh /tmp/get.sh --no-helper --no-firewall --no-pair", 3*time.Minute)
		fmt.Fprintf(r.out, "I1 get.sh --no-helper: %s\n", strings.Join(strings.Fields(out), " "))
		if err != nil {
			return err
		}
		if !strings.Contains(out, "The release's signature checks out (0.6.1).") {
			return fmt.Errorf("get.sh --no-helper printed %q, without that the signature checks out", out)
		}
		if out, err := Run(ctx, d, "cbb version", ""); err != nil || !strings.Contains(out, "0.6.1") {
			return fmt.Errorf("cbb version after get.sh --no-helper: %q (%v)", out, err)
		}
		if out, err := Run(ctx, d, "ls /usr/local/bin/cbb-helper 2>/dev/null; ls "+smallConf, ""); err != nil || strings.TrimSpace(out) != smallConf {
			return fmt.Errorf("after get.sh --no-helper, want only %s and no cbb-helper: %q (%v)", smallConf, out, err)
		}
		return eventually(ctx, 30*time.Second, func() error {
			out, err := Run(ctx, d, "systemctl is-active cbb; cbb status 2>&1; true", "")
			if err == nil && (!strings.HasPrefix(out, "active") || !strings.Contains(out, "in no group")) {
				err = fmt.Errorf("cbb after get.sh --no-helper: %q", out)
			}
			return err
		})
	})
}

// smallConf is the drop-in install.sh writes for cbb without its helper.
const smallConf = "/etc/systemd/system/cbb.service.d/small.conf"
