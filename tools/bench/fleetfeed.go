// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// otherArch is a CPU the fleet's containers cannot run.
func otherArch() string {
	if goarchOf() == "arm64" {
		return "amd64"
	}
	return "arm64"
}

// runOut runs cmd on d and returns what it printed, also when it failed.
func runOut(ctx context.Context, d *Device, cmd string, timeout time.Duration) (string, error) {
	out, err := RunFor(ctx, d, cmd, "", timeout)
	var re *RunError
	if errors.As(err, &re) {
		out = re.Output
	}
	return out, err
}

// updates (I8, I9, I10, I11): a computer installed from a release of the
// build under test (install.sh in a container with systemd) checks for and
// installs a newer release from the bench's feed; refuses a tampered
// archive, a release signed by a key the keys do not list, keys signed by
// no root, an expired channel, a release whose min_from it does not meet
// and one without its platform, each named; keeps the highest version it
// saw; rolls back a build that never becomes healthy and skips it; and,
// installed by another method, prints that method's command instead.
func updates(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/I8-update/"
	var fd *feed
	builds := map[string]string{}
	defer func() { fd.remove() }()
	if r.Do(p+"feed", func() error {
		var err error
		if fd, err = newFeed(ctx); err != nil {
			return err
		}
		for _, b := range []struct{ key, version, arch string }{
			{"0.6.0", "0.6.0", goarchOf()}, {"0.6.1", "0.6.1", goarchOf()}, {"0.5.9", "0.5.9", goarchOf()},
			{"0.6.2-broken", "0.6.2", otherArch()}, {"0.6.3", "0.6.3", goarchOf()},
		} {
			if builds[b.key], err = fd.build(ctx, b.version, b.arch, goarchOf()); err != nil {
				return err
			}
		}
		builds["0.6.1-other-platform"], err = fd.build(ctx, "0.6.1", otherArch(), otherArch())
		return err
	}) != nil {
		return
	}
	var d *Device
	if r.Do(p+"install", func() error {
		var err error
		if d, err = f.AddSystemd(ctx, f.net); err != nil {
			return err
		}
		if _, err := installArchive(ctx, d, builds["0.6.0"], "--express --auto-update off"); err != nil {
			return err
		}
		return runsVersion(ctx, d, "0.6.0")
	}) != nil {
		return
	}
	// update runs cbb update with flags against the feed's folder dir.
	update := func(dir, flags string) (string, error) {
		at, err := fd.toDevice(ctx, d, dir)
		if err != nil {
			return "", err
		}
		return runOut(ctx, d, feedEnv(at)+"cbb update "+flags, 5*time.Minute)
	}
	publish := func(build, name, version string, o releaseOpts) (string, error) {
		return fd.publish(ctx, builds[build], name, version, o)
	}

	// I9 first, while 0.6.0 runs: each refusal leaves it running.
	for _, c := range []struct {
		name, build, version string
		o                    releaseOpts
		spoil                func(dir string) error
		want                 string
	}{
		{name: "tampered", build: "0.6.1", version: "0.6.1", spoil: func(dir string) error {
			return tamper(dir, "cbb-linux-"+goarchOf()+".tar.gz")
		}, want: "does not match the signed release.json"},
		{name: "unknown-release-key", build: "0.6.1", version: "0.6.1", o: releaseOpts{relBy: "other"}, want: "stable.json: release: the signature is not valid"},
		{name: "keys-by-no-root", build: "0.6.1", version: "0.6.1", o: releaseOpts{keysBy: "other"}, want: "keys.json: release: the signature is not valid"},
		{name: "min-from", build: "0.6.1", version: "0.6.1", o: releaseOpts{minFrom: "0.6.1"}, want: "0.6.1"},
		{name: "other-platform", build: "0.6.1-other-platform", version: "0.6.1", want: "cbb-linux-" + goarchOf() + ".tar.gz"},
	} {
		r.Do("fleet/I9-refused/"+c.name, func() error {
			dir, err := publish(c.build, "refused-"+c.name, c.version, c.o)
			if err != nil {
				return err
			}
			if c.spoil != nil {
				if err := c.spoil(dir); err != nil {
					return err
				}
			}
			out, err := update(dir, "")
			fmt.Fprintf(r.out, "I9 %s: %s\n", c.name, strings.Join(strings.Fields(out), " "))
			if err == nil {
				return fmt.Errorf("cbb update took a release that is %s: %q", c.name, out)
			}
			if !strings.Contains(out, c.want) {
				return fmt.Errorf("cbb update refused a release that is %s with %q, which does not name %q", c.name, out, c.want)
			}
			return runsVersion(ctx, d, "0.6.0")
		})
	}

	r.Do("fleet/I8-update/check", func() error {
		dir, err := publish("0.6.1", "0.6.1", "0.6.1", releaseOpts{})
		if err != nil {
			return err
		}
		out, err := update(dir, "-check")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "CBB 0.6.1 is available; this device runs v0.6.0") {
			return fmt.Errorf("cbb update -check printed %q", out)
		}
		return runsVersion(ctx, d, "0.6.0")
	})
	r.Do("fleet/I8-update/install", func() error {
		dir, err := publish("0.6.1", "0.6.1", "0.6.1", releaseOpts{})
		if err != nil {
			return err
		}
		out, err := update(dir, "")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "CBB 0.6.1 is installed.") {
			return fmt.Errorf("cbb update printed %q", out)
		}
		return runsVersion(ctx, d, "0.6.1")
	})
	r.Do("fleet/I9-refused/older", func() error {
		// An older release is not installed; the highest seen stays.
		dir, err := publish("0.5.9", "0.5.9", "0.5.9", releaseOpts{})
		if err != nil {
			return err
		}
		out, err := update(dir, "")
		fmt.Fprintf(r.out, "I9 older: %s\n", strings.Join(strings.Fields(out), " "))
		if err == nil && !strings.Contains(out, "newest") && !strings.Contains(out, "not below") {
			return fmt.Errorf("cbb update with 0.5.9 printed %q", out)
		}
		return runsVersion(ctx, d, "0.6.1")
	})
	r.Do("fleet/I10-rollback", func() error {
		dir, err := publish("0.6.2-broken", "0.6.2", "0.6.2", releaseOpts{})
		if err != nil {
			return err
		}
		out, err := update(dir, "")
		fmt.Fprintf(r.out, "I10: %s\n", strings.Join(strings.Fields(out), " "))
		if err == nil {
			return fmt.Errorf("cbb update installed a build that never starts: %q", out)
		}
		if err := runsVersion(ctx, d, "0.6.1"); err != nil {
			return fmt.Errorf("not rolled back: %w", err)
		}
		// The timer skips it from then on; a person's cbb update tries
		// it again and says so.
		out, _ = update(dir, "")
		if !strings.Contains(out, "did not start here before") {
			return fmt.Errorf("cbb update after a rollback printed %q, without that 0.6.2 did not start before", out)
		}
		return runsVersion(ctx, d, "0.6.1")
	})
	r.Do("fleet/I11-method", func() error {
		dir, err := publish("0.6.3", "0.6.3", "0.6.3", releaseOpts{})
		if err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), d, "cbb update -installed-by get", "")
		if _, err := Run(ctx, d, "cbb update -installed-by docker", ""); err != nil {
			return err
		}
		out, err := update(dir, "")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "It came from docker, which updates it:") {
			return fmt.Errorf("cbb update of a Docker install printed %q", out)
		}
		return runsVersion(ctx, d, "0.6.1")
	})
	getScript(ctx, r, f, fd, builds)
	groupUpdate(ctx, r, f, fd, builds)
	installers(ctx, r, f, builds)
	ufwRules(ctx, r, f, builds["0.6.0"])
	inviteGrant(ctx, r, f, builds["0.6.0"])
	besideAvahi(ctx, r, f, builds["0.6.0"])
	installerErrors(ctx, r, f, builds["0.6.0"])
	systemLimit(ctx, r, f, builds["0.6.0"], timeout)
}
