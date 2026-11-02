// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The fleet's copies of files and folders (O2, O3, O5), the command line
// (U2), what a member writes to its clipboard after an absence (Y20 to
// Y23), and a removed device away from home and what the servers keep
// (W21, W40).

// tinyPNG is a 1x1 PNG.
const tinyPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

// treeSums lists every file under dir with its SHA-256 and every folder,
// sorted, relative to dir.
func treeSums(ctx context.Context, d *Device, dir string) (string, error) {
	return RunFor(ctx, d, "cd "+dir+" && { find . -type d | sort; find . -type f -exec sha256sum {} + | sort -k2; }", "", time.Minute)
}

// pasteInto saves d's clipboard copy into a new, empty folder dir.
func pasteInto(ctx context.Context, d *Device, dir string, timeout time.Duration) error {
	_, err := RunFor(ctx, d, "rm -rf "+dir+" && mkdir "+dir+" && cbb paste -o "+dir, "", timeout)
	return err
}

// files (O2, O3, O5): a folder's tree arrives whole, without links and
// special files and with names made safe; 10 000 entries go and 10 001 do
// not; cbb paste -o never replaces a file; images and the text that goes
// with a copy; each device's limits.
func files(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	g := fleetGroup(ctx, r, f, "fleet/O2-files", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	a, b, c := g.members[0], g.members[1], g.members[2]
	wait := 3 * time.Minute
	// arrive waits until b has the copy of the tree under top and it is
	// what a sent.
	arrive := func(dir, top string) error {
		want, err := treeSums(ctx, a, dir+"/"+top)
		if err != nil {
			return err
		}
		return eventually(ctx, wait, func() error {
			if err := pasteInto(ctx, b, "/tmp/o", time.Minute); err != nil {
				return err
			}
			got, err := treeSums(ctx, b, "/tmp/o/"+top)
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("%s saved another tree than %s sent:\n%s\nnot\n%s", b.Name, a.Name, got, want)
			}
			return nil
		})
	}
	r.Do("fleet/O2-tree", func() error {
		// 100 files in ten folders, an empty file and folder, a link and
		// a pipe, which stay behind.
		mk := "rm -rf /tmp/t && mkdir -p /tmp/t/top/empty && cd /tmp/t/top && for i in $(seq 0 9); do mkdir d$i; for j in $(seq 0 9); do head -c $((i*1000+j)) /dev/urandom >d$i/f$j; done; done && : >zero && ln -s d0/f0 link && mkfifo pipe"
		if _, err := RunFor(ctx, a, mk, "", time.Minute); err != nil {
			return err
		}
		out, err := RunFor(ctx, a, "cbb copy /tmp/t/top 2>&1", "", time.Minute)
		if err != nil {
			return err
		}
		if !strings.Contains(out, "left out 2 links and special files") {
			return fmt.Errorf("cbb copy did not say it left the link and the pipe out: %q", out)
		}
		if err := arrive("/tmp/t", "top"); err != nil {
			return err
		}
		_, err = Run(ctx, b, "test ! -e /tmp/o/top/link && test ! -e /tmp/o/top/pipe && test -d /tmp/o/top/empty && test -f /tmp/o/top/zero", "")
		return err
	})
	r.Do("fleet/O2-names", func() error {
		long := strings.Repeat("x", 255)
		mk := "rm -rf /tmp/n && mkdir -p /tmp/n/names && cd /tmp/n/names && echo 1 >CON && echo 2 >notes. && echo 3 >\"$(printf 'a\\001b')\" && echo 4 >'q?' && echo 5 >" + long
		if _, err := Run(ctx, a, mk, ""); err != nil {
			return err
		}
		if _, err := RunFor(ctx, a, "cbb copy /tmp/n/names", "", time.Minute); err != nil {
			return err
		}
		want := []string{"CON_", "a_b", "notes._", "q_", long}
		return eventually(ctx, wait, func() error {
			if err := pasteInto(ctx, b, "/tmp/o", time.Minute); err != nil {
				return err
			}
			out, err := Run(ctx, b, "ls /tmp/o/names | LC_ALL=C sort", "")
			if err != nil {
				return err
			}
			if got := strings.Fields(out); strings.Join(got, " ") != strings.Join(want, " ") {
				return fmt.Errorf("%s saved the names %q, not %q", b.Name, got, want)
			}
			return nil
		})
	})
	r.Do("fleet/O2-ten-thousand", func() error {
		// The folder and 9 999 files are 10 000 entries.
		if _, err := RunFor(ctx, a, "rm -rf /tmp/m && mkdir -p /tmp/m/many && cd /tmp/m/many && seq 1 9999 | xargs touch", "", time.Minute); err != nil {
			return err
		}
		if _, err := RunFor(ctx, a, "cbb copy /tmp/m/many", "", 2*time.Minute); err != nil {
			return err
		}
		return eventually(ctx, wait, func() error {
			if err := pasteInto(ctx, b, "/tmp/o", 2*time.Minute); err != nil {
				return err
			}
			out, err := Run(ctx, b, "ls /tmp/o/many | wc -l", "")
			if err == nil && strings.TrimSpace(out) != "9999" {
				err = fmt.Errorf("%s saved %s of 9999 files", b.Name, strings.TrimSpace(out))
			}
			return err
		})
	})
	fails(ctx, r, "fleet/O2-ten-thousand-one", a, errorCase{cmd: "touch /tmp/m/many/10000 && cbb copy /tmp/m/many", want: []string{"at most 10000 files and folders"}})

	r.Do("fleet/O3-never-replaces", func() error {
		if _, err := Run(ctx, a, "rm -rf /tmp/s && mkdir /tmp/s && echo theirs >/tmp/s/same.txt && cbb copy /tmp/s/same.txt", ""); err != nil {
			return err
		}
		return eventually(ctx, wait, func() error {
			out, err := Run(ctx, b, "rm -rf /tmp/k && mkdir /tmp/k && echo mine >/tmp/k/same.txt && ! cbb paste -o /tmp/k && cat /tmp/k/same.txt && ls /tmp/k", "")
			if err != nil {
				return err
			}
			if strings.Fields(out)[0] != "mine" || len(strings.Fields(out)) != 2 {
				return fmt.Errorf("cbb paste -o changed the folder: %q", out)
			}
			return nil
		})
	})
	r.Do("fleet/O3-image-and-text", func() error {
		if _, err := Run(ctx, a, "echo "+tinyPNG+" | base64 -d >/tmp/i.png && cbb copy -text 'the alt text' -type png /tmp/i.png", ""); err != nil {
			return err
		}
		if err := arrives(ctx, c, "the alt text", timeout); err != nil {
			return err
		}
		return eventually(ctx, wait, func() error {
			if err := pasteInto(ctx, b, "/tmp/o", time.Minute); err != nil {
				return err
			}
			out, err := Run(ctx, b, "echo "+tinyPNG+" | base64 -d >/tmp/i.png && cmp /tmp/o/image.png /tmp/i.png && ls /tmp/o", "")
			if err == nil && strings.TrimSpace(out) != "image.png" {
				err = fmt.Errorf("%s saved %q, not image.png", b.Name, out)
			}
			return err
		})
	})
	r.Do("fleet/O3-own-saves-the-group's", func() error {
		if err := setMode(ctx, b, "own"); err != nil {
			return err
		}
		defer shareClipboard(context.WithoutCancel(ctx), b)
		if _, err := Run(ctx, a, "rm -rf /tmp/w && mkdir /tmp/w && echo own >/tmp/w/group.txt && cbb copy /tmp/w/group.txt", ""); err != nil {
			return err
		}
		return eventually(ctx, wait, func() error {
			if err := pasteInto(ctx, b, "/tmp/o", time.Minute); err != nil {
				return err
			}
			_, err := Run(ctx, b, "grep -qx own /tmp/o/group.txt", "")
			return err
		})
	})

	fails(ctx, r, "fleet/O5-below-1MiB", a, errorCase{cmd: "cbb config max-copy 512KiB", want: []string{"max-copy must be from 1 MiB to 1 GiB"}})
	fails(ctx, r, "fleet/O5-over-1GiB", a, errorCase{cmd: "cbb config max-copy 2GiB", want: []string{"max-copy must be from 1 MiB to 1 GiB"}})
	fails(ctx, r, "fleet/O5-away-over-home", a, errorCase{cmd: "cbb config max-copy-away 200MiB", want: []string{"max-copy-away must be from 1 MiB to max-copy, 100 MiB"}})
	r.Do("fleet/O5-sender's-limit", func() error {
		if err := succeeds(ctx, a, "cbb config max-copy 1MiB", "", "1 MiB"); err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), a, "cbb config max-copy 100MiB", "")
		if _, err := fileOn(ctx, a, "/tmp/two", 2); err != nil {
			return err
		}
		return errorShown(ctx, a, errorCase{cmd: "cbb copy /tmp/two", want: []string{"larger than this device's limit of 1 MiB"}})
	})
	r.Do("fleet/O5-receiver's-limit", func() error {
		if err := succeeds(ctx, c, "cbb config max-copy 1MiB", "", "1 MiB"); err != nil {
			return err
		}
		defer Run(context.WithoutCancel(ctx), c, "cbb config max-copy 100MiB", "")
		sum, err := fileOn(ctx, a, "/tmp/two", 2)
		if err != nil {
			return err
		}
		if _, err := Run(ctx, a, "cbb copy /tmp/two", ""); err != nil {
			return err
		}
		if err := eventually(ctx, wait, func() error {
			got, err := pastedFile(ctx, b, time.Minute)
			if err == nil && got != sum {
				err = fmt.Errorf("%s has another file", b.Name)
			}
			return err
		}); err != nil {
			return err
		}
		if err := eventually(ctx, timeout, func() error {
			return succeeds(ctx, c, "cbb status", "", "is over this device's limit of 1 MiB")
		}); err != nil {
			return err
		}
		if out, err := Run(ctx, c, "rm -rf /tmp/o && mkdir /tmp/o && cbb paste -o /tmp/o; ls /tmp/o", ""); err == nil && strings.TrimSpace(out) != "" {
			return fmt.Errorf("%s saved the copy over its limit: %q", c.Name, out)
		}
		return nil
	})
}

// usageCommands are the commands of cbb's usage, each of which prints its
// usage for -h without doing anything.
var usageCommands = []string{"copy", "paste", "paste-receive", "action", "status", "remove", "rename", "admin",
	"takeover", "upgrade", "freeze", "unfreeze", "global", "forward", "relay", "new", "mode", "config", "pair",
	"invite", "update", "version", "holder", "network", "service", "agent", "paste-helper", "install"}

// commandLine (U2): cbb version and help, each command's -h, and unknown
// commands and flags, on a member whose service runs.
func commandLine(ctx context.Context, r *Report, f *Fleet) {
	const p = "fleet/U2-cli/"
	g := fleetGroup(ctx, r, f, "fleet/U2-cli", 2)
	if g == nil {
		return
	}
	d := g.members[1]
	r.Do(p+"version", func() error {
		out, err := Run(ctx, d, "cbb version", "")
		if err == nil && !regexp.MustCompile(`^clipboardbridge \S+ .*linux/`).MatchString(out) {
			err = fmt.Errorf("cbb version printed %q", firstLine(out))
		}
		return err
	})
	r.Do(p+"help", func() error { return succeeds(ctx, d, "cbb help", "", "Usage: clipboardbridge <command>") })
	r.Do(p+"each-h", func() error {
		var errs []error
		for _, c := range usageCommands {
			out, err := Run(ctx, d, "cbb "+c+" -h; echo \"exit $?\"", "")
			if err != nil {
				return err
			}
			if !strings.HasSuffix(strings.TrimSpace(out), "exit 2") {
				errs = append(errs, fmt.Errorf("cbb %s -h: %q", c, out))
			}
		}
		return errors.Join(errs...)
	})
	fails(ctx, r, p+"unknown-command", d, errorCase{cmd: "cbb frobnicate", want: []string{`unknown command "frobnicate"`}})
	fails(ctx, r, p+"unknown-flag", d, errorCase{cmd: "cbb copy -frobnicate", want: []string{"flag provided but not defined: -frobnicate"}})
	r.Do(p+"nothing-done", func() error {
		// The -h runs above removed, froze and took nothing over.
		return listsAs(ctx, g.members, d.Name, "", false, 10*time.Second)
	})
}

// freshness (Y20 to Y23, Y33, D16): what a member writes to its own
// clipboard. A member that only lost its peers keeps its text; after a
// network drop it does not write the group's text that is older than 60 s;
// after its service was away it does, within 30 s, unless that text is a
// secret, of which a hello carries only the mark. Then a member's address
// changes and it syncs on.
func freshness(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	g := fleetGroup(ctx, r, f, "fleet/Y20-fresh", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	a, b, c := g.members[0], g.members[1], g.members[2]
	before := "cbb-bench " + g.run + " before the drop"
	if r.Do("fleet/Y20-live", func() error {
		if err := Copy(ctx, a, before); err != nil {
			return err
		}
		return arrives(ctx, c, before, timeout)
	}) != nil {
		return
	}
	old := "cbb-bench " + g.run + " during the drop"
	r.Do("fleet/Y23-keeps-its-text", func() error {
		if err := cut(ctx, c, a); err != nil {
			return err
		}
		if err := cut(ctx, c, b); err != nil {
			return err
		}
		if err := Copy(ctx, a, old); err != nil {
			return err
		}
		if err := arrives(ctx, b, old, timeout); err != nil {
			return err
		}
		time.Sleep(65 * time.Second)
		got, err := Paste(ctx, c)
		if err == nil && strings.TrimSpace(got) != before {
			err = fmt.Errorf("%s, alone, has %s, not its own text", c.Name, describe(got))
		}
		return err
	})
	r.Do("fleet/Y22-drop-opens-no-window", func() error {
		if err := heal(ctx, a, b, c); err != nil {
			return err
		}
		// Back in sync: c lists a as online again; the old text
		// stays off its clipboard meanwhile and after.
		if err := eventually(ctx, time.Minute, func() error {
			row, err := statusRow(ctx, c, a.Name)
			if err == nil && !strings.Contains(row, "online") {
				err = fmt.Errorf("%s lists %s as %q", c.Name, a.Name, row)
			}
			return err
		}); err != nil {
			return err
		}
		time.Sleep(35 * time.Second)
		got, err := Paste(ctx, c)
		if err == nil && strings.TrimSpace(got) != before {
			err = fmt.Errorf("%s wrote the group's text of 65 s ago after a network drop: %s", c.Name, describe(got))
		}
		if err != nil {
			return err
		}
		return syncs(ctx, g, a, c, "after the drop", timeout)
	})
	r.Do("fleet/Y21-away-opens-the-window", func() error {
		if err := f.stop(ctx, c); err != nil {
			return err
		}
		text := "cbb-bench " + g.run + " while the service was away"
		if err := Copy(ctx, a, text); err != nil {
			return err
		}
		time.Sleep(65 * time.Second)
		if err := f.start(ctx, c); err != nil {
			return err
		}
		return arrives(ctx, c, text, 40*time.Second)
	})
	r.Do("fleet/Y33-secret-in-a-hello", func() error {
		if err := f.stop(ctx, c); err != nil {
			return err
		}
		secret := "cbb-bench " + g.run + " a secret while the service was away"
		if _, err := Run(ctx, a, "cbb copy -secret", secret); err != nil {
			return err
		}
		if err := arrives(ctx, b, secret, timeout); err != nil {
			return err
		}
		if err := f.start(ctx, c); err != nil {
			return err
		}
		// The window after the start is open, but the hello carries only
		// the secret's mark.
		time.Sleep(35 * time.Second)
		// Its clipboard, empty after the container's restart, gets no
		// text from it.
		got, err := Paste(ctx, c)
		if err == nil && strings.Contains(got, secret) {
			err = fmt.Errorf("%s wrote a secret that a hello named", c.Name)
		}
		return err
	})
	r.Do("fleet/D16-new-address", func() error {
		ip, err := fleetIP(ctx, c)
		if err != nil {
			return err
		}
		if _, err := docker(ctx, "network", "disconnect", c.Network, c.Container); err != nil {
			return err
		}
		// A new lease: another member takes the old address meanwhile.
		taker, err := f.AddOn(ctx, c.Network)
		if err != nil {
			return err
		}
		if _, err := docker(ctx, "network", "connect", c.Network, c.Container); err != nil {
			return err
		}
		if now, err := fleetIP(ctx, c); err != nil || now == ip {
			return fmt.Errorf("%s kept the address %s (%v)", c.Name, ip, err)
		}
		f.stop(ctx, taker)
		if err := syncs(ctx, g, a, c, "to the new address", time.Minute); err != nil {
			return err
		}
		return syncs(ctx, g, c, b, "from the new address", time.Minute)
	})
}

// removedAway (W21, W40): a client removed from the group drops off the
// hub at once and gets nothing more; the forwarder's and the relay's
// files and logs name no address, device or group.
func removedAway(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/W21-removed/"
	a := newAwayGroup(ctx, r, f, "fleet/W21-removed", 2)
	if a == nil {
		return
	}
	c1 := a.join(ctx, r, p+"c1-invited")
	c2 := a.join(ctx, r, p+"c2-invited")
	if c1 == nil || c2 == nil {
		return
	}
	clients := func() (int, error) {
		out, err := Run(ctx, a.hub, "cbb global", "")
		if err != nil {
			return 0, err
		}
		m := regexp.MustCompile(`for (\d+) devices`).FindStringSubmatch(out)
		if m == nil {
			return 0, fmt.Errorf("cbb global on the hub names no clients: %q", firstLine(out))
		}
		return strconv.Atoi(m[1])
	}
	if r.Do(p+"connected", func() error {
		for _, c := range []*Device{c1, c2} {
			if err := connected(ctx, c, 3*time.Minute); err != nil {
				return err
			}
		}
		return syncs(ctx, a.benchGroup, a.members[1], c1, "to the client", 2*timeout)
	}) != nil {
		return
	}
	r.Do("fleet/W21-key-dropped", func() error {
		n, err := clients()
		if err != nil {
			return err
		}
		if _, err := Run(ctx, a.hub, "cbb remove "+c2.Name, ""); err != nil {
			return err
		}
		return eventually(ctx, 10*time.Second, func() error {
			m, err := clients()
			if err == nil && m != n-1 {
				err = fmt.Errorf("the hub serves %d clients after a removal, not %d", m, n-1)
			}
			return err
		})
	})
	r.Do("fleet/W21-gets-nothing", func() error {
		if err := cutOff(ctx, c2, time.Minute); err != nil {
			return err
		}
		text := "cbb-bench " + a.run + " after the client's removal"
		if err := Copy(ctx, a.hub, text); err != nil {
			return err
		}
		if err := arrives(ctx, c1, text, 2*timeout); err != nil {
			return err
		}
		if got, _ := Paste(ctx, c2); strings.Contains(got, text) {
			return fmt.Errorf("%s got a copy after its removal", c2.Name)
		}
		return nil
	})
	// S6: the removed client reaches no one: what it copies arrives
	// nowhere, at home or away.
	r.Do("fleet/S6-removed-reaches-no-one", func() error {
		text := "cbb-bench " + a.run + " from the removed client"
		if err := Copy(ctx, c2, text); err != nil {
			return err
		}
		time.Sleep(timeout)
		for _, d := range a.members {
			if d == c2 {
				continue
			}
			if got, err := Paste(ctx, d); err != nil {
				return err
			} else if strings.Contains(got, text) {
				return fmt.Errorf("%s got a copy from the removed client", d.Name)
			}
		}
		return nil
	})
	r.Do("fleet/W40-forwarder-keeps-nothing", func() error {
		var secrets []string
		for _, d := range a.members {
			id, err := deviceOf(ctx, d)
			if err != nil {
				return err
			}
			ip, err := fleetIP(ctx, d)
			if err != nil {
				return err
			}
			secrets = append(secrets, id, ip)
		}
		return keepsNothing(ctx, a.fwd, fwdState, secrets)
	})
}

// keepsNothing checks that no file a server made since it started (its key
// in dir being the oldest), nor its log, holds one of secrets: the group's
// device IDs and addresses (W40).
func keepsNothing(ctx context.Context, d *Device, dir string, secrets []string) error {
	out, err := Run(ctx, d, "find / -xdev -type f -newer "+dir+"/forwarder.pem ! -path '/proc/*' ! -path '/sys/*' ! -path '/usr/local/bin/*'", "")
	if err != nil {
		return err
	}
	files := append(strings.Fields(out), dir+"/log")
	for _, s := range secrets {
		if s == "" {
			continue
		}
		hit, _ := Run(ctx, d, "grep -lF -- "+shellQuote(s)+" "+strings.Join(files, " ")+" 2>/dev/null; true", "")
		if strings.TrimSpace(hit) != "" {
			return fmt.Errorf("%s keeps %q in %s", d.Name, s, strings.Join(strings.Fields(hit), ", "))
		}
	}
	return nil
}

// otherSystem (G35): a member whose hello names another system than its
// record, as a computer that moved from Linux to Windows with its state,
// gets a new record from the root; back on Linux, another one.
func otherSystem(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/G35-system/"
	g := fleetGroup(ctx, r, f, "fleet/G35-system", 3)
	if g == nil || len(g.members) < 3 {
		return
	}
	root, m, other := g.members[0], g.members[1], g.members[2]
	r.Do("fleet/G35-new-system", func() error {
		h, err := forgeHost(ctx, f, m, root)
		if err != nil {
			return err
		}
		id, err := deviceOf(ctx, root)
		if err != nil {
			return err
		}
		ip, err := fleetIP(ctx, root)
		if err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() {
			_, err := RunFor(ctx, h, fmt.Sprintf("cbbbench-forge -os windows -state /tmp/%s -signer /tmp/%s -to %s -addr %s:8764 hold:60", m.Name, root.Name, id, ip), "", 2*time.Minute)
			done <- err
		}()
		if err := listsAs(ctx, []*Device{root, other}, m.Name, "Windows", false, 45*time.Second); err != nil {
			return err
		}
		if err := <-done; err != nil {
			return err
		}
		return f.stop(ctx, h)
	})
	r.Do(p+"back-on-linux", func() error {
		if err := f.start(ctx, m); err != nil {
			return err
		}
		return listsAs(ctx, []*Device{root, other}, m.Name, "Linux", false, time.Minute)
	})
}

// controlSocket (U11): what no cbb sends on the control socket: junk, a
// header too long or with a bad length, an unknown operation, one that
// changes the group, a payload cut short and a hundred connections that
// send nothing; the service answers or closes each, and still answers.
func controlSocket(ctx context.Context, r *Report, f *Fleet) {
	const p = "fleet/U11-socket/"
	g := fleetGroup(ctx, r, f, "fleet/U11-socket", 2)
	if g == nil {
		return
	}
	d := g.members[1]
	var out string
	if r.Do(p+"forge", func() error {
		bin, err := forgeOn(ctx, d)
		if err != nil {
			return err
		}
		out, err = RunFor(ctx, d, bin+" control:junk control:long control:big control:negative control:unknown control:admin control:short control:idle-100", "", 2*time.Minute)
		return err
	}) != nil {
		return
	}
	for _, c := range []struct{ name, want string }{
		{"junk", "closed"}, {"long", "closed"}, {"big", "closed"}, {"negative", "closed"},
		{"unknown", "answered: "}, {"admin", "answered: \"revoke\" changes the group"}, {"short", "closed"},
		{"idle-100", "100 open, 36 closed, status refused while open, answered after"}, {"status", "answered"},
	} {
		r.Do(p+c.name, func() error {
			for _, l := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(l, c.name+": "); ok {
					if !strings.HasPrefix(rest, c.want) {
						return fmt.Errorf("the service %s, not %s", rest, c.want)
					}
					return nil
				}
			}
			return fmt.Errorf("the forge printed nothing for %s: %q", c.name, out)
		})
	}
}
