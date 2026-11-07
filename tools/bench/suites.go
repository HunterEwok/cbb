// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxSkew is how far a device's clock may be from the controller's
// (docs/testbench.md, section 12), with room for the SSH round trip.
const maxSkew = 2 * time.Second

var (
	groupRE  = regexp.MustCompile(`group\s+([0-9a-f]{8,})`)
	deviceRE = regexp.MustCompile(`(?i)device\s+([0-9a-f]{8,})`)
	codeRE   = regexp.MustCompile(`Pairing code:\s*(\d{3})\s*(\d{3})`)
	addrRE   = regexp.MustCompile(`cbb pair -code (\S+:\d+)`)
)

// Check reaches every device: SSH, the clock, the installed version and its
// group.
func Check(ctx context.Context, r *Report, devices []*Device) {
	for _, d := range devices {
		r.Do("check/"+d.Name+"/reach", func() error {
			_, err := Run(ctx, d, "exit 0", "")
			return err
		})
		r.Do("check/"+d.Name+"/clock", func() error { return checkClock(ctx, d) })
		r.Do("check/"+d.Name+"/version", func() error {
			out, err := Run(ctx, d, cbbCmd(d)+" version", "")
			if err != nil {
				return fmt.Errorf("%s is not installed or does not run: %w", cbbCmd(d), err)
			}
			fmt.Fprintf(r.out, "     %s: %s\n", d.Name, strings.TrimSpace(out))
			return nil
		})
		r.Do("check/"+d.Name+"/group", func() error {
			g, err := groupOf(ctx, d)
			if err != nil {
				return err
			}
			if g == "" {
				g = "none"
			}
			fmt.Fprintf(r.out, "     %s: group %s\n", d.Name, g)
			return nil
		})
	}
}

func checkClock(ctx context.Context, d *Device) error {
	cmd := "date +%s.%N"
	if d.OS == "windows" {
		cmd = "[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0"
	} else if coarseDate(d) {
		cmd = "date +%s" // BSD's and busybox's date may have no %N
	}
	before := time.Now()
	out, err := Run(ctx, d, cmd, "")
	if err != nil {
		return err
	}
	sec, err := strconv.ParseFloat(strings.TrimSpace(strings.ReplaceAll(out, ",", ".")), 64)
	if err != nil {
		return fmt.Errorf("cannot read the clock of %s from %q", d.Name, strings.TrimSpace(out))
	}
	mid := before.Add(time.Since(before) / 2)
	skew := time.Duration(sec*float64(time.Second)) - time.Duration(mid.UnixNano())
	if coarseDate(d) {
		skew = skew.Truncate(time.Second)
	}
	if skew > maxSkew || skew < -maxSkew {
		return fmt.Errorf("the clock of %s is off by %v; turn on NTP there", d.Name, skew.Round(time.Millisecond))
	}
	return nil
}

// groupOf returns the device's group ID, or "" when it is in no group.
func groupOf(ctx context.Context, d *Device) (string, error) {
	out, err := Run(ctx, d, cbbCmd(d)+" status", "")
	if err != nil {
		var re *RunError
		// The full member says "Not in a group.", the lite member "in no
		// group"; both exit 1.
		if errors.As(err, &re) && (strings.Contains(re.Output, "Not in a group") || strings.Contains(re.Output, "in no group")) {
			return "", nil
		}
		return "", err
	}
	if m := groupRE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", nil
}

// Smoke makes a group of the devices around the hub and sends one text from
// each device to every other one.
func Smoke(ctx context.Context, r *Report, inv *Inventory, devices []*Device, timeout time.Duration) {
	g := formGroup(ctx, r, "smoke", devices)
	if g == nil {
		return
	}
	defer g.end(ctx, r)

	// One text from each member; every other member must show it.
	for _, from := range g.members {
		text := fmt.Sprintf("cbb-bench %s from %s café ✓", g.run, from.Name)
		if r.Do("smoke/"+from.Name+"/copy", func() error { return Copy(ctx, from, text) }) != nil {
			continue
		}
		spread(ctx, r, "smoke/sync/", g.members, from, text, timeout)
	}
}

// benchGroup is a group the bench made for one run.
type benchGroup struct {
	suite   string
	run     string
	hub     *Device
	members []*Device // the hub first
	tag     string
	codes   []string  // the pairing codes of the run, which no log may hold
	left    []*Device // joined, but out of the cases: only revoked at the end
	undo    []func()
}

// formGroup makes a group of the devices around the hub: each must start
// in no group, the bench never touches a group it did not make. It returns
// nil when the run cannot go on.
func formGroup(ctx context.Context, r *Report, suite string, devices []*Device) *benchGroup {
	devices = atHome(devices)
	var hub *Device
	for _, d := range devices {
		if d.Has("hub") {
			hub = d
		}
	}
	if hub == nil || (hub.OS != "linux" && hub.OS != "openwrt" && hub.OS != "freebsd" && hub.OS != "fleet") {
		r.Do(suite+"/setup", func() error {
			return errors.New(suite + " needs a Linux, OpenWrt or FreeBSD device with the role hub in the inventory: it makes the group with cbb new")
		})
		return nil
	}
	g := &benchGroup{suite: suite, run: runID(), hub: hub, members: []*Device{hub}}
	fmt.Fprintf(r.out, "run %s, hub %s\n", g.run, hub.Name)

	ok := true
	for _, d := range devices {
		err := r.Do(suite+"/"+d.Name+"/no-group", func() error {
			if err := checkClock(ctx, d); err != nil {
				return err
			}
			tag, err := groupOf(ctx, d)
			if err != nil {
				return err
			}
			if tag != "" {
				return fmt.Errorf("%s is in group %s; reset it before the run (uninstall with --purge, -Purge on Windows)", d.Name, tag)
			}
			return nil
		})
		ok = ok && err == nil
	}
	if !ok {
		return nil
	}

	// mDNS does not cross subnets: a lite member is told where the hub is
	// for the run, and the service goes back to its own settings after it.
	if hub.Address != "" {
		for _, d := range devices {
			if d.OS != "linux-lite" {
				continue
			}
			if r.Do(suite+"/"+d.Name+"/peer", func() error { return litePeer(ctx, d, hub.Address) }) == nil {
				g.undo = append(g.undo, func() {
					r.Do(suite+"/"+d.Name+"/unpeer", func() error { return litePeer(context.WithoutCancel(ctx), d, "") })
				})
			}
		}
	}

	if r.Do(suite+"/"+hub.Name+"/new", func() error {
		_, err := Run(ctx, hub, adminCmd(hub)+" new", "")
		if err == nil {
			err = shareClipboard(ctx, hub)
		}
		return noSudo(hub, err)
	}) != nil {
		g.undoAll()
		return nil
	}
	for _, d := range devices {
		if d == hub {
			continue
		}
		joined := false
		if r.Do(suite+"/"+d.Name+"/join", func() error {
			code, err := pairOne(ctx, hub, d)
			if code != "" {
				g.codes = append(g.codes, code)
			}
			if err != nil {
				return err
			}
			joined = true
			// cbb pair on the lite member returns a moment before its
			// service has taken the group.
			return eventually(ctx, 10*time.Second, func() error { return shareClipboard(ctx, d) })
		}) == nil {
			g.members = append(g.members, d)
		} else if joined {
			// It is in the group even if the rest failed: the end of the
			// run revokes it with the others.
			g.left = append(g.left, d)
		}
	}
	r.Do(suite+"/group", func() error {
		var err error
		g.tag, err = groupOf(ctx, hub)
		if err == nil && g.tag == "" {
			err = fmt.Errorf("%s made no group", hub.Name)
		}
		if err != nil {
			return err
		}
		for _, d := range g.members[1:] {
			tag, err := groupOf(ctx, d)
			if err != nil {
				return err
			}
			if tag != g.tag {
				return fmt.Errorf("%s is in group %q, not %s", d.Name, tag, g.tag)
			}
		}
		return nil
	})
	return g
}

// atHome leaves out the devices that are only away from home (the role away
// without member or hub): they cannot pair by code, and join by invitation
// in the away suite.
func atHome(devices []*Device) []*Device {
	var out []*Device
	for _, d := range devices {
		if d.Has("member") || d.Has("hub") {
			out = append(out, d)
		}
	}
	return out
}

// end closes the run. The hub revokes the others, so nothing copied on
// them after the run (the Mac is also someone's own computer) reaches the
// bench's group. Only the hub, the group's root, holds its CA keys, so
// every other member can be removed.
func (g *benchGroup) end(ctx context.Context, r *Report) {
	ctx = context.WithoutCancel(ctx)
	for _, d := range append(g.members[1:], g.left...) {
		r.Do(g.suite+"/"+d.Name+"/revoke", func() error {
			id, err := deviceOf(ctx, d)
			if err != nil {
				return err
			}
			_, err = Run(ctx, g.hub, adminCmd(g.hub)+" revoke "+id, "")
			return noSudo(g.hub, err)
		})
	}
	g.undoAll()
}

// undoAll takes back what the bench changed for the run, newest first.
func (g *benchGroup) undoAll() {
	for i := len(g.undo) - 1; i >= 0; i-- {
		g.undo[i]()
	}
	g.undo = nil
}

// spread checks that text, copied on from, reaches every other member
// within the timeout, one case per receiver.
func spread(ctx context.Context, r *Report, prefix string, members []*Device, from *Device, text string, timeout time.Duration) {
	var wg sync.WaitGroup
	for _, to := range members {
		if to == from {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Do(fmt.Sprintf("%s%s->%s", prefix, from.Name, to.Name), func() error {
				return arrives(ctx, to, seen(text, from, to), timeout)
			})
		}()
	}
	wg.Wait()
}

// arrives waits until the device's clipboard holds text.
// seen is the text that to's clipboard holds after from copied text. The
// Windows agent turns CR LF into LF when it reads the clipboard and LF into
// CR LF when it writes it (docs/design.md, Windows); every other member
// keeps the bytes as they are.
func seen(text string, from, to *Device) string {
	if from.OS == "windows" || to.OS == "windows" {
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	if to.OS == "windows" {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	return text
}

func arrives(ctx context.Context, to *Device, text string, timeout time.Duration) error {
	text = strings.TrimRight(text, "\r\n")
	return eventually(ctx, timeout, func() error {
		got, err := Paste(ctx, to)
		if err != nil {
			return err
		}
		if strings.TrimRight(got, "\r\n") != text {
			return fmt.Errorf("%s did not get the text within %v; it has %s", to.Name, timeout, describe(got))
		}
		return nil
	})
}

// describe shows a clipboard's text in an error: quoted when short, else
// its size and first line.
func describe(s string) string {
	if len(s) <= 80 && !strings.ContainsAny(s, "\r\n") {
		return strconv.Quote(s)
	}
	return fmt.Sprintf("%d bytes starting %q", len(s), firstLine(s))
}

// liteDropIn is the bench's systemd drop-in for the lite member's service.
const liteDropIn = "/etc/systemd/system/cbb.service.d/cbbbench.conf"

// litePeer restarts the lite member's service with -peer addr, or without
// the bench's drop-in when addr is "".
func litePeer(ctx context.Context, d *Device, addr string) error {
	cmd := "sudo -n rm -f " + liteDropIn + " && sudo -n rmdir --ignore-fail-on-non-empty " + path.Dir(liteDropIn)
	if addr != "" {
		conf := "[Service]\nExecStart=\nExecStart=/usr/local/bin/cbb service -peer " + addr + "\n"
		cmd = "sudo -n mkdir -p " + path.Dir(liteDropIn) + " && printf '" + conf + "' | sudo -n tee " + liteDropIn + " >/dev/null"
	}
	_, err := Run(ctx, d, cmd+" && sudo -n systemctl daemon-reload && sudo -n systemctl restart cbb", "")
	return err
}

// deviceOf returns the device's ID from its status.
func deviceOf(ctx context.Context, d *Device) (string, error) {
	out, err := Run(ctx, d, cbbCmd(d)+" status", "")
	if err != nil {
		return "", err
	}
	if m := deviceRE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("%s shows no device ID in its status: %q", d.Name, firstLine(out))
}

// pairOne admits a device into the hub's group: cbb pair on the hub, and
// cbb pair -code with its code on the device (as the service's user on the
// lite member). It returns the code it used.
func pairOne(ctx context.Context, hub, d *Device) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	type window struct{ code, addr string }
	got := make(chan window, 1)
	done := make(chan error, 1)
	go func() {
		var w window
		done <- Stream(ctx, hub, adminCmd(hub)+" pair", func(line string) {
			if m := addrRE.FindStringSubmatch(line); m != nil {
				w.addr = m[1]
			}
			if m := codeRE.FindStringSubmatch(line); m != nil {
				w.code = m[1] + m[2]
			}
			if strings.HasPrefix(line, "Waiting up to") && w.code != "" {
				select {
				case got <- w:
				default:
				}
			}
		})
	}()
	var w window
	select {
	case w = <-got:
	case err := <-done:
		if err == nil {
			err = errors.New("cbb pair ended without a code")
		}
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("cbb pair on %s showed no code", hub.Name)
	}
	addr := d.addrFor(hub, w.addr)
	join := adminCmd(d) + " pair -code"
	if d.OS == "linux-lite" {
		// The lite member joins as its service's user, which alone may
		// write its keys (lite/README.md); the bench user has sudo.
		join = "sudo -n -u cbb " + cbbCmd(d) + " pair -code"
	}
	if d.OS == "linux-lite" || addr != "" {
		if addr == "" {
			cancel()
			return w.code, fmt.Errorf("the lite member joins at an address; set address for %s in the inventory", hub.Name)
		}
		join += " " + addr
	}
	if _, err := Run(ctx, d, join, w.code+"\n"); err != nil {
		cancel()
		return w.code, noSudo(d, err)
	}
	if err := <-done; err != nil {
		return w.code, fmt.Errorf("cbb pair on %s did not see %s join: %w", hub.Name, d.Name, err)
	}
	return w.code, nil
}

// addrFor returns the address d dials to pair with hub: the hub's address in
// the inventory, the one cbb pair printed for a lite member (which cannot
// search), or "" to find it on the network.
func (d *Device) addrFor(hub *Device, printed string) string {
	if hub.Address != "" {
		return hub.Address
	}
	if d.OS == "linux-lite" {
		return printed
	}
	return ""
}

func runID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b)
}

// shareClipboard puts a device that just made or joined the group in the
// sync mode shared, as the sync cases need: a new device keeps its own
// clipboard.
func shareClipboard(ctx context.Context, d *Device) error { return setMode(ctx, d, "shared") }

// setMode sets the device's sync mode, which is on the admin socket.
func setMode(ctx context.Context, d *Device, mode string) error {
	_, err := Run(ctx, d, adminCmd(d)+" sync "+syncWord(mode), "")
	return noSudo(d, err)
}

// syncWord is what cbb sync takes for a sync mode: on for shared, off for
// own (docs/design.md, "Sync on and off").
func syncWord(mode string) string {
	if mode == "own" {
		return "off"
	}
	return "on"
}

// adminCmd runs cbb for a command that changes the group. Such commands go
// to the admin socket, which only root and the service's own account reach
// (internal/control, IsAdmin): on Linux and macOS the bench user runs them
// with sudo, without a password (docs/testbench.md, section 13). In the
// container cbb runs as the service's user; on Windows the SSH user is an
// administrator.
func adminCmd(d *Device) string {
	switch d.OS {
	case "linux", "linux-lite", "darwin", "freebsd":
		return "sudo -n " + cbbCmd(d)
	}
	return cbbCmd(d)
}

// sudoRefused tells whether a command failed because sudo wanted a
// password: the device lacks the bench's sudoers rule.
func sudoRefused(err error) bool {
	var re *RunError
	return errors.As(err, &re) && (strings.Contains(re.Output, "sudo: a password is required") ||
		strings.Contains(re.Output, "sudo: a terminal is required") ||
		strings.Contains(re.Output, "is not allowed to execute"))
}

// noSudo turns a refused sudo into a skipped case: the device cannot take
// part until it has the bench's sudoers rule, which is no fault of the build
// under test.
func noSudo(d *Device, err error) error {
	if sudoRefused(err) {
		return Skipped(d.Name + " runs no sudo without a password for cbb; add the bench's sudoers rule (docs/testbench.md, section 13)")
	}
	return err
}

// All runs every suite of the harness in turn: check, then each of the
// others after a quick reset (R1 without the install), the fleet on the
// controller's containers, the time suite on its time-scaled build, and a
// last quick reset, so the devices end in no group. One report holds them
// all.
func All(ctx context.Context, r *Report, inv *Inventory, devices []*Device, timeout time.Duration, stopForwarder bool, cbb, cbbTime string, fleetSize int) {
	Check(ctx, r, devices)
	if r.Failed() > 0 {
		r.Skip("all", "check failed; the other suites need a healthy bench")
		return
	}
	reset := func(name string) {
		r.within(name + "/")
		Reset(ctx, r, devices, nil, true)
		r.within("")
	}
	for _, s := range suites[1:] {
		if ctx.Err() != nil {
			return
		}
		if s == "fleet" {
			// The fleet is the controller's own containers: no reset.
			if cbb == "" {
				r.Skip("fleet", "give -cbb FILE, a static Linux cbb of the build for the controller, to run the fleet")
			} else {
				FleetSuite(ctx, r, cbb, fleetSize, timeout)
			}
			continue
		}
		if s == "time" {
			if cbbTime == "" {
				r.Skip("time", "give -cbb-time FILE, the same cbb built with -tags benchtime, to run the time suite")
			} else {
				TimeSuite(ctx, r, cbbTime, timeout)
			}
			continue
		}
		reset("before-" + s)
		switch s {
		case "smoke":
			Smoke(ctx, r, inv, devices, timeout)
		case "full":
			Full(ctx, r, devices, timeout)
		case "faults":
			Faults(ctx, r, devices, timeout)
		case "desktop":
			Desktop(ctx, r, devices, timeout)
		case "away":
			Away(ctx, r, inv, devices, timeout, stopForwarder)
		case "relay":
			Relay(ctx, r, inv, devices, timeout)
		}
	}
	reset("after")
}
