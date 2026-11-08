// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
)

// cmdMute, on an admin, mutes a device of the group, whose copies then
// stay its own (design.md, "Muting a device"); with unmute set it ends the
// mute.
func cmdMute(args []string, unmute bool, stdout, stderr io.Writer) int {
	name := "mute"
	if unmute {
		name = "unmute"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	on := fs.String("on", "", "the device, by name or ID, to mute for the whole group (on an admin)")
	var dur *time.Duration
	if !unmute {
		dur = fs.Duration("for", 0, "how long, up to 720h; until cbb unmute if left out")
	}
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() > 0 || *on == "" {
		if unmute {
			fmt.Fprintln(stderr, "usage: cbb unmute -on DEVICE")
		} else {
			fmt.Fprintln(stderr, "usage: cbb mute -on DEVICE [-for DURATION]")
		}
		if *on == "" {
			fmt.Fprintln(stderr, "cbb sync off turns this device's own sync off.")
		}
		return 2
	}
	h := control.Header{Op: control.OpMute, Device: *on}
	if unmute {
		h.Op = control.OpUnmute
	} else {
		if *dur < 0 || *dur > group.MaxMute || *dur > 0 && *dur < time.Millisecond {
			fmt.Fprintf(stderr, "cbb: -for is from 1ms to %v\n", group.MaxMute)
			return 2
		}
		h.ForMS = dur.Milliseconds()
	}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: h}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, muteDone(h, time.Now()))
	return 0
}

// muteDone says what a mute or unmute did.
func muteDone(h control.Header, now time.Time) string {
	until := "until an admin unmutes it"
	if h.ForMS > 0 {
		until = "until " + now.Add(time.Duration(h.ForMS)*time.Millisecond).Format("2006-01-02 15:04")
	}
	if h.Op == control.OpUnmute {
		return fmt.Sprintf("%s is no longer muted: its copies reach the group again.", h.Device)
	}
	return fmt.Sprintf("%s is muted %s: its copies do not reach the group.", h.Device, until)
}

// muteLines describe this device's mute for cbb status.
func muteLines(st *control.Status) []string {
	at := func(ms int64) string { return time.UnixMilli(ms).Format("2006-01-02 15:04") }
	var out []string
	switch {
	case st.Muted && st.MutedUntilMS == 0:
		out = append(out, "An admin muted this device: its copies do not reach the group until an admin unmutes it.")
	case st.Muted:
		out = append(out, "An admin muted this device until "+at(st.MutedUntilMS)+": its copies do not reach the group until then.")
	}
	return out
}
