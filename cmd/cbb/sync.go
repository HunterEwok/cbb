// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
)

// cmdSync shows whether this device syncs its clipboard with the group, or
// turns sync on, or off for a while or until turned on (design.md, "Sync on
// or off"). With -on, an admin turns it on or off on another device.
func cmdSync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	on := fs.String("on", "", "the device, by name or ID, to turn sync on or off on (on an admin)")
	dur := fs.Duration("for", 0, "with off: how long, up to 720h; until cbb sync on if left out")
	if fs.Parse(args) != nil {
		return 2
	}
	// The flags may follow on or off too: cbb sync off -for 1h.
	var word []string
	if fs.NArg() > 1 {
		word = fs.Args()[:1]
		if fs.Parse(fs.Args()[1:]) != nil {
			return 2
		}
	}
	args = append(word, fs.Args()...)
	arg := func(i int) string { return args[i] }
	narg := len(args)
	usage := func() int {
		fmt.Fprintln(stderr, "usage: cbb sync [on | off [-for DURATION]]\n       cbb sync -on DEVICE on|off")
		return 2
	}
	switch {
	case narg > 1, *on != "" && narg != 1, narg == 1 && arg(0) != "on" && arg(0) != "off":
		return usage()
	case *dur != 0 && (arg(0) != "off" || *on != ""):
		fmt.Fprintln(stderr, "cbb: -for goes with cbb sync off on this device")
		return 2
	case *dur < 0 || *dur > group.MaxMute || *dur > 0 && *dur < time.Millisecond:
		fmt.Fprintf(stderr, "cbb: -for is from 1ms to %v\n", group.MaxMute)
		return 2
	}
	h := control.Header{Op: control.OpStatus}
	if narg == 1 {
		h = control.Header{Op: control.OpSync, Name: arg(0), Device: *on, ForMS: dur.Milliseconds()}
	}
	dial := func() (*control.Client, error) { return control.Dial(control.SocketPath()) }
	if control.NeedsAdmin(h) {
		dial = func() (*control.Client, error) { return control.DialFor(h.Op) }
	}
	c, err := dial()
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	if *on != "" {
		fmt.Fprintf(stdout, "Sync is %s on %s now.\n", arg(0), *on)
		return 0
	}
	if m.Status == nil {
		return fail(stderr, errors.New("the service sent no status"))
	}
	if m.Status.Group == "" {
		return fail(stderr, errors.New("this device is in no group; run cbb new here to start one, or cbb pair to join one"))
	}
	fmt.Fprintln(stdout, syncLine(m.Status))
	return 0
}

// syncLine says whether sync is on, and until when it is off.
func syncLine(st *control.Status) string {
	switch {
	case st.Mode == "shared":
		return "Sync is on: copies here go to the group, and the group's copies come here."
	case st.SyncUntilMS != 0:
		return "Sync is off until " + time.UnixMilli(st.SyncUntilMS).Format("2006-01-02 15:04") + ": this clipboard is this device's own; cbb paste prints the group's text, and cbb copy sends to the group."
	}
	return "Sync is off until cbb sync on: this clipboard is this device's own; cbb paste prints the group's text, and cbb copy sends to the group."
}
