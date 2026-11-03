// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/HunterEwok/cbb/internal/control"
)

// cmdMode shows or changes this device's sync mode: what moves between its
// clipboard and the group. With -on, an admin sets another device's mode.
func cmdMode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mode", flag.ContinueOnError)
	fs.SetOutput(stderr)
	on := fs.String("on", "", "the device, by name or ID, whose mode to set (on an admin)")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() > 1 || *on != "" && fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: cbb mode [own|shared|receive|send]\n       cbb mode -on DEVICE own|shared|receive|send")
		return 2
	}
	h := control.Header{Op: control.OpStatus}
	if fs.NArg() == 1 {
		h = control.Header{Op: control.OpMode, Name: fs.Arg(0), Device: *on}
	}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h})
	if err != nil {
		return fail(stderr, err)
	}
	if *on != "" {
		fmt.Fprintf(stdout, "%s is in sync mode %s now.\n", *on, fs.Arg(0))
		return 0
	}
	if m.Status == nil {
		return fail(stderr, errors.New("the service sent no status"))
	}
	if m.Status.Group == "" {
		return fail(stderr, errors.New("this device is in no group; run cbb new here to start one, or cbb pair to join one"))
	}
	fmt.Fprintln(stdout, modeLine(m.Status.Mode))
	return 0
}

// modeLine says what the sync mode mode does.
func modeLine(mode string) string {
	switch mode {
	case "own":
		return "Sync mode own: this device keeps its clipboard to itself; cbb paste prints the group's text, and cbb copy sends to the group."
	case "shared":
		return "Sync mode shared: copies here go to the group, and the group's copies come here."
	case "receive":
		return "Sync mode receive: the group's copies come here, and copies here stay here."
	case "send":
		return "Sync mode send: copies here go to the group, and the group's copies do not come here."
	}
	return "Sync mode " + mode + "."
}
