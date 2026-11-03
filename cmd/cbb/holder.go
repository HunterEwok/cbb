// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
)

// cmdHolder shows or changes whether this computer holds
// cbb.local first, only as a fallback, or never.
func cmdHolder(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 || len(args) == 1 && helpFlag(args[0]) {
		fmt.Fprintln(stderr, "usage: cbb holder [auto|first|fallback|never]")
		return 2
	}
	h := control.Header{Op: control.OpStatus}
	if len(args) == 1 {
		h = control.Header{Op: control.OpHolder, Name: args[0]}
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
	if m.Status == nil {
		return fail(stderr, errors.New("the service sent no status"))
	}
	fmt.Fprintln(stdout, holderLine(m.Status))
	return 0
}

// cmdNetwork takes the networks this computer is on now as known, for a
// home network that it does not recognize, as after a new router.
func cmdNetwork(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: cbb network")
		return 2
	}
	c, err := control.DialFor(control.OpNetwork)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpNetwork}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "This network is one where the group is now: this computer publishes itself and takes connections here.")
	return 0
}

// quietLine says on which interfaces this computer keeps quiet, as their
// networks are new to it; "" when there is none.
func quietLine(st *control.Status) string {
	if len(st.Quiet) == 0 || st.Group == "" {
		return ""
	}
	return fmt.Sprintf("Quiet on %s: a network where this computer has not met its group, so it does not publish itself or take connections there, and only looks for the members. It does once it connects to a member there; at home after a new router, run sudo cbb network.", strings.Join(st.Quiet, ", "))
}

// holderLine says how this computer takes part in holding
// cbb.local, the name the shortcut on an iPhone reaches.
func holderLine(st *control.Status) string {
	setting := st.HoldSetting
	if setting == "auto" {
		if st.Battery {
			setting += ", a laptop"
		} else {
			setting += ", no battery"
		}
	}
	var turn string
	switch st.HoldPriority {
	case 1:
		turn = "first"
	case 2:
		turn = "as a fallback"
	}
	switch {
	case st.Group == "":
		return fmt.Sprintf("Holder of cbb.local: setting %s.", setting)
	case turn == "" && st.HoldSetting == "never":
		return fmt.Sprintf("Never holds cbb.local (setting %s).", setting)
	case turn == "":
		return "Never holds cbb.local: it does not hold the group's iPhone key."
	case st.Holder:
		return fmt.Sprintf("Answers for cbb.local (%s; setting %s).", turn, setting)
	}
	return fmt.Sprintf("Answers for cbb.local %s when elected; another member does now (setting %s).", turn, setting)
}
