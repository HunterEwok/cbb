// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
)

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
