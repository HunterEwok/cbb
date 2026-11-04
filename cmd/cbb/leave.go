// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
)

// leaveQuestion is what cbb leave asks before it deletes the keys.
const leaveQuestion = `This device leaves its group: its keys and the group's files here are deleted, remote paste
and the quick actions are turned off, and the rest of the settings stay. It can then join this
group again or another one (cbb pair). The group keeps listing it until an admin removes it.
Leave the group? [y/N] `

// cmdLeave takes this device out of its group (D-83), after a question
// that -yes answers: the apps run it with -yes once their user agreed.
func cmdLeave(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	yes := false
	for _, a := range args {
		switch {
		case a == "-yes" || a == "--yes":
			yes = true
		default:
			fmt.Fprintln(stderr, "cbb: usage: cbb leave [-yes]; it deletes this device's keys and the group's files, keeps the settings, and lets it join a group again")
			return 2
		}
	}
	if !yes {
		fmt.Fprint(stdout, leaveQuestion)
		line, err := readLine(stdin)
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
		default:
			if err != nil {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintln(stdout, "Nothing changed. (cbb leave -yes leaves without the question.)")
			return 1
		}
	}
	c, err := control.DialFor(control.OpLeave)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	if _, err := c.Do(&control.Message{Header: control.Header{Op: control.OpLeave}}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "Left the group. The service restarts in no group: cbb pair joins one, cbb new starts one.")
	return 0
}
