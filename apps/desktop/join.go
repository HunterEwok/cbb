// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import "strings"

// JoinGroup joins a group by the six digits of a pairing window open on
// one of its devices (cbb pair -code as the administrator): on 0.6 a
// device in no group dials the window, and none waits for a phone to dial
// it (D-119). The digits go on standard input, never the command line.
func (d *Desk) JoinGroup(code string) {
	d.adminWith([]string{"pair", "-code"}, strings.TrimSpace(code)+"\n", "Joined the group.")
}
