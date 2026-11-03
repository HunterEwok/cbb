// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"strings"
	"testing"
)

func TestDescribeHolders(t *testing.T) {
	out := `USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
root     mdns-repeat 812  3   udp4   *:5353                *:*
avahi    avahi-daem 900   14  udp4   *:5353                *:*
avahi    avahi-daem 900   15  udp6   *:5353                *:*
cbb cbb 77    9   udp4   *:5353                *:*
`
	got := describeHolders(out, 77)
	if !strings.Contains(got, "mdns-repeat (user root), avahi-daem (user avahi),") || strings.Contains(got, "cbb (user") {
		t.Errorf("describeHolders = %q", got)
	}
	if got := describeHolders("USER COMMAND PID FD PROTO LOCAL FOREIGN\n", 1); got != "" {
		t.Errorf("no holders = %q", got)
	}
}
