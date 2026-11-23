// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command forge is the bench's stand-in for an attacker and for the
// outside world (docs/maintainers/testbench-catalogue.md): in a fleet
// container it plays what a member must withstand or talk to, one case per
// run. The tunnel's cases are in tunnel.go, the stand-in for a well-known
// site that VLESS borrows in site.go, the control socket's in control.go,
// the TVs in tv.go, the mDNS records in mdns.go, watching the writes in
// watch.go, random bytes and the control socket fuzzed in fuzz.go, a
// remote invitation to a hub that is not there in invite.go, looking for a
// text in the services' memory in memscan.go, the stand-in for the
// internet in outside.go, the web server in front of a forwarder's XHTTP in
// web.go. It is never part of a release.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	state := flag.String("state", "", "the tunnel's cases: the state directory of the member to play")
	device := flag.String("device", "", "the tunnel's cases: that member's device ID, if not in -state's bench-device-id")
	addr := flag.String("addr", "", "the target's member port, HOST:PORT")
	endpoint := flag.String("endpoint", "", "the tunnel's cases: the hub's UDP address, HOST:PORT, instead of its first one")
	hubState := flag.String("hub-state", "", "the tunnel's cases: the state directory whose hub's offer to use instead of -state's")
	socket := flag.String("socket", "", "the control socket's cases: its path, if not the default")
	flag.Parse()
	if flag.NArg() > 0 && outsideCase(flag.Arg(0)) {
		// It serves until it fails.
		fmt.Fprintln(os.Stderr, "forge:", runOutside(*addr, flag.Arg(0)))
		os.Exit(1)
	}
	if flag.NArg() > 0 && webCase(flag.Arg(0)) {
		// It serves until it fails.
		fmt.Fprintln(os.Stderr, "forge:", runWeb(*addr, flag.Arg(0)))
		os.Exit(1)
	}
	if flag.Arg(0) == "memscan" {
		// forge memscan TEXT looks for TEXT in the services' memory.
		if err := runMemscan(flag.Arg(1)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if kind, ok := strings.CutPrefix(flag.Arg(0), "tv:"); ok {
		// forge -addr DIR tv:KIND plays a TV, writing what it saw in DIR.
		if err := runTV(kind, *addr); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && fuzzCase(flag.Arg(0)) {
		if err := runFuzz(*addr, *socket, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && inviteCase(flag.Arg(0)) {
		if err := runInvite(flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && probeCase(flag.Arg(0)) {
		if err := runProbe(flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && mdnsCase(flag.Arg(0)) {
		if err := runMDNS(*addr, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && watchCase(flag.Arg(0)) {
		if err := runWatch(*socket, flag.Arg(0)); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && controlCase(flag.Arg(0)) {
		if err := runControl(*socket, flag.Args()); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() > 0 && tunnelCase(flag.Arg(0)) {
		if err := runTunnel(*state, *device, *hubState, *endpoint, flag.Args()); err != nil {
			fmt.Fprintln(os.Stderr, "forge:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "forge: no case %q\n", strings.Join(flag.Args(), " "))
	os.Exit(2)
}
