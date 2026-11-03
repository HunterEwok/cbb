// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package mdns

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestSystemNetwork runs two responders on the host's real sockets, as two
// members would on one network: they share port 5353 and find each other
// through multicast loopback.
func TestSystemNetwork(t *testing.T) {
	probe, err := listen(t.Logf, nil)
	if err != nil {
		t.Skipf("cannot listen on port 5353: %v", err)
	}
	ifaces, err := probe.interfaces()
	probe.close()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no interface with a private address")
	}
	found := make(chan []Peer, 16)
	start := func(id string, port uint16, onPeers func([]Peer)) {
		r, err := New(Config{ID: id, Port: port, TXT: []string{"v=1"}, OnPeers: onPeers, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx) }()
		t.Cleanup(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("Run: %v", err)
			}
		})
	}
	start(idA, 4001, func(p []Peer) { found <- p })
	start(idB, 4002, nil)
	timeout := time.After(10 * time.Second)
	for {
		select {
		case p := <-found:
			for _, peer := range p {
				if peer.ID == idB && peer.Port == 4002 && len(peer.Addrs) > 0 {
					return
				}
			}
		case <-timeout:
			t.Fatal("A did not find B on the system network")
		}
	}
}

// TestAvahi checks that avahi, the usual mDNS daemon on Linux, sees the
// member while both share port 5353: it browses the service, resolves the
// host name and, while the member holds it, cbb.local. It needs
// avahi-daemon running and the avahi tools, so it runs only when
// CBB_TEST_AVAHI is set, for example in a container.
func TestAvahi(t *testing.T) {
	if os.Getenv("CBB_TEST_AVAHI") == "" {
		t.Skip("set CBB_TEST_AVAHI to run it against a running avahi-daemon")
	}
	r, err := New(Config{ID: idA, Port: 4001, TXT: []string{"v=1", "g=0123456789abcdef"}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	defer func() { cancel(); <-done }()

	run := func(args ...string) string {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Logf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	eventually := func(what string, args []string, want ...string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			out := run(args...)
			ok := true
			for _, w := range want {
				ok = ok && strings.Contains(out, w)
			}
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: avahi did not show %q; last output:\n%s", what, want, out)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	eventually("browse", []string{"avahi-browse", "-rtp", "_cbb._tcp"},
		idA, "cb-"+idA+".local", ";4001;", "g=0123456789abcdef")
	eventually("host name", []string{"avahi-resolve", "-4", "-n", "cb-" + idA + ".local"}, "cb-"+idA+".local")
	r.SetHolder(true)
	eventually("cbb.local", []string{"avahi-resolve", "-4", "-n", "cbb.local"}, "cbb.local\t")
}
