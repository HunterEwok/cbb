// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/refused"
	"github.com/HunterEwok/cbb/internal/relay"
)

// cmdRelay runs a blind relay: the meeting point, on a server the user runs,
// for the devices of a group that has no computer to be its hub. It holds
// none of the group's keys and passes only the member protocol's ciphertext
// between two devices (docs/design.md, "Blind relay"). It runs in the
// foreground, for systemd or a terminal.
func cmdRelay(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8764", "the address to listen on, UDP and TCP")
	keyFile := fs.String("key", defaultRelayKey(), "the relay's keys, made on the first run")
	groups := fs.String("group", "", "the tags of the groups to serve, separated by commas, as cbb status shows them")
	open := fs.Bool("open", false, "serve every group that registers, within limits per group and per network, in place of -group")
	showKey := fs.Bool("show-key", false, "print the key for cbb global relay -key and stop")
	refusedFile := fs.String("refused", "", "the list of groups refused after an abuse report, a tag a line, read again when it changes (default: refused-groups next to the keys; \"none\" refuses none)")
	if fs.Parse(args) != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "cbb: relay takes only flags")
		return 2
	}
	keys, err := relay.LoadKeys(*keyFile)
	if err != nil {
		return fail(stderr, err)
	}
	if *showKey {
		fmt.Fprintln(stdout, keys.Pin())
		return 0
	}
	var tags []string
	for _, g := range strings.Split(*groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			tags = append(tags, g)
		}
	}
	logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
	list, err := refused.Open(*refusedFile, *keyFile)
	if err != nil {
		return fail(stderr, err)
	}
	r, err := relay.Listen(relay.Config{Listen: *listen, Keys: keys, Groups: tags, Open: *open, Refused: list, Logf: logf, Verbose: os.Getenv("CBB_DEBUG") == "1"})
	if err != nil {
		return fail(stderr, err)
	}
	serving := fmt.Sprintf("%d groups", len(tags))
	if *open {
		serving = "every group"
	}
	logf("cbb relay: listening on UDP and TCP port %s for %s; its key, for cbb global relay -key: %s", portOf(r.Addr().String()), serving, keys.Pin())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if os.Getenv("CBB_DEBUG") == "1" {
		// Counts only: the relay logs nothing about a device.
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					g, m := r.Stats()
					logf("cbb relay: %d groups, %d devices", g, m)
				}
			}
		}()
	}
	if err := r.Serve(ctx); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// portOf returns the port of a host:port address.
func portOf(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

// defaultRelayKey is where the relay keeps its keys: in systemd's state
// directory for it, or next to the service's state.
func defaultRelayKey() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return filepath.Join(d, "relay.pem")
	}
	return filepath.Join(defaultStateDir(), "relay.pem")
}
