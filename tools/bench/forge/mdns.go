// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/mdns"
)

// The member's mDNS records (D17, D3): forge -addr DIR mdns-browse browses
// for as long as it runs and keeps the members it finds in DIR/peers, one
// line each, "ID PORT TXT...", sorted, and each change in DIR/events, a
// line "found ID" or "gone ID"; forge mdns:SECONDS:TXT,... publishes
// a member with the highest device ID, whom every full member dials when
// they share a group, with those TXT strings on port mdnsPort for SECONDS,
// and prints a line "dialed from ADDR" for each connection to the port.

// mdnsPort is the port the forge's member publishes.
const mdnsPort = 8790

// mdnsID is the forge's device ID: higher than any other, so that a full
// member of its group dials it at once.
const mdnsID = "ffffffffffffffffffffffffffffffff"

func mdnsCase(arg string) bool {
	return arg == "mdns-browse" || strings.HasPrefix(arg, "mdns:")
}

func runMDNS(dir, arg string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if arg == "mdns-browse" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		events, err := os.OpenFile(dir+"/events", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer events.Close()
		seen := map[string]bool{}
		r, err := mdns.New(mdns.Config{ID: "forge", BrowseOnly: true, OnPeers: func(peers []mdns.Peer) {
			var lines []string
			now := map[string]bool{}
			for _, p := range peers {
				lines = append(lines, strings.Join(append([]string{p.ID, strconv.Itoa(int(p.Port))}, p.TXT...), " "))
				now[p.ID] = true
				if !seen[p.ID] {
					fmt.Fprintln(events, "found", p.ID)
				}
			}
			for id := range seen {
				if !now[id] {
					fmt.Fprintln(events, "gone", id)
				}
			}
			seen = now
			slices.Sort(lines)
			text := strings.Join(lines, "\n")
			if text != "" {
				text += "\n"
			}
			os.WriteFile(dir+"/peers.new", []byte(text), 0o644)
			os.Rename(dir+"/peers.new", dir+"/peers")
		}})
		if err != nil {
			return err
		}
		fmt.Println("mdns: browsing")
		return r.Run(ctx)
	}
	f := strings.SplitN(strings.TrimPrefix(arg, "mdns:"), ":", 2)
	secs, err := strconv.Atoi(f[0])
	if err != nil || len(f) != 2 {
		return fmt.Errorf("mdns:SECONDS:TXT,..., not %q", arg)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second)
	defer cancel()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", mdnsPort))
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			fmt.Println("dialed from", host)
			c.Close()
		}
	}()
	r, err := mdns.New(mdns.Config{ID: mdnsID, Port: mdnsPort, TXT: strings.Split(f[1], ",")})
	if err != nil {
		return err
	}
	if err := r.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
