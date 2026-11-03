// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/invite"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// An invitation to a hub that is not there (G15): forge
// invite:ADDR:PORT[,ADDR:PORT...] prints an invitation of a made-up group
// whose hub listens at those endpoints, so that a join with it reaches
// for the addresses and fails.

func inviteCase(arg string) bool { return strings.HasPrefix(arg, "invite:") }

func runInvite(arg string) error {
	tag := make([]byte, 8)
	rand.Read(tag)
	in := &invite.Invitation{Group: hex.EncodeToString(tag), Hub: string(group.NewDeviceID()), Expires: time.Now().Add(time.Hour), Secret: make([]byte, 32)}
	for _, s := range strings.Split(strings.TrimPrefix(arg, "invite:"), ",") {
		ep, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("invite:ADDR:PORT,..., not %q: %w", arg, err)
		}
		in.Endpoints = append(in.Endpoints, ep)
	}
	hub, err := tunnel.NewPrivateKey()
	if err != nil {
		return err
	}
	in.HubKey = hub.Public()
	if in.GuestKey, err = tunnel.NewPrivateKey(); err != nil {
		return err
	}
	if in.GuestPSK, err = tunnel.NewPresharedKey(); err != nil {
		return err
	}
	rand.Read(in.Secret)
	fmt.Println(in.String())
	return nil
}
