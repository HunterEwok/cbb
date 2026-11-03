// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/HunterEwok/cbb/internal/mdns"
)

// runAs opens what only root may open and then runs the process as the
// user name, for cbb service -user: on FreeBSD the mDNS sockets, which
// share port 5353 with another user's responder, such as avahi, only when
// root opened them. Failing to open them is no reason to stop: the
// responder tries again when it starts, and says who holds the port.
func runAs(name string, logf func(string, ...any)) error {
	if os.Geteuid() != 0 {
		return errors.New("-user needs root")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	gids := []int{gid}
	if ids, err := u.GroupIds(); err == nil {
		for _, s := range ids {
			if g, err := strconv.Atoi(s); err == nil && g != gid {
				gids = append(gids, g)
			}
		}
	}
	if err := mdns.Preopen(); err != nil {
		logf("cbb: opening the mDNS sockets as root: %v", err)
	}
	if err := syscall.Setgroups(gids); err != nil {
		return fmt.Errorf("setting the groups of %s: %w", name, err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setting the group of %s: %w", name, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("becoming %s: %w", name, err)
	}
	if syscall.Setuid(0) == nil {
		return errors.New("root came back after becoming " + name)
	}
	os.Setenv("HOME", u.HomeDir)
	os.Setenv("USER", name)
	os.Setenv("LOGNAME", name)
	return nil
}
