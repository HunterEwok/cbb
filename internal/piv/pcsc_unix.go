// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd || openbsd || netbsd || dragonfly

package piv

import (
	"errors"
	"fmt"
	"os"

	pcsc "github.com/gballet/go-libpcsclite"
)

// cards connects to every card in the readers pcscd lists, over its
// socket, without cgo (PCSCLITE_CSOCK_NAME names another socket).
func cards() ([]Card, error) {
	ctx, err := pcsc.EstablishContext(os.Getenv("PCSCLITE_CSOCK_NAME"), pcsc.ScopeSystem)
	if err != nil {
		return nil, fmt.Errorf("a YubiKey needs pcscd, the PC/SC daemon: install it (the package pcscd or pcsc-lite) and start it: %w", err)
	}
	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		ctx.ReleaseContext()
		if err == nil {
			err = ErrNoCard
		}
		return nil, err
	}
	var out []Card
	open := &shared{ctx: ctx}
	for _, r := range readers {
		c, err := ctx.Connect(r, pcsc.ShareExclusive, pcsc.ProtocolT1)
		if err != nil {
			continue
		}
		open.n++
		out = append(out, &unixCard{c: c, ctx: open})
	}
	if len(out) == 0 {
		ctx.ReleaseContext()
		return nil, ErrNoCard
	}
	return out, nil
}

// shared is the daemon's context, released once its last card closes.
type shared struct {
	ctx *pcsc.Client
	n   int
}

type unixCard struct {
	c      *pcsc.Card
	ctx    *shared
	closed bool
}

func (u *unixCard) Transmit(apdu []byte) ([]byte, error) {
	if u.closed {
		return nil, errors.New("piv: the card is closed")
	}
	r, _, err := u.c.Transmit(apdu)
	return r, err
}

func (u *unixCard) Close() error {
	if u.closed {
		return nil
	}
	u.closed = true
	err := u.c.Disconnect(pcsc.LeaveCard)
	if u.ctx.n--; u.ctx.n == 0 {
		u.ctx.ctx.ReleaseContext()
	}
	return err
}
