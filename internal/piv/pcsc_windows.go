// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package piv

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows' PC/SC, winscard.dll.
var (
	winscard               = windows.NewLazySystemDLL("winscard.dll")
	procEstablish          = winscard.NewProc("SCardEstablishContext")
	procRelease            = winscard.NewProc("SCardReleaseContext")
	procListReaders        = winscard.NewProc("SCardListReadersW")
	procConnect            = winscard.NewProc("SCardConnectW")
	procDisconnect         = winscard.NewProc("SCardDisconnect")
	procTransmit           = winscard.NewProc("SCardTransmit")
	errNoReaders    uint32 = 0x8010002e // SCARD_E_NO_READERS_AVAILABLE
	errNoService    uint32 = 0x8010001d // SCARD_E_NO_SERVICE
)

const (
	scopeSystem    = 2
	shareExclusive = 1
	protocolT1     = 2
	leaveCard      = 0
)

// ioRequest is SCARD_IO_REQUEST.
type ioRequest struct {
	protocol uint32
	length   uint32
}

func scardErr(what string, r uintptr) error {
	return fmt.Errorf("piv: %s: PC/SC error %#x", what, uint32(r))
}

// cards connects to every card in the readers Windows lists.
func cards() ([]Card, error) {
	var ctx uintptr
	if r, _, _ := procEstablish.Call(scopeSystem, 0, 0, uintptr(unsafe.Pointer(&ctx))); r != 0 {
		if uint32(r) == errNoService {
			return nil, ErrNoCard
		}
		return nil, scardErr("SCardEstablishContext", r)
	}
	var n uint32
	r, _, _ := procListReaders.Call(ctx, 0, 0, uintptr(unsafe.Pointer(&n)))
	if r != 0 || n == 0 {
		procRelease.Call(ctx)
		if uint32(r) == errNoReaders || r == 0 {
			return nil, ErrNoCard
		}
		return nil, scardErr("SCardListReaders", r)
	}
	buf := make([]uint16, n)
	if r, _, _ := procListReaders.Call(ctx, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r != 0 {
		procRelease.Call(ctx)
		return nil, scardErr("SCardListReaders", r)
	}
	open := &winContext{ctx: ctx}
	var out []Card
	for start := 0; start < len(buf) && buf[start] != 0; {
		end := start
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		name := buf[start : end+1]
		start = end + 1
		var card uintptr
		var proto uint32
		if r, _, _ := procConnect.Call(ctx, uintptr(unsafe.Pointer(&name[0])), shareExclusive, protocolT1,
			uintptr(unsafe.Pointer(&card)), uintptr(unsafe.Pointer(&proto))); r != 0 {
			continue
		}
		open.n++
		out = append(out, &winCard{card: card, ctx: open})
	}
	if len(out) == 0 {
		procRelease.Call(ctx)
		return nil, ErrNoCard
	}
	return out, nil
}

// winContext is the context, released once its last card closes.
type winContext struct {
	ctx uintptr
	n   int
}

type winCard struct {
	card   uintptr
	ctx    *winContext
	closed bool
}

func (w *winCard) Transmit(apdu []byte) ([]byte, error) {
	if w.closed {
		return nil, errors.New("piv: the card is closed")
	}
	send := ioRequest{protocol: protocolT1, length: uint32(unsafe.Sizeof(ioRequest{}))}
	out := make([]byte, 258)
	n := uint32(len(out))
	r, _, _ := procTransmit.Call(w.card, uintptr(unsafe.Pointer(&send)), uintptr(unsafe.Pointer(&apdu[0])), uintptr(len(apdu)), 0,
		uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&n)))
	if r != 0 {
		return nil, scardErr("SCardTransmit", r)
	}
	return out[:n], nil
}

func (w *winCard) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	procDisconnect.Call(w.card, leaveCard)
	if w.ctx.n--; w.ctx.n == 0 {
		procRelease.Call(w.ctx.ctx)
	}
	return nil
}
