// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build darwin && cgo

package piv

/*
#cgo LDFLAGS: -framework PCSC
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func scardErr(what string, r C.LONG) error {
	return fmt.Errorf("piv: %s: PC/SC error %#x", what, uint32(r))
}

// cards connects to every card in the readers macOS lists.
func cards() ([]Card, error) {
	var ctx C.SCARDCONTEXT
	if r := C.SCardEstablishContext(C.SCARD_SCOPE_SYSTEM, nil, nil, &ctx); r != C.SCARD_S_SUCCESS {
		return nil, scardErr("SCardEstablishContext", r)
	}
	var n C.uint32_t
	if r := C.SCardListReaders(ctx, nil, nil, &n); r != C.SCARD_S_SUCCESS || n == 0 {
		C.SCardReleaseContext(ctx)
		if r == C.SCARD_E_NO_READERS_AVAILABLE || r == C.SCARD_S_SUCCESS {
			return nil, ErrNoCard
		}
		return nil, scardErr("SCardListReaders", r)
	}
	buf := (*C.char)(C.malloc(C.size_t(n)))
	defer C.free(unsafe.Pointer(buf))
	if r := C.SCardListReaders(ctx, nil, buf, &n); r != C.SCARD_S_SUCCESS {
		C.SCardReleaseContext(ctx)
		return nil, scardErr("SCardListReaders", r)
	}
	names := C.GoBytes(unsafe.Pointer(buf), C.int(n))
	open := &macContext{ctx: ctx}
	var out []Card
	for start := 0; start < len(names) && names[start] != 0; {
		end := start
		for end < len(names) && names[end] != 0 {
			end++
		}
		name := C.CString(string(names[start:end]))
		start = end + 1
		var card C.SCARDHANDLE
		var proto C.uint32_t
		r := C.SCardConnect(ctx, name, C.SCARD_SHARE_EXCLUSIVE, C.SCARD_PROTOCOL_T1, &card, &proto)
		C.free(unsafe.Pointer(name))
		if r != C.SCARD_S_SUCCESS {
			continue
		}
		open.n++
		out = append(out, &macCard{card: card, ctx: open})
	}
	if len(out) == 0 {
		C.SCardReleaseContext(ctx)
		return nil, ErrNoCard
	}
	return out, nil
}

// macContext is the context, released once its last card closes.
type macContext struct {
	ctx C.SCARDCONTEXT
	n   int
}

type macCard struct {
	card   C.SCARDHANDLE
	ctx    *macContext
	closed bool
}

func (m *macCard) Transmit(apdu []byte) ([]byte, error) {
	if m.closed {
		return nil, errors.New("piv: the card is closed")
	}
	in := C.CBytes(apdu)
	defer C.free(in)
	out := (*C.uchar)(C.malloc(258))
	defer C.free(unsafe.Pointer(out))
	n := C.uint32_t(258)
	if r := C.SCardTransmit(m.card, C.SCARD_PCI_T1, (*C.uchar)(in), C.uint32_t(len(apdu)), nil, out, &n); r != C.SCARD_S_SUCCESS {
		return nil, scardErr("SCardTransmit", r)
	}
	return C.GoBytes(unsafe.Pointer(out), C.int(n)), nil
}

func (m *macCard) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	C.SCardDisconnect(m.card, C.SCARD_LEAVE_CARD)
	if m.ctx.n--; m.ctx.n == 0 {
		C.SCardReleaseContext(m.ctx.ctx)
	}
	return nil
}
