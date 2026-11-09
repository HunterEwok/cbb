// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/phone"
)

// The joiner that listens (G17, docs/protocol.md section 6, "The joiner
// listens"): forge qr:HOW:URL has the service on this device, the group's
// root or an admin, admit the joiner whose QR code URL cbb pair showed, as
// the phone that scanned it would, and prints
//
//	qr HOW: joined NAME
//	qr HOW: refused: REASON
//
// HOW is right (the code and fingerprint of the QR code), code (a wrong
// code) or fp (another fingerprint, as for another computer). -socket
// names the service's control socket, if not the default.

func qrCase(arg string) bool { return strings.HasPrefix(arg, "qr:") }

func runQR(socket, arg string) error {
	how, raw, ok := strings.Cut(strings.TrimPrefix(arg, "qr:"), ":")
	jc, ok2 := phone.ParseJoinQR(raw)
	if !ok || !ok2 || len(jc.Addrs) == 0 {
		return fmt.Errorf("qr:HOW:URL with a QR code of cbb pair, not %q", arg)
	}
	switch how {
	case "right":
	case "code":
		jc.Code = fmt.Sprintf("%06d", (atoiOr(jc.Code)+1)%1000000)
	case "fp":
		jc.Fingerprint = "AAAA" + jc.Fingerprint[4:]
	default:
		return fmt.Errorf("qr: HOW is right, code or fp, not %q", how)
	}
	if socket == "" {
		socket = control.SocketPath()
	}
	c, err := control.Dial(control.AdminSocketFor(socket))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Minute))
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpPair, Code: jc.Code, Addrs: jc.Addrs, Fingerprint: jc.Fingerprint}})
	if err != nil {
		fmt.Printf("qr %s: refused: %v\n", how, err)
		return nil
	}
	fmt.Printf("qr %s: joined %s\n", how, m.Name)
	return nil
}

func atoiOr(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
