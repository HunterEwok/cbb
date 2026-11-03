// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/phone"
)

// The joiner that listens (G17, docs/protocol.md section 6, "The joiner
// listens"): forge -signer DIR qr:HOW:URL plays the phone that scanned the
// QR code URL of cbb pair, as the admin in DIR, and prints
//
//	qr HOW: joined DEVICE
//	qr HOW: refused: REASON
//
// HOW is right (the code and fingerprint of the QR code), code (a wrong
// code) or fp (another fingerprint, as for another computer).

func qrCase(arg string) bool { return strings.HasPrefix(arg, "qr:") }

func runQR(signerDir, arg string) error {
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
	admin, err := group.Load(signerDir)
	if err != nil {
		return err
	}
	w, err := pair.Open(admin, jc.Code, pair.Options{})
	if err != nil {
		return err
	}
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := net.DialTimeout("tcp", jc.Addrs[0], 5*time.Second)
	if err != nil {
		fmt.Printf("qr %s: refused: %v\n", how, err)
		return nil
	}
	if err := w.Dial(ctx, conn, jc.Fingerprint); err != nil {
		fmt.Printf("qr %s: refused: %v\n", how, err)
		return nil
	}
	res, err := w.Result()
	if err != nil {
		fmt.Printf("qr %s: refused: %v\n", how, err)
		return nil
	}
	fmt.Printf("qr %s: joined %s\n", how, res.Device)
	return nil
}

func atoiOr(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
