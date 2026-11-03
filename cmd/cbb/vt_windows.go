// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// firewallHint ends cbb pair's note on a firewall in the way.
const firewallHint = "the home network; install.ps1 adds it to Windows Firewall (docs/guide/install.md)."

// enableVT turns on the console's escape sequences for w when it is a
// console. Windows Terminal has them on, but the console host that
// Windows PowerShell 5.1 and cmd open in has them off and prints them as
// text, which breaks the QR code. A pipe, a file or an older Windows is
// left as it is.
func enableVT(w io.Writer) {
	f, ok := w.(*os.File)
	if !ok {
		return
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
