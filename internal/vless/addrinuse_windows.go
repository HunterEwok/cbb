// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import "golang.org/x/sys/windows"

// errAddrInUse is the error of a bind to a port another socket holds.
var errAddrInUse error = windows.WSAEADDRINUSE
