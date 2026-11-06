// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package vless

import "syscall"

// errAddrInUse is the error of a bind to a port another socket holds.
var errAddrInUse error = syscall.EADDRINUSE
