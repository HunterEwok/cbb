// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package service

import "syscall"

var resetErrnos = []syscall.Errno{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE}
