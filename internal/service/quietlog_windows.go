// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import "syscall"

// WSAECONNABORTED and WSAECONNRESET.
var resetErrnos = []syscall.Errno{10053, syscall.WSAECONNRESET}
