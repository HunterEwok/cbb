// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package main

import (
	"context"
	"fmt"
	"io"
)

// runUinput refuses: the uinput helper is Linux's.
func runUinput(_ context.Context, stderr io.Writer) int {
	fmt.Fprintln(stderr, "cbb: the uinput helper runs only on Linux")
	return 2
}
