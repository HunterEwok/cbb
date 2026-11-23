// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
)

// listens reports whether something on d's network takes a TCP connection
// to addr.
func listens(ctx context.Context, from *Device, addr string) bool {
	host, port, _ := strings.Cut(addr, ":")
	_, err := Run(ctx, from, fmt.Sprintf("timeout 3 bash -c '</dev/tcp/%s/%s'", host, port), "")
	return err == nil
}
