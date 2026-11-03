// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package main

import "io"

// firewallHint ends cbb pair's note on a firewall in the way.
const firewallHint = "the home network; the installer opens it in the system's firewall (docs/guide/install.md)."

// enableVT does nothing: terminals outside Windows take escape sequences.
func enableVT(io.Writer) {}
