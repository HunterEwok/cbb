// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !freebsd

package agent

import "context"

// runDesktop is the agent on a Linux desktop; Run calls it only there.
func runDesktop(context.Context, string, func(string, ...any)) error { return nil }
