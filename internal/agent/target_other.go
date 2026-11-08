// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !windows

package agent

import (
	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/pasteboard"
)

// target is the agent's remote paste target: none on the Mac, where
// the Mac app, which holds the Accessibility permission, is the target.
func target(*pasteboard.Watch) connector.Target { return nil }
