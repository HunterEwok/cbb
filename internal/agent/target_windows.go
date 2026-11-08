// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package agent

import (
	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/pasteboard"
	"github.com/HunterEwok/cbb/internal/winpaste"
)

// target is the agent's remote paste target: on Windows the window
// with the focus in its session.
func target(w *pasteboard.Watch) connector.Target { return winpaste.New(w) }
