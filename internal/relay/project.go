// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

// The project's open relay on cbb.tools, which cbb global relay default
// names, so that nobody types its address or key. It runs on a port of its
// own, beside the project's forwarder on 8764.
const (
	// ProjectHost is its address, resolved when the relay is set, and the
	// name keys.json and entries.json give it.
	ProjectHost = "cbb.tools:8765"
	// Project stands for both in cbb global relay, and for its key in a
	// relay request: the service takes the pins it accepts at each start.
	Project = "default"
)
