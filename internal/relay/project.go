// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

// The project's open relay on cbb.tools, which cbb global relay default
// names, so that nobody types its address or key. It runs on a port of its
// own, beside the project's forwarder on 8764.
const (
	// ProjectHost is its address, resolved when the relay is set.
	ProjectHost = "cbb.tools:8765"
	// ProjectPin is the pin of its key, as cbb relay prints it.
	ProjectPin = "hnHvkm6ZrTMmfPEP4Bo0s38nlnNKeyXEdhQNKYt2Pzw="
	// Project stands for both in cbb global relay.
	Project = "default"
)
