// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"crypto/sha256"
	"encoding/base64"
)

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

// projectPins are the pins of its key that this release knows. keys.json
// may name others (docs/protocol.md, section 16), which take their place.
var projectPins = []string{"hnHvkm6ZrTMmfPEP4Bo0s38nlnNKeyXEdhQNKYt2Pzw="}

// ProjectPins returns the pins a member accepts from the project's relay:
// those of the keys keys.json lists for it (each a SubjectPublicKeyInfo,
// DER) when it lists any, which lets a new key reach the devices without a
// release and the old and the new pin hold while it changes, else the
// built-in ones.
func ProjectPins(listed [][]byte) []string {
	if len(listed) == 0 {
		return append([]string(nil), projectPins...)
	}
	pins := make([]string, 0, len(listed))
	for _, spki := range listed {
		h := sha256.Sum256(spki)
		pins = append(pins, base64.StdEncoding.EncodeToString(h[:]))
	}
	return pins
}
