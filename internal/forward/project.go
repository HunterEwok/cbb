// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/sha256"
	"encoding/base64"
)

// The project's forwarder, which a hub uses when cbb global hub names no
// other (cbb global hub -forwarder default, or a hub without addresses),
// so that nobody types its address or key.
const (
	// ProjectHost is its address, resolved when the hub is set.
	ProjectHost = "cbb.tools:8764"
	// ProjectKey stands for its key in a hub request: the service fills in
	// the pins it accepts.
	ProjectKey = "default"
)

// projectPins are the pins of its key that this release knows. keys.json
// may name others (docs/protocol.md, section 16), which take their place.
var projectPins = []string{"efzUG2YzJBqS8FfojZGwqioECt46VzQcFo3oWpPru/g="}

// ProjectPins returns the pins a hub accepts from the project's forwarder:
// those of the keys keys.json lists for it (each a SubjectPublicKeyInfo,
// DER) when it lists any, which lets a new key reach the devices without a
// release and both pins hold while it changes, else the built-in ones.
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
