// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"encoding/json"
	"testing"
)

// TestManifestRefusesNegativeZero: "-0" is no integer as signed bodies
// write them.
func TestManifestRefusesNegativeZero(t *testing.T) {
	var m Manifest
	if err := json.Unmarshal([]byte(`{"size":-0}`), &m); err == nil {
		t.Error("a manifest with -0 decoded")
	}
}
