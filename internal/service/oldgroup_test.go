// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// identityFile is the identity of a group made before 0.6.
const identityFile = "identity.json"

// TestUpgrade checks that a group made before 0.6 is left at start, even
// one of 0.3 without a records file, instead of being upgraded in place:
// its files move aside and the device's own settings stay.
func TestUpgrade(t *testing.T) {
	dir := t.TempDir()
	// The identity file as 0.3 wrote it: the member never reads it, only
	// sees that it is there.
	data, err := json.Marshal(map[string]any{"v": 1, "device": strings.Repeat("ab", 16), "key": []byte{1}, "cert": []byte{2}, "group_ca": []byte{3}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, identityFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(syncFile, `{"off":true}`)

	var h hub
	s := startIn(t, &h, &testService{name: "pi", dir: dir, os: "linux"})
	if st := s.status(t); st.Group != "" {
		t.Errorf("the device is still in the group %s", st.Group)
	}
	if !s.logged("made before 0.6") {
		t.Error("the service did not say it left the old group")
	}
	if _, err := os.Stat(filepath.Join(dir, "before-0.6", identityFile)); err != nil {
		t.Error("the identity did not move")
	}
	if _, err := os.Stat(filepath.Join(dir, syncFile)); err != nil {
		t.Error("the device's settings moved")
	}
}
