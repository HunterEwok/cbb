// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/HunterEwok/cbb/internal/hlc"
)

// TestEdgeEvents: a sealed mark is a mark, and an unread event needs its
// sealed copy and a sane ID, origin and time.
func TestEdgeEvents(t *testing.T) {
	if !(Event{Sealed: &Sealed{}}).IsMark() {
		t.Error("a sealed copy without its payload is no mark")
	}
	if (Event{Sealed: &Sealed{Payload: []byte{1}}}).IsMark() {
		t.Error("a sealed copy with its payload is a mark")
	}
	if err := (Event{Unread: true}).Validate(); err == nil {
		t.Error("an unread event without its sealed copy is valid")
	}
	if err := (Event{Unread: true, Sealed: &Sealed{}, ID: "x"}).Validate(); err == nil {
		t.Error("an unread event with a bad ID is valid")
	}
	ok := Event{Unread: true, Sealed: &Sealed{}, ID: NewID(), Origin: NewID(), Time: hlc.Timestamp{Wall: 1, Logical: 1}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a sane unread event: %v", err)
	}
}

// TestManifestRefusesNegativeZero: "-0" is no integer as signed bodies
// write them.
func TestManifestRefusesNegativeZero(t *testing.T) {
	var m Manifest
	if err := json.Unmarshal([]byte(`{"size":-0}`), &m); err == nil {
		t.Error("a manifest with -0 decoded")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("full") }

// TestSealBlobStopsOnErrors: a short source or a writer that fails stops
// the blob.
func TestSealBlobStopsOnErrors(t *testing.T) {
	key := NewKey()
	if _, err := SealBlob(key, bytes.NewReader([]byte("short")), 100, &bytes.Buffer{}); err == nil {
		t.Error("a source shorter than the parts sealed")
	}
	if _, err := SealBlob(key, bytes.NewReader([]byte("parts")), 5, failingWriter{}); err == nil {
		t.Error("a writer that fails took the blob")
	}
}
