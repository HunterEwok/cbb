// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestBlobRefusals checks what a blob's sealing and opening refuse: a key
// that is not 32 bytes, a segment too large or of the wrong size, sizes
// that do not fit, a short source, a writer that fails and a padding that
// is not zeros.
func TestBlobRefusals(t *testing.T) {
	key := NewKey()
	if _, err := SealSegment(key[:31], 0, true, nil); err == nil {
		t.Error("a segment sealed with a short key")
	}
	if _, err := SealSegment(key, 0, true, make([]byte, Segment+1)); err == nil {
		t.Error("a segment larger than Segment sealed")
	}
	if _, err := OpenSegment(key, 0, true, make([]byte, SealedSegment-1)); err == nil {
		t.Error("a short segment opened")
	}
	var sink bytes.Buffer
	for _, n := range []int64{0, -1, MaxMedia + 1} {
		if _, err := SealBlob(key, bytes.NewReader(nil), n, &sink); err == nil {
			t.Errorf("a blob of %d bytes sealed", n)
		}
	}
	if _, err := SealBlob(key, bytes.NewReader([]byte("ab")), 3, &sink); err == nil {
		t.Error("a blob sealed from a source shorter than it")
	}
	if _, err := SealBlob(key, bytes.NewReader([]byte("abc")), 3, failWriter{}); err == nil {
		t.Error("a blob sealed into a writer that fails")
	}
	sink.Reset()
	b, err := SealBlob(key, bytes.NewReader([]byte("abc")), 3, &sink)
	if err != nil {
		t.Fatal(err)
	}
	sealed := sink.Bytes()
	if err := OpenBlob(key, bytes.NewReader(sealed), nil, 3, io.Discard); err == nil {
		t.Error("a blob opened without its record")
	}
	if err := OpenBlob(key, bytes.NewReader(sealed), b, 3, failWriter{}); err == nil {
		t.Error("a blob opened into a writer that fails")
	}
	if err := OpenBlob(key, bytes.NewReader(sealed[:10]), b, 3, io.Discard); err == nil {
		t.Error("a short blob opened")
	}
	// Two bytes claimed of three: the third is not padding.
	if err := OpenBlob(key, bytes.NewReader(sealed), &Blob{Size: BlobSize(2)}, 2, io.Discard); err == nil {
		t.Error("a blob whose padding is not zeros opened")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("the disk is full") }
