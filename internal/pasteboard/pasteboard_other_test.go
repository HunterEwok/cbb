// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build (!darwin || !cgo) && !windows

package pasteboard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/connector"
)

// TestNoPasteboard: a build without a pasteboard says so on every write,
// and a watch of it sees nothing.
func TestNoPasteboard(t *testing.T) {
	if Supported {
		t.Fatal("supported")
	}
	b := General()
	defer b.Release()
	Private("x").Release()
	if _, ok, err := b.Read(); ok || !errors.Is(err, ErrUnsupported) {
		t.Errorf("Read: %v, %v", ok, err)
	}
	w := NewWatch(b)
	if _, ok, err := w.Current(); ok || !errors.Is(err, ErrUnsupported) {
		t.Errorf("Current: %v, %v", ok, err)
	}
	for name, err := range map[string]error{
		"Write":      w.Write("x", false),
		"WriteImage": w.WriteImage(connector.Image{Type: "image/png", Data: []byte{1}}, ""),
		"WriteHTML":  w.WriteHTML("<b>x</b>", "x"),
		"WriteFiles": w.WriteFiles([]string{"/x"}),
	} {
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if w.Holds("x") {
		t.Error("holds a write that failed")
	}
	if err := w.ClearIfUnchanged(); err != nil || b.Clear() != 0 {
		t.Errorf("ClearIfUnchanged: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*pollEvery+100*time.Millisecond)
	defer cancel()
	if _, _, err := w.Next(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Next: %v", err)
	}
}
