// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build darwin && cgo

package pasteboard

import (
	"fmt"
	"os"
	"testing"
)

// The tests use private pasteboards, never the general one, so they leave
// the user's clipboard alone.
func private(t *testing.T) *Board {
	t.Helper()
	b := Private(fmt.Sprintf("tools.cbb.test.%d.%s", os.Getpid(), t.Name()))
	t.Cleanup(b.Release)
	return b
}

func TestWriteRead(t *testing.T) {
	b := private(t)
	before := b.ChangeCount()
	text := "hello \u043f\u0440\u0438\u0432\u0435\u0442 \U0001F600\nsecond line\x00after a NUL"
	change, err := b.Write(text, false)
	if err != nil {
		t.Fatal(err)
	}
	if change <= before || b.ChangeCount() != change {
		t.Errorf("change counter %d -> %d (now %d)", before, change, b.ChangeCount())
	}
	it, ok, err := b.Read()
	if err != nil || !ok {
		t.Fatalf("Read = %v, %v", ok, err)
	}
	if it.Text != text || it.Secret || it.Remote || it.Change != change {
		t.Errorf("Read = %+v", it)
	}
}

func TestSecret(t *testing.T) {
	b := private(t)
	if _, err := b.Write("hunter2", true); err != nil {
		t.Fatal(err)
	}
	it, ok, err := b.Read()
	if err != nil || !ok {
		t.Fatalf("Read = %v, %v", ok, err)
	}
	if !it.Secret || it.Text != "hunter2" {
		t.Errorf("Read of a secret = %+v", it)
	}
}

func TestEmptyAndClear(t *testing.T) {
	b := private(t)
	if _, ok, err := b.Read(); ok || err != nil {
		t.Errorf("Read of an empty pasteboard = %v, %v", ok, err)
	}
	if _, err := b.Write("x", false); err != nil {
		t.Fatal(err)
	}
	b.Clear()
	if _, ok, _ := b.Read(); ok {
		t.Error("the text survived Clear")
	}
}
