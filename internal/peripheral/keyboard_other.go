// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package peripheral

import (
	"context"

	"github.com/HunterEwok/cbb/internal/control"
)

// Only Linux has the Bluetooth keyboard (keyboard_linux.go): BlueZ lets a
// program be one, macOS and Windows do not, and the D-Bus library is left
// out of the other systems' builds.

// BusDialer stands for the Linux build's connection to BlueZ.
type BusDialer = func() (any, error)

// keyboardState is empty: there is never a keyboard here.
type keyboardState struct{}

// ApplyKeyboard does nothing: there is no keyboard here.
func (h *Host) ApplyKeyboard() error { return nil }

func (h *Host) closeKeyboard() {}

// Keyboard serves cbb keyboard, which has no keyboard here.
func (h *Host) Keyboard(context.Context, *control.Message) error { return ErrKeyboardOS }

// KeyboardStatus is nil: there is no keyboard here.
func (h *Host) KeyboardStatus() *control.Keyboard { return nil }

// NextKeyboardLayout refuses: there is no keyboard here.
func (h *Host) NextKeyboardLayout() error { return &Refusal{Reason: ErrKeyboardOS.Error()} }

func (h *Host) keyboardPastes() bool { return false }

func (h *Host) keyboardPaste(string, bool, bool, func() bool) (Result, bool) { return Result{}, false }
