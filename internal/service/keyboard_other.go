// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux

package service

import (
	"context"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
)

// Only Linux has the Bluetooth keyboard (keyboard_linux.go): BlueZ lets a
// program be one, macOS and Windows do not, and the D-Bus library is left
// out of the other systems' builds.

// keyboardDialer stands for the Linux build's connection to BlueZ.
type keyboardDialer = func() (any, error)

// keyboardState is empty: there is never a keyboard here.
type keyboardState struct{}

func (keyboardState) status() *control.Keyboard { return nil }

func (s *Service) applyKeyboard() error { return nil }

func (s *Service) closeKeyboard() {}

func (s *Service) keyboard(context.Context, *control.Message) error { return errKeyboardOS }

func (s *Service) keyboardStatus() *control.Keyboard { return s.kbd.status() }

func (s *Service) nextKeyboardLayout() error { return &actions.Refusal{Reason: errKeyboardOS.Error()} }

func (s *Service) keyboardPastes() bool { return false }

func (s *Service) keyboardPaste(group.CommandBody, string, bool, func() bool) (node.Result, bool) {
	return node.Result{}, false
}
