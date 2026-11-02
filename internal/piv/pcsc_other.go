// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !(linux || freebsd || openbsd || netbsd || dragonfly || windows || (darwin && cgo))

package piv

import "errors"

// cards: this build reaches no PC/SC; a Mac needs cbb built with cgo, as
// the releases are.
func cards() ([]Card, error) {
	return nil, errors.New("this build of cbb cannot reach a YubiKey: use a release build")
}
