// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package desktop

import (
	"context"
	"os"
	"time"

	"github.com/HunterEwok/cbb/internal/ei"
	"github.com/HunterEwok/cbb/internal/uinput"
)

func (p *portal) paste() error {
	return p.press([]ei.Key{{Code: ei.KeyLeftShift, Press: true}, {Code: ei.KeyInsert, Press: true},
		{Code: ei.KeyInsert}, {Code: ei.KeyLeftShift}})
}

func (p *portal) enter() error {
	return p.press([]ei.Key{{Code: ei.KeyEnter, Press: true}, {Code: ei.KeyEnter}})
}

// pasteKeys returns the way to press a paste's keys where the session
// offers no protocol for it: the uinput helper when the user installed it,
// since they chose it and it asks nothing on the screen, else the
// RemoteDesktop portal; nil when neither is there.
func pasteKeys(logf func(string, ...any)) keyboard {
	if k := newKeysHelper(); k != nil {
		return k
	}
	if p := newPortal(logf); p != nil {
		return p
	}
	return nil
}

func closeKeys(k keyboard) {
	if p, ok := k.(*portal); ok {
		p.close()
	}
}

// keysHelper is the uinput helper (internal/uinput), which presses the
// keys for the user of the active session under the grant of the inject.
type keysHelper struct{ socket, grant string }

// newKeysHelper returns the helper when install.sh --uinput installed it,
// or nil.
func newKeysHelper() keyboard {
	if _, err := os.Stat(uinput.Socket); err != nil {
		return nil
	}
	return keysHelper{socket: uinput.Socket}
}

func (k keysHelper) withGrant(g string) keyboard { k.grant = g; return k }
func (k keysHelper) ready() error                { return nil }
func (k keysHelper) paste() error                { return k.ask("paste") }
func (k keysHelper) enter() error                { return k.ask("enter") }

func (k keysHelper) ask(req string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return uinput.Ask(ctx, k.socket, req, k.grant)
}
