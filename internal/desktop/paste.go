// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"fmt"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/lockcheck"
)

// keyboard presses a paste's keys where the board's own way cannot: the
// RemoteDesktop portal, or the uinput helper.
type keyboard interface {
	// ready returns once the keys can be pressed, or why not.
	ready() error
	paste() error // Shift+Insert
	enter() error
}

// granted is a keyboard that presses keys only under the service's grant
// of the inject, the uinput helper.
type granted interface {
	withGrant(grant string) keyboard
}

// keysInject pastes through the clipboard and kb, on GNOME and KDE and
// where the user installed the uinput helper.
func keysInject(ctx context.Context, kb keyboard, b connector.PasteBoard, text, method string, enter, secret bool) error {
	switch method {
	case "paste":
	case "type":
		return &connector.Refusal{Reason: "on this desktop remote paste pastes but does not type key by key; send it as a paste"}
	default:
		return &connector.Refusal{Reason: fmt.Sprintf("this desktop pastes, not %q", method)}
	}
	if why := lockcheck.Reason(connector.NoLockCheck(ctx)); why != "" {
		return &connector.Refusal{Reason: why}
	}
	if k, ok := kb.(granted); ok {
		kb = k.withGrant(connector.KeysGrant(ctx))
	}
	if err := kb.ready(); err != nil {
		return err
	}
	err := connector.PasteThrough(b, text, secret, kb.paste)
	if err == nil && enter {
		err = kb.enter()
	}
	return err
}
