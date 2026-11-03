// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/HunterEwok/cbb/internal/connector"
)

// Board is a desktop clipboard that can be closed.
type Board interface {
	connector.Board
	io.Closer
}

// Open opens the session's clipboard: Wayland with data-control if the
// session is Wayland and the compositor has it, otherwise X11, which on
// GNOME is XWayland. It returns the name of the access it chose.
func Open(logf func(string, ...any)) (Board, string, error) {
	var errs []error
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		w, err := OpenWayland(logf)
		if err == nil {
			return w, "Wayland data-control", nil
		}
		errs = append(errs, err)
	}
	if os.Getenv("DISPLAY") != "" {
		x, err := OpenX11(logf)
		if err == nil {
			name := "X11"
			if os.Getenv("WAYLAND_DISPLAY") != "" {
				name = "X11 through XWayland"
			}
			return x, name, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, "", errors.New("desktop: no graphical session: neither WAYLAND_DISPLAY nor DISPLAY is set")
	}
	return nil, "", fmt.Errorf("desktop: %w", errors.Join(errs...))
}
