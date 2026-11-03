// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/blekeyboard"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/keyboard"
	"github.com/HunterEwok/cbb/internal/node"
)

// This computer as a Bluetooth keyboard (docs/roadmap.md, item 25, way 3;
// internal/blekeyboard; keyboard.go elsewhere): on Linux the service registers a BLE keyboard
// with BlueZ when its user turned it on with cbb keyboard on, types what
// cbb keyboard type gives it, and, when the user sends them there, the
// remote pastes of the group's admins.

// keyboardDialer connects to the bus BlueZ is on.
type keyboardDialer = func() (*dbus.Conn, error)

// keyboardState is the Bluetooth keyboard: k is nil while it is off or
// does not run, with why in err.
type keyboardState struct {
	mu   sync.Mutex
	k    *blekeyboard.Keyboard
	conn *dbus.Conn
	err  error
}

// visibleFor is how long cbb keyboard pair makes the keyboard
// discoverable.
const visibleFor = 2 * time.Minute

// keyboardBus connects to the bus BlueZ is on: the system bus, or the
// one Config.KeyboardBus gives.
func (s *Service) keyboardBus() (*dbus.Conn, error) {
	if s.cfg.KeyboardBus != nil {
		return s.cfg.KeyboardBus()
	}
	if s.cfg.OS != group.OSLinux {
		return nil, errKeyboardOS
	}
	return dbus.ConnectSystemBus()
}

// keyboardName is what a host shows for the keyboard before it pairs:
// "CBB" and this device's name, short enough for an
// advertisement. After pairing a host shows the GAP name, the computer's
// Bluetooth name.
func (s *Service) keyboardName() string {
	// "CBB", as everything a user sees but does not type, and
	// the computer's name, within the 29 bytes a scan response leaves for it.
	name := "CBB " + s.cfg.Name
	for len(name) > 29 {
		_, n := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-n]
	}
	return strings.TrimSpace(name)
}

// applyKeyboard opens the keyboard when it is on in the settings and closes
// it when it is off. The reason it does not run is kept for the status.
func (s *Service) applyKeyboard() error {
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("reading the keyboard settings: %w", err)
	}
	s.kbd.mu.Lock()
	defer s.kbd.mu.Unlock()
	if !set.On {
		s.closeKeyboardLocked()
		s.kbd.err = nil
		return nil
	}
	if s.kbd.k != nil {
		return nil
	}
	conn, err := s.keyboardBus()
	if err == nil {
		var k *blekeyboard.Keyboard
		if k, err = blekeyboard.Open(conn, s.keyboardName(), s.cfg.StateDir, s.logf); err == nil {
			s.kbd.k, s.kbd.conn, s.kbd.err = k, conn, nil
			s.logf("cbb: this computer is a Bluetooth keyboard")
			return nil
		}
		conn.Close()
	}
	s.kbd.err = err
	s.logf("cbb: the Bluetooth keyboard: %v", err)
	return err
}

func (s *Service) closeKeyboardLocked() {
	if s.kbd.k == nil {
		return
	}
	s.kbd.k.Close()
	s.kbd.conn.Close()
	s.kbd.k, s.kbd.conn = nil, nil
}

// closeKeyboard takes the keyboard off BlueZ, as the service stops.
func (s *Service) closeKeyboard() {
	s.kbd.mu.Lock()
	defer s.kbd.mu.Unlock()
	s.closeKeyboardLocked()
}

// openKeyboard returns the running keyboard, opening it again when it
// could not open before (Bluetooth was off), or why there is none.
func (s *Service) openKeyboard() (*blekeyboard.Keyboard, error) {
	s.kbd.mu.Lock()
	k := s.kbd.k
	s.kbd.mu.Unlock()
	if k != nil {
		return k, nil
	}
	if err := s.applyKeyboard(); err != nil {
		return nil, err
	}
	s.kbd.mu.Lock()
	defer s.kbd.mu.Unlock()
	if s.kbd.k == nil {
		return nil, errors.New("the Bluetooth keyboard is off here; its user turns it on with cbb keyboard on")
	}
	return s.kbd.k, nil
}

// keyboard serves cbb keyboard: on with the settings, off, pair (visible
// for a while), type (the payload), or the status with no name.
func (s *Service) keyboard(ctx context.Context, m *control.Message) error {
	if s.cfg.KeyboardBus == nil && s.cfg.OS != group.OSLinux {
		return errKeyboardOS
	}
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil {
		return err
	}
	switch m.Name {
	case "":
		return nil
	case "on":
		if k := m.Keyboard; k != nil {
			if k.Layout != "" {
				if !keyboard.Layout(k.Layout).Known() {
					return fmt.Errorf("the layout is us or ru, not %q", k.Layout)
				}
				set.Layout = keyboard.Layout(k.Layout)
			}
			if k.Rate != 0 {
				if k.Rate < blekeyboard.MinRate || k.Rate > blekeyboard.MaxRate {
					return fmt.Errorf("the rate is %d to %d characters a second", blekeyboard.MinRate, blekeyboard.MaxRate)
				}
				set.Rate = k.Rate
			}
			set.Pastes = k.Pastes
		}
		set.On = true
	case "off":
		set = blekeyboard.Settings{}
	case "pair":
		k, err := s.openKeyboard()
		if err != nil {
			return err
		}
		return k.Visible(visibleFor)
	case "type":
		k, err := s.openKeyboard()
		if err != nil {
			return err
		}
		text := strings.ReplaceAll(string(m.Payload), "\r\n", "\n")
		return k.Type(ctx, text, set.Layout, set.Rate)
	default:
		return fmt.Errorf("cbb keyboard takes on, off, pair or type, not %q", m.Name)
	}
	if err := blekeyboard.Save(s.cfg.StateDir, set); err != nil {
		return fmt.Errorf("saving the keyboard settings: %w", err)
	}
	s.logf("cbb: the Bluetooth keyboard is %s here (layout %s, rate %d, pastes %v)", m.Name, set.Layout, set.Rate, set.Pastes)
	err = s.applyKeyboard()
	if m.Name == "on" && err != nil {
		return fmt.Errorf("the keyboard is on, but it does not run yet: %w", err)
	}
	return nil
}

// nextKeyboardLayout switches the keyboard to the next layout, at an
// admin's quick action, for a device whose own layout the user just
// switched: the keys mean other letters there now.
func (s *Service) nextKeyboardLayout() error {
	if s.cfg.KeyboardBus == nil && s.cfg.OS != group.OSLinux {
		return &actions.Refusal{Reason: errKeyboardOS.Error()}
	}
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil {
		return err
	}
	if !set.On {
		return &actions.Refusal{Reason: "the Bluetooth keyboard is off here: sudo cbb keyboard on"}
	}
	i := slices.Index(keyboard.Layouts, set.Layout)
	set.Layout = keyboard.Layouts[(i+1)%len(keyboard.Layouts)]
	if err := blekeyboard.Save(s.cfg.StateDir, set); err != nil {
		return fmt.Errorf("saving the keyboard settings: %w", err)
	}
	s.logf("cbb: the Bluetooth keyboard types in the layout %s now", set.Layout)
	return nil
}

// keyboardStatus describes the keyboard for cbb status: nil where there is
// none and it was never turned on.
func (s *Service) keyboardStatus() *control.Keyboard {
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil {
		return &control.Keyboard{Problem: err.Error()}
	}
	if s.cfg.OS != group.OSLinux && s.cfg.KeyboardBus == nil {
		return nil
	}
	st := &control.Keyboard{On: set.On, Layout: string(set.Layout), Rate: set.Rate, Pastes: set.Pastes}
	s.kbd.mu.Lock()
	k, kerr := s.kbd.k, s.kbd.err
	s.kbd.mu.Unlock()
	switch {
	case k != nil:
		st.Connected = k.Connected()
		if t := k.VisibleUntil(); !t.IsZero() {
			st.VisibleUntilMS = t.UnixMilli()
		}
	case set.On && kerr != nil:
		st.Problem = kerr.Error()
	}
	return st
}

// keyboardPastes is whether remote pastes go to the keyboard's host.
func (s *Service) keyboardPastes() bool {
	k, err := blekeyboard.Load(s.cfg.StateDir)
	return err == nil && k.On && k.Pastes
}

// keyboardPaste types a remote paste on the keyboard's host, when the user
// sends pastes there; ok is false when they go to this computer's screen.
// Keys go straight in there, so a line break presses Enter: a text with
// one is refused unless the user allowed Enter. The answer is done once
// typing starts, as a long text takes longer than the sender waits; typing
// stops when still says the paste may no longer go on, or the user turns
// the keyboard's pastes off.
func (s *Service) keyboardPaste(body group.CommandBody, text string, enter bool, still func() bool) (node.Result, bool) {
	set, err := blekeyboard.Load(s.cfg.StateDir)
	if err != nil || !set.On || !set.Pastes {
		return node.Result{}, false
	}
	res := node.Result{ID: body.ID, Status: node.ResultRefused}
	if strings.Contains(text, "\n") && !enter {
		res.Reason = "the text has a line break, which the Bluetooth keyboard types as Enter, and this device takes pastes without Enter only; send it as one line"
		return res, true
	}
	if body.Enter {
		text += "\n"
	}
	k, err := s.openKeyboard()
	if err == nil {
		err = k.Check(text, set.Layout)
	}
	var refusal *blekeyboard.Refusal
	switch {
	case errors.As(err, &refusal):
		res.Reason = refusal.Reason
		return res, true
	case err != nil:
		res.Status, res.Reason = node.ResultFailed, err.Error()
		return res, true
	}
	on := func() bool {
		set, err := blekeyboard.Load(s.cfg.StateDir)
		return err == nil && set.On && set.Pastes && still()
	}
	if !s.typeLater("the Bluetooth keyboard", on, func(ctx context.Context) error { return k.Type(ctx, text, set.Layout, set.Rate) }) {
		res.Reason = "the Bluetooth keyboard is still typing the last paste; send this one when it is done"
		return res, true
	}
	return node.Result{ID: body.ID, Status: node.ResultDone}, true
}
