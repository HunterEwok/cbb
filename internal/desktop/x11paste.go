// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jezek/xgb/screensaver"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/lockcheck"
)

// Remote paste on X11 (design.md, "Remote paste"): XTEST presses the keys
// as if the user did, into the window with the focus.
//
// A paste puts the text into CLIPBOARD and PRIMARY, presses Shift+Insert,
// which pastes in GTK, Qt and terminals alike, and gives the clipboard back
// what it held before, unless the user copied meanwhile. Typing presses a
// key for each character: the key of a spare keycode that is given that
// character's keysym in every column, so neither Shift nor the keyboard
// layout the user chose changes it. The spare keycodes get no keysym again
// when the text is typed.

// The keysyms the paste presses, from X11's keysymdef.h.
const (
	ksReturn = 0xff0d
	ksTab    = 0xff09
	ksInsert = 0xff63
	ksShiftL = 0xffe1
)

const (
	// keyPause lets the programs take a keymap change, and a key, before
	// the next.
	keyPause = 3 * time.Millisecond
)

// x11Keys is the keyboard mapping a paste uses.
type x11Keys struct {
	min, max xproto.Keycode
	per      int             // keysyms per keycode
	syms     []xproto.Keysym // per keysyms for each keycode from min
	spare    []xproto.Keycode
	next     int                              // the spare keycode to give the next keysym
	given    map[xproto.Keysym]xproto.Keycode // spare keycodes that hold a keysym now
}

// x11Inject is the paste state of an X11 board.
type x11Inject struct {
	mu   sync.Mutex // one paste at a time
	once sync.Once
	err  error // XTEST is missing
}

// Target offers the desktop for remote paste: XTEST in an X11 session. In a
// Wayland session XWayland's keys reach only X11 programs, so the keys go
// through the uinput helper or the RemoteDesktop portal there, as on GNOME.
func (b *X11) Target() string {
	if os.Getenv("WAYLAND_DISPLAY") != "" && b.kb == nil {
		return ""
	}
	return "desktop"
}

// Inject puts text where the focus is (connector.Target).
func (b *X11) Inject(ctx context.Context, text, method string, enter, secret bool) error {
	b.inj.mu.Lock()
	defer b.inj.mu.Unlock()
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		if b.kb == nil {
			return &connector.Refusal{Reason: "this Wayland desktop offers no way to press keys for a paste"}
		}
		return keysInject(ctx, b.kb, b, text, method, enter, secret)
	}
	b.inj.once.Do(func() {
		if err := xtest.Init(b.x); err != nil {
			b.inj.err = fmt.Errorf("the X server has no XTEST: %w", err)
		}
	})
	if b.inj.err != nil {
		return &connector.Refusal{Reason: "this desktop cannot press keys for a paste: " + b.inj.err.Error()}
	}
	if why := b.locked(connector.NoLockCheck(ctx)); why != "" {
		return &connector.Refusal{Reason: why}
	}
	keys, err := b.keyboard()
	if err != nil {
		return err
	}
	defer keys.release(b)
	switch method {
	case "paste":
		err = connector.PasteThrough(b, text, secret, func() error { return keys.press(b, ksInsert, true) })
	case "type":
		err = b.typeText(ctx, keys, text)
	default:
		return &connector.Refusal{Reason: fmt.Sprintf("this desktop pastes or types, not %q", method)}
	}
	if err == nil && enter {
		err = keys.press(b, ksReturn, false)
	}
	return err
}

// locked says why the session cannot take a paste now, or "" if it can:
// it is locked, or the screen saver is on; noLockCheck lets it paste where
// nothing tells whether the session is locked.
func (b *X11) locked(noLockCheck bool) string {
	if why := lockcheck.Reason(noLockCheck); why != "" {
		return why
	}
	if screensaver.Init(b.x) == nil {
		root := xproto.Setup(b.x).DefaultScreen(b.x).Root
		if r, err := screensaver.QueryInfo(b.x, xproto.Drawable(root)).Reply(); err == nil && r.State == screensaver.StateOn {
			return "the screen saver is on"
		}
	}
	return ""
}

func (b *X11) Holds(text string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.owned && b.text == text
}

// typeText types text key by key; it stops early when ctx ends.
func (b *X11) typeText(ctx context.Context, keys *x11Keys, text string) error {
	for _, r := range text {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := keys.press(b, runeKeysym(r), false); err != nil {
			return err
		}
	}
	return nil
}

// runeKeysym is the keysym of a character: Latin-1 as it is, the rest by
// the Unicode keysyms X11 has, 0x1000000 plus the code point.
func runeKeysym(r rune) xproto.Keysym {
	switch {
	case r == '\n':
		return ksReturn
	case r == '\t':
		return ksTab
	case r >= 0x20 && r <= 0x7e, r >= 0xa0 && r <= 0xff:
		return xproto.Keysym(r)
	}
	return xproto.Keysym(0x1000000 + r)
}

// keyboard reads the keyboard mapping and finds the spare keycodes: those
// with no keysym.
func (b *X11) keyboard() (*x11Keys, error) {
	setup := xproto.Setup(b.x)
	k := &x11Keys{min: setup.MinKeycode, max: setup.MaxKeycode, given: map[xproto.Keysym]xproto.Keycode{}}
	r, err := xproto.GetKeyboardMapping(b.x, k.min, byte(k.max-k.min+1)).Reply()
	if err != nil {
		return nil, fmt.Errorf("reading the keyboard mapping: %w", err)
	}
	k.per, k.syms = int(r.KeysymsPerKeycode), r.Keysyms
	for code := int(k.min); code <= int(k.max); code++ {
		empty := true
		for _, s := range k.column(xproto.Keycode(code)) {
			empty = empty && s == 0
		}
		if empty {
			k.spare = append(k.spare, xproto.Keycode(code))
		}
	}
	if len(k.spare) == 0 {
		return nil, errors.New("the keyboard mapping has no spare keycode to type with")
	}
	return k, nil
}

func (k *x11Keys) column(code xproto.Keycode) []xproto.Keysym {
	i := int(code-k.min) * k.per
	return k.syms[i : i+k.per]
}

// mapped returns the keycode that gives ks without a modifier, in the first
// column, or 0.
func (k *x11Keys) mapped(ks xproto.Keysym) xproto.Keycode {
	for code := int(k.min); code <= int(k.max); code++ {
		if k.column(xproto.Keycode(code))[0] == ks {
			return xproto.Keycode(code)
		}
	}
	return 0
}

// keycode returns a keycode for ks: a spare one that holds it already, or
// the next spare one, given ks in every column.
func (k *x11Keys) keycode(b *X11, ks xproto.Keysym) (xproto.Keycode, error) {
	if code, ok := k.given[ks]; ok {
		return code, nil
	}
	code := k.spare[k.next%len(k.spare)]
	k.next++
	for s, c := range k.given {
		if c == code {
			delete(k.given, s)
		}
	}
	syms := make([]xproto.Keysym, k.per)
	for i := range syms {
		syms[i] = ks
	}
	if err := xproto.ChangeKeyboardMappingChecked(b.x, 1, code, byte(k.per), syms).Check(); err != nil {
		return 0, fmt.Errorf("mapping a keycode for a key: %w", err)
	}
	k.given[ks] = code
	time.Sleep(keyPause) // the programs reread the mapping on MappingNotify
	return code, nil
}

// press presses and releases the key of ks, with Shift held when shift is
// set. Return, Insert and Shift use the keyboard's own keys.
func (k *x11Keys) press(b *X11, ks xproto.Keysym, shift bool) error {
	code := xproto.Keycode(0)
	if ks == ksReturn || ks == ksInsert {
		code = k.mapped(ks)
	}
	if code == 0 {
		var err error
		if code, err = k.keycode(b, ks); err != nil {
			return err
		}
	}
	var shiftCode xproto.Keycode
	if shift {
		if shiftCode = k.mapped(ksShiftL); shiftCode == 0 {
			return errors.New("the keyboard mapping has no Shift key")
		}
		b.fake(xproto.KeyPress, shiftCode)
	}
	b.fake(xproto.KeyPress, code)
	b.fake(xproto.KeyRelease, code)
	if shift {
		b.fake(xproto.KeyRelease, shiftCode)
	}
	// A round trip makes sure the server took the keys.
	if _, err := xproto.GetInputFocus(b.x).Reply(); err != nil {
		return fmt.Errorf("pressing a key: %w", err)
	}
	time.Sleep(keyPause)
	return nil
}

func (b *X11) fake(typ byte, code xproto.Keycode) {
	xtest.FakeInput(b.x, typ, byte(code), xproto.TimeCurrentTime, xproto.WindowNone, 0, 0, 0)
}

// release gives the spare keycodes it used no keysym again.
func (k *x11Keys) release(b *X11) {
	if len(k.given) == 0 {
		return
	}
	time.Sleep(10 * keyPause) // let the last key be read with its keysym
	for _, code := range k.given {
		xproto.ChangeKeyboardMapping(b.x, 1, code, byte(k.per), make([]xproto.Keysym, k.per))
	}
	xproto.GetInputFocus(b.x).Reply()
	clear(k.given)
}
