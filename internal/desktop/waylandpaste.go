// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

package desktop

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/lockcheck"
	"github.com/HunterEwok/cbb/internal/wl"
)

// Remote paste on Wayland (design.md, "Remote paste"): a virtual keyboard
// (zwp_virtual_keyboard_v1, in sway, Hyprland, labwc and other wlroots
// compositors) presses the keys into the window with the focus.
//
// The virtual keyboard brings its own keymap: one key for each character
// of the text, by its Unicode keysym, so any character is typed whatever
// layout the user chose. A paste puts the text into the clipboard and the
// primary selection through data-control, presses Shift+Insert, and gives
// the clipboard back what it held, unless the user copied meanwhile.

const virtualKeyboards = "zwp_virtual_keyboard_manager_v1"

// Opcodes of the virtual keyboard protocol.
const (
	vkmCreate   = 0
	vkKeymap    = 0
	vkKey       = 1
	vkModifiers = 2
)

const (
	keymapXKBv1 = 1
	keyPressed  = 1
	keyReleased = 0
	modShift    = 1
	// keysPerMap is how many keys one keymap holds: keycodes 9 to 255.
	keysPerMap = 247
)

// waylandInject is the paste state of a Wayland board.
type waylandInject struct {
	mu    sync.Mutex // one paste at a time
	vk    uint32     // the virtual keyboard, made at the first paste
	start time.Time  // the keys' timestamps count from here
	syms  []string   // the keysyms of the keymap the keyboard has now
}

// Target offers the desktop for remote paste when the compositor has
// virtual keyboards, or the session the uinput helper or the RemoteDesktop
// portal (GNOME, KDE).
func (w *Wayland) Target() string {
	if w.vkm == 0 && w.kb == nil {
		return ""
	}
	return "desktop"
}

// Inject puts text where the focus is (connector.Target).
func (w *Wayland) Inject(ctx context.Context, text, method string, enter, secret bool) error {
	w.inj.mu.Lock()
	defer w.inj.mu.Unlock()
	if w.vkm == 0 {
		if w.kb == nil {
			return &connector.Refusal{Reason: "this compositor offers no virtual keyboard to paste with"}
		}
		return keysInject(ctx, w.kb, w, text, method, enter, secret)
	}
	if why := lockcheck.Reason(connector.NoLockCheck(ctx)); why != "" {
		return &connector.Refusal{Reason: why}
	}
	if w.inj.vk == 0 {
		w.inj.vk = w.d.NewID(nil)
		w.inj.start = time.Now()
		if err := w.d.Send(w.vkm, vkmCreate, (&wl.Request{}).Uint(w.seat).Uint(w.inj.vk)); err != nil {
			return err
		}
	}
	var err error
	switch method {
	case "paste":
		err = connector.PasteThrough(w, text, secret, func() error {
			if err := w.sync(); err != nil { // the selection is set before the keys
				return err
			}
			return w.keys([]string{"Insert"}, modShift)
		})
	case "type":
		err = w.typeText(ctx, text)
	default:
		return &connector.Refusal{Reason: fmt.Sprintf("this desktop pastes or types, not %q", method)}
	}
	if err == nil && enter {
		err = w.keys([]string{"Return"}, 0)
	}
	return err
}

func (w *Wayland) Holds(text string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.own != 0 && w.item.Text == text
}

// typeText types text key by key, a keymap for every keysPerMap different
// characters; it stops early when ctx ends.
func (w *Wayland) typeText(ctx context.Context, text string) error {
	var syms []string
	for _, r := range text {
		syms = append(syms, keysymName(r))
	}
	for len(syms) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, seen := 0, map[string]bool{}
		for n < len(syms) && (seen[syms[n]] || len(seen) < keysPerMap) {
			seen[syms[n]] = true
			n++
		}
		if err := w.keys(syms[:n], 0); err != nil {
			return err
		}
		syms = syms[n:]
	}
	return nil
}

// keysymName is the name xkbcommon knows a character's keysym by.
func keysymName(r rune) string {
	switch r {
	case '\n':
		return "Return"
	case '\t':
		return "Tab"
	}
	return fmt.Sprintf("U%04X", r)
}

// keys presses and releases a key for each keysym in syms, at most
// keysPerMap different ones, with the modifiers mods held: it gives the
// keyboard a keymap of those keysyms first, unless it has them.
func (w *Wayland) keys(syms []string, mods uint32) error {
	var codes []uint32
	for _, s := range syms {
		i := slices.Index(w.inj.syms, s)
		if i < 0 {
			codes = nil
			break
		}
		codes = append(codes, uint32(i))
	}
	if codes == nil {
		var keymap []string
		for _, s := range syms {
			if i := slices.Index(keymap, s); i >= 0 {
				codes = append(codes, uint32(i))
				continue
			}
			codes = append(codes, uint32(len(keymap)))
			keymap = append(keymap, s)
		}
		if err := w.setKeymap(keymap); err != nil {
			return err
		}
	}
	if mods != 0 {
		if err := w.d.Send(w.inj.vk, vkModifiers, (&wl.Request{}).Uint(mods).Uint(0).Uint(0).Uint(0)); err != nil {
			return err
		}
	}
	for _, c := range codes {
		// The protocol's keys are evdev codes, 8 below the keymap's.
		for _, state := range []uint32{keyPressed, keyReleased} {
			if err := w.d.Send(w.inj.vk, vkKey, (&wl.Request{}).Uint(w.ms()).Uint(c+1).Uint(state)); err != nil {
				return err
			}
		}
		time.Sleep(keyPause)
	}
	if mods != 0 {
		if err := w.d.Send(w.inj.vk, vkModifiers, (&wl.Request{}).Uint(0).Uint(0).Uint(0).Uint(0)); err != nil {
			return err
		}
	}
	return w.sync()
}

func (w *Wayland) ms() uint32 { return uint32(time.Since(w.inj.start).Milliseconds()) }

// setKeymap gives the virtual keyboard a keymap with one key for each
// keysym, keycode 9 for the first.
func (w *Wayland) setKeymap(syms []string) error {
	if len(syms) > keysPerMap {
		return errors.New("too many keys for one keymap")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "xkb_keymap {\nxkb_keycodes \"cbb\" {\nminimum = 8;\nmaximum = %d;\n", 9+len(syms))
	for i := range syms {
		fmt.Fprintf(&b, "<K%d> = %d;\n", i, 9+i)
	}
	b.WriteString("};\nxkb_types \"cbb\" { include \"complete\" };\nxkb_compatibility \"cbb\" { include \"complete\" };\nxkb_symbols \"cbb\" {\n")
	for i, s := range syms {
		fmt.Fprintf(&b, "key <K%d> {[ %s ]};\n", i, s)
	}
	b.WriteString("};\n};\n")
	keymap := append([]byte(b.String()), 0)
	fd, err := anonFile("cbb-keymap")
	if err != nil {
		return fmt.Errorf("making the keymap: %w", err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, keymap); err != nil {
		return fmt.Errorf("making the keymap: %w", err)
	}
	if err := w.d.Send(w.inj.vk, vkKeymap, (&wl.Request{}).Uint(keymapXKBv1).FD(fd).Uint(uint32(len(keymap)))); err != nil {
		return err
	}
	w.inj.syms = slices.Clone(syms)
	if err := w.sync(); err != nil {
		return err
	}
	time.Sleep(10 * keyPause) // the programs take the new keymap
	return nil
}

// sync waits until the compositor handled every request sent before it;
// the board's event goroutine sees the answer.
func (w *Wayland) sync() error {
	done := make(chan struct{})
	var once sync.Once
	id := w.d.NewID(func(op uint16, a *wl.Args) error {
		once.Do(func() { close(done) })
		return a.Err
	})
	defer w.d.Forget(id)
	if err := w.d.Send(1, 0, (&wl.Request{}).Uint(id)); err != nil { // wl_display.sync
		return err
	}
	select {
	case <-done:
		return nil
	case err := <-w.errc:
		w.errc <- err
		return err
	case <-time.After(5 * time.Second):
		return errors.New("the compositor did not answer")
	}
}
