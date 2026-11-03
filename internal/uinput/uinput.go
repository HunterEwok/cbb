// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

// Package uinput is remote paste's opt-in keyboard on Linux (design.md,
// "Remote paste"): a kernel virtual keyboard that every compositor, the X
// server and gamescope take as hardware, so it works where neither a
// virtual keyboard protocol nor the RemoteDesktop portal does, and without
// the portal's dialog.
//
// A uinput keyboard can type anywhere, a root shell and a lock screen
// included, so it is not given to the user: cbb paste-helper uinput, the
// cbb-uinput unit that install.sh --uinput adds, holds the
// device and presses only Shift+Insert and Enter, the keys of a paste,
// for the user of the active graphical session while it is not locked.
// The desktop connector of that session writes the clipboard and asks the
// helper for the keys over a socket.
package uinput

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Device is the path of the uinput device.
const Device = "/dev/uinput"

// Evdev key codes (linux/input-event-codes.h), the same on every layout.
const (
	KeyEnter     = 28
	KeyLeftShift = 42
	KeyInsert    = 110
)

// keys are the only keys the keyboard has.
var keys = []uint16{KeyEnter, KeyLeftShift, KeyInsert}

// From linux/uinput.h and linux/input.h.
const (
	uiSetEvBit   = 0x40045564 // _IOW('U', 100, int)
	uiSetKeyBit  = 0x40045565 // _IOW('U', 101, int)
	uiDevSetup   = 0x405c5503 // _IOW('U', 3, struct uinput_setup)
	uiDevCreate  = 0x5501     // _IO('U', 1)
	uiDevDestroy = 0x5502     // _IO('U', 2)

	evSyn      = 0
	evKey      = 1
	synReport  = 0
	busVirtual = 0x06
)

// setup is struct uinput_setup.
type setup struct {
	bustype, vendor, product, version uint16
	name                              [80]byte
	ffEffectsMax                      uint32
}

// event is struct input_event, whose time the kernel sets.
type event struct {
	time  unix.Timeval
	typ   uint16
	code  uint16
	value int32
}

// settle is how long compositors take to notice a new keyboard.
const settle = 500 * time.Millisecond

// A Key is a key event: a press or a release of an evdev code.
type Key struct {
	Code  uint16
	Press bool
}

// Keyboard is a uinput keyboard with Shift, Insert and Enter.
type Keyboard struct {
	f *os.File
}

// Open makes a keyboard named name on the uinput device at path, and waits
// until the compositors took it.
func Open(path, name string) (*Keyboard, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("uinput: %w", err)
	}
	k := &Keyboard{f: f}
	if err := k.create(name); err != nil {
		f.Close()
		return nil, err
	}
	time.Sleep(settle)
	return k, nil
}

func (k *Keyboard) ioctl(req, arg uintptr) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, k.f.Fd(), req, arg); e != 0 {
		return e
	}
	return nil
}

func (k *Keyboard) create(name string) error {
	if err := k.ioctl(uiSetEvBit, evKey); err != nil {
		return fmt.Errorf("uinput: UI_SET_EVBIT: %w", err)
	}
	for _, c := range keys {
		if err := k.ioctl(uiSetKeyBit, uintptr(c)); err != nil {
			return fmt.Errorf("uinput: UI_SET_KEYBIT: %w", err)
		}
	}
	s := setup{bustype: busVirtual, vendor: 0x1d6b, product: 0xcbb0, version: 1}
	if len(name) >= len(s.name) {
		return errors.New("uinput: the name is too long")
	}
	copy(s.name[:], name)
	if err := k.ioctl(uiDevSetup, uintptr(unsafe.Pointer(&s))); err != nil {
		return fmt.Errorf("uinput: UI_DEV_SETUP: %w", err)
	}
	if err := k.ioctl(uiDevCreate, 0); err != nil {
		return fmt.Errorf("uinput: UI_DEV_CREATE: %w", err)
	}
	return nil
}

// Press sends the keys in order, each in a report of its own.
func (k *Keyboard) Press(ks []Key) error {
	for _, key := range ks {
		v := int32(0)
		if key.Press {
			v = 1
		}
		if err := k.write(event{typ: evKey, code: key.Code, value: v}, event{typ: evSyn, code: synReport}); err != nil {
			return err
		}
		time.Sleep(3 * time.Millisecond)
	}
	return nil
}

func (k *Keyboard) write(evs ...event) error {
	b := unsafe.Slice((*byte)(unsafe.Pointer(&evs[0])), len(evs)*int(unsafe.Sizeof(evs[0])))
	if _, err := k.f.Write(b); err != nil {
		return fmt.Errorf("uinput: %w", err)
	}
	return nil
}

// Close removes the keyboard.
func (k *Keyboard) Close() error {
	k.ioctl(uiDevDestroy, 0)
	return k.f.Close()
}
