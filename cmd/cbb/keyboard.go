// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// cmdKeyboard shows or sets this computer as a Bluetooth keyboard, makes
// it visible to a new device, or types a text on the connected one.
func cmdKeyboard(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keyboard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	layout := fs.String("layout", "", "with on: the layout active on the device it types into, us or ru")
	rate := fs.Int("rate", 0, "with on: characters a second, 5 to 60 (20 if not set)")
	pastes := fs.Bool("pastes", false, "with on: type the group's remote pastes there instead of on this computer")
	// The verb comes first, as the usage shows; before the flags, it would
	// end them. A text to type is never read as flags.
	verb := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		verb, args = args[0], args[1:]
	}
	var rest []string
	if verb == "type" {
		rest = args
	} else {
		if fs.Parse(args) != nil {
			return 2
		}
		rest = fs.Args()
	}
	if verb == "" && len(rest) > 0 {
		verb, rest = rest[0], rest[1:]
	}
	usage := "usage: cbb keyboard [on [-layout us|ru] [-rate N] [-pastes] | off | pair | type [TEXT]]"
	h := control.Header{Op: control.OpKeyboard, Name: verb}
	var payload []byte
	switch {
	case verb == "on" && len(rest) == 0:
		h.Keyboard = &control.Keyboard{Layout: *layout, Rate: *rate, Pastes: *pastes}
	case *layout != "" || *rate != 0 || *pastes:
		fmt.Fprintln(stderr, usage)
		return 2
	case (verb == "" || verb == "off" || verb == "pair") && len(rest) == 0:
	case verb == "type" && len(rest) == 1:
		payload = []byte(rest[0])
	case verb == "type" && len(rest) == 0:
		b, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
		if err != nil {
			return fail(stderr, err)
		}
		payload = []byte(strings.TrimSuffix(string(b), "\n"))
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	c, err := control.DialFor(h.Op)
	if err != nil {
		return fail(stderr, err)
	}
	defer c.Close()
	m, err := c.Do(&control.Message{Header: h, Payload: payload})
	if err != nil {
		return fail(stderr, err)
	}
	if verb == "type" {
		fmt.Fprintln(stdout, "Typed.")
		return 0
	}
	if m.Status == nil || m.Status.Keyboard == nil {
		return fail(stderr, errors.New("this computer cannot be a Bluetooth keyboard"))
	}
	fmt.Fprintln(stdout, keyboardLine(m.Status.Keyboard))
	return 0
}

// keyboardLine says how the Bluetooth keyboard stands.
func keyboardLine(k *control.Keyboard) string {
	if !k.On {
		return "The Bluetooth keyboard is off: cbb keyboard on makes this computer one, for a TV, a tablet or a computer near it."
	}
	line := fmt.Sprintf("The Bluetooth keyboard is on, typing in the %s layout at %d characters a second", k.Layout, k.Rate)
	if k.Pastes {
		line += "; remote pastes go to the device it types into"
	}
	switch {
	case k.Problem != "":
		return line + ".\nIt does not run: " + k.Problem
	case k.Connected:
		line += ". A device is connected"
	default:
		line += ". No device is connected; pair one with cbb keyboard pair, then connect it from the device"
	}
	if k.VisibleUntilMS != 0 {
		line += fmt.Sprintf(". New devices find it until %s", time.UnixMilli(k.VisibleUntilMS).Format("15:04:05"))
	}
	return line + "."
}
