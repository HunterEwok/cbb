// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

func TestRemoteCommand(t *testing.T) {
	tvs := control.Header{Status: &control.Status{TVs: []control.TV{
		{Name: "Living room", Kind: "androidtv", Host: "10.0.0.5", Pastes: true},
		{Name: "Bedroom", Kind: "roku", Host: "10.0.0.6"},
		{Kind: "androidtv", Host: "10.0.0.7", Pairing: true},
	}}}
	runCommandCases(t, []commandCase{
		{name: "list", args: []string{"remote"}, answer: tvs,
			check:  sent(control.OpRemote, func(m *control.Message) bool { return m.Name == "" }),
			stdout: "Living room (Android TV) at 10.0.0.5: remote pastes go to it.\nBedroom (Roku, plain HTTP) at 10.0.0.6.\nPairing with the TV at 10.0.0.7"},
		{name: "list of none", args: []string{"remote"}, check: sent(control.OpRemote, nil), stdout: "the remote of no TV"},
		{name: "add an Android TV", args: []string{"remote", "add", "-name", "Den", "10.0.0.8"},
			check: sent(control.OpRemote, func(m *control.Message) bool {
				return m.Name == "add" && m.Address == "10.0.0.8" && m.NewName == "Den" && m.Value == "" && !m.Consent
			}),
			stdout: "The TV shows a code now"},
		// Flags may follow the words.
		{name: "add a Roku", args: []string{"remote", "add", "10.0.0.6", "-roku", "-consent"}, answer: tvs,
			check:  sent(control.OpRemote, func(m *control.Message) bool { return m.Value == "roku" && m.Consent && m.Address == "10.0.0.6" }),
			stdout: "Bedroom (Roku"},
		{name: "code", args: []string{"remote", "code", "A1B2C3"}, check: sent(control.OpRemote, func(m *control.Message) bool { return m.Name == "code" && m.Code == "A1B2C3" })},
		{name: "cancel", args: []string{"remote", "cancel"}, check: sent(control.OpRemote, func(m *control.Message) bool { return m.Name == "cancel" })},
		{name: "remove", args: []string{"remote", "remove", "Bedroom"}, check: sent(control.OpRemote, func(m *control.Message) bool { return m.Device == "Bedroom" })},
		{name: "pastes on", args: []string{"remote", "pastes", "Den", "on"}, check: sent(control.OpRemote, func(m *control.Message) bool { return m.Device == "Den" && m.Value == "on" })},
		{name: "type", args: []string{"remote", "type", "-tv", "Den", "hello"},
			check: sent(control.OpRemote, func(m *control.Message) bool { return m.Device == "Den" && string(m.Payload) == "hello" }), stdout: "Typed."},
		{name: "type from stdin", args: []string{"remote", "type"}, stdin: "from stdin\n",
			check: sent(control.OpRemote, func(m *control.Message) bool { return string(m.Payload) == "from stdin" }), stdout: "Typed."},
		{name: "refused", args: []string{"remote", "code", "000000"}, answer: control.Header{Error: "the TV took no code"}, check: sent(control.OpRemote, nil), code: 1, stderr: "took no code"},
		{name: "pastes maybe", args: []string{"remote", "pastes", "Den", "maybe"}, code: 2, stderr: "usage: cbb remote"},
		{name: "roku without add", args: []string{"remote", "-roku"}, code: 2, stderr: "usage: cbb remote"},
		{name: "tv without type", args: []string{"remote", "cancel", "-tv", "Den"}, code: 2, stderr: "usage: cbb remote"},
		{name: "add without an address", args: []string{"remote", "add"}, code: 2, stderr: "usage: cbb remote"},
		{name: "code without one", args: []string{"remote", "code"}, code: 2},
		{name: "cancel with an argument", args: []string{"remote", "cancel", "x"}, code: 2},
		{name: "remove without a TV", args: []string{"remote", "remove"}, code: 2},
		{name: "type with two texts", args: []string{"remote", "type", "a", "b"}, code: 2},
		{name: "list with an argument", args: []string{"remote", "", "x"}, code: 2},
		{name: "an unknown verb", args: []string{"remote", "volume"}, code: 2, stderr: "usage: cbb remote"},
	})
}

func TestKeyboardCommand(t *testing.T) {
	on := control.Header{Status: &control.Status{Keyboard: &control.Keyboard{On: true, Layout: "ru", Rate: 30, Pastes: true, Connected: true}}}
	runCommandCases(t, []commandCase{
		{name: "status", args: []string{"keyboard"}, answer: on, check: sent(control.OpKeyboard, func(m *control.Message) bool { return m.Name == "" }),
			stdout: "on, typing in the ru layout at 30 characters a second; remote pastes go to the device it types into. A device is connected."},
		{name: "on", args: []string{"keyboard", "-layout", "ru", "-rate", "30", "-pastes", "on"}, answer: on,
			check: sent(control.OpKeyboard, func(m *control.Message) bool {
				return m.Name == "on" && m.Keyboard != nil && *m.Keyboard == control.Keyboard{Layout: "ru", Rate: 30, Pastes: true}
			})},
		{name: "off", args: []string{"keyboard", "off"}, answer: control.Header{Status: &control.Status{Keyboard: &control.Keyboard{}}},
			check: sent(control.OpKeyboard, func(m *control.Message) bool { return m.Name == "off" && m.Keyboard == nil }), stdout: "The Bluetooth keyboard is off"},
		{name: "on before its flags", args: []string{"keyboard", "on", "-layout", "us"}, answer: on,
			check: sent(control.OpKeyboard, func(m *control.Message) bool {
				return m.Name == "on" && m.Keyboard != nil && *m.Keyboard == control.Keyboard{Layout: "us"}
			})},
		{name: "type a text like a flag", args: []string{"keyboard", "type", "-rate"}, check: sent(control.OpKeyboard, func(m *control.Message) bool { return string(m.Payload) == "-rate" }), stdout: "Typed."},
		{name: "pair", args: []string{"keyboard", "pair"}, answer: on, check: sent(control.OpKeyboard, func(m *control.Message) bool { return m.Name == "pair" })},
		{name: "type", args: []string{"keyboard", "type", "hi"}, check: sent(control.OpKeyboard, func(m *control.Message) bool { return string(m.Payload) == "hi" }), stdout: "Typed."},
		{name: "type from stdin", args: []string{"keyboard", "type"}, stdin: "typed\n", check: sent(control.OpKeyboard, func(m *control.Message) bool { return string(m.Payload) == "typed" })},
		{name: "no keyboard here", args: []string{"keyboard"}, answer: control.Header{Status: &control.Status{}}, check: sent(control.OpKeyboard, nil), code: 1, stderr: "cannot be a Bluetooth keyboard"},
		{name: "refused", args: []string{"keyboard", "pair"}, answer: control.Header{Error: "Bluetooth is off"}, check: sent(control.OpKeyboard, nil), code: 1, stderr: "Bluetooth is off"},
		{name: "layout without on", args: []string{"keyboard", "-layout", "us", "off"}, code: 2, stderr: "usage: cbb keyboard"},
		{name: "unknown verb", args: []string{"keyboard", "loud"}, code: 2, stderr: "usage: cbb keyboard"},
	})
}

func TestKeyboardLine(t *testing.T) {
	until := time.Date(2026, 1, 2, 15, 4, 5, 0, time.Local).UnixMilli()
	for _, c := range []struct {
		k    control.Keyboard
		want string
	}{
		{control.Keyboard{On: true, Layout: "us", Rate: 20, Problem: "no Bluetooth adapter"}, ".\nIt does not run: no Bluetooth adapter"},
		{control.Keyboard{On: true, Layout: "us", Rate: 20, VisibleUntilMS: until}, "No device is connected; pair one with cbb keyboard pair, then connect it from the device. New devices find it until 15:04:05."},
	} {
		if got := keyboardLine(&c.k); !strings.Contains(got, c.want) {
			t.Errorf("keyboardLine(%+v) = %q, want %q in it", c.k, got, c.want)
		}
	}
}

func TestPasteOnCommand(t *testing.T) {
	runCommandCases(t, []commandCase{
		{name: "paste", args: []string{"paste", "-on", "desk"}, stdin: "hello",
			check: sent(control.OpPasteOn, func(m *control.Message) bool {
				return m.Device == "desk" && m.Method == group.PasteByClipboard && m.Kind == control.KindText && !m.Enter && string(m.Payload) == "hello"
			}),
			stdout: "Pasted on desk."},
		{name: "typed secret with Enter", args: []string{"paste", "-on", "desk", "-type", "-enter", "-secret"}, stdin: "pw",
			check: sent(control.OpPasteOn, func(m *control.Message) bool {
				return m.Method == group.PasteByTyping && m.Kind == control.KindSecret && m.Enter
			})},
		{name: "too long to type", args: []string{"paste", "-on", "desk", "-type"}, stdin: strings.Repeat("x", group.MaxTypeText+1), code: 1, stderr: "too long to type"},
		{name: "larger than 1 MiB", args: []string{"paste", "-on", "desk"}, stdin: strings.Repeat("x", maxText+1), code: 1, stderr: "larger than 1 MiB"},
		{name: "refused", args: []string{"paste", "-on", "desk"}, stdin: "x", answer: control.Header{Error: "remote paste is off on desk"}, check: sent(control.OpPasteOn, nil), code: 1, stderr: "off on desk"},
	})
}
