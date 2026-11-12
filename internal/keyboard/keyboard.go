// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package keyboard types a text as a Bluetooth keyboard (docs/roadmap.md,
// item 25): the keys of a layout and the HID boot keyboard's reports that
// press them, as the Rust core's cbb_core::keyboard has them for the
// Nano ESP32 and the Android kit's Keyboard for the phone. All three are
// checked against testdata/interop/keyboard.json.
//
// A keyboard sends the position of a key, not a character: the host's
// layout turns the position into one. So the member needs the layout that
// is active on the host, and a character that layout cannot type is
// refused rather than typed as something else.
package keyboard

// LeftShift is Shift, of the modifier bits in a report's first byte.
const LeftShift = 0x02

// The usages of the keys a text needs besides its characters.
const (
	Enter = 0x28
	Tab   = 0x2b
	Space = 0x2c
)

// A Key is a key of the HID keyboard page and the modifiers held with it.
type Key struct {
	Usage     byte
	Modifiers byte
}

// Report is the boot keyboard's report that holds k down: the modifiers, a
// reserved byte and up to six keys.
func (k Key) Report() [8]byte { return [8]byte{k.Modifiers, 0, k.Usage} }

// Release is the report with every key up.
var Release [8]byte

// Descriptor is the HID report map of a boot keyboard without report IDs:
// eight modifier bits, a reserved byte and six keys, with the five LEDs
// the host sets. A host reads it when it pairs.
var Descriptor = []byte{
	0x05, 0x01, // usage page: generic desktop
	0x09, 0x06, // usage: keyboard
	0xa1, 0x01, // collection: application
	0x05, 0x07, //   usage page: keyboard
	0x19, 0xe0, //   usage minimum: left control
	0x29, 0xe7, //   usage maximum: right GUI
	0x15, 0x00, //   logical minimum 0
	0x25, 0x01, //   logical maximum 1
	0x75, 0x01, //   report size 1
	0x95, 0x08, //   report count 8
	0x81, 0x02, //   input: the modifiers
	0x95, 0x01, //   report count 1
	0x75, 0x08, //   report size 8
	0x81, 0x01, //   input: the reserved byte
	0x95, 0x05, //   report count 5
	0x75, 0x01, //   report size 1
	0x05, 0x08, //   usage page: LEDs
	0x19, 0x01, //   usage minimum: num lock
	0x29, 0x05, //   usage maximum: kana
	0x91, 0x02, //   output: the LEDs
	0x95, 0x01, //   report count 1
	0x75, 0x03, //   report size 3
	0x91, 0x01, //   output: padding
	0x95, 0x06, //   report count 6
	0x75, 0x08, //   report size 8
	0x15, 0x00, //   logical minimum 0
	0x25, 0x65, //   logical maximum 101
	0x05, 0x07, //   usage page: keyboard
	0x19, 0x00, //   usage minimum 0
	0x29, 0x65, //   usage maximum 101
	0x81, 0x00, //   input: the keys
	0xc0, // end collection
}

// A Layout is a layout active on the host, by the name a user sets it with.
type Layout string

const (
	// US is English (US), the default of most TVs and computers.
	US Layout = "us"
	// RU is Russian (the JCUKEN layout), as Windows, macOS's "Russian - PC"
	// and XKB's ru have it.
	RU Layout = "ru"
)

// Layouts are the layouts there are, the default first.
var Layouts = []Layout{US, RU}

// Known reports whether l is one of Layouts.
func (l Layout) Known() bool { return l == US || l == RU }

// Key returns the key that types r, if this layout has one. A new line
// presses Enter and a tab Tab.
func (l Layout) Key(r rune) (Key, bool) {
	switch r {
	case '\n':
		return Key{Usage: Enter}, true
	case '\t':
		return Key{Usage: Tab}, true
	case ' ':
		return Key{Usage: Space}, true
	}
	switch l {
	case US:
		return us(r)
	case RU:
		return ru(r)
	}
	return Key{}, false
}

// Untypeable returns the characters of text, each once and in the order
// they first come, that this layout cannot type.
func (l Layout) Untypeable(text string) []rune {
	var out []rune
	seen := map[rune]bool{}
	for _, r := range text {
		if _, ok := l.Key(r); r != '\r' && !ok && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// Reports returns the reports that type text: each key down and then all
// keys up, so that the same key twice in a row is two presses. A carriage
// return types nothing, so a CRLF line end is one Enter. It reports false
// when the layout cannot type a character of it (Untypeable says which).
func (l Layout) Reports(text string) ([][8]byte, bool) {
	out := make([][8]byte, 0, 2*len(text))
	for _, r := range text {
		if r == '\r' {
			continue
		}
		k, ok := l.Key(r)
		if !ok {
			return nil, false
		}
		out = append(out, k.Report(), Release)
	}
	return out, true
}

// digit is the digits' row and the keys right of it, which most layouts
// share.
func digit(r rune) (Key, bool) {
	switch {
	case r >= '1' && r <= '9':
		return Key{Usage: 0x1e + byte(r-'1')}, true
	case r == '0':
		return Key{Usage: 0x27}, true
	case r == '-':
		return Key{Usage: 0x2d}, true
	case r == '=':
		return Key{Usage: 0x2e}, true
	}
	return Key{}, false
}

var usShifted = map[rune]byte{
	'!': 0x1e, '@': 0x1f, '#': 0x20, '$': 0x21, '%': 0x22, '^': 0x23, '&': 0x24,
	'*': 0x25, '(': 0x26, ')': 0x27, '_': 0x2d, '+': 0x2e, '{': 0x2f, '}': 0x30,
	'|': 0x31, ':': 0x33, '"': 0x34, '~': 0x35, '<': 0x36, '>': 0x37, '?': 0x38,
}

var usPlain = map[rune]byte{
	'[': 0x2f, ']': 0x30, '\\': 0x31, ';': 0x33, '\'': 0x34, '`': 0x35, ',': 0x36,
	'.': 0x37, '/': 0x38,
}

func us(r rune) (Key, bool) {
	if k, ok := digit(r); ok {
		return k, true
	}
	switch {
	case r >= 'a' && r <= 'z':
		return Key{Usage: 0x04 + byte(r-'a')}, true
	case r >= 'A' && r <= 'Z':
		return Key{Usage: 0x04 + byte(r-'A'), Modifiers: LeftShift}, true
	}
	if u, ok := usShifted[r]; ok {
		return Key{Usage: u, Modifiers: LeftShift}, true
	}
	if u, ok := usPlain[r]; ok {
		return Key{Usage: u}, true
	}
	return Key{}, false
}

// ruLetters are the Russian letters on the keys of the US letters q to /.
var ruLetters = map[rune]byte{
	'\u0439': 0x14, // short i
	'\u0446': 0x1a, // tse
	'\u0443': 0x08, // u
	'\u043a': 0x15, // ka
	'\u0435': 0x17, // ie
	'\u043d': 0x1c, // en
	'\u0433': 0x18, // ghe
	'\u0448': 0x0c, // sha
	'\u0449': 0x12, // shcha
	'\u0437': 0x13, // ze
	'\u0445': 0x2f, // ha
	'\u044a': 0x30, // hard sign
	'\u0444': 0x04, // ef
	'\u044b': 0x16, // yeru
	'\u0432': 0x07, // ve
	'\u0430': 0x09, // a
	'\u043f': 0x0a, // pe
	'\u0440': 0x0b, // er
	'\u043e': 0x0d, // o
	'\u043b': 0x0e, // el
	'\u0434': 0x0f, // de
	'\u0436': 0x33, // zhe
	'\u044d': 0x34, // e
	'\u044f': 0x1d, // ya
	'\u0447': 0x1b, // che
	'\u0441': 0x06, // es
	'\u043c': 0x19, // em
	'\u0438': 0x05, // i
	'\u0442': 0x11, // te
	'\u044c': 0x10, // soft sign
	'\u0431': 0x36, // be
	'\u044e': 0x37, // yu
	'\u0451': 0x35, // io
}

var ruShifted = map[rune]byte{
	'!': 0x1e, '"': 0x1f, '\u2116': 0x20 /* the numero sign */, ';': 0x21, '%': 0x22, ':': 0x23,
	'?': 0x24, '*': 0x25, '(': 0x26, ')': 0x27, '_': 0x2d, '+': 0x2e, '/': 0x31, ',': 0x38,
}

var ruPlain = map[rune]byte{'\\': 0x31, '.': 0x38}

func ru(r rune) (Key, bool) {
	if k, ok := digit(r); ok {
		return k, true
	}
	if u, ok := ruLetters[r]; ok {
		return Key{Usage: u}, true
	}
	// A capital: the small letter's key with Shift. The Cyrillic capitals
	// U+0410 to U+042F are 32 below their small letters, and Io's capital
	// U+0401 is 80 below.
	switch {
	case r >= '\u0410' && r <= '\u042f':
		if u, ok := ruLetters[r+0x20]; ok {
			return Key{Usage: u, Modifiers: LeftShift}, true
		}
	case r == '\u0401':
		return Key{Usage: ruLetters['\u0451'], Modifiers: LeftShift}, true
	}
	if u, ok := ruShifted[r]; ok {
		return Key{Usage: u, Modifiers: LeftShift}, true
	}
	if u, ok := ruPlain[r]; ok {
		return Key{Usage: u}, true
	}
	return Key{}, false
}
