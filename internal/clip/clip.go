// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package clip holds what the helper's and the desktop's clipboards share
// about a copy: its kind, how its text reached the member that made it,
// and the manifest of its images and files (docs/format.md, section 10).
// The member that syncs the copies is the Rust core's.
package clip

import (
	"fmt"
)

// MaxText is the largest text, in bytes, that the group carries.
const MaxText = 1 << 20

// Kind tells normal text from a secret, such as a password, and from
// images and files.
type Kind uint8

const (
	Text   Kind = iota // normal text
	Secret             // kept only in memory, expires, sent in a hello only as a mark
	Media              // images or files: a manifest, and maybe a plain-text alternative
)

// MarshalText implements encoding.TextMarshaler.
func (k Kind) MarshalText() ([]byte, error) {
	switch k {
	case Text:
		return []byte("text"), nil
	case Secret:
		return []byte("secret"), nil
	case Media:
		return []byte("media"), nil
	}
	return nil, fmt.Errorf("clip: unknown kind %d", k)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Kind) UnmarshalText(b []byte) error {
	switch string(b) {
	case "text":
		*k = Text
	case "secret":
		*k = Secret
	case "media":
		*k = Media
	default:
		return fmt.Errorf("clip: unknown kind %q", b)
	}
	return nil
}

// Via tells how a text reached the member that made the event.
type Via uint8

const (
	Copy      Via = iota // copied on that member
	Phone                // sent from a phone's app
	Universal            // reached a Mac through Universal Clipboard, from an iPhone or another Mac
)

// MarshalText implements encoding.TextMarshaler.
func (v Via) MarshalText() ([]byte, error) {
	switch v {
	case Copy:
		return []byte("copy"), nil
	case Phone:
		return []byte("phone"), nil
	case Universal:
		return []byte("universal-clipboard"), nil
	}
	return nil, fmt.Errorf("clip: unknown via %d", v)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (v *Via) UnmarshalText(b []byte) error {
	switch string(b) {
	case "copy":
		*v = Copy
	case "phone":
		*v = Phone
	case "universal-clipboard":
		*v = Universal
	default:
		return fmt.Errorf("clip: unknown via %q", b)
	}
	return nil
}
