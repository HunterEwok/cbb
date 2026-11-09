// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package clip holds the copies as they travel between members: their
// events, kinds and media, sealed end to end (docs/protocol.md, section 4),
// and the rule on which incoming copies are written (Decide). The member
// that syncs them is the Rust core's; this package is Go's reference for
// the interop vectors in testdata/interop and for the helper's and the
// desktop's clipboards.
package clip

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/hlc"
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

// Event is one copy, as it travels between members.
type Event struct {
	ID     string        `json:"id"`     // 128 random bits, 32 lowercase hex characters
	Origin string        `json:"origin"` // the device ID of the member that made the event
	Via    Via           `json:"via,omitempty"`
	Time   hlc.Timestamp `json:"time"`
	Age    int64         `json:"age_ms"` // milliseconds since the copy, when the event was sent
	Kind   Kind          `json:"kind"`
	Text   string        `json:"text"` // empty only in the mark of a secret, and in media without a text
	// Media is the content of a media event, which only it has.
	Media *Manifest `json:"media,omitempty"`

	// Sealed is the copy as it travels between members, sealed end to end
	// (docs/protocol.md, section 4), when the event came from one.
	Sealed *Sealed `json:"-"`
	// Unread says that this member does not know the event's content: it
	// is a mark, or a copy not sealed to this member. Kind, Via, Text and
	// Media are then empty, and the event is current only for ordering.
	Unread bool `json:"-"`
	// Key is the copy's key, which opens its blob, when this member
	// opened the copy (EventOf).
	Key []byte `json:"-"`
}

// IsMark reports whether e is the mark of a secret: the event without its
// payload, or, unsealed, without its text.
func (e Event) IsMark() bool {
	if e.Sealed != nil {
		return e.Sealed.IsMark()
	}
	return e.Kind == Secret && e.Text == ""
}

// Validate checks an event received from another member.
func (e Event) Validate() error {
	if e.Unread {
		switch {
		case e.Sealed == nil:
			return errors.New("clip: an unread event without its sealed copy")
		case !isID(e.ID), !isID(e.Origin), e.Time.IsZero() || !e.Time.Valid(), e.Age < 0:
			return errors.New("clip: bad event ID, origin, timestamp or age")
		}
		return nil
	}
	switch {
	case !isID(e.ID):
		return errors.New("clip: bad event ID")
	case !isID(e.Origin):
		return errors.New("clip: bad origin device ID")
	case e.Time.IsZero() || !e.Time.Valid():
		return errors.New("clip: bad timestamp")
	case e.Kind > Media:
		return fmt.Errorf("clip: unknown kind %d", e.Kind)
	case (e.Kind == Media) != (e.Media != nil):
		return errors.New("clip: only a media event has a manifest, and it always does")
	case e.Via > Universal:
		return fmt.Errorf("clip: unknown via %d", e.Via)
	case e.Age < 0:
		return fmt.Errorf("clip: negative event age %d ms", e.Age)
	case e.IsMark():
		return nil
	case e.Kind == Media:
		if err := e.Media.Validate(); err != nil {
			return err
		}
		if e.Text == "" {
			return nil
		}
		if len(e.Text) > MaxAltText {
			return fmt.Errorf("clip: a media event's text of %d bytes is larger than %d", len(e.Text), MaxAltText)
		}
	}
	return checkText(e.Text)
}

func checkText(s string) error {
	switch {
	case s == "":
		return errors.New("clip: empty text")
	case len(s) > MaxText:
		return fmt.Errorf("clip: text of %d bytes is larger than %d", len(s), MaxText)
	case !utf8.ValidString(s):
		return errors.New("clip: text is not valid UTF-8")
	}
	return nil
}

// isID reports whether s is 32 lowercase hex characters: an event or device ID.
func isID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// NewID returns a random event or device ID.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b) // never fails, see crypto/rand
	return hex.EncodeToString(b)
}
