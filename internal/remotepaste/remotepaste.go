// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package remotepaste holds what a member keeps for remote paste (design.md,
// "Remote paste"): the switches its own user sets, the cleaning of a text
// before it goes in, the limits per sender and the log of the last pastes.
package remotepaste

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/atomicfile"
)

// Settings are the switches of remote paste on a device, which only its own
// user turns on: On lets the group's admins paste, Enter lets a paste press
// Enter, Console lets it reach text consoles and root's tmux, and
// NoLockCheck lets a target paste where it cannot tell whether the session
// is locked, which it otherwise refuses.
type Settings struct {
	On          bool `json:"on"`
	Enter       bool `json:"enter,omitempty"`
	Console     bool `json:"console,omitempty"`
	NoLockCheck bool `json:"no_lock_check,omitempty"`
}

// settingsFile holds the settings in the state directory.
const settingsFile = "paste-receive"

// Load reads the settings from dir: all off when there are none.
func Load(dir string) (Settings, error) {
	var s Settings
	b, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", settingsFile, err)
	}
	return s, nil
}

// Save writes the settings to dir. Off, the other switches are off too.
func Save(dir string, s Settings) error {
	if !s.On {
		s = Settings{}
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, settingsFile), append(b, '\n'), 0o600)
}

// Clean returns the text as it may go in: valid UTF-8 with newlines and
// tabs, without other control characters and without terminal escape
// sequences, so that a paste cannot move a terminal's cursor or run what
// the user does not see. CR LF and a lone CR become LF.
func Clean(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); {
		r, n := utf8.DecodeRuneInString(text[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			// Not UTF-8: dropped.
		case r == '\r':
			b.WriteByte('\n')
			if i+1 < len(text) && text[i+1] == '\n' {
				n++
			}
		case r == 0x1b:
			n = escapeLen(text[i:])
		case r == 0x9b: // CSI on its own
			n += csiLen(text[i+n:])
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0:
			// Another control character: dropped.
		default:
			b.WriteString(text[i : i+n])
		}
		i += n
	}
	return b.String()
}

// escapeLen is the length of the escape sequence at the start of s, which
// starts with ESC: CSI (ESC [ … final), OSC, DCS and the like up to their
// end (BEL or ESC \), or ESC and one character.
func escapeLen(s string) int {
	if len(s) < 2 {
		return len(s)
	}
	switch s[1] {
	case '[':
		return 2 + csiLen(s[2:])
	case ']', 'P', 'X', '^', '_':
		for i := 2; i < len(s); i++ {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
		}
		return len(s)
	}
	_, n := utf8.DecodeRuneInString(s[1:])
	return 1 + n
}

// csiLen is the length of a CSI sequence's parameters and final byte.
func csiLen(s string) int {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 0x40 && c <= 0x7e:
			return i + 1
		case c < 0x20 || c > 0x7e:
			return i
		}
	}
	return len(s)
}

// The limits per sender: at most one paste a second and Burst a minute.
const (
	Every = time.Second
	Burst = 30
)

// A Limiter counts each sender's pastes.
type Limiter struct {
	mu   sync.Mutex
	sent map[string][]time.Time
}

// Allow reports whether the sender may paste at now, and counts it if so.
func (l *Limiter) Allow(sender string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sent == nil {
		l.sent = map[string][]time.Time{}
	}
	for k, ts := range l.sent {
		for len(ts) > 0 && now.Sub(ts[0]) >= time.Minute {
			ts = ts[1:]
		}
		if len(ts) == 0 {
			delete(l.sent, k)
		} else {
			l.sent[k] = ts
		}
	}
	ts := l.sent[sender]
	if len(ts) >= Burst || len(ts) > 0 && now.Sub(ts[len(ts)-1]) < Every {
		return false
	}
	l.sent[sender] = append(ts, now)
	return true
}

// An Entry is one paste in the log: who sent it, when, how long it was and
// how it ended, never its text.
type Entry struct {
	TimeMS int64  `json:"time_ms"`
	By     string `json:"by"`             // the sender's device ID
	Name   string `json:"name,omitempty"` // the sender's name, when known
	// Unverified: the records do not show that the device By names
	// signed; By is then only the signer's word.
	Unverified bool   `json:"unverified,omitempty"`
	Len        int    `json:"len"`    // bytes of the text
	Method     string `json:"method"` // paste or type
	Enter      bool   `json:"enter,omitempty"`
	Result     string `json:"result"` // done, refused or failed
	Reason     string `json:"reason,omitempty"`
}

// LogFile keeps the last LogSize pastes in the state directory.
const (
	LogFile = "pastes.json"
	LogSize = 100
)

// Append adds an entry to the log in dir, keeping the last LogSize.
func Append(dir string, e Entry) error {
	es, err := ReadLog(dir)
	if err != nil {
		es = nil
	}
	es = append(es, e)
	if len(es) > LogSize {
		es = es[len(es)-LogSize:]
	}
	b, err := json.Marshal(es)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, LogFile), b, 0o600)
}

// ReadLog returns the log in dir, oldest first.
func ReadLog(dir string) ([]Entry, error) {
	b, err := os.ReadFile(filepath.Join(dir, LogFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("%s: %w", LogFile, err)
	}
	return es, nil
}
