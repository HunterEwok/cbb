// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"fmt"
	"time"

	"github.com/HunterEwok/cbb/internal/core"
)

// The rule of incoming copies (docs/protocol.md, section 5, "Writing to
// the clipboard") is the Rust core's (cbb_core::rule): a build that links
// the core (every release build) asks it through copy_verdict, so that
// every member keeps one rule; a build without it runs this copy of it,
// which testdata/interop/copy-verdicts.json keeps the same.

// Incoming is what the member knows of the group's current copy when it
// decides whether the copy goes into its clipboard.
type Incoming struct {
	Receives    bool  `json:"receives"`
	Kind        Kind  `json:"kind"`
	Mark        bool  `json:"mark"`
	Unread      bool  `json:"unread"`
	HasText     bool  `json:"has_text"`
	HasMedia    bool  `json:"has_media"`
	TakesMedia  bool  `json:"takes_media"`
	Held        bool  `json:"held"`
	AgeMS       int64 `json:"age_ms"`
	WindowMS    int64 `json:"window_ms"`
	SecretTTLMS int64 `json:"secret_ttl_ms"`
}

// Verdict is "write", or why the copy is not written.
type Verdict string

// The verdicts.
const (
	VerdictWrite      Verdict = "write"
	VerdictMode       Verdict = "mode"
	VerdictUnread     Verdict = "unread"
	VerdictSecretGone Verdict = "secret_gone"
	VerdictNoText     Verdict = "no_text"
	VerdictHeld       Verdict = "held"
	VerdictOld        Verdict = "old"
)

// Decide gives the verdict on the copy: the core's in a build that links
// it, Go's own otherwise. A core that does not answer leaves the copy
// out of the clipboard, with the error for the log.
func Decide(i Incoming) (Verdict, error) {
	if !core.Linked() {
		return decide(i), nil
	}
	var out struct {
		Verdict Verdict `json:"verdict"`
	}
	if err := core.Do("copy_verdict", i, &out); err != nil {
		return VerdictMode, fmt.Errorf("clip: the core's rule of incoming copies: %w", err)
	}
	return out.Verdict, nil
}

// decide is Go's copy of cbb_core::rule::incoming.
func decide(i Incoming) Verdict {
	switch {
	case !i.Receives:
		return VerdictMode
	case i.Mark || i.Unread:
		return VerdictUnread
	case i.Kind == Secret && i.AgeMS >= i.SecretTTLMS:
		return VerdictSecretGone
	case !i.HasText && !(i.TakesMedia && i.HasMedia):
		return VerdictNoText
	case i.Held:
		return VerdictHeld
	case i.AgeMS >= i.WindowMS:
		return VerdictOld
	}
	return VerdictWrite
}

// holds reports whether a mute or sync turned off until until (the zero time for
// until it is lifted, nil for none) holds at now: cbb_core::rule::holds.
func holds(until *time.Time, now time.Time) bool {
	switch {
	case until == nil:
		return false
	case until.IsZero():
		return true
	}
	return now.Before(*until)
}
