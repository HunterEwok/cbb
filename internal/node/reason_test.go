// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
)

func TestCleanReason(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"plain":         {"the screen is locked", "the screen is locked"},
		"empty":         {"", ""},
		"escape":        {"a\x1b[2Jb\x1b]52;c;ZXZpbA==\x07c", "a [2Jb ]52;c;ZXZpbA== c"},
		"newline, tab":  {"a\nb\tc\r", "a b c "},
		"C1 control":    {"a\u009bb", "a b"},
		"invalid UTF-8": {"a\xffb", "a�b"},
		"text kept":     {"écran verrouillé", "écran verrouillé"},
	} {
		if got := CleanReason(c.in); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	long := CleanReason(strings.Repeat("a", 1000))
	if len(long) != MaxReason {
		t.Errorf("a long reason has %d bytes", len(long))
	}
	// A character cut by the limit goes whole.
	cut := CleanReason(strings.Repeat("a", MaxReason-1) + "é")
	if !utf8.ValidString(cut) || cut != strings.Repeat("a", MaxReason-1) {
		t.Errorf("a character at the limit: %q", cut[len(cut)-3:])
	}
	if got := CleanReason(strings.Repeat("é", MaxReason)); len(got) > MaxReason || !utf8.ValidString(got) {
		t.Errorf("a long reason of 2-byte characters has %d bytes", len(got))
	}
}

// The sender gets what a receiver answers as plain, short text.
func TestResultReasonCleaned(t *testing.T) {
	evil := "\x1b]52;c;ZXZpbA==\x07\x1b[2J\x1b[Hdone" + strings.Repeat("x", 1000)
	b := newMember(t, Member, func(_ *clip.Config, nc *Config) {
		nc.OnCommand = func(group.DeviceID, group.Record) Result { return Result{Status: ResultFailed, Reason: evil} }
	})
	a := newMember(t, Member)
	link(t, a, b)
	waitPeers(t, a, 1)
	id := group.NewCommandID()
	body, _ := json.Marshal(map[string]any{"id": id, "to": b.id.ID, "expires_ms": time.Now().Add(10 * time.Second).UnixMilli()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := a.SendCommand(ctx, b.id.ID, group.Record{Body: body}, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != ResultFailed {
		t.Errorf("status %q", res.Status)
	}
	if strings.ContainsAny(res.Reason, "\x1b\x07") || len(res.Reason) > MaxReason || !strings.HasPrefix(res.Reason, " ]52;c;ZXZpbA==") {
		t.Errorf("reason %q (%d bytes)", res.Reason, len(res.Reason))
	}
}
