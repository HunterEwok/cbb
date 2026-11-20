// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/lockcheck"
	"github.com/HunterEwok/cbb/internal/uinput"
)

// memBoard is a clipboard in memory that records what it held when the
// keys were pressed.
type memBoard struct {
	mu   sync.Mutex
	item connector.Item
	has  bool
	own  bool
}

func (b *memBoard) Current() (connector.Item, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.item, b.has, nil
}

func (b *memBoard) Write(text string, secret bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.item, b.has, b.own = connector.Item{Text: text, Secret: secret}, true, true
	return nil
}

func (b *memBoard) ClearIfUnchanged() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.own {
		b.item, b.has = connector.Item{}, false
	}
	return nil
}

func (b *memBoard) Holds(text string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.own && b.item.Text == text
}

type recordKeys struct {
	mu    sync.Mutex
	keys  []uinput.Key
	board *memBoard
	seen  []string // what the clipboard held at each press
}

func (r *recordKeys) Press(ks []uinput.Key) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, ks...)
	it, _, _ := r.board.Current()
	r.seen = append(r.seen, it.Text)
	return nil
}

// TestKeysHelperPaste checks a paste through the uinput helper: the text is
// in the clipboard when the helper presses Shift+Insert, Enter follows when
// asked, the clipboard gets its text back, and typing is refused.
func TestKeysHelperPaste(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "keys")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	board := &memBoard{item: connector.Item{Text: "before"}, has: true}
	keys := &recordKeys{board: board}
	h := &uinput.Helper{Keys: keys, Logf: t.Logf, Check: func(uint32) string { return "" }, Grant: func(_ uint32, _, grant string) string {
		if grant != "g7" {
			return "no remote paste asked for these keys now"
		}
		return ""
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Serve(ctx, ln)

	kb := keysHelper{socket: sock}
	var r *connector.Refusal
	// Without logind nothing tells whether the session is locked: the
	// paste is refused unless the device's user allowed that.
	t.Setenv("PATH", t.TempDir())
	if err := keysInject(connector.WithKeysGrant(context.Background(), "g7"), kb, board, "unknown lock", "paste", false, false); !errors.As(err, &r) || r.Reason != lockcheck.Unknown {
		t.Errorf("a paste where nothing tells whether the session is locked: %v", err)
	}
	unchecked := connector.WithoutLockCheck(context.Background(), true)
	if err := keysInject(unchecked, kb, board, "no grant", "paste", false, false); !errors.As(err, &r) || r.Reason == lockcheck.Unknown {
		t.Errorf("a paste without the service's grant: %v", err)
	}
	if err := keysInject(connector.WithKeysGrant(unchecked, "g7"), kb, board, "pasted text", "paste", true, false); err != nil {
		t.Fatal(err)
	}
	want := []uinput.Key{{Code: uinput.KeyLeftShift, Press: true}, {Code: uinput.KeyInsert, Press: true}, {Code: uinput.KeyInsert}, {Code: uinput.KeyLeftShift},
		{Code: uinput.KeyEnter, Press: true}, {Code: uinput.KeyEnter}}
	keys.mu.Lock()
	got, seen := slices.Clone(keys.keys), slices.Clone(keys.seen)
	keys.mu.Unlock()
	if !slices.Equal(got, want) {
		t.Errorf("pressed %v, want %v", got, want)
	}
	if len(seen) == 0 || seen[0] != "pasted text" {
		t.Errorf("the clipboard at the paste keys: %q", seen)
	}
	if it, _, _ := board.Current(); it.Text != "before" {
		t.Errorf("the clipboard afterwards: %q, want its text back", it.Text)
	}
	if err := keysInject(context.Background(), kb, board, "typed", "type", false, false); !errors.As(err, &r) {
		t.Errorf("typing through the helper: %v", err)
	}
	if err := keysInject(unchecked, kb, board, "x", "shout", false, false); !errors.As(err, &r) {
		t.Errorf("an unknown method: %v", err)
	}

	// Images and files: write puts them in, then the same keys.
	keys.mu.Lock()
	keys.keys, keys.seen = nil, nil
	keys.mu.Unlock()
	if err := keysInjectMedia(connector.WithKeysGrant(unchecked, "g7"), kb, func() error { return board.Write("an image", false) }, false); err != nil {
		t.Fatal(err)
	}
	keys.mu.Lock()
	got, seen = slices.Clone(keys.keys), slices.Clone(keys.seen)
	keys.mu.Unlock()
	if !slices.Equal(got, want[:4]) || len(seen) == 0 || seen[0] != "an image" {
		t.Errorf("media: pressed %v with %q", got, seen)
	}
	if err := keysInjectMedia(connector.WithKeysGrant(unchecked, "g7"), kb, func() error { return errors.New("no image") }, false); err == nil {
		t.Error("pasted media it could not write")
	}
	if err := keysInjectMedia(unchecked, kb, func() error { return nil }, true); !errors.As(err, &r) {
		t.Errorf("media without the service's grant: %v", err)
	}
	if err := keysInjectMedia(context.Background(), kb, func() error { return nil }, true); !errors.As(err, &r) || r.Reason != lockcheck.Unknown {
		t.Errorf("media where nothing tells whether the session is locked: %v", err)
	}
	if err := keysInjectMedia(connector.WithKeysGrant(unchecked, "g7"), kb, func() error { return nil }, true); err != nil {
		t.Errorf("media with Enter: %v", err)
	}
}
