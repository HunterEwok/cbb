// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
)

// cacheBytes adds up the files in the cache.
func cacheBytes(t *testing.T, dir string) int64 {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, e := range ents {
		if i, err := e.Info(); err == nil {
			n += i.Size()
		}
	}
	return n
}

// TestLeftPartsSwept: what fetches that ended without the whole part left
// counts against twice the limit and goes contentKeep after no copy needs
// it, while what the current copy's fetch left, and what a fetch writes,
// stays.
func TestLeftPartsSwept(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := filepath.Join(t.TempDir(), contentDir)
	store, err := openContent(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	const limit = 1 << 20
	left := func(sum [sha256.Size]byte) {
		f, _, _, err := store.partial(sum)
		if err != nil {
			t.Fatal(err)
		}
		f.Write(make([]byte, limit))
		store.leave(f, sum)
		store.fetchEnded(sum)
	}
	for i := range 20 {
		left([sha256.Size]byte{byte(i)})
		store.setCurrent(nil, limit) // the next copy replaces it
		now = now.Add(time.Second)
	}
	if n := cacheBytes(t, dir); n > 2*limit {
		t.Errorf("%d bytes of left parts held, over twice the limit", n)
	}

	// One of the current copy stays, one a fetch writes too.
	cur := [sha256.Size]byte{0xc0}
	left(cur)
	store.setCurrent(&clip.Manifest{Size: limit, Parts: []clip.Part{{SHA256: cur[:], Size: limit}}}, limit)
	busy := [sha256.Size]byte{0xb0}
	f, _, _, err := store.partial(busy)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(make([]byte, limit))
	now = now.Add(time.Hour)
	store.sweep(limit)
	for _, sum := range [][sha256.Size]byte{cur, busy} {
		if _, err := os.Stat(store.path(sum) + ".part"); err != nil {
			t.Errorf("the part %x: %v", sum[:1], err)
		}
	}
	if n := cacheBytes(t, dir); n != 2*limit {
		t.Errorf("%d bytes held after an hour, want the current copy's and the fetch's", n)
	}
}

// TestReplacedPartsSweptWithoutNextCopy: the service deletes a replaced
// copy's part once contentKeep has passed even when no later copy comes
// to replace the one after it.
func TestReplacedPartsSweptWithoutNextCopy(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	dir := filepath.Join(t.TempDir(), contentDir)
	store, err := openContent(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	const limit = 1 << 20
	data := []byte("a copied file's only part")
	f, err := store.temp()
	if err != nil {
		t.Fatal(err)
	}
	f.Write(data)
	sum := sha256.Sum256(data)
	if err := store.commit(f, sum, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	store.setCurrent(&clip.Manifest{Size: int64(len(data)), Parts: []clip.Part{{SHA256: sum[:], Size: int64(len(data))}}}, limit)
	store.setCurrent(&clip.Manifest{Size: 0}, limit) // a text copy replaces it, and nothing follows

	s := &Service{content: store, limits: mediaLimits{Home: limit, Away: limit}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.sweepContent(ctx, 5*time.Millisecond)

	time.Sleep(50 * time.Millisecond)
	if !store.has(sum) {
		t.Fatal("the replaced part went before contentKeep")
	}
	mu.Lock()
	now = now.Add(contentKeep + time.Second)
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for store.has(sum) {
		if time.Now().After(deadline) {
			t.Fatalf("the part replaced %v ago is still in the cache", contentKeep)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(store.path(sum)); !os.IsNotExist(err) {
		t.Errorf("the part's file: %v", err)
	}
}
