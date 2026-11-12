// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/refused"
)

// writeList writes the list of refused groups with its own time, as an
// editor's save would have.
func writeList(t *testing.T, path, s string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-age)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

// TestRefusedGroups: a group on the operator's list cannot register, one
// put on it is dropped, one taken off registers again, and the others go
// on all the while (docs/relay-budget.md, "Abuse reports").
func TestRefusedGroups(t *testing.T) {
	certA, tagA, rootA := member(t)
	certB, tagB, rootB := member(t)
	path := filepath.Join(t.TempDir(), "refused-groups")
	writeList(t, path, "# reported 2026-11-09\n"+tagA+"\n", 3*time.Minute)
	list, err := refused.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f, pin := startForwarderWith(t, Config{Refused: list})
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	keyB, _ := ecdh.X25519().GenerateKey(rand.Reader)

	if a := rawRegister(t, f, pin, certA, key.PublicKey().Bytes(), key, hubAuth{key: rootA.Key}); a.Error != refused.Message {
		t.Fatalf("a refused group: %+v", a)
	}
	if f.registered(tagA) {
		t.Fatal("a refused group is registered")
	}
	tc, a := rawOpen(t, f, pin, certB, keyB.PublicKey().Bytes(), keyB, hubAuth{key: rootB.Key})
	if tc == nil || a.Error != "" {
		t.Fatalf("another group: %+v", a)
	}
	defer tc.Close()

	// Put on the list, B goes; A, taken off it, comes back.
	writeList(t, path, tagB+"\n", 2*time.Minute)
	f.reloadRefused()
	waitUntil(t, "the refused group dropped", func() bool { return !f.registered(tagB) })
	tcA, a := rawOpen(t, f, pin, certA, key.PublicKey().Bytes(), key, hubAuth{key: rootA.Key})
	if tcA == nil || a.Error != "" {
		t.Fatalf("a group taken off the list: %+v", a)
	}
	defer tcA.Close()

	// A broken list keeps the one before: B stays out, A stays in.
	writeList(t, path, "not a tag\n", time.Minute)
	f.reloadRefused()
	if a := rawRegister(t, f, pin, certB, keyB.PublicKey().Bytes(), keyB, hubAuth{key: rootB.Key}); a.Error != refused.Message {
		t.Fatalf("a refused group, after a broken list: %+v", a)
	}
	if !f.registered(tagA) {
		t.Fatal("a broken list dropped a group not on the list before")
	}
}
