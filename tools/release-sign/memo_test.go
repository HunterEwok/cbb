// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// An SLH-DSA-SHA2-128s signature takes a quarter of a second here, eight
// times that under the race detector and far more in an emulated machine,
// and the tests sign some 150 files. So the tests share their keys, and
// the SLH-DSA halves keep each signature they made: a body signed again
// under the same key gets the same signature back, which verifies as a new
// one would. Each test takes the pool's keys in the same order and starts
// at the same time, so the files its first steps sign repeat from test to
// test. The ES256 halves sign anew each time.

// memoSigner is an SLH-DSA half that signs each message once.
type memoSigner struct {
	crypto.Signer
	mu   sync.Mutex
	sigs map[string][]byte
}

var memo struct {
	mu   sync.Mutex
	slh  map[string]*memoSigner // by the half's public key
	pool []release.Signer
	next map[string]int // the pool's next key, by test
}

// memoized gives the SLH-DSA half of s the signatures this half made
// before, read from a file or not.
func memoized(s release.Signer) release.Signer {
	if len(s) != 2 {
		return s
	}
	_, pub, err := release.MarshalPublic(s[1].Public())
	if err != nil {
		return s
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	m := memo.slh[string(pub)]
	if m == nil {
		if m, ok := s[1].(*memoSigner); ok {
			memo.slh[string(pub)] = m
			return s
		}
		m = &memoSigner{Signer: s[1], sigs: map[string][]byte{}}
		memo.slh[string(pub)] = m
	}
	return release.Signer{s[0], m}
}

// pooledKey returns the test's next key from the pool, as generated: a
// test's keys differ, and every test gets the same ones in the same order.
// Read back from its file, the key signs through memoized.
func pooledKey(t *testing.T) release.Signer {
	t.Helper()
	test, _, _ := strings.Cut(t.Name(), "/")
	memo.mu.Lock()
	i := memo.next[test]
	memo.next[test]++
	for len(memo.pool) <= i {
		k, err := release.GenerateSigner()
		if err != nil {
			memo.mu.Unlock()
			t.Fatal(err)
		}
		memo.pool = append(memo.pool, k)
	}
	k := memo.pool[i]
	memo.mu.Unlock()
	return k
}

// testStart is the time every test's clock starts at.
var testStart = time.Now()

func (m *memoSigner) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sig, ok := m.sigs[string(msg)]; ok {
		return slices.Clone(sig), nil
	}
	sig, err := m.Signer.Sign(r, msg, opts)
	if err != nil {
		return nil, err
	}
	m.sigs[string(msg)] = sig
	return slices.Clone(sig), nil
}

var testDrill struct {
	once sync.Once
	ks   [4]release.Signer
	err  error
}

// sharedDrillSigners gives every drill of the tests the same four keys.
func sharedDrillSigners() ([4]release.Signer, error) {
	d := &testDrill
	d.once.Do(func() {
		for i := range d.ks {
			k, err := release.GenerateSigner()
			if err != nil {
				d.err = err
				return
			}
			d.ks[i] = memoized(k)
		}
	})
	return d.ks, d.err
}

// drillClock holds the clock still for a test's drills, so that their
// bodies, and so their signatures, repeat.
func drillClock(t *testing.T) {
	prev := now
	now = func() time.Time { return testStart }
	t.Cleanup(func() { now = prev })
}

func TestMain(m *testing.M) {
	memo.slh, memo.next = map[string]*memoSigner{}, map[string]int{}
	drillSigners, fileSigner = sharedDrillSigners, memoized
	m.Run()
}
