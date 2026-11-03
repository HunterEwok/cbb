// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package grouptest signs group records for the tests of other packages,
// as a chain per signer in the records of version 2 (docs/records-v2.md).
// No product code imports it.
package grouptest

import (
	"crypto"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/group"
)

// chainKey names a signer's chain in one test: each test starts its
// signers' chains again, since its records go to sets of its own.
type chainKey struct {
	test   string
	signer group.KeyHash
}

// heads keeps, for each signer in each test, the record it signed last and
// its group.
var heads = struct {
	sync.Mutex
	m     map[chainKey]authority.Head
	group map[chainKey]string
}{m: map[chainKey]authority.Head{}, group: map[chainKey]string{}}

// Sign signs body as the next record of key: seq and prev follow the key's
// last record signed here in the same test, and a removal, freeze or claim
// without seen saw every record signed here for its group in that test. chain, if any, starts with the
// admin CA that certifies key; a root's own key needs none.
func Sign(t testing.TB, body group.RecordBody, key crypto.Signer, chain ...*x509.Certificate) group.Record {
	t.Helper()
	signer, err := authority.PublicKeyHash(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	heads.Lock()
	defer heads.Unlock()
	at := chainKey{t.Name(), signer}
	h := heads.m[at]
	body.Seq = h.Seq + 1
	if h.Seq > 0 {
		prev := h.ID
		body.Prev = &prev
	}
	switch body.Type {
	case group.RecordRevoke, group.RecordFreeze, group.RecordClaim:
		if body.Seen == nil {
			body.Seen = []authority.Seen{{Key: signer, Seq: h.Seq}}
			for k, o := range heads.m {
				if k.test == at.test && k.signer != signer && heads.group[k] == body.Group {
					body.Seen = append(body.Seen, authority.Seen{Key: k.signer, Seq: o.Seq})
				}
			}
		}
	}
	var adminCA *x509.Certificate
	if len(chain) > 0 {
		adminCA = chain[0]
	}
	r, err := authority.Sign(body, key, adminCA)
	if err != nil {
		t.Fatal(err)
	}
	heads.m[at] = authority.Head{Key: signer, Seq: body.Seq, ID: r.ID()}
	heads.group[at] = body.Group
	return r
}
