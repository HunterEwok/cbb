// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	_ "embed"
	"errors"
	"fmt"
)

// rootsPEM holds the project's release root keys, two YubiKeys, each with
// its post-quantum half (roots/README.md).
//
//go:embed roots/roots.pem
var rootsPEM []byte

// UseRoot is the use of a pinned root key.
const UseRoot = "root"

// Roots are the pinned root keys, the halves of each named by its PEM
// header Name, that every keys.json must verify under (docs/maintaining.md,
// "Signed releases").
var Roots = mustRoots(rootsPEM)

func mustRoots(data []byte) []Key {
	r, err := ParseRoots(data)
	if err != nil {
		panic("release: roots.pem: " + err.Error())
	}
	return r
}

// ParseRoots reads root keys from PEM: each block a PUBLIC KEY with the
// header Name, the halves of one root sharing it.
func ParseRoots(data []byte) ([]Key, error) {
	var roots []Key
	for {
		b, rest := pemDecode(data)
		if b == nil {
			if len(roots) == 0 {
				return nil, errors.New("no root keys")
			}
			return roots, nil
		}
		data = rest
		if b.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("a %s", b.Type)
		}
		name := b.Headers["Name"]
		if name == "" || len(name) > maxName {
			return nil, errors.New("a root key has no Name")
		}
		alg, err := spkiAlg(b.Bytes)
		if err != nil {
			return nil, err
		}
		roots = append(roots, Key{Alg: alg, Key: b.Bytes, Name: name, Use: UseRoot})
	}
}

// spkiAlg returns the algorithm of a SubjectPublicKeyInfo this version
// knows.
func spkiAlg(spki []byte) (int, error) {
	for _, alg := range []int{AlgES256, AlgSLHDSA} {
		if checkPublic(alg, spki) == nil {
			return alg, nil
		}
	}
	return 0, errors.New("a root key of an unknown algorithm")
}
