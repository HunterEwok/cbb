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

// CompleteRoots checks that roots can sign a keys.json devices take: two
// roots or more, each with exactly one half for every algorithm of
// Required. The pinned roots must pass it before a release
// (docs/maintaining.md, "Two signatures"): a root missing a half signs
// nothing a device of that build takes.
func CompleteRoots(roots []Key) error {
	halves := map[string]map[int]int{}
	var names []string
	for _, r := range roots {
		if halves[r.Name] == nil {
			halves[r.Name] = map[int]int{}
			names = append(names, r.Name)
		}
		halves[r.Name][r.Alg]++
	}
	if len(names) < 2 {
		return fmt.Errorf("%d root keys, not two or more", len(names))
	}
	for _, n := range names {
		for _, alg := range Required {
			if c := halves[n][alg]; c != 1 {
				return fmt.Errorf("the root %s has %d halves of algorithm %d, not one", n, c, alg)
			}
		}
		if len(halves[n]) != len(Required) {
			return fmt.Errorf("the root %s has a half of an algorithm devices do not require", n)
		}
	}
	return nil
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
