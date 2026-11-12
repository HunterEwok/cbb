// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	_ "embed"
	"encoding/pem"
)

// rootsPEM holds the project's release root keys, two YubiKeys
// (roots/README.md).
//
//go:embed roots/roots.pem
var rootsPEM []byte

// Roots are the pinned root keys (SubjectPublicKeyInfos, DER) that every
// keys.json must verify under (docs/maintainers/maintaining.md, "Signed releases").
var Roots = parseRoots(rootsPEM)

func parseRoots(data []byte) [][]byte {
	var roots [][]byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return roots
		}
		if b.Type != "PUBLIC KEY" {
			panic("release: roots.pem holds a " + b.Type)
		}
		roots = append(roots, b.Bytes)
	}
}
