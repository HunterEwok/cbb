// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"fmt"

	"github.com/HunterEwok/cbb/internal/strict"
)

// checkStrict checks that b is a signed body in the strict form
// (strict.Check), with each name in required a member of its object.
func checkStrict(b []byte, required ...string) error {
	if err := strict.Check(b, required...); err != nil {
		return fmt.Errorf("group: %w", err)
	}
	return nil
}

// decodeStrictBase64 decodes s, standard base64 with padding, only when s
// is the one encoding of its bytes.
func decodeStrictBase64(s string) ([]byte, error) {
	b, err := strict.DecodeBase64(s)
	if err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}
	return b, nil
}
