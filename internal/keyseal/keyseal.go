// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package keyseal names a secret sealed by the device's hardware
// (docs/protocol.md, section 17): by a TPM, or by a Mac's Secure Enclave.
// It imports neither, so that a package that keeps such secrets in a file
// (internal/tunnel, also in the phones' tunnel) does not pull in the code
// that seals them.
package keyseal

import "github.com/HunterEwok/clipboardbridge/internal/tpmkey"

// A Blob is a sealed secret: exactly one of TPM and SE is set.
type Blob struct {
	// TPM is a sealed data object under the TPM's storage root key.
	TPM *tpmkey.Blob
	// SE is the secret sealed to a key in a Mac's Secure Enclave
	// (sekey.Seal), a JSON object.
	SE []byte
}

// A Sealer seals secrets with the device's hardware.
type Sealer interface {
	// Seal seals secret, or returns nil, nil where secrets stay in files.
	Seal(secret []byte) (*Blob, error)
	// Unseal returns what Seal sealed in b.
	Unseal(b *Blob) ([]byte, error)
}
