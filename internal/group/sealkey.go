// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/keyseal"
	"github.com/HunterEwok/clipboardbridge/internal/seal"
	"github.com/HunterEwok/clipboardbridge/internal/tpmkey"
)

// SealKeyFileName is the file next to the identity that keeps the device's
// secret for sealed messages (internal/seal).
const SealKeyFileName = "seal.json"

// sealKeyFile is SealKeyFileName: the secret sealed by the TPM or the
// Secure Enclave where the device has one, as the WireGuard key, and in the
// file otherwise.
type sealKeyFile struct {
	V      int             `json:"v"`
	Secret []byte          `json:"secret,omitempty"`
	TPM    *tpmkey.Blob    `json:"tpm,omitempty"`
	SE     json.RawMessage `json:"se,omitempty"`
}

// LoadSealSecret returns the device's secret for sealed messages, kept in
// dir; the first call makes it. Its public key goes into the device's
// record (docs/records-v2.md, the field seal), so that a command for this
// device can be sealed to it (docs/protocol.md, section 15).
func LoadSealSecret(dir string) ([]byte, error) {
	path := filepath.Join(dir, SealKeyFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newSealSecret(path)
	}
	if err != nil {
		return nil, err
	}
	var f sealKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", SealKeyFileName, err)
	}
	if f.V != 1 {
		return nil, fmt.Errorf("%s: unknown version %d", SealKeyFileName, f.V)
	}
	secret := f.Secret
	if f.TPM != nil || f.SE != nil {
		if secret, err = (Sealer{}).Unseal(&keyseal.Blob{TPM: f.TPM, SE: f.SE}); err != nil {
			return nil, fmt.Errorf("%s: %w", SealKeyFileName, err)
		}
	}
	if _, err := seal.PublicKey(secret); err != nil {
		return nil, fmt.Errorf("%s: %w", SealKeyFileName, err)
	}
	return secret, nil
}

func newSealSecret(path string) ([]byte, error) {
	secret, err := seal.GenerateSecret()
	if err != nil {
		return nil, err
	}
	f := sealKeyFile{V: 1}
	b, err := (Sealer{}).Seal(secret)
	if err != nil {
		return nil, err
	}
	if b != nil {
		f.TPM, f.SE = b.TPM, b.SE
	} else {
		f.Secret = secret
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicfile.Write(path, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return secret, nil
}
