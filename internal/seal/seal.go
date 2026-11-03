// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package seal encrypts a message for one device: HPKE (RFC 9180) in base
// mode with X-Wing (ML-KEM-768 and X25519, KEM 0x647a), HKDF-SHA256 and
// ChaCha20-Poly1305, and a fixed info string. Each device keeps a 32-byte
// secret; its public key is 1216 bytes. A sealed message is the 1120-byte
// encapsulated key followed by the ciphertext, which is 16 bytes longer than
// the message. The same is in the Rust core (cbb_core::seal); both are
// checked on testdata/interop/seal-go.json and seal-rust.json.
//
// The keys in the TPM, the Secure Enclave and the Android Keystore only
// sign, so the secret is kept as the service keeps its other secrets.
package seal

import (
	"crypto/hpke"
	"errors"
	"fmt"
)

const (
	// SecretSize is the size of a device's secret.
	SecretSize = 32
	// PublicKeySize is the size of a public key.
	PublicKeySize = 1216
	// EncSize is the size of the encapsulated key at the start of a sealed
	// message.
	EncSize = 1120
	// Overhead is how much longer a sealed message is than the message.
	Overhead = EncSize + 16
)

// Info is HPKE's info for every sealed message.
var Info = []byte("cbb seal v1")

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.ChaCha20Poly1305()
)

// ErrOpen is returned when a sealed message does not open: it was sealed to
// another key, with other associated data, or changed on the way.
var ErrOpen = errors.New("seal: the message does not open with this key")

// GenerateSecret makes a new secret.
func GenerateSecret() ([]byte, error) {
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("seal: make a key: %w", err)
	}
	b, err := k.Bytes()
	if err != nil {
		return nil, fmt.Errorf("seal: make a key: %w", err)
	}
	return b, nil
}

func privateKey(secret []byte) (hpke.PrivateKey, error) {
	if len(secret) != SecretSize {
		return nil, fmt.Errorf("seal: a secret is %d bytes, not %d", SecretSize, len(secret))
	}
	k, err := kem.NewPrivateKey(secret)
	if err != nil {
		return nil, fmt.Errorf("seal: read the secret: %w", err)
	}
	return k, nil
}

// PublicKey gives the public key of a secret.
func PublicKey(secret []byte) ([]byte, error) {
	k, err := privateKey(secret)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// CheckPublicKey reports whether b is a public key that Seal takes.
func CheckPublicKey(b []byte) error {
	if len(b) != PublicKeySize {
		return fmt.Errorf("seal: a public key is %d bytes, not %d", PublicKeySize, len(b))
	}
	if _, err := kem.NewPublicKey(b); err != nil {
		return fmt.Errorf("seal: read the public key: %w", err)
	}
	return nil
}

// Seal encrypts msg for the holder of public, bound to aad, which is not
// encrypted but must be the same when the message is opened.
func Seal(public, aad, msg []byte) ([]byte, error) {
	if err := CheckPublicKey(public); err != nil {
		return nil, err
	}
	pk, err := kem.NewPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("seal: read the public key: %w", err)
	}
	enc, s, err := hpke.NewSender(pk, kdf, aead, Info)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	ct, err := s.Seal(aad, msg)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	out := make([]byte, 0, len(enc)+len(ct))
	return append(append(out, enc...), ct...), nil
}

// Open decrypts a message that Seal sealed to secret's public key with the
// same aad.
func Open(secret, aad, sealed []byte) ([]byte, error) {
	k, err := privateKey(secret)
	if err != nil {
		return nil, err
	}
	if len(sealed) < Overhead {
		return nil, ErrOpen
	}
	r, err := hpke.NewRecipient(sealed[:EncSize], k, kdf, aead, Info)
	if err != nil {
		return nil, ErrOpen
	}
	msg, err := r.Open(aad, sealed[EncSize:])
	if err != nil {
		return nil, ErrOpen
	}
	return msg, nil
}
