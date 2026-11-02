// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package sekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// sealed is what Seal returns, as JSON (docs/protocol.md, section 17).
type sealed struct {
	V   int    `json:"v"`
	Key []byte `json:"key"` // the enclave's key, as Key.Blob
	Eph []byte `json:"eph"` // the ephemeral public key, uncompressed
	Box []byte `json:"box"` // AES-256-GCM: the nonce, then the sealed secret
}

const sealInfo = "cbb sekey seal v1"

// Seal seals secret to a new key in the enclave, which the enclave never
// gives out: an ephemeral P-256 key agrees on a secret with it (ECDH), and
// HKDF-SHA256 of that secret keys AES-256-GCM. Only this Mac's enclave
// opens what it returns.
func Seal(secret []byte) ([]byte, error) {
	k, err := New()
	if err != nil {
		return nil, err
	}
	defer k.ref.release()
	pub, err := k.pub.ECDH()
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	aead, err := sealAEAD(shared, eph.PublicKey().Bytes(), pub.Bytes())
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	box := aead.Seal(nonce, nonce, secret, []byte(sealInfo))
	return json.Marshal(sealed{V: 1, Key: k.blob, Eph: eph.PublicKey().Bytes(), Box: box})
}

// Unseal opens what Seal returned.
func Unseal(b []byte) ([]byte, error) {
	var s sealed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("sekey: the sealed secret: %w", err)
	}
	if s.V != 1 {
		return nil, fmt.Errorf("sekey: a sealed secret of unknown version %d", s.V)
	}
	eph, err := ecdh.P256().NewPublicKey(s.Eph)
	if err != nil {
		return nil, fmt.Errorf("sekey: the sealed secret's ephemeral key: %w", err)
	}
	k, err := Load(s.Key)
	if err != nil {
		return nil, err
	}
	defer k.ref.release()
	pub, err := k.pub.ECDH()
	if err != nil {
		return nil, err
	}
	shared, err := k.ref.agree(eph.Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := sealAEAD(shared, s.Eph, pub.Bytes())
	if err != nil {
		return nil, err
	}
	if len(s.Box) < aead.NonceSize() {
		return nil, errors.New("sekey: the sealed secret is too short")
	}
	secret, err := aead.Open(nil, s.Box[:aead.NonceSize()], s.Box[aead.NonceSize():], []byte(sealInfo))
	if err != nil {
		return nil, errors.New("sekey: the sealed secret does not open")
	}
	return secret, nil
}

// sealAEAD derives the AES-256-GCM key from the shared secret and both
// public keys.
func sealAEAD(shared, eph, pub []byte) (cipher.AEAD, error) {
	if len(shared) != 32 {
		return nil, errors.New("sekey: the agreed secret has the wrong length")
	}
	key, err := hkdf.Key(sha256.New, shared, append(append([]byte(nil), eph...), pub...), sealInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
