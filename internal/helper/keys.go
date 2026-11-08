// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/keyseal"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// The operations on keys that hardware holds (docs/design.md, "The service
// and its helper"). Their requests and answers are JSON in the payload.
const (
	// OpKeyNew makes a device key in the TPM or the Secure Enclave; the
	// answer is a Key, with no blob where the key would go into a file.
	OpKeyNew = "key-new"
	// OpKeyPublic loads the key a HeldKey keeps; the answer is a Key.
	OpKeyPublic = "key-public"
	// OpKeySign signs a SHA-256 digest with the key a Sign names; the
	// answer's payload is the ECDSA signature, DER.
	OpKeySign = "key-sign"
	// OpSeal seals a secret with the TPM or the Secure Enclave
	// (group.Sealer); the request and the answer are a Sealed, the
	// answer with no blob where secrets stay in files.
	OpSeal = "seal"
	// OpUnseal opens what seal sealed; the request and the answer are a
	// Sealed.
	OpUnseal = "unseal"
)

// Sealed is a secret and the blob the hardware sealed it in, as the state
// files keep it: key_tpm or key_se.
type Sealed struct {
	Secret []byte          `json:"secret,omitempty"`
	TPM    *tpmkey.Blob    `json:"tpm,omitempty"`
	SE     json.RawMessage `json:"se,omitempty"`
}

// Key is a device key that hardware holds: where the identity file keeps it,
// and its public key, SEC1 uncompressed. Why says, when key-new made no key
// in hardware, what failed, if anything did.
type Key struct {
	group.HeldKey
	Public []byte `json:"public,omitempty"`
	Why    string `json:"why,omitempty"`
}

// Sign asks for a signature with a held key.
type Sign struct {
	group.HeldKey
	Digest []byte `json:"digest"`
}

// keys serves the key operations; it keeps each key it loaded.
type keys struct {
	mu     sync.Mutex
	loaded map[string]crypto.Signer
}

// HandleKeys serves the key operations on s. A YubiKey cbb reads itself
// (member/src/piv.rs).
func (s *Server) HandleKeys() {
	k := &keys{loaded: map[string]crypto.Signer{}}
	s.Handle(OpKeyNew, k.new)
	s.Handle(OpKeyPublic, k.public)
	s.Handle(OpKeySign, k.sign)
	s.Handle(OpSeal, seal)
	s.Handle(OpUnseal, unseal)
}

func seal(req *control.Message) (*control.Message, error) {
	var r Sealed
	if err := json.Unmarshal(req.Payload, &r); err != nil || len(r.Secret) == 0 {
		return nil, errors.New("a sealing request that is not understood")
	}
	b, err := group.Sealer{}.Seal(r.Secret)
	if err != nil || b == nil {
		return answer(Sealed{})
	}
	return answer(Sealed{TPM: b.TPM, SE: b.SE})
}

func unseal(req *control.Message) (*control.Message, error) {
	var r Sealed
	if err := json.Unmarshal(req.Payload, &r); err != nil || r.TPM == nil && r.SE == nil {
		return nil, errors.New("an unsealing request that is not understood")
	}
	secret, err := group.Sealer{}.Unseal(&keyseal.Blob{TPM: r.TPM, SE: r.SE})
	if err != nil {
		return nil, err
	}
	return answer(Sealed{Secret: secret})
}

func answer(v any) (*control.Message, error) {
	p, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &control.Message{Payload: p}, nil
}

func (k *keys) new(*control.Message) (*control.Message, error) {
	key := group.NewHardwareKey()
	if key == nil {
		return answer(Key{Why: group.WhyNotHardware()})
	}
	held, _ := group.HeldOf(key)
	pub, err := public(key)
	if err != nil {
		return nil, err
	}
	k.keep(held, key)
	return answer(Key{HeldKey: held, Public: pub})
}

func (k *keys) public(req *control.Message) (*control.Message, error) {
	var held group.HeldKey
	if err := json.Unmarshal(req.Payload, &held); err != nil {
		return nil, fmt.Errorf("a key request that is not understood: %w", err)
	}
	key, err := k.load(held)
	if err != nil {
		return nil, err
	}
	pub, err := public(key)
	if err != nil {
		return nil, err
	}
	return answer(Key{HeldKey: held, Public: pub})
}

func (k *keys) sign(req *control.Message) (*control.Message, error) {
	var r Sign
	if err := json.Unmarshal(req.Payload, &r); err != nil {
		return nil, fmt.Errorf("a signing request that is not understood: %w", err)
	}
	if len(r.Digest) != sha256.Size {
		return nil, errors.New("a signing request without a SHA-256 digest")
	}
	key, err := k.load(r.HeldKey)
	if err != nil {
		return nil, err
	}
	sig, err := key.Sign(rand.Reader, r.Digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing with this device's key: %w", err)
	}
	return &control.Message{Payload: sig}, nil
}

// load returns the key held loads, loading it once.
func (k *keys) load(held group.HeldKey) (crypto.Signer, error) {
	id, err := json.Marshal(held)
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.loaded[string(id)]; ok {
		return key, nil
	}
	key, err := held.Load()
	if err != nil {
		return nil, err
	}
	k.loaded[string(id)] = key
	return key, nil
}

func (k *keys) keep(held group.HeldKey, key crypto.Signer) {
	id, err := json.Marshal(held)
	if err != nil {
		return
	}
	k.mu.Lock()
	k.loaded[string(id)] = key
	k.mu.Unlock()
}

// public returns k's public key, SEC1 uncompressed.
func public(k crypto.Signer) ([]byte, error) {
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("the device key is not an ECDSA key")
	}
	e, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	if e.Curve() != ecdh.P256() {
		return nil, errors.New("the device key is not a P-256 key")
	}
	return e.Bytes(), nil
}
