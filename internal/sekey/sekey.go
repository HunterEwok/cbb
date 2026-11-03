// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package sekey keeps P-256 signing keys in a Mac's Secure Enclave
// (docs/protocol.md, section 17), as tpmkey does in a TPM: a key is made
// inside the enclave and never leaves it; what a device stores is the key's
// blob, which only that Mac's enclave can load. The service, a LaunchDaemon
// running as root, needs no keychain and no entitlement for it.
package sekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
)

// ErrNoEnclave is returned on a machine without a Secure Enclave this
// program may use: not a Mac, a Mac without one (an Intel Mac before the
// T2 chip), or a build without cgo.
var ErrNoEnclave = errors.New("sekey: no Secure Enclave")

// testEnv set to "1" lets a test binary use the Mac's enclave; without it
// the tests' keys never go into it (as tpmkey keeps them out of the TPM).
const testEnv = "CBB_SE_TEST"

// A Key is a P-256 key in the Secure Enclave. It is a crypto.Signer.
type Key struct {
	blob []byte
	pub  *ecdsa.PublicKey
	ref  ref // the loaded key
}

// Available tells whether New can make keys here.
func Available() bool {
	if testing.Testing() && os.Getenv(testEnv) != "1" {
		return false
	}
	return available()
}

// New makes a key in the enclave.
func New() (*Key, error) {
	if !Available() {
		return nil, ErrNoEnclave
	}
	r, blob, pub, err := create()
	if err != nil {
		return nil, err
	}
	return newKey(r, blob, pub)
}

// Load loads a key from its blob, which only the enclave that made it can
// open.
func Load(blob []byte) (*Key, error) {
	if testing.Testing() && os.Getenv(testEnv) != "1" {
		return nil, ErrNoEnclave
	}
	if !available() {
		return nil, ErrNoEnclave
	}
	r, pub, err := load(blob)
	if err != nil {
		return nil, err
	}
	k, err := newKey(r, append([]byte(nil), blob...), pub)
	if err != nil {
		return nil, err
	}
	// The enclave opens the key's sealed part only when it signs, so a
	// damaged blob loads; one signature tells.
	d := sha256.Sum256([]byte("sekey: the key loads"))
	if _, err := k.Sign(nil, d[:], crypto.SHA256); err != nil {
		k.ref.release()
		return nil, fmt.Errorf("sekey: the key does not open: %w", err)
	}
	return k, nil
}

func newKey(r ref, blob, pub []byte) (*Key, error) {
	p, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil {
		r.release()
		return nil, fmt.Errorf("sekey: the enclave gave a public key that is not on P-256: %w", err)
	}
	return &Key{blob: blob, pub: p, ref: r}, nil
}

// Blob returns what to store of the key.
func (k *Key) Blob() []byte { return append([]byte(nil), k.blob...) }

// Public returns the key's *ecdsa.PublicKey.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Sign signs digest, made with opts' hash, as ecdsa.PrivateKey.Sign does:
// an ASN.1 ECDSA signature.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch opts.HashFunc() {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
	default:
		return nil, fmt.Errorf("sekey: cannot sign a %v digest", opts.HashFunc())
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, errors.New("sekey: the digest has the wrong length")
	}
	sig, err := k.ref.sign(digest)
	if err != nil {
		return nil, err
	}
	// The enclave signs the digest it is given; check the signature before
	// it leaves, as crypto/ecdsa does for its own.
	if !ecdsa.VerifyASN1(k.pub, digest, sig) {
		return nil, errors.New("sekey: the enclave's signature does not verify")
	}
	return sig, nil
}
