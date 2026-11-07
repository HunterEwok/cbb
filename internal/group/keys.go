// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/HunterEwok/cbb/internal/keyseal"
	"github.com/HunterEwok/cbb/internal/sekey"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// TPMEnv set to "off" keeps new member and admin keys out of the TPM and
// a Mac's Secure Enclave; a key already in one stays there.
const TPMEnv = "CBB_TPM"

var (
	tpmOnce sync.Once
	tpm     *tpmkey.TPM
	tpmErr  error
	// keyErr is why the last NewDeviceKey left its key in a file though
	// the TPM opened.
	keyErr error
)

// theTPM opens the machine's TPM once; every key of the process uses it.
func theTPM() (*tpmkey.TPM, error) {
	tpmOnce.Do(func() { tpm, tpmErr = tpmkey.Open() })
	return tpm, tpmErr
}

// CloseTPM closes the TPM, flushing what this process loaded into it: a TPM
// without the kernel's resource manager, as a simulator, keeps a process's
// objects after it ends. It opens again when next used.
func CloseTPM() { ReopenTPM() }

// ReopenTPM closes the TPM, which opens again when next used: for the tests
// that start a simulator (tpmtest.Start) after another test used the TPM.
func ReopenTPM() {
	if tpm != nil {
		tpm.Close()
	}
	tpmOnce, tpm, tpmErr = sync.Once{}, nil, nil
}

// NewDeviceKey makes a member or admin key: in the TPM when the machine has
// one that this program may use, in the Secure Enclave on a Mac that has
// one (docs/protocol.md, section 17), and in memory, to be saved in the
// identity file, otherwise.
func NewDeviceKey() (crypto.Signer, error) {
	if k := NewHardwareKey(); k != nil {
		return k, nil
	}
	return NewKey()
}

// NewHardwareKey makes a member or admin key in the TPM or the Secure
// Enclave, as NewDeviceKey does, and returns nil where it would put the key
// in a file.
func NewHardwareKey() crypto.Signer {
	if os.Getenv(TPMEnv) == "off" {
		return nil
	}
	if t, err := theTPM(); err == nil {
		k, err := t.NewKey()
		if err == nil {
			return k
		}
		// A TPM that opens but cannot make keys (full, or refusing the
		// template) leaves the key in a file.
		keyErr = err
	}
	if sekey.Available() {
		if k, err := sekey.New(); err == nil {
			return k
		}
	}
	return nil
}

// HeldKey is how an identity file keeps a device key that hardware holds:
// the TPM's blob or the Secure Enclave's, as its key_tpm and key_se.
type HeldKey struct {
	TPM *tpmkey.Blob `json:"key_tpm,omitempty"`
	SE  []byte       `json:"key_se,omitempty"`
}

// HeldOf returns what keeps k, a key in the TPM or the Secure Enclave, and
// false for a key in a file.
func HeldOf(k crypto.Signer) (HeldKey, bool) {
	s, err := storeKey(k)
	if err != nil || s.der != nil {
		return HeldKey{}, false
	}
	return HeldKey{TPM: s.tpm, SE: s.se}, true
}

// Load loads the key that h keeps.
func (h HeldKey) Load() (crypto.Signer, error) {
	if h.TPM == nil && h.SE == nil {
		return nil, errors.New("group: a key held by hardware without its blob")
	}
	return storedKey{tpm: h.TPM, se: h.SE}.load()
}

// HardwareKeys tells whether NewDeviceKey would put a new key in the TPM
// or the Secure Enclave: the machine has one this program may use, and
// CBB_TPM is not off.
func HardwareKeys() bool {
	if os.Getenv(TPMEnv) == "off" {
		return false
	}
	_, err := theTPM()
	return err == nil || sekey.Available()
}

// WhyNotHardware tells why a key is not in the TPM: TPM support turned
// off, the TPM that did not open, or the error of the last key it did not
// make; "" when nothing failed (a machine without a TPM, or a Mac's Secure
// Enclave, whose errors are not kept).
func WhyNotHardware() string {
	if os.Getenv(TPMEnv) == "off" {
		return TPMEnv + " is off"
	}
	if _, err := theTPM(); err != nil {
		if errors.Is(err, tpmkey.ErrNoTPM) {
			return ""
		}
		return "the TPM: " + err.Error()
	}
	if keyErr != nil {
		return "a key in the TPM: " + keyErr.Error()
	}
	return ""
}

// KeyStoreOf returns where k lives: StoreHardware for a key in the TPM or
// the Secure Enclave, StoreFile otherwise.
func KeyStoreOf(k crypto.Signer) string {
	switch k.(type) {
	case *tpmkey.Key, *sekey.Key:
		return StoreHardware
	}
	return StoreFile
}

// A storedKey is how a file keeps a device key: one of a TPM blob, the
// Secure Enclave's blob, or the key itself in PKCS #8.
type storedKey struct {
	der []byte
	tpm *tpmkey.Blob
	se  []byte
}

// storeKey returns what to keep of k.
func storeKey(k crypto.Signer) (storedKey, error) {
	if b := keyBlob(k); b != nil {
		return storedKey{tpm: b}, nil
	}
	if s, ok := k.(*sekey.Key); ok {
		return storedKey{se: s.Blob()}, nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	return storedKey{der: der}, err
}

// load loads the key that s keeps.
func (s storedKey) load() (crypto.Signer, error) {
	switch {
	case s.tpm != nil:
		return loadTPMKey(s.tpm)
	case s.se != nil:
		k, err := sekey.Load(s.se)
		if errors.Is(err, sekey.ErrNoEnclave) {
			return nil, errors.New("group: this device's key is in a Secure Enclave that is not there; was the identity copied from another machine?")
		}
		if err != nil {
			return nil, fmt.Errorf("group: loading this device's key from the Secure Enclave: %w", err)
		}
		return k, nil
	}
	return parseKey(s.der)
}

// keyBlob returns the TPM blob of k, nil for a key in a file.
func keyBlob(k crypto.Signer) *tpmkey.Blob {
	if t, ok := k.(*tpmkey.Key); ok {
		b := t.Blob()
		return &b
	}
	return nil
}

// loadTPMKey loads a key that the identity file keeps as a TPM blob.
func loadTPMKey(b *tpmkey.Blob) (crypto.Signer, error) {
	t, err := theTPM()
	if errors.Is(err, tpmkey.ErrNoTPM) {
		return nil, errors.New("group: this device's key is in a TPM that is not there; was the identity copied from another machine?")
	}
	if err != nil {
		return nil, fmt.Errorf("group: opening the TPM that holds this device's key: %w", err)
	}
	return t.LoadKey(*b)
}

// Sealer seals secrets, as the WireGuard key, with the TPM or the Secure
// Enclave that would hold new device keys; where new keys go into a file,
// Seal returns nil, nil and the secret stays in its file too.
type Sealer struct{}

// Seal seals secret, or returns nil, nil without hardware to use.
func (Sealer) Seal(secret []byte) (*keyseal.Blob, error) {
	if os.Getenv(TPMEnv) == "off" {
		return nil, nil
	}
	if t, err := theTPM(); err == nil {
		b, err := t.Seal(secret)
		if err != nil {
			return nil, nil // as NewDeviceKey: a TPM that cannot seal leaves the file
		}
		return &keyseal.Blob{TPM: &b}, nil
	}
	if sekey.Available() {
		if b, err := sekey.Seal(secret); err == nil {
			return &keyseal.Blob{SE: b}, nil
		}
	}
	return nil, nil
}

// Unseal returns what Seal sealed in b.
func (Sealer) Unseal(b *keyseal.Blob) ([]byte, error) {
	if b.SE != nil {
		secret, err := sekey.Unseal(b.SE)
		if errors.Is(err, sekey.ErrNoEnclave) {
			return nil, errors.New("the key is sealed by a Secure Enclave that is not there; was the state copied from another machine?")
		}
		if err != nil {
			return nil, fmt.Errorf("opening the key sealed by the Secure Enclave: %w", err)
		}
		return secret, nil
	}
	if b.TPM == nil {
		return nil, errors.New("a sealed key without its blob")
	}
	t, err := theTPM()
	if errors.Is(err, tpmkey.ErrNoTPM) {
		return nil, errors.New("the key is sealed by a TPM that is not there; was the state copied from another machine?")
	}
	if err != nil {
		return nil, fmt.Errorf("opening the TPM that sealed the key: %w", err)
	}
	return t.Unseal(*b.TPM)
}
