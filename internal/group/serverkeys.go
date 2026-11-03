// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// ServerKeysFileName is the file next to the identity that keeps the
// device's keys for the servers.
const ServerKeysFileName = "server-keys.json"

// The kinds of keys ServerKeys keeps for a period.
const (
	ServerKey = "server" // the device's key for the servers in the period
	PeriodKey = "period" // the period key, on the root that started the period
)

// ServerKeys keeps a device's keys for the servers (docs/protocol.md,
// section 18): its server key for each period, and on the root the period
// key, each in the TPM where there is one, as the member key. A device
// keeps the keys of the current period only, so a key it used with the
// servers is gone once the period is over. It is safe for concurrent use.
type ServerKeys struct {
	file string
	mu   sync.Mutex
	keys map[string]crypto.Signer // by kind and period tag
}

type savedServerKey struct {
	Key []byte       `json:"key,omitempty"` // PKCS #8
	TPM *tpmkey.Blob `json:"tpm,omitempty"`
	SE  []byte       `json:"se,omitempty"` // the Secure Enclave's blob
}

// NewServerKeys returns an empty set that saves to dir/server-keys.json.
func NewServerKeys(dir string) *ServerKeys {
	return &ServerKeys{file: filepath.Join(dir, ServerKeysFileName), keys: map[string]crypto.Signer{}}
}

// LoadServerKeys reads dir/server-keys.json; a missing file keeps no keys.
func LoadServerKeys(dir string) (*ServerKeys, error) {
	k := NewServerKeys(dir)
	data, err := os.ReadFile(k.file)
	if errors.Is(err, fs.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	var saved map[string]savedServerKey
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("%s: %w", k.file, err)
	}
	for name, s := range saved {
		key, err := (storedKey{s.Key, s.TPM, s.SE}).load()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k.file, err)
		}
		k.keys[name] = key
	}
	return k, nil
}

// Get returns the key of kind for the period of tag, and makes and saves
// one if there is none.
func (k *ServerKeys) Get(kind, tag string) (crypto.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	name := kind + " " + tag
	if key, ok := k.keys[name]; ok {
		return key, nil
	}
	key, err := NewDeviceKey()
	if err != nil {
		return nil, err
	}
	k.keys[name] = key
	if err := k.saveLocked(); err != nil {
		delete(k.keys, name)
		return nil, err
	}
	return key, nil
}

// Has reports whether it keeps a key of kind for the period of tag.
func (k *ServerKeys) Has(kind, tag string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.keys[kind+" "+tag]
	return ok
}

// Keep drops the keys of every period but tag's.
func (k *ServerKeys) Keep(tag string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := len(k.keys)
	for name := range k.keys {
		if name != ServerKey+" "+tag && name != PeriodKey+" "+tag {
			delete(k.keys, name)
		}
	}
	if len(k.keys) == n {
		return nil
	}
	return k.saveLocked()
}

func (k *ServerKeys) saveLocked() error {
	saved := map[string]savedServerKey{}
	for _, name := range slices.Sorted(maps.Keys(k.keys)) {
		s, err := storeKey(k.keys[name])
		if err != nil {
			return err
		}
		saved[name] = savedServerKey{Key: s.der, TPM: s.tpm, SE: s.se}
	}
	data, err := json.MarshalIndent(saved, "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(k.file, append(data, '\n'), 0o600)
}

// PublicKeyHash returns the hash of a public key, as KeyHashOf a
// certificate of it: SHA-256 over its SubjectPublicKeyInfo.
func PublicKeyHash(pub crypto.PublicKey) KeyHash {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return KeyHash{}
	}
	return sha256.Sum256(spki)
}
