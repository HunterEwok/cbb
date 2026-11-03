// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// Keys are the relay's own keys: the TLS key of the registrations, which
// members pin, and the WireGuard key of the tunnels, which the registration
// gives them.
type Keys struct {
	Cert      tls.Certificate
	WireGuard tunnel.Key
}

// Pin returns the pin of the relay's key, which members are given with its
// address.
func (k Keys) Pin() string { return forward.Pin(k.Cert.Leaf) }

// NewKeys makes the relay's keys.
func NewKeys() (Keys, error) {
	cert, err := forward.NewCert()
	if err != nil {
		return Keys{}, err
	}
	wg, err := tunnel.NewPrivateKey()
	if err != nil {
		return Keys{}, err
	}
	return Keys{Cert: cert, WireGuard: wg}, nil
}

// wgBlock is the PEM type of the WireGuard key in the relay's key file. It
// does not end in "PRIVATE KEY", so the TLS key's parser never takes it.
const wgBlock = "CBB WIREGUARD KEY"

// LoadKeys reads the relay's keys from path, a PEM file, and makes them
// first if the file does not exist. It is the one file the relay keeps:
// nothing about the groups is ever written.
func LoadKeys(path string) (Keys, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := NewKeys()
		if err != nil {
			return Keys{}, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(k.Cert.PrivateKey)
		if err != nil {
			return Keys{}, err
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.Cert.Certificate[0]})...)
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: wgBlock, Bytes: k.WireGuard[:]})...)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return Keys{}, err
		}
		if err := atomicfile.Write(path, data, 0o600); err != nil {
			return Keys{}, err
		}
		return k, nil
	}
	if err != nil {
		return Keys{}, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return Keys{}, fmt.Errorf("%s: %w", path, err)
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return Keys{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	k := Keys{Cert: cert}
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == wgBlock && len(b.Bytes) == len(k.WireGuard) {
			copy(k.WireGuard[:], b.Bytes)
		}
	}
	if k.WireGuard.IsZero() {
		return Keys{}, fmt.Errorf("%s: no WireGuard key", path)
	}
	return k, nil
}
