// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// Keys are a relay's own keys: the TLS key of the registrations, which
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

// Write writes the keys to path as the PEM file cbb-relay reads with -key.
func (k Keys) Write(path string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(k.Cert.PrivateKey)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.Cert.Certificate[0]})...)
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: wgBlock, Bytes: k.WireGuard[:]})...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, data, 0o600)
}
