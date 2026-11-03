// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// NewCert makes a forwarder's key and its self-signed certificate. Hubs pin
// the key, so the certificate's names and dates mean nothing; it lasts as
// long as the key.
func NewCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "cbb forwarder"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.AddDate(100, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// LoadCert reads the forwarder's key and certificate from path, a PEM file,
// and makes them first if the file does not exist. It is the one file the
// forwarder keeps: nothing about the groups is ever written.
func LoadCert(path string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cert, err := NewCert()
		if err != nil {
			return tls.Certificate{}, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			return tls.Certificate{}, err
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})...)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return tls.Certificate{}, err
		}
		if err := atomicfile.Write(path, data, 0o600); err != nil {
			return tls.Certificate{}, err
		}
		return cert, nil
	}
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

// realityBlock is the PEM type of the forwarder's REALITY key in its key
// file, next to its own key and certificate.
const realityBlock = "CBB REALITY KEY"

// LoadRealityKey reads the forwarder's REALITY key, X25519, for VLESS from
// its key file at path, and adds a new one to the file if it has none.
func LoadRealityKey(path string) ([32]byte, error) {
	var key [32]byte
	data, err := os.ReadFile(path)
	if err != nil {
		return key, err
	}
	for rest := data; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == realityBlock {
			if len(b.Bytes) != len(key) {
				return key, fmt.Errorf("%s: the REALITY key is not %d bytes", path, len(key))
			}
			copy(key[:], b.Bytes)
			return key, nil
		}
	}
	if _, err := rand.Read(key[:]); err != nil {
		return key, err
	}
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: realityBlock, Bytes: key[:]})...)
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return key, err
	}
	return key, nil
}

// xhttpBlock is the PEM type of the path the web server passes to the
// forwarder's XHTTP, in its key file.
const xhttpBlock = "CBB XHTTP PATH"

// LoadXHTTPPath reads the path of the forwarder's XHTTP from its key file
// at path, and adds a new random one to the file if it has none. The path
// keeps scanners off the listener; it is not a secret the design relies
// on.
func LoadXHTTPPath(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for rest := data; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == xhttpBlock {
			p := string(b.Bytes)
			if err := tunnel.CheckVLESSPath(p); err != nil {
				return "", fmt.Errorf("%s: %w", path, err)
			}
			return p, nil
		}
	}
	p, err := tunnel.NewVLESSPath()
	if err != nil {
		return "", err
	}
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: xhttpBlock, Bytes: []byte(p)})...)
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return "", err
	}
	return p, nil
}
