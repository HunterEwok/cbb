// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package group holds what Go's parts share about a device of a cbb group:
// its keys in a file, the TPM or the Secure Enclave (keys.go), the names a
// device's role, key store and system take, the key hash that names a
// key, a quick action's name, and the certificate a device registers with
// on a forwarder or a relay. The group's state itself is the Rust core's.
package group

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"time"
)

// Device roles: a member (a computer, a board or a router with the
// service or the firmware), a phone with the app, and a watch with an
// admin key of its own.
const (
	RoleMember = "member"
	RolePhone  = "phone"
	RoleWatch  = "watch"
)

// Where a device's keys live (docs/protocol.md, section 17): in a file,
// which a thief with the device can copy, or in hardware that never lets
// them out (the Secure Enclave, the Android Keystore, a TPM), and proven
// there when the root checked an attestation of the key; rootless for a
// rootless install, whose keys are in a file that every program of its
// user may read (D-79).
const (
	StoreFile     = "file"
	StoreHardware = "hardware"
	StoreProven   = "proven"
	StoreRootless = "rootless"
)

// Operating systems in hellos and device statements: what the device
// runs, shown and never trusted for anything else.
const (
	OSLinux     = "linux"
	OSWindows   = "windows"
	OSMacOS     = "macos"
	OSiOS       = "ios"
	OSAndroid   = "android"
	OSAurora    = "aurora"
	OSSailfish  = "sailfish"
	OSHarmonyOS = "harmonyos"
	OSWatchOS   = "watchos"
	OSWearOS    = "wearos"
	OSNone      = "none" // firmware without an operating system
)

// A KeyHash names a key: SHA-256 over a SubjectPublicKeyInfo.
type KeyHash [sha256.Size]byte

// String returns the key hash in standard base64, as a forwarder's pin
// shows it.
func (h KeyHash) String() string { return base64.StdEncoding.EncodeToString(h[:]) }

// KeyHashOf returns the key hash of a certificate's key.
func KeyHashOf(cert *x509.Certificate) KeyHash { return sha256.Sum256(cert.RawSubjectPublicKeyInfo) }

// A DeviceID identifies a device: 128 random bits as 32 lowercase hex
// characters, which fit in a DNS label.
type DeviceID string

// NewDeviceID returns a new random device ID.
func NewDeviceID() DeviceID {
	var b [16]byte
	rand.Read(b[:]) // never fails
	return DeviceID(hex.EncodeToString(b[:]))
}

// NewKey returns a new P-256 private key.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MaxActionName bounds the name of a quick action.
const MaxActionName = 32

// ValidActionName reports whether name may name a quick action: 1 to
// MaxActionName of a-z, 0-9 and -, starting with a letter. The name is all
// the network carries; the member defines what it does.
func ValidActionName(name string) bool {
	if name == "" || len(name) > MaxActionName || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range []byte(name) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// ServerCertificateName is the subject of the certificate a device
// registers with on a server when it has the group's credentials: it names
// no device and no group.
const ServerCertificateName = "cbb server"

// ServerCertificate returns the certificate a device registers with on a
// forwarder or a relay when it has the group's credentials
// (docs/protocol.md, section 18): one of its server key, signed by that
// key, that names neither a device nor a group.
func ServerCertificate(key crypto.Signer) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: ServerCertificateName},
		NotBefore:    time.Unix(0, 0).UTC(),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
