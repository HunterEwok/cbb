// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package group holds the certificates and keys of a cbb group: the
// group CA, which certifies the members, and this device's own identity.
//
// Every certificate uses ECDSA P-256.
package group

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/benchtime"
)

// Lifetimes of the certificates, and how long before its end a certificate
// is renewed; the bench's time-scaled build runs them faster.
const (
	caYears     = 20
	memberYears = 2
)

var (
	memberRenewBefore = benchtime.D(240 * 24 * time.Hour)
	backdate          = benchtime.D(24 * time.Hour) // for a device whose clock is a little behind
)

const (
	groupCAName = "cbb group CA"
	rootCAName  = "cbb group root"
)

// A DeviceID identifies a device: 128 random bits as 32 lowercase hex
// characters, which fit in a DNS label.
type DeviceID string

// NewDeviceID returns a new random device ID.
func NewDeviceID() DeviceID {
	var b [16]byte
	rand.Read(b[:]) // never fails
	return DeviceID(hex.EncodeToString(b[:]))
}

// ParseDeviceID checks that s is a device ID.
func ParseDeviceID(s string) (DeviceID, error) {
	if len(s) != 32 || strings.Trim(s, "0123456789abcdef") != "" {
		return "", fmt.Errorf("group: %q is not a device ID", s)
	}
	return DeviceID(s), nil
}

// HostName returns the device's own mDNS host name, cb-<device ID>.local.
// It is also the DNS name in the device's member certificate.
func (id DeviceID) HostName() string { return "cb-" + string(id) + ".local" }

// NewKey returns a new P-256 private key.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKey returns k's P-256 public key, or nil when k is nil or not a
// P-256 key.
func PublicKey(k crypto.Signer) *ecdsa.PublicKey {
	if k == nil {
		return nil
	}
	p, ok := k.Public().(*ecdsa.PublicKey)
	if !ok || p.Curve != elliptic.P256() {
		return nil
	}
	return p
}

// SameKey reports whether k is the private key of pub.
func SameKey(k crypto.Signer, pub crypto.PublicKey) bool {
	p := PublicKey(k)
	return p != nil && p.Equal(pub)
}

// A CA is a certificate authority of the group: its certificate and, on
// members that hold it, its private key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer // a P-256 key; nil when this device does not hold the key
}

// NewGroupCA creates a CA with path length 0, which certifies members
// only, as group CAs were before 0.4: an identity with one is refused
// (ErrOldGroup). New groups have a root CA (NewRootCA).
func NewGroupCA(now time.Time) (*CA, error) {
	return newCA(&x509.Certificate{
		Subject: pkix.Name{CommonName: groupCAName + " " + now.UTC().Format(time.DateOnly)},
	}, now)
}

// NewRootCA creates the root CA of a new group: path length 1, so it
// certifies the admins' admin CAs as well as members, as the root a phone
// creates does (docs/protocol.md, section 9).
func NewRootCA(now time.Time) (*CA, error) {
	return newCA(&x509.Certificate{
		Subject:    pkix.Name{CommonName: rootCAName + " " + now.UTC().Format(time.DateOnly)},
		MaxPathLen: 1,
	}, now)
}

func newCA(tmpl *x509.Certificate, now time.Time) (*CA, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	tmpl.NotBefore = now.Add(-backdate)
	tmpl.NotAfter = benchtime.Years(now, caYears)
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.MaxPathLenZero = tmpl.MaxPathLen == 0
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert, err := create(tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// IssueMember certifies a member's public key for the device id. The
// certificate is valid for two years, and its NotBefore is the CA's, so a
// device whose clock is behind still accepts it.
func (ca *CA) IssueMember(id DeviceID, pub *ecdsa.PublicKey, now time.Time) (*x509.Certificate, error) {
	if _, err := ParseDeviceID(string(id)); err != nil {
		return nil, err
	}
	return ca.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: string(id)},
		DNSNames:    []string{id.HostName()},
		NotBefore:   ca.Cert.NotBefore,
		NotAfter:    benchtime.Years(now, memberYears),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, pub, now)
}

// IssueAdmin certifies the admin key pub of the device dev as its admin CA,
// as the root does when it makes a member an admin: path length 0 and the
// root's lifetime (docs/protocol.md, section 10). Only a root issues one.
func (ca *CA) IssueAdmin(dev DeviceID, pub *ecdsa.PublicKey, now time.Time) (*x509.Certificate, error) {
	if _, err := ParseDeviceID(string(dev)); err != nil {
		return nil, err
	}
	if ca.Cert.MaxPathLen != 1 {
		return nil, errors.New("group: only a root with path length 1 issues admin CAs")
	}
	switch {
	case ca.Key == nil:
		return nil, errors.New("group: this device does not hold the root key")
	case pub == nil || pub.Curve != elliptic.P256():
		return nil, errors.New("group: the admin key is not a P-256 key")
	case now.Before(ca.Cert.NotBefore) || !now.Before(ca.Cert.NotAfter):
		return nil, fmt.Errorf("group: the clock (%v) is outside the lifetime of %q; check the date", now.UTC(), ca.Cert.Subject.CommonName)
	}
	return create(&x509.Certificate{
		Subject:               pkix.Name{CommonName: AdminName(dev)},
		NotBefore:             ca.Cert.NotBefore,
		NotAfter:              ca.Cert.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, ca.Cert, pub, ca.Key)
}

// issue signs tmpl. A clock outside the CA's lifetime is an error: the
// certificate would be useless, and the date is most likely wrong.
func (ca *CA) issue(tmpl *x509.Certificate, pub *ecdsa.PublicKey, now time.Time) (*x509.Certificate, error) {
	if ca.Key == nil {
		return nil, errors.New("group: this device does not hold the CA key")
	}
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("group: the key to certify is not a P-256 key")
	}
	if now.Before(ca.Cert.NotBefore) || !now.Before(ca.Cert.NotAfter) {
		return nil, fmt.Errorf("group: the clock (%v) is outside the lifetime of %q; check the date", now.UTC(), ca.Cert.Subject.CommonName)
	}
	tmpl.NotAfter = minTime(tmpl.NotAfter, ca.Cert.NotAfter)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.BasicConstraintsValid = true
	return create(tmpl, ca.Cert, pub, ca.Key)
}

// create signs a certificate; a nil serial number makes x509 pick a random
// one.
func create(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("group: %w", err)
	}
	return x509.ParseCertificate(der)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Tag returns a short identifier of the group CA, 16 hex characters, which
// members publish so that the members of another group ignore them. A new
// group CA has a new tag.
func Tag(groupCA *x509.Certificate) string {
	sum := sha256.Sum256(groupCA.Raw)
	return hex.EncodeToString(sum[:8])
}

// DeviceOf returns the device ID that a member certificate names.
func DeviceOf(cert *x509.Certificate) (DeviceID, error) {
	id, err := ParseDeviceID(cert.Subject.CommonName)
	if err != nil {
		return "", err
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != id.HostName() {
		return "", fmt.Errorf("group: the certificate of %s does not name %s", id, id.HostName())
	}
	return id, nil
}

// verifyTime returns the time at which to check certificates issued by ca:
// now, but never before the CA's NotBefore. Member certificates start when
// their CA starts, so a device whose clock is behind, such as a Raspberry Pi
// without a real-time clock before it synchronizes, still accepts them.
// Expired certificates are rejected.
func verifyTime(ca *x509.Certificate, now time.Time) time.Time {
	return maxTime(now, ca.NotBefore)
}

// checkRoot checks that c may be a root of a group: a CA as the group CA
// is, that certifies admin CAs (path length 1).
func checkRoot(c *x509.Certificate) error {
	if err := checkCA(&CA{Cert: c}, "new root", maxGroupCAPath); err != nil {
		return err
	}
	if c.MaxPathLen != 1 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("group: the new root does not certify admin CAs")
	}
	return nil
}

// CheckAdminCA checks that c is an admin CA certified by root.
func CheckAdminCA(c, root *x509.Certificate) error { return checkAdminCA(c, root) }

// checkAdminCA checks that c is an admin CA certified by root: a CA with
// path length 0 and a P-256 key, signed by root, which allows one level of
// CAs below it.
func checkAdminCA(c, root *x509.Certificate) error {
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("group: the signer is not an admin CA")
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return errors.New("group: the admin CA key is not a P-256 key")
	}
	if root.MaxPathLen < 1 {
		return errors.New("group: the group CA certifies no admin CAs")
	}
	if err := c.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("group: the admin CA is not from the group CA: %w", err)
	}
	return nil
}
