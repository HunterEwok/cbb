// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
)

// TestServerCertificate checks the certificate a device registers with on
// a server: its server key only, with no device and no group.
func TestServerCertificate(t *testing.T) {
	key, _ := NewKey()
	c, err := ServerCertificate(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Leaf.DNSNames) != 0 || c.Leaf.Subject.CommonName != ServerCertificateName {
		t.Errorf("the server certificate names %v %v", c.Leaf.Subject, c.Leaf.DNSNames)
	}
	if len(c.Certificate) != 1 {
		t.Error("a chain follows")
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if !bytes.Equal(c.Leaf.RawSubjectPublicKeyInfo, spki) {
		t.Error("another key")
	}
	h := KeyHashOf(c.Leaf)
	if s := h.String(); len(s) != 44 || !strings.HasSuffix(s, "=") {
		t.Errorf("a key hash in base64 is %q", s)
	}
}

// TestNames checks a quick action's name and a new device ID.
func TestNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"lock": true, "a": true, "turn-off-2": true, strings.Repeat("a", MaxActionName): true,
		"": false, "2fa": false, "-x": false, "Lock": false, "a_b": false, "a b": false, strings.Repeat("a", MaxActionName+1): false,
	} {
		if ValidActionName(name) != ok {
			t.Errorf("ValidActionName(%q) = %v", name, !ok)
		}
	}
	a, b := NewDeviceID(), NewDeviceID()
	if a == b || len(a) != 32 || strings.Trim(string(a), "0123456789abcdef") != "" {
		t.Errorf("device IDs %q, %q", a, b)
	}
}
