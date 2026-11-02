// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"testing"
)

func TestProjectPins(t *testing.T) {
	builtIn := ProjectPins(nil)
	if len(builtIn) == 0 {
		t.Fatal("no built-in pin")
	}
	for _, p := range builtIn {
		if err := CheckPin(p); err != nil {
			t.Error(err)
		}
	}
	// keys.json's keys take the built-in ones' place, each as its pin.
	a, _ := NewCert()
	b, _ := NewCert()
	got := ProjectPins([][]byte{a.Leaf.RawSubjectPublicKeyInfo, b.Leaf.RawSubjectPublicKeyInfo})
	if want := []string{Pin(a.Leaf), Pin(b.Leaf)}; !slices.Equal(got, want) {
		t.Errorf("ProjectPins = %v, want %v", got, want)
	}
	// The list returned is the caller's own.
	builtIn[0] = "changed"
	if ProjectPins(nil)[0] == "changed" {
		t.Error("ProjectPins handed out its own list")
	}
}

func TestPinsWhileTheKeyChanges(t *testing.T) {
	a, _ := NewCert()
	b, _ := NewCert()
	c, _ := NewCert()
	cfg := TLSVerifiedByPin(a, Protocol, "forwarder", Pin(a.Leaf), Pin(b.Leaf))
	if err := cfg.VerifyConnection(stateWith(b, Protocol)); err != nil {
		t.Errorf("the second pin: %v", err)
	}
	if err := cfg.VerifyConnection(stateWith(c, Protocol)); err == nil {
		t.Error("a key of neither pin passed")
	}
}

func stateWith(cert tls.Certificate, protocol string) tls.ConnectionState {
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.Leaf}, NegotiatedProtocol: protocol}
}
