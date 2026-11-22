// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

// A relay between two TLS sessions (G8, docs/protocol.md section 6): forge
// -state DIR -addr :PORT relay:HOST:PORT takes one pairing connection from
// a joiner on PORT, with the member certificate in DIR (an insider of the
// group), dials the pairing window at HOST:PORT with a certificate of its
// own, and passes every frame between the two, unread. CPace binds each
// side to its own TLS session, so the two cannot agree; it prints
//
//	relay: N bytes to the window, M bytes to the joiner

func relayCase(arg string) bool { return strings.HasPrefix(arg, "relay:") }

func runRelay(state, listen, arg string) error {
	target := strings.TrimPrefix(arg, "relay:")
	id, err := group.Load(state)
	if err != nil {
		return err
	}
	// The window takes any P-256 certificate whose CN is a device ID.
	key, err := group.NewDeviceKey()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: string(group.NewDeviceID())},
		NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, group.PublicKey(key), key)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("relay: listening")
	raw, err := ln.Accept()
	if err != nil {
		return err
	}
	joiner := tls.Server(raw, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{id.Cert.Raw}, PrivateKey: id.Key, Leaf: id.Cert}},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{pairProtocol},
	})
	defer joiner.Close()
	if err := joiner.Handshake(); err != nil {
		return fmt.Errorf("the joiner's handshake: %w", err)
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return err
	}
	window := tls.Client(up, insecureRelayConfig(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}))
	defer window.Close()
	if err := window.Handshake(); err != nil {
		return fmt.Errorf("the window's handshake: %w", err)
	}
	deadline := time.Now().Add(time.Minute)
	joiner.SetDeadline(deadline)
	window.SetDeadline(deadline)
	var wg sync.WaitGroup
	var toWindow, toJoiner int64
	pass := func(dst, src *tls.Conn, n *int64) {
		defer wg.Done()
		*n, _ = io.Copy(dst, src)
		// One side ending ends the other.
		dst.Close()
		src.Close()
	}
	wg.Add(2)
	go pass(window, joiner, &toWindow)
	go pass(joiner, window, &toJoiner)
	wg.Wait()
	fmt.Printf("relay: %d bytes to the window, %d bytes to the joiner\n", toWindow, toJoiner)
	return nil
}

// insecureRelayConfig is the relay's side towards the window: it trusts
// any certificate, since it only passes frames it never reads. The bench's
// forge only, never part of a release.
func insecureRelayConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{pairProtocol},
	}
}

// pairProtocol is the pairing's ALPN (docs/protocol.md, section 6).
const pairProtocol = "cbb-pair/3"
