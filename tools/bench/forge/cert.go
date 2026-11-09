// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

// The renewals (K3): forge -target-state DIR ... cert:KIND[:SIGNER] sends
// the target a member certificate that signer's CA (-signer by default)
// issued, of a kind it must refuse but the last: other-device (for
// another device, with the target's key), other-key (for the target, with
// another key), earlier (ending before the target's current one),
// server-only (not for client authentication), and valid (a renewal it
// takes). It prints "cert KIND: sent".

// targetState is the state directory of the target, for its key.
var targetState string

func sendCert(n *memberConn, kind string, signer *group.Identity) error {
	if targetState == "" {
		return errors.New("cert takes -target-state")
	}
	t, err := group.Load(targetState)
	if err != nil {
		return err
	}
	ca, _ := signer.Signer()
	if ca == nil {
		return errors.New("the signer holds no CA key")
	}
	pub, ok := t.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("the target's certificate has no ECDSA key")
	}
	id, now := t.ID, time.Now()
	switch kind {
	case "other-device":
		id = group.NewDeviceID()
	case "other-key":
		k, err := group.NewKey()
		if err != nil {
			return err
		}
		pub = &k.PublicKey
	case "earlier":
		// Within the CA's lifetime, a day before the target joined.
		now = ca.Cert.NotBefore.Add(time.Hour)
	case "server-only", "valid":
	default:
		return fmt.Errorf("no cert case %q", kind)
	}
	cert, err := ca.IssueMember(id, pub, now)
	if err != nil {
		return err
	}
	if kind == "server-only" {
		tmpl := *cert
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.Cert, pub, ca.Key)
		if err != nil {
			return err
		}
		if cert, err = x509.ParseCertificate(der); err != nil {
			return err
		}
	}
	if err := n.cert(cert, signer.AdminCA); err != nil {
		return fmt.Errorf("the target is not connected: %v", err)
	}
	fmt.Printf("cert %s: sent\n", kind)
	// It leaves before the next one, and before the connection closes.
	time.Sleep(2 * time.Second)
	return nil
}
