// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

var randReader = rand.Reader

// tool is a key held by a hardware key that a program reaches: it prints
// the public key (a PUBLIC KEY or a CERTIFICATE in PEM) and signs the data
// on its standard input, writing an ECDSA signature with SHA-256 in DER.
type tool struct {
	pub     *ecdsa.PublicKey
	signCmd []string
	// data is the body to sign: the programs hash it themselves.
	data []byte
}

func newTool(publicCmd, signCmd []string) (*tool, error) {
	out, err := run(publicCmd, nil)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(out)
	if b == nil {
		return nil, fmt.Errorf("%s printed no PEM key", publicCmd[0])
	}
	var pub any
	switch b.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(b.Bytes)
	case "CERTIFICATE":
		var c *x509.Certificate
		if c, err = x509.ParseCertificate(b.Bytes); err == nil {
			pub = c.PublicKey
		}
	default:
		err = fmt.Errorf("%s printed a %s, not a key", publicCmd[0], b.Type)
	}
	if err != nil {
		return nil, err
	}
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, errors.New("the hardware key is not P-256")
	}
	return &tool{pub: k, signCmd: signCmd}, nil
}

func run(cmd []string, stdin []byte) ([]byte, error) {
	c := exec.Command(cmd[0], cmd[1:]...)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	// The PIN prompt and Touch ID's messages go to the terminal.
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cmd[0], err)
	}
	return out, nil
}

func (t *tool) Public() crypto.PublicKey { return t.pub }

// Sign signs digest, the SHA-256 of data, which the caller sets first,
// since the programs hash what they sign.
func (t *tool) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if sum := sha256.Sum256(t.data); !bytes.Equal(sum[:], digest) {
		return nil, errors.New("the hardware key signs only the body it was given")
	}
	sig, err := run(t.signCmd, t.data)
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(t.pub, digest, sig) {
		return nil, errors.New("the hardware key's signature does not verify")
	}
	return sig, nil
}
