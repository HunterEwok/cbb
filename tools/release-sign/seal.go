// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// The post-quantum half of a key in hardware is sealed twice: first with
// the owner's passphrase (scrypt, XChaCha20-Poly1305), then with age to
// the hardware. The hardware's wrap is P-256, which the adversary the
// second signature is for breaks; the passphrase's is symmetric. So a
// copied HASH.age opens neither with the hardware alone nor, to that
// adversary, without the passphrase (docs/maintaining.md, "Two
// signatures"). One passphrase serves every hardware half; release-sign
// asks for it once a run and keeps it in memory only.
//
// A sealed half is the line
//
//	cbb-pq-sealed v1 scrypt LOGN R P
//
// then 16 bytes of salt, 24 of nonce, and the half's PEM sealed with the
// key scrypt gives, the line and the key's name as additional data. The
// cost is in the line, so a later run may raise it without a new format.

const sealMagic = "cbb-pq-sealed v1"

// sealLogN, sealR and sealP are scrypt's cost for a new seal: 2^18 with
// r 8 is 256 MiB and about a second on the Mac. A variable for the tests.
var (
	sealLogN = 18
	sealR    = 8
	sealP    = 1
)

// errPassphrase is a passphrase that does not open the half.
var errPassphrase = errors.New("the passphrase is wrong: nothing was signed")

func sealed(data []byte) bool { return bytes.HasPrefix(data, []byte(sealMagic+" ")) }

// seal seals secret under passphrase for the key named name.
func seal(passphrase, secret []byte, name string) ([]byte, error) {
	head := fmt.Sprintf("%s scrypt %d %d %d\n", sealMagic, sealLogN, sealR, sealP)
	salt := make([]byte, 16)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase, salt, 1<<sealLogN, sealR, sealP, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(head), salt...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, secret, []byte(head+name)), nil
}

// unseal opens what seal made; a wrong passphrase is errPassphrase.
func unseal(passphrase, data []byte, name string) ([]byte, error) {
	i := bytes.IndexByte(data, '\n')
	if !sealed(data) || i < 0 {
		return nil, errors.New("the half is not sealed with a passphrase")
	}
	head := string(data[:i+1])
	f := strings.Fields(strings.TrimPrefix(strings.TrimSuffix(head, "\n"), sealMagic))
	if len(f) != 4 || f[0] != "scrypt" {
		return nil, errors.New("the half's seal is of an unknown kind")
	}
	var n [3]int
	for j := range n {
		v, err := strconv.Atoi(f[j+1])
		if err != nil {
			return nil, errors.New("the half's seal has no valid cost")
		}
		n[j] = v
	}
	// Bounds that keep a damaged line from asking for more than a few GiB.
	if n[0] < 10 || n[0] > 24 || n[1] < 1 || n[1] > 32 || n[2] < 1 || n[2] > 16 {
		return nil, errors.New("the half's seal has a cost out of range")
	}
	rest := data[i+1:]
	if len(rest) < 16+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, errors.New("the half's seal is cut short")
	}
	salt, nonce, box := rest[:16], rest[16:16+chacha20poly1305.NonceSizeX], rest[16+chacha20poly1305.NonceSizeX:]
	key, err := scrypt.Key(passphrase, salt, 1<<n[0], n[1], n[2], chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, nonce, box, []byte(head+name))
	if err != nil {
		return nil, errPassphrase
	}
	return out, nil
}

// cachedPassphrase is the passphrase of this run, once asked for.
var cachedPassphrase []byte

// readPassphrase asks for a passphrase on the terminal, never echoed; a
// variable for the tests. The passphrase comes from no argument and no
// environment variable, and goes to no log.
var readPassphrase = func(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("the passphrase of the post-quantum halves is asked on a terminal, and there is none")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	p, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return p, err
}

// passphrase returns the run's passphrase, asking for it the first time.
func passphrase() ([]byte, error) {
	if cachedPassphrase != nil {
		return cachedPassphrase, nil
	}
	p, err := readPassphrase("release-sign: the passphrase of the post-quantum halves: ")
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, errors.New("no passphrase")
	}
	cachedPassphrase = p
	return p, nil
}

// newPassphrase asks for the passphrase twice, for a new seal, unless the
// run has it already; one passphrase serves every hardware half.
func newPassphrase() ([]byte, error) {
	if cachedPassphrase != nil {
		return cachedPassphrase, nil
	}
	p, err := readPassphrase("release-sign: the passphrase of the post-quantum halves (the same for every hardware key; keep it in the password manager and on paper with the backup): ")
	if err != nil {
		return nil, err
	}
	again, err := readPassphrase("release-sign: the passphrase again: ")
	if err != nil {
		return nil, err
	}
	defer clear(again)
	if len(p) < 12 {
		return nil, errors.New("the passphrase must be 12 characters or more")
	}
	if !bytes.Equal(p, again) {
		return nil, errors.New("the two passphrases differ")
	}
	cachedPassphrase = p
	return p, nil
}
