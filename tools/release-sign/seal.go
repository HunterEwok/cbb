// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// The writer's r and p, and LOGN at most 20: a damaged line asks for
	// 1 GiB at most (128 * r * 2^LOGN bytes).
	if n[0] < 10 || n[0] > 20 || n[1] != sealR || n[2] != sealP {
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

// passphraseCheck is a file beside the halves, sealed with the
// passphrase, so that a run knows a wrong passphrase before it asks the
// hardware for anything, and every half gets the same passphrase. It is
// not encrypted to the hardware, so whoever copies it can try
// passphrases against it without the hardware, at scrypt's cost each:
// hence a long passphrase (minPassphrase), five random words or more.
func passphraseCheck() string { return filepath.Join(pqDir(), "passphrase.check") }

const checkText = "the passphrase of the post-quantum halves"

// minPassphrase is the shortest new passphrase, in bytes.
const minPassphrase = 24

// passphrase returns the run's passphrase, asking for it the first time
// and checking it against passphrase.check when there is one.
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
	if box, err := os.ReadFile(passphraseCheck()); err == nil {
		if _, err := unseal(p, box, "check"); err != nil {
			clear(p)
			return nil, err
		}
	}
	cachedPassphrase = p
	return p, nil
}

// sealedHalves tells whether pqDir holds a sealed half (HASH.age).
func sealedHalves() bool {
	m, _ := filepath.Glob(filepath.Join(pqDir(), "*.age"))
	return len(m) > 0
}

// newPassphrase returns the passphrase for a new seal: the one every half
// has, checked against passphrase.check, or for the first half a new one,
// asked twice, which passphrase.check then records.
func newPassphrase() ([]byte, error) {
	if cachedPassphrase != nil {
		return cachedPassphrase, nil
	}
	if _, err := os.Stat(passphraseCheck()); err == nil {
		return passphrase()
	}
	// Halves without the check file: a new passphrase here would seal the
	// next half under another one than theirs.
	if sealedHalves() {
		return nil, fmt.Errorf("%s holds sealed halves but no passphrase.check: put it back from the backup before making another half", pqDir())
	}
	p, err := readPassphrase("release-sign: a new passphrase for the post-quantum halves (five random words or more, the same for every hardware key; keep it in the password manager and on paper with the backup): ")
	if err != nil {
		return nil, err
	}
	again, err := readPassphrase("release-sign: the passphrase again: ")
	if err != nil {
		return nil, err
	}
	defer clear(again)
	if len(p) < minPassphrase {
		return nil, fmt.Errorf("the passphrase must be %d characters or more: five random words or more", minPassphrase)
	}
	if !bytes.Equal(p, again) {
		return nil, errors.New("the two passphrases differ")
	}
	box, err := seal(p, []byte(checkText), "check")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(pqDir(), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(passphraseCheck(), box, 0o600); err != nil {
		return nil, err
	}
	cachedPassphrase = p
	return p, nil
}
