// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/HunterEwok/cbb/internal/release"
)

// The post-quantum half of a key (docs/maintaining.md, "Two signatures")
// cannot live in a YubiKey or the Secure Enclave. It is a file encrypted
// with age to a key in the same hardware that holds the classical half
// (age-plugin-yubikey in a free slot of that YubiKey, age-plugin-se in the
// Mac's enclave), opened for one signature and dropped: the file alone
// signs nothing, and the classical half alone signs nothing a device
// takes.

// pqDir is where the encrypted halves are, each named by the SHA-256 of
// its classical half's SubjectPublicKeyInfo: HASH.age, opened with the
// age identity HASH.identity (a pointer to the hardware, not a secret).
func pqDir() string {
	if d := os.Getenv("CBB_RELEASE_PQ_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cbb-release", "pq")
}

// pqName is the base name of the files of a classical half's partner.
func pqName(classical crypto.Signer) (string, error) {
	_, spki, err := release.MarshalPublic(classical.Public())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(spki)
	return hex.EncodeToString(h[:16]), nil
}

// ageDecrypt is the age program, a variable for the tests.
var ageDecrypt = func(identity, file string) ([]byte, error) {
	c := exec.Command("age", "--decrypt", "-i", identity, file)
	// The plugin asks for the PIN and the touch on the terminal.
	c.Stdin, c.Stderr = os.Stdin, os.Stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("age could not open %s: %w", file, err)
	}
	return out, nil
}

// ageEncrypt encrypts data to recipient into file.
var ageEncrypt = func(recipient, file string, data []byte) error {
	c := exec.Command("age", "--encrypt", "-r", recipient, "-o", file)
	c.Stdin, c.Stderr = bytes.NewReader(data), os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("age could not write %s: %w", file, err)
	}
	return nil
}

// cutPaths splits IDENTITY:FILE at the colon between the two paths,
// passing over the drive letter that starts the first on Windows
// (C:\x.identity:C:\x.age); the second is taken whole.
func cutPaths(arg string, windows bool) (string, string, bool) {
	skip := 0
	if windows && len(arg) >= 2 && arg[1] == ':' && ('a' <= arg[0]|0x20 && arg[0]|0x20 <= 'z') {
		skip = 2
	}
	i := strings.IndexByte(arg[skip:], ':')
	if i < 0 {
		return "", "", false
	}
	return arg[:skip+i], arg[skip+i+1:], true
}

// pqOf returns the post-quantum half that goes with classical, from spec
// (slh:FILE, a key in a file, or age:IDENTITY:FILE) or, when spec is
// empty, from the encrypted file pqDir names for it.
func pqOf(classical crypto.Signer, spec string) (crypto.Signer, error) {
	var data []byte
	var err error
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "slh":
		data, err = os.ReadFile(arg)
	case "age":
		identity, file, ok := cutPaths(arg, runtime.GOOS == "windows")
		if !ok {
			return nil, fmt.Errorf("%q is not age:IDENTITY:FILE", spec)
		}
		data, err = ageDecrypt(identity, file)
	case "":
		name, err2 := pqName(classical)
		if err2 != nil {
			return nil, err2
		}
		dir := pqDir()
		file := filepath.Join(dir, name+".age")
		if _, err2 := os.Stat(file); err2 != nil {
			return nil, fmt.Errorf("the key's post-quantum half is not in %s (release-sign pq-new makes it): %w", dir, err2)
		}
		step("opening the key's post-quantum half: touch the hardware key again if it asks")
		data, err = ageDecrypt(filepath.Join(dir, name+".identity"), file)
	default:
		return nil, fmt.Errorf("unknown post-quantum half %q: slh:FILE or age:IDENTITY:FILE", spec)
	}
	if err != nil {
		return nil, err
	}
	defer clear(data)
	h, err := release.ParseHalf(data)
	if err != nil {
		return nil, err
	}
	if alg, _, err := release.MarshalPublic(h.Public()); err != nil || alg != release.AlgSLHDSA {
		return nil, errors.New("the post-quantum half is not an SLH-DSA-SHA2-128s key")
	}
	return h, nil
}

// pqNew makes the post-quantum half of a key whose classical half SIGNER
// names: encrypted with age to -to, the hardware's age recipient, into
// pqDir under the classical half's name, with -identity copied beside it;
// or with -out - written as PEM to the standard output, for a server's
// encrypted credential (systemd-creds encrypt). It prints both halves'
// public keys, with -name as roots.pem names them.
func pqNew(args []string) error {
	fs := flag.NewFlagSet("pq-new", flag.ExitOnError)
	key := fs.String("key", "", "the classical half: piv:SLOT, se:KEY or file:KEY.pem")
	to := fs.String("to", "", "the age recipient of the hardware that holds the classical half (age1yubikey1..., age1se1...)")
	identity := fs.String("identity", "", "the age identity file of that hardware")
	out := fs.String("out", "", "- writes the half as PEM to the standard output instead, for a server's credential")
	public := fs.String("public", "", "where both halves' public keys go (PEM); the standard output by default")
	name := fs.String("name", "", "the Name header of the public keys, for roots.pem")
	fs.Parse(args)
	if *key == "" || fs.NArg() != 0 || (*out == "") == (*to == "") || (*to != "" && *identity == "") {
		return errors.New("pq-new needs -key and either -to with -identity or -out -")
	}
	classical, err := classicalSigner(*key)
	if err != nil {
		return err
	}
	pq, err := release.GenerateSLH(randReader)
	if err != nil {
		return err
	}
	secret, err := release.MarshalSLHPEM(pq)
	if err != nil {
		return err
	}
	defer clear(secret)
	pubs, err := release.PublicPEM(release.Signer{classical, pq}, *name)
	if err != nil {
		return err
	}
	if *out == "-" {
		if *public == "" {
			return errors.New("-out - needs -public for the public keys")
		}
		if _, err := stdout.Write(secret); err != nil {
			return err
		}
	} else {
		n, err := pqName(classical)
		if err != nil {
			return err
		}
		dir := pqDir()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		file := filepath.Join(dir, n+".age")
		if _, err := os.Stat(file); err == nil {
			return fmt.Errorf("%s exists: this key has its post-quantum half already", file)
		}
		id, err := os.ReadFile(*identity)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, n+".identity"), id, 0o600); err != nil {
			return err
		}
		if err := ageEncrypt(*to, file, secret); err != nil {
			return err
		}
		step("checking that the hardware opens it: touch it when it asks")
		back, err := pqOf(classical, "")
		if err != nil {
			os.Remove(file)
			return fmt.Errorf("the encrypted half does not open, removed: %w", err)
		}
		if !back.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(pq.Public()) {
			os.Remove(file)
			return errors.New("the encrypted half opens to another key, removed")
		}
		step("the post-quantum half is in %s", file)
	}
	if *public == "" {
		_, err = stdout.Write(pubs)
		return err
	}
	return os.WriteFile(*public, pubs, 0o644)
}

// pqCheck proves that a key's two halves work and match a public file:
// it signs a test body with both, as a release is signed (the hardware
// asks twice), and checks the signatures under the keys -public holds,
// as a device would. Run after pq-new while the hardware is still in.
func pqCheck(args []string) error {
	fs := flag.NewFlagSet("pq-check", flag.ExitOnError)
	key := fs.String("key", "", "the signer, as for sign: piv:SLOT, se:KEY, file:KEY.pem or CLASSICAL+slh:FILE")
	public := fs.String("public", "", "the key's public halves (PEM), as pq-new wrote them")
	fs.Parse(args)
	if *key == "" || *public == "" || fs.NArg() != 0 {
		return errors.New("pq-check needs -key and -public")
	}
	data, err := os.ReadFile(*public)
	if err != nil {
		return err
	}
	halves, err := release.ReadHalves(data)
	if err != nil {
		return fmt.Errorf("%s: %w", *public, err)
	}
	var keys []release.Key
	for _, alg := range release.Required {
		if halves[alg] == nil {
			return fmt.Errorf("%s has no half of algorithm %d", *public, alg)
		}
		keys = append(keys, release.Key{Alg: alg, Key: halves[alg], Name: "checked"})
	}
	s, err := signer(*key)
	if err != nil {
		return err
	}
	// A body no device takes for anything, signed as a release file is.
	body := []byte(`{"type":"pq-check"}`)
	for _, h := range s {
		if t, ok := h.(*tool); ok {
			t.data = body
		}
	}
	f, err := signRaw(body, s)
	if err != nil {
		return err
	}
	if err := f.VerifyWith(keys); err != nil {
		return fmt.Errorf("the key's signatures do not check out under %s: %w", *public, err)
	}
	fmt.Fprintf(stdout, "both halves sign, and the signatures check out under %s\n", *public)
	return nil
}
