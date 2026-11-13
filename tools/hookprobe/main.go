// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command hookprobe asks a cbb-helper one thing a test hook changes: it
// starts the helper with CBB_TEST_ATTEST_ROOTS naming the root of an
// Android Key Attestation it made, sends that attestation for checking as
// cbb does (helper.OpAttestAndroid), and prints whether the helper took
// it. A release helper reads no test hook (internal/testhooks), so it
// checks the chain against Google's roots and refuses it; only a build
// with the hooks takes it. .github/release-ignores-hooks.sh runs it.
//
//	hookprobe CBB-HELPER
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/attest/attesttest"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/helper"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hookprobe CBB-HELPER")
		os.Exit(2)
	}
	took, why, err := probe(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "hookprobe:", err)
		os.Exit(1)
	}
	if took {
		fmt.Println("cbb-helper took an attestation under the roots CBB_TEST_ATTEST_ROOTS names")
		return
	}
	fmt.Println("cbb-helper refused an attestation under the roots CBB_TEST_ATTEST_ROOTS names:", why)
}

// probe runs the helper at bin and reports whether it proved the key.
func probe(bin string) (took bool, why string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return false, "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return false, "", err
	}
	challenge, err := attest.Challenge("", nil, salt)
	if err != nil {
		return false, "", err
	}
	chain, root, err := attesttest.Android(&key.PublicKey, challenge)
	if err != nil {
		return false, "", err
	}
	dir, err := os.MkdirTemp("", "hookprobe")
	if err != nil {
		return false, "", err
	}
	defer os.RemoveAll(dir)
	roots := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: root}), 0o644); err != nil {
		return false, "", err
	}
	payload, err := json.Marshal(helper.AndroidCheck{
		Evidence: helper.Evidence{Format: "android", Salt: salt, Chain: chain},
		SPKI:     spki,
	})
	if err != nil {
		return false, "", err
	}

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "CBB_TEST_ATTEST_ROOTS="+roots)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return false, "", err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false, "", err
	}
	if err := cmd.Start(); err != nil {
		return false, "", err
	}
	defer cmd.Wait()
	defer in.Close()
	req := control.Message{Header: control.Header{Op: helper.OpAttestAndroid, Seq: 1}, Payload: payload}
	if err := control.Write(in, &req); err != nil {
		return false, "", fmt.Errorf("writing the request: %w", err)
	}
	ans, err := control.NewReader(out).Read()
	if err != nil {
		return false, "", fmt.Errorf("reading the answer: %w", err)
	}
	if ans.Error != "" {
		// Refused outright, as a chain to no known root is.
		return false, ans.Error, nil
	}
	var p helper.Proven
	if err := json.Unmarshal(ans.Payload, &p); err != nil {
		return false, "", fmt.Errorf("an answer that is not understood: %w", err)
	}
	if p.Store == group.StoreProven {
		return true, "", nil
	}
	if p.Why == "" {
		return false, "", errors.New("the helper neither proved the key nor said why not")
	}
	return false, p.Why, nil
}
