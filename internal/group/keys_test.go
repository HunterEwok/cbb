// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// useTPM points the package at the TPM that tpmtest started, for one test.
func useTPM(t *testing.T) {
	tpmtest.Start(t)
	ReopenTPM()
	t.Cleanup(ReopenTPM)
}

// TestKeysInTPM checks that a new device key goes into the TPM, that its
// held form loads the same key again, and that CBB_TPM=off keeps new keys
// in a file.
func TestKeysInTPM(t *testing.T) {
	useTPM(t)
	k, err := NewDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(k) != StoreHardware {
		t.Fatal("the device key is not in the TPM")
	}
	held, ok := HeldOf(k)
	if !ok {
		t.Fatal("a key in the TPM has no held form")
	}
	got, err := held.Load()
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(got) != StoreHardware || !got.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(k.Public()) {
		t.Fatal("the loaded key is not the TPM's")
	}
	if NewHardwareKey() == nil {
		t.Errorf("no hardware key with a TPM: %s", WhyNotHardware())
	}

	t.Setenv(TPMEnv, "off")
	if k, err = NewDeviceKey(); err != nil || KeyStoreOf(k) != StoreFile {
		t.Errorf("CBB_TPM=off made a key in the %s", KeyStoreOf(k))
	}
}

// TestTunnelKeySealed checks that the WireGuard key in the tunnel state is
// sealed by the TPM, that a key from the file moves there, and that the
// state loads again with the same key.
func TestTunnelKeySealed(t *testing.T) {
	useTPM(t)
	old := tunnel.KeySealer
	t.Cleanup(func() { tunnel.KeySealer = old })
	dir := t.TempDir()
	path := filepath.Join(dir, tunnel.StateFile)

	// A state written without a sealer keeps the key in the file.
	tunnel.KeySealer = nil
	st, err := tunnel.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := st.Key
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"key":`) || strings.Contains(string(data), "key_tpm") {
		t.Fatalf("without a sealer: %s", data)
	}

	// With one, loading moves it into the TPM.
	tunnel.KeySealer = Sealer{}
	if st, err = tunnel.LoadState(dir); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), `"key":`) || !strings.Contains(string(data), "key_tpm") {
		t.Fatalf("with a sealer: %s", data)
	}
	if st.Key != key {
		t.Fatal("the key changed when it was sealed")
	}
	if st, err = tunnel.LoadState(dir); err != nil || st.Key != key {
		t.Fatalf("loading the sealed key: %v", err)
	}

	// A new key is sealed again.
	n, err := tunnel.NewState()
	if err != nil {
		t.Fatal(err)
	}
	st.Key = n.Key
	if err := st.Save(dir); err != nil {
		t.Fatal(err)
	}
	if st, err = tunnel.LoadState(dir); err != nil || st.Key != n.Key {
		t.Fatalf("loading the new key: %v", err)
	}

	// Without the TPM, the sealed state does not load.
	tunnel.KeySealer = nil
	if _, err := tunnel.LoadState(dir); err == nil {
		t.Error("a sealed key loaded without the TPM")
	}

	// CBB_TPM=off keeps it in the file.
	tunnel.KeySealer = Sealer{}
	t.Setenv(TPMEnv, "off")
	if b, err := (Sealer{}).Seal(key[:]); b != nil || err != nil {
		t.Errorf("Seal with CBB_TPM=off = %v, %v", b, err)
	}
}
