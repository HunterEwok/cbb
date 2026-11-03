// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// useTPM points the package at the TPM that tpmtest started, for one test.
func useTPM(t *testing.T) {
	tpmtest.Start(t)
	ReopenTPM()
	t.Cleanup(ReopenTPM)
}

// TestKeysInTPM checks that a new identity's member key and a computer's
// admin key go into the TPM, are saved as blobs, load again, and that
// CBB_TPM=off keeps new keys in the file.
func TestKeysInTPM(t *testing.T) {
	useTPM(t)
	id, err := Create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(id.Key) != StoreHardware {
		t.Fatal("the member key is not in the TPM")
	}
	dir := t.TempDir()
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, FileName))
	if !strings.Contains(string(data), `"key_tpm"`) || strings.Contains(string(data), `"key":`) {
		t.Errorf("the identity file keeps the member key as %s", data)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(got.Key) != StoreHardware || !SameKey(got.Key, id.Key.Public()) {
		t.Fatal("the loaded member key is not the TPM's")
	}
	// The root's member certificate renews with the key in the TPM.
	if _, _, err := got.Renew(time.Now().AddDate(1, 6, 0)); err != nil {
		t.Fatal(err)
	}

	pg := newPhoneGroup(t)
	pending, err := adminIdentity(t, pg, nil).WithAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if KeyStoreOf(pending.AdminKey) != StoreHardware {
		t.Error("the admin key is not in the TPM")
	}
	if err := pending.Save(dir); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(dir); err != nil || KeyStoreOf(got.AdminKey) != StoreHardware {
		t.Errorf("the admin key did not load from the TPM: %v", err)
	}

	t.Setenv(TPMEnv, "off")
	k, err := NewDeviceKey()
	if err != nil || KeyStoreOf(k) != StoreFile {
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
