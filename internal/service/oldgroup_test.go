// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

func TestLeaveVersion1Group(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}

	// No records, or records of version 2: nothing moves.
	if left, err := leaveVersion1Group(dir); left || err != nil {
		t.Fatalf("no records: %v %v", left, err)
	}
	write(group.FileName, "{}")
	write(group.RecordsFileName, `{"v":2,"records":[]}`)
	if left, err := leaveVersion1Group(dir); left || err != nil || !exists(filepath.Join(dir, group.FileName)) {
		t.Fatalf("records of version 2: %v %v", left, err)
	}

	// A group of 0.5: its files move, the settings stay.
	write(group.RecordsFileName, "\n [ ]")
	write(group.CredentialsFileName, "{}")
	write(syncFile, `{"off":true}`)
	left, err := leaveVersion1Group(dir)
	if !left || err != nil {
		t.Fatalf("a group of 0.5: %v %v", left, err)
	}
	for _, name := range []string{group.FileName, group.RecordsFileName, group.CredentialsFileName} {
		if exists(filepath.Join(dir, name)) || !exists(filepath.Join(dir, oldGroupDir, name)) {
			t.Errorf("%s did not move", name)
		}
	}
	if !exists(filepath.Join(dir, syncFile)) {
		t.Error("sync off moved")
	}
	if _, err := group.Load(dir); err != group.ErrNoGroup {
		t.Errorf("the device is still in a group: %v", err)
	}
	if left, err := leaveVersion1Group(dir); left || err != nil {
		t.Fatalf("again: %v %v", left, err)
	}
}

// TestUpgrade checks that a group made before 0.4, whose group CA
// certifies no admin CAs, is left at start, even without a records file,
// instead of being upgraded in place.
func TestUpgrade(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ca, err := group.NewGroupCA(now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := group.NewDeviceID()
	cert, err := ca.IssueMember(dev, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	// Save refuses such an identity, so the file is written as 0.3 did.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"v": 1, "device": dev, "key": keyDER, "cert": cert.Raw, "group_ca": ca.Cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, group.FileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := group.Load(dir); !errors.Is(err, group.ErrOldGroup) {
		t.Fatalf("Load: %v, want ErrOldGroup", err)
	}
	if left, err := leaveVersion1Group(dir); !left || err != nil {
		t.Fatalf("a group of 0.3: %v %v", left, err)
	}
	if _, err := os.Stat(filepath.Join(dir, oldGroupDir, group.FileName)); err != nil {
		t.Error("the identity did not move")
	}
	if _, err := group.Load(dir); !errors.Is(err, group.ErrNoGroup) {
		t.Errorf("the device is still in a group: %v", err)
	}
}
