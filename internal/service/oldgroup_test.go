// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

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
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(syncFile, `{"off":true}`)

	var h hub
	s := startIn(t, &h, &testService{name: "pi", dir: dir, os: group.OSLinux})
	if st := s.status(t); st.Group != "" {
		t.Errorf("the device is still in the group %s", st.Group)
	}
	if !s.logged("made before 0.6") {
		t.Error("the service did not say it left the old group")
	}
	if _, err := os.Stat(filepath.Join(dir, "before-0.6", group.FileName)); err != nil {
		t.Error("the identity did not move")
	}
	if _, err := os.Stat(filepath.Join(dir, syncFile)); err != nil {
		t.Error("the device's settings moved")
	}
}
