// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"runtime"
	"testing"

	"github.com/HunterEwok/cbb/internal/keyseal"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// A key or a secret kept by hardware that is not there, or kept without
// its blob, says so instead of loading something else.
func TestHeldKeysWithoutTheirHardware(t *testing.T) {
	if _, err := (HeldKey{}).Load(); err == nil {
		t.Error("a held key without its blob loaded")
	}
	if _, err := (Sealer{}).Unseal(&keyseal.Blob{}); err == nil {
		t.Error("a sealed secret without its blob opened")
	}
	if runtime.GOOS != "darwin" {
		if _, err := (storedKey{se: []byte{1, 2, 3}}).load(); err == nil {
			t.Error("a Secure Enclave key loaded where there is no enclave")
		}
		if _, err := (Sealer{}).Unseal(&keyseal.Blob{SE: []byte{1, 2, 3}}); err == nil {
			t.Error("a secret the Secure Enclave sealed opened where there is no enclave")
		}
	}
	if _, err := theTPM(); err != nil {
		if _, err := loadTPMKey(&tpmkey.Blob{}); err == nil {
			t.Error("a TPM key loaded where there is no TPM")
		}
		if _, err := (Sealer{}).Unseal(&keyseal.Blob{TPM: &tpmkey.Blob{}}); err == nil {
			t.Error("a secret the TPM sealed opened where there is no TPM")
		}
	}
}

// With CBB_TPM off nothing goes to the hardware, and the reason says so.
func TestHardwareOff(t *testing.T) {
	t.Setenv(TPMEnv, "off")
	if got := WhyNotHardware(); got != TPMEnv+" is off" {
		t.Errorf("WhyNotHardware() = %q", got)
	}
	if b, err := (Sealer{}).Seal([]byte("secret")); b != nil || err != nil {
		t.Errorf("Seal with CBB_TPM off: %v, %v", b, err)
	}
	if _, held := HeldOf(newGroup(t).Key); held {
		t.Error("a key in a file is held by hardware")
	}
}
