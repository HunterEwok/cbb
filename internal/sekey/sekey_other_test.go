// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !darwin || !cgo

package sekey

import (
	"errors"
	"testing"
)

// TestNoEnclave: without a Secure Enclave every way in says so.
func TestNoEnclave(t *testing.T) {
	if available() {
		t.Error("an enclave here")
	}
	r, _, _, err := create()
	if !errors.Is(err, ErrNoEnclave) {
		t.Errorf("create: %v", err)
	}
	if _, _, err := load([]byte("x")); !errors.Is(err, ErrNoEnclave) {
		t.Errorf("load: %v", err)
	}
	r.release()
	if _, err := r.sign(nil); !errors.Is(err, ErrNoEnclave) {
		t.Errorf("sign: %v", err)
	}
	if _, err := r.agree(nil); !errors.Is(err, ErrNoEnclave) {
		t.Errorf("agree: %v", err)
	}
	t.Setenv(testEnv, "1")
	if _, err := Load([]byte("x")); !errors.Is(err, ErrNoEnclave) {
		t.Errorf("Load: %v", err)
	}
}
