// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build !linux && !windows

package tpmkey

import "github.com/google/go-tpm/tpm2/transport"

// openDevice finds no TPM: the service uses one only on Linux
// and Windows.
func openDevice() (transport.TPMCloser, error) { return nil, ErrNoTPM }
