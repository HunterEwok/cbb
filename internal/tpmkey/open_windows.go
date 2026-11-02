// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tpmkey

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
	"github.com/google/go-tpm/tpmutil/tbs"
)

// openDevice opens the TPM 2.0 through Windows' TPM Base Services, which
// every program shares. Windows keeps the owner hierarchy's password, so
// the keys go under its storage root key at PersistentSRK.
func openDevice() (transport.TPMCloser, error) {
	info, err := tbs.GetDeviceInfo()
	if err != nil || info.TPMVersion != tbs.TPMVersion20 {
		return nil, ErrNoTPM
	}
	t, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: %w", err)
	}
	return t, nil
}
