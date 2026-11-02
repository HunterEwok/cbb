// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// oldGroupDir is where a group made before 0.6 goes when the device
// leaves it, in the state directory.
const oldGroupDir = "before-0.6"

// oldGroupFiles are the files of a group: those a device keeps while it
// is a member, from 0.5 and from 0.6. The records go last, so that a start
// cut short moves the rest at the next one.
var oldGroupFiles = []string{
	group.FileName, group.CredentialsFileName, group.ServerKeysFileName,
	group.SealKeyFileName, signedFile, group.RecordsFileName,
}

// leaveVersion1Group moves a group made before 0.6 out of the state
// directory, so the device starts in no group: 0.6 reads only records of
// version 2, with no migration (docs/records-v2.md), so such a group can
// no longer work, and is set up again. Such a group's records file is a
// JSON array; version 2's is an object. Nothing else of the state moves,
// so the device's settings stay.
func leaveVersion1Group(dir string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, group.RecordsFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
		return false, nil
	}
	to := filepath.Join(dir, oldGroupDir)
	if err := os.MkdirAll(to, 0o700); err != nil {
		return false, err
	}
	for _, name := range oldGroupFiles {
		err := os.Rename(filepath.Join(dir, name), filepath.Join(to, name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	return true, nil
}
