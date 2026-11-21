// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// RemoveGroupFiles deletes the files that earlier versions kept in dir, one
// for each group that registered, with its roots and removals, and then dir
// itself when nothing else is left in it. It returns how many it deleted.
func RemoveGroupFiles(dir string) (int, error) {
	es, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range es {
		name := e.Name()
		tag, ok := strings.CutSuffix(strings.TrimSuffix(name, ".tmp"), ".json")
		if !ok || !validTag(tag) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return n, err
		}
		n++
	}
	os.Remove(dir) // only when it is empty
	return n, nil
}

// validTag reports whether tag is a group tag, 16 lowercase hex digits.
func validTag(tag string) bool {
	if len(tag) != 16 {
		return false
	}
	_, err := hex.DecodeString(tag)
	return err == nil && tag == strings.ToLower(tag)
}
