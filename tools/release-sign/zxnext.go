// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/release"
)

// zxnextName is the release file in which a release key lists the ZX
// Spectrum Next's files of cbb-zxnext.tar.gz (docs/protocol.md, section 16,
// "The ZX Spectrum Next's files"), and zxnextSigned the file of the Next's
// directory on cbb.tools that holds keys.json and it, a line each, for
// `.cbb update`, whose Pi checks them.
const (
	zxnextName   = "zxnext.json"
	zxnextSigned = "SIGNED"
)

// zxnextList lists the Next's files of an unpacked cbb-zxnext.tar.gz.
func zxnextList(files map[string][]byte, version string, at int64) (release.ZXNext, error) {
	z := release.ZXNext{V: 1, Type: release.TypeZXNext, Version: version, TimeMS: at}
	for _, name := range release.ZXNextNames {
		data, ok := files[name]
		if !ok {
			return z, fmt.Errorf("%s has no %s", zxnextArchive, name)
		}
		sum := sha256.Sum256(data)
		z.Files = append(z.Files, release.ZXNextFile{
			Name: name, Size: int64(len(data)), CRC32: fmt.Sprintf("%08x", crc32.ChecksumIEEE(data)), SHA256: hex.EncodeToString(sum[:]),
		})
	}
	return z, nil
}

// zxnextMatches reports whether z lists files as they are, for version.
func zxnextMatches(z release.ZXNext, files map[string][]byte, version string) error {
	want, err := zxnextList(files, version, z.TimeMS)
	if err != nil {
		return err
	}
	if z.Version != version {
		return fmt.Errorf("%s is of %s, not %s", zxnextName, z.Version, version)
	}
	for _, w := range want.Files {
		if f, ok := z.File(w.Name); !ok || f != w {
			return fmt.Errorf("%s does not list %s as %s has it", zxnextName, w.Name, zxnextArchive)
		}
	}
	return nil
}

// signZXNext signs the list of the Next's files of the release in dir, when
// it has them; ok is false for a release without them.
func signZXNext(dir, version string, rs crypto.Signer) (f release.File, ok bool, err error) {
	path := filepath.Join(dir, zxnextArchive)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return f, false, nil
	}
	files, err := readZXNext(path)
	if err != nil {
		return f, false, err
	}
	z, err := zxnextList(files, version, now().UnixMilli())
	if err != nil {
		return f, false, err
	}
	step("signing %s with the release key", zxnextName)
	f, err = signWith(rs, z)
	return f, err == nil, err
}

// writeZXNextSigned checks the release's zxnext.json, in the mirror's
// vX.Y.Z, under keys and against the Next's files it unpacked, and writes
// keys.json and it to dir's SIGNED; without one that checks out it removes
// SIGNED, so that .cbb update takes no newer CBB.
func writeZXNextSigned(out, dir, version string, keys release.File, files map[string][]byte) error {
	signed := filepath.Join(dir, zxnextSigned)
	drop := func(why error) error {
		step("no %s for the Next: %v", zxnextSigned, why)
		if err := os.Remove(signed); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	list, err := readFile(filepath.Join(out, "v"+version, zxnextName))
	if err != nil {
		return drop(err)
	}
	z, err := release.CheckZXNext(keys, list, pinnedRoots(), now(), "")
	if err != nil {
		return drop(err)
	}
	if err := zxnextMatches(z, files, version); err != nil {
		return drop(err)
	}
	var b bytes.Buffer
	for _, f := range []release.File{keys, list} {
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		b.Write(append(data, '\n'))
	}
	return replace(signed, b.Bytes())
}
