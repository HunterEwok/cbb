// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// TypeZXNext is the type of zxnext.json: the ZX Spectrum Next's files of a
// release, signed by a release key, which the Pi's cbb checks before
// `.cbb update` takes a newer CBB (docs/protocol.md, section 16, "Where the
// files are").
const TypeZXNext = "zxnext"

// ZXNextNames are the files zxnext.json lists, each once: the dot command,
// its overlay, its driver and the Pi's cbb.
var ZXNextNames = []string{"CBB", "CBB.OVL", "CBB.DRV", "cbb"}

// MaxZXNextFile is the largest file zxnext.json may list.
const MaxZXNextFile = 64 << 20

// ZXNextFile is one of the Next's files, as packaging/zxnext/site.sh lists
// it: its size, its CRC-32 (zlib's, in hex) and its SHA-256.
type ZXNextFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	CRC32  string `json:"crc32"`
	SHA256 string `json:"sha256"`
}

// ZXNext is the body of zxnext.json.
type ZXNext struct {
	V       int          `json:"v"`
	Type    string       `json:"type"`
	Version string       `json:"version"`
	TimeMS  int64        `json:"time_ms"`
	Files   []ZXNextFile `json:"files"`
}

var hexCRC32 = regexp.MustCompile(`^[0-9a-f]{8}$`)

func decodeZXNext(data []byte) (ZXNext, error) {
	var z ZXNext
	if err := decode(data, TypeZXNext, &z, "version", "time_ms", "files"); err != nil {
		return z, err
	}
	if !versionRE.MatchString(z.Version) {
		return z, fmt.Errorf("release: %q is not a version", z.Version)
	}
	if z.TimeMS < 0 {
		return z, errors.New("release: zxnext.json has no signing time")
	}
	if len(z.Files) != len(ZXNextNames) {
		return z, errors.New("release: zxnext.json must list the Next's four files")
	}
	seen := map[string]bool{}
	for _, f := range z.Files {
		known := false
		for _, n := range ZXNextNames {
			known = known || f.Name == n
		}
		if !known || seen[f.Name] {
			return z, fmt.Errorf("release: %q is not one of the Next's files, or twice", f.Name)
		}
		seen[f.Name] = true
		if f.Size <= 0 || f.Size > MaxZXNextFile || !hexCRC32.MatchString(f.CRC32) || !hexSHA256.MatchString(f.SHA256) {
			return z, fmt.Errorf("release: the entry for %s is not valid", f.Name)
		}
	}
	return z, nil
}

// File returns the entry for name.
func (z ZXNext) File(name string) (ZXNextFile, bool) {
	for _, f := range z.Files {
		if f.Name == name {
			return f, true
		}
	}
	return ZXNextFile{}, false
}

// CheckZXNext verifies zxnext.json: keys.json under the roots, the list
// under one of its release keys, not signed ahead of now, and not of a
// release older than installed, the version of the cbb that checks it
// (none when empty). A clock that is not set yet takes keys.json as it
// is, as VerifyKeys does.
func CheckZXNext(keys, list File, roots []Key, now time.Time, installed string) (ZXNext, error) {
	k, err := VerifyKeys(keys, roots, now, Seen{})
	if err != nil {
		return ZXNext{}, fmt.Errorf("keys.json: %w", err)
	}
	if err := list.verify(k.of(UseRelease)); err != nil {
		return ZXNext{}, fmt.Errorf("zxnext.json: %w", err)
	}
	z, err := decodeZXNext(list.Body)
	if err != nil {
		return ZXNext{}, fmt.Errorf("zxnext.json: %w", err)
	}
	if signedAhead(z.TimeMS, now) {
		return ZXNext{}, fmt.Errorf("zxnext.json: %w", ErrJump)
	}
	if installed != "" && Compare(z.Version, installed) < 0 {
		return ZXNext{}, fmt.Errorf("zxnext.json: %w", ErrRollback)
	}
	return z, nil
}
