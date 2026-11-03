// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/HunterEwok/cbb/internal/release"
)

// maxUnpacked is the most an archive may unpack to.
const maxUnpacked = 512 << 20

// unpack unpacks the archive at file into dir, checks every program that
// release.json lists for it, and returns the archive's top folder in dir.
// It takes only plain files and folders under one top folder.
func unpack(file, dir string, a release.Asset) (string, error) {
	want := make(map[string]string, len(a.Binaries))
	for _, b := range a.Binaries {
		want[b.Name] = b.SHA256
	}
	var top string
	got := make(map[string]bool)
	var total int64
	put := func(name string, mode os.FileMode, isDir bool, r io.Reader) error {
		// A release never has ".." in a name, so any name with it is
		// refused whole, before it reaches a path.
		if strings.Contains(name, "..") {
			return fmt.Errorf("it holds the path %q", name)
		}
		clean := path.Clean(name)
		if path.IsAbs(clean) || clean == "." || strings.Contains(clean, "\\") || !filepath.IsLocal(filepath.FromSlash(clean)) {
			return fmt.Errorf("it holds the path %q", name)
		}
		first, _, _ := strings.Cut(clean, "/")
		if top == "" {
			top = first
		} else if first != top {
			return errors.New("it has more than one top folder")
		}
		dst := filepath.Join(dir, filepath.FromSlash(clean))
		if isDir {
			return os.MkdirAll(dst, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm()&0o755|0o600)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, maxUnpacked-total+1))
		total += n
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if total > maxUnpacked {
			return errors.New("it unpacks to too much")
		}
		if sum, ok := want[clean]; ok {
			if hex.EncodeToString(h.Sum(nil)) != sum {
				return fmt.Errorf("%s does not match the signed release.json", clean)
			}
			got[clean] = true
		}
		return nil
	}
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	switch {
	case strings.HasSuffix(a.Name, ".tar.gz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", err
			}
			switch h.Typeflag {
			case tar.TypeDir:
				err = put(h.Name, 0o755, true, nil)
			case tar.TypeReg:
				err = put(h.Name, os.FileMode(h.Mode), false, tr)
			default:
				err = fmt.Errorf("it holds %s, which is not a plain file", h.Name)
			}
			if err != nil {
				return "", err
			}
		}
	case strings.HasSuffix(a.Name, ".zip"):
		fi, err := f.Stat()
		if err != nil {
			return "", err
		}
		zr, err := zip.NewReader(f, fi.Size())
		if err != nil {
			return "", err
		}
		for _, zf := range zr.File {
			if zf.Mode()&os.ModeType&^os.ModeDir != 0 {
				return "", fmt.Errorf("it holds %s, which is not a plain file", zf.Name)
			}
			if zf.FileInfo().IsDir() {
				err = put(zf.Name, 0o755, true, nil)
			} else {
				var rc io.ReadCloser
				if rc, err = zf.Open(); err == nil {
					err = put(zf.Name, 0o755, false, rc)
					rc.Close()
				}
			}
			if err != nil {
				return "", err
			}
		}
	default:
		return "", errors.New("it is not an archive cbb update knows")
	}
	for name := range want {
		if !got[name] {
			return "", fmt.Errorf("%s, which release.json lists, is missing", name)
		}
	}
	if top == "" {
		return "", errors.New("it is empty")
	}
	return filepath.Join(dir, top), nil
}
