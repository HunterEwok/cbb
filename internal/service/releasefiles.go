// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/release"
)

// The archives of the held release (docs/protocol.md, section 16, "In the
// group"): cbb update hands the service each archive it installed, which
// keeps it named by its SHA-256 and serves it to the peers as it serves
// images and files; cbb update elsewhere asks its own service first, which
// fetches the archive from the peers. Only files that the held release.json
// lists are kept or served, and those of an older release are deleted.

const releaseFilesDir = "release-files"

// releaseFetchTimeout is how long the service tries the peers for an
// archive before cbb update downloads it itself.
const releaseFetchTimeout = 10 * time.Minute

func (s *Service) releaseFilePath(sum [sha256.Size]byte) string {
	return filepath.Join(s.cfg.StateDir, releaseFilesDir, hex.EncodeToString(sum[:]))
}

// heldAsset returns the file of the held release whose SHA-256 is sum.
func (s *Service) heldAsset(sum [sha256.Size]byte) (release.Asset, bool) {
	h := s.heldRelease()
	if h == nil {
		return release.Asset{}, false
	}
	want := hex.EncodeToString(sum[:])
	for _, a := range h.release.Files {
		if a.SHA256 == want {
			return a, true
		}
	}
	return release.Asset{}, false
}

// openReleaseFile returns an archive of the held release this member
// holds whole, and its size.
func (s *Service) openReleaseFile(sum [sha256.Size]byte) (*os.File, int64, bool) {
	a, ok := s.heldAsset(sum)
	if !ok {
		return nil, 0, false
	}
	f, err := os.Open(s.releaseFilePath(sum))
	if err != nil {
		return nil, 0, false
	}
	if fi, err := f.Stat(); err != nil || fi.Size() != a.Size {
		f.Close()
		return nil, 0, false
	}
	return f, a.Size, true
}

// releaseContent serves the archives to the peers (node.Content).
type releaseContent struct{ s *Service }

func (r releaseContent) Open(sum [sha256.Size]byte) (io.ReaderAt, int64, bool) {
	f, size, ok := r.s.openReleaseFile(sum)
	if !ok {
		return nil, 0, false
	}
	return f, size, true
}

// contents is node.Content over several stores, the first that holds a
// part serving it.
type contents []node.Content

func (cs contents) Open(sum [sha256.Size]byte) (io.ReaderAt, int64, bool) {
	for _, c := range cs {
		if r, size, ok := c.Open(sum); ok {
			return r, size, true
		}
	}
	return nil, 0, false
}

// pruneReleaseFiles deletes the archives the held release does not list.
func (s *Service) pruneReleaseFiles() {
	dir := filepath.Join(s.cfg.StateDir, releaseFilesDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		sum, err := hex.DecodeString(e.Name())
		if err == nil && len(sum) == sha256.Size {
			if _, ok := s.heldAsset([sha256.Size]byte(sum)); ok {
				continue
			}
		}
		os.Remove(filepath.Join(dir, e.Name()))
	}
}

// parseSum reads a SHA-256 in hex.
func parseSum(v string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != sha256.Size {
		return sum, fmt.Errorf("%q is not a SHA-256", v)
	}
	return [sha256.Size]byte(b), nil
}

// maxWanted bounds the archives a hub asks cbb update for at a time.
const maxWanted = 16

// wantedReleaseFiles returns, on a hub, the archives of the held release
// that the group's members update from and this device does not hold whole
// (OpReleaseWant): its cbb update downloads them, so that devices on
// networks that block the update servers get them through the group, also
// inside its tunnel (docs/protocol.md, section 16, "In the group").
// Elsewhere it returns none.
func (s *Service) wantedReleaseFiles() []string {
	s.tunMu.Lock()
	hub := s.tunnel != nil && s.tunnel.IsHub
	s.tunMu.Unlock()
	h := s.heldRelease()
	if !hub || h == nil {
		return nil
	}
	s.mu.Lock()
	names := map[string]bool{}
	for _, a := range s.archives {
		names[a] = true
	}
	s.mu.Unlock()
	return wantedFiles(h.release.Files, names, func(sum [sha256.Size]byte) bool {
		f, _, ok := s.openReleaseFile(sum)
		if ok {
			f.Close()
		}
		return ok
	})
}

// wantedFiles returns the names of the files that names lists and holds
// does not, at most maxWanted.
func wantedFiles(files []release.Asset, names map[string]bool, holds func([sha256.Size]byte) bool) []string {
	var out []string
	for _, a := range files {
		if !names[a.Name] || len(out) == maxWanted {
			continue
		}
		if sum, err := parseSum(a.SHA256); err == nil && !holds(sum) {
			out = append(out, a.Name)
		}
	}
	return out
}

// receiveReleaseFile takes an archive from cbb update (OpReleaseFile): it
// must be a file of the held release, whole and matching its hash.
func (s *Service) receiveReleaseFile(r *control.Reader, m *control.Message) error {
	sum, err := parseSum(m.Value)
	if err != nil {
		return err
	}
	a, ok := s.heldAsset(sum)
	if !ok {
		return errors.New("the release this device holds lists no such file")
	}
	if m.Part == nil || m.Part.Size != a.Size {
		return fmt.Errorf("%s is %d bytes, not as said", a.Name, a.Size)
	}
	dir := filepath.Join(s.cfg.StateDir, releaseFilesDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".part-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	w := io.MultiWriter(f, h)
	for got := int64(0); got < a.Size; {
		dm, err := r.Read()
		if err != nil || dm.Op != control.OpData || int64(len(dm.Payload)) > a.Size-got || len(dm.Payload) == 0 {
			f.Close()
			return fmt.Errorf("the bytes of %s did not come as said", a.Name)
		}
		if _, err := w.Write(dm.Payload); err != nil {
			f.Close()
			return err
		}
		got += int64(len(dm.Payload))
	}
	if err := f.Close(); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), sum[:]) {
		return fmt.Errorf("%s does not match the signed release.json", a.Name)
	}
	return os.Rename(f.Name(), s.releaseFilePath(sum))
}

// fetchReleaseFile fetches an archive of the held release from the
// connected peers that serve content, unless this member holds it.
func (s *Service) fetchReleaseFile(ctx context.Context, sum [sha256.Size]byte) error {
	a, ok := s.heldAsset(sum)
	if !ok {
		return errors.New("the release this device holds lists no such file")
	}
	if f, _, ok := s.openReleaseFile(sum); ok {
		f.Close()
		return nil
	}
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		return s.errNoGroup()
	}
	dir := filepath.Join(s.cfg.StateDir, releaseFilesDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	last := errors.New("no member that serves files is connected")
	for _, q := range nd.Peers() {
		if !q.Media {
			continue
		}
		err := s.fetchReleaseFrom(ctx, nd, q, sum, a)
		if err == nil || ctx.Err() != nil {
			return err
		}
		last = fmt.Errorf("from %s: %w", q.Name, err)
	}
	return last
}

func (s *Service) fetchReleaseFrom(ctx context.Context, nd *node.Node, q node.Peer, sum [sha256.Size]byte, a release.Asset) error {
	f, err := os.CreateTemp(filepath.Join(s.cfg.StateDir, releaseFilesDir), ".part-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	err = nd.Fetch(ctx, q.ID, sum, a.Size, 0, func(off int64, data []byte) error {
		if _, err := f.WriteAt(data, off); err != nil {
			return err
		}
		h.Write(data)
		return nil
	})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), sum[:]) {
		return fmt.Errorf("%s does not match the signed release.json", a.Name)
	}
	s.logf("cbb: fetched %s from %s for cbb update", a.Name, q.Name)
	return os.Rename(f.Name(), s.releaseFilePath(sum))
}

// sendReleaseFile answers OpReleaseGet: the archive whose SHA-256 is
// m.Value, from this member or its peers, as a part and its bytes.
func (s *Service) sendReleaseFile(ctx context.Context, c net.Conn, m *control.Message) error {
	sum, err := parseSum(m.Value)
	if err != nil {
		return err
	}
	fctx, cancel := context.WithTimeout(ctx, releaseFetchTimeout)
	defer cancel()
	// A client that stops waiting downloads the file itself.
	left := gone(c)
	go func() {
		select {
		case <-left:
			cancel()
		case <-fctx.Done():
		}
	}()
	if err := s.fetchReleaseFile(fctx, sum); err != nil {
		return err
	}
	f, size, ok := s.openReleaseFile(sum)
	if !ok {
		return errors.New("the file left this device")
	}
	defer f.Close()
	if err := reply(c, control.Header{Part: &control.Part{Size: size}}, nil); err != nil {
		return err
	}
	if err := sendPart(c, f, make([]byte, 1<<20)); err != nil {
		return err
	}
	return reply(c, control.Header{Done: true}, nil)
}
