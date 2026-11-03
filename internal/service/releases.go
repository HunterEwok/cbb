// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/release"
	"github.com/HunterEwok/cbb/internal/update"
	"github.com/HunterEwok/cbb/internal/version"
)

// releaseFile keeps the newest signed release the group passed around, as
// the member protocol carries it.
const releaseFile = "release.json"

// heldRelease is a signed release that checked out, with what it says.
type heldRelease struct {
	set       node.ReleaseSet
	seen      release.Seen
	release   release.Release
	version   string
	expiresMS int64
}

// releaseStore is the node's view of the group's newest signed release
// (docs/protocol.md, section 16, "In the group").
type releaseStore struct{ s *Service }

func (r releaseStore) Current() (*node.ReleaseSet, node.ReleaseOrder) {
	h := r.s.heldRelease()
	if h == nil {
		return nil, node.ReleaseOrder{}
	}
	return &h.set, h.order()
}

// order is where the release stands: a release under a newer keys.json
// is newer whatever its channel file's seq.
func (h *heldRelease) order() node.ReleaseOrder {
	return node.ReleaseOrder{Keys: h.seen.KeysSeq, Channel: h.seen.ChannelSeq}
}

func (r releaseStore) Add(from group.DeviceID, set node.ReleaseSet) bool {
	newer, err := r.s.takeRelease(set)
	if err != nil {
		r.s.logf("cbb: dropped the release %s sent: %v", orThis(from), err)
	}
	return newer
}

func (s *Service) releaseRoots() [][]byte {
	if s.cfg.ReleaseRoots != nil {
		return s.cfg.ReleaseRoots
	}
	return release.Roots
}

// checkRelease verifies a release under the release roots, its channel
// not below seen's.
func (s *Service) checkRelease(set node.ReleaseSet, seen release.Seen) (*heldRelease, error) {
	roots := s.releaseRoots()
	if len(roots) == 0 {
		return nil, update.ErrNoRoots
	}
	seen.Version = ""
	r, next, err := release.Check(set.Keys, set.Channel, set.Release, roots, update.Channel, s.cfg.now(), seen)
	if err != nil {
		return nil, err
	}
	var c release.Channel
	if err := json.Unmarshal(set.Channel.Body, &c); err != nil {
		return nil, err
	}
	return &heldRelease{set: set, seen: next, release: r, version: r.Version, expiresMS: c.ExpiresMS}, nil
}

// heldRelease returns the release this device holds, nil for none or
// one whose channel file has expired. It reads the file the first time.
func (s *Service) heldRelease() *heldRelease {
	s.relMu.Lock()
	defer s.relMu.Unlock()
	if !s.relRan {
		s.relRan = true
		s.rel = s.loadRelease()
	}
	if s.rel == nil || s.cfg.now().UnixMilli() >= s.rel.expiresMS {
		return nil
	}
	return s.rel
}

// loadRelease reads the release kept, and checks it again: the roots may
// be others since.
func (s *Service) loadRelease() *heldRelease {
	data, err := os.ReadFile(filepath.Join(s.cfg.StateDir, releaseFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var set node.ReleaseSet
	if err == nil {
		err = json.Unmarshal(data, &set)
	}
	var h *heldRelease
	if err == nil {
		h, err = s.checkRelease(set, release.Seen{})
	}
	if err != nil {
		s.logf("cbb: the release kept in %s: %v", releaseFile, err)
		return nil
	}
	return h
}

// takeRelease keeps a release when it checks out and its channel file is
// newer than the one held, and reports whether it did.
func (s *Service) takeRelease(set node.ReleaseSet) (bool, error) {
	cur := s.heldRelease()
	var seen release.Seen
	if cur != nil {
		seen = cur.seen
	}
	h, err := s.checkRelease(set, seen)
	if err != nil {
		return false, err
	}
	s.relMu.Lock()
	defer s.relMu.Unlock()
	if s.rel != nil && !h.order().After(s.rel.order()) && s.cfg.now().UnixMilli() < s.rel.expiresMS {
		return false, nil
	}
	data, err := json.Marshal(set)
	if err != nil {
		return false, err
	}
	if err := atomicfile.Write(filepath.Join(s.cfg.StateDir, releaseFile), data, 0o600); err != nil {
		s.logf("cbb: saving the release: %v", err)
	}
	s.rel = h
	if offered(h.version) {
		s.logf("cbb: CBB %s is available; cbb update installs it", h.version)
	}
	go s.pruneReleaseFiles()
	return true, nil
}

// putRelease takes a release that cbb update fetched, and sends it to the
// peers when it is newer than the one held.
func (s *Service) putRelease(set node.ReleaseSet) error {
	newer, err := s.takeRelease(set)
	if err != nil {
		return fmt.Errorf("the release does not check out: %w", err)
	}
	if !newer {
		return nil
	}
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd != nil {
		nd.SendRelease(&set)
	}
	return nil
}

// releaseStatus returns the newest release the group passed around, and
// that release again when this device should install it; "" for none.
func (s *Service) releaseStatus() (newest, available string) {
	h := s.heldRelease()
	if h == nil {
		return "", ""
	}
	if offered(h.version) {
		available = h.version
	}
	return h.version, available
}

// offered reports whether this device should install the release v: it
// is above this build's version. A development build is offered nothing,
// as cbb update installs over releases only.
func offered(v string) bool {
	own := update.TrimVersion(version.Version)
	return own != "dev" && release.Compare(v, own) > 0
}
