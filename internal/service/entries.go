// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/release"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/update"
)

// The signed list of the project's entry points (docs/protocol.md, section
// 16, "Entry points"): cbb update fetches it with its check, any member
// passes it on, and a string or QR code carries it between devices; the
// signature is what a device trusts, wherever it came from. A hub of the
// project's forwarder registers over VLESS through the ways in it names.

// entriesFile keeps the newest signed entry points, as the member protocol
// carries them.
const entriesFile = "entries.json"

// heldEntries is a signed list of entry points that checked out.
type heldEntries struct {
	set     node.EntriesSet
	seen    release.Seen // its own floors, apart from the release's
	entries release.Entries
}

func (h *heldEntries) order() node.ReleaseOrder {
	return node.ReleaseOrder{Keys: h.seen.KeysSeq, Channel: h.seen.EntriesSeq}
}

// entriesStore is the node's view of them.
type entriesStore struct{ s *Service }

func (e entriesStore) Current() (*node.EntriesSet, node.ReleaseOrder) {
	h := e.s.heldEntries()
	if h == nil {
		return nil, node.ReleaseOrder{}
	}
	return &h.set, h.order()
}

func (e entriesStore) Add(from group.DeviceID, set node.EntriesSet) bool {
	newer, err := e.s.takeEntries(set)
	if err != nil {
		e.s.logf("cbb: dropped the entry points %s sent: %v", orThis(from), err)
	}
	return newer
}

func (s *Service) checkEntries(set node.EntriesSet, seen release.Seen) (*heldEntries, error) {
	roots := s.releaseRoots()
	if len(roots) == 0 {
		return nil, update.ErrNoRoots
	}
	e, next, err := release.CheckEntries(set.Keys, set.Entries, roots, s.cfg.now(), seen)
	if err != nil {
		return nil, err
	}
	return &heldEntries{set: set, seen: next, entries: e}, nil
}

// heldEntries returns the entry points this device holds, nil for none or
// for a list that has expired. It reads the file the first time.
func (s *Service) heldEntries() *heldEntries {
	s.entMu.Lock()
	defer s.entMu.Unlock()
	if !s.entRan {
		s.entRan = true
		s.ent = s.loadEntries()
	}
	if s.ent == nil || s.cfg.now().UnixMilli() >= s.ent.entries.ExpiresMS {
		return nil
	}
	return s.ent
}

func (s *Service) loadEntries() *heldEntries {
	data, err := os.ReadFile(filepath.Join(s.cfg.StateDir, entriesFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var set node.EntriesSet
	if err == nil {
		err = json.Unmarshal(data, &set)
	}
	var h *heldEntries
	if err == nil {
		h, err = s.checkEntries(set, release.Seen{})
	}
	if err != nil {
		s.logf("cbb: the entry points kept in %s: %v", entriesFile, err)
		return nil
	}
	return h
}

// takeEntries keeps a list when it checks out and is newer than the one
// held, and reports whether it did.
func (s *Service) takeEntries(set node.EntriesSet) (bool, error) {
	var seen release.Seen
	if cur := s.heldEntries(); cur != nil {
		seen = cur.seen
	}
	h, err := s.checkEntries(set, seen)
	if err != nil {
		return false, err
	}
	s.entMu.Lock()
	defer s.entMu.Unlock()
	if s.ent != nil && !h.order().After(s.ent.order()) && s.cfg.now().UnixMilli() < s.ent.entries.ExpiresMS {
		return false, nil
	}
	data, err := json.Marshal(set)
	if err != nil {
		return false, err
	}
	if err := atomicfile.Write(filepath.Join(s.cfg.StateDir, entriesFile), data, 0o600); err != nil {
		s.logf("cbb: saving the entry points: %v", err)
	}
	s.ent = h
	return true, nil
}

// putEntries takes a list from cbb update or a string, and sends it to the
// peers when it is newer than the one held.
func (s *Service) putEntries(set node.EntriesSet) error {
	newer, err := s.takeEntries(set)
	if err != nil {
		return fmt.Errorf("the entry points do not check out: %w", err)
	}
	if !newer {
		return nil
	}
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd != nil {
		nd.SendEntries(&set)
	}
	return nil
}

// projectVLESS returns the ways in over VLESS to the project's forwarder,
// at addr, for a hub's registration: those the held entry points name,
// else the built-in one.
func (s *Service) projectVLESS(addr netip.Addr) []tunnel.VLESS {
	var ways []release.EntryVLESS
	if h := s.heldEntries(); h != nil {
		if f, ok := h.entries.Forwarder(forward.ProjectHost); ok {
			ways = f.VLESS
		}
	}
	return forward.ProjectWays(addr, ways)
}
