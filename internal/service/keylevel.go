// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"fmt"
	"slices"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/group"
)

// The group's key levels (docs/roadmap.md, "Key levels"): which keys may be
// the group's root, an admin or a hub.
const (
	LevelProven   = "proven"   // only keys that attestation proves are in hardware
	LevelHardware = "hardware" // keys in hardware, by the device's own word; the default
	LevelFiles    = "files"    // keys in files too, each time after a warning
)

// keyLevel returns the group's key level from its records.
func (s *Service) keyLevel() string {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return LevelHardware
	}
	if l := s.records.State().KeyLevel; l != "" {
		return l
	}
	return LevelHardware
}

// levelAllows tells whether the group's key level lets a device whose
// key is in store be the group's root, an admin or a hub. At the level
// "files", a key in a file needs consent, which the user gives after the
// warning that hint names how to give.
func levelAllows(level, store, name, hint string, consent bool) error {
	switch {
	case store == group.StoreRootless:
		return fmt.Errorf("%s is installed without root, so every program of its user can read its keys; such a device is never the group's root, an admin or a hub (D-79)", name)
	case level == LevelProven && store != group.StoreProven:
		return fmt.Errorf("attestation does not prove that %s keeps its key in hardware, and the group's key level lets only such keys be its root, an admin or a hub; on the root, cbb keys hardware lets keys in hardware by the device's own word too", name)
	case store != group.StoreFile:
		return nil
	case level != LevelFiles:
		return fmt.Errorf("%s keeps its keys in a file, and the group's key level lets only keys in hardware be its root, an admin or a hub; on the root, cbb keys files lets keys in files too, each time after a warning", name)
	case !consent:
		return fmt.Errorf("%s keeps its keys in a file, which a thief with it can copy and then act for it until another admin removes it; to allow it anyway, %s", name, hint)
	}
	return nil
}

// currentSettings returns what the newest settings record of the root
// whose key hash is root set, so that a new one keeps what it does not
// change: the state counts only the newest.
func (s *Service) currentSettings(root group.KeyHash) (delay *int64, level string) {
	var seq int64 = -1
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil, ""
	}
	for _, r := range s.records.All() {
		b, err := authority.ParseBody(r.Body)
		if err != nil || b.Type != group.RecordSettings || b.Signer != root || b.Seq <= seq {
			continue
		}
		seq, delay, level = b.Seq, b.TakeoverDelayMS, b.KeyLevel
	}
	return delay, level
}

// setKeyLevel signs, on the group's root, a settings record with the key
// level, keeping the takeover delay. It returns the admins and hubs that
// the new level would not let in, which stay until the user removes them.
func (s *Service) setKeyLevel(level string) ([]string, error) {
	if !slices.Contains(authority.KeyLevels, level) {
		return nil, fmt.Errorf("the key level is %s, %s or %s", LevelProven, LevelHardware, LevelFiles)
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return nil, s.errNoGroup()
	}
	if !id.IsRoot() {
		return nil, errors.New("only the group's root sets the key level")
	}
	if err := levelAllows(level, s.keyStore(id), "this device, the group's root,", "", true); err != nil {
		return nil, err
	}
	delay, _ := s.currentSettings(group.KeyHashOf(id.Root()))
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordSettings, TakeoverDelayMS: delay, KeyLevel: level})
	if err != nil {
		return nil, err
	}
	s.publish(nd, r)
	s.logf("cbb: the group's key level is %s now", level)
	devs, err := s.devices()
	if err != nil {
		return nil, nil
	}
	s.recMu.Lock()
	hubs := s.records.State().Hubs
	s.recMu.Unlock()
	var below []string
	for _, d := range devs {
		if (d.Admin || slices.Contains(hubs, d.ID)) && !d.Self && levelAllows(level, d.Store, d.Name, "", true) != nil {
			below = append(below, d.Name)
		}
	}
	return below, nil
}
