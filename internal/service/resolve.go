// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/group"
)

// resolveHistories, on the group's root, voids both histories of every key
// the state names in a conflict of two histories, with one resolve record
// that names each record of the seq where they part: the key then goes on
// from the record below, and its device signs again what it needs
// (docs/protocol.md, section 10, "Going on after two histories"). It
// returns the names of the devices whose keys they were.
func (s *Service) resolveHistories() ([]string, error) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return nil, s.errNoGroup()
	}
	if !id.IsRoot() {
		return nil, errors.New("only the group's root resolves two histories: run cbb resolve on the root computer, or resolve them on the root phone")
	}
	s.recMu.Lock()
	if s.records == nil {
		s.recMu.Unlock()
		return nil, s.errNoGroup()
	}
	var ids []group.KeyHash
	var who []string
	for _, c := range s.records.State().Conflicts {
		if c.Kind != authority.ConflictTwoHistories {
			continue
		}
		ids = append(ids, c.Records...)
		for _, k := range c.Signers {
			who = append(who, s.records.SignerName(k))
		}
	}
	s.recMu.Unlock()
	if len(ids) == 0 {
		return nil, errors.New("no key of the group signed two histories")
	}
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordResolve, Records: uniqueKeys(ids)})
	if err != nil {
		return nil, err
	}
	s.publish(nd, r)
	s.logf("cbb: voided both histories of %v", who)
	return who, nil
}
