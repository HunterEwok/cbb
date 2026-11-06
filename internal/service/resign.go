// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/group"
)

// signedFile is the log of the records this device signed, in the state
// directory.
const signedFile = "signed.json"

// maxSigned is how many record IDs the log keeps, the newest: as many as a
// set keeps of one signer.
const maxSigned = 1024

// signedLog is what signed.json holds: the IDs of the records this device
// signed, and for each of them a root's resolve voided, the record it
// signed again. A device brought back from a backup has the log of the
// backup, so the records it signed before the backup was restored, which
// it cannot tell from a thief's, are not in it.
type signedLog struct {
	Signed []group.KeyHash          `json:"signed"`
	Again  map[string]group.KeyHash `json:"again,omitempty"`
}

func (l *signedLog) has(id group.KeyHash) bool {
	for _, k := range l.Signed {
		if k == id {
			return true
		}
	}
	return false
}

// loadSigned reads the log; signedMu is held.
func (s *Service) loadSigned() *signedLog {
	l := &signedLog{}
	data, err := os.ReadFile(filepath.Join(s.cfg.StateDir, signedFile))
	if err == nil {
		err = json.Unmarshal(data, l)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.logf("cbb: reading the log of the records this device signed: %v", err)
	}
	if l.Again == nil {
		l.Again = map[string]group.KeyHash{}
	}
	return l
}

// saveSigned writes the log; signedMu is held.
func (s *Service) saveSigned(l *signedLog) {
	if len(l.Signed) > maxSigned {
		l.Signed = l.Signed[len(l.Signed)-maxSigned:]
	}
	data, err := json.Marshal(l)
	if err == nil {
		err = atomicfile.Write(filepath.Join(s.cfg.StateDir, signedFile), data, 0o600)
	}
	if err != nil {
		s.logf("cbb: saving the log of the records this device signed: %v", err)
	}
}

// noteSigned adds a record this device signed to the log.
func (s *Service) noteSigned(id group.KeyHash) {
	s.signedMu.Lock()
	defer s.signedMu.Unlock()
	l := s.loadSigned()
	l.Signed = append(l.Signed, id)
	s.saveSigned(l)
}

// resignable are the types of record a device signs again after the root
// voided both histories of its key: what admits, removes, freezes and
// sets. A claim is made again by its user, and the apps sign checkpoints
// by themselves.
var resignable = map[string]bool{
	group.RecordDevice: true, group.RecordRevoke: true, group.RecordFreeze: true,
	group.RecordThaw: true, group.RecordHubs: true, group.RecordSettings: true, group.RecordCopies: true,
}

// resignVoided signs again, once the group's root voided both histories of
// this device's key, each voided record the log says this device signed,
// in their order, and sends them (docs/protocol.md, section 10, "Going on
// after two histories"). The voided records it did not sign, as a thief's
// or its own from before a backup was restored, it only counts in the log,
// for the user to do again what was theirs.
func (s *Service) resignVoided() {
	s.resignMu.Lock()
	defer s.resignMu.Unlock()
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return
	}
	ca, _ := id.Signer()
	if ca == nil {
		return
	}
	signer, err := authority.PublicKeyHash(ca.Key.Public())
	if err != nil {
		return
	}
	s.recMu.Lock()
	if s.records == nil || s.records.TwoHistories(signer) {
		s.recMu.Unlock()
		return
	}
	voided := s.records.Voided(signer)
	s.recMu.Unlock()
	if len(voided) == 0 {
		return
	}
	s.signedMu.Lock()
	l := s.loadSigned()
	s.signedMu.Unlock()
	var again []group.Record
	others := 0
	for _, r := range voided {
		old := r.ID()
		if _, done := l.Again[old.String()]; done {
			continue
		}
		if !l.has(old) {
			others++
			continue
		}
		b, err := authority.ParseBody(r.Body)
		if err != nil || !resignable[b.Type] {
			continue
		}
		b.Seq, b.Prev, b.Seen = 0, nil, nil
		nr, err := s.signRecord(id, b)
		if err != nil {
			s.logf("cbb: signing a voided record again: %v", err)
			break
		}
		l.Again[old.String()] = nr.ID()
		again = append(again, nr)
	}
	s.signedMu.Lock()
	cur := s.loadSigned()
	for k, v := range l.Again {
		cur.Again[k] = v
	}
	s.saveSigned(cur)
	s.signedMu.Unlock()
	if len(again) > 0 {
		s.publish(nd, again...)
		s.logf("cbb: the group's root voided both histories of this device's key; signed %d of its records again", len(again))
	}
	if others > 0 {
		s.logf("cbb: %d voided records of this device's key were not signed on this device since its last backup, or were a thief's; they stay void, so do again what was yours (cbb status lists the devices)", others)
	}
}
