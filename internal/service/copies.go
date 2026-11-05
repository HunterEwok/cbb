// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"slices"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
)

// sealer is what this member seals its copies with and opens the others'
// with: its identity, whose member key signs, and its secret for sealed
// messages. The engine calls on it while it holds its own lock, so it is
// kept apart from s.mu, which is held around calls into the engine.
type sealer struct {
	id             *group.Identity
	secret, public []byte
}

// setSealer records the identity and the keys for sealed messages that
// copies are sealed and opened with.
func (s *Service) setSealer(id *group.Identity, secret, public []byte) {
	s.copyKeys.Store(&sealer{id: id, secret: secret, public: public})
}

// sealCopy seals and signs a copy this member made, to the devices of the
// group that read copies (docs/protocol.md, section 4, "Sealing"); the
// engine's Config.Seal.
func (s *Service) sealCopy(ev clip.Event) (*clip.Sealed, error) {
	k := s.copyKeys.Load()
	if k == nil || k.id == nil {
		return nil, s.errNoGroup()
	}
	s.recMu.Lock()
	var readers []clip.Reader
	if s.records != nil {
		readers = s.records.Readers(ev.Kind == clip.Secret)
	}
	s.recMu.Unlock()
	// This member reads its own copies, which a copy it gets back after
	// a restart needs, even while its record does not name its key yet.
	if k.public != nil && !slices.ContainsFunc(readers, func(r clip.Reader) bool { return r.ID == ev.Origin }) && len(readers) < clip.MaxReaders {
		readers = append(readers, clip.Reader{ID: ev.Origin, Seal: k.public})
	}
	if len(readers) == 0 {
		return nil, errors.New("no device of the group has a key for sealed messages yet; the copy stays on this device")
	}
	var issuer []byte
	if k.id.Issuer != nil {
		issuer = k.id.Issuer.Raw
	}
	key, blob := clip.NewKey(), (*clip.Blob)(nil)
	if ev.Media != nil {
		// copyMedia sealed the parts into the blob already, under the
		// copy's key.
		v, ok := s.ownCopies.Load(ev.Media)
		if !ok {
			return nil, errors.New("the copy's images and files were not sealed")
		}
		mc := v.(*mediaCopy)
		key, blob = mc.key, mc.blob
	}
	return clip.SealCopy(ev.ID, ev.Origin, ev.Time, k.id.Cert.Raw, issuer, readers,
		clip.Content{Kind: ev.Kind, Via: ev.Via, Text: ev.Text, Media: ev.Media}, blob, key, k.id.Key)
}

// takeCopy checks a copy a peer sent against the group's records and
// opens it when it is sealed to this member (docs/protocol.md, section 4,
// "Opening"); the node's Config.TakeCopy. A copy sealed to this member
// that does not open is kept and passed on unread, and logged.
func (s *Service) takeCopy(from group.DeviceID, c *clip.Sealed) (clip.Event, error) {
	s.recMu.Lock()
	err := errors.New("this device has no records of its group yet")
	if s.records != nil {
		err = s.records.CheckCopy(c, s.cfg.now())
	}
	s.recMu.Unlock()
	if err != nil {
		return clip.Event{}, err
	}
	k := s.copyKeys.Load()
	if k == nil || k.id == nil {
		return clip.Event{}, s.errNoGroup()
	}
	ev, err := clip.EventOf(c, string(k.id.ID), k.secret)
	if err != nil {
		s.logf("cbb: a copy from %s, passed on by %s, is sealed to this device but does not open: %v", c.Origin, from, err)
	}
	return ev, nil
}
