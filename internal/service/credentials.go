// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/relay"
)

// credentialStore is the node's view of the group's server credentials
// (docs/protocol.md, section 18).
type credentialStore struct{ s *Service }

func (c credentialStore) All() []group.Credential {
	c.s.recMu.Lock()
	defer c.s.recMu.Unlock()
	if c.s.creds == nil {
		return nil
	}
	return c.s.creds.All()
}

func (c credentialStore) Add(from group.DeviceID, cs []group.Credential) []group.Credential {
	fresh := c.s.addCredentials(from, cs)
	if len(fresh) > 0 {
		// A new period wants this device's server key, and new server keys
		// new lists from the root or an admin.
		c.s.refreshCredential()
	}
	return fresh
}

// currentRootLocked returns the group's current root, the last of its
// path. s.recMu is held.
func (s *Service) currentRootLocked() *x509.Certificate {
	if roots := s.records.Roots(); len(roots) > 0 {
		return roots[len(roots)-1]
	}
	return s.creds.GroupCA()
}

// loadCredentials reads the group's credentials; a file that cannot be
// read leaves the set empty, since the peers give them again.
func (s *Service) loadCredentials(id *group.Identity, recs *group.Records) *group.Credentials {
	root := id.GroupCA.Cert
	if roots := recs.Roots(); len(roots) > 0 {
		root = roots[len(roots)-1]
	}
	creds, err := group.LoadCredentials(s.cfg.StateDir, id.GroupCA.Cert, root, recs.IsMember)
	if err != nil {
		s.logf("cbb: reading the server credentials: %v", err)
		return group.NewCredentials(id.GroupCA.Cert)
	}
	return creds
}

// loadServerKeys reads this device's keys for the servers; when the file
// cannot be read the device takes fresh keys, which only means new
// pseudonyms at the servers.
func (s *Service) loadServerKeys() *group.ServerKeys {
	k, err := group.LoadServerKeys(s.cfg.StateDir)
	if err != nil {
		s.logf("cbb: reading the keys for the servers: %v; making new ones", err)
		return group.NewServerKeys(s.cfg.StateDir)
	}
	return k
}

// addCredentials adds the valid credentials among cs, saves them, and
// returns those that were new.
func (s *Service) addCredentials(from group.DeviceID, cs []group.Credential) []group.Credential {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.creds == nil || s.records == nil {
		return nil
	}
	fresh, errs := s.creds.Add(s.currentRootLocked(), s.records.IsMember, cs)
	for _, err := range errs {
		s.logf("cbb: dropped a server credential from %s: %v", orThis(from), err)
	}
	if len(fresh) > 0 {
		if err := s.creds.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the server credentials: %v", err)
		}
		if s.credChanged != nil {
			close(s.credChanged)
			s.credChanged = nil
		}
	}
	return fresh
}

// credentialsChanged returns a channel that is closed when the group's
// server credentials change next.
func (s *Service) credentialsChanged() <-chan struct{} {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.credChanged == nil {
		s.credChanged = make(chan struct{})
	}
	return s.credChanged
}

// refreshCredential brings the group's server credentials up to date as
// far as this device can (docs/protocol.md, section 18), and sends what it
// signed to the peers: on the root, a new period when the one kept is due
// or a member that sent its server key left the group; on every member,
// its server key for the period; on the root, the hubs' and the members'
// credentials when they list other keys than the records and the server
// credentials say; and on an admin that the hubs' credential lists, the
// members' credential. On a hub it then brings the hub's WireGuard key up
// to the period.
func (s *Service) refreshCredential() {
	s.credMu.Lock()
	defer s.credMu.Unlock()
	defer s.rotateHubKey()
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return
	}
	var signed []group.Credential
	defer func() {
		if len(signed) > 0 && nd != nil {
			nd.SendCredentials(signed)
		}
	}()
	add := func(what string, c group.Credential, err error) bool {
		if err != nil {
			s.logf("cbb: signing the %s: %v", what, err)
			return false
		}
		signed = append(signed, s.addCredentials("", []group.Credential{c})...)
		return true
	}
	now := s.cfg.now()

	s.recMu.Lock()
	if s.creds == nil || s.records == nil || s.serverKeys == nil {
		s.recMu.Unlock()
		return
	}
	creds, keys, recs := s.creds, s.serverKeys, s.records
	root := s.currentRootLocked()
	s.recMu.Unlock()
	member := func(k group.KeyHash) bool {
		s.recMu.Lock()
		defer s.recMu.Unlock()
		return recs.IsMember(k)
	}

	// The period, on the root.
	ca := id.RootCA()
	isRoot := id.IsRoot() && ca != nil && ca.Cert.Equal(root)
	if isRoot && creds.PeriodStale(root, member, now) {
		tag, err := group.NewPeriodTag()
		if err != nil {
			s.logf("cbb: starting a new period: %v", err)
			return
		}
		pk, err := keys.Get(group.PeriodKey, tag)
		if err != nil {
			s.logf("cbb: making the period key: %v", err)
			return
		}
		var prev uint64
		if _, p, ok := creds.Period(root); ok {
			prev = p.Version
		}
		c, err := group.SignPeriod(group.Tag(id.GroupCA.Cert), tag, pk.Public(), group.NextVersion(prev, now), now, ca.Key)
		if !add("period", c, err) {
			return
		}
	}
	_, p, ok := creds.Period(root)
	if !ok {
		return
	}
	if err := keys.Keep(p.Tag); err != nil {
		s.logf("cbb: dropping the keys of the period before: %v", err)
	}

	// This device's server key for the period.
	sk, err := keys.Get(group.ServerKey, p.Tag)
	if err != nil {
		s.logf("cbb: making the key for the servers: %v", err)
		return
	}
	mine := group.PublicKeyHash(sk.Public())
	if got, ok := creds.Server(group.KeyHashOf(id.Cert)); !ok || got != mine {
		c, err := group.SignServer(p, sk.Public(), group.NextVersion(0, now), id.Key)
		if !add("server key", c, err) {
			return
		}
	}

	s.recMu.Lock()
	l := recs.CredentialLists()
	s.recMu.Unlock()
	hubs, admins, members := creds.ServerKeys(l.Hubs), creds.ServerKeys(l.Admins), creds.ServerKeys(l.Members)
	var signer crypto.Signer
	switch _, hb, listed := creds.Hubs(); {
	case isRoot && keys.Has(group.PeriodKey, p.Tag):
		pk, err := keys.Get(group.PeriodKey, p.Tag)
		if err != nil {
			return
		}
		if !listed || creds.ListStale(hb.Hubs, hubs, true) || creds.ListStale(hb.Admins, admins, false) {
			var prev uint64
			if listed {
				prev = hb.Version
			}
			c, err := group.SignHubs(p, hubs, admins, group.NextVersion(prev, now), pk)
			add("hubs' credential", c, err)
		}
		signer = pk
	case listed && slices.Contains(hb.Admins, mine):
		signer = sk
	default:
		return
	}
	if _, mb, ok := creds.Members(); !ok || creds.ListStale(mb.Members, members, false) {
		var prev uint64
		if ok {
			prev = mb.Version
		}
		c, err := group.SignMembers(p, members, group.NextVersion(prev, now), signer)
		add("members' credential", c, err)
	}
}

// serverKey returns this device's server key for the period kept and the
// period, or false before the root started one.
func (s *Service) serverKey() (crypto.Signer, *group.CredentialBody, bool) {
	s.recMu.Lock()
	if s.creds == nil || s.records == nil || s.serverKeys == nil {
		s.recMu.Unlock()
		return nil, nil, false
	}
	creds, keys, root := s.creds, s.serverKeys, s.currentRootLocked()
	s.recMu.Unlock()
	_, p, ok := creds.Period(root)
	if !ok || !keys.Has(group.ServerKey, p.Tag) {
		return nil, nil, false
	}
	k, err := keys.Get(group.ServerKey, p.Tag)
	if err != nil {
		return nil, nil, false
	}
	return k, p, true
}

// hubCredentials is what the hub registers with on its forwarder when the
// period's hubs' credential lists its server key: that credential. It
// returns nil otherwise, and the hub registers with its member
// certificate and the records.
func (s *Service) hubCredentials() []group.Credential {
	k, p, ok := s.serverKey()
	if !ok {
		return nil
	}
	c, hb, ok := s.creds.Hubs()
	if !ok || !s.cfg.now().Before(p.Expires()) || !slices.Contains(hb.Hubs, group.PublicKeyHash(k.Public())) {
		return nil
	}
	return []group.Credential{c}
}

// hubCert is the certificate the hub registers with when it has a
// credential: one of its server key, which names no device and no group.
func (s *Service) hubCert() (tls.Certificate, error) {
	k, _, ok := s.serverKey()
	if !ok {
		return tls.Certificate{}, errors.New("this device has no key for the servers yet")
	}
	return group.ServerCertificate(k)
}

// relayCredentials is what this device registers with on its relay when
// the period's members' credential lists its server key
// (docs/protocol.md, section 18); false otherwise, and it registers with
// its member certificate and the records.
func (s *Service) relayCredentials() (relay.Credentialed, bool) {
	k, p, ok := s.serverKey()
	if !ok || !s.cfg.now().Before(p.Expires()) {
		return relay.Credentialed{}, false
	}
	s.recMu.Lock()
	creds, root := s.creds, s.currentRootLocked()
	roots := append([]*x509.Certificate{creds.GroupCA()}, s.records.Roots()...)
	s.recMu.Unlock()
	hubs, _, ok := creds.Hubs()
	if !ok {
		return relay.Credentialed{}, false
	}
	members, mb, ok := creds.Members()
	mine := group.PublicKeyHash(k.Public())
	if !ok || !slices.Contains(mb.Members, mine) {
		return relay.Credentialed{}, false
	}
	period, _, _ := creds.Period(root)
	cert, err := group.ServerCertificate(k)
	if err != nil {
		return relay.Credentialed{}, false
	}
	out := relay.Credentialed{Cert: cert, Self: group.Pseudonym(mine), Creds: []group.Credential{hubs, members}, Period: period}
	for _, r := range roots {
		out.Roots = append(out.Roots, r.Raw)
	}
	return out, true
}

// relayPeer returns the device that a name at the relay stands for: a
// device ID itself, or a pseudonym, the hash of a server key that a
// member's server credential names.
func (s *Service) relayPeer(name string) (group.DeviceID, bool) {
	if _, err := group.ParseDeviceID(name); err == nil {
		return group.DeviceID(name), true
	}
	k, ok := group.ParsePseudonym(name)
	if !ok {
		return "", false
	}
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.creds == nil || s.records == nil {
		return "", false
	}
	m, ok := s.creds.MemberOfServer(k)
	if !ok {
		return "", false
	}
	return s.records.MemberOf(m)
}
