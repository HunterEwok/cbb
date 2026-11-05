// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/HunterEwok/cbb/internal/benchtime"
	"github.com/HunterEwok/cbb/internal/group"
)

// renewEvery is how often a member checks whether certificates are due for
// renewal: its own, if it holds the CA keys, and those of the connected
// members. The renewal periods are months long, so twice a day is plenty.
// It is a variable for the tests; the bench's time-scaled build checks
// every few seconds.
var renewEvery = max(benchtime.D(12*time.Hour), 5*time.Second)

// renewLoop renews certificates when the group starts and every renewEvery
// after, until ctx is done.
func (s *Service) renewLoop(ctx context.Context) {
	t := time.NewTicker(renewEvery)
	defer t.Stop()
	for {
		s.renew(s.cfg.now())
		s.refreshCredential()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// renew renews this member's own certificates if they are due and it holds
// the CA keys, then sends renewed certificates to the connected members
// whose certificates are due.
func (s *Service) renew(now time.Time) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	if id == nil || nd == nil {
		s.mu.Unlock()
		return
	}
	next, changed, err := id.Renew(now)
	if err == nil && changed {
		err = s.setIdentityLocked(next)
	}
	s.mu.Unlock()
	switch {
	case err != nil:
		s.logf("cbb: renewing the certificates: %v", err)
	case changed:
		s.logf("cbb: renewed this member's certificates; the member certificate is valid until %s",
			next.Cert.NotAfter.UTC().Format(time.DateOnly))
	}
	nd.RenewPeers()
}

// certRenewed keeps a member certificate that another member renewed for
// this one, from issuer when an admin phone sent its admin CA.
func (s *Service) certRenewed(der, issuer []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil {
		return errors.New("this device is in no group")
	}
	// A new root may renew before this member has acted on its root
	// record.
	if err := s.adoptRootsLocked(); err != nil {
		return err
	}
	next, err := s.id.WithCertFrom(der, issuer)
	if err != nil {
		return err
	}
	// A certificate the records refuse, as from a removed admin, would
	// cut this member off. Its own device record may come after it, as
	// right after joining: the key is this member's, so that refuses
	// nothing.
	chain := []*x509.Certificate{next.Cert}
	if next.Issuer != nil {
		chain = append(chain, next.Issuer)
	}
	if err := s.allow(next.ID, chain); err != nil && !errors.Is(err, group.ErrNotListed) && !errors.Is(err, group.ErrStopped) {
		return err
	}
	if s.issuerRemoved(next) {
		return errors.New("its issuer was removed from the group")
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	s.logf("cbb: got a renewed member certificate, valid until %s", next.Cert.NotAfter.UTC().Format(time.DateOnly))
	return nil
}

// issuerRemoved reports whether the records revoke the key of the CA that
// issued id's certificate, an admin CA or a root. The certificates a
// removed admin or an old root issued stay valid for the devices its
// removal keeps (docs/protocol.md, section 10), but it renews none.
func (s *Service) issuerRemoved(id *group.Identity) bool {
	issuer := id.Issuer
	if issuer == nil {
		for _, r := range id.Trusted() {
			if id.Cert.CheckSignatureFrom(r) == nil {
				issuer = r
				break
			}
		}
	}
	s.recMu.Lock()
	defer s.recMu.Unlock()
	return issuer != nil && s.records != nil && s.records.Revoked(group.KeyHashOf(issuer))
}

// withAdminKey gives a member that is not the group's root the admin key
// that its hello offers, so that the root can make it an admin
// (docs/protocol.md, section 10). Without one it carries on as it is.
func (s *Service) withAdminKey(id *group.Identity) *group.Identity {
	if !id.NeedsAdminKey() {
		return id
	}
	if s.cfg.Rootless {
		s.logf("cbb: this device is installed without root, so it offers no admin key and cannot be made an admin")
		return id
	}
	if s.keysAllowed() != nil {
		s.logf("cbb: this device runs in a container, so it offers no admin key and cannot be made an admin; set %s=yes in its environment to allow it", keysInFileEnv)
		return id
	}
	next, err := id.WithAdminKey()
	if err == nil {
		err = next.Save(s.cfg.StateDir)
	}
	if err != nil {
		s.logf("cbb: making the admin key: %v", err)
		return id
	}
	return next
}

// becomeAdmin keeps the admin CA that the group's root sent for this
// member's admin key: from then on it admits and removes devices and
// renews certificates with it.
func (s *Service) becomeAdmin(der []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil {
		return errors.New("this device is in no group")
	}
	if s.id.AdminCA != nil && bytes.Equal(s.id.AdminCA.Raw, der) {
		return nil
	}
	if err := s.keysAllowed(); err != nil {
		return err
	}
	if err := s.adoptRootsLocked(); err != nil {
		return err
	}
	renewed := s.id.AdminCA != nil
	next, err := s.id.WithAdminCA(der, s.cfg.now())
	if err != nil {
		// It may be from a new root, or for a key a thaw lets in, whose
		// records come after it: try it again when they do.
		s.pendingAdminCA = der
		return err
	}
	// An admin CA that replaces one is from the current root, which
	// renews a CA of an earlier root; an earlier root's would split the
	// group's roots again.
	if renewed && next.AdminCA.CheckSignatureFrom(next.Root()) != nil {
		return errors.New("the new admin CA is not from the group's current root")
	}
	// An admin CA the records refuse, as from a root that handed the
	// group over, would make records nobody takes.
	if err := s.refusedAdminCA(next.AdminCA); err != nil {
		s.pendingAdminCA = der
		return err
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	s.pendingAdminCA = nil
	if renewed {
		s.logf("cbb: the group's root renewed this admin's CA, for the same key")
		return nil
	}
	s.logf("cbb: this device is now an admin of the group: it can admit and remove devices")
	return nil
}

// setIdentityLocked saves a renewed identity and starts using it: new member
// connections and the iPhone port present its certificates.
func (s *Service) setIdentityLocked(next *group.Identity) error {
	if err := next.Save(s.cfg.StateDir); err != nil {
		return err
	}
	s.id = next
	s.setSealer(next, s.sealSecret, s.sealPublic)
	s.nd.SetIdentity(next)
	return nil
}
