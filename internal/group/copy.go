// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
)

// CheckCopy checks a sealed copy's origin against the records at now, as a
// member must before it passes the copy on or keeps it (docs/protocol.md,
// section 4, "Opening"): its certificate, through its issuer, verifies to a
// root on the path, the records take that chain, its key is one of the
// origin's device, and it signed the copy. The same is
// cbb_core::copy::Sealed::check.
func (s *Records) CheckCopy(c *clip.Sealed, now time.Time) error {
	if err := c.Validate(); err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(c.Cert)
	if err != nil {
		return fmt.Errorf("group: the copy's certificate: %w", err)
	}
	chain := []*x509.Certificate{leaf}
	inter := x509.NewCertPool()
	if len(c.Issuer) > 0 {
		issuer, err := x509.ParseCertificate(c.Issuer)
		if err != nil {
			return fmt.Errorf("group: the copy's issuer: %w", err)
		}
		chain = append(chain, issuer)
		inter.AddCert(issuer)
	}
	path := s.path()
	roots := x509.NewCertPool()
	for _, r := range path {
		roots.AddCert(r)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter,
		CurrentTime: verifyTime(path[len(path)-1], now),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("group: the copy's origin is not a member of the group: %w", err)
	}
	if dev, err := DeviceOf(leaf); err != nil || string(dev) != c.Origin {
		return errors.New("group: the copy's certificate is not of its origin")
	}
	if err := s.Refused(chain); err != nil {
		return fmt.Errorf("group: the copy's origin is refused: %w", err)
	}
	key := KeyHashOf(leaf)
	if !slices.ContainsFunc(s.Devices(), func(d Device) bool { return string(d.ID) == c.Origin && slices.Contains(d.Keys, key) }) {
		return errors.New("group: the copy's certificate is not one its origin's records name")
	}
	if !c.Verifies(leaf) {
		return errors.New("group: the copy's signature does not verify")
	}
	return nil
}

// Readers returns the devices a copy is sealed to by the records
// (docs/protocol.md, section 4, "Readers"): those with a key that stands,
// a key for sealed messages, the role full, phone or lite, not frozen, and
// not only passing copies on; for a secret, none that the records keep
// secrets from. The same is cbb_core::copy::readers.
func (s *Records) Readers(secret bool) []clip.Reader {
	var out []clip.Reader
	for _, d := range s.Devices() {
		switch {
		case len(d.Keys) == 0, len(d.Seal) == 0, d.Frozen, d.ForwardOnly:
		case d.Role != RoleFull && d.Role != RolePhone && d.Role != RoleLite:
		case secret && s.NoSecretsTo(d.ID):
		default:
			out = append(out, clip.Reader{ID: string(d.ID), Seal: d.Seal})
		}
	}
	slices.SortFunc(out, func(a, b clip.Reader) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	if len(out) > clip.MaxReaders {
		out = out[:clip.MaxReaders]
	}
	return out
}
