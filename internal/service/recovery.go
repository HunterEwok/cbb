// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/core"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/piv"
)

// recoverySheet is what a recovery sheet gives (docs/protocol.md, section
// 10, "The recovery sheet"): the recovery key, its key hash, and from the QR
// code only its admin CA and the group's tag.
type recoverySheet struct {
	Key   *ecdsa.PrivateKey
	Admin group.KeyHash
	Cert  []byte // DER; nil when the user typed the text
	Group string // empty when the user typed the text
}

// errRefusedSheet is a text that is no recovery key, as the core says why.
type errRefusedSheet struct{ reason, message string }

func (e *errRefusedSheet) Error() string { return e.message }

// readSheetWithCore reads text with the core's read_recovery_sheet.
func readSheetWithCore(text string) (*recoverySheet, error) {
	var out struct {
		Sheet *struct {
			PKCS8 []byte `json:"pkcs8"`
			Admin []byte `json:"admin"`
			Cert  []byte `json:"cert"`
			Group string `json:"group"`
		} `json:"sheet"`
		Refused *struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"refused"`
	}
	if err := core.Do("read_recovery_sheet", map[string]string{"text": text}, &out); err != nil {
		return nil, fmt.Errorf("reading the recovery key: %w", err)
	}
	switch {
	case out.Refused != nil:
		return nil, &errRefusedSheet{out.Refused.Reason, out.Refused.Message}
	case out.Sheet == nil || len(out.Sheet.Admin) != len(group.KeyHash{}):
		return nil, errors.New("reading the recovery key: the core's answer has no key")
	}
	k, err := x509.ParsePKCS8PrivateKey(out.Sheet.PKCS8)
	if err != nil {
		return nil, fmt.Errorf("reading the recovery key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("reading the recovery key: not a P-256 key")
	}
	s := &recoverySheet{Key: key, Cert: out.Sheet.Cert, Group: out.Sheet.Group}
	copy(s.Admin[:], out.Sheet.Admin)
	return s, nil
}

var errNoRecoveryKey = errors.New("the group has no recovery key: the root phone has not made one, or removed it")

// recoverGroup claims the group with its recovery key, on a computer of the
// group whose root is lost (docs/protocol.md, section 10, "The recovery
// key"): text is what the user typed or scanned from the sheet. The
// computer makes a new root and the recovery key signs the claim that names
// it; when the claim takes effect after the group's wait, unless the root
// cancels it, this computer is the group's root (finishTakeoverLocked). The
// recovery key itself is not kept.
func (s *Service) recoverGroup(text string) error {
	if err := s.canRecover(); err != nil {
		return err
	}
	read := s.cfg.readSheet
	if read == nil {
		read = readSheetWithCore
	}
	sheet, err := read(text)
	if err != nil {
		return err
	}
	return s.claimWithRecovery(sheet.Key, sheet.Admin, sheet.Cert, sheet.Group)
}

// recoverWithCard claims the group as recoverGroup does, with the recovery
// key on a YubiKey (internal/piv), which signs the claim after pin and, as
// the root phone set it, a touch: the key never leaves the card. The card's
// slot that holds it is the one whose certificate is the admin CA of the
// key the records name.
func (s *Service) recoverWithCard(pin string) error {
	if err := s.canRecover(); err != nil {
		return err
	}
	s.recMu.Lock()
	var named *authority.Hash
	if s.records != nil {
		named = s.records.State().Recovery
	}
	s.recMu.Unlock()
	if named == nil {
		return errNoRecoveryKey
	}
	open := s.cfg.openCard
	if open == nil {
		open = piv.Open
	}
	k, err := open(func(c *x509.Certificate) bool { return group.KeyHashOf(c) == *named })
	if err != nil {
		return err
	}
	defer k.Card.Close()
	if err := piv.Verify(k.Card, pin); err != nil {
		return err
	}
	signer, err := k.Signer()
	if err != nil {
		return err
	}
	return s.claimWithRecovery(signer, group.KeyHashOf(k.Cert), k.Cert.Raw, "")
}

// canRecover says why this device cannot claim the group with its recovery
// key, if it cannot.
func (s *Service) canRecover() error {
	if err := s.keysAllowed(); err != nil {
		return err
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	switch {
	case id == nil:
		return s.errNoGroup()
	case id.IsRoot():
		return errors.New("this device is the group's root already")
	case id.Claim != nil:
		return errors.New("this device's claim to take the group over is waiting already; cbb status shows the time left")
	}
	return nil
}

// claimWithRecovery claims the group for a new root of this device with
// key, the recovery key, whose admin CA has the key hash admin: cert is
// that admin CA as the sheet or the card gives it, used when the records
// do not carry it, and tag the group's tag from the sheet, if any.
func (s *Service) claimWithRecovery(key crypto.Signer, admin group.KeyHash, cert []byte, tag string) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return s.errNoGroup()
	}
	if tag != "" && tag != group.Tag(id.GroupCA.Cert) {
		return errors.New("this recovery key is of another group")
	}
	s.recMu.Lock()
	var named *authority.Hash
	var kept []byte
	var roots []*x509.Certificate
	if s.records != nil {
		named = s.records.State().Recovery
		roots = s.records.Roots()
		kept = recoveryCert(s.records.All(), roots, admin)
	}
	s.recMu.Unlock()
	switch {
	case named == nil:
		return errNoRecoveryKey
	case *named != admin:
		return errors.New("this is not the group's recovery key: the root phone made a new one since, which replaced it")
	}
	// The sheet's or the card's admin CA when a root of the group issued
	// it, else the one a recovery record carries under such a root.
	if !underARoot(cert, roots, admin) && kept != nil {
		cert = kept
	}
	adminCA, err := x509.ParseCertificate(cert)
	if err != nil {
		return fmt.Errorf("the recovery key's admin CA: %w", err)
	}
	if group.KeyHashOf(adminCA) != admin || !group.SameKey(key, adminCA.PublicKey) {
		return errors.New("the recovery key's admin CA is for another key")
	}
	newRoot, err := group.NewRootCA(s.cfg.now())
	if err != nil {
		return err
	}
	// The identity keeps the new root's key before the claim goes out, so
	// that the claim never takes effect for a key this device lost.
	s.mu.Lock()
	next, err := s.id.WithClaim(newRoot)
	if err == nil {
		err = s.setIdentityLocked(next)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.awaitRecords(next)
	r, err := s.signAs(key, adminCA, group.RecordBody{Type: group.RecordClaim, Root: newRoot.Cert.Raw, TimeMS: s.cfg.now().UnixMilli()})
	if err != nil {
		s.mu.Lock()
		if back, e := s.id.WithClaim(nil); e == nil {
			_ = s.setIdentityLocked(back)
		}
		s.mu.Unlock()
		return err
	}
	s.publish(nd, r)
	s.logf("cbb: claimed the group with its recovery key; this device becomes the root when the waiting time ends, unless the root cancels the claim")
	return nil
}

// recoveryCert is the admin CA a recovery record in rs gives for the key
// hash admin, the newest that one of roots, the group's roots, issued; nil
// if none does. Another admin may sign a recovery record too, which counts
// for nothing, so a CA no root issued is never taken from one.
func recoveryCert(rs []group.Record, roots []*x509.Certificate, admin group.KeyHash) []byte {
	var cert []byte
	var at int64
	for _, r := range rs {
		b, err := authority.ParseBody(r.Body)
		if err != nil || b.Type != group.RecordRecovery || b.Admin == nil || *b.Admin != admin || b.TimeMS < at {
			continue
		}
		if underARoot(b.Cert, roots, admin) {
			cert, at = b.Cert, b.TimeMS
		}
	}
	return bytes.Clone(cert)
}

// underARoot reports whether der is an admin CA for the key hash admin
// that one of roots issued.
func underARoot(der []byte, roots []*x509.Certificate, admin group.KeyHash) bool {
	c, err := x509.ParseCertificate(der)
	if err != nil || group.KeyHashOf(c) != admin {
		return false
	}
	for _, root := range roots {
		if c.CheckSignatureFrom(root) == nil {
			return true
		}
	}
	return false
}

// handOver hands the group to the admin target names, on the root
// (docs/protocol.md, section 10, "Handing the group over"): a handover
// record names its admin key, so that its claim takes effect at once,
// without the wait. The admin, a phone that joined this computer's group
// or a computer, then claims the group.
func (s *Service) handOver(target string) (string, error) {
	if err := s.keysAllowed(); err != nil {
		return "", err
	}
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || !id.IsRoot() {
		return "", errors.New("only the group's root hands the group over")
	}
	s.recMu.Lock()
	var admin *group.KeyHash
	for _, dev := range s.records.Devices() {
		if dev.ID == group.DeviceID(d.ID) && dev.AdminKey != nil && !dev.Frozen {
			k := *dev.AdminKey
			admin = &k
		}
	}
	s.recMu.Unlock()
	switch {
	case d.ID == string(id.ID):
		return "", errors.New("this device is the group's root already")
	case admin == nil:
		return "", fmt.Errorf("%s is no admin: make it one first (cbb admin), then hand the group over", d.Name)
	}
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordHandover, Admin: admin})
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	s.logf("cbb: handed the group over to %s (%s): its claim takes effect at once", d.Name, d.ID)
	return d.Name, nil
}
