// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
	"github.com/HunterEwok/clipboardbridge/internal/core"
	"github.com/HunterEwok/clipboardbridge/internal/group"
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

// recoverGroup claims the group with its recovery key, on a computer of the
// group whose root is lost (docs/protocol.md, section 10, "The recovery
// key"): text is what the user typed or scanned from the sheet. The
// computer makes a new root and the recovery key signs the claim that names
// it; when the claim takes effect after the group's wait, unless the root
// cancels it, this computer is the group's root (finishTakeoverLocked). The
// recovery key itself is not kept.
func (s *Service) recoverGroup(text string) error {
	if err := s.keysAllowed(); err != nil {
		return err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	switch {
	case id == nil:
		return s.errNoGroup()
	case id.IsRoot():
		return errors.New("this device is the group's root already")
	case id.Legacy():
		return errors.New("this group is from before admin CAs and has no recovery key; upgrade it first (cbb upgrade)")
	case id.Claim != nil:
		return errors.New("this device's claim to take the group over is waiting already; cbb status shows the time left")
	}
	read := s.cfg.readSheet
	if read == nil {
		read = readSheetWithCore
	}
	sheet, err := read(text)
	if err != nil {
		return err
	}
	if sheet.Group != "" && sheet.Group != group.Tag(id.GroupCA.Cert) {
		return errors.New("this recovery key is of another group")
	}
	s.recMu.Lock()
	var named *authority.Hash
	var cert []byte
	if s.records != nil {
		named = s.records.State().Recovery
		cert = recoveryCert(s.records.All(), sheet.Admin)
	}
	s.recMu.Unlock()
	switch {
	case named == nil:
		return errors.New("the group has no recovery key: the root phone has not made one, or removed it")
	case *named != sheet.Admin:
		return errors.New("this is not the group's recovery key: the root phone made a new one since, which replaced it")
	}
	if cert == nil {
		cert = sheet.Cert
	}
	adminCA, err := x509.ParseCertificate(cert)
	if err != nil {
		return fmt.Errorf("the recovery key's admin CA: %w", err)
	}
	if group.KeyHashOf(adminCA) != sheet.Admin || !group.SameKey(sheet.Key, adminCA.PublicKey) {
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
	r, err := s.signAs(sheet.Key, adminCA, group.RecordBody{Type: group.RecordClaim, Root: newRoot.Cert.Raw, TimeMS: s.cfg.now().UnixMilli()})
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
// hash admin, the newest; nil if none does.
func recoveryCert(rs []group.Record, admin group.KeyHash) []byte {
	var cert []byte
	var at int64
	for _, r := range rs {
		b, err := authority.ParseBody(r.Body)
		if err != nil || b.Type != group.RecordRecovery || b.Admin == nil || *b.Admin != admin || b.TimeMS < at {
			continue
		}
		if c, err := x509.ParseCertificate(b.Cert); err == nil && group.KeyHashOf(c) == admin {
			cert, at = b.Cert, b.TimeMS
		}
	}
	return bytes.Clone(cert)
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
