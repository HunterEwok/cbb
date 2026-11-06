// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
)

// Admins of a group a computer created (docs/design.md, "Full members,
// admins and the operating system"): the root makes a full member an admin
// by certifying the admin key its hello offers.

// makeAdmin makes the device that target names an admin, on the group's
// root: it issues the admin CA for the admin key the device's hello
// offers, records it in the device's record and sends it. The device must
// be connected. A device whose keys sit in a
// file becomes an admin only with allowFileKey, which the user gives after
// a warning (docs/protocol.md, section 17).
func (s *Service) makeAdmin(target string, allowFileKey bool) (string, error) {
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	switch {
	case !id.IsRoot():
		return "", errors.New("only the group's root makes admins: run cbb admin on the computer that created the group, or use \"Make it an admin\" on the root phone")
	case d.Self:
		return "", errors.New("this device is the group's root, which is more than an admin")
	case d.Role != group.RoleFull:
		return "", fmt.Errorf("%s is no computer with the service; only those can be admins", d.Name)
	case d.Admin:
		return "", fmt.Errorf("%s is already an admin", d.Name)
	}
	var peer *node.Peer
	for _, p := range nd.Peers() {
		if string(p.ID) == d.ID {
			peer = &p
			break
		}
	}
	switch {
	case peer == nil:
		return "", fmt.Errorf("%s is not connected; it gets its admin CA over its connection, so start it and try again", d.Name)
	case peer.KeyStore == group.StoreRootless || d.Store == group.StoreRootless:
		return "", fmt.Errorf("%s is installed without root, so every program of its user can read its keys; such a device is never an admin (D-79)", d.Name)
	case peer.AdminKey == nil:
		return "", fmt.Errorf("%s offers no admin key: it runs an older CBB, or in a container that may not hold the group's keys (its log says so)", d.Name)
	}
	store, kind, proof := group.StoreOf(peer.KeyStore, group.RoleFull), "", ""
	if rec := s.deviceRecord(peer.ID); rec != nil && rec.Key == peer.Key && rec.Store == group.StoreProven {
		store, kind, proof = rec.Store, rec.Kind, rec.Proof
	}
	if err := levelAllows(s.keyLevel(), store, d.Name, "run cbb admin -allow-file-key "+target, allowFileKey); err != nil {
		return "", err
	}
	k, err := x509.ParsePKIXPublicKey(peer.AdminKey)
	pub, ok := k.(*ecdsa.PublicKey)
	if err != nil || !ok {
		return "", fmt.Errorf("the admin key that %s offers is no ECDSA key", d.Name)
	}
	adminCA, err := id.RootCA().IssueAdmin(peer.ID, pub, s.cfg.now())
	if err != nil {
		return "", err
	}
	adminKey := group.KeyHashOf(adminCA)
	// Its connection still shows no admin CA, and its hello the admin
	// key: renewAdminCAs, which may run as soon as the record below is in
	// the set, must not give it a second one. Noted before signing, and
	// undone if it never gets this one.
	s.mu.Lock()
	if s.adminCAsUnder == nil {
		s.adminCAsUnder = map[group.DeviceID]group.KeyHash{}
	}
	before, had := s.adminCAsUnder[peer.ID]
	s.adminCAsUnder[peer.ID] = group.KeyHashOf(id.Root())
	s.mu.Unlock()
	undo := func() {
		s.mu.Lock()
		if had {
			s.adminCAsUnder[peer.ID] = before
		} else {
			delete(s.adminCAsUnder, peer.ID)
		}
		s.mu.Unlock()
	}
	sealKey := peer.Seal
	if rec := s.deviceRecord(peer.ID); rec != nil && len(rec.Seal) > 0 {
		sealKey = rec.Seal
	}
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: string(peer.ID), Name: d.Name, Role: group.RoleFull,
		OS: d.OS, Key: &peer.Key, Admin: &adminKey, Store: store, Kind: kind, Proof: proof, Seal: sealKey})
	if err != nil {
		undo()
		return "", err
	}
	s.publish(nd, r)
	if !nd.SendAdmin(peer.ID, adminCA) {
		undo()
		return "", fmt.Errorf("%s left before it got its admin CA; it is listed as an admin, so run cbb admin again when it is back", d.Name)
	}
	s.logf("cbb: made %s (%s) an admin of the group", d.Name, d.ID)
	return d.Name, nil
}

// renewAdminCAs, on the group's root, gives each connected admin computer
// whose admin CA is from an earlier root, as after a takeover, a new admin
// CA for the same key from this root: the records name the key, so they
// stay as they are, and a takeover by that admin later hangs under this
// root, not under the earlier one (docs/protocol.md, section 10). The key
// comes from the admin CA in its chain, or from its hello, which offers it
// again then.
func (s *Service) renewAdminCAs(peers []node.Peer) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || nd == nil || !id.IsRoot() {
		return
	}
	root := group.KeyHashOf(id.Root())
	for _, p := range peers {
		admin := s.adminKeyOf(p.ID)
		if admin == nil {
			continue
		}
		var pub *ecdsa.PublicKey
		if len(p.Chain) > 1 && p.Chain[1].IsCA && group.KeyHashOf(p.Chain[1]) == *admin {
			if p.Chain[1].CheckSignatureFrom(id.Root()) == nil {
				continue // from this root already
			}
			pub, _ = p.Chain[1].PublicKey.(*ecdsa.PublicKey)
		} else if p.AdminKey != nil && group.KeyHash(sha256.Sum256(p.AdminKey)) == *admin {
			k, _ := x509.ParsePKIXPublicKey(p.AdminKey)
			pub, _ = k.(*ecdsa.PublicKey)
		}
		s.recMu.Lock()
		gone := s.records.Revoked(*admin) || s.records.Frozen(*admin)
		s.recMu.Unlock()
		s.mu.Lock()
		sent := s.adminCAsUnder[p.ID] == root
		s.mu.Unlock()
		if pub == nil || gone || sent {
			continue
		}
		ca, err := id.RootCA().IssueAdmin(p.ID, pub, s.cfg.now())
		if err != nil {
			s.logf("cbb: a new admin CA for %s: %v", p.ID, err)
			continue
		}
		// This root's own record of the admin lets it take the group over
		// from this root in turn.
		s.recMu.Lock()
		listed := s.records.AdminUnder(root, *admin)
		s.recMu.Unlock()
		if d := s.deviceRecord(p.ID); !listed && d != nil {
			r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: string(d.ID), Name: d.Name, Role: group.RoleFull,
				OS: d.OS, Key: &d.Key, Admin: admin, Powers: d.Powers, Commands: d.Commands, Store: d.Store, Kind: d.Kind, Proof: d.Proof, Seal: d.Seal})
			if err != nil {
				s.logf("cbb: recording the admin %s under this root: %v", p.ID, err)
				continue
			}
			s.publish(nd, r)
		}
		if nd.SendAdmin(p.ID, ca) {
			s.mu.Lock()
			if s.adminCAsUnder == nil {
				s.adminCAsUnder = map[group.DeviceID]group.KeyHash{}
			}
			s.adminCAsUnder[p.ID] = root
			s.mu.Unlock()
			s.logf("cbb: gave the admin %s (%s) a new admin CA from this root, for the same key", p.Name, p.ID)
		}
	}
}

// adminPeer reports whether the peer dev, whose verified chain is chain, is the
// group's root or one of its admins: its chain carries its own admin CA,
// or the records list it as the root or as an admin with that key.
func (s *Service) adminPeer(dev group.DeviceID, chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return false
	}
	if len(chain) > 1 && chain[1].IsCA && chain[1].Subject.CommonName == group.AdminName(dev) {
		// The chain is the verified one (node's peerChain), but the admin
		// CA is checked here too: it must have issued the leaf and stand
		// under one of the group's roots, or it proves nothing.
		return chain[0].CheckSignatureFrom(chain[1]) == nil && underRoot(id, chain[1]) &&
			!s.records.Revoked(group.KeyHashOf(chain[1])) && !s.records.Frozen(group.KeyHashOf(chain[1]))
	}
	// The root is the device whose own record has this key: an ID alone is
	// what a joining device picks itself.
	key := group.KeyHashOf(chain[0])
	if root, rootKey := s.records.RootMember(); root == dev && rootKey == key && !s.records.Revoked(key) {
		return true
	}
	for _, d := range s.records.Devices() {
		if d.ID == dev && d.Key == key && d.Admin {
			return true
		}
	}
	return false
}

// underRoot reports whether c is an admin CA that one of the roots of the
// group of id certified.
func underRoot(id *group.Identity, c *x509.Certificate) bool {
	if id == nil {
		return false
	}
	for _, root := range id.Trusted() {
		if group.CheckAdminCA(c, root) == nil {
			return true
		}
	}
	return false
}

// computerRooted reports whether the group's root is a computer, from the
// records.
func (s *Service) computerRooted() bool {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return false
	}
	root := s.records.RootDevice()
	for _, d := range s.records.Devices() {
		if d.ID == root {
			return d.Role == group.RoleFull
		}
	}
	return false
}

// findDevice returns the device that target names, by its device ID or its
// name (case-insensitive).
func (s *Service) findDevice(target string) (control.Device, error) {
	devs, err := s.devices()
	if err != nil {
		return control.Device{}, err
	}
	var match []control.Device
	for _, d := range devs {
		if d.ID == target {
			return d, nil
		}
		if strings.EqualFold(d.Name, target) {
			match = append(match, d)
		}
	}
	switch len(match) {
	case 0:
		return control.Device{}, fmt.Errorf("no device %q in the group; cbb status lists them", target)
	case 1:
		return match[0], nil
	}
	var ids []string
	for _, d := range match {
		ids = append(ids, d.ID)
	}
	return control.Device{}, fmt.Errorf("several devices are named %q; name one by its ID: %s", target, strings.Join(ids, ", "))
}

// takeOver takes the group over from its lost root, on an admin of a group
// whose root is a computer, as an admin phone does in a phone group
// (docs/protocol.md, section 10): it makes a new root and names it in a
// root record that its admin CA signs. Under the new root it then revokes
// the old root's key and the lost root's own key, keeping every device the
// old root admitted and every other admin, records itself as the group's
// root.
// setTakeoverDelay signs, on the group's root, a settings record with how
// long an admin's claim waits on each member before it takes effect: a
// duration from 0 to 7 days (docs/protocol.md, section 10, "Handing the group
// over").
func (s *Service) setTakeoverDelay(value string) error {
	d, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || d < 0 || d.Milliseconds() > authority.MaxDelay {
		return errors.New("the takeover delay is a duration from 0s to 168h, as 72h")
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || !id.IsRoot() {
		return errors.New("only the group's root sets how long a claim waits")
	}
	ms := d.Milliseconds()
	// The newest settings record counts whole, so this one keeps the level.
	_, level := s.currentSettings(group.KeyHashOf(id.Root()))
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordSettings, TakeoverDelayMS: &ms, KeyLevel: level})
	if err != nil {
		return err
	}
	s.publish(nd, r)
	s.logf("cbb: a claim to take the group over now waits %v on each member", d)
	return nil
}

// setIncoming signs, on the group's root or an admin, how long a copy from
// another device stays live after it arrives: a duration from 5s to 1h
// (docs/protocol.md, section 10, "The copies setting").
func (s *Service) setIncoming(value string) error {
	d, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || d.Milliseconds() < authority.MinIncoming || d.Milliseconds() > authority.MaxIncoming {
		return errors.New("how long an incoming copy stays live is a duration from 5s to 1h, as 1m")
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return s.errNoGroup()
	}
	if !id.IsRoot() && id.AdminCA == nil {
		return errors.New("only the group's root or an admin sets how long an incoming copy stays live")
	}
	ms := d.Milliseconds()
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordCopies, IncomingMS: &ms})
	if err != nil {
		return err
	}
	s.publish(nd, r)
	s.logf("cbb: a copy from another device now stays live for %v after it arrives", d)
	return nil
}

// setHubs signs, on the group's root or an admin with the power hub, the
// table of the group's main hubs: the devices targets name, in the order
// they serve, before the hubs the records give (docs/protocol.md, section 10, "The
// hubs table").
func (s *Service) setHubs(targets []string) error {
	if len(targets) == 0 || len(targets) > authority.MaxHubs {
		return fmt.Errorf("name 1 to %d hubs, in the order they serve", authority.MaxHubs)
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return s.errNoGroup()
	}
	s.recMu.Lock()
	may := s.records != nil && (id.IsRoot() || s.records.MayHost(id.ID))
	s.recMu.Unlock()
	if !may {
		return errors.New("only the group's root or an admin that may be a hub sets the main hubs")
	}
	var ids []string
	for _, t := range targets {
		d, err := s.findDevice(t)
		if err != nil {
			return err
		}
		if d.Role != group.RoleFull && d.Role != group.RolePhone {
			return fmt.Errorf("%s cannot be a hub: only a computer or a phone can", d.Name)
		}
		// Naming it in the table is the user's consent to a key in a file,
		// where the level allows one.
		if err := levelAllows(s.keyLevel(), d.Store, d.Name, "", true); err != nil {
			return err
		}
		if slices.Contains(ids, d.ID) {
			return fmt.Errorf("%s is named twice", d.Name)
		}
		ids = append(ids, d.ID)
	}
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordHubs, Hubs: ids})
	if err != nil {
		return err
	}
	s.publish(nd, r)
	s.logf("cbb: the group's main hubs are now %s", strings.Join(targets, ", "))
	return nil
}

func (s *Service) takeOver(target string) (string, error) {
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
	s.recMu.Lock()
	root := s.records.RootDevice()
	s.recMu.Unlock()
	switch {
	case id.IsRoot():
		return "", errors.New("this device is the group's root already")
	case !id.IsAdmin():
		return "", errors.New("only an admin takes the group over; this device is none")
	case !s.computerRooted():
		return "", errors.New("the group's root is a phone: an admin phone takes the group over, never a computer")
	case d.ID != string(root):
		return "", fmt.Errorf("%s is not the group's root; cbb status shows which device is", d.Name)
	case id.Claim != nil:
		return "", errors.New("this admin's claim to take the group over is waiting already; cbb status shows the time left")
	case id.StaleAdminCA():
		return "", errors.New("this admin's CA is from a root before the current one, so a new root from it would split the group; the current root renews it when they next meet, so take the group over on an admin that met it since")
	}
	s.recMu.Lock()
	var self group.Device
	for _, dev := range s.records.Devices() {
		if dev.ID == id.ID {
			self = dev
		}
	}
	s.recMu.Unlock()
	if !self.May(authority.PowerTakeover) {
		return "", errors.New("the root did not give this admin the power to take the group over; take it over on another admin")
	}
	newRoot, err := group.NewRootCA(s.cfg.now())
	if err != nil {
		return "", err
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
		return "", err
	}
	s.awaitRecords(next)
	r, err := s.signRecord(next, group.RecordBody{Type: group.RecordClaim, Root: newRoot.Cert.Raw})
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	s.logf("cbb: claimed the group from its root %s (%s); this device becomes the root when the waiting time ends, unless the root cancels the claim", d.Name, d.ID)
	return d.Name, nil
}

// finishTakeoverLocked makes this admin the group's root once the records
// make the new root of its claim the current root (roots): it holds that
// root's key from now on, and the records that follow (afterTakeover) go
// out once s.mu is free. A claim that was cancelled or became void is
// dropped. s.mu is held.
func (s *Service) finishTakeoverLocked(roots []*x509.Certificate) (bool, error) {
	id := s.id
	if id == nil || id.Claim == nil {
		return false, nil
	}
	claim := group.KeyHashOf(id.Claim.Cert)
	if len(roots) > 0 && roots[len(roots)-1].Equal(id.Claim.Cert) {
		oldRoot := group.KeyHashOf(id.Root())
		next, err := id.TakenOver(id.Claim, roots, s.cfg.now())
		if err != nil {
			return false, err
		}
		if err := s.setIdentityLocked(next); err != nil {
			return false, err
		}
		go s.afterTakeover(oldRoot)
		return true, nil
	}
	s.recMu.Lock()
	var state string
	for _, c := range s.records.State().Claims {
		if c.Root == claim {
			state = c.State
		}
	}
	s.recMu.Unlock()
	if state == "cancelled" || state == "void" {
		next, err := id.WithClaim(nil)
		if err != nil {
			return false, err
		}
		s.logf("cbb: the claim to take the group over is %s; this device stays an admin", state)
		return false, s.setIdentityLocked(next)
	}
	return false, nil
}

// afterTakeover signs, on the admin whose claim made it the group's root,
// the records a new root starts with (docs/protocol.md, section 10, "Handing the
// group over"): its own device that holds the root, the admins it keeps
// under the new root, and a removal of the old root's device.
func (s *Service) afterTakeover(oldRoot group.KeyHash) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || nd == nil || !id.IsRoot() {
		return
	}
	s.recMu.Lock()
	devs := s.records.Devices()
	lost := s.records.DeviceOfRoot(oldRoot)
	s.recMu.Unlock()
	var revoke group.RecordBody
	revoke.Type = group.RecordRevoke
	var bodies []group.RecordBody
	name := s.cfg.Name
	for _, dev := range devs {
		switch {
		case dev.ID == id.ID:
			name = dev.Name
		case dev.ID == lost:
			revoke.Keys = append(revoke.Keys, dev.Keys...)
		case dev.AdminKey != nil && !dev.Frozen:
			bodies = append(bodies, group.RecordBody{Type: group.RecordDevice, Device: string(dev.ID), Name: dev.Name, Role: dev.Role, OS: dev.OS,
				Key: &dev.Key, Admin: dev.AdminKey, Powers: dev.Powers, Commands: dev.Commands, Store: dev.Store, Kind: dev.Kind, Proof: dev.Proof, Seal: dev.Seal})
		}
	}
	if !group.ValidName(name) {
		name = defaultName(group.RoleFull, id.ID)
	}
	key := group.KeyHashOf(id.Cert)
	bodies = append([]group.RecordBody{{Type: group.RecordDevice, Device: string(id.ID), Name: name, Role: group.RoleFull, OS: s.cfg.OS, Key: &key, Store: group.KeyStoreOf(id.Key), Seal: s.sealPublic}}, bodies...)
	if len(revoke.Keys) > 0 {
		revoke.Keys = uniqueKeys(revoke.Keys)
		bodies = append(bodies, revoke)
	}
	// The state counts only the current root's settings, so the new root
	// signs the old root's again: the takeover delay and the key level.
	if delay, level := s.currentSettings(oldRoot); delay != nil || level != "" {
		bodies = append(bodies, group.RecordBody{Type: group.RecordSettings, TakeoverDelayMS: delay, KeyLevel: level})
	}
	var rs []group.Record
	for _, body := range bodies {
		r, err := s.signRecord(id, body)
		if err != nil {
			s.logf("cbb: a record of the new root: %v", err)
			continue
		}
		// Each record goes in before the next is signed, so that seq and
		// prev follow on.
		s.addRecords("", []group.Record{r})
		rs = append(rs, r)
	}
	nd.SendRecords(rs)
	s.settleRecords(rs)
	// The other admins' CAs are from the old root: each gets one from the
	// new root, so that a takeover by it later stays on this root.
	s.renewAdminCAs(nd.Peers())
	s.logf("cbb: the claim took effect; this device is the group's root now")
}
