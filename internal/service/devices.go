// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto"
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
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/seal"
)

// The group's devices list and revocation (docs/protocol.md, section 10):
// the member keeps the group's signed records, gives them to its peers,
// refuses the devices they revoke, and, where it is an admin (it holds the
// group CA key, or an admin CA from the root phone), records the devices it
// admits and removes devices on request.

// recordStore is the service as the node's store of records.
type recordStore struct{ s *Service }

func (r recordStore) Digest() string {
	r.s.recMu.Lock()
	defer r.s.recMu.Unlock()
	if r.s.records == nil {
		return ""
	}
	return r.s.records.Digest()
}

func (r recordStore) All() []group.Record {
	r.s.recMu.Lock()
	defer r.s.recMu.Unlock()
	if r.s.records == nil {
		return nil
	}
	return r.s.records.All()
}

func (r recordStore) Add(from group.DeviceID, rs []group.Record) []group.Record {
	return r.s.addRecords(from, rs)
}

func (r recordStore) Settle(fresh []group.Record) { r.s.settleRecords(fresh) }

// GroupCA is the group's first root, which a records-only connection
// with a device no record names yet sends it (node.Node's hello).
func (r recordStore) GroupCA() *x509.Certificate {
	r.s.recMu.Lock()
	defer r.s.recMu.Unlock()
	if r.s.records == nil {
		return nil
	}
	return r.s.records.GroupCA()
}

// loadRecords reads the records of the group of id; a file that cannot be
// read leaves the set empty, since the peers give the records again.
func (s *Service) loadRecords(id *group.Identity) *group.Records {
	recs, err := group.LoadRecords(s.cfg.StateDir, id.GroupCA.Cert)
	if err != nil {
		s.logf("cbb: reading the device records: %v", err)
		return group.NewRecords(id.GroupCA.Cert)
	}
	return recs
}

// addRecords adds the valid records among rs, saves them, and returns
// those that were new. settleRecords carries out what they change once
// they are on their way to the peers.
func (s *Service) addRecords(from group.DeviceID, rs []group.Record) []group.Record {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	recs := s.records
	if recs == nil {
		return nil
	}
	fresh, errs := recs.AddAll(rs)
	for _, err := range errs {
		s.logf("cbb: dropped a device record from %s: %v", orThis(from), err)
	}
	if len(fresh) > 0 {
		if err := recs.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the device records: %v", err)
		}
	}
	return fresh
}

// settleRecords follows records addRecords returned: a new root is
// trusted, and after a revocation the connections to devices that are now
// refused close. It runs after the records were queued for the peers, so
// that a revoked device gets the record that revokes it.
func (s *Service) settleRecords(fresh []group.Record) {
	revoked, rooted, thawed := false, false, false
	for _, r := range fresh {
		b, err := authority.ParseBody(r.Body)
		if err != nil {
			continue
		}
		// A freeze refuses devices as a revocation does; a resolve or a
		// checkpoint may undo either, and a claim, a resolve, a settings or
		// a recovery record may change the root.
		switch b.Type {
		case group.RecordRevoke, group.RecordFreeze:
			revoked = true
		case group.RecordThaw:
			revoked, thawed = true, true
		case group.RecordClaim, group.RecordResolve, group.RecordSettings, group.RecordCheckpoint, group.RecordRecovery:
			revoked, rooted = true, true
		}
	}
	// A claim may not count yet when it comes: it counts once the records
	// that make its signer an admin are in, and those may come later from
	// another peer. So the roots are checked after every record that can
	// change them. An admin CA that came before the device record naming
	// its key is tried again with any new records.
	s.mu.Lock()
	var err error
	if rooted || revoked {
		err = s.adoptRootsLocked()
	}
	pending := s.pendingAdminCA
	s.pendingAdminCA = nil
	s.mu.Unlock()
	if err != nil {
		s.logf("cbb: trusting the group's new root: %v", err)
	}
	if pending != nil {
		if err := s.becomeAdmin(pending); err != nil {
			s.logf("cbb: an admin CA that came before its records: %v", err)
		}
	}
	if revoked || rooted {
		s.afterRevocation()
	}
	if thawed || rooted {
		// Devices refused until now may be let in.
		s.redial()
	}
	if rooted {
		// A resolve may have voided both histories of this device's key.
		go s.resignVoided()
	}
	if len(fresh) > 0 {
		s.refreshCredential()
	}
	s.applyCopyRules()
}

// applyCopyRules gives the engine what the records say about the group's
// copies: how long an incoming copy stays live (docs/protocol.md, section
// 10, "The copies setting"), and whether the current event's origin is
// still a member. A copy from a device removed since, or from a root an
// admin took the group over from, is dropped then, so it is never written
// later (docs/protocol.md, section 4, "Writing the member's own clipboard").
func (s *Service) applyCopyRules() {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return
	}
	id, sealed := eng.CurrentCopy()
	s.recMu.Lock()
	if s.records == nil {
		s.recMu.Unlock()
		return
	}
	window := time.Duration(s.records.State().IncomingMS) * time.Millisecond
	var refused error
	if sealed != nil {
		refused = s.records.CheckCopy(sealed, s.cfg.now())
	}
	s.recMu.Unlock()
	eng.SetLiveWindow(window)
	if refused != nil && eng.Forget(id) {
		s.logf("cbb: the group's last copy, from %s, no longer counts and is dropped: %v", sealed.Origin, refused)
	}
}

// adoptRootsLocked makes the identity trust the roots the records lead to
// when they differ from its own, after a root record handed the group to a
// new root or a takeover stopped counting (docs/protocol.md, section 10).
// The roots are compared by content, not by number, so a root the records
// do not name never stays trusted. s.mu is held.
func (s *Service) adoptRootsLocked() error {
	if s.id == nil || s.nd == nil {
		return nil
	}
	s.recMu.Lock()
	roots, empty := s.records.Roots(), s.records.Len() == 0
	s.recMu.Unlock()
	// A set that is empty, as after a records file that could not be read,
	// says nothing yet: the peers give the records again.
	if empty {
		return nil
	}
	// An admin whose claim took effect becomes the root.
	if done, err := s.finishTakeoverLocked(roots); done || err != nil {
		return err
	}
	if slices.EqualFunc(roots, s.id.Roots, (*x509.Certificate).Equal) {
		return nil
	}
	if _, _, taken := s.takenOver(s.id); taken {
		// A root computer an admin took the group over from keeps its
		// root key, so that removing that admin undoes the takeover.
		return nil
	}
	next, err := s.id.WithRoots(roots)
	if err != nil {
		return err
	}
	if err := s.setIdentityLocked(next); err != nil {
		return err
	}
	if len(roots) == 0 {
		// A takeover from the first root stopped counting.
		s.logf("cbb: the group's root is its first one again")
		return nil
	}
	s.logf("cbb: the group has a new root, %s", roots[len(roots)-1].Subject.CommonName)
	return nil
}

func orThis(from group.DeviceID) string {
	if from == "" {
		return "this device"
	}
	return string(from)
}

// afterRevocation closes the connections to devices that are now refused,
// and tells whether this device itself was removed.
func (s *Service) afterRevocation() {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if nd != nil {
		nd.Recheck()
	}
	s.pruneTunnel()
	if id != nil {
		switch err := s.allow(id.ID, ownChain(id)); {
		case errors.Is(err, group.ErrStopped):
			s.logf("cbb: the group's records stop the exchange until its root decides (cbb status says why); members exchange records only")
		case errors.Is(err, group.ErrRecordsOnly):
			// Also a new group's root for a moment, before its own device
			// record is in: no one took it over then.
			if by := s.takenOverBy(id); by != "" {
				s.logf("cbb: %s took the group over from this computer, its root; if this computer is not lost, cbb remove %s undoes it", by, by)
			}
		case err != nil && s.frozen(id):
			s.logf("cbb: another admin froze this computer's admin key; the other members refuse it until the group's root or an admin phone unfreezes it")
		case err != nil:
			s.logf("cbb: this device was removed from the group; the other members refuse it until it pairs again")
		}
	}
}

// takenOverBy names the admin that took the group over from this root
// computer, "" when none did.
func (s *Service) takenOverBy(id *group.Identity) string {
	dev, _, ok := s.takenOver(id)
	if !ok {
		return ""
	}
	s.recMu.Lock()
	defer s.recMu.Unlock()
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return d.Name
		}
	}
	return string(dev)
}

// takenOver returns the device of the admin that took the group over from
// this root computer, and that admin's CA key (group.Records.TakenOver).
func (s *Service) takenOver(id *group.Identity) (group.DeviceID, group.KeyHash, bool) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil || id == nil || !id.IsRoot() {
		return "", group.KeyHash{}, false
	}
	return s.records.TakenOver(ownChain(id))
}

// ownChain is the chain this device presents: its member certificate and
// the admin CA that issued it, if one did.
func ownChain(id *group.Identity) []*x509.Certificate {
	if id.Issuer != nil {
		return []*x509.Certificate{id.Cert, id.Issuer}
	}
	return []*x509.Certificate{id.Cert}
}

// allow is the TLS check of member connections: it refuses devices that the
// records revoke.
func (s *Service) allow(_ group.DeviceID, chain []*x509.Certificate) error {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	err := s.records.Refused(chain)
	if err != nil {
		if _, _, ok := s.records.TakenOver(chain); ok {
			return group.ErrRecordsOnly
		}
	}
	return err
}

// refusedAdminCA returns why the records refuse an admin CA, nil when they
// take it or there are none (group.Records.RefusedAdminCA).
func (s *Service) refusedAdminCA(ca *x509.Certificate) error {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	return s.records.RefusedAdminCA(ca)
}

// signRecord signs the next record of this member's signer: the root's
// own key, or its admin key under its admin CA. A device record that makes
// an admin gives it a computer admin's powers unless body names them, and
// the root's record of its own device says that it holds the root
// (docs/protocol.md, section 10, "Who signs what").
func (s *Service) signRecord(id *group.Identity, body group.RecordBody) (group.Record, error) {
	ca, chain := id.Signer()
	if ca == nil {
		return group.Record{}, errNotAdmin
	}
	if s.frozen(id) {
		return group.Record{}, errFrozen
	}
	body.TimeMS = s.cfg.now().UnixMilli()
	if body.Type == group.RecordDevice {
		if body.Admin != nil && len(body.Powers) == 0 {
			body.Powers, body.Commands = computerAdminPowers(id.IsRoot()), slices.Clone(authority.Commands)
		}
		body.HoldsRoot = id.IsRoot() && body.Device == string(id.ID)
	}
	var adminCA *x509.Certificate
	if len(chain) > 0 {
		adminCA = chain[0]
	}
	return s.signAs(ca.Key, adminCA, body)
}

// signAs signs body, its time set, with key under adminCA (nil for the
// root's own key), puts the record in the set and keeps the set.
func (s *Service) signAs(key crypto.Signer, adminCA *x509.Certificate, body group.RecordBody) (group.Record, error) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return group.Record{}, s.errNoGroup()
	}
	r, err := s.records.Sign(body, key, adminCA)
	if err != nil {
		return group.Record{}, err
	}
	// The set holds the record before the lock is let go, so that the
	// next record this signer signs, here or in another goroutine, takes
	// the next seq and names it in prev: two records with one seq would be
	// two histories of the signer. publish sends it on.
	if _, err := s.records.Add(r); err != nil {
		return group.Record{}, err
	}
	if err := s.records.Save(s.cfg.StateDir); err != nil {
		s.logf("cbb: saving the device records: %v", err)
	}
	s.noteSigned(r.ID())
	return r, nil
}

// syncWait is how long a signer waits for another member's records before
// it signs anyway.
var syncWait = 10 * time.Second

// awaitRecords waits, before this device signs a record the user asked
// for, until it holds
// another member's records, at most syncWait, when the group lists another
// device: a device brought back from an old backup would otherwise sign
// with a seq it signed already, and the group would stop until its root
// resolves the two histories (docs/protocol.md, section 10, "Two numbers").
// When no member answers it signs anyway, and says so in the log.
func (s *Service) awaitRecords(id *group.Identity) {
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil || nd.Synced() {
		return
	}
	s.recMu.Lock()
	others := false
	if s.records != nil {
		for _, d := range s.records.Devices() {
			if d.ID != id.ID {
				others = true
				break
			}
		}
	}
	s.recMu.Unlock()
	if !others {
		return
	}
	for end := time.Now().Add(syncWait); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if nd.Synced() {
			return
		}
	}
	s.logf("cbb: no member of the group answered since this device started; signing anyway. If it was brought back from a backup, the group's root may have to resolve two histories (cbb resolve)")
}

// computerAdminPowers are the powers of an admin computer: takeover too
// when the root that makes it an admin is a computer (docs/records-v2.md,
// "Who signs what").
func computerAdminPowers(computerRoot bool) []string {
	p := []string{authority.PowerAdmit, authority.PowerFreeze, authority.PowerHub, authority.PowerRemove, authority.PowerRenew}
	if computerRoot {
		p = append(p, authority.PowerTakeover)
	}
	return p
}

var errFrozen = errors.New("another admin froze this computer's admin key: it changes nothing until the group's root or an admin phone unfreezes it")

// frozen reports whether the records freeze this device's admin CA.
func (s *Service) frozen(id *group.Identity) bool {
	ca, chain := id.Signer()
	if ca == nil || len(chain) == 0 {
		return false
	}
	s.recMu.Lock()
	defer s.recMu.Unlock()
	return s.records != nil && s.records.Frozen(group.KeyHashOf(ca.Cert))
}

var errNotAdmin = errors.New("only an admin can change the devices list: the group's root, an admin it made (cbb admin), or an admin phone")

// publish adds records made on this member and sends them to the peers.
func (s *Service) publish(nd *node.Node, rs ...group.Record) {
	// signRecord already put this member's own records in the set, so
	// they are sent and settled whether or not they are fresh here.
	s.addRecords("", rs)
	if len(rs) > 0 && nd != nil {
		nd.SendRecords(rs)
	}
	s.settleRecords(rs)
}

// recordDeviceAdmin records a device this member admitted, if it is an
// admin; adminCA is the device's admin CA when it is an admin too, as a
// phone the root admitted, and nil for none.
func (s *Service) recordDeviceAdmin(dev group.DeviceID, name, role, os string, key group.KeyHash, sealKey []byte, adminCA *x509.Certificate) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return
	}
	if ca, _ := id.Signer(); ca == nil {
		return
	}
	if !group.ValidName(name) {
		name = defaultName(role, dev)
	}
	s.awaitRecords(id)
	if seal.CheckPublicKey(sealKey) != nil {
		sealKey = nil
	}
	body := group.RecordBody{Type: group.RecordDevice, Device: string(dev), Name: name, Role: role, OS: os, Key: &key, Seal: sealKey}
	if adminCA != nil {
		a := group.KeyHashOf(adminCA)
		body.Admin = &a
	}
	r, err := s.signRecord(id, body)
	if err != nil {
		s.logf("cbb: recording %s in the devices list: %v", dev, err)
		return
	}
	s.publish(nd, r)
}

// recordAdmitted records a computer, a lite member or a phone that a
// pairing window admitted.
func (s *Service) recordAdmitted(res *pair.Result) {
	role := group.RoleFull
	switch {
	case res.Info.Role == pair.RoleLite:
		role = group.RoleLite
	case res.Info.Phone():
		role = group.RolePhone
	}
	s.recordDeviceAdmin(res.Device, res.Info.Name, role, res.Info.OS, group.KeyHashOf(res.Cert), res.Info.Seal, res.AdminCA)
}

// defaultName names a device that has no valid name: its role and the start
// of its ID.
func defaultName(role string, dev group.DeviceID) string {
	return role + " " + string(dev)[:min(8, len(dev))]
}

// roleOf maps a member role to the role in a device record.
func roleOf(r node.Role) string {
	switch r {
	case node.Full:
		return group.RoleFull
	case node.Phone:
		return group.RolePhone
	}
	return group.RoleLite
}

// ensureListed records this member, and the connected peers, in the devices
// list when they are not in it yet, as in a group made before the list
// existed. Only a member that holds the root's key does.
func (s *Service) ensureListed() {
	s.listMu.Lock()
	defer s.listMu.Unlock()
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || nd == nil || id.RootCA() == nil {
		return
	}
	s.recMu.Lock()
	listed := map[group.KeyHash]group.Device{}
	for _, d := range s.records.Devices() {
		listed[d.Key] = d
	}
	s.recMu.Unlock()
	var rs []group.Record
	add := func(dev group.DeviceID, name, role, os string, key group.KeyHash, store string, sealKey []byte) {
		if seal.CheckPublicKey(sealKey) != nil {
			sealKey = nil
		}
		body := group.RecordBody{Type: group.RecordDevice, Device: string(dev), Name: name, Role: role, OS: os, Key: &key, Store: store, Seal: sealKey}
		if d, ok := listed[key]; ok {
			// A computer whose record names no system or another one, as a
			// Windows PC that joined as a Linux member, or that its record
			// has in a file while its hello says hardware, as a computer
			// with its keys in a TPM recorded when it was admitted, or
			// whose hello says it is a rootless install (D-79): record
			// what its hello says, keeping the rest of its record. A
			// rootless device is no admin, and its keys prove nothing.
			newOS := os != "" && d.OS != os
			rootless := store == group.StoreRootless && d.Store != group.StoreRootless
			newStore := d.Store == group.StoreFile && store == group.StoreHardware || rootless
			// A lite member's record changes only to say rootless. A
			// computer's or a lite member's record takes the key for
			// sealed messages its hello offers (docs/protocol.md,
			// section 15).
			changed := d.Role == group.RoleFull && (newOS || newStore) || d.Role == group.RoleLite && rootless
			newSeal := sealKey != nil && !bytes.Equal(d.Seal, sealKey) && (d.Role == group.RoleFull || d.Role == group.RoleLite)
			if !changed && !newSeal {
				return
			}
			body.Name, body.Admin, body.Kind, body.Proof = d.Name, d.AdminKey, d.Kind, d.Proof
			body.Powers, body.Commands = d.Powers, d.Commands
			if !newSeal {
				body.Seal = d.Seal
			}
			if rootless {
				body.Admin, body.Kind, body.Proof, body.Powers, body.Commands = nil, "", "", nil, nil
			}
			if !newOS {
				body.OS = d.OS
			}
			if !newStore {
				body.Store = d.Store
			}
		}
		if !group.ValidName(body.Name) {
			body.Name = defaultName(role, dev)
		}
		r, err := s.signRecord(id, body)
		if err != nil {
			s.logf("cbb: recording %s in the devices list: %v", dev, err)
			return
		}
		rs = append(rs, r)
	}
	add(id.ID, s.cfg.Name, roleOf(s.cfg.Role), s.cfg.OS, group.KeyHashOf(id.Cert), s.keyStore(id), s.sealPublic)
	for _, p := range nd.Peers() {
		add(p.ID, p.Name, roleOf(p.Role), p.OS, p.Key, p.KeyStore, p.Seal)
	}
	if len(rs) > 0 {
		s.publish(nd, rs...)
	}
}

// trackSeen notes when the connected peers were last seen.
func (s *Service) trackSeen(peers []node.Peer) {
	now := s.cfg.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	online := map[group.DeviceID]bool{}
	for _, p := range peers {
		online[p.ID] = true
		s.seen[p.ID] = now
		if p.Device.Archive != "" {
			s.archives[p.ID] = p.Device.Archive
		}
		// A member with the lower device ID dials this one; when the
		// connection came up only once this one dialed back, the member
		// could not reach it, as a firewall here would do.
		if d := s.dialers[p.ID]; d != nil && d.fallback && !s.online[p.ID] {
			s.unreached[p.ID] = true
		}
	}
	for id := range s.online {
		if !online[id] {
			s.seen[id] = now // it was there until now
		}
	}
	s.online = online
}

// devices returns the devices list as cbb status shows it: the
// devices in the records, then this device and the connected peers that
// are not in them yet.
func (s *Service) devices() ([]control.Device, error) {
	s.mu.Lock()
	id, nd, eng := s.id, s.nd, s.eng
	seen := make(map[group.DeviceID]time.Time, len(s.seen))
	for k, v := range s.seen {
		seen[k] = v
	}
	s.mu.Unlock()
	if id == nil || nd == nil {
		return nil, s.errNoGroup()
	}
	peers := map[group.DeviceID]node.Peer{}
	for _, p := range nd.Peers() {
		peers[p.ID] = p
	}
	s.recMu.Lock()
	list := s.records.Devices()
	root := s.records.RootDevice()
	mayHub := map[group.DeviceID]bool{}
	for _, d := range list {
		mayHub[d.ID] = s.records.MayHost(d.ID)
	}
	s.recMu.Unlock()
	hubs := s.knownHubs(id.ID)

	frozen := map[group.DeviceID]bool{}
	forwardOnly := map[group.DeviceID]bool{}
	for _, d := range list {
		frozen[d.ID] = d.Frozen
		forwardOnly[d.ID] = d.ForwardOnly
	}
	selfFrozen := s.frozen(id)
	now := s.cfg.now()
	var out []control.Device
	shown := map[group.DeviceID]bool{}
	entry := func(dev group.DeviceID, name, role, os, store string, admin, listed bool) {
		d := control.Device{ID: string(dev), Name: name, Role: role, OS: os, Store: store, Listed: listed, Self: dev == id.ID, Root: dev == root, Frozen: frozen[dev], MayHub: mayHub[dev], ForwardOnly: forwardOnly[dev], Hub: hubs[dev]}
		d.Admin = admin
		if _, ok := peers[dev]; ok || d.Self {
			d.Online, d.LastSeenMS = true, now.UnixMilli()
		} else if t, ok := seen[dev]; ok {
			d.LastSeenMS = t.UnixMilli()
		}
		if d.Self {
			d.Admin = id.IsAdmin() && !selfFrozen
		}
		info := s.cfg.Device.Clean()
		if d.Self {
			d.Mode = eng.Mode().String()
			if muted, until := eng.Muted(); muted {
				d.Muted, d.MutedUntilMS = true, unixMS(until)
			}
		}
		if p, ok := peers[dev]; ok {
			info, d.Mode = p.Device, p.Mode
			d.Muted, d.MutedUntilMS = p.Muted, unixMS(p.MutedUntil)
		} else if !d.Self {
			info = group.DeviceInfo{}
		}
		d.Form, d.OSVersion, d.Version, d.MAC = info.Form, info.OSVersion, info.Version, info.MAC
		out = append(out, d)
		shown[dev] = true
	}
	for _, d := range list {
		os := d.OS
		if p, ok := peers[d.ID]; ok && p.OS != "" {
			os = p.OS
		}
		entry(d.ID, d.Name, d.Role, os, d.Store, d.Admin, true)
	}
	if !shown[id.ID] {
		entry(id.ID, s.cfg.Name, roleOf(s.cfg.Role), s.cfg.OS, s.keyStore(id), false, false)
	}
	for _, p := range nd.Peers() {
		if !shown[p.ID] {
			entry(p.ID, p.Name, roleOf(p.Role), p.OS, group.StoreOf(p.KeyStore, roleOf(p.Role)), false, false)
		}
	}
	return out, nil
}

// revoke removes a device, named by its device ID or its name, from the
// group: it signs a revocation of its key, which spreads to every member.
func (s *Service) revoke(target string) (string, error) {
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
	admin := s.adminKeyOf(group.DeviceID(d.ID))
	// The root an admin took the group over from removes that admin,
	// which undoes the takeover (docs/protocol.md, section 10).
	undo, undoCA, _ := s.takenOver(id)
	undoing := undo != "" && d.ID == string(undo)
	if undoing {
		admin = &undoCA
	}
	switch {
	case !id.IsAdmin():
		return "", errNotAdmin
	case d.Self:
		return "", errors.New("a device cannot remove itself; run cbb remove on another member")
	case d.ID == string(root) && !undoing && d.Role == group.RolePhone:
		return "", fmt.Errorf("%s holds the group's root; remove it on another admin phone, which takes the group over", d.Name)
	case d.ID == string(root) && !undoing:
		return "", fmt.Errorf("%s holds the group's root; run cbb takeover %s on an admin, which takes the group over and removes it", d.Name, d.Name)
	case admin != nil && !id.IsRoot():
		return "", fmt.Errorf("%s is an admin; only the group's root or an admin phone removes an admin, since this computer's admin key sits in a file", d.Name)
	}
	keys := s.keysOf(group.DeviceID(d.ID), nd)
	if len(keys) == 0 {
		return "", fmt.Errorf("the key of %s is unknown", d.ID)
	}
	// Every key the device ever had in the group goes, so none of them
	// stays a member nobody sees. An admin goes with its admin key; what
	// it signed before this record saw it stays (docs/records-v2.md,
	// "Removals and freezes keep what the author saw").
	body := group.RecordBody{Type: group.RecordRevoke, Keys: keys}
	if admin != nil {
		body.Keys = append(body.Keys, *admin)
	}
	body.Keys = uniqueKeys(body.Keys)
	s.awaitRecords(id)
	r, err := s.signRecord(id, body)
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	s.logf("cbb: removed %s (%s) from the group", d.Name, d.ID)
	return d.Name, nil
}

// rename gives the device that target names a new name: an admin signs a
// device record like its newest one with that name, and the newest record
// of a device names it everywhere (docs/protocol.md, section 10). It
// returns the old name.
func (s *Service) rename(target, name string) (string, error) {
	name = strings.TrimSpace(name)
	if !group.ValidName(name) {
		return "", errors.New("a device name has 1 to 64 characters and no control characters")
	}
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if !id.IsAdmin() {
		return "", errNotAdmin
	}
	rec := s.deviceRecord(group.DeviceID(d.ID))
	if rec == nil {
		return "", fmt.Errorf("%s is not in the devices list yet; rename it once it is", d.Name)
	}
	if rec.Name == name {
		return rec.Name, nil
	}
	// A device record that names an admin key, or of a watch, counts only
	// from a root's own key (docs/protocol.md, section 10, "Who signs what"),
	// and so does the root's own device's.
	s.recMu.Lock()
	rootDevice := s.records.RootDevice()
	s.recMu.Unlock()
	if !id.IsRoot() && (rec.AdminKey != nil || rec.Role == group.RoleWatch || rec.ID == rootDevice) {
		return "", fmt.Errorf("only the group's root renames %s: it is an admin or a watch, or the root's own device", rec.Name)
	}
	s.awaitRecords(id)
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: string(rec.ID), Name: name, Role: rec.Role,
		OS: rec.OS, Key: &rec.Key, Admin: rec.AdminKey, Powers: rec.Powers, Commands: rec.Commands, Store: rec.Store, Kind: rec.Kind, Proof: rec.Proof, Seal: rec.Seal, ForwardOnly: rec.ForwardOnly})
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	s.logf("cbb: renamed %s (%s) to %s", rec.Name, rec.ID, name)
	return rec.Name, nil
}

// freeze freezes (on true) or unfreezes the admin computer that target
// names (docs/design.md, "Who may remove an admin"). Any admin freezes
// another admin computer: from then on nothing the frozen admin signs
// counts, beyond the records it signed before, and its connections are
// refused. Only the root unfreezes it here; the root and the admin phones
// remove it with cbb remove or Remove.
func (s *Service) freeze(target string, on bool) (string, error) {
	d, err := s.findDevice(target)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	admin := s.adminKeyOf(group.DeviceID(d.ID))
	s.recMu.Lock()
	root := s.records.RootDevice()
	frozen := admin != nil && s.records.Frozen(*admin)
	s.recMu.Unlock()
	switch {
	case !id.IsAdmin():
		return "", errNotAdmin
	case d.Self:
		return "", errors.New("a device cannot freeze or unfreeze itself")
	case d.ID == string(root):
		return "", fmt.Errorf("%s holds the group's root, which nobody freezes", d.Name)
	case admin == nil || d.Role == group.RolePhone:
		return "", fmt.Errorf("%s is no admin computer; only those are frozen, and an ordinary device is removed with cbb remove", d.Name)
	case on && frozen:
		return "", fmt.Errorf("%s is frozen already", d.Name)
	case !on && !frozen:
		return "", fmt.Errorf("%s is not frozen", d.Name)
	case !on && !id.IsRoot():
		return "", errors.New("only the group's root or an admin phone unfreezes an admin, since this computer's admin key sits in a file")
	}
	// What it signed before this record saw it keeps counting, so the
	// devices it admitted stay; nothing it signs later does.
	body := group.RecordBody{Type: group.RecordFreeze, Keys: []group.KeyHash{*admin}}
	if !on {
		s.recMu.Lock()
		body.Type, body.Keys, body.Records = group.RecordThaw, nil, s.records.FreezesOf(*admin)
		s.recMu.Unlock()
	}
	s.awaitRecords(id)
	r, err := s.signRecord(id, body)
	if err != nil {
		return "", err
	}
	s.publish(nd, r)
	if on {
		s.logf("cbb: froze the admin %s (%s)", d.Name, d.ID)
	} else {
		s.logf("cbb: unfroze the admin %s (%s)", d.Name, d.ID)
	}
	return d.Name, nil
}

// uniqueKeys returns keys sorted as a record wants them, each once.
func uniqueKeys(keys []group.KeyHash) []group.KeyHash {
	keys = slices.Clone(keys)
	slices.SortFunc(keys, func(a, b group.KeyHash) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(keys)
}

// adminKeyOf returns the key of a listed device's admin CA, nil when it has
// none.
func (s *Service) adminKeyOf(dev group.DeviceID) *group.KeyHash {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return d.AdminKey
		}
	}
	return nil
}

// keysOf returns the keys of a device that are not revoked: every key its
// records name, and the key of its connection when it has one.
func (s *Service) keysOf(dev group.DeviceID, nd *node.Node) []group.KeyHash {
	s.recMu.Lock()
	list := s.records.Devices()
	s.recMu.Unlock()
	var keys []group.KeyHash
	for _, d := range list {
		if d.ID == dev {
			keys = append(keys, d.Keys...)
		}
	}
	for _, p := range nd.Peers() {
		if p.ID == dev && !slices.Contains(keys, p.Key) {
			keys = append(keys, p.Key)
		}
	}
	return keys
}

// idTaken reports whether a joining device may not take the device ID dev:
// a device record names it, with any key, or a member with it is connected
// (docs/protocol.md, section 6). A device that joins again gets a new ID.
func (s *Service) idTaken(dev group.DeviceID) bool {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id != nil && id.ID == dev {
		return true
	}
	s.recMu.Lock()
	known := s.records != nil && s.records.Known(dev)
	s.recMu.Unlock()
	if known || nd == nil {
		return known
	}
	return slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.ID == dev })
}

// deviceRecord returns the devices list's entry for dev, or nil.
func (s *Service) deviceRecord(dev group.DeviceID) *group.Device {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return &d
		}
	}
	return nil
}

// signCommand signs body for its receiver with ca, sealing its orders to
// the receiver's key when the receiver's record has one, so that only the
// receiver reads them (docs/protocol.md, section 15, "Sealed commands").
func (s *Service) signCommand(body group.CommandBody, ca *group.CA, chain []*x509.Certificate) (group.Record, error) {
	if d := s.deviceRecord(body.To); d != nil && len(d.Seal) > 0 {
		sealed, err := group.SealCommand(body, d.Seal)
		if err != nil {
			return group.Record{}, err
		}
		body = sealed
	}
	return group.SignCommand(body, ca.Key, chain...)
}

// loadSealSecretLocked loads this device's secret for sealed messages,
// making it on first use. A device without one works on, and gets
// commands only unsealed (docs/protocol.md, section 15).
func (s *Service) loadSealSecretLocked() {
	if s.sealSecret != nil {
		return
	}
	secret, err := group.LoadSealSecret(s.cfg.StateDir)
	if err == nil {
		var pub []byte
		if pub, err = seal.PublicKey(secret); err == nil {
			s.sealSecret, s.sealPublic = secret, pub
			return
		}
	}
	s.logf("cbb: the key for sealed commands: %v; commands come unsealed", err)
}

// noSecretsTo reports whether this member sends dev no secret, as the
// records say (group.Records.NoSecretsTo); false while it holds no records.
func (s *Service) noSecretsTo(dev group.DeviceID) bool {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	return s.records != nil && s.records.NoSecretsTo(dev)
}
