// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/authority"
	"github.com/HunterEwok/clipboardbridge/internal/core"
	"github.com/HunterEwok/clipboardbridge/internal/strict"
)

// RecordsFileName is the name of the records file in the state directory.
const RecordsFileName = "records.json"

// Limits of the record set (docs/records-v2.md): a member keeps at most
// MaxPerSigner records of one signer, waiting ones included, and
// MaxRecords in all.
const (
	MaxRecords   = 4096
	MaxPerSigner = 1024
)

// Record types (docs/protocol.md, section 10, "Types").
const (
	RecordDevice     = authority.TypeDevice
	RecordRevoke     = authority.TypeRevoke
	RecordFreeze     = authority.TypeFreeze
	RecordThaw       = authority.TypeThaw
	RecordClaim      = authority.TypeClaim
	RecordResolve    = authority.TypeResolve
	RecordSettings   = authority.TypeSettings
	RecordCheckpoint = authority.TypeCheckpoint
	RecordHubs       = authority.TypeHubs
	RecordRecovery   = authority.TypeRecovery
	RecordHandover   = authority.TypeHandover
)

// Device roles in device records: the member roles, shortcut for an
// iPhone without the app that uses the shortcut and its token, and watch
// for a watch with an admin key of its own, which the root certified and
// which signs only a few emergency actions (docs/protocol.md, section 10,
// rule 8).
const (
	RoleFull     = "full"
	RolePhone    = "phone"
	RoleLite     = "lite"
	RoleShortcut = "shortcut"
	RoleWatch    = "watch"
)

// Where a device's keys live, as its device record says (docs/protocol.md,
// section 17): in a file, which a thief with the device can copy, or in
// hardware that never lets them out (the Secure Enclave, the Android
// Keystore, a TPM), and proven there when the root checked an attestation
// of the key; rootless for a rootless install, whose keys are in a file
// that every program of its user may read (D-79).
const (
	StoreFile     = "file"
	StoreHardware = "hardware"
	StoreProven   = "proven"
	StoreRootless = "rootless"
)

// StoreOf reads the store field of a device record of role. A record
// without one, made before 0.6, or with a value this version does not
// know, counts as a phone's in hardware and any other device's in a file,
// as those versions kept them.
func StoreOf(store, role string) string {
	switch store {
	case StoreFile, StoreHardware, StoreProven, StoreRootless:
		return store
	}
	if role == RolePhone || role == RoleWatch {
		return StoreHardware
	}
	return StoreFile
}

// Operating systems in device records, hellos and the pairing Info: what
// the device runs, shown and never trusted for anything else.
const (
	OSLinux   = "linux"
	OSWindows = "windows"
	OSMacOS   = "macos"
	OSiOS     = "ios"
	OSAndroid = "android"
	OSWatchOS = "watchos"
	OSWearOS  = "wearos"
	OSNone    = "none" // firmware without an operating system
)

// ValidOS reports whether os names a known operating system.
func ValidOS(os string) bool {
	switch os {
	case OSLinux, OSWindows, OSMacOS, OSiOS, OSAndroid, OSWatchOS, OSWearOS, OSNone:
		return true
	}
	return false
}

// OSName names an operating system for the user: "Linux", "Windows",
// "macOS", "iOS", "Android", "watchOS", "Wear OS", "device" for firmware,
// "?" when unknown.
func OSName(os string) string {
	switch os {
	case OSLinux:
		return "Linux"
	case OSWindows:
		return "Windows"
	case OSMacOS:
		return "macOS"
	case OSiOS:
		return "iOS"
	case OSAndroid:
		return "Android"
	case OSWatchOS:
		return "watchOS"
	case OSWearOS:
		return "Wear OS"
	case OSNone:
		return "device"
	}
	return "?"
}

// A KeyHash names a key in records: SHA-256 over a SubjectPublicKeyInfo, or
// over the 16 bytes of a phone ID for an iPhone's token; also a record ID.
type KeyHash = authority.Hash

// KeyHashOf returns the key hash of a certificate's key.
func KeyHashOf(cert *x509.Certificate) KeyHash { return sha256.Sum256(cert.RawSubjectPublicKeyInfo) }

// PhoneKeyHash returns the key hash that names an iPhone's token.
func PhoneKeyHash(phoneID []byte) KeyHash { return sha256.Sum256(phoneID) }

// A RecordBody is what a record says (docs/protocol.md, section 10, "Records").
type RecordBody = authority.Body

// A Record is a signed record body: the body's exact bytes, an ECDSA
// signature over them, and the admin CA that certifies the signing key
// (none when a root's own key signed).
type Record = authority.Record

// ValidName reports whether s is a device name: 1 to 64 bytes of UTF-8
// without control characters.
func ValidName(s string) bool { return authority.ValidName(s) }

// Records is the set of a group's records. What it says depends on the
// records alone, never on the order in which they were added, and on the
// member's clock for the claims it waits on (docs/records-v2.md). It is
// not safe for concurrent use.
type Records struct {
	groupCA *x509.Certificate
	tag     string
	// recs holds each record once, by body and signature; bySigner counts
	// each signer's records (MaxPerSigner).
	recs     map[held]Record
	bySigner map[KeyHash]int
	// roots are the keys records may be signed with without an admin CA:
	// the group CA and the new root of every claim in the set.
	roots map[KeyHash]*x509.Certificate
	// firstSeen is when, on now's clock, the set first held each claim.
	firstSeen map[KeyHash]int64
	now       func() time.Time
	// st is the state, worked out on first use after a change; at is the
	// time it was worked out at, since a waiting claim changes it with time.
	st *authority.State
	at time.Time
}

type held struct {
	id  KeyHash
	sig string
}

// NewRecords returns an empty set for the group of groupCA, the group's
// first root, which names the group for good.
func NewRecords(groupCA *x509.Certificate) *Records {
	return &Records{
		groupCA:   groupCA,
		tag:       Tag(groupCA),
		recs:      map[held]Record{},
		bySigner:  map[KeyHash]int{},
		roots:     map[KeyHash]*x509.Certificate{KeyHashOf(groupCA): groupCA},
		firstSeen: map[KeyHash]int64{},
		now:       time.Now,
	}
}

// SetClock sets the clock the set counts a claim's wait by.
func (s *Records) SetClock(now func() time.Time) {
	s.now = now
	s.st = nil
}

// Len returns the number of records.
func (s *Records) Len() int { return len(s.recs) }

// Has reports whether the set holds exactly the record r.
func (s *Records) Has(r Record) bool {
	_, ok := s.recs[held{r.ID(), string(r.Sig)}]
	return ok
}

// Add checks a record and adds it. It reports whether the record was new.
// A record that is not of this group, does not read, or whose signature
// does not verify with a root the set knows or its admin CA is an error;
// whether its signer may sign it is for the evaluation.
func (s *Records) Add(r Record) (bool, error) {
	if s.Has(r) {
		return false, nil
	}
	sr, err := authority.Verify(r, func(h KeyHash) crypto.PublicKey {
		if c := s.roots[h]; c != nil {
			return c.PublicKey
		}
		return nil
	})
	if err != nil {
		signer, ok := s.laterVersion(r)
		if !ok {
			return false, fmt.Errorf("group: %w", err)
		}
		// A record of a later version is kept and passed on, never
		// applied; the state lists it when its signer may raise the
		// signal (docs/protocol.md, section 10, "Records of a later version").
		if s.bySigner[signer] >= MaxPerSigner || len(s.recs) >= MaxRecords {
			return false, errors.New("group: too many records")
		}
		if r.Chain == nil {
			r.Chain = [][]byte{}
		}
		s.recs[held{r.ID(), string(r.Sig)}] = r
		s.bySigner[signer]++
		s.st = nil
		return true, nil
	}
	if sr.Body.Group != s.tag {
		return false, errors.New("group: a record of another group")
	}
	if sr.AdminCA != nil && !s.underRoot(sr.AdminCA) {
		return false, errors.New("group: a record's admin CA is from no root of the group")
	}
	if s.bySigner[sr.Body.Signer] >= MaxPerSigner {
		return false, errors.New("group: too many records from one signer")
	}
	// Past MaxRecords the set still takes up to MaxPerSigner records of a
	// root's own key on the path, so that admins that fill it leave room
	// for the root to remove them.
	if n := len(s.recs); n >= MaxRecords && (n >= MaxRecords+MaxPerSigner || len(r.Chain) > 0 || !s.onPath(sr.Body.Signer)) {
		return false, errors.New("group: too many records")
	}
	if r.Chain == nil {
		r.Chain = [][]byte{}
	}
	s.recs[held{sr.ID, string(r.Sig)}] = r
	s.bySigner[sr.Body.Signer]++
	if sr.Body.Type == RecordClaim {
		if c, err := x509.ParseCertificate(sr.Body.Root); err == nil {
			s.roots[KeyHashOf(c)] = c
		}
		if _, ok := s.firstSeen[sr.ID]; !ok {
			s.firstSeen[sr.ID] = s.now().UnixMilli()
		}
	}
	s.st = nil
	return true, nil
}

// underRoot reports whether the admin CA ca is signed by a root the set
// knows: the group CA or the new root of a claim in it.
func (s *Records) underRoot(ca *x509.Certificate) bool {
	for _, root := range s.roots {
		if ca.CheckSignatureFrom(root) == nil {
			return true
		}
	}
	return false
}

// laterVersion reports whether r is a record of a later version that a
// member keeps: a canonical body of at most MaxBody bytes, v from 3 to
// 2^31-1, this group's tag, and a signature that verifies with a root the
// set knows (no chain) or with its admin CA. Whether its signer may raise
// the signal is for the evaluation. It returns the signer.
func (s *Records) laterVersion(r Record) (KeyHash, bool) {
	if len(r.Body) > authority.MaxBody || strict.CheckCanonical(r.Body, "v", "group", "signer") != nil {
		return KeyHash{}, false
	}
	var b struct {
		V      json.RawMessage `json:"v"`
		Group  any             `json:"group"`
		Signer KeyHash         `json:"signer"`
	}
	if json.Unmarshal(r.Body, &b) != nil || b.Group != s.tag {
		return KeyHash{}, false
	}
	v, err := strconv.ParseInt(string(b.V), 10, 64)
	if err != nil || v <= 2 || v > authority.MaxSeq {
		return KeyHash{}, false
	}
	var pub crypto.PublicKey
	switch len(r.Chain) {
	case 0:
		if c := s.roots[b.Signer]; c != nil {
			pub = c.PublicKey
		}
	case 1:
		if ca, err := x509.ParseCertificate(r.Chain[0]); err == nil && KeyHashOf(ca) == b.Signer && s.underRoot(ca) {
			pub = ca.PublicKey
		}
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	digest := sha256.Sum256(r.Body)
	if !ok || !ecdsa.VerifyASN1(ec, digest[:], r.Sig) {
		return KeyHash{}, false
	}
	return b.Signer, true
}

// AddAll adds the valid records among rs and returns those that were new,
// and an error for each record that is not valid. A record signed by a
// claim's new root is taken once the claim is in the set, so the result
// does not depend on the order of rs.
func (s *Records) AddAll(rs []Record) (fresh []Record, errs []error) {
	pending := rs
	for {
		var rest []Record
		errs = errs[:0]
		roots := len(s.roots)
		for _, r := range pending {
			isNew, err := s.Add(r)
			switch {
			case err != nil:
				rest = append(rest, r)
				errs = append(errs, err)
			case isNew:
				fresh = append(fresh, r)
			}
		}
		if len(s.roots) == roots || len(rest) == 0 {
			return fresh, errs
		}
		pending = rest
	}
}

// All returns every record, sorted by ID and then signature.
func (s *Records) All() []Record {
	keys := make([]held, 0, len(s.recs))
	for k := range s.recs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c := bytes.Compare(keys[i].id[:], keys[j].id[:]); c != 0 {
			return c < 0
		}
		return keys[i].sig < keys[j].sig
	})
	out := make([]Record, len(keys))
	for i, k := range keys {
		out[i] = s.recs[k]
	}
	return out
}

// bodies returns the body of every record that reads, with its ID.
func (s *Records) bodies() []parsed {
	var out []parsed
	for _, r := range s.All() {
		if b, err := authority.ParseBody(r.Body); err == nil {
			out = append(out, parsed{r.ID(), b, r})
		}
	}
	return out
}

type parsed struct {
	id KeyHash
	b  RecordBody
	r  Record
}

// State returns what the records say (docs/protocol.md, section 10, "The state"),
// from the Rust core when the build links it.
func (s *Records) State() *authority.State {
	now := s.now()
	if s.st != nil && (len(s.st.Claims) == 0 || now.Sub(s.at) < time.Second) {
		return s.st
	}
	st, err := core.Evaluate(authority.Input{
		GroupCA:   s.groupCA,
		Group:     s.tag,
		Records:   s.All(),
		NowMS:     now.UnixMilli(),
		FirstSeen: maps.Clone(s.firstSeen),
	})
	if err != nil {
		// The evaluation refuses only a broken input, such as a group CA
		// it cannot read: nothing counts then, and the group stops.
		st = &authority.State{Roots: []KeyHash{KeyHashOf(s.groupCA)}, Stop: authority.StopFull}
	}
	s.st, s.at = st, now
	return st
}

// Stop returns how far the records stop the exchange: "none", "secrets"
// or "full" (docs/protocol.md, section 10, "Stopping the exchange").
func (s *Records) Stop() string { return s.State().Stop }

// path returns the roots on the path as certificates, the group CA first.
func (s *Records) path() []*x509.Certificate {
	var out []*x509.Certificate
	for _, h := range s.State().Roots {
		if c := s.roots[h]; c != nil {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		out = []*x509.Certificate{s.groupCA}
	}
	return out
}

// onPath reports whether k is the key of a root on the path.
func (s *Records) onPath(k KeyHash) bool {
	return slices.Contains(s.State().Roots, k)
}

// Roots returns the roots that took the group over from the group CA, in
// order; the last is the current root. It is empty in a group that was
// never handed over.
func (s *Records) Roots() []*x509.Certificate { return s.path()[1:] }

// Revoked reports whether a revocation that counts names the key k.
func (s *Records) Revoked(k KeyHash) bool { return slices.Contains(s.State().Revoked, k) }

// Frozen reports whether k is a frozen admin key, or a key of the device
// of a frozen admin.
func (s *Records) Frozen(k KeyHash) bool {
	for _, d := range s.State().Devices {
		if d.Frozen && (d.Admin != nil && *d.Admin == k || slices.Contains(d.Keys, k)) {
			return true
		}
	}
	return false
}

// Watch reports whether k is a watch's admin key.
func (s *Records) Watch(k KeyHash) bool {
	for _, d := range s.State().Devices {
		if d.Role == RoleWatch && d.Admin != nil && *d.Admin == k {
			return true
		}
	}
	return false
}

// A Device is one entry of the devices list.
type Device struct {
	ID   DeviceID
	Name string
	Role string // RoleFull, RolePhone, RoleLite, RoleShortcut or RoleWatch
	OS   string // "" when its record does not tell
	// Key is the member key of its newest counting record.
	Key KeyHash
	// Store is where its keys live (StoreOf); Kind and Proof name the
	// attestation the root checked, if any.
	Store, Kind, Proof string
	// Seal is its public key for sealed messages, if its record has one.
	Seal  []byte
	Admin bool
	// AdminKey is its admin key, nil when it is no admin; Powers and
	// Commands what its newest root record gives it.
	AdminKey         *KeyHash
	Powers, Commands []string
	// Keys are every key that a counting device record names for it and
	// that is not revoked, Key among them: what removing it revokes.
	Keys  []KeyHash
	Since time.Time
	// Frozen says that another admin froze it: it is no admin until the
	// freeze ends, and its connections are refused.
	Frozen bool
}

// May reports whether the device is an admin with the power p.
func (d Device) May(p string) bool { return d.Admin && slices.Contains(d.Powers, p) }

// Devices returns the devices list, sorted by name and then ID.
func (s *Records) Devices() []Device {
	st := s.State()
	newest := map[string]parsed{}
	for _, p := range s.bodies() {
		if p.b.Type != RecordDevice {
			continue
		}
		if o, ok := newest[p.b.Device]; !ok || p.b.TimeMS > o.b.TimeMS || p.b.TimeMS == o.b.TimeMS && p.b.Seq > o.b.Seq {
			newest[p.b.Device] = p
		}
	}
	var out []Device
	for _, d := range st.Devices {
		dev := Device{ID: DeviceID(d.Device), Name: d.Name, Role: d.Role, OS: d.OS, Store: StoreOf(d.Store, d.Role), Kind: d.Kind, Proof: d.Proof,
			Seal: d.Seal, Keys: d.Keys, Powers: d.Powers, Commands: d.Commands, Frozen: d.Frozen}
		if d.Admin != nil {
			// A frozen admin is no admin until the freeze ends.
			a := *d.Admin
			dev.Admin, dev.AdminKey = !d.Frozen, &a
		}
		if p, ok := newest[d.Device]; ok {
			dev.Since = time.UnixMilli(p.b.TimeMS)
			if p.b.Key != nil && slices.Contains(d.Keys, *p.b.Key) {
				dev.Key = *p.b.Key
			}
		}
		if dev.Key == (KeyHash{}) && len(d.Keys) > 0 {
			dev.Key = d.Keys[len(d.Keys)-1]
		}
		out = append(out, dev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// listed reports whether a device of the list has the key k.
func (s *Records) listed(k KeyHash) bool {
	for _, d := range s.State().Devices {
		if slices.Contains(d.Keys, k) {
			return true
		}
	}
	return false
}

// adminDevice returns the device whose admin key is k.
func (s *Records) adminDevice(k KeyHash) (authority.Device, bool) {
	for _, d := range s.State().Devices {
		if d.Admin != nil && *d.Admin == k {
			return d, true
		}
	}
	return authority.Device{}, false
}

// Refused returns why a member's chain is not taken, nil when it is
// (docs/protocol.md, section 10, "Certificates"): its key must be a listed device's
// that is not revoked nor frozen, and its issuer a root on the path or the
// admin CA, under one, of an admin that may admit or renew, not frozen.
// A chain that passes all but the first rule, as a device whose record has
// not reached this member yet or a new member that holds no records yet,
// is refused with ErrNotListed, which lets records through
// (ErrRecordsOnly), so that the records reach the member that lacks them.
//
// A chain that passes every rule while the state stops the exchange with
// its device (Stopped) is refused with ErrStopped, which lets records
// through too, so that the root's decision reaches every member.
func (s *Records) Refused(chain []*x509.Certificate) error {
	if err := s.refusedChain(chain); err != nil {
		return err
	}
	if !s.listed(KeyHashOf(chain[0])) {
		// A device no record names gets records only, unless the admin
		// that certified it was removed: so the holder of a removed
		// recovery key gets nothing.
		if a, ok := s.issuerAdmin(chain); ok && s.Revoked(a) {
			return errors.New("group: the admin that certified the device was removed from the group")
		}
		return ErrNotListed
	}
	if dev, err := DeviceOf(chain[0]); err == nil && s.Stopped(dev) {
		return ErrStopped
	}
	return nil
}

// Stopped reports whether the state stops the exchange with dev: the
// whole group stops (stop full), or dev is a device that gets nothing
// (docs/protocol.md, section 10, "Stopping the exchange"). A connection
// with it carries records only.
func (s *Records) Stopped(dev DeviceID) bool {
	st := s.State()
	return st.Stop == authority.StopFull || slices.Contains(st.NothingTo, string(dev))
}

// NoSecretsTo reports whether this member sends dev no secret: while the
// state stops secrets or everything, or names dev among the devices that
// get no secrets or nothing (docs/protocol.md, section 10, "Stopping the
// exchange"). Such a device gets the mark of a secret, never its text, and
// no secret paste.
func (s *Records) NoSecretsTo(dev DeviceID) bool {
	st := s.State()
	return st.Stop != authority.StopNone || slices.Contains(st.NoSecretsTo, string(dev)) || slices.Contains(st.NothingTo, string(dev))
}

// issuerAdmin returns the key hash of the admin CA in chain that signed
// its leaf; false when a root on the path signed it or none did.
func (s *Records) issuerAdmin(chain []*x509.Certificate) (KeyHash, bool) {
	if signedByAny(chain[0], s.path()) {
		return KeyHash{}, false
	}
	for _, c := range chain[1:] {
		if chain[0].CheckSignatureFrom(c) == nil {
			return KeyHashOf(c), true
		}
	}
	return KeyHash{}, false
}

// refusedChain is Refused without the rule that a device record names the
// key.
func (s *Records) refusedChain(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("group: no certificate")
	}
	leaf := KeyHashOf(chain[0])
	if s.Revoked(leaf) {
		return errors.New("group: the device was removed from the group")
	}
	if s.Frozen(leaf) {
		return errors.New("group: the device is a frozen admin; the root or an admin with thaw unfreezes or removes it")
	}
	path := s.path()
	if signedByAny(chain[0], path) {
		return nil
	}
	var issuer *x509.Certificate
	for _, c := range chain[1:] {
		if chain[0].CheckSignatureFrom(c) == nil {
			issuer = c
			break
		}
	}
	if issuer == nil {
		return errors.New("group: the certificate's issuer is not in its chain")
	}
	if !signedByAny(issuer, path) {
		return errors.New("group: the certificate is not from a root of the group")
	}
	admin := KeyHashOf(issuer)
	if s.Frozen(admin) {
		return errors.New("group: the admin that certified the device is frozen")
	}
	// An admin removed later still certified the devices whose records
	// stay; one listed must have a power to certify.
	if d, ok := s.adminDevice(admin); ok && !slices.Contains(d.Powers, authority.PowerAdmit) && !slices.Contains(d.Powers, authority.PowerRenew) {
		return errors.New("group: the admin that certified the device certifies no devices")
	}
	return nil
}

// RefusedAdminCA returns why an admin CA is not taken, nil when it is
// (docs/protocol.md, section 10, "Certificates"): it is under a root on the path,
// its key is not revoked, and a device record that counts names it as an
// admin key; one whose record has not reached this member yet is refused
// with ErrNotListed.
func (s *Records) RefusedAdminCA(ca *x509.Certificate) error {
	k := KeyHashOf(ca)
	if s.Revoked(k) {
		return errors.New("group: the admin CA's key was removed from the group")
	}
	if !signedByAny(ca, s.path()) {
		return errors.New("group: the admin CA is not from a root of the group")
	}
	if _, ok := s.adminDevice(k); !ok {
		return ErrNotListed
	}
	return nil
}

// ErrNotListed is what Refused returns for a chain that no device record
// that counts names; errors.Is(ErrNotListed, ErrRecordsOnly) holds, so the
// connection carries records only.
var ErrNotListed error = notListed{}

type notListed struct{}

func (notListed) Error() string {
	return "group: no device record that counts names the device's key"
}

func (notListed) Is(target error) bool { return target == ErrRecordsOnly }

// ErrStopped is what Refused returns for a chain it takes while the state
// stops the exchange with its device (Records.Stopped); errors.Is(ErrStopped,
// ErrRecordsOnly) holds, so the connection carries records only until the
// root's records end the stop.
var ErrStopped error = stopped{}

type stopped struct{}

func (stopped) Error() string {
	return "group: the group's records stop the exchange until its root decides; the connection carries records only"
}

func (stopped) Is(target error) bool { return target == ErrRecordsOnly }

// signedByAny reports whether one of roots signed c.
func signedByAny(c *x509.Certificate, roots []*x509.Certificate) bool {
	for _, root := range roots {
		if c.CheckSignatureFrom(root) == nil {
			return true
		}
	}
	return false
}

// RootDevice returns the phone or computer that holds the group's current
// root: the device of the newest device record with holds_root that the
// current root's own key signed; "" when there is none.
func (s *Records) RootDevice() DeviceID {
	dev, _ := s.RootMember()
	return dev
}

// RootMember returns the device that holds the group's current root and
// its member key: a peer is the root only when its certificate has that
// key.
func (s *Records) RootMember() (DeviceID, KeyHash) {
	st := s.State()
	if st.RootDevice == "" {
		return "", KeyHash{}
	}
	cur := st.Roots[len(st.Roots)-1]
	var best *parsed
	for _, p := range s.bodies() {
		if p.b.Type == RecordDevice && p.b.HoldsRoot && p.b.Signer == cur && p.b.Device == st.RootDevice && (best == nil || p.b.Seq > best.b.Seq) {
			best = &p
		}
	}
	if best == nil || best.b.Key == nil {
		return "", KeyHash{}
	}
	return DeviceID(st.RootDevice), *best.b.Key
}

// DeviceOfRoot returns the device of the newest holds_root device record
// that the root key root signed: the device that held that root; "" when
// there is none.
func (s *Records) DeviceOfRoot(root KeyHash) DeviceID {
	var best *parsed
	for _, p := range s.bodies() {
		if p.b.Type == RecordDevice && p.b.HoldsRoot && p.b.Signer == root && (best == nil || p.b.Seq > best.b.Seq) {
			best = &p
		}
	}
	if best == nil {
		return ""
	}
	return DeviceID(best.b.Device)
}

// AdminUnder reports whether a device record that the root key root signed
// names the admin key admin.
func (s *Records) AdminUnder(root, admin KeyHash) bool {
	for _, p := range s.bodies() {
		if p.b.Type == RecordDevice && p.b.Signer == root && p.b.Admin != nil && *p.b.Admin == admin {
			return true
		}
	}
	return false
}

// MayHost reports whether the device dev may be the group's hub for sync
// away from home by the records alone: the root's own device, whose key is
// not revoked, or an admin with the power hub (docs/protocol.md, section
// 11).
func (s *Records) MayHost(dev DeviceID) bool {
	if root, key := s.RootMember(); root == dev && !s.Revoked(key) {
		return true
	}
	for _, d := range s.Devices() {
		if d.ID == dev && d.May(authority.PowerHub) {
			return true
		}
	}
	return false
}

// HubOrder returns the devices that may be the group's hubs, in the order
// in which they serve (docs/protocol.md, section 11, "Several hubs"):
// first the main hubs of the hubs table, in its order, then the others:
// the phones, whose keys are in hardware, then the rest, and in each part
// the root's own device first, then by device ID.
func (s *Records) HubOrder() []DeviceID {
	root, key := s.RootMember()
	if root != "" && s.Revoked(key) {
		root = ""
	}
	type hub struct {
		id    DeviceID
		phone bool
	}
	var hubs []hub
	for _, d := range s.Devices() {
		if d.ID == root || d.May(authority.PowerHub) {
			hubs = append(hubs, hub{d.ID, d.Role == RolePhone})
		}
	}
	sort.Slice(hubs, func(i, j int) bool {
		a, b := hubs[i], hubs[j]
		switch {
		case a.phone != b.phone:
			return a.phone
		case (a.id == root) != (b.id == root):
			return a.id == root
		}
		return a.id < b.id
	})
	var out []DeviceID
	main := map[DeviceID]bool{}
	for _, id := range s.State().Hubs {
		for _, h := range hubs {
			if h.id == DeviceID(id) {
				out = append(out, h.id)
				main[h.id] = true
			}
		}
	}
	for _, h := range hubs {
		if !main[h.id] {
			out = append(out, h.id)
		}
	}
	return out
}

// Known reports whether a device record that reads names the device dev,
// whether or not it counts: an ID a new device may not take
// (docs/protocol.md, section 6).
func (s *Records) Known(dev DeviceID) bool {
	for _, p := range s.bodies() {
		if p.b.Type == RecordDevice && p.b.Device == string(dev) {
			return true
		}
	}
	return false
}

// FreezesOf returns the IDs of the freeze records that name the admin key
// admin: what a thaw of that admin names.
func (s *Records) FreezesOf(admin KeyHash) []KeyHash {
	var out []KeyHash
	for _, p := range s.bodies() {
		if p.b.Type == RecordFreeze && slices.Contains(p.b.Keys, admin) && !slices.Contains(out, p.id) {
			out = append(out, p.id)
		}
	}
	return out
}

// TakenOver reports whether chain is the member certificate of a root's
// own device that a claim took the group over from: its leaf is the key of
// a holds_root device record of a root on the path that is no longer the
// current root, which certified it. It returns the device and admin key
// of the claimant. Such a peer is refused, but its connections carry
// records (ErrRecordsOnly), so that the old root, if it is still in use,
// can cancel the claim (docs/protocol.md, section 10, "Handing the group over").
func (s *Records) TakenOver(chain []*x509.Certificate) (DeviceID, KeyHash, bool) {
	if len(chain) == 0 {
		return "", KeyHash{}, false
	}
	st := s.State()
	path := s.path()
	leaf := KeyHashOf(chain[0])
	for i, root := range path[:len(path)-1] {
		if chain[0].CheckSignatureFrom(root) != nil {
			continue
		}
		rk := KeyHashOf(root)
		own := false
		for _, p := range s.bodies() {
			if p.b.Type == RecordDevice && p.b.HoldsRoot && p.b.Signer == rk && p.b.Key != nil && *p.b.Key == leaf {
				own = true
			}
		}
		if !own {
			continue
		}
		next := KeyHashOf(path[i+1])
		for _, c := range st.Claims {
			if c.Root == next && c.State == "effective" {
				dev := DeviceID("")
				for _, p := range s.bodies() {
					if p.b.Type == RecordDevice && p.b.Admin != nil && *p.b.Admin == c.Claimant {
						dev = DeviceID(p.b.Device)
					}
				}
				return dev, c.Claimant, true
			}
		}
	}
	return "", KeyHash{}, false
}

// ErrRecordsOnly is what a check of a peer returns for a root that a claim
// took the group over from (Records.TakenOver), and what ErrNotListed is:
// its connection carries records and nothing else.
var ErrRecordsOnly = errors.New("group: the group was taken over from this root; its connection carries records only")

// Next returns the seq and prev of the next record the key signer signs:
// one above its newest record in the set that is on no branch a root's
// resolve voided. So once the root voids both histories of a key
// (docs/protocol.md, section 10, "Two numbers"), the key goes on from the
// record below the fork, and what it signs counts.
func (s *Records) Next(signer KeyHash) (int64, *KeyHash) {
	own, dead := s.branches(signer)
	var seq int64
	var prev KeyHash
	// Of two records with one seq, which only a key that signed two
	// histories has, the lower ID, so that every member gives the same.
	for _, p := range own {
		if !dead(p) && (p.b.Seq > seq || p.b.Seq == seq && bytes.Compare(p.id[:], prev[:]) < 0) {
			seq, prev = p.b.Seq, p.id
		}
	}
	if seq == 0 {
		return 1, nil
	}
	return seq + 1, &prev
}

// Voided returns the records of signer that are on a branch a root's
// resolve voided, by seq: what its device may sign again once the root
// voided both of its histories.
func (s *Records) Voided(signer KeyHash) []Record {
	own, dead := s.branches(signer)
	var ps []parsed
	for _, p := range own {
		if dead(p) {
			ps = append(ps, p)
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].b.Seq < ps[j].b.Seq })
	out := make([]Record, len(ps))
	for i, p := range ps {
		out[i] = p.r
	}
	return out
}

// branches returns the records of signer, by ID, and whether one is on a
// voided branch: its prev chain, as far as the set holds it, passes
// through a record that a root's resolve names and that has a sibling.
func (s *Records) branches(signer KeyHash) (map[KeyHash]parsed, func(parsed) bool) {
	roots := map[KeyHash]bool{}
	for _, k := range s.State().Roots {
		roots[k] = true
	}
	voided := map[KeyHash]bool{}
	byID := map[KeyHash]parsed{}
	bySeq := map[int64]int{}
	for _, p := range s.bodies() {
		if p.b.Type == RecordResolve && roots[p.b.Signer] && len(p.r.Chain) == 0 {
			for _, id := range p.b.Records {
				voided[id] = true
			}
		}
		if p.b.Signer == signer {
			byID[p.id] = p
			bySeq[p.b.Seq]++
		}
	}
	dead := func(p parsed) bool {
		for steps := 0; steps <= authority.MaxSeq; steps++ {
			if voided[p.id] && bySeq[p.b.Seq] > 1 {
				return true
			}
			if p.b.Prev == nil {
				return false
			}
			q, ok := byID[*p.b.Prev]
			if !ok {
				return false
			}
			p = q
		}
		return false
	}
	return byID, dead
}

// ErrTwoHistories is what Sign returns for a key that signed two histories
// the root has not resolved yet: a record it signed now would count for
// nothing (docs/protocol.md, section 10, "Two numbers").
var ErrTwoHistories = errors.New("group: this key signed two histories; the group's root must resolve them before it signs again")

// TwoHistories reports whether the state names signer in a conflict of two
// histories.
func (s *Records) TwoHistories(signer KeyHash) bool {
	for _, c := range s.State().Conflicts {
		if c.Kind == authority.ConflictTwoHistories && slices.Contains(c.Signers, signer) {
			return true
		}
	}
	return false
}

// Seen returns, for every signer of the set, the highest seq the set holds
// of it: what a removal, a freeze or a claim names in seen.
func (s *Records) Seen() []authority.Seen {
	top := map[KeyHash]int64{}
	for _, p := range s.bodies() {
		if p.b.Seq > top[p.b.Signer] {
			top[p.b.Signer] = p.b.Seq
		}
	}
	out := make([]authority.Seen, 0, len(top))
	for k, n := range top {
		out = append(out, authority.Seen{Key: k, Seq: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// Sign signs body as the next record of key, a root's own key (adminCA
// nil) or the admin key adminCA certifies: it sets the group, seq and prev,
// and seen for a removal, freeze or claim, from the set. The caller adds
// the record to the set.
func (s *Records) Sign(body RecordBody, key crypto.Signer, adminCA *x509.Certificate) (Record, error) {
	signer, err := authority.PublicKeyHash(key.Public())
	if err != nil {
		return Record{}, err
	}
	// A root ends its own two histories with a resolve, which counts
	// whatever forks its chain has; nothing else of a forked key counts.
	if body.Type != RecordResolve && s.TwoHistories(signer) {
		return Record{}, ErrTwoHistories
	}
	body.Group = s.tag
	body.Seq, body.Prev = s.Next(signer)
	switch body.Type {
	case RecordRevoke, RecordFreeze, RecordClaim:
		body.Seen = s.Seen()
		if !slices.ContainsFunc(body.Seen, func(e authority.Seen) bool { return e.Key == signer }) {
			body.Seen = append(body.Seen, authority.Seen{Key: signer, Seq: body.Seq - 1})
		}
	}
	return authority.Sign(body, key, adminCA)
}

// ClaimTimes returns when the set first held each claim, sorted by record.
func (s *Records) ClaimTimes() []ClaimTime {
	var out []ClaimTime
	for id, ms := range s.firstSeen {
		out = append(out, ClaimTime{id, ms})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Record.String() < out[j].Record.String() })
	return out
}

// TakeClaimTimes takes, for each claim the set holds, the time in ts when
// it is earlier than the set's own and not in the future: a new member
// takes the times of the member that admitted it from the Welcome, so a
// claim that took effect there takes effect on the new member too
// (docs/protocol.md, section 10, "Handing the group over").
func (s *Records) TakeClaimTimes(ts []ClaimTime) {
	now := s.now().UnixMilli()
	for _, t := range ts {
		if ms, ok := s.firstSeen[t.Record]; ok && t.MS < ms && t.MS <= now {
			s.firstSeen[t.Record] = t.MS
			s.st = nil
		}
	}
}

// Digest returns SHA-256 over each record's ID and signature, sorted as
// All sorts them, in base64: the value a hello carries; "" for an empty
// set.
func (s *Records) Digest() string {
	if len(s.recs) == 0 {
		return ""
	}
	h := sha256.New()
	for _, r := range s.All() {
		id := r.ID()
		sig := sha256.Sum256(r.Sig)
		h.Write(id[:])
		h.Write(sig[:])
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// recordsFile is the records file: the records and when this member first
// held each claim.
type recordsFile struct {
	V         int         `json:"v"`
	Records   []Record    `json:"records"`
	FirstSeen []ClaimTime `json:"first_seen,omitempty"`
}

// ClaimTime is when a member first held a claim, in Unix milliseconds:
// what the records file keeps and a Welcome hands a new member.
type ClaimTime struct {
	Record KeyHash `json:"record"`
	MS     int64   `json:"ms"`
}

// Save writes the records to dir/records.json, replacing the file in one
// step.
func (s *Records) Save(dir string) error {
	f := recordsFile{V: 2, Records: s.All(), FirstSeen: s.ClaimTimes()}
	data, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, RecordsFileName), append(data, '\n'), 0o600)
}

// LoadRecords reads dir/records.json for the group of groupCA. A missing
// file, or one of version 1, is an empty set; records that are not valid
// for the group are left out.
func LoadRecords(dir string, groupCA *x509.Certificate) (*Records, error) {
	s := NewRecords(groupCA)
	data, err := os.ReadFile(filepath.Join(dir, RecordsFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f recordsFile
	if err := json.Unmarshal(data, &f); err != nil || f.V != 2 {
		// Version 1's file was a bare array: its group is set up again.
		return s, nil
	}
	for _, e := range f.FirstSeen {
		s.firstSeen[e.Record] = e.MS
	}
	s.AddAll(f.Records)
	return s, nil
}

// AuthorityRecords returns the records a hub or a member sends its
// forwarder or relay so that it can tell a removed device: all of them,
// until the servers take only server credentials (docs/records-v2.md, "What
// else changes with it").
func (s *Records) AuthorityRecords() []Record { return s.All() }

// PathRecords returns the records a new member gets in the Welcome to check
// that the Welcome's roots are the group's: all of them, since it evaluates
// the set as every member does.
func (s *Records) PathRecords() []Record { return s.All() }

// SignerName names the device of a signer's key for the user: the device
// whose newest root record names it as its admin key, the root's own
// device for a root key on the path, or the key hash when neither does.
func (s *Records) SignerName(k KeyHash) string {
	st := s.State()
	for _, d := range st.Devices {
		if d.Admin != nil && *d.Admin == k {
			return d.Name
		}
	}
	if slices.Contains(st.Roots, k) {
		for _, d := range st.Devices {
			if d.Device == st.RootDevice {
				return d.Name
			}
		}
	}
	return k.String()
}
