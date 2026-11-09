// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/benchtime"
	"github.com/HunterEwok/cbb/internal/core"
)

// PeriodLifetime is how long a period lasts, and PeriodRenew how old it may
// get before the root starts the next: a phone's root asks for Face ID for
// it about once a month. The bench's time-scaled build runs them faster.
var (
	PeriodLifetime = benchtime.D(35 * 24 * time.Hour)
	PeriodRenew    = benchtime.D(30 * 24 * time.Hour)
)

// Server credentials are what a forwarder and a relay check in place of the
// group's records (docs/protocol.md, section 18; D-67, D-75). The group
// lives in periods of about 30 days. For each, its root signs, inside the
// group, a period credential: a fresh tag for the servers and a fresh
// period key. Each device signs with its member key the server key it
// uses with the servers in that period. The servers see only what the
// period key signs: the hubs' credential and the members' credential,
// lists of padded server key hashes under the period's tag. So a server
// sees no root, no device ID, no name, no system and no date of signing,
// and cannot link a group or a device from one period to the next.
const (
	CredentialPeriod  = "period"  // the period's tag and key, signed by the root; inside the group only
	CredentialServer  = "server"  // a device's server key for a period, signed by its member key; inside the group only
	CredentialHubs    = "hubs"    // the hubs and admins, signed by the period key
	CredentialMembers = "members" // the members, signed by the period key or an admin the hubs' credential lists

	credentialVersion = 1
	// CredentialsFileName is the file next to the identity that keeps the
	// group's credentials.
	CredentialsFileName = "credentials.json"

	// MaxCredentialHubs bounds the hubs a credential lists, the first of
	// the order; MaxCredentialMembers the members; maxCredentialList the
	// admins.
	MaxCredentialHubs    = 16
	MaxCredentialMembers = 256
	maxCredentialList    = 64
	maxCredentialBody    = 16 << 10
	// MaxCredentials bounds the credentials a member keeps and sends: the
	// period, the hubs' and the members' credentials and one server
	// credential for each member.
	MaxCredentials = MaxCredentialMembers + 3
)

// A Credential is a signed credential body: the body's exact bytes, an
// ECDSA P-256 signature over them, and the signer's public key
// (SubjectPublicKeyInfo).
type Credential struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
	Key  []byte `json:"key"`
}

// A CredentialBody is what a credential says.
type CredentialBody struct {
	V    int    `json:"v"`
	Type string `json:"type"`
	// Group is the group's own tag (Tag of the group CA) in a period or a
	// server credential, and the period's tag in a hubs' or a members'
	// credential, the only tag the servers see.
	Group     string `json:"group"`
	Version   uint64 `json:"version"`
	ExpiresMS int64  `json:"expires_ms"`

	// Tag is a period's tag for the servers, or the period a server
	// credential is for.
	Tag string `json:"tag,omitempty"`
	// Key is the period key of a period, or the device's server key of a
	// server credential (SubjectPublicKeyInfo).
	Key []byte `json:"key,omitempty"`

	Hubs    []KeyHash `json:"hubs,omitempty"`    // hubs: the hubs' server keys, in their order
	Admins  []KeyHash `json:"admins,omitempty"`  // hubs: the admins' server keys
	Members []KeyHash `json:"members,omitempty"` // members: the members' server keys
}

// ID returns the credential's ID: SHA-256 over its body.
func (c Credential) ID() [sha256.Size]byte { return sha256.Sum256(c.Body) }

// Signer returns the hash of the key that signed the credential.
func (c Credential) Signer() KeyHash { return sha256.Sum256(c.Key) }

// Expires returns when the credential stops counting.
func (b *CredentialBody) Expires() time.Time { return time.UnixMilli(b.ExpiresMS) }

// KeyHash returns the hash of the key a period or a server credential
// carries.
func (b *CredentialBody) KeyHash() KeyHash { return sha256.Sum256(b.Key) }

// Pseudonym is how the relay knows a device that registered with its
// server credential: the fingerprint of its server key, its key hash in
// standard base64 (docs/protocol.md, Conventions, "Fingerprints").
func Pseudonym(k KeyHash) string { return k.String() }

// ParsePseudonym returns the key hash a pseudonym names.
func ParsePseudonym(s string) (KeyHash, bool) {
	var k KeyHash
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != len(k) || base64.StdEncoding.EncodeToString(b) != s {
		return KeyHash{}, false
	}
	copy(k[:], b)
	return k, true
}

// CredentialLists are the real entries of the hubs' and the members'
// credentials, before padding, as member keys: what the group's records
// say. The credentials list the server keys of these members.
type CredentialLists struct {
	Hubs, Admins, Members []KeyHash
}

// CredentialLists returns what the group's credentials must list, by
// member key: the hubs in their order (HubOrder), at most
// MaxCredentialHubs; the admins that are neither revoked nor frozen, other
// than the root's own device, which holds the period key; and every device
// that is not frozen, at most MaxCredentialMembers.
func (s *Records) CredentialLists() CredentialLists {
	var l CredentialLists
	root, rootKey := s.RootMember()
	devs := s.Devices()
	for _, id := range s.HubOrder() {
		if len(l.Hubs) == MaxCredentialHubs {
			break
		}
		if id == root {
			l.Hubs = append(l.Hubs, rootKey)
			continue
		}
		for _, d := range devs {
			if d.ID == id {
				l.Hubs = append(l.Hubs, d.Key)
			}
		}
	}
	for _, d := range devs {
		// A watch reaches the group only through its phone, so no server
		// needs its key.
		if d.Frozen || d.Role == RoleWatch {
			continue
		}
		if d.Admin && d.ID != root && len(l.Admins) < maxCredentialList {
			l.Admins = append(l.Admins, d.Key)
		}
		if len(l.Members) < MaxCredentialMembers {
			l.Members = append(l.Members, d.Key)
		}
	}
	return l
}

// MemberOf returns the device whose counting device records name the
// member key k, if it is not revoked or frozen.
func (s *Records) MemberOf(k KeyHash) (DeviceID, bool) {
	for _, d := range s.Devices() {
		if !d.Frozen && slices.Contains(d.Keys, k) {
			return d.ID, true
		}
	}
	return "", false
}

// IsMember reports whether k is the member key of a device in the group
// that is not frozen (MemberOf).
func (s *Records) IsMember(k KeyHash) bool {
	_, ok := s.MemberOf(k)
	return ok
}

// padTo returns the size a list of n entries is padded to: the next of 4,
// 8, 16, 32, 64, 128 and 256.
func padTo(n int) int {
	size := 4
	for size < n {
		size *= 2
	}
	return size
}

// pad appends random 32-byte strings to ks up to padTo(len(ks)): a key
// hash looks random, so the padding cannot be told from a real entry.
func pad(ks []KeyHash) ([]KeyHash, error) {
	out := slices.Clone(ks)
	for len(out) < padTo(len(ks)) {
		var k KeyHash
		if _, err := rand.Read(k[:]); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// NewPeriodTag returns a fresh tag for the servers: 8 random bytes in hex,
// as Tag's.
func NewPeriodTag() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// SignPeriod signs, with the root's key, the period of the group of
// groupTag with the servers' tag and the period key, lasting
// PeriodLifetime from now.
func SignPeriod(groupTag, tag string, key crypto.PublicKey, version uint64, now time.Time, root crypto.Signer) (Credential, error) {
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return Credential{}, err
	}
	return SignCredential(CredentialBody{Type: CredentialPeriod, Group: groupTag, Version: version,
		ExpiresMS: now.Add(PeriodLifetime).UnixMilli(), Tag: tag, Key: spki}, root)
}

// SignServer signs, with a device's member key, the server key it uses in
// the period p.
func SignServer(p *CredentialBody, key crypto.PublicKey, version uint64, member crypto.Signer) (Credential, error) {
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return Credential{}, err
	}
	return SignCredential(CredentialBody{Type: CredentialServer, Group: p.Group, Version: version,
		ExpiresMS: p.ExpiresMS, Tag: p.Tag, Key: spki}, member)
}

// SignHubs signs the period's hubs' credential with the period key: the
// hubs' and the admins' server keys, padded.
func SignHubs(p *CredentialBody, hubs, admins []KeyHash, version uint64, key crypto.Signer) (Credential, error) {
	b := CredentialBody{Type: CredentialHubs, Group: p.Tag, Version: version, ExpiresMS: p.ExpiresMS}
	var err error
	if b.Hubs, err = pad(hubs); err != nil {
		return Credential{}, err
	}
	if b.Admins, err = pad(admins); err != nil {
		return Credential{}, err
	}
	return SignCredential(b, key)
}

// SignMembers signs the period's members' credential with the period key
// or an admin's server key: the members' server keys, padded.
func SignMembers(p *CredentialBody, members []KeyHash, version uint64, key crypto.Signer) (Credential, error) {
	b := CredentialBody{Type: CredentialMembers, Group: p.Tag, Version: version, ExpiresMS: p.ExpiresMS}
	var err error
	if b.Members, err = pad(members); err != nil {
		return Credential{}, err
	}
	return SignCredential(b, key)
}

// SignCredential signs a credential body with key.
func SignCredential(b CredentialBody, key crypto.Signer) (Credential, error) {
	b.V = credentialVersion
	if err := b.check(); err != nil {
		return Credential{}, err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return Credential{}, err
	}
	if _, err := parseCredentialBody(data); err != nil {
		return Credential{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return Credential{}, err
	}
	sum := sha256.Sum256(data)
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Body: data, Sig: sig, Key: spki}, nil
}

func (b *CredentialBody) check() error {
	if b.V != credentialVersion {
		return fmt.Errorf("group: unknown credential version %d", b.V)
	}
	if b.Version == 0 || b.ExpiresMS <= 0 {
		return errors.New("group: a credential without a version or an expiry")
	}
	if !ValidTag(b.Group) {
		return errors.New("group: a credential's group is not a tag")
	}
	switch b.Type {
	case CredentialPeriod, CredentialServer:
		if !ValidTag(b.Tag) {
			return errors.New("group: a credential's period tag is not a tag")
		}
		if _, err := p256Key(b.Key); err != nil {
			return err
		}
		if len(b.Hubs)+len(b.Admins)+len(b.Members) != 0 {
			return errors.New("group: a period or server credential lists keys")
		}
	case CredentialHubs:
		switch {
		case len(b.Hubs) > MaxCredentialHubs || len(b.Admins) > maxCredentialList:
			return errors.New("group: a hubs' credential lists too many keys")
		case b.Tag != "" || len(b.Key) != 0 || len(b.Members) != 0:
			return errors.New("group: a hubs' credential carries more than its lists")
		}
	case CredentialMembers:
		switch {
		case len(b.Members) > MaxCredentialMembers:
			return errors.New("group: a members' credential lists too many keys")
		case b.Tag != "" || len(b.Key) != 0 || len(b.Hubs)+len(b.Admins) != 0:
			return errors.New("group: a members' credential carries more than its list")
		}
	default:
		return fmt.Errorf("group: unknown credential type %q", b.Type)
	}
	return nil
}

// ValidTag reports whether s is a tag: 16 lower-case hex characters.
func ValidTag(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// p256Key parses a P-256 public key from its SubjectPublicKeyInfo.
func p256Key(spki []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("group: the credential's key does not parse")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("group: the credential's key is not a P-256 key")
	}
	return ec, nil
}

// Open checks the credential's signature and returns its body. It checks
// neither who signed it nor the group.
func (c Credential) Open() (*CredentialBody, error) {
	b, err := parseCredentialBody(c.Body)
	if err != nil {
		return nil, err
	}
	ec, err := p256Key(c.Key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.Body)
	if !ecdsa.VerifyASN1(ec, sum[:], c.Sig) {
		return nil, errors.New("group: the credential's signature does not verify")
	}
	return b, nil
}

// parseCredentialBody reads and checks a credential's body: its size, the
// strict form of signed bodies, then its fields.
func parseCredentialBody(data []byte) (*CredentialBody, error) {
	if checked, err := core.CheckBody(core.KindCredential, data); checked {
		if err != nil {
			return nil, fmt.Errorf("group: a credential: %w", err)
		}
		var b CredentialBody
		if err := json.Unmarshal(data, &b); err != nil {
			return nil, errors.New("group: the credential does not decode")
		}
		return &b, nil
	}
	if len(data) > maxCredentialBody {
		return nil, errors.New("group: the credential is too large")
	}
	if err := checkStrict(data, "v", "type", "group", "version", "expires_ms"); err != nil {
		return nil, err
	}
	var b CredentialBody
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, errors.New("group: the credential does not decode")
	}
	// The key is the only plain bytes of a body; the key hashes check
	// their own form.
	var raw struct {
		Key *string `json:"key"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("group: the credential does not decode")
	}
	if raw.Key != nil {
		if _, err := decodeStrictBase64(*raw.Key); err != nil {
			return nil, fmt.Errorf("group: a credential's key: %w", err)
		}
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Presented is what a server checked of the credentials a hub or a member
// presented (CheckPresented).
type Presented struct {
	Tag     string          // the period's tag
	Signer  KeyHash         // the period key, which signed the hubs' credential
	Hubs    *CredentialBody // the hubs' credential
	Members *CredentialBody // the members' credential, nil if none came
	// Period is the period credential, nil if none came: a device sends
	// it only to a relay that serves a fixed list of groups, whose roots
	// it then shows; PeriodRoot is the key that signed it.
	Period     *CredentialBody
	PeriodRoot []byte
}

// CheckPresented checks the credentials a device presents a server
// (docs/protocol.md, section 18): one hubs' credential, which the period
// key signed, and with it at most one members' credential of the same
// period, which the period key or an admin that the hubs' credential lists
// signed, and at most one period credential, whose tag and key are those
// of the hubs' credential. None may have expired at now. It does not check
// that the period key is the group's: a server takes the first it sees for
// a tag and from then on only that one.
func CheckPresented(cs []Credential, now time.Time) (*Presented, error) {
	wrong := errors.New("group: the credentials are not a hubs' credential with at most a members' and a period credential")
	if len(cs) == 0 || len(cs) > 3 {
		return nil, wrong
	}
	var p Presented
	var hubsSigner []byte
	var members, period *Credential
	for i, c := range cs {
		b, err := c.Open()
		if err != nil {
			return nil, err
		}
		if !now.Before(b.Expires()) {
			return nil, fmt.Errorf("group: the %s credential expired", b.Type)
		}
		switch {
		case b.Type == CredentialHubs && p.Hubs == nil:
			p.Hubs, p.Tag, p.Signer, hubsSigner = b, b.Group, c.Signer(), c.Key
		case b.Type == CredentialMembers && members == nil:
			p.Members, members = b, &cs[i]
		case b.Type == CredentialPeriod && period == nil:
			p.Period, period = b, &cs[i]
		default:
			return nil, wrong
		}
	}
	if p.Hubs == nil {
		return nil, errors.New("group: no hubs' credential")
	}
	if members != nil {
		if p.Members.Group != p.Tag {
			return nil, errors.New("group: a members' credential of another period")
		}
		if !bytes.Equal(members.Key, hubsSigner) && !slices.Contains(p.Hubs.Admins, members.Signer()) {
			return nil, errors.New("group: a members' credential that neither the period key nor a listed admin signed")
		}
	}
	if period != nil {
		if p.Period.Tag != p.Tag || !bytes.Equal(p.Period.Key, hubsSigner) {
			return nil, errors.New("group: a period credential of another period")
		}
		p.PeriodRoot = period.Key
	}
	return &p, nil
}

// Credentials keeps a member's credentials (docs/protocol.md, section 18):
// the newest period that the group's current root signed, and for it each
// member's newest server credential and the newest hubs' and members'
// credentials. It is safe for concurrent use.
type Credentials struct {
	mu      sync.Mutex
	groupCA *x509.Certificate
	period  *Credential
	servers map[KeyHash]Credential // by the member key that signed it
	hubs    *Credential
	members *Credential
}

// NewCredentials returns an empty set for the group of groupCA.
func NewCredentials(groupCA *x509.Certificate) *Credentials {
	return &Credentials{groupCA: groupCA, servers: map[KeyHash]Credential{}}
}

// rank orders credentials for Add: each counts against the ones before.
func rank(c Credential) int {
	var b struct {
		Type string `json:"type"`
	}
	json.Unmarshal(c.Body, &b)
	return slices.Index([]string{CredentialPeriod, CredentialServer, CredentialHubs, CredentialMembers}, b.Type)
}

// Add takes the credentials that are valid for the group and newer than
// what it keeps, and returns those it took. root is the group's current
// root; member tells whether a key is a member key of a device in the
// group (Records.IsMember). A period counts when root signed it; a server
// credential when a member signed it for the period kept; a hubs'
// credential when the period key signed it; a members' credential when
// the period key or an admin of the hubs' credential kept signed it. A
// newer period drops the credentials of the one before.
func (s *Credentials) Add(root *x509.Certificate, member func(KeyHash) bool, cs []Credential) (fresh []Credential, errs []error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tag := Tag(s.groupCA)
	order := slices.Clone(cs)
	slices.SortStableFunc(order, func(a, b Credential) int { return rank(a) - rank(b) })
	newer := func(old *Credential, b *CredentialBody) bool {
		if old == nil {
			return true
		}
		ob, err := old.Open()
		return err != nil || b.Version > ob.Version
	}
	for _, c := range order {
		b, err := c.Open()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		p := s.periodLocked(root)
		switch b.Type {
		case CredentialPeriod:
			switch {
			case b.Group != tag:
				errs = append(errs, errors.New("group: a period of another group"))
				continue
			case !bytes.Equal(c.Key, root.RawSubjectPublicKeyInfo):
				errs = append(errs, errors.New("group: a period that the group's root did not sign"))
				continue
			}
			var cur *Credential
			if p != nil {
				cur = s.period
			}
			if !newer(cur, b) {
				continue
			}
			if p == nil || p.Tag != b.Tag {
				clear(s.servers)
				s.hubs, s.members = nil, nil
			}
			s.period = &c
		case CredentialServer:
			switch {
			case p == nil || b.Group != tag || b.Tag != p.Tag:
				continue // of a period it does not keep
			case !member(c.Signer()):
				errs = append(errs, errors.New("group: a server credential that no member signed"))
				continue
			}
			old, ok := s.servers[c.Signer()]
			if ok && !newer(&old, b) {
				continue
			}
			if !ok && len(s.servers) >= MaxCredentialMembers {
				errs = append(errs, errors.New("group: too many server credentials"))
				continue
			}
			s.servers[c.Signer()] = c
		case CredentialHubs:
			switch {
			case p == nil || b.Group != p.Tag:
				continue
			case !bytes.Equal(c.Key, p.Key):
				errs = append(errs, errors.New("group: a hubs' credential that the period key did not sign"))
				continue
			case !newer(s.hubs, b):
				continue
			}
			s.hubs = &c
		case CredentialMembers:
			switch {
			case p == nil || b.Group != p.Tag:
				continue
			case !bytes.Equal(c.Key, p.Key) && !s.listedAdminLocked(c.Signer()):
				errs = append(errs, errors.New("group: a members' credential that neither the period key nor a listed admin signed"))
				continue
			case !newer(s.members, b):
				continue
			}
			s.members = &c
		}
		fresh = append(fresh, c)
	}
	return fresh, errs
}

// periodLocked returns the period kept, if root signed it.
func (s *Credentials) periodLocked(root *x509.Certificate) *CredentialBody {
	if s.period == nil || !bytes.Equal(s.period.Key, root.RawSubjectPublicKeyInfo) {
		return nil
	}
	b, err := s.period.Open()
	if err != nil {
		return nil
	}
	return b
}

func (s *Credentials) listedAdminLocked(k KeyHash) bool {
	if s.hubs == nil {
		return false
	}
	b, err := s.hubs.Open()
	return err == nil && slices.Contains(b.Admins, k)
}

// All returns every credential it keeps, the period first.
func (s *Credentials) All() []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Credential
	for _, c := range []*Credential{s.period, s.hubs, s.members} {
		if c != nil {
			out = append(out, *c)
		}
	}
	for _, c := range s.servers {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b Credential) int {
		if d := rank(a) - rank(b); d != 0 {
			return d
		}
		x, y := a.ID(), b.ID()
		return bytes.Compare(x[:], y[:])
	})
	return out
}

// Period returns the period kept and its body, if the group's current root
// root signed it.
func (s *Credentials) Period(root *x509.Certificate) (Credential, *CredentialBody, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.periodLocked(root)
	if b == nil {
		return Credential{}, nil, false
	}
	return *s.period, b, true
}

// Server returns the hash of the server key that the member key member
// signed for the period kept.
func (s *Credentials) Server(member KeyHash) (KeyHash, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.servers[member]
	if !ok {
		return KeyHash{}, false
	}
	b, err := c.Open()
	if err != nil {
		return KeyHash{}, false
	}
	return b.KeyHash(), true
}

// MemberOfServer returns the member key that signed the server key k for
// the period kept: whom a pseudonym at the relay names.
func (s *Credentials) MemberOfServer(k KeyHash) (KeyHash, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for m, c := range s.servers {
		if b, err := c.Open(); err == nil && b.KeyHash() == k {
			return m, true
		}
	}
	return KeyHash{}, false
}

// ServerKeys returns the server keys of the member keys ms, in their
// order, leaving out those that sent none for the period kept.
func (s *Credentials) ServerKeys(ms []KeyHash) []KeyHash {
	var out []KeyHash
	for _, m := range ms {
		if k, ok := s.Server(m); ok {
			out = append(out, k)
		}
	}
	return out
}

// Hubs returns the hubs' credential kept for the period, and its body.
func (s *Credentials) Hubs() (Credential, *CredentialBody, bool) {
	return s.typed(func() *Credential { return s.hubs })
}

func (s *Credentials) typed(f func() *Credential) (Credential, *CredentialBody, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := f()
	if c == nil {
		return Credential{}, nil, false
	}
	b, err := c.Open()
	if err != nil {
		return Credential{}, nil, false
	}
	return *c, b, true
}

// PeriodStale reports whether the root must start a new period: there is
// none from this root, it is PeriodRenew old, or a member that sent a
// server credential for it is no longer in the group (member false),
// since a removed device knows the period's tag.
func (s *Credentials) PeriodStale(root *x509.Certificate, member func(KeyHash) bool, now time.Time) bool {
	s.mu.Lock()
	p := s.periodLocked(root)
	senders := slices.Collect(maps.Keys(s.servers))
	s.mu.Unlock()
	if p == nil || p.Expires().Sub(now) < PeriodLifetime-PeriodRenew {
		return true
	}
	// member is asked without the lock: it may take the records' lock,
	// which Add's callers hold before this one.
	return slices.ContainsFunc(senders, func(m KeyHash) bool { return !member(m) })
}

// ListStale reports whether a credential's list got needs a new version
// for the server keys want: a key it wants is missing, the first ones are
// not want in its order when ordered, or it names a server key it keeps
// that it no longer wants. Padding never matches a kept key.
func (s *Credentials) ListStale(got, want []KeyHash, ordered bool) bool {
	if len(got) != padTo(len(want)) || ordered && !slices.Equal(got[:len(want)], want) {
		return true
	}
	for _, k := range want {
		if !slices.Contains(got, k) {
			return true
		}
	}
	for _, k := range got {
		if !slices.Contains(want, k) {
			if _, ok := s.MemberOfServer(k); ok {
				return true
			}
		}
	}
	return false
}

// Save writes the credentials to dir/credentials.json.
func (s *Credentials) Save(dir string) error {
	data, err := json.MarshalIndent(s.All(), "", "\t")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, CredentialsFileName), append(data, '\n'), 0o600)
}

// LoadCredentials reads dir/credentials.json for the group of groupCA,
// whose current root is root; a missing file is an empty set, and
// credentials that are not valid for the group are left out.
func LoadCredentials(dir string, groupCA, root *x509.Certificate, member func(KeyHash) bool) (*Credentials, error) {
	s := NewCredentials(groupCA)
	data, err := os.ReadFile(filepath.Join(dir, CredentialsFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var all []Credential
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, CredentialsFileName), err)
	}
	s.Add(root, member, all)
	return s, nil
}

// PublicKeyHash returns the hash of a public key, as KeyHashOf a
// certificate of it: SHA-256 over its SubjectPublicKeyInfo.
func PublicKeyHash(pub crypto.PublicKey) KeyHash {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return KeyHash{}
	}
	return sha256.Sum256(spki)
}
