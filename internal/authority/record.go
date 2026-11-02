// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package authority reads, writes and evaluates the group's authority
// records of version 2 (docs/records-v2.md): the record, its closed
// canonical body, its signature, and the one rule that turns a set of
// records into the group's state. It depends on no other part of the
// service, so the lite member's Rust core and Go can be compared on the
// same vectors.
package authority

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"unicode/utf8"

	"github.com/HunterEwok/clipboardbridge/internal/strict"
)

// MaxBody is the largest record body a member takes (8 KiB).
const MaxBody = 8 << 10

// MaxCheckpointBody is the largest body of a checkpoint (64 KiB), which
// lists the live records of the whole group.
const MaxCheckpointBody = 64 << 10

// SealKeySize is the size of a device record's seal: a public key of
// internal/seal (X-Wing), which a member checks in full before it seals
// to it.
const SealKeySize = 1216

// MaxSeq is the largest seq a signer gives a record.
const MaxSeq = 1<<31 - 1

// AlgES256 is the one signature algorithm of version 2: ECDSA P-256 with
// SHA-256, DER.
const AlgES256 = "es256"

// MaxNewer is how many records of a later version a state lists.
const MaxNewer = 16

// MaxDelay is the longest takeover delay the root may set (7 days), and
// DefaultDelay the delay without a settings record (72 hours), both in
// milliseconds.
const (
	MaxDelay     = 7 * 24 * 3600 * 1000
	DefaultDelay = 72 * 3600 * 1000
)

// KeyLevels are the key levels a settings record may set (docs/roadmap.md,
// "Key levels"): only proven hardware keys, hardware keys (the default),
// or files allowed too.
var KeyLevels = []string{"proven", "hardware", "files"}

// The record types.
const (
	TypeDevice     = "device"
	TypeRevoke     = "revoke"
	TypeFreeze     = "freeze"
	TypeThaw       = "thaw"
	TypeClaim      = "claim"
	TypeResolve    = "resolve"
	TypeSettings   = "settings"
	TypeCheckpoint = "checkpoint"
	TypeHubs       = "hubs"
	TypeRecovery   = "recovery"
	TypeHandover   = "handover"
)

// MaxHubs is how many devices a hubs record names.
const MaxHubs = 16

// The powers an admin's device record may give.
const (
	PowerAdmit        = "admit"
	PowerRenew        = "renew"
	PowerRemove       = "remove"
	PowerRemoveAdmins = "remove-admins"
	PowerFreeze       = "freeze"
	PowerThaw         = "thaw"
	PowerTakeover     = "takeover"
	PowerHub          = "hub"
)

// Powers lists every power, sorted.
var Powers = []string{PowerAdmit, PowerFreeze, PowerHub, PowerRemove, PowerRemoveAdmins, PowerRenew, PowerTakeover, PowerThaw}

// Commands lists every command type an admin may be given, sorted
// (docs/protocol.md, section 15).
var Commands = []string{"action", "actions-off", "away-off", "hub", "mode", "paste", "paste-off"}

// Roles and systems a device record may name.
var (
	roles = map[string]bool{"full": true, "phone": true, "lite": true, "watch": true, "shortcut": true}
	oses  = map[string]bool{"linux": true, "windows": true, "macos": true, "ios": true, "android": true, "watchos": true, "wearos": true, "none": true}
)

// Hash is a key hash (SHA-256 of a SubjectPublicKeyInfo, or of a phone
// ID) or a record ID (SHA-256 of a body). In JSON it is standard base64
// in its one form.
type Hash [sha256.Size]byte

// KeyHashOf returns the hash of a certificate's key.
func KeyHashOf(c *x509.Certificate) Hash { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// PublicKeyHash returns the hash of a public key's SubjectPublicKeyInfo.
func PublicKeyHash(pub crypto.PublicKey) (Hash, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(der), nil
}

func (h Hash) String() string { return strict.EncodeBase64(h[:]) }

// MarshalJSON writes h as base64.
func (h Hash) MarshalJSON() ([]byte, error) { return json.Marshal(h.String()) }

// UnmarshalJSON reads h from base64 in its one form, 32 bytes.
func (h *Hash) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("a hash is not a string")
	}
	raw, err := strict.DecodeBase64(s)
	if err != nil || len(raw) != len(h) {
		return errors.New("a hash is not 32 bytes of base64")
	}
	copy(h[:], raw)
	return nil
}

// Seen is one entry of a record's seen: the highest seq of a signer that
// the author held.
type Seen struct {
	Key Hash  `json:"key"`
	Seq int64 `json:"seq"`
}

// Head is one entry of a checkpoint's heads: a signer's newest record the
// checkpoint covers.
type Head struct {
	Key Hash  `json:"key"`
	Seq int64 `json:"seq"`
	ID  Hash  `json:"id"`
}

// Body is a record's body (docs/protocol.md, section 10, "Records").
type Body struct {
	V      int    `json:"v"`
	Alg    string `json:"alg"`
	Type   string `json:"type"`
	Group  string `json:"group"`
	Signer Hash   `json:"signer"`
	Seq    int64  `json:"seq"`
	Prev   *Hash  `json:"prev,omitempty"`
	TimeMS int64  `json:"time_ms"`

	Device   string   `json:"device,omitempty"`
	Name     string   `json:"name,omitempty"`
	Role     string   `json:"role,omitempty"`
	OS       string   `json:"os,omitempty"`
	Key      *Hash    `json:"key,omitempty"`
	Admin    *Hash    `json:"admin,omitempty"`
	Powers   []string `json:"powers,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Store    string   `json:"store,omitempty"`
	Kind     string   `json:"kind,omitempty"`
	Proof    string   `json:"proof,omitempty"`
	// HoldsRoot marks the device that holds the signing root's key; only
	// in a record a root's own key signed.
	HoldsRoot bool `json:"holds_root,omitempty"`
	// Seal is the device's public key for sealed messages (internal/seal).
	Seal []byte `json:"seal,omitempty"`

	Keys    []Hash `json:"keys,omitempty"`
	Seen    []Seen `json:"seen,omitempty"`
	Records []Hash `json:"records,omitempty"`
	Root    []byte `json:"root,omitempty"`
	// Cert is the recovery key's admin CA (DER), in a recovery record.
	Cert []byte `json:"cert,omitempty"`

	TakeoverDelayMS *int64 `json:"takeover_delay_ms,omitempty"`
	// KeyLevel is which keys may be the group's root, an admin or a hub:
	// one of KeyLevels; "" means "hardware".
	KeyLevel string `json:"key_level,omitempty"`

	Heads []Head `json:"heads,omitempty"`
	Keep  []Hash `json:"keep,omitempty"`

	// Hubs is the user's main hubs, in the order they serve.
	Hubs []string `json:"hubs,omitempty"`
}

// fields lists, for each type, the fields beyond those every record has
// that it may carry; needed lists those it must.
var (
	fields = map[string]map[string]bool{
		TypeDevice:     set("device", "name", "role", "os", "key", "admin", "powers", "commands", "store", "kind", "proof", "holds_root", "seal"),
		TypeRevoke:     set("keys", "seen"),
		TypeFreeze:     set("keys", "seen"),
		TypeThaw:       set("records"),
		TypeClaim:      set("root", "seen"),
		TypeResolve:    set("records"),
		TypeSettings:   set("takeover_delay_ms", "key_level"),
		TypeCheckpoint: set("heads", "keep"),
		TypeHubs:       set("hubs"),
		TypeRecovery:   set("admin", "cert"),
		TypeHandover:   set("admin"),
	}
	common = []string{"v", "alg", "type", "group", "signer", "seq", "time_ms"}
)

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// present returns the names of the fields b carries.
func (b *Body) present() []string {
	var names []string
	add := func(on bool, n string) {
		if on {
			names = append(names, n)
		}
	}
	add(b.Device != "", "device")
	add(b.Name != "", "name")
	add(b.Role != "", "role")
	add(b.OS != "", "os")
	add(b.Key != nil, "key")
	add(b.Admin != nil, "admin")
	add(len(b.Powers) > 0, "powers")
	add(len(b.Commands) > 0, "commands")
	add(b.Store != "", "store")
	add(b.Kind != "", "kind")
	add(b.Proof != "", "proof")
	add(b.HoldsRoot, "holds_root")
	add(len(b.Seal) > 0, "seal")
	add(len(b.Keys) > 0, "keys")
	add(len(b.Seen) > 0, "seen")
	add(len(b.Records) > 0, "records")
	add(len(b.Root) > 0, "root")
	add(len(b.Cert) > 0, "cert")
	add(b.TakeoverDelayMS != nil, "takeover_delay_ms")
	add(b.KeyLevel != "", "key_level")
	add(len(b.Heads) > 0, "heads")
	add(len(b.Keep) > 0, "keep")
	add(len(b.Hubs) > 0, "hubs")
	return names
}

// Encode returns the canonical bytes of b after checking its fields, as a
// signer's own code does before it signs.
func (b *Body) Encode() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return strict.Canonicalize(raw)
}

// ParseBody reads a record body: its size, the strict and canonical form,
// no field its type does not know and none empty, and each field against
// its row (docs/protocol.md, section 10, "Field rows").
func ParseBody(data []byte) (Body, error) {
	var b Body
	if len(data) > MaxCheckpointBody {
		return b, fmt.Errorf("authority: a record body of %d bytes is over %d", len(data), MaxCheckpointBody)
	}
	if err := strict.CheckCanonical(data, common...); err != nil {
		return b, fmt.Errorf("authority: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("authority: a record body: %w", err)
	}
	if err := b.check(); err != nil {
		return b, err
	}
	if max := b.maxBody(); len(data) > max {
		return b, fmt.Errorf("authority: a %s record body of %d bytes is over %d", b.Type, len(data), max)
	}
	// Writing it again shows a field that is there but empty (form/empty),
	// which decoding cannot tell from one left out, and any value Go reads
	// in more than one form.
	again, err := b.Encode()
	if err != nil {
		return b, err
	}
	if !bytes.Equal(again, data) {
		return b, errors.New("authority: a record body has an empty field or a value not in its one form")
	}
	return b, nil
}

// check checks b's fields against their rows.
func (b *Body) check() error {
	if b.V != 2 {
		return fmt.Errorf("authority: a record of version %d", b.V)
	}
	if b.Alg != AlgES256 {
		return fmt.Errorf("authority: a record signed with %q", b.Alg)
	}
	allowed, ok := fields[b.Type]
	if !ok {
		return fmt.Errorf("authority: an unknown record type %q", b.Type)
	}
	for _, n := range b.present() {
		if !allowed[n] {
			return fmt.Errorf("authority: a %s record has %s", b.Type, n)
		}
	}
	if b.Group == "" {
		return errors.New("authority: a record has no group")
	}
	if b.Seq < 1 || b.Seq > MaxSeq {
		return fmt.Errorf("authority: a record's seq %d is not from 1 to %d", b.Seq, MaxSeq)
	}
	if (b.Seq == 1) != (b.Prev == nil) {
		return errors.New("authority: a record has prev exactly when its seq is above 1")
	}
	switch b.Type {
	case TypeDevice:
		return b.checkDevice()
	case TypeRevoke, TypeFreeze:
		if len(b.Keys) == 0 || len(b.Seen) == 0 {
			return fmt.Errorf("authority: a %s record needs keys and seen", b.Type)
		}
		if err := sortedHashes(b.Keys, "keys"); err != nil {
			return err
		}
		return checkSeen(b.Seen)
	case TypeThaw, TypeResolve:
		if len(b.Records) == 0 {
			return fmt.Errorf("authority: a %s record needs records", b.Type)
		}
		return sortedHashes(b.Records, "records")
	case TypeClaim:
		if len(b.Root) == 0 || len(b.Seen) == 0 {
			return errors.New("authority: a claim needs root and seen")
		}
		return checkSeen(b.Seen)
	case TypeSettings:
		if d := b.TakeoverDelayMS; d != nil && (*d < 0 || *d > MaxDelay) {
			return fmt.Errorf("authority: a takeover delay of %d ms is not from 0 to %d", *d, MaxDelay)
		}
		if b.KeyLevel != "" && !slices.Contains(KeyLevels, b.KeyLevel) {
			return fmt.Errorf("authority: an unknown key level %q", b.KeyLevel)
		}
	case TypeCheckpoint:
		if len(b.Heads) == 0 {
			return errors.New("authority: a checkpoint needs heads")
		}
		for i, h := range b.Heads {
			if h.Seq < 1 || h.Seq > MaxSeq {
				return fmt.Errorf("authority: a head's seq %d is not from 1 to %d", h.Seq, MaxSeq)
			}
			if i > 0 && b.Heads[i-1].Key.String() >= h.Key.String() {
				return errors.New("authority: heads is not sorted by key, each once")
			}
		}
		return sortedHashes(b.Keep, "keep")
	case TypeHubs:
		return checkHubs(b.Hubs)
	case TypeRecovery:
		if b.Admin == nil || len(b.Cert) == 0 {
			return errors.New("authority: a recovery record needs admin and cert")
		}
		ca, err := x509.ParseCertificate(b.Cert)
		if err != nil || KeyHashOf(ca) != *b.Admin {
			return errors.New("authority: a recovery record's cert is not the admin CA of its admin key")
		}
	case TypeHandover:
		if b.Admin == nil {
			return errors.New("authority: a handover record needs admin")
		}
	}
	return nil
}

// checkHubs checks a hubs record's hubs: 1 to MaxHubs device IDs, each
// once, in the user's order.
func checkHubs(hubs []string) error {
	if len(hubs) == 0 || len(hubs) > MaxHubs {
		return fmt.Errorf("authority: a hubs record names %d devices, not 1 to %d", len(hubs), MaxHubs)
	}
	seen := map[string]bool{}
	for _, h := range hubs {
		if !deviceID(h) || seen[h] {
			return errors.New("authority: a hubs record's hubs are not device IDs, each once")
		}
		seen[h] = true
	}
	return nil
}

// maxBody is the largest body of b's type.
func (b *Body) maxBody() int {
	if b.Type == TypeCheckpoint {
		return MaxCheckpointBody
	}
	return MaxBody
}

func (b *Body) checkDevice() error {
	if !deviceID(b.Device) {
		return errors.New("authority: a device record's device is not a device ID")
	}
	if !ValidName(b.Name) {
		return errors.New("authority: a device record's name is not 1 to 64 bytes without control characters")
	}
	if !roles[b.Role] {
		return fmt.Errorf("authority: an unknown role %q", b.Role)
	}
	if b.OS != "" && !oses[b.OS] {
		return fmt.Errorf("authority: an unknown os %q", b.OS)
	}
	if b.Key == nil {
		return errors.New("authority: a device record has no key")
	}
	if b.Admin == nil && (len(b.Powers) > 0 || len(b.Commands) > 0) {
		return errors.New("authority: powers and commands come only with admin")
	}
	if len(b.Seal) > 0 && len(b.Seal) != SealKeySize {
		return fmt.Errorf("authority: a device record's seal is %d bytes, not %d", len(b.Seal), SealKeySize)
	}
	if err := sortedOf(b.Powers, Powers, "powers"); err != nil {
		return err
	}
	return sortedOf(b.Commands, Commands, "commands")
}

// ValidName reports whether s is a device name: 1 to 64 bytes of UTF-8
// without a control character (U+0000 to U+001F, U+007F to U+009F).
func ValidName(s string) bool {
	if len(s) < 1 || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return false
		}
	}
	return true
}

func deviceID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sortedHashes checks that hs is sorted by its base64 strings, each once.
func sortedHashes(hs []Hash, field string) error {
	for i := 1; i < len(hs); i++ {
		if hs[i-1].String() >= hs[i].String() {
			return fmt.Errorf("authority: %s is not sorted, each once", field)
		}
	}
	return nil
}

func checkSeen(seen []Seen) error {
	for i, s := range seen {
		if s.Seq < 0 || s.Seq > MaxSeq {
			return fmt.Errorf("authority: a seen seq %d is not from 0 to %d", s.Seq, MaxSeq)
		}
		if i > 0 && seen[i-1].Key.String() >= s.Key.String() {
			return errors.New("authority: seen is not sorted by key, each once")
		}
	}
	return nil
}

// sortedOf checks that vs is sorted, each once, and each one of known.
func sortedOf(vs, known []string, field string) error {
	for i, v := range vs {
		if j := sort.SearchStrings(known, v); j == len(known) || known[j] != v {
			return fmt.Errorf("authority: an unknown value %q in %s", v, field)
		}
		if i > 0 && vs[i-1] >= v {
			return fmt.Errorf("authority: %s is not sorted, each once", field)
		}
	}
	return nil
}

// Sort puts b's arrays in the order the canonical form wants, for a
// signer that built them in another order.
func (b *Body) Sort() {
	sort.Strings(b.Powers)
	sort.Strings(b.Commands)
	byString := func(hs []Hash) {
		sort.Slice(hs, func(i, j int) bool { return hs[i].String() < hs[j].String() })
	}
	byString(b.Keys)
	byString(b.Records)
	byString(b.Keep)
	sort.Slice(b.Heads, func(i, j int) bool { return b.Heads[i].Key.String() < b.Heads[j].Key.String() })
	sort.Slice(b.Seen, func(i, j int) bool { return b.Seen[i].Key.String() < b.Seen[j].Key.String() })
}

// Record is a signed record as it travels and is kept: its body's exact
// bytes, the signature over them, and the signer's admin CA when an
// admin signed it.
type Record struct {
	Body  []byte   `json:"body"`
	Sig   []byte   `json:"sig"`
	Chain [][]byte `json:"chain"`
}

// MarshalJSON writes the envelope with chain, empty for a root's own key,
// as the records Sign makes and a set keeps carry it; a record that never
// had one (nil), as a test's made-up record, is written without it, as
// version 1 wrote such records, never with a null chain.
func (r Record) MarshalJSON() ([]byte, error) {
	if r.Chain == nil {
		return json.Marshal(struct {
			Body []byte `json:"body"`
			Sig  []byte `json:"sig"`
		}{r.Body, r.Sig})
	}
	type plain Record
	return json.Marshal(plain(r))
}

// ID returns the record ID: SHA-256 over the body.
func (r Record) ID() Hash { return sha256.Sum256(r.Body) }

// Signed is a record whose body was read and whose signature verifies
// with the key its body names.
type Signed struct {
	Record
	Body Body
	ID   Hash
	// AdminCA is the admin CA in the chain, nil when a root's own key
	// signed.
	AdminCA *x509.Certificate
}

// Verify reads r's body and checks its signature. With an admin CA in the
// chain the body's signer must be that CA's key and the signature verify
// with it. With an empty chain the signer must be the hash of rootKey's
// key, a root the group may have, which the caller finds by the signer.
// Where the admin CA stands and whether the signer may sign the record is
// for the evaluation.
func Verify(r Record, rootKey func(Hash) crypto.PublicKey) (*Signed, error) {
	b, err := ParseBody(r.Body)
	if err != nil {
		return nil, err
	}
	s := &Signed{Record: r, Body: b, ID: r.ID()}
	var pub crypto.PublicKey
	switch len(r.Chain) {
	case 0:
		pub = rootKey(b.Signer)
		if pub == nil {
			return nil, errors.New("authority: a record's signer is no root of the group")
		}
	case 1:
		ca, err := x509.ParseCertificate(r.Chain[0])
		if err != nil {
			return nil, fmt.Errorf("authority: a record's admin CA: %w", err)
		}
		if KeyHashOf(ca) != b.Signer {
			return nil, errors.New("authority: a record's signer is not its admin CA's key")
		}
		s.AdminCA, pub = ca, ca.PublicKey
	default:
		return nil, errors.New("authority: a record's chain holds more than its admin CA")
	}
	if h, err := PublicKeyHash(pub); err != nil || h != b.Signer {
		return nil, errors.New("authority: a record's signer is not the key it is checked with")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	digest := sha256.Sum256(r.Body)
	if !ok || !ecdsa.VerifyASN1(ec, digest[:], r.Sig) {
		return nil, errors.New("authority: a record's signature does not verify")
	}
	return s, nil
}

// Sign signs b with key, a root's own key (adminCA nil) or the admin key
// that adminCA certifies. It sets the body's signer and sorts its arrays.
func Sign(b Body, key crypto.Signer, adminCA *x509.Certificate) (Record, error) {
	signer, err := PublicKeyHash(key.Public())
	if err != nil {
		return Record{}, err
	}
	if adminCA != nil && KeyHashOf(adminCA) != signer {
		return Record{}, errors.New("authority: the admin CA does not certify the signing key")
	}
	if pub, ok := key.Public().(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return Record{}, errors.New("authority: version 2 signs only with a P-256 key")
	}
	b.V, b.Alg, b.Signer = 2, AlgES256, signer
	b.Sort()
	body, err := b.Encode()
	if err != nil {
		return Record{}, err
	}
	if max := b.maxBody(); len(body) > max {
		return Record{}, fmt.Errorf("authority: a record body of %d bytes is over %d", len(body), max)
	}
	digest := sha256.Sum256(body)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return Record{}, err
	}
	r := Record{Body: body, Sig: sig, Chain: [][]byte{}}
	if adminCA != nil {
		r.Chain = [][]byte{adminCA.Raw}
	}
	return r, nil
}
