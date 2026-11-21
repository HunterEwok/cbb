// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package blind

import "slices"

// LabelCredential is the label server credentials are signed under.
const LabelCredential = "cbb credential v2"

// MaxCredentialBody is a credential body's ceiling (format section 13).
const MaxCredentialBody = 16 * 1024

// The kinds of credential.
const (
	TypePeriod  = 1
	TypeServer  = 2
	TypeHubs    = 3
	TypeMembers = 4
)

// The padded lengths of each list.
var (
	hubsLengths    = []int{4, 8, 16}
	adminsLengths  = []int{4, 8, 16, 32, 64}
	membersLengths = []int{4, 8, 16, 32, 64, 128, 256}
)

// RuleCritical is a field of a later version, or one the type does not
// list, which a server refuses.
const RuleCritical Rule = "form/critical"

// Credential is a server credential read, its signature checked by the
// Key in it.
type Credential struct {
	Kind uint64
	// Group is the Group ID for a period or a server credential, the
	// period's tag for a hubs' or a members' credential.
	Group     [16]byte
	Signer    []byte // the signer's point
	Version   uint64
	ExpiresMs uint64
	Tag       *[16]byte // period and server: the period's tag
	Key       []byte    // period: the period key; server: the server key
	Hubs      [][32]byte
	Admins    [][32]byte
	Members   [][32]byte
	ID        [32]byte // SHA-256 over the body
}

var kindNames = map[uint64]string{TypePeriod: "period", TypeServer: "server", TypeHubs: "hubs", TypeMembers: "members"}

// rule is the rule of a field of a kind, as the core names it.
func rule(kind uint64, field string) Rule {
	t := kindNames[kind]
	switch field {
	case "tag", "key":
		if t == "" {
			return "credentials/type"
		}
		return Rule("credentials/" + t + "/" + field)
	case "hubs", "admins":
		return Rule("credentials/hubs/" + field)
	case "members":
		return "credentials/members/members"
	case "signer", "version", "expires", "group", "signer2":
		return Rule("credentials/" + field)
	}
	return "credentials/type"
}

func hashes(v Value, ok bool, lengths []int, r Rule) ([][32]byte, error) {
	if !ok || v.Kind != KindArray || !slices.Contains(lengths, len(v.Array)) {
		return nil, r
	}
	out := make([][32]byte, 0, len(v.Array))
	for _, x := range v.Array {
		if !x.IsBytes() || len(x.Bytes) != 32 {
			return nil, r
		}
		out = append(out, [32]byte(x.Bytes))
	}
	return out, nil
}

// ReadCredential reads a credential envelope: its form, each field against
// its kind's row, then its signature by the Key in it.
func ReadCredential(b []byte) (*Credential, error) {
	env, err := ParseEnvelope(b, MaxCredentialBody)
	if err != nil {
		return nil, err
	}
	m := env.Map
	if s2, ok := m.Get(fieldSigner2); ok && (!s2.IsBytes() || len(s2.Bytes) != 32) {
		return nil, rule(0, "signer2")
	}
	kv, ok := m.Get(1)
	if !ok || !kv.IsUint() {
		return nil, rule(0, "type")
	}
	kind := kv.Uint
	if kind < TypePeriod || kind > TypeMembers {
		return nil, rule(kind, "type")
	}
	var allowed []uint16
	switch kind {
	case TypePeriod, TypeServer:
		allowed = []uint16{1, 2, 3, 4, 7, 10, 11}
	case TypeHubs:
		allowed = []uint16{1, 2, 3, 4, 7, 12, 13}
	default:
		allowed = []uint16{1, 2, 3, 4, 7, 14}
	}
	for _, p := range m.Map {
		// The optional zone, and the second signer, which the first
		// signature covers.
		if p.Key >= 256 || p.Key == fieldSigner2 {
			continue
		}
		if !slices.Contains(allowed, p.Key) {
			name := map[uint16]string{10: "tag", 11: "key", 12: "hubs", 13: "admins", 14: "members"}[p.Key]
			if name == "" {
				return nil, RuleCritical
			}
			return nil, rule(kind, name)
		}
	}
	c := &Credential{Kind: kind, ID: env.ID()}
	g, ok := m.Get(2)
	if !ok || !g.IsBytes() || len(g.Bytes) != 16 {
		return nil, rule(kind, "group")
	}
	c.Group = [16]byte(g.Bytes)
	sv, ok := m.Get(fieldSigner)
	if !ok {
		return nil, rule(kind, "signer")
	}
	if c.Signer, ok = es256Key(sv); !ok {
		return nil, rule(kind, "signer")
	}
	vv, ok := m.Get(4)
	if !ok || !vv.IsUint() || vv.Uint < 1 {
		return nil, rule(kind, "version")
	}
	c.Version = vv.Uint
	ev, ok := m.Get(7)
	if !ok || !ev.IsUint() || ev.Uint < 1 {
		return nil, rule(kind, "expires")
	}
	c.ExpiresMs = ev.Uint
	switch kind {
	case TypePeriod, TypeServer:
		t, ok := m.Get(10)
		if !ok || !t.IsBytes() || len(t.Bytes) != 16 {
			return nil, rule(kind, "tag")
		}
		tag := [16]byte(t.Bytes)
		c.Tag = &tag
		kv, ok := m.Get(11)
		if !ok {
			return nil, rule(kind, "key")
		}
		if c.Key, ok = es256Key(kv); !ok {
			return nil, rule(kind, "key")
		}
	case TypeHubs:
		v, ok := m.Get(12)
		if c.Hubs, err = hashes(v, ok, hubsLengths, rule(kind, "hubs")); err != nil {
			return nil, err
		}
		v, ok = m.Get(13)
		if c.Admins, err = hashes(v, ok, adminsLengths, rule(kind, "admins")); err != nil {
			return nil, err
		}
	default:
		v, ok := m.Get(14)
		if c.Members, err = hashes(v, ok, membersLengths, rule(kind, "members")); err != nil {
			return nil, err
		}
	}
	if err := env.Verify(c.Signer, LabelCredential); err != nil {
		return nil, err
	}
	return c, nil
}

// SignerHash is the hash of the signer's Key.
func (c *Credential) SignerHash() [32]byte { return KeyHash(AlgES256, c.Signer) }

// Live reports whether it is still good at nowMs.
func (c *Credential) Live(nowMs uint64) bool { return nowMs < c.ExpiresMs }

// Lists reports whether a hubs' credential lists the server key of hash h
// among its hubs.
func (c *Credential) Lists(h [32]byte) bool {
	return c.Kind == TypeHubs && slices.Contains(c.Hubs, h)
}

// The ways a set of credentials does not hold together.
const (
	ChainPeriod  Rule = "credentials/chain/period"
	ChainHubs    Rule = "credentials/chain/hubs"
	ChainMembers Rule = "credentials/chain/members"
)

// CheckChain checks that credentials hold together as a server needs
// them: the hubs' credential signed by the period key under the period's
// tag, and the members' credential, when given, by the period key or by a
// server key the hubs' credential lists among its admins.
func CheckChain(period, hubs, members *Credential) error {
	if period.Kind != TypePeriod || period.Tag == nil || period.Key == nil {
		return ChainPeriod
	}
	if hubs.Kind != TypeHubs || !slices.Equal(hubs.Signer, period.Key) || hubs.Group != *period.Tag {
		return ChainHubs
	}
	if members != nil {
		byPeriod := slices.Equal(members.Signer, period.Key)
		byAdmin := slices.Contains(hubs.Admins, members.SignerHash())
		if members.Kind != TypeMembers || members.Group != *period.Tag || !(byPeriod || byAdmin) {
			return ChainMembers
		}
	}
	return nil
}
