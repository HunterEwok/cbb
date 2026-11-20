// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/blind"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// The registration's messages of `cbb-forward/3` (docs/protocol.md,
// section 13), each one frame of the format: their types.
const (
	tChallenge  = 80
	tRegister   = 81
	tRegistered = 82
	tError      = 83
	tSeen       = 84
)

// maxReason is the longest reason of an error, in bytes.
const maxReason = 256

// register is a hub's `forward/register`, read and checked against its
// table: its WireGuard key, the proof that it holds it, the group's
// obfuscation settings and VLESS user ID when it gave them, and its
// credentials' envelopes.
type register struct {
	Key         [32]byte
	Proof       [32]byte
	Obfuscation *tunnel.Obfuscation
	// BadObfuscation is set when settings of the table came that the
	// forwarder cannot route by: the way is then unusable, not the
	// message.
	BadObfuscation bool
	VLESS          string
	Credentials    [][]byte
}

// way is the way over VLESS of `forward/registered`: the group's user ID,
// the web server's port, its site and the group's path.
type way struct {
	User [16]byte
	Port uint16
	Host string
	Path string
}

func msgChallenge(e []byte) []byte {
	return blind.WriteFrame(blind.P(blind.FieldT, blind.Uint(tChallenge)), blind.P(2, blind.Bytes(e)))
}

func msgRegistered(id uint64, mask []byte, w *way) []byte {
	f := []blind.Pair{blind.P(blind.FieldT, blind.Uint(tRegistered)), blind.P(2, blind.Uint(id)), blind.P(3, blind.Bytes(mask))}
	if w != nil {
		m := []blind.Pair{blind.P(1, blind.Bytes(w.User[:]))}
		if w.Port != 0 {
			m = append(m, blind.P(2, blind.Uint(uint64(w.Port))))
		}
		if w.Host != "" {
			m = append(m, blind.P(3, blind.Text(w.Host)))
		}
		if w.Path != "" {
			m = append(m, blind.P(4, blind.Text(w.Path)))
		}
		f = append(f, blind.P(4, blind.Map(m...)))
	}
	return blind.WriteFrame(f...)
}

// msgError is a refusal, its reason cut to maxReason bytes at a whole
// character.
func msgError(reason string) []byte {
	if reason == "" {
		reason = "refused"
	}
	for len(reason) > maxReason {
		_, n := utf8.DecodeLastRuneInString(reason)
		reason = reason[:len(reason)-n]
	}
	return blind.WriteFrame(blind.P(blind.FieldT, blind.Uint(tError)), blind.P(2, blind.Text(reason)))
}

// msgSeen says where the forwarder sees the hub's WireGuard port, in the
// address's one written form.
func msgSeen(at netip.AddrPort) []byte {
	at = netip.AddrPortFrom(at.Addr().Unmap().WithZone(""), at.Port())
	return blind.WriteFrame(blind.P(blind.FieldT, blind.Uint(tSeen)), blind.P(2, blind.Text(at.String())))
}

// canonicalAddr tells whether s is an address and port in the one written
// form msgSeen gives: a port not 0, an address neither unspecified nor
// IPv4-mapped, without a zone.
func canonicalAddr(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.Port() != 0 && !ap.Addr().IsUnspecified() && !ap.Addr().Is4In6() &&
		ap.Addr().Zone() == "" && ap.String() == s
}

// field is the rule of a field of `forward/register`.
func field(name string) blind.Rule { return blind.Rule("forward/register/" + name) }

// vlessID writes a VLESS user ID as internal/tunnel takes it.
func vlessID(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// readRegister reads a hub's `forward/register` against its table. A field
// of a later version is passed over; a needed field missing or broken
// refuses the message by its rule.
func readRegister(t uint64, m blind.Value) (*register, error) {
	if t != tRegister {
		return nil, errors.New("not a registration")
	}
	r := &register{}
	k, ok := m.Get(2)
	if !ok || k.Kind != blind.KindArray || len(k.Array) != 2 || !k.Array[0].IsUint() || k.Array[0].Uint != 3 ||
		!k.Array[1].IsBytes() || len(k.Array[1].Bytes) != 32 {
		return nil, field("key")
	}
	r.Key = [32]byte(k.Array[1].Bytes)
	p, ok := m.Get(3)
	if !ok || !p.IsBytes() || len(p.Bytes) != 32 {
		return nil, field("proof")
	}
	r.Proof = [32]byte(p.Bytes)
	if o, ok := m.Get(4); ok {
		// Settings of the table that the forwarder cannot route by make
		// the way unusable, not the message.
		var usable bool
		if r.Obfuscation, usable = obfuscationOf(o); r.Obfuscation == nil {
			return nil, field("obfuscation")
		}
		r.BadObfuscation = !usable
	}
	if v, ok := m.Get(5); ok {
		if !v.IsBytes() || len(v.Bytes) != 16 {
			return nil, field("vless")
		}
		r.VLESS = vlessID([16]byte(v.Bytes))
	}
	c, ok := m.Get(6)
	if !ok || c.Kind != blind.KindArray || len(c.Array) == 0 || len(c.Array) > 3 {
		return nil, field("credentials")
	}
	for _, e := range c.Array {
		if _, err := blind.EnvelopeOf(e); err != nil {
			return nil, field("credentials")
		}
		r.Credentials = append(r.Credentials, blind.Encode(e))
	}
	return r, nil
}

// obfuscationOf reads the format's table `obfuscation` (1 jc 1..128, 2
// jmin 0..1280, 3 jmax 1..1280, 4 s: 1 to 4 sizes 0..1280, 5 h: 1 to 4
// headers, each a value or a range of 32 bits, 6 key, 32 bytes, when
// given) into the settings the forwarder routes by, a size or header not
// given 0: nil when they break the table, and usable when the forwarder can
// route by them (tunnel.Obfuscation's Check).
func obfuscationOf(v blind.Value) (o *tunnel.Obfuscation, usable bool) {
	if v.Kind != blind.KindMap {
		return nil, false
	}
	num := func(k uint16, lo, hi uint64) (int, bool) {
		x, ok := v.Get(k)
		if !ok || !x.IsUint() || x.Uint < lo || x.Uint > hi {
			return 0, false
		}
		return int(x.Uint), true
	}
	jc, ok1 := num(1, 1, 128)
	jmin, ok2 := num(2, 0, 1280)
	jmax, ok3 := num(3, 1, 1280)
	if !ok1 || !ok2 || !ok3 {
		return nil, false
	}
	o = &tunnel.Obfuscation{JC: jc, JMin: jmin, JMax: jmax}
	s, ok := v.Get(4)
	if !ok || s.Kind != blind.KindArray || len(s.Array) < 1 || len(s.Array) > 4 {
		return nil, false
	}
	for i, x := range s.Array {
		if !x.IsUint() || x.Uint > 1280 {
			return nil, false
		}
		*[]*int{&o.S1, &o.S2, &o.S3, &o.S4}[i] = int(x.Uint)
	}
	h, ok := v.Get(5)
	if !ok || h.Kind != blind.KindArray || len(h.Array) < 1 || len(h.Array) > 4 {
		return nil, false
	}
	for i, x := range h.Array {
		if x.Kind != blind.KindArray || len(x.Array) < 1 || len(x.Array) > 2 {
			return nil, false
		}
		for _, e := range x.Array {
			if !e.IsUint() || e.Uint > 1<<32-1 {
				return nil, false
			}
		}
		r := tunnel.Range{Min: uint32(x.Array[0].Uint), Max: uint32(x.Array[len(x.Array)-1].Uint)}
		*[]*tunnel.Range{&o.H1, &o.H2, &o.H3, &o.H4}[i] = r
	}
	if key, ok := v.Get(6); ok {
		if !key.IsBytes() || len(key.Bytes) != 32 {
			return nil, false
		}
		o.HeaderKey = tunnel.Key(key.Bytes)
	}
	return o, o.Check() == nil
}

// obfuscationValue writes settings as the format's table `obfuscation`,
// as a hub registers them: four sizes, four ranges, and the header
// protection key when there is one.
func obfuscationValue(o *tunnel.Obfuscation) blind.Value {
	u := func(n int) blind.Value { return blind.Uint(uint64(n)) }
	r := func(x tunnel.Range) blind.Value {
		return blind.Array(blind.Uint(uint64(x.Min)), blind.Uint(uint64(x.Max)))
	}
	m := []blind.Pair{
		blind.P(1, u(o.JC)), blind.P(2, u(o.JMin)), blind.P(3, u(o.JMax)),
		blind.P(4, blind.Array(u(o.S1), u(o.S2), u(o.S3), u(o.S4))),
		blind.P(5, blind.Array(r(o.H1), r(o.H2), r(o.H3), r(o.H4))),
	}
	if !o.HeaderKey.IsZero() {
		m = append(m, blind.P(6, blind.Bytes(o.HeaderKey[:])))
	}
	return blind.Map(m...)
}

// msgRegister is a hub's `forward/register`.
func msgRegister(r register) ([]byte, error) {
	f := []blind.Pair{
		blind.P(blind.FieldT, blind.Uint(tRegister)),
		blind.P(2, blind.Array(blind.Uint(3), blind.Bytes(r.Key[:]))),
		blind.P(3, blind.Bytes(r.Proof[:])),
	}
	if r.Obfuscation != nil {
		f = append(f, blind.P(4, obfuscationValue(r.Obfuscation)))
	}
	if r.VLESS != "" {
		id, err := hex.DecodeString(stripDashes(r.VLESS))
		if err != nil || len(id) != 16 {
			return nil, errors.New("the group's VLESS user ID is not one")
		}
		f = append(f, blind.P(5, blind.Bytes(id)))
	}
	creds := make([]blind.Value, 0, len(r.Credentials))
	for _, e := range r.Credentials {
		v, err := blind.Decode(e)
		if err != nil {
			return nil, fmt.Errorf("a credential of the hub's: %w", err)
		}
		creds = append(creds, v)
	}
	f = append(f, blind.P(6, blind.Array(creds...)))
	return blind.WriteFrame(f...), nil
}

func stripDashes(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		if s[i] != '-' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// answer is the forwarder's answer as a hub reads it: `forward/registered`
// or `forward/error`, and later `forward/seen`.
type answer struct {
	ID    uint64
	Mask  []byte
	VLESS *way
	Error string
	Seen  string
}

// readAnswer reads a message of the forwarder's.
func readAnswer(t uint64, m blind.Value) (answer, error) {
	text := func(k uint16) string {
		v, _ := m.Get(k)
		if v.IsText() {
			return v.TextOf()
		}
		return ""
	}
	switch t {
	case tError:
		return answer{Error: text(2)}, nil
	case tSeen:
		at := text(2)
		if !canonicalAddr(at) {
			return answer{}, blind.Rule("forward/seen/addr")
		}
		return answer{Seen: at}, nil
	case tRegistered:
		var a answer
		if id, ok := m.Get(2); ok && id.IsUint() {
			a.ID = id.Uint
		}
		if mk, ok := m.Get(3); ok && mk.IsBytes() && len(mk.Bytes) == 32 {
			a.Mask = mk.Bytes
		}
		if w, ok := m.Get(4); ok && w.Kind == blind.KindMap {
			u, ok := w.Get(1)
			if ok && u.IsBytes() && len(u.Bytes) == 16 {
				a.VLESS = &way{User: [16]byte(u.Bytes), Port: 443}
				if p, ok := w.Get(2); ok && p.IsUint() && p.Uint > 0 && p.Uint <= 65535 {
					a.VLESS.Port = uint16(p.Uint)
				}
				if h, ok := w.Get(3); ok && h.IsText() {
					a.VLESS.Host = h.TextOf()
				}
				if p, ok := w.Get(4); ok && p.IsText() {
					a.VLESS.Path = p.TextOf()
				}
			}
		}
		return a, nil
	}
	return answer{}, fmt.Errorf("not a message of the forwarder's (t %d)", t)
}
