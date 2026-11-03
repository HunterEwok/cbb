// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package invite is the remote invitation: what a device that shares no
// network with the group needs to join it through the hub's tunnel
// (docs/design.md, "Joining from another network"; docs/protocol.md,
// section 12). It travels only as a QR code or a file, never typed, and is a
// secret until it is used.
package invite

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/strict"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// prefix starts an invitation's text: the URI of a QR code, and the one
// line of a .cbbinvite file. The rest is a fragment, which a browser never
// sends anywhere.
const prefix = "cbb://invite#"

// Ext is the file name extension of an invitation file.
const Ext = ".cbbinvite"

// MaxLifetime is the longest an invitation may be valid; DefaultLifetime
// is how long it is unless the admin asks otherwise.
const (
	MaxLifetime     = 24 * time.Hour
	DefaultLifetime = time.Hour
)

// Invitation is everything a device needs to join through the hub.
type Invitation struct {
	Group     string           // the group's tag
	Hub       string           // the hub's device ID
	HubKey    tunnel.Key       // the hub's WireGuard public key
	Endpoints []netip.AddrPort // where the hub's UDP port is reached
	GuestKey  tunnel.Key       // the one-time WireGuard private key of the guest tunnel
	GuestPSK  tunnel.Key       // its preshared key
	Secret    []byte           // the pairing secret, in place of a code
	Expires   time.Time
	// Obfuscation is the hub's AmneziaWG settings; nil for plain
	// WireGuard.
	Obfuscation *tunnel.Obfuscation
}

// wire is the JSON of an invitation, with short names for a small QR code.
type wire struct {
	V         int      `json:"v"`
	Group     string   `json:"g"`
	Hub       string   `json:"h"`
	HubKey    []byte   `json:"hk"`
	Endpoints []string `json:"ep"`
	GuestKey  []byte   `json:"k"`
	GuestPSK  []byte   `json:"psk"`
	Secret    []byte   `json:"s"`
	Expires   int64    `json:"exp"` // Unix seconds

	Obfuscation *tunnel.Obfuscation `json:"o,omitempty"`
}

// String returns the invitation's text.
func (in *Invitation) String() string {
	w := wire{V: 1, Group: in.Group, Hub: in.Hub, HubKey: in.HubKey[:], GuestKey: in.GuestKey[:],
		GuestPSK: in.GuestPSK[:], Secret: in.Secret, Expires: in.Expires.Unix(), Obfuscation: in.Obfuscation}
	for _, ep := range in.Endpoints {
		w.Endpoints = append(w.Endpoints, ep.String())
	}
	data, err := json.Marshal(w)
	if err != nil {
		panic(err) // it has nothing that cannot be marshaled
	}
	return prefix + base64.StdEncoding.EncodeToString(data)
}

// Reason names why Parse refused a text, the same in Go and in the Rust
// core (cbb_core::invite), as testdata/interop/invites.json lists them.
type Reason string

// The reasons Parse gives.
const (
	NotInvitation  Reason = "not_invitation" // not the invitation's prefix
	Damaged        Reason = "damaged"        // not standard base64, not strict JSON, a field missing, unknown or of another type
	Version        Reason = "version"        // a v other than 1
	BadGroup       Reason = "group"          // g is not a group tag
	BadHub         Reason = "hub"            // h is not a device ID
	BadKey         Reason = "key"            // hk, k or psk is not 32 bytes, or all zeros
	BadEndpoints   Reason = "endpoints"      // ep is empty, longer than 8, or holds an address that is not ip:port
	BadSecret      Reason = "secret"         // s is shorter than 16 bytes or longer than 64
	BadExpiry      Reason = "expiry"         // exp is not after 0
	BadObfuscation Reason = "obfuscation"    // o is damaged
)

// Error is Parse's error.
type Error struct {
	Reason Reason
	msg    string
}

func (e *Error) Error() string { return "invite: " + e.msg }

func refuse(r Reason, msg string) error { return &Error{Reason: r, msg: msg} }

// MaxSecret is the longest pairing secret an invitation carries.
const MaxSecret = 64

// strictWire is what Parse reads: the fields of wire, with the byte
// strings as text so that only their standard form passes.
type strictWire struct {
	V         int64      `json:"v"`
	Group     string     `json:"g"`
	Hub       string     `json:"h"`
	HubKey    string     `json:"hk"`
	Endpoints []string   `json:"ep"`
	GuestKey  string     `json:"k"`
	GuestPSK  string     `json:"psk"`
	Secret    string     `json:"s"`
	Expires   int64      `json:"exp"`
	Obf       *strictObf `json:"o"`
}

type strictObf struct {
	JC        *int64  `json:"jc"`
	JMin      *int64  `json:"jmin"`
	JMax      *int64  `json:"jmax"`
	S1        *int64  `json:"s1"`
	S2        *int64  `json:"s2"`
	S3        *int64  `json:"s3"`
	S4        *int64  `json:"s4"`
	H1        *string `json:"h1"`
	H2        *string `json:"h2"`
	H3        *string `json:"h3"`
	H4        *string `json:"h4"`
	HeaderKey *string `json:"header_protection_key"`
}

// Parse reads an invitation's text, such as a file's content, and checks
// it; spaces, tabs and line breaks around it are ignored. It does not check the expiry
// (Expired does). The JSON must be in the strict form of signed bodies
// (docs/protocol.md, Conventions) with exactly the fields of section 12,
// byte strings in standard base64, so that every implementation reads one
// text alike.
func Parse(text string) (*Invitation, error) {
	text = strings.Trim(text, " \t\r\n")
	enc, ok := strings.CutPrefix(text, prefix)
	if !ok {
		return nil, refuse(NotInvitation, "this is not a cbb invitation")
	}
	// Go's decoder skips line breaks; the text has none.
	data, err := base64.StdEncoding.Strict().DecodeString(enc)
	if err != nil || strings.ContainsAny(enc, "\r\n") {
		return nil, refuse(Damaged, "the invitation is damaged")
	}
	if err := strict.Check(data, "v"); err != nil {
		return nil, refuse(Damaged, "the invitation is damaged")
	}
	var v struct {
		V json.RawMessage `json:"v"`
	}
	var version int64
	if err := json.Unmarshal(data, &v); err != nil || json.Unmarshal(v.V, &version) != nil {
		return nil, refuse(Damaged, "the invitation is damaged")
	}
	if version != 1 {
		return nil, refuse(Version, fmt.Sprintf("an invitation of version %d; update cbb", version))
	}
	if err := strict.Check(data, "v", "g", "h", "hk", "ep", "k", "psk", "s", "exp"); err != nil {
		return nil, refuse(Damaged, "the invitation is damaged")
	}
	var w strictWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, refuse(Damaged, "the invitation is damaged")
	}
	in := &Invitation{Group: w.Group, Hub: w.Hub, Expires: time.Unix(w.Expires, 0)}
	if !isHex(w.Group, 16) {
		return nil, refuse(BadGroup, "the invitation names no group")
	}
	if !isHex(w.Hub, 32) {
		return nil, refuse(BadHub, "the invitation names no hub")
	}
	for _, k := range []struct {
		dst *tunnel.Key
		src string
	}{{&in.HubKey, w.HubKey}, {&in.GuestKey, w.GuestKey}, {&in.GuestPSK, w.GuestPSK}} {
		b, err := strict.DecodeBase64(k.src)
		if err != nil || len(b) != len(k.dst) {
			return nil, refuse(BadKey, "the invitation lacks a key")
		}
		copy(k.dst[:], b)
		if k.dst.IsZero() {
			return nil, refuse(BadKey, "the invitation lacks a key")
		}
	}
	if len(w.Endpoints) == 0 || len(w.Endpoints) > 8 {
		return nil, refuse(BadEndpoints, "the invitation has no hub address, or too many")
	}
	for _, e := range w.Endpoints {
		ep, err := ParseEndpoint(e)
		if err != nil {
			return nil, refuse(BadEndpoints, "the invitation has an address that is not ip:port")
		}
		in.Endpoints = append(in.Endpoints, ep)
	}
	if in.Secret, err = strict.DecodeBase64(w.Secret); err != nil || len(in.Secret) < pair.MinSecret || len(in.Secret) > MaxSecret {
		return nil, refuse(BadSecret, "the invitation's secret is too short or too long")
	}
	if w.Expires <= 0 {
		return nil, refuse(BadExpiry, "the invitation has no expiry")
	}
	if w.Obf != nil {
		if in.Obfuscation, err = w.Obf.read(); err != nil {
			return nil, refuse(BadObfuscation, "the invitation's obfuscation settings are damaged")
		}
	}
	return in, nil
}

// Expired tells whether the invitation has expired at now.
func (in *Invitation) Expired(now time.Time) bool { return !now.Before(in.Expires) }

// ParseEndpoint reads an address as ip:port in its canonical form (an
// IPv6 address in brackets, without a zone), with a port that is not 0.
func ParseEndpoint(s string) (netip.AddrPort, error) {
	ep, err := netip.ParseAddrPort(s)
	if err != nil || ep.Addr().Zone() != "" || ep.Port() == 0 || ep.String() != s {
		return netip.AddrPort{}, fmt.Errorf("invite: %q is not ip:port", s)
	}
	return ep, nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (o *strictObf) read() (*tunnel.Obfuscation, error) {
	ints := []*int64{o.JC, o.JMin, o.JMax, o.S1, o.S2, o.S3, o.S4}
	strs := []*string{o.H1, o.H2, o.H3, o.H4, o.HeaderKey}
	for _, p := range ints {
		if p == nil || *p < 0 || *p > 1<<31 {
			return nil, errors.New("a number is missing or out of range")
		}
	}
	for _, p := range strs {
		if p == nil {
			return nil, errors.New("a field is missing")
		}
	}
	out := &tunnel.Obfuscation{JC: int(*o.JC), JMin: int(*o.JMin), JMax: int(*o.JMax),
		S1: int(*o.S1), S2: int(*o.S2), S3: int(*o.S3), S4: int(*o.S4)}
	for i, r := range []*tunnel.Range{&out.H1, &out.H2, &out.H3, &out.H4} {
		if err := r.UnmarshalText([]byte(*strs[i])); err != nil {
			return nil, err
		}
	}
	key, err := strict.DecodeBase64(*o.HeaderKey)
	if err != nil || len(key) != len(out.HeaderKey) {
		return nil, errors.New("the header protection key is not 32 bytes")
	}
	copy(out.HeaderKey[:], key)
	return out, out.Check()
}
