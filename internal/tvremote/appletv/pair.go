// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package appletv is a remote of an Apple TV through the Companion
// protocol, the one of the Apple TV Remote on an iPhone (docs/roadmap.md,
// item 25, way 2): it pairs with the PIN the TV shows, as HomeKit pairs
// (SRP with the PIN, then Ed25519 keys both sides keep), and then, after
// pair-verify on each connection, sets the text of the field open on the
// TV through its text input session, with no key presses.
//
// The protocol is not documented; this follows what pyatv found and the
// TV answered in the spike of 2026-11-01 (an Apple TV 4K of the second
// generation, tvOS 27.2). The TV refuses every pairing unless Settings,
// AirPlay and HomeKit, Allow Access is "Everyone on the Same Network" or
// "Everyone".
package appletv

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/tvremote/appletv/wire"
)

// Port is the Companion protocol's usual port. The TV announces its own
// in _companion-link._tcp; an address may name it.
const Port = 49153

// stepTimeout bounds each exchange with the TV.
const stepTimeout = 10 * time.Second

// Credentials are a pairing: this remote's identifier and key, and the
// TV's, which pair-verify checks on each connection.
type Credentials struct {
	ID    string `json:"id"`    // this remote's pairing identifier
	Key   []byte `json:"key"`   // its Ed25519 seed
	TV    []byte `json:"tv"`    // the TV's pairing identifier
	TVKey []byte `json:"tvKey"` // the TV's Ed25519 public key
}

// addr is the TV's address with the Companion port, unless host names one.
func addr(host string) string {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			return net.JoinHostPort(h, p)
		}
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(Port))
}

// dial connects to the TV, on the home network only.
func dial(ctx context.Context, host string) (*wire.Conn, error) {
	d := net.Dialer{Timeout: stepTimeout, Control: netguard.ControlHome}
	c, err := d.DialContext(ctx, "tcp", addr(host))
	if err != nil {
		return nil, fmt.Errorf("cannot reach the TV's Companion port: %w", err)
	}
	return wire.NewConn(c), nil
}

// The pairing's errors.
var (
	// ErrCode is a PIN that is not the one the TV shows.
	ErrCode = errors.New("that is not the PIN the TV shows")
	// ErrRefused is the TV refusing to pair.
	ErrRefused = errors.New(`the Apple TV refuses to pair: set Settings, AirPlay and HomeKit, Allow Access to "Everyone on the Same Network" on it, then try again`)
	// ErrBusy is the TV pairing with another device or locked after
	// wrong PINs.
	ErrBusy = errors.New("the Apple TV is busy pairing, or waits after wrong PINs: try again in a minute")
)

// pairingError reads a TLV8 error code.
func pairingError(code []byte) error {
	if len(code) != 1 {
		return fmt.Errorf("the Apple TV's pairing failed (error %x)", code)
	}
	switch code[0] {
	case wire.TLVErrAuthentication:
		return ErrCode
	case wire.TLVErrUnavailable, wire.TLVErrMaxPeers:
		return ErrRefused
	case wire.TLVErrBusy, wire.TLVErrBackOff, wire.TLVErrMaxTries:
		return ErrBusy
	}
	return fmt.Errorf("the Apple TV's pairing failed (error %d)", code[0])
}

// exchange sends a pairing message in "_pd" and reads the answer's TLV8.
// Every answer comes in the *Next frame of its kind.
func exchange(c *wire.Conn, typ byte, extra map[string]any, tlv wire.TLV) (map[byte][]byte, error) {
	m := map[string]any{"_pd": tlv.Encode()}
	for k, v := range extra {
		m[k] = v
	}
	c.SetDeadline(time.Now().Add(stepTimeout))
	if err := c.WriteOPACK(typ, m); err != nil {
		return nil, err
	}
	want := byte(wire.FramePSNext)
	if typ == wire.FramePVStart || typ == wire.FramePVNext {
		want = wire.FramePVNext
	}
	for {
		got, ans, err := c.ReadOPACK()
		if err != nil {
			return nil, err
		}
		if got != want {
			continue // not the pairing's: nothing else is expected yet
		}
		pd, ok := ans["_pd"].([]byte)
		if !ok {
			return nil, errors.New("the Apple TV's pairing answer has no data")
		}
		t, err := wire.DecodeTLV(pd)
		if err != nil {
			return nil, err
		}
		if e, ok := t[wire.TLVError]; ok {
			return nil, pairingError(e)
		}
		return t, nil
	}
}

// need reads TLV8 items an answer must have.
func need(t map[byte][]byte, types ...byte) error {
	for _, typ := range types {
		if len(t[typ]) == 0 {
			return fmt.Errorf("the Apple TV's pairing answer lacks item %#x", typ)
		}
	}
	return nil
}

// Pairing is a pair-setup in progress: the TV shows a PIN, which Finish
// takes.
type Pairing struct {
	conn *wire.Conn
	srp  *wire.SRPClient
	salt []byte
	b    []byte
	name string
}

// Pair asks the TV at host to pair with a new remote named name; the TV
// shows a PIN.
func Pair(ctx context.Context, host, name string) (*Pairing, error) {
	c, err := dial(ctx, host)
	if err != nil {
		return nil, err
	}
	srp, err := wire.NewSRPClient()
	if err != nil {
		c.Close()
		return nil, err
	}
	t, err := exchange(c, wire.FramePSStart, map[string]any{"_pwTy": int64(1)}, wire.TLV{
		{Type: wire.TLVMethod, Value: []byte{0}},
		{Type: wire.TLVState, Value: []byte{1}},
	})
	if err == nil {
		err = need(t, wire.TLVSalt, wire.TLVPublicKey)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return &Pairing{conn: c, srp: srp, salt: t[wire.TLVSalt], b: t[wire.TLVPublicKey], name: name}, nil
}

// Close ends the pairing; the TV stops showing the PIN.
func (p *Pairing) Close() error { return p.conn.Close() }

// Finish sends the PIN the TV shows, exchanges the keys and returns the
// credentials.
func (p *Pairing) Finish(pin string) (Credentials, error) {
	defer p.conn.Close()
	pin = strings.TrimSpace(pin)
	if len(pin) != 4 || strings.Trim(pin, "0123456789") != "" {
		return Credentials{}, fmt.Errorf("%w: it has four digits", ErrCode)
	}
	a, m1, m2, key, err := p.srp.Respond(p.salt, p.b, pin)
	if err != nil {
		return Credentials{}, err
	}
	pw := map[string]any{"_pwTy": int64(1)}
	t, err := exchange(p.conn, wire.FramePSNext, pw, wire.TLV{
		{Type: wire.TLVState, Value: []byte{3}},
		{Type: wire.TLVPublicKey, Value: a},
		{Type: wire.TLVProof, Value: m1},
	})
	if err != nil {
		return Credentials{}, err
	}
	if !equal(t[wire.TLVProof], m2) {
		return Credentials{}, errors.New("the Apple TV's SRP proof does not match: something between this device and the TV may have answered")
	}

	// M5: this remote's long-term key, signed, sealed under the SRP key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Credentials{}, err
	}
	id, err := newID()
	if err != nil {
		return Credentials{}, err
	}
	x := wire.Key(key, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
	sig := ed25519.Sign(priv, cat(x, []byte(id), pub))
	name, err := wire.Pack(map[string]any{"name": p.name})
	if err != nil {
		return Credentials{}, err
	}
	sk := wire.Key(key, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	sealed, err := wire.Seal(sk, "PS-Msg05", wire.TLV{
		{Type: wire.TLVID, Value: []byte(id)},
		{Type: wire.TLVPublicKey, Value: pub},
		{Type: wire.TLVSignature, Value: sig},
		{Type: wire.TLVName, Value: name},
	}.Encode())
	if err != nil {
		return Credentials{}, err
	}
	t, err = exchange(p.conn, wire.FramePSNext, pw, wire.TLV{
		{Type: wire.TLVState, Value: []byte{5}},
		{Type: wire.TLVEncrypted, Value: sealed},
	})
	if err == nil {
		err = need(t, wire.TLVEncrypted)
	}
	if err != nil {
		return Credentials{}, err
	}

	// M6: the TV's long-term key, signed the same way.
	plain, err := wire.Open(sk, "PS-Msg06", t[wire.TLVEncrypted])
	if err != nil {
		return Credentials{}, err
	}
	tv, err := wire.DecodeTLV(plain)
	if err == nil {
		err = need(tv, wire.TLVID, wire.TLVPublicKey, wire.TLVSignature)
	}
	if err != nil {
		return Credentials{}, err
	}
	tvKey := tv[wire.TLVPublicKey]
	if len(tvKey) != ed25519.PublicKeySize {
		return Credentials{}, fmt.Errorf("the Apple TV's key has %d bytes", len(tvKey))
	}
	tx := wire.Key(key, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
	if !ed25519.Verify(tvKey, cat(tx, tv[wire.TLVID], tvKey), tv[wire.TLVSignature]) {
		return Credentials{}, errors.New("the Apple TV's signature over its key does not verify")
	}
	return Credentials{ID: id, Key: priv.Seed(), TV: tv[wire.TLVID], TVKey: tvKey}, nil
}

// newID is a pairing identifier, a UUID as the iPhone's remote has.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0F | 0x40
	b[8] = b[8]&0x3F | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func equal(a, b []byte) bool {
	return len(a) == len(b) && len(a) > 0 && string(a) == string(b)
}
