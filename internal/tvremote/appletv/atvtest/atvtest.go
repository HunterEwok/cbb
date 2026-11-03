// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package atvtest is a fake Apple TV for tests: the Companion port with
// pair-setup by a PIN, pair-verify, and a text field the test opens.
package atvtest

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tvremote/appletv/wire"
)

// id is the fake TV's pairing identifier.
const id = "FA4E7E1E-0000-4000-8000-000000000001"

// TV is the fake TV. Its port is random; Addr names it.
type TV struct {
	l   net.Listener
	key ed25519.PrivateKey

	mu      sync.Mutex
	pin     string
	paired  map[string]ed25519.PublicKey // the remotes, by identifier
	names   []string                     // the names the remotes gave
	focused bool
	session []byte // the open field's input session
	conns   []net.Conn
	text    []string // what came into the text field, one edit each
	changed chan struct{}
}

// New starts a TV, closed with the test.
func New(t testing.TB) *TV {
	t.Helper()
	tv, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tv.Close)
	return tv
}

// Start starts a TV whose Companion port listens at addr; the caller
// closes it.
func Start(addr string) (*TV, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	tv := &TV{l: l, key: key, paired: map[string]ed25519.PublicKey{}, changed: make(chan struct{}, 1)}
	go tv.accept()
	return tv, nil
}

// Addr is the TV's address with its Companion port.
func (tv *TV) Addr() string { return tv.l.Addr().String() }

// PIN is the PIN the TV shows, "" before a pairing asks for one.
func (tv *TV) PIN() string {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	return tv.pin
}

// Names are the names the paired remotes gave.
func (tv *TV) Names() []string {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	return append([]string(nil), tv.names...)
}

// Forget forgets the paired remotes, as a reset TV does.
func (tv *TV) Forget() {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	tv.paired = map[string]ed25519.PublicKey{}
}

// Focus opens a text field on the TV, with a new input session.
func (tv *TV) Focus() {
	s := make([]byte, 16)
	rand.Read(s)
	tv.mu.Lock()
	tv.focused, tv.session = true, s
	tv.mu.Unlock()
}

// Text is what came into the text field.
func (tv *TV) Text() []string {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	return append([]string(nil), tv.text...)
}

// Wait waits until the text field has n edits.
func (tv *TV) Wait(t testing.TB, n int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if text := tv.Text(); len(text) >= n {
			return
		}
		select {
		case <-tv.changed:
		case <-deadline:
			t.Fatalf("the TV has %q, want %d edits", tv.Text(), n)
		}
	}
}

// Close stops the TV.
func (tv *TV) Close() {
	tv.l.Close()
	tv.mu.Lock()
	defer tv.mu.Unlock()
	for _, c := range tv.conns {
		c.Close()
	}
}

func (tv *TV) accept() {
	for {
		c, err := tv.l.Accept()
		if err != nil {
			return
		}
		tv.mu.Lock()
		tv.conns = append(tv.conns, c)
		tv.mu.Unlock()
		go func() {
			defer c.Close()
			(&conn{tv: tv, c: wire.NewConn(c)}).serve()
		}()
	}
}

// conn is one remote's connection and its pairing state.
type conn struct {
	tv *TV
	c  *wire.Conn

	srp    *wire.SRPServer
	srpKey []byte

	verify   *ecdh.PrivateKey
	remote   []byte // the remote's verify key
	shared   []byte
	verified bool
}

func (c *conn) serve() {
	for {
		typ, m, err := c.c.ReadOPACK()
		if err != nil {
			return
		}
		switch typ {
		case wire.FramePSStart, wire.FramePSNext:
			err = c.pairSetup(m)
		case wire.FramePVStart, wire.FramePVNext:
			err = c.pairVerify(m)
		case wire.FrameEOPACK:
			if !c.verified {
				return
			}
			err = c.message(m)
		}
		if err != nil {
			return
		}
	}
}

func pairingData(m map[string]any) (map[byte][]byte, error) {
	pd, ok := m["_pd"].([]byte)
	if !ok {
		return nil, errors.New("no _pd")
	}
	return wire.DecodeTLV(pd)
}

func (c *conn) answer(typ byte, items ...wire.TLVItem) error {
	return c.c.WriteOPACK(typ, map[string]any{"_pd": wire.TLV(items).Encode()})
}

func (c *conn) fail(typ byte, state, code byte) error {
	return c.answer(typ,
		wire.TLVItem{Type: wire.TLVState, Value: []byte{state}},
		wire.TLVItem{Type: wire.TLVError, Value: []byte{code}})
}

func (c *conn) pairSetup(m map[string]any) error {
	t, err := pairingData(m)
	if err != nil {
		return err
	}
	switch string(t[wire.TLVState]) {
	case "\x01":
		n, err := rand.Int(rand.Reader, big.NewInt(10000))
		if err != nil {
			return err
		}
		pin := fmt.Sprintf("%04d", n)
		if c.srp, err = wire.NewSRPServer(pin); err != nil {
			return err
		}
		c.tv.mu.Lock()
		c.tv.pin = pin
		c.tv.mu.Unlock()
		return c.answer(wire.FramePSNext,
			wire.TLVItem{Type: wire.TLVState, Value: []byte{2}},
			wire.TLVItem{Type: wire.TLVSalt, Value: c.srp.Salt},
			wire.TLVItem{Type: wire.TLVPublicKey, Value: c.srp.Public()})
	case "\x03":
		if c.srp == nil {
			return c.fail(wire.FramePSNext, 4, wire.TLVErrUnknown)
		}
		m2, key, err := c.srp.Verify(t[wire.TLVPublicKey], t[wire.TLVProof])
		if err != nil {
			return c.fail(wire.FramePSNext, 4, wire.TLVErrAuthentication)
		}
		c.srpKey = key
		return c.answer(wire.FramePSNext,
			wire.TLVItem{Type: wire.TLVState, Value: []byte{4}},
			wire.TLVItem{Type: wire.TLVProof, Value: m2})
	case "\x05":
		if c.srpKey == nil {
			return c.fail(wire.FramePSNext, 6, wire.TLVErrUnknown)
		}
		sk := wire.Key(c.srpKey, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
		plain, err := wire.Open(sk, "PS-Msg05", t[wire.TLVEncrypted])
		if err != nil {
			return c.fail(wire.FramePSNext, 6, wire.TLVErrAuthentication)
		}
		r, err := wire.DecodeTLV(plain)
		if err != nil {
			return err
		}
		x := wire.Key(c.srpKey, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
		pub := r[wire.TLVPublicKey]
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, cat(x, r[wire.TLVID], pub), r[wire.TLVSignature]) {
			return c.fail(wire.FramePSNext, 6, wire.TLVErrAuthentication)
		}
		name := ""
		if v, err := wire.Unpack(r[wire.TLVName]); err == nil {
			if m, ok := v.(map[string]any); ok {
				name, _ = m["name"].(string)
			}
		}
		c.tv.mu.Lock()
		c.tv.paired[string(r[wire.TLVID])] = pub
		c.tv.names = append(c.tv.names, name)
		c.tv.pin = ""
		c.tv.mu.Unlock()
		ax := wire.Key(c.srpKey, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
		mine := c.tv.key.Public().(ed25519.PublicKey)
		sealed, err := wire.Seal(sk, "PS-Msg06", wire.TLV{
			{Type: wire.TLVID, Value: []byte(id)},
			{Type: wire.TLVPublicKey, Value: mine},
			{Type: wire.TLVSignature, Value: ed25519.Sign(c.tv.key, cat(ax, []byte(id), mine))},
		}.Encode())
		if err != nil {
			return err
		}
		return c.answer(wire.FramePSNext,
			wire.TLVItem{Type: wire.TLVState, Value: []byte{6}},
			wire.TLVItem{Type: wire.TLVEncrypted, Value: sealed})
	}
	return c.fail(wire.FramePSNext, 2, wire.TLVErrUnknown)
}

func (c *conn) pairVerify(m map[string]any) error {
	t, err := pairingData(m)
	if err != nil {
		return err
	}
	switch string(t[wire.TLVState]) {
	case "\x01":
		theirs, err := ecdh.X25519().NewPublicKey(t[wire.TLVPublicKey])
		if err != nil {
			return c.fail(wire.FramePVNext, 2, wire.TLVErrAuthentication)
		}
		if c.verify, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			return err
		}
		if c.shared, err = c.verify.ECDH(theirs); err != nil {
			return err
		}
		c.remote = t[wire.TLVPublicKey]
		pub := c.verify.PublicKey().Bytes()
		sk := wire.Key(c.shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
		sealed, err := wire.Seal(sk, "PV-Msg02", wire.TLV{
			{Type: wire.TLVID, Value: []byte(id)},
			{Type: wire.TLVSignature, Value: ed25519.Sign(c.tv.key, cat(pub, []byte(id), c.remote))},
		}.Encode())
		if err != nil {
			return err
		}
		return c.answer(wire.FramePVNext,
			wire.TLVItem{Type: wire.TLVState, Value: []byte{2}},
			wire.TLVItem{Type: wire.TLVPublicKey, Value: pub},
			wire.TLVItem{Type: wire.TLVEncrypted, Value: sealed})
	case "\x03":
		if c.shared == nil {
			return c.fail(wire.FramePVNext, 4, wire.TLVErrUnknown)
		}
		sk := wire.Key(c.shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
		plain, err := wire.Open(sk, "PV-Msg03", t[wire.TLVEncrypted])
		if err != nil {
			return c.fail(wire.FramePVNext, 4, wire.TLVErrAuthentication)
		}
		r, err := wire.DecodeTLV(plain)
		if err != nil {
			return err
		}
		c.tv.mu.Lock()
		key, ok := c.tv.paired[string(r[wire.TLVID])]
		c.tv.mu.Unlock()
		mine := c.verify.PublicKey().Bytes()
		if !ok || !ed25519.Verify(key, cat(c.remote, r[wire.TLVID], mine), r[wire.TLVSignature]) {
			return c.fail(wire.FramePVNext, 4, wire.TLVErrAuthentication)
		}
		if err := c.answer(wire.FramePVNext, wire.TLVItem{Type: wire.TLVState, Value: []byte{4}}); err != nil {
			return err
		}
		c.verified = true
		return c.c.Encrypt(
			wire.Key(c.shared, "", "ServerEncrypt-main"),
			wire.Key(c.shared, "", "ClientEncrypt-main"))
	}
	return c.fail(wire.FramePVNext, 2, wire.TLVErrUnknown)
}

// message answers a request, and takes the text of a "_tiC" event.
func (c *conn) message(m map[string]any) error {
	id, _ := m["_i"].(string)
	t, _ := wire.Int(m, "_t")
	if t == 1 {
		if id != "_tiC" {
			return nil
		}
		content, _ := m["_c"].(map[string]any)
		d, _ := content["_tiD"].([]byte)
		session, text, clear, err := wire.TextOperation(d)
		if err != nil {
			return err
		}
		c.tv.mu.Lock()
		ok := c.tv.focused && string(session) == string(c.tv.session)
		c.tv.mu.Unlock()
		if !ok {
			return nil // a stale session: the TV drops it
		}
		if clear {
			text = "\x00clear"
		}
		c.tv.mu.Lock()
		c.tv.text = append(c.tv.text, text)
		c.tv.mu.Unlock()
		select {
		case c.tv.changed <- struct{}{}:
		default:
		}
		return nil
	}
	answer := map[string]any{}
	switch id {
	case "_sessionStart":
		answer["_sid"] = int64(7)
	case "_tiStart":
		c.tv.mu.Lock()
		focused, session := c.tv.focused, c.tv.session
		c.tv.mu.Unlock()
		if focused {
			d, err := wire.SessionArchive(session)
			if err != nil {
				return err
			}
			answer["_tiD"] = d
		}
	case "_systemInfo", "_tiStop":
	default:
		return c.c.WriteOPACK(wire.FrameEOPACK, map[string]any{"_t": int64(3), "_x": m["_x"], "_em": "unknown request " + id})
	}
	return c.c.WriteOPACK(wire.FrameEOPACK, map[string]any{"_t": int64(3), "_x": m["_x"], "_c": answer})
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
