// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package appletv

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/HunterEwok/cbb/internal/tvremote/appletv/wire"
)

// ErrNoField is no text field open on the TV.
var ErrNoField = errors.New("no text field is open on the Apple TV: open a search or a text field first")

// ErrNotPaired is the TV no longer taking this remote's keys.
var ErrNotPaired = errors.New("the Apple TV no longer knows this remote: pair it again with cbb remote add")

// The OPACK messages' types ("_t").
const (
	msgEvent    = 1
	msgRequest  = 2
	msgResponse = 3
)

// Remote is a verified connection to a paired TV.
type Remote struct {
	conn *wire.Conn
	xid  int64
}

// Dial connects to the TV at host and runs pair-verify with the
// credentials: both sides prove their long-term keys over a fresh X25519
// exchange, whose secret then keys the frames.
func Dial(ctx context.Context, host string, cr Credentials, name string) (*Remote, error) {
	if len(cr.Key) != ed25519.SeedSize || len(cr.TVKey) != ed25519.PublicKeySize {
		return nil, ErrNotPaired
	}
	c, err := dial(ctx, host)
	if err != nil {
		return nil, err
	}
	r := &Remote{conn: c}
	if err := r.verify(cr); err != nil {
		c.Close()
		return nil, err
	}
	if err := r.start(cr, name); err != nil {
		c.Close()
		return nil, err
	}
	return r, nil
}

func (r *Remote) verify(cr Credentials) error {
	mine, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pub := mine.PublicKey().Bytes()
	t, err := exchange(r.conn, wire.FramePVStart, map[string]any{"_auTy": int64(4)}, wire.TLV{
		{Type: wire.TLVState, Value: []byte{1}},
		{Type: wire.TLVPublicKey, Value: pub},
	})
	if errors.Is(err, ErrCode) {
		return ErrNotPaired
	}
	if err == nil {
		err = need(t, wire.TLVPublicKey, wire.TLVEncrypted)
	}
	if err != nil {
		return err
	}
	tvPub := t[wire.TLVPublicKey]
	theirs, err := ecdh.X25519().NewPublicKey(tvPub)
	if err != nil {
		return fmt.Errorf("the Apple TV's verify key: %w", err)
	}
	shared, err := mine.ECDH(theirs)
	if err != nil {
		return err
	}
	sk := wire.Key(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	plain, err := wire.Open(sk, "PV-Msg02", t[wire.TLVEncrypted])
	if err != nil {
		return err
	}
	tv, err := wire.DecodeTLV(plain)
	if err == nil {
		err = need(tv, wire.TLVID, wire.TLVSignature)
	}
	if err != nil {
		return err
	}
	if string(tv[wire.TLVID]) != string(cr.TV) {
		return errors.New("another Apple TV answers at this address: pair with it, or give the paired one's address")
	}
	if !ed25519.Verify(cr.TVKey, cat(tvPub, cr.TV, pub), tv[wire.TLVSignature]) {
		return errors.New("the Apple TV's signature does not verify: something other than the paired TV answers at this address")
	}
	priv := ed25519.NewKeyFromSeed(cr.Key)
	sealed, err := wire.Seal(sk, "PV-Msg03", wire.TLV{
		{Type: wire.TLVID, Value: []byte(cr.ID)},
		{Type: wire.TLVSignature, Value: ed25519.Sign(priv, cat(pub, []byte(cr.ID), tvPub))},
	}.Encode())
	if err != nil {
		return err
	}
	_, err = exchange(r.conn, wire.FramePVNext, nil, wire.TLV{
		{Type: wire.TLVState, Value: []byte{3}},
		{Type: wire.TLVEncrypted, Value: sealed},
	})
	if errors.Is(err, ErrCode) {
		return ErrNotPaired
	}
	if err != nil {
		return err
	}
	return r.conn.Encrypt(
		wire.Key(shared, "", "ClientEncrypt-main"),
		wire.Key(shared, "", "ServerEncrypt-main"))
}

// start introduces the remote and opens the remote session, as the
// iPhone's remote does.
func (r *Remote) start(cr Credentials, name string) error {
	if _, err := r.Call("_systemInfo", map[string]any{
		"_bf":    int64(0),
		"_cf":    int64(512),
		"_clFl":  int64(128),
		"_i":     cr.ID,
		"_idsID": cr.ID,
		"_pubID": cr.ID,
		"_sf":    int64(256),
		"_sv":    "170.18",
		"model":  "iPhone10,6",
		"name":   name,
	}); err != nil {
		return err
	}
	var sid [4]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return err
	}
	_, err := r.Call("_sessionStart", map[string]any{
		"_srvT": "com.apple.tvremoteservices",
		"_sid":  int64(binary.BigEndian.Uint32(sid[:])),
	})
	return err
}

// Call sends a request and waits for its response's content, skipping the
// events the TV sends meanwhile.
func (r *Remote) Call(id string, content map[string]any) (map[string]any, error) {
	r.xid++
	x := r.xid
	r.conn.SetDeadline(time.Now().Add(stepTimeout))
	if err := r.conn.WriteOPACK(wire.FrameEOPACK, map[string]any{
		"_i": id, "_t": int64(msgRequest), "_c": content, "_x": x,
	}); err != nil {
		return nil, err
	}
	for {
		typ, m, err := r.conn.ReadOPACK()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		if typ != wire.FrameEOPACK {
			continue
		}
		if t, _ := wire.Int(m, "_t"); t != msgResponse {
			continue
		}
		if got, _ := wire.Int(m, "_x"); got != x {
			continue
		}
		if em, ok := m["_em"]; ok {
			return nil, fmt.Errorf("the Apple TV refused %s: %v", id, em)
		}
		c, _ := m["_c"].(map[string]any)
		return c, nil
	}
}

// event sends an event, which has no response.
func (r *Remote) event(id string, content map[string]any) error {
	r.xid++
	r.conn.SetDeadline(time.Now().Add(stepTimeout))
	return r.conn.WriteOPACK(wire.FrameEOPACK, map[string]any{
		"_i": id, "_t": int64(msgEvent), "_c": content, "_x": r.xid,
	})
}

// session restarts the text input, so the field's session is the current
// one, and returns it; ErrNoField if no field is open.
func (r *Remote) session() ([]byte, error) {
	if _, err := r.Call("_tiStop", map[string]any{}); err != nil {
		return nil, err
	}
	c, err := r.Call("_tiStart", map[string]any{})
	if err != nil {
		return nil, err
	}
	d, ok := c["_tiD"].([]byte)
	if !ok {
		return nil, ErrNoField
	}
	return wire.InputSession(d)
}

// Type adds text to the field open on the TV, as one edit. A line break
// goes into the text as it is, which ends the entry where the field takes
// one line.
func (r *Remote) Type(text string) error {
	s, err := r.session()
	if err != nil {
		return err
	}
	d, err := wire.TextArchive(s, text, false)
	if err != nil {
		return err
	}
	if err := r.event("_tiC", map[string]any{"_tiV": int64(1), "_tiD": d}); err != nil {
		return err
	}
	// A request after the event returns once the TV has read both.
	_, err = r.Call("_tiStop", map[string]any{})
	return err
}

// Close ends the connection.
func (r *Remote) Close() error { return r.conn.Close() }
