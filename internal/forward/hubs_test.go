// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/blind"
	"github.com/HunterEwok/cbb/internal/group"
)

// testGroup is a group as a forwarder sees it (docs/protocol.md, section
// 13): its period's tag and period key, and the server key of one of its
// hubs with that key's certificate, which names neither a device nor a
// group.
type testGroup struct {
	tag    [16]byte
	period *ecdsa.PrivateKey
	hub    *ecdsa.PrivateKey
	cert   tls.Certificate
}

func newTestGroup(t testing.TB) *testGroup {
	t.Helper()
	g := &testGroup{}
	rand.Read(g.tag[:])
	var err error
	if g.period, err = group.NewKey(); err != nil {
		t.Fatal(err)
	}
	g.hub, g.cert = newServerKey(t)
	return g
}

// newServerKey is a hub's server key with its certificate.
func newServerKey(t testing.TB) (*ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	k, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := group.ServerCertificate(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, c
}

// serverKeyHash is the hash a hubs' credential lists a server key by.
func serverKeyHash(k *ecdsa.PrivateKey) [32]byte {
	return blind.KeyHash(blind.AlgES256, blind.Point(&k.PublicKey))
}

// name is the name the forwarder keeps the group under.
func (g *testGroup) name() string { return credentialTag(hex.EncodeToString(g.tag[:])) }

// hubs is the period's hubs' credential at version v that the period key
// signed, listing the server keys hubs, or the group's own hub's when none
// is given.
func (g *testGroup) hubs(t testing.TB, v uint64, hubs ...*ecdsa.PrivateKey) []byte {
	t.Helper()
	return g.signHubs(t, g.period, v, time.Now().Add(periodLifetime), hubs...)
}

// signHubs is a hubs' credential of the period's tag, signed by by, at
// version v, expiring at expires.
func (g *testGroup) signHubs(t testing.TB, by *ecdsa.PrivateKey, v uint64, expires time.Time, hubs ...*ecdsa.PrivateKey) []byte {
	t.Helper()
	if len(hubs) == 0 {
		hubs = []*ecdsa.PrivateKey{g.hub}
	}
	c := blind.Credential{Kind: blind.TypeHubs, Group: g.tag, Version: v, ExpiresMs: uint64(expires.UnixMilli())}
	for _, h := range hubs {
		c.Hubs = append(c.Hubs, serverKeyHash(h))
	}
	env, err := blind.SignCredential(c, by)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// period is the period credential of the group, which only its members
// see: the forwarder refuses it.
func (g *testGroup) periodCredential(t testing.TB) []byte {
	t.Helper()
	root, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var gid [16]byte
	rand.Read(gid[:])
	env, err := blind.SignCredential(blind.Credential{Kind: blind.TypePeriod, Group: gid, Version: 1,
		ExpiresMs: uint64(time.Now().Add(periodLifetime).UnixMilli()), Tag: &g.tag, Key: blind.Point(&g.period.PublicKey)}, root)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// auth is a registration with the group's hubs' credential at version 1.
func (g *testGroup) auth(t testing.TB) hubAuth {
	t.Helper()
	return hubAuth{creds: [][]byte{g.hubs(t, 1)}}
}

// credentials is HubConfig's Credentials for the group's hub.
func (g *testGroup) credentials(t testing.TB) func() [][]byte {
	env := g.hubs(t, 1)
	return func() [][]byte { return [][]byte{env} }
}

// hubCert is HubConfig's HubCert for the group's hub.
func (g *testGroup) hubCert() func() (tls.Certificate, error) {
	return func() (tls.Certificate, error) { return g.cert, nil }
}

// member is a new group's hub: the certificate of its server key, the
// name the forwarder keeps the group under, and the group.
func member(t testing.TB) (tls.Certificate, string, *testGroup) {
	t.Helper()
	g := newTestGroup(t)
	return g.cert, g.name(), g
}

// hubAuth is what a hand-made registration shows: its credentials, and
// edit, which changes the registration before it is sent.
type hubAuth struct {
	creds [][]byte
	edit  func(*register)
}

// rawRegister registers by hand, claiming key with the proof made by
// holder: a hub that holds key passes holder == key.
func rawRegister(t *testing.T, f *Forwarder, pin string, cert tls.Certificate, claimKey []byte, holder *ecdh.PrivateKey, auth hubAuth) answer {
	t.Helper()
	tc, a := rawOpen(t, f, pin, cert, claimKey, holder, auth)
	if tc != nil {
		tc.Close()
	}
	return a
}

// registerFrame is the frame of r claiming key, which may be of any
// length, as a broken hub would send it.
func registerFrame(t *testing.T, key []byte, r register) []byte {
	t.Helper()
	if len(key) == 32 {
		r.Key = [32]byte(key)
		b, err := msgRegister(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	creds := make([]blind.Value, 0, len(r.Credentials))
	for _, e := range r.Credentials {
		v, err := blind.Decode(e)
		if err != nil {
			t.Fatal(err)
		}
		creds = append(creds, v)
	}
	return blind.WriteFrame(blind.P(blind.FieldT, blind.Uint(tRegister)),
		blind.P(2, blind.Array(blind.Uint(3), blind.Bytes(key))),
		blind.P(3, blind.Bytes(r.Proof[:])), blind.P(6, blind.Array(creds...)))
}

// readAnswerFrom reads one message of the forwarder's.
func readAnswerFrom(r io.Reader) (answer, error) {
	t, m, _, err := blind.ReadFrame(r, maxSetup)
	if err != nil {
		return answer{}, err
	}
	return readAnswer(t, m)
}

// rawOpen is rawRegister that keeps the registration open.
func rawOpen(t *testing.T, f *Forwarder, pin string, cert tls.Certificate, claimKey []byte, holder *ecdh.PrivateKey, auth hubAuth) (*tls.Conn, answer) {
	t.Helper()
	tc, err := tls.Dial("tcp", f.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{Protocol},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, answer{Error: err.Error()}
	}
	if Pin(tc.ConnectionState().PeerCertificates[0]) != pin {
		t.Fatal("the forwarder's pin changed")
	}
	ty, m, _, err := blind.ReadFrame(tc, maxSetup)
	if err != nil || ty != tChallenge {
		tc.Close()
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, answer{Error: err.Error()}
	}
	ev, _ := m.Get(2)
	e, err := ecdh.X25519().NewPublicKey(ev.Bytes)
	if err != nil {
		tc.Close()
		return nil, answer{Error: err.Error()}
	}
	shared, _ := holder.ECDH(e)
	p, _ := proof(shared, tc.ConnectionState())
	r := register{Proof: [32]byte(p), Credentials: auth.creds}
	if auth.edit != nil {
		auth.edit(&r)
	}
	if _, err := tc.Write(registerFrame(t, claimKey, r)); err != nil {
		tc.Close()
		return nil, answer{Error: err.Error()}
	}
	a, err := readAnswerFrom(tc)
	if err != nil {
		tc.Close()
		return nil, answer{Error: err.Error()}
	}
	return tc, a
}

// registered tells whether the forwarder holds a registration of the group
// it keeps under tag.
func (f *Forwarder) registered(tag string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.regs[tag] != nil
}
