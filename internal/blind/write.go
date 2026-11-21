// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package blind

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// SignES256 signs label, a zero byte and data with key: r and s of 32
// bytes each, s low, as the profile takes it.
func SignES256(key *ecdsa.PrivateKey, label string, data []byte) ([]byte, error) {
	h := sha256.Sum256(append(append([]byte(label), 0), data...))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(curveN, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// Point is a key's uncompressed point.
func Point(k *ecdsa.PublicKey) []byte {
	b, err := k.Bytes()
	if err != nil {
		return nil
	}
	return b
}

func pad(real [][32]byte, lengths []int) ([][32]byte, error) {
	for _, n := range lengths {
		if n >= len(real) {
			out := append([][32]byte(nil), real...)
			for len(out) < n {
				var h [32]byte
				rand.Read(h[:])
				out = append(out, h)
			}
			return out, nil
		}
	}
	return nil, errors.New("blind: a credential's list is longer than it may be")
}

// SignCredential signs a credential of c's kind and fields with key, whose
// point becomes its signer, its lists padded with random entries to their
// lengths: the writer the tests of the forwarder and of the phones' hub
// make a group's credentials with (the members sign theirs in the Rust
// core, core/src/blind/credential.rs). It gives the envelope, which
// ReadCredential takes.
func SignCredential(c Credential, key *ecdsa.PrivateKey) ([]byte, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("blind: not a P-256 key")
	}
	signer := Point(&key.PublicKey)
	es := func(p []byte) Value { return Array(Uint(AlgES256), Bytes(p)) }
	m := []Pair{
		P(1, Uint(c.Kind)), P(2, Bytes(c.Group[:])), P(3, es(signer)),
		P(4, Uint(c.Version)), P(7, Uint(c.ExpiresMs)),
	}
	list := func(l [][32]byte) Value {
		a := make([]Value, len(l))
		for i := range l {
			a[i] = Bytes(l[i][:])
		}
		return Array(a...)
	}
	var err error
	switch c.Kind {
	case TypePeriod, TypeServer:
		if c.Tag == nil || c.Key == nil {
			return nil, errors.New("blind: a period or server credential needs its tag and key")
		}
		m = append(m, P(10, Bytes(c.Tag[:])), P(11, es(c.Key)))
	case TypeHubs:
		if c.Hubs, err = pad(c.Hubs, hubsLengths); err != nil {
			return nil, err
		}
		if c.Admins, err = pad(c.Admins, adminsLengths); err != nil {
			return nil, err
		}
		m = append(m, P(12, list(c.Hubs)), P(13, list(c.Admins)))
	case TypeMembers:
		if c.Members, err = pad(c.Members, membersLengths); err != nil {
			return nil, err
		}
		m = append(m, P(14, list(c.Members)))
	default:
		return nil, errors.New("blind: no such kind of credential")
	}
	body := Encode(Map(m...))
	sig, err := SignES256(key, LabelCredential, body)
	if err != nil {
		return nil, err
	}
	env := Encode(Array(Bytes(body), Bytes(sig)))
	if _, err := ReadCredential(env); err != nil {
		return nil, err
	}
	return env, nil
}
