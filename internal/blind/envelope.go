// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package blind

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
)

// The envelope's and the signature's rules.
const (
	RuleEnvShape   Rule = "env/shape"
	RuleEnvSize    Rule = "env/size"
	RuleEnvSig2    Rule = "env/sig2"
	RuleEnvDamaged Rule = "env/damaged"
	RuleSigSize    Rule = "sig/size"
	RuleSigRange   Rule = "sig/range"
	RuleSigLowS    Rule = "sig/low-s"
	RuleSigVerify  Rule = "sig/verify"
	RuleKeysShape  Rule = "keys/shape"
	RuleKeysES256  Rule = "keys/es256"
)

// The fields every signed body may carry: its type, its signer, and its
// second signer.
const (
	fieldType    = 1
	fieldSigner  = 3
	fieldSigner2 = 8
)

// The largest second signatures: of any body, and of a recovery head.
const (
	MaxSig2          = 8192
	MaxSig2Head      = 32 * 1024
	typeRecoveryHead = 13
)

// AlgES256 is the number of ES256 in a Key (`[alg, pub]`).
const AlgES256 = 1

// Envelope is `[body, sig]` or `[body, sig, sig2]`, its body read: a map.
type Envelope struct {
	Body []byte
	Sig  []byte
	Sig2 []byte // present exactly when the body names a second signer
	Map  Value
}

// ParseEnvelope reads an envelope whose body is at most maxBody bytes.
func ParseEnvelope(b []byte, maxBody int) (*Envelope, error) {
	if len(b) > maxBody+1+9+66+3+MaxSig2Head {
		return nil, RuleEnvSize
	}
	v, err := Decode(b)
	if err != nil {
		return nil, err
	}
	e, err := EnvelopeOf(v)
	if err != nil {
		return nil, err
	}
	if len(e.Body) > maxBody {
		return nil, RuleEnvSize
	}
	return e, nil
}

// EnvelopeOf takes an envelope already read as a value: its shape, its
// body a map of the profile, and the second signature where the body
// names a second signer.
func EnvelopeOf(v Value) (*Envelope, error) {
	if v.Kind != KindArray || (len(v.Array) != 2 && len(v.Array) != 3) {
		return nil, RuleEnvShape
	}
	for _, x := range v.Array {
		if !x.IsBytes() {
			return nil, RuleEnvShape
		}
	}
	e := &Envelope{Body: v.Array[0].Bytes, Sig: v.Array[1].Bytes}
	if len(v.Array) == 3 {
		e.Sig2 = v.Array[2].Bytes
	}
	m, err := Decode(e.Body)
	if err != nil {
		return nil, err
	}
	if m.Kind != KindMap {
		return nil, RuleEnvShape
	}
	_, named := m.Get(fieldSigner2)
	if named != (len(v.Array) == 3) {
		return nil, RuleEnvShape
	}
	max := MaxSig2
	if t, ok := m.Get(fieldType); ok && t.IsUint() && t.Uint == typeRecoveryHead {
		max = MaxSig2Head
	}
	if len(v.Array) == 3 && len(e.Sig2) > max {
		return nil, RuleEnvSig2
	}
	e.Map = m
	return e, nil
}

// ID is the SHA-256 of the body.
func (e *Envelope) ID() [32]byte { return sha256.Sum256(e.Body) }

// Verify checks the first signature by the uncompressed point pub under
// label. Beside a second signature it covers the body and the second's
// SHA-256, so a second signature changed on the way makes the copy
// damaged.
func (e *Envelope) Verify(pub []byte, label string) error {
	data := e.Body
	if e.Sig2 != nil {
		d := sha256.Sum256(e.Sig2)
		data = append(bytes.Clone(e.Body), d[:]...)
	}
	err := VerifyES256(pub, label, data, e.Sig)
	if e.Sig2 != nil && err == RuleSigVerify {
		return RuleEnvDamaged
	}
	return err
}

var (
	curveN = elliptic.P256().Params().N
	halfN  = new(big.Int).Rsh(curveN, 1)
)

// CheckSigForm checks an ES256 signature's form: 64 bytes, r and s in
// range, s low.
func CheckSigForm(sig []byte) error {
	if len(sig) != 64 {
		return RuleSigSize
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(curveN) >= 0 {
		return RuleSigRange
	}
	if s.Cmp(halfN) > 0 {
		return RuleSigLowS
	}
	return nil
}

// PublicKey reads an uncompressed P-256 point.
func PublicKey(pub []byte) (*ecdsa.PublicKey, error) {
	if len(pub) != 65 || pub[0] != 4 {
		return nil, RuleKeysES256
	}
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil {
		return nil, RuleKeysES256
	}
	return k, nil
}

// VerifyES256 checks sig, r and s of 32 bytes each, by the point pub over
// label, a zero byte and data.
func VerifyES256(pub []byte, label string, data, sig []byte) error {
	if err := CheckSigForm(sig); err != nil {
		return err
	}
	k, err := PublicKey(pub)
	if err != nil {
		return RuleSigVerify
	}
	h := sha256.Sum256(append(append([]byte(label), 0), data...))
	if !ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return RuleSigVerify
	}
	return nil
}

// KeyHash is the hash of a Key, SHA-256 over its encoding `[alg, pub]`:
// how the credentials list server keys.
func KeyHash(alg uint64, pub []byte) [32]byte {
	return sha256.Sum256(Encode(Array(Uint(alg), Bytes(pub))))
}

// es256Key reads a Key of ES256 with a point on the curve.
func es256Key(v Value) ([]byte, bool) {
	if v.Kind != KindArray || len(v.Array) != 2 || !v.Array[0].IsUint() || !v.Array[1].IsBytes() {
		return nil, false
	}
	if v.Array[0].Uint != AlgES256 {
		return nil, false
	}
	if _, err := PublicKey(v.Array[1].Bytes); err != nil {
		return nil, false
	}
	return v.Array[1].Bytes, true
}

// PublicKeyOf is the uncompressed P-256 point of a certificate's key.
func PublicKeyOf(c *x509.Certificate) ([]byte, error) {
	k, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, RuleKeysES256
	}
	return Point(k), nil
}
