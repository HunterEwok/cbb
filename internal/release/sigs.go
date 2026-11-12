// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/cloudflare/circl/sign/slhdsa"
)

// The algorithms of the format's registry (docs/protocol.md, section 16,
// "Two signatures") that release files use. A key or a signature of a
// number this version does not know is kept and skipped: it signs nothing
// for this reader.
const (
	// AlgES256 is ECDSA P-256 with SHA-256, the signature DER.
	AlgES256 = 1
	// AlgSLHDSA is SLH-DSA-SHA2-128s (FIPS 205), pure, with the context
	// SLHContext: the post-quantum half, hash-based.
	AlgSLHDSA = 4
)

// Required are the algorithms every signed file must carry a signature of,
// all by the halves of one key. There is no setting that changes them: a
// file signed by fewer is refused.
var Required = []int{AlgES256, AlgSLHDSA}

// SLHContext is the context of every SLH-DSA signature on a release file,
// so that one never stands for a signature of another kind.
var SLHContext = []byte("cbb release v1")

const (
	// maxSigs is the most signatures a file may carry.
	maxSigs = 8
	// maxSigBytes is the largest signature of an algorithm this version
	// knows; one of another algorithm is skipped whatever its length.
	maxSigBytes = 16 << 10
	slhSigSize  = 7856
)

// slhSPKIPrefix is the SubjectPublicKeyInfo of an SLH-DSA-SHA2-128s key up
// to its 32 bytes (RFC 9909: the OID 2.16.840.1.101.3.4.3.20, no
// parameters).
var slhSPKIPrefix = []byte{
	0x30, 0x30, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14,
	0x03, 0x21, 0x00,
}

// Sig is one signature of a file: its algorithm, the SHA-256 of the
// signing half's SubjectPublicKeyInfo, and the signature.
type Sig struct {
	Alg int    `json:"alg"`
	Key []byte `json:"key"`
	Sig []byte `json:"sig"`
}

// Signer signs as one key: its halves, one for each algorithm of Required.
type Signer []crypto.Signer

// GenerateSigner makes a key with both halves in memory, for tests and
// drills.
func GenerateSigner() (Signer, error) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pq, err := GenerateSLH(rand.Reader)
	if err != nil {
		return nil, err
	}
	return Signer{ec, pq}, nil
}

// GenerateSLH makes an SLH-DSA-SHA2-128s key.
func GenerateSLH(r io.Reader) (crypto.Signer, error) {
	_, sk, err := slhdsa.GenerateKey(r, slhdsa.SHA2_128s)
	if err != nil {
		return nil, err
	}
	return &slhKey{sk}, nil
}

// ParseSLH reads an SLH-DSA-SHA2-128s private key in its 64 bytes.
func ParseSLH(b []byte) (crypto.Signer, error) {
	sk := slhdsa.PrivateKey{ID: slhdsa.SHA2_128s}
	if err := sk.UnmarshalBinary(b); err != nil {
		return nil, errors.New("release: not an SLH-DSA-SHA2-128s key")
	}
	return &slhKey{sk}, nil
}

// MarshalSLH returns an SLH-DSA key's 64 bytes, for its encrypted file.
func MarshalSLH(s crypto.Signer) ([]byte, error) {
	k, ok := s.(*slhKey)
	if !ok {
		return nil, errors.New("release: not an SLH-DSA key in memory")
	}
	return k.sk.MarshalBinary()
}

// slhKey signs with the context of release files.
type slhKey struct{ sk slhdsa.PrivateKey }

func (k *slhKey) Public() crypto.PublicKey { return k.sk.PublicKey() }

func (k *slhKey) Sign(r io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	return slhdsa.SignRandomized(&k.sk, r, slhdsa.NewMessage(msg), SLHContext)
}

// PublicKeys returns the SubjectPublicKeyInfos of the signer's halves, by
// algorithm.
func (s Signer) PublicKeys() (map[int][]byte, error) {
	out := map[int][]byte{}
	for _, h := range s {
		alg, spki, err := MarshalPublic(h.Public())
		if err != nil {
			return nil, err
		}
		if _, twice := out[alg]; twice {
			return nil, fmt.Errorf("release: the signer has two halves of algorithm %d", alg)
		}
		out[alg] = spki
	}
	for _, alg := range Required {
		if out[alg] == nil {
			return nil, fmt.Errorf("release: the signer has no half of algorithm %d", alg)
		}
	}
	return out, nil
}

// Keys returns the signer's entries for keys.json under name and use.
func (s Signer) Keys(name, use string) ([]Key, error) {
	pubs, err := s.PublicKeys()
	if err != nil {
		return nil, err
	}
	var out []Key
	for _, alg := range Required {
		out = append(out, Key{Alg: alg, Key: pubs[alg], Name: name, Use: use})
	}
	return out, nil
}

// MarshalPublic returns the algorithm and SubjectPublicKeyInfo of a P-256
// or SLH-DSA-SHA2-128s public key.
func MarshalPublic(pub crypto.PublicKey) (int, []byte, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return 0, nil, errors.New("release: the key is not P-256")
		}
		spki, err := x509.MarshalPKIXPublicKey(p)
		return AlgES256, spki, err
	case slhdsa.PublicKey:
		if p.ID != slhdsa.SHA2_128s {
			return 0, nil, errors.New("release: the key is not SLH-DSA-SHA2-128s")
		}
		raw, err := p.MarshalBinary()
		if err != nil {
			return 0, nil, err
		}
		return AlgSLHDSA, append(bytes.Clone(slhSPKIPrefix), raw...), nil
	}
	return 0, nil, fmt.Errorf("release: a key of type %T", pub)
}

// checkPublic checks that spki is a key of alg, for an algorithm this
// version knows; a key of another is kept unread, whatever its length.
func checkPublic(alg int, spki []byte) error {
	switch alg {
	case AlgES256:
		pub, err := x509.ParsePKIXPublicKey(spki)
		if err != nil {
			return fmt.Errorf("release: a key: %w", err)
		}
		if e, ok := pub.(*ecdsa.PublicKey); !ok || e.Curve != elliptic.P256() {
			return errors.New("release: a key of algorithm 1 is not P-256")
		}
	case AlgSLHDSA:
		if len(spki) != len(slhSPKIPrefix)+32 || !bytes.HasPrefix(spki, slhSPKIPrefix) {
			return errors.New("release: a key of algorithm 4 is not SLH-DSA-SHA2-128s")
		}
	}
	return nil
}

// known reports whether this version verifies signatures of alg.
func known(alg int) bool { return alg == AlgES256 || alg == AlgSLHDSA }

// verifyHalf checks one signature of a known algorithm over body.
func verifyHalf(alg int, spki, body, sig []byte) bool {
	switch alg {
	case AlgES256:
		pub, err := x509.ParsePKIXPublicKey(spki)
		k, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok || k.Curve != elliptic.P256() {
			return false
		}
		sum := sha256.Sum256(body)
		return ecdsa.VerifyASN1(k, sum[:], sig)
	case AlgSLHDSA:
		if checkPublic(alg, spki) != nil || len(sig) != slhSigSize {
			return false
		}
		pk := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
		if pk.UnmarshalBinary(spki[len(slhSPKIPrefix):]) != nil {
			return false
		}
		return slhdsa.Verify(&pk, slhdsa.NewMessage(body), sig, SLHContext)
	}
	return false
}

// verify checks that f is signed by one key among keys: for each
// algorithm of Required, a signature by that key's half of the algorithm
// (keys of one key share name and use). Signatures of algorithms this
// version does not know, or by keys not among keys, are skipped; a
// signature by a half among keys that does not verify refuses the file.
func (f File) verify(keys []Key) error {
	if len(f.Body) > MaxBody {
		return errors.New("release: the body is too large")
	}
	if len(f.Sigs) == 0 || len(f.Sigs) > maxSigs {
		return ErrSignature
	}
	type signer struct{ name, use string }
	good := map[signer]map[int]bool{}
	for _, s := range f.Sigs {
		if !known(s.Alg) || len(s.Sig) > maxSigBytes {
			continue
		}
		for _, k := range keys {
			if k.Alg != s.Alg {
				continue
			}
			kh := sha256.Sum256(k.Key)
			if !bytes.Equal(kh[:], s.Key) {
				continue
			}
			if !verifyHalf(s.Alg, k.Key, f.Body, s.Sig) {
				return ErrSignature
			}
			who := signer{k.Name, k.Use}
			if good[who] == nil {
				good[who] = map[int]bool{}
			}
			good[who][s.Alg] = true
		}
	}
	for _, algs := range good {
		all := true
		for _, alg := range Required {
			all = all && algs[alg]
		}
		if all {
			return nil
		}
	}
	return ErrSignature
}

// VerifyWith checks that f is signed by one key among keys, as a device
// checks a file under the keys that may sign it: a signature for every
// algorithm of Required by that key's halves.
func (f File) VerifyWith(keys []Key) error { return f.verify(keys) }

// signData signs data with each half of s.
func signData(data []byte, s Signer) (File, error) {
	pubs, err := s.PublicKeys()
	if err != nil {
		return File{}, err
	}
	f := File{Body: data}
	for _, h := range s {
		alg, _, _ := MarshalPublic(h.Public())
		var sig []byte
		switch alg {
		case AlgES256:
			sum := sha256.Sum256(data)
			sig, err = h.Sign(rand.Reader, sum[:], crypto.SHA256)
		default:
			sig, err = h.Sign(rand.Reader, data, crypto.Hash(0))
		}
		if err != nil {
			return File{}, err
		}
		if !verifyHalf(alg, pubs[alg], data, sig) {
			return File{}, fmt.Errorf("release: the half of algorithm %d made a signature that does not verify", alg)
		}
		kh := sha256.Sum256(pubs[alg])
		f.Sigs = append(f.Sigs, Sig{Alg: alg, Key: kh[:], Sig: sig})
	}
	sort.SliceStable(f.Sigs, func(i, j int) bool { return f.Sigs[i].Alg < f.Sigs[j].Alg })
	return f, nil
}

func pemDecode(data []byte) (*pem.Block, []byte) { return pem.Decode(data) }

// EncodeRoots writes root keys as ParseRoots reads them.
func EncodeRoots(roots []Key) []byte {
	var out []byte
	for _, r := range roots {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Name": r.Name}, Bytes: r.Key})...)
	}
	return out
}

// slhPKCS8Prefix is the PKCS#8 PrivateKeyInfo of an SLH-DSA-SHA2-128s key
// up to its 64 bytes (RFC 9909).
var slhPKCS8Prefix = []byte{
	0x30, 0x52, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14,
	0x04, 0x40,
}

// MarshalSLHPEM returns an SLH-DSA key as a PRIVATE KEY in PEM (PKCS#8).
func MarshalSLHPEM(s crypto.Signer) ([]byte, error) {
	raw, err := MarshalSLH(s)
	if err != nil {
		return nil, err
	}
	der := append(bytes.Clone(slhPKCS8Prefix), raw...)
	clear(raw)
	out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	return out, nil
}

// ParseSigner reads the halves of a key from PEM: a P-256 key (EC PRIVATE
// KEY or PRIVATE KEY) and an SLH-DSA-SHA2-128s key (PRIVATE KEY), in one
// text or several.
func ParseSigner(texts ...[]byte) (Signer, error) {
	var s Signer
	for _, data := range texts {
		for {
			b, rest := pem.Decode(data)
			if b == nil {
				break
			}
			data = rest
			h, err := parsePrivate(b)
			clear(b.Bytes)
			if err != nil {
				return nil, err
			}
			s = append(s, h)
		}
	}
	if _, err := s.PublicKeys(); err != nil {
		return nil, err
	}
	return s, nil
}

func parsePrivate(b *pem.Block) (crypto.Signer, error) {
	switch {
	case b.Type == "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(b.Bytes)
	case b.Type != "PRIVATE KEY":
		return nil, fmt.Errorf("release: a %s, not a private key", b.Type)
	case bytes.HasPrefix(b.Bytes, slhPKCS8Prefix) && len(b.Bytes) == len(slhPKCS8Prefix)+64:
		return ParseSLH(b.Bytes[len(slhPKCS8Prefix):])
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("release: not a signing key")
	}
	return s, nil
}

// MarshalSignerPEM returns both halves of an in-memory signer as PEM, for
// drills and tests.
func MarshalSignerPEM(s Signer) ([]byte, error) {
	var out []byte
	for _, h := range s {
		switch k := h.(type) {
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, err
			}
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
		default:
			p, err := MarshalSLHPEM(h)
			if err != nil {
				return nil, err
			}
			out = append(out, p...)
		}
	}
	return out, nil
}

// PublicPEM returns the halves of a signer as PUBLIC KEY blocks, each with
// the header Name when name is not empty: as roots.pem pins a root.
func PublicPEM(s Signer, name string) ([]byte, error) {
	pubs, err := s.PublicKeys()
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, alg := range Required {
		b := &pem.Block{Type: "PUBLIC KEY", Bytes: pubs[alg]}
		if name != "" {
			b.Headers = map[string]string{"Name": name}
		}
		out = append(out, pem.EncodeToMemory(b)...)
	}
	return out, nil
}

// ReadHalves reads the halves of one key from PEM PUBLIC KEY blocks, by
// algorithm, each an algorithm this version knows, at most one of each.
func ReadHalves(data []byte) (map[int][]byte, error) {
	out := map[int][]byte{}
	for {
		b, rest := pem.Decode(data)
		if b == nil {
			break
		}
		data = rest
		if b.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("a %s, not a PUBLIC KEY", b.Type)
		}
		alg, err := spkiAlg(b.Bytes)
		if err != nil {
			return nil, err
		}
		if out[alg] != nil {
			return nil, fmt.Errorf("two keys of algorithm %d", alg)
		}
		out[alg] = b.Bytes
	}
	if len(out) == 0 {
		return nil, errors.New("no PUBLIC KEY")
	}
	return out, nil
}

// ParseHalf reads the one private key a PEM text holds: a half of a key.
func ParseHalf(data []byte) (crypto.Signer, error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return nil, errors.New("release: no PEM key")
	}
	defer clear(b.Bytes)
	if next, _ := pem.Decode(rest); next != nil {
		clear(next.Bytes)
		return nil, errors.New("release: more than one key where one half was wanted")
	}
	return parsePrivate(b)
}

// SignUnchecked signs data as it is, without Sign's check of its form: for
// drills and tests of files every reader refuses.
func SignUnchecked(data []byte, key Signer) (File, error) { return signData(data, key) }
