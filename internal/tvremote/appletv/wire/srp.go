// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package wire

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"math/big"
)

// SRP-6a as HomeKit's pair-setup runs it: the 3072-bit group of RFC 5054
// with SHA-512, the user "Pair-Setup" and the code the TV shows as the
// password. The numbers go into the hashes without leading zero bytes,
// except where RFC 5054 pads them to the group's length (k and u), as the
// Apple TV takes them.

const srpPrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6" +
	"3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411" +
	"7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08" +
	"CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
	"04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8760273" +
	"3EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

// SRPUser is pair-setup's user name.
const SRPUser = "Pair-Setup"

var (
	srpN, _ = new(big.Int).SetString(srpPrimeHex, 16)
	srpG    = big.NewInt(5)
	srpLen  = len(srpN.Bytes())
	srpK    = hashInt(srpN.Bytes(), pad(srpG))
)

// ErrProof is the other side's SRP proof failing: on pair-setup, a wrong
// code.
var ErrProof = errors.New("the SRP proof does not match")

func pad(x *big.Int) []byte {
	return x.FillBytes(make([]byte, srpLen))
}

func hash(parts ...[]byte) []byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func hashInt(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(hash(parts...))
}

// trim drops leading zero bytes, as a number written without padding.
func trim(b []byte) []byte {
	return bytes.TrimLeft(b, "\x00")
}

// srpX is x = H(s | H(I ":" P)), P the PIN the TV shows for this one
// pairing. SHA-512 is the protocol's: nothing is stored to slow down a
// guess, and a wrong guess ends the pairing on the TV.
func srpX(salt []byte, code string) *big.Int {
	return hashInt(trim(salt), hash([]byte(SRPUser+":"+code)))
}

// srpProofs are M1 = H(H(N) xor H(g) | H(I) | s | A | B | K) and
// M2 = H(A | M1 | K).
func srpProofs(salt []byte, a, b *big.Int, key []byte) (m1, m2 []byte) {
	hn := hashInt(srpN.Bytes())
	hg := hashInt(srpG.Bytes())
	m1 = hash(new(big.Int).Xor(hn, hg).Bytes(), trim(hash([]byte(SRPUser))), trim(salt), a.Bytes(), b.Bytes(), key)
	m2 = hash(a.Bytes(), m1, key)
	return m1, m2
}

func srpU(a, b *big.Int) *big.Int {
	return hashInt(pad(a), pad(b))
}

// randomInt is a random secret exponent of 256 bits.
func randomInt() (*big.Int, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// SRPClient is the remote's side.
type SRPClient struct {
	a, A *big.Int
}

// NewSRPClient picks the client's secret.
func NewSRPClient() (*SRPClient, error) {
	a, err := randomInt()
	if err != nil {
		return nil, err
	}
	return newSRPClient(a), nil
}

func newSRPClient(a *big.Int) *SRPClient {
	return &SRPClient{a: a, A: new(big.Int).Exp(srpG, a, srpN)}
}

// Respond takes the TV's salt and public key B and the PIN, and returns
// the client's public key A, its proof M1, the proof M2 the TV must send
// back, and the session key K.
func (c *SRPClient) Respond(salt, serverPublic []byte, code string) (public, m1, m2, key []byte, err error) {
	b := new(big.Int).SetBytes(serverPublic)
	if new(big.Int).Mod(b, srpN).Sign() == 0 {
		return nil, nil, nil, nil, errors.New("the TV's SRP public key is zero")
	}
	u := srpU(c.A, b)
	if u.Sign() == 0 {
		return nil, nil, nil, nil, errors.New("the SRP scrambler is zero")
	}
	x := srpX(salt, code)
	v := new(big.Int).Exp(srpG, x, srpN)
	base := new(big.Int).Sub(b, new(big.Int).Mul(srpK, v))
	base.Mod(base, srpN)
	exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
	s := new(big.Int).Exp(base, exp, srpN)
	key = hash(s.Bytes())
	m1, m2 = srpProofs(salt, c.A, b, key)
	return c.A.Bytes(), m1, m2, key, nil
}

// SRPServer is the TV's side, for the fake TV of the tests.
type SRPServer struct {
	Salt    []byte
	v, b, B *big.Int
}

// NewSRPServer makes a salt and the server's keys for the code.
func NewSRPServer(code string) (*SRPServer, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	b, err := randomInt()
	if err != nil {
		return nil, err
	}
	return newSRPServer(salt, b, code), nil
}

func newSRPServer(salt []byte, b *big.Int, code string) *SRPServer {
	v := new(big.Int).Exp(srpG, srpX(salt, code), srpN)
	B := new(big.Int).Mul(srpK, v)
	B.Add(B, new(big.Int).Exp(srpG, b, srpN))
	B.Mod(B, srpN)
	return &SRPServer{Salt: salt, v: v, b: b, B: B}
}

// Public is B.
func (s *SRPServer) Public() []byte { return s.B.Bytes() }

// Verify checks the client's proof and returns the server's proof M2 and
// the session key K.
func (s *SRPServer) Verify(clientPublic, m1 []byte) (m2, key []byte, err error) {
	a := new(big.Int).SetBytes(clientPublic)
	if new(big.Int).Mod(a, srpN).Sign() == 0 {
		return nil, nil, ErrProof
	}
	u := srpU(a, s.B)
	base := new(big.Int).Mul(a, new(big.Int).Exp(s.v, u, srpN))
	sec := new(big.Int).Exp(base.Mod(base, srpN), s.b, srpN)
	key = hash(sec.Bytes())
	want, m2 := srpProofs(s.Salt, a, s.B, key)
	if subtle.ConstantTimeCompare(want, m1) != 1 {
		return nil, nil, ErrProof
	}
	return m2, key, nil
}

// Key derives a 32-byte key with HKDF-SHA-512.
func Key(secret []byte, salt, info string) []byte {
	// SHA-512 gives any length up to 255 of its sizes, so 32 never fails.
	k, _ := hkdf.Key(sha512.New, secret, []byte(salt), info, 32)
	return k
}
