// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package piv signs with the group's recovery key on a YubiKey, or another
// card with the PIV application (NIST SP 800-73-4): the root phone made the
// key in a free retired slot (82 to 95), where it never leaves the card,
// and stored the key's admin CA as the slot's certificate (docs/protocol.md,
// section 10, "The recovery key"). The YubiKey may be in daily use for
// other things, so nothing else on it is touched. Only what a claim needs
// is here: select the application, find the slot whose certificate is the
// recovery key's, check the PIN and sign a SHA-256 digest with P-256. The
// card is reached through PC/SC (pcsc_*.go).
package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Card is a connection to one card: Transmit sends an APDU and returns the
// answer with its status word last.
type Card interface {
	Transmit(apdu []byte) ([]byte, error)
	Close() error
}

// The PIV application's identifier.
var aid = []byte{0xa0, 0x00, 0x00, 0x03, 0x08}

const (
	// FirstSlot and LastSlot are the retired key slots, where the
	// recovery key goes.
	FirstSlot = 0x82
	LastSlot  = 0x95
	// algECCP256 is the PIV algorithm of an ECC P-256 key.
	algECCP256 = 0x11
	// pinRef is the PIV application PIN's reference.
	pinRef = 0x80
)

// certObject is the data object of a retired slot's certificate: 5FC10D for
// slot 82, up to 5FC120 for slot 95.
func certObject(slot byte) []byte { return []byte{0x5f, 0xc1, 0x0d + slot - FirstSlot} }

var (
	// ErrNoCard is what Open says when no reader holds a card with the
	// PIV application.
	ErrNoCard = errors.New("no YubiKey found: plug it in, or hold it to the reader")
	// ErrTwoCards is what Open says when two cards hold the recovery key: it
	// signs with one only.
	ErrTwoCards = errors.New("two YubiKeys hold the recovery key: leave only one plugged in")
	// ErrNoKey is what Open says when no slot holds the recovery key's
	// certificate.
	ErrNoKey = errors.New("this YubiKey holds no recovery key of the group: the root phone puts it in a retired PIV slot with its certificate, and a newer recovery key replaces the older one")
	// ErrBlocked is what Verify says when the PIN is blocked.
	ErrBlocked = errors.New("the YubiKey's PIN is blocked: unblock it with its PUK (ykman piv access unblock-pin)")
)

// WrongPIN is what Verify says for a wrong PIN, with the attempts left.
type WrongPIN struct{ Left int }

func (e WrongPIN) Error() string {
	return fmt.Sprintf("wrong PIN for the YubiKey; %d attempts left before it is blocked", e.Left)
}

// statusError is an answer the card refused, by its status word.
type statusError uint16

func (e statusError) Error() string {
	return fmt.Sprintf("the YubiKey refused: status %04x", uint16(e))
}

// transmit sends one command and returns its data, following the card's
// "more data" answers (61xx) with GET RESPONSE, and its status word.
func transmit(c Card, apdu []byte) ([]byte, uint16, error) {
	var out []byte
	for {
		r, err := c.Transmit(apdu)
		if err != nil {
			return nil, 0, err
		}
		if len(r) < 2 {
			return nil, 0, errors.New("piv: an answer without a status word")
		}
		out = append(out, r[:len(r)-2]...)
		sw1, sw2 := r[len(r)-2], r[len(r)-1]
		if sw1 != 0x61 {
			if len(out) > maxAnswer {
				return nil, 0, errors.New("piv: the answer is too long")
			}
			return out, uint16(sw1)<<8 | uint16(sw2), nil
		}
		if len(out) > maxAnswer {
			return nil, 0, errors.New("piv: the answer is too long")
		}
		apdu = []byte{0x00, 0xc0, 0x00, 0x00, sw2}
	}
}

// maxAnswer bounds what one command takes from the card: a certificate
// object is at most a few kilobytes.
const maxAnswer = 16 << 10

// command builds a short APDU: CLA INS P1 P2, then Lc and data when there
// is data, then Le 00; data longer than 255 bytes goes in a chain of
// commands (CLA 10 on all but the last), and command returns the last.
func command(c Card, ins, p1, p2 byte, data []byte) ([]byte, uint16, error) {
	for len(data) > 255 {
		apdu := append([]byte{0x10, ins, p1, p2, 255}, data[:255]...)
		_, sw, err := transmit(c, apdu)
		if err != nil {
			return nil, 0, err
		}
		if sw != 0x9000 {
			return nil, sw, nil
		}
		data = data[255:]
	}
	apdu := []byte{0x00, ins, p1, p2}
	if len(data) > 0 {
		apdu = append(append(apdu, byte(len(data))), data...)
	}
	return transmit(c, append(apdu, 0x00))
}

// Select selects the PIV application.
func Select(c Card) error {
	_, sw, err := command(c, 0xa4, 0x04, 0x00, aid)
	if err != nil {
		return err
	}
	if sw != 0x9000 {
		return statusError(sw)
	}
	return nil
}

// Certificate reads a retired slot's certificate; ErrNoKey if it holds none.
func Certificate(c Card, slot byte) (*x509.Certificate, error) {
	if slot < FirstSlot || slot > LastSlot {
		return nil, errors.New("piv: not a retired slot")
	}
	data, sw, err := command(c, 0xcb, 0x3f, 0xff, tlv(0x5c, certObject(slot)))
	switch {
	case err != nil:
		return nil, err
	case sw == 0x6a82:
		return nil, ErrNoKey
	case sw != 0x9000:
		return nil, statusError(sw)
	}
	obj, rest, err := readTLV(data, 0x53)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("piv: the certificate object does not parse")
	}
	der, rest, err := readTLV(obj, 0x70)
	if err != nil {
		return nil, errors.New("piv: the certificate object holds no certificate")
	}
	// 71 says whether it is compressed; the root phone never compresses it.
	if info, _, err := readTLV(rest, 0x71); err == nil && len(info) == 1 && info[0] != 0 {
		return nil, errors.New("piv: the certificate is compressed")
	}
	return x509.ParseCertificate(der)
}

// Verify checks the PIN, which the card then takes as given until the
// connection ends.
func Verify(c Card, pin string) error {
	if len(pin) < 6 || len(pin) > 8 {
		return errors.New("a YubiKey's PIN has 6 to 8 characters")
	}
	p := bytes.Repeat([]byte{0xff}, 8)
	copy(p, pin)
	_, sw, err := command(c, 0x20, 0x00, pinRef, p)
	switch {
	case err != nil:
		return err
	case sw == 0x9000:
		return nil
	case sw == 0x6983:
		return ErrBlocked
	case sw&0xfff0 == 0x63c0:
		if sw&0xf == 0 {
			return ErrBlocked
		}
		return WrongPIN{Left: int(sw & 0xf)}
	}
	return statusError(sw)
}

// Signer is the recovery key on the card as a crypto.Signer: it signs a
// SHA-256 digest with the P-256 key in its slot, which may wait for a
// touch.
type Signer struct {
	card Card
	slot byte
	pub  *ecdsa.PublicKey
}

// NewSigner returns the signer for the key in slot whose public key the
// slot's certificate cert holds; Verify must have taken the PIN.
func NewSigner(c Card, slot byte, cert *x509.Certificate) (*Signer, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("piv: the recovery key is not a P-256 key")
	}
	return &Signer{card: c, slot: slot, pub: pub}, nil
}

func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign signs digest, which must be a SHA-256 digest, and checks the
// signature against the certificate's key, so that a card with another key
// in the slot never signs a record that would not verify.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("piv: only SHA-256 digests are signed")
	}
	in := tlv(0x7c, slices.Concat(tlv(0x82, nil), tlv(0x81, digest)))
	data, sw, err := command(s.card, 0x87, algECCP256, s.slot, in)
	switch {
	case err != nil:
		return nil, err
	case sw == 0x6982:
		return nil, errors.New("piv: the YubiKey wants its PIN first")
	case sw != 0x9000:
		return nil, statusError(sw)
	}
	outer, _, err := readTLV(data, 0x7c)
	if err != nil {
		return nil, errors.New("piv: the signature does not parse")
	}
	sig, _, err := readTLV(outer, 0x82)
	if err != nil {
		return nil, errors.New("piv: the signature does not parse")
	}
	if !ecdsa.VerifyASN1(s.pub, digest, sig) {
		return nil, errors.New("piv: the YubiKey's signature does not match its certificate's key")
	}
	return sig, nil
}

// tlv encodes tag, length (BER) and value.
func tlv(tag byte, v []byte) []byte {
	out := []byte{tag}
	switch n := len(v); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, v...)
}

// readTLV reads one TLV with tag at the start of b and returns its value
// and what follows it.
func readTLV(b []byte, tag byte) (value, rest []byte, err error) {
	if len(b) < 2 || b[0] != tag {
		return nil, nil, errors.New("piv: unexpected tag")
	}
	n, i := int(b[1]), 2
	switch b[1] {
	case 0x81:
		if len(b) < 3 {
			return nil, nil, errors.New("piv: short length")
		}
		n, i = int(b[2]), 3
	case 0x82:
		if len(b) < 4 {
			return nil, nil, errors.New("piv: short length")
		}
		n, i = int(b[2])<<8|int(b[3]), 4
	default:
		if b[1] >= 0x80 {
			return nil, nil, errors.New("piv: unsupported length")
		}
	}
	if len(b)-i < n {
		return nil, nil, errors.New("piv: short value")
	}
	return b[i : i+n], b[i+n:], nil
}

// Key is the recovery key on a card: the card, selected, the slot and its
// certificate.
type Key struct {
	Card Card
	Slot byte
	Cert *x509.Certificate
}

// Signer returns the key as a crypto.Signer; Verify must have taken the PIN.
func (k *Key) Signer() (*Signer, error) { return NewSigner(k.Card, k.Slot, k.Cert) }

// Open finds the recovery key among the cards in the readers PC/SC lists:
// the one retired slot whose certificate match takes, on the one card that
// holds such a slot.
func Open(match func(*x509.Certificate) bool) (*Key, error) {
	cards, err := cards()
	if err != nil {
		return nil, err
	}
	return find(cards, match)
}

// find keeps the card of cards that holds the key match takes and closes
// the others.
func find(cards []Card, match func(*x509.Certificate) bool) (*Key, error) {
	var keys []*Key
	var lastErr error = ErrNoCard
	for _, c := range cards {
		if Select(c) != nil {
			c.Close()
			continue
		}
		lastErr = ErrNoKey
		var k *Key
		for slot := byte(FirstSlot); slot <= LastSlot && k == nil; slot++ {
			crt, err := Certificate(c, slot)
			if err == nil && match(crt) {
				k = &Key{Card: c, Slot: slot, Cert: crt}
			}
		}
		if k == nil {
			c.Close()
			continue
		}
		keys = append(keys, k)
	}
	switch len(keys) {
	case 0:
		return nil, lastErr
	case 1:
		return keys[0], nil
	}
	for _, k := range keys {
		k.Card.Close()
	}
	return nil, ErrTwoCards
}
