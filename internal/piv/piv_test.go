// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/piv/pivtest"
)

// newCard returns a card whose slot 84 holds a key and its certificate; the
// other slots are empty, but for 82, which holds a key of something else.
func newCard(t *testing.T) *pivtest.Card {
	t.Helper()
	key, cert := newKey(t)
	c := pivtest.New(0x84, key, cert)
	k, crt := newKey(t)
	c.Slots[0x82] = pivtest.Slot{Key: k, Cert: crt}
	return c
}

// recovery takes the certificate of slot 84 of the card, by its key.
func recovery(c *pivtest.Card) func(*x509.Certificate) bool {
	want := c.Slots[0x84].Cert
	return func(crt *x509.Certificate) bool { return want != nil && crt.Equal(want) }
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "recovery"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// A long extension, so that the certificate comes in parts.
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3, 4}, Value: make([]byte, 600)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func TestSigns(t *testing.T) {
	card := newCard(t)
	k, err := find([]Card{card}, recovery(card))
	if err != nil {
		t.Fatal(err)
	}
	if k.Slot != 0x84 || !k.Cert.Equal(card.Slots[0x84].Cert) {
		t.Fatalf("slot %x", k.Slot)
	}
	c := k.Card
	s, err := k.Signer()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("a record"))
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Error("signed without the PIN")
	}
	if err := Verify(c, "123456"); err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&card.Slots[0x84].Key.PublicKey, digest[:], sig) {
		t.Error("the signature does not verify")
	}
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
		t.Error("signed a digest that is not SHA-256")
	}
}

func TestWrongPIN(t *testing.T) {
	card := newCard(t)
	if err := Select(card); err != nil {
		t.Fatal(err)
	}
	var w WrongPIN
	if err := Verify(card, "654321"); !errors.As(err, &w) || w.Left != 2 {
		t.Fatalf("a wrong PIN: %v", err)
	}
	Verify(card, "654321")
	Verify(card, "654321")
	if err := Verify(card, "123456"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("a blocked PIN: %v", err)
	}
	if err := Verify(card, "12345"); err == nil {
		t.Error("took a PIN of 5 characters")
	}
}

func TestOtherKeyInSlot(t *testing.T) {
	card := newCard(t)
	other, _ := newKey(t)
	card.Slots[0x84] = pivtest.Slot{Key: other, Cert: card.Slots[0x84].Cert}
	k, err := find([]Card{card}, recovery(card))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(k.Card, "123456"); err != nil {
		t.Fatal(err)
	}
	s, _ := k.Signer()
	digest := sha256.Sum256(nil)
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Error("took a signature from another key than the certificate's")
	}
}

func TestFind(t *testing.T) {
	bank := newCard(t)
	bank.NoPIV = true
	empty := newCard(t)
	delete(empty.Slots, 0x84)
	none := func(*x509.Certificate) bool { return false }
	if _, err := find(nil, none); !errors.Is(err, ErrNoCard) {
		t.Errorf("no cards: %v", err)
	}
	if _, err := find([]Card{bank}, recovery(bank)); !errors.Is(err, ErrNoCard) {
		t.Errorf("a card without PIV: %v", err)
	}
	if _, err := find([]Card{empty}, recovery(newCard(t))); !errors.Is(err, ErrNoKey) {
		t.Errorf("no recovery key: %v", err)
	}
	if !bank.Closed() || !empty.Closed() {
		t.Error("left a card it does not use open")
	}
	one := newCard(t)
	k, err := find([]Card{newCard(t), one, newCard(t)}, recovery(one))
	if err != nil || k.Card != one {
		t.Errorf("one card among others: %v", err)
	}
	last := newCard(t)
	k1, _ := newKey(t)
	last.Slots[LastSlot] = last.Slots[0x84]
	last.Slots[0x84] = pivtest.Slot{Key: k1}
	if k, err := find([]Card{last}, recovery(&pivtest.Card{Slots: map[byte]pivtest.Slot{0x84: last.Slots[LastSlot]}})); err != nil || k.Slot != LastSlot {
		t.Errorf("the last slot: %v", err)
	}
	twin := newCard(t)
	twin.Slots[0x84] = one.Slots[0x84]
	a := newCard(t)
	a.Slots[0x84] = one.Slots[0x84]
	if _, err := find([]Card{a, twin}, recovery(one)); !errors.Is(err, ErrTwoCards) {
		t.Errorf("two keys: %v", err)
	}
	if !a.Closed() || !twin.Closed() {
		t.Error("left a card open after two")
	}
	if _, err := Certificate(one, 0x9c); err == nil {
		t.Error("read a slot that is not retired")
	}
}

func TestChaining(t *testing.T) {
	card := newCard(t)
	if err := Select(card); err != nil {
		t.Fatal(err)
	}
	// A long SELECT goes in a chain, which the card puts back together:
	// the AID with 300 bytes after it is not the PIV application's.
	if _, sw, err := command(card, 0xa4, 0x04, 0x00, make([]byte, 300)); err != nil || sw != 0x6a82 {
		t.Fatalf("a chained command: %04x, %v", sw, err)
	}
}

func TestReadTLV(t *testing.T) {
	for _, n := range []int{0, 0x7f, 0x80, 0xff, 0x100, 0x1234} {
		v := make([]byte, n)
		got, rest, err := readTLV(append(tlv(0x53, v), 1), 0x53)
		if err != nil || len(got) != n || len(rest) != 1 {
			t.Errorf("length %d: %d, %d, %v", n, len(got), len(rest), err)
		}
	}
	for _, b := range [][]byte{nil, {0x53}, {0x54, 0}, {0x53, 0x83, 0, 0, 1}, {0x53, 0x81}, {0x53, 0x82, 1}, {0x53, 2, 0}} {
		if _, _, err := readTLV(b, 0x53); err == nil {
			t.Errorf("% x parsed", b)
		}
	}
}
