// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package phone serves the iPhone: the shortcut's /sync endpoint, the
// pairing page and the configuration profile with the iPhone CA.
package phone

import (
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/HunterEwok/cbb/internal/group"
)

// A token is what the shortcut sends in its Authorization header. It is
// derived from the iPhone CA's key, which every Linux member holds, so any
// of them checks it without a list to keep in step; a new iPhone CA, as a
// revocation makes, ends every token at once.
//
//	cb1.<base64url of a 16-byte phone ID and a 16-byte MAC>
const tokenPrefix = "cb1."

const (
	phoneIDLen = 16
	tokenMAC   = 16
)

// ErrBadToken reports a token that this group did not issue.
var ErrBadToken = errors.New("phone: this shortcut is not paired with the group; pair the iPhone again")

// tokenKey derives the token key from the iPhone CA.
func tokenKey(ca *group.CA) ([]byte, error) {
	if ca == nil || ca.Key == nil {
		return nil, errors.New("phone: this member does not hold the iPhone CA key")
	}
	// The iPhone CA key always sits in the file: the token key is derived
	// from its bytes.
	k, ok := ca.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("phone: the iPhone CA key is not in a file")
	}
	priv, err := k.ECDH()
	if err != nil {
		return nil, err
	}
	salt := sha256.Sum256(ca.Cert.Raw)
	return hkdf.Key(sha256.New, priv.Bytes(), salt[:], "cbb iPhone token v1", 32)
}

func mac(key []byte, id []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(id)
	return h.Sum(nil)[:tokenMAC]
}

// NewToken issues a token for a new phone and returns it with the phone's
// ID, which names it in cbb status.
func NewToken(ca *group.CA) (token, phoneID string, err error) {
	key, err := tokenKey(ca)
	if err != nil {
		return "", "", err
	}
	id := make([]byte, phoneIDLen)
	rand.Read(id)
	raw := append(id, mac(key, id)...)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(raw), hex.EncodeToString(id), nil
}

// CheckToken returns the phone ID of a token this group issued.
func CheckToken(ca *group.CA, token string) (string, error) {
	key, err := tokenKey(ca)
	if err != nil {
		return "", err
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), tokenPrefix)
	if !ok {
		return "", ErrBadToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(raw) != phoneIDLen+tokenMAC {
		return "", ErrBadToken
	}
	id, got := raw[:phoneIDLen], raw[phoneIDLen:]
	if !hmac.Equal(got, mac(key, id)) {
		return "", ErrBadToken
	}
	return hex.EncodeToString(id), nil
}
