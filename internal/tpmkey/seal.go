// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tpmkey

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// MaxSealed is the most a sealed object holds: what every TPM 2.0 takes
// (MAX_SYM_DATA).
const MaxSealed = 128

// sealTemplate is a sealed data object: no key, only the data it was made
// with, fixed to the TPM and released to whoever loads it.
var sealTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgKeyedHash,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:     true,
		FixedParent:  true,
		UserWithAuth: true,
		NoDA:         true,
	},
}

// Seal keeps data, at most MaxSealed bytes, as an object of the TPM: the
// blob it returns gives the data back only in this TPM (Unseal). The data
// crosses to the TPM encrypted under its storage root key, so whoever
// listens on the chip's bus does not see it.
func (t *TPM) Seal(data []byte) (Blob, error) {
	if len(data) == 0 || len(data) > MaxSealed {
		return Blob{}, fmt.Errorf("tpmkey: cannot seal %d bytes", len(data))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	srk, handle, err := t.parent()
	if err != nil {
		return Blob{}, err
	}
	s, err := t.session(srk, true)
	if err != nil {
		return Blob{}, err
	}
	var rsp *tpm2.CreateResponse
	err = t.room(func() (err error) {
		rsp, err = tpm2.Create{
			ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
			InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data}),
			}},
			InPublic: tpm2.New2B(sealTemplate),
		}.Execute(t.t, s)
		return err
	})
	if err != nil {
		return Blob{}, fmt.Errorf("tpmkey: sealing: %w", err)
	}
	return Blob{Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate), Parent: handle}, nil
}

// Unseal returns the data that Seal kept in b.
func (t *TPM) Unseal(b Blob) ([]byte, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the sealed object's public area: %w", err)
	}
	if p, err := pub.Contents(); err != nil || p.Type != tpm2.TPMAlgKeyedHash || !p.ObjectAttributes.FixedTPM {
		return nil, errors.New("tpmkey: not a sealed object fixed in the TPM")
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the sealed object's private area: %w", err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	srk, err := t.parentOf(b.Parent)
	if err != nil {
		return nil, err
	}
	var obj *tpm2.LoadResponse
	err = t.room(func() (err error) {
		obj, err = tpm2.Load{
			ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
			InPublic:     *pub,
			InPrivate:    *priv,
		}.Execute(t.t)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tpmkey: loading the sealed object, which another TPM may have made: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: obj.ObjectHandle}.Execute(t.t)
	s, err := t.session(srk, false)
	if err != nil {
		return nil, err
	}
	rsp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: obj.ObjectHandle, Name: obj.Name, Auth: tpm2.PasswordAuth(nil)},
	}.Execute(t.t, s)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: unsealing: %w", err)
	}
	return rsp.OutData.Buffer, nil
}

// session is a session salted with the storage root key that encrypts
// the command's first parameter (in) or the response's.
func (t *TPM) session(srk *tpm2.CreatePrimaryResponse, in bool) (tpm2.Session, error) {
	pub, err := srk.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the storage root key: %w", err)
	}
	enc := tpm2.AESEncryption(128, tpm2.EncryptOut)
	if in {
		enc = tpm2.AESEncryption(128, tpm2.EncryptIn)
	}
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, enc, tpm2.Salted(srk.ObjectHandle, *pub)), nil
}
