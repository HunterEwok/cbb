// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tpmkey

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// The attestation of a key in the TPM (docs/protocol.md, section 17, "TPM
// evidence"): the endorsement key (EK), which the TPM's maker certified,
// vouches for an attestation key (AK) by credential activation, and the AK
// certifies the key.

// EKIndexRSA and EKIndexECC are where the maker keeps the certificates of
// the RSA 2048 and the ECC P-256 EK, made from the TCG's templates.
const (
	EKIndexRSA = 0x01c00002
	EKIndexECC = 0x01c0000a
)

// ErrNoEKCertificate is returned by Endorsement on a TPM whose maker put no
// EK certificate in it, as Intel's and AMD's firmware TPMs often.
var ErrNoEKCertificate = errors.New("tpmkey: the TPM holds no certificate of its endorsement key")

// An Endorsement is the TPM's EK with its certificate.
type Endorsement struct {
	Cert     []byte // DER
	Public   []byte // TPM2B_PUBLIC
	template tpm2.TPMTPublic
}

// Endorsement returns the EK whose certificate the TPM holds, the ECC one
// before the RSA one. The EK is made again from its template whenever it
// is used, as every TPM gives the same one.
func (t *TPM) Endorsement() (*Endorsement, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ek != nil {
		return t.ek, nil
	}
	for _, c := range []struct {
		index    tpm2.TPMHandle
		template tpm2.TPMTPublic
	}{{EKIndexECC, tpm2.ECCEKTemplate}, {EKIndexRSA, tpm2.RSAEKTemplate}} {
		cert, err := readNV(t.t, c.index)
		if err != nil || len(cert) == 0 {
			continue
		}
		var pub []byte
		err = t.room(func() error {
			rsp, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic:      tpm2.New2B(c.template),
			}.Execute(t.t)
			if err != nil {
				return err
			}
			tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t.t)
			pub = tpm2.Marshal(rsp.OutPublic)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("tpmkey: making the endorsement key: %w", err)
		}
		t.ek = &Endorsement{Cert: cert, Public: pub, template: c.template}
		return t.ek, nil
	}
	return nil, ErrNoEKCertificate
}

// readNV reads an NV index whole, in pieces the TPM takes.
func readNV(t transport.TPM, index tpm2.TPMHandle) ([]byte, error) {
	pub, err := tpm2.NVReadPublic{NVIndex: index}.Execute(t)
	if err != nil {
		return nil, err
	}
	info, err := pub.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	h := tpm2.NamedHandle{Handle: index, Name: pub.NVName}
	var out []byte
	for off := 0; off < int(info.DataSize); {
		n := min(int(info.DataSize)-off, 768) // under every TPM's MAX_NV_BUFFER_SIZE
		rsp, err := tpm2.NVRead{AuthHandle: h, NVIndex: h, Size: uint16(n), Offset: uint16(off)}.Execute(t)
		if err != nil {
			return nil, err
		}
		out = append(out, rsp.Data.Buffer...)
		off += n
	}
	return out, nil
}

// akTemplate is a restricted P-256 key that signs only what the TPM made,
// as a certification of another key.
var akTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		Restricted:          true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		CurveID: tpm2.TPMECCNistP256,
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
	}),
}

// An AK is an attestation key, loaded only while it is used.
type AK struct {
	tpm    *TPM
	Public []byte // TPM2B_PUBLIC
	ak     *tpm2.CreateResponse
	parent uint32 // the storage root key's handle, as a Blob's
}

// NewAK makes an attestation key under the storage root key.
func (t *TPM) NewAK() (*AK, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	srk, handle, err := t.parent()
	if err != nil {
		return nil, err
	}
	var rsp *tpm2.CreateResponse
	err = t.room(func() (err error) {
		rsp, err = tpm2.Create{ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
			InPublic: tpm2.New2B(akTemplate)}.Execute(t.t)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tpmkey: making an attestation key: %w", err)
	}
	return &AK{tpm: t, Public: tpm2.Marshal(rsp.OutPublic), ak: rsp, parent: handle}, nil
}

// load loads the AK until the returned function flushes it; t.mu is held.
func (ak *AK) load() (*tpm2.LoadResponse, func(), error) {
	t := ak.tpm
	srk, err := t.parentOf(ak.parent)
	if err != nil {
		return nil, nil, err
	}
	var h *tpm2.LoadResponse
	err = t.room(func() (err error) {
		h, err = tpm2.Load{ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
			InPublic: ak.ak.OutPublic, InPrivate: ak.ak.OutPrivate}.Execute(t.t)
		return err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tpmkey: loading the attestation key: %w", err)
	}
	return h, func() { tpm2.FlushContext{FlushHandle: h.ObjectHandle}.Execute(t.t) }, nil
}

// TPM returns the TPM that holds the key.
func (k *Key) TPM() *TPM { return k.tpm }

// PublicArea returns the key's TPM2B_PUBLIC, which an attestation names.
func (k *Key) PublicArea() []byte { return k.blob.Public }

// Certify makes the TPM attest, with the AK, that k is one of its keys,
// with qualifying data extra: the TPMS_ATTEST it signed and the
// TPMT_SIGNATURE.
func (ak *AK) Certify(k *Key, extra []byte) (attest, sig []byte, err error) {
	t := ak.tpm
	t.mu.Lock()
	defer t.mu.Unlock()
	a, flush, err := ak.load()
	if err != nil {
		return nil, nil, err
	}
	defer flush()
	h, err := k.loaded()
	if err != nil {
		return nil, nil, err
	}
	rsp, err := tpm2.Certify{
		ObjectHandle:   tpm2.AuthHandle{Handle: h.ObjectHandle, Name: h.Name, Auth: tpm2.PasswordAuth(nil)},
		SignHandle:     tpm2.AuthHandle{Handle: a.ObjectHandle, Name: a.Name, Auth: tpm2.PasswordAuth(nil)},
		QualifyingData: tpm2.TPM2BData{Buffer: extra},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(t.t)
	if err != nil {
		return nil, nil, fmt.Errorf("tpmkey: certifying the key: %w", err)
	}
	return rsp.CertifyInfo.Bytes(), tpm2.Marshal(rsp.Signature), nil
}

// Activate recovers the secret that a verifier encrypted to the EK for the
// AK (tpm2.CreateCredential): the TPM gives it only when both are its own.
func (ak *AK) Activate(e *Endorsement, credential, secret []byte) ([]byte, error) {
	t := ak.tpm
	t.mu.Lock()
	defer t.mu.Unlock()
	a, flush, err := ak.load()
	if err != nil {
		return nil, err
	}
	defer flush()
	var ek *tpm2.CreatePrimaryResponse
	err = t.room(func() (err error) {
		ek, err = tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHEndorsement, InPublic: tpm2.New2B(e.template)}.Execute(t.t)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tpmkey: making the endorsement key: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: ek.ObjectHandle}.Execute(t.t)
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: a.ObjectHandle, Name: a.Name, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle: tpm2.AuthHandle{Handle: ek.ObjectHandle, Name: ek.Name,
			Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, endorsementPolicy)},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credential},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: secret},
	}.Execute(t.t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: activating the credential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

// endorsementPolicy satisfies the policy of the TCG's EK templates: the
// endorsement hierarchy's authorization, empty as on every machine that
// did not set one.
func endorsementPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonce tpm2.TPM2BNonce) error {
	_, err := tpm2.PolicySecret{AuthHandle: tpm2.TPMRHEndorsement, PolicySession: handle, NonceTPM: nonce}.Execute(t)
	return err
}
