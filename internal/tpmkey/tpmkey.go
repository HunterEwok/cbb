// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package tpmkey keeps P-256 signing keys in a TPM 2.0 (docs/protocol.md,
// section 17): a key is made inside the TPM under its storage root key and
// never leaves it; what a device stores is the key's blob, which only that
// TPM can load. The service signs member TLS and records with such a key
// as with one in a file.
package tpmkey

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

// Device is the kernel's resource manager, which every program shares;
// never the raw /dev/tpm0.
const Device = "/dev/tpmrm0"

// simEnv names a TPM simulator's command port (host:port, the platform
// port the next one) that tests use in place of Device.
const simEnv = "CBB_TPM_SIMULATOR"

// ErrNoTPM is returned by Open on a machine without a TPM the service may
// use.
var ErrNoTPM = errors.New("tpmkey: no TPM")

// A TPM is an open TPM. Its commands run one at a time.
type TPM struct {
	mu  sync.Mutex
	t   transport.TPMCloser
	srk *tpm2.CreatePrimaryResponse // loaded on first use
	// psrk is the persistent storage root key at PersistentSRK, read on
	// first use when the owner hierarchy has a password, as on Windows.
	psrk *tpm2.CreatePrimaryResponse
	ek   *Endorsement // read on first use
	// keys are the keys loaded, which room flushes when the TPM has no
	// room for another object.
	keys []*Key
}

// Open opens the TPM: Device, or the simulator that CBB_TPM_SIMULATOR names.
func Open() (*TPM, error) {
	if addr := os.Getenv(simEnv); addr != "" {
		return openSimulator(addr)
	}
	t, err := openDevice()
	if err != nil {
		return nil, err
	}
	return &TPM{t: t}, nil
}

func openSimulator(addr string) (*TPM, error) {
	host, port, ok := splitPort(addr)
	if !ok {
		return nil, fmt.Errorf("tpmkey: %s=%q is not host:port", simEnv, addr)
	}
	t, err := tcp.Open(tcp.Config{CommandAddress: addr, PlatformAddress: fmt.Sprintf("%s:%d", host, port+1)})
	if err != nil {
		return nil, fmt.Errorf("tpmkey: %w", err)
	}
	return &TPM{t: t}, nil
}

func splitPort(addr string) (string, int, bool) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			var p int
			if _, err := fmt.Sscanf(addr[i+1:], "%d", &p); err != nil || p <= 0 || p >= 65535 {
				return "", 0, false
			}
			return addr[:i], p, true
		}
	}
	return "", 0, false
}

// Close closes the TPM; its keys no longer sign.
func (t *TPM) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.srk != nil {
		tpm2.FlushContext{FlushHandle: t.srk.ObjectHandle}.Execute(t.t)
		t.srk = nil
	}
	t.psrk = nil // persistent: never flushed
	t.evict()
	t.ek = nil
	return t.t.Close()
}

// room runs f, and again after flushing the loaded keys when the TPM had
// no room for another object: a TPM without the kernel's resource manager,
// as a simulator, holds three. Keys load again when they next sign.
// t.mu is held.
func (t *TPM) room(f func() error) error {
	err := f()
	if errors.Is(err, tpm2.TPMRCObjectMemory) && len(t.keys) > 0 {
		t.evict()
		err = f()
	}
	return err
}

// evict flushes the loaded keys; t.mu is held.
func (t *TPM) evict() {
	for _, k := range t.keys {
		if k.handle != nil {
			tpm2.FlushContext{FlushHandle: k.handle.ObjectHandle}.Execute(t.t)
			k.handle = nil
		}
	}
	t.keys = nil
}

// PersistentSRK is where Windows, and other systems that keep the owner
// hierarchy's password, keep a storage root key that needs none (TCG's
// "Provisioning Guidance", the SRK's handle).
const PersistentSRK uint32 = 0x81000001

// parent returns the storage root key for a new object, and the handle a
// blob records for it: the one made from the standard template, the same
// each time without a persistent handle (0), or, when the owner hierarchy
// has a password that this program does not know, PersistentSRK. t.mu is
// held.
func (t *TPM) parent() (*tpm2.CreatePrimaryResponse, uint32, error) {
	if t.psrk == nil {
		srk, err := t.made()
		if err == nil {
			return srk, 0, nil
		}
		if t.persistent() != nil {
			return nil, 0, err
		}
	}
	return t.psrk, PersistentSRK, nil
}

// parentOf returns the storage root key of a blob's parent handle.
func (t *TPM) parentOf(handle uint32) (*tpm2.CreatePrimaryResponse, error) {
	switch handle {
	case 0:
		return t.made()
	case PersistentSRK:
		if err := t.persistent(); err != nil {
			return nil, err
		}
		return t.psrk, nil
	}
	return nil, fmt.Errorf("tpmkey: an unknown parent handle %#x", handle)
}

// made returns the storage root key made from the standard template.
func (t *TPM) made() (*tpm2.CreatePrimaryResponse, error) {
	if t.srk != nil {
		return t.srk, nil
	}
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t.t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: making the storage root key: %w", err)
	}
	t.srk = rsp
	return rsp, nil
}

// persistent reads the storage root key at PersistentSRK into t.psrk.
func (t *TPM) persistent() error {
	if t.psrk != nil {
		return nil
	}
	rp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(PersistentSRK)}.Execute(t.t)
	if err != nil {
		return fmt.Errorf("tpmkey: reading the storage root key at %#x: %w", PersistentSRK, err)
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil || !pub.ObjectAttributes.Restricted || !pub.ObjectAttributes.Decrypt || !pub.ObjectAttributes.FixedTPM {
		return fmt.Errorf("tpmkey: the object at %#x is no storage root key", PersistentSRK)
	}
	t.psrk = &tpm2.CreatePrimaryResponse{ObjectHandle: tpm2.TPMHandle(PersistentSRK), OutPublic: rp.OutPublic, Name: rp.Name}
	return nil
}

// keyTemplate is a P-256 key that signs with ECDSA and never leaves the
// TPM.
var keyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		CurveID: tpm2.TPMECCNistP256,
		Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
	}),
}

// Blob is what a device stores of a key: its public and private areas,
// the private one encrypted under the TPM's storage root key, and that
// key's persistent handle, 0 for the one made from the standard template.
type Blob struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
	Parent  uint32 `json:"parent,omitempty"`
}

// A Key is a P-256 key in the TPM. It is a crypto.Signer.
type Key struct {
	tpm    *TPM
	blob   Blob
	pub    *ecdsa.PublicKey
	handle *tpm2.LoadResponse // loaded on first use
}

// NewKey makes a key in the TPM.
func (t *TPM) NewKey() (*Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	srk, handle, err := t.parent()
	if err != nil {
		return nil, err
	}
	var rsp *tpm2.CreateResponse
	err = t.room(func() (err error) {
		rsp, err = tpm2.Create{
			ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
			InPublic:     tpm2.New2B(keyTemplate),
		}.Execute(t.t)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tpmkey: making a key: %w", err)
	}
	return t.key(Blob{Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate), Parent: handle})
}

// LoadKey returns the key of a blob that NewKey made in this TPM.
func (t *TPM) LoadKey(b Blob) (*Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k, err := t.key(b)
	if err != nil {
		return nil, err
	}
	// Loading it now tells a blob of another TPM at once.
	if _, err := k.loaded(); err != nil {
		return nil, err
	}
	return k, nil
}

func (t *TPM) key(b Blob) (*Key, error) {
	pub2b, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the key's public area: %w", err)
	}
	pub, err := pub2b.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the key's public area: %w", err)
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil || pub.Type != tpm2.TPMAlgECC || parms.CurveID != tpm2.TPMECCNistP256 || !pub.ObjectAttributes.FixedTPM {
		return nil, errors.New("tpmkey: the key is not a P-256 key fixed in the TPM")
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the key's public area: %w", err)
	}
	ec, err := tpm2.ECDSAPub(parms, point)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the key's public key: %w", err)
	}
	return &Key{tpm: t, blob: b, pub: ec}, nil
}

// loaded loads the key once; t.mu is held.
func (k *Key) loaded() (*tpm2.LoadResponse, error) {
	if k.handle != nil {
		return k.handle, nil
	}
	srk, err := k.tpm.parentOf(k.blob.Parent)
	if err != nil {
		return nil, err
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](k.blob.Public)
	if err != nil {
		return nil, err
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](k.blob.Private)
	if err != nil {
		return nil, err
	}
	var rsp *tpm2.LoadResponse
	err = k.tpm.room(func() (err error) {
		rsp, err = tpm2.Load{
			ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
			InPublic:     *pub,
			InPrivate:    *priv,
		}.Execute(k.tpm.t)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tpmkey: loading the key, which another TPM may have made: %w", err)
	}
	k.handle = rsp
	k.tpm.keys = append(k.tpm.keys, k)
	return rsp, nil
}

// Blob returns what to store of the key.
func (k *Key) Blob() Blob { return k.blob }

// Public returns the key's *ecdsa.PublicKey.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Sign signs digest, made with opts' hash, as ecdsa.PrivateKey.Sign does:
// an ASN.1 ECDSA signature.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var alg tpm2.TPMAlgID
	switch opts.HashFunc() {
	case crypto.SHA256:
		alg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		alg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		alg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("tpmkey: cannot sign a %v digest", opts.HashFunc())
	}
	if len(digest) != opts.HashFunc().Size() {
		return nil, errors.New("tpmkey: the digest has the wrong length")
	}
	k.tpm.mu.Lock()
	defer k.tpm.mu.Unlock()
	h, err := k.loaded()
	if err != nil {
		return nil, err
	}
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{Handle: h.ObjectHandle, Name: h.Name},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: alg}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(k.tpm.t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: signing: %w", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: the signature: %w", err)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(sig.SignatureR.Buffer),
		new(big.Int).SetBytes(sig.SignatureS.Buffer),
	})
}
