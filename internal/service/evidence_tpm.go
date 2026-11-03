// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// The attestation of a member key in the TPM (docs/protocol.md, section
// 17, "TPM evidence"): the device sends the TPM's certification of its key
// by an attestation key, the root answers with a credential that only the
// TPM holding both that AK and the certified EK opens, and the device
// sends back what it holds.

// tpmRoots are the TPM makers' certificates; attest.TPMRoots when nil, as
// everywhere but in tests.
var tpmRoots []*x509.Certificate

// tpmAttestation is this device's: its TPM's EK and the AK that certified
// the member key.
type tpmAttestation struct {
	ek *tpmkey.Endorsement
	ak *tpmkey.AK
}

// tpmPending is what the root expects back of a credential it sent.
type tpmPending struct {
	value []byte
	cert  []byte // the peer's TLS certificate, DER
	proof string
}

// ownEvidence is the evidence this device sends its peers: the TPM's
// attestation of its member key, when the key is in a TPM whose maker put
// an EK certificate in it; none otherwise.
func (s *Service) ownEvidence(id *group.Identity) []node.Evidence {
	k, ok := id.Key.(*tpmkey.Key)
	if !ok {
		return nil
	}
	e, err := s.attestTPM(id, k)
	if errors.Is(err, tpmkey.ErrNoEKCertificate) {
		return nil
	}
	if err != nil {
		s.logf("cbb: the TPM's attestation of the member key: %v", err)
		return nil
	}
	return []node.Evidence{e}
}

func (s *Service) attestTPM(id *group.Identity, k *tpmkey.Key) (node.Evidence, error) {
	t := k.TPM()
	ek, err := t.Endorsement()
	if err != nil {
		return node.Evidence{}, err
	}
	s.tpmMu.Lock()
	att := s.tpmAtt
	s.tpmMu.Unlock()
	if att == nil || att.ek != ek {
		ak, err := t.NewAK()
		if err != nil {
			return node.Evidence{}, err
		}
		att = &tpmAttestation{ek: ek, ak: ak}
		s.tpmMu.Lock()
		s.tpmAtt = att
		s.tpmMu.Unlock()
	}
	tag := group.Tag(id.GroupCA.Cert)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return node.Evidence{}, err
	}
	challenge, err := attest.Challenge(tag, nil, salt)
	if err != nil {
		return node.Evidence{}, err
	}
	at, sig, err := att.ak.Certify(k, challenge)
	if err != nil {
		return node.Evidence{}, err
	}
	return node.Evidence{Format: node.EvidenceTPM, Key: node.EvidenceMember, GroupTag: tag, Salt: salt,
		Chain: [][]byte{ek.Cert},
		TPM:   &node.TPMEvidence{EK: ek.Public, AK: att.ak.Public, Key: k.PublicArea(), Attest: at, Signature: sig}}, nil
}

// tpmEvidence checks, on the root, the TPM attestation a peer sent and
// sends it the credential.
func (s *Service) tpmEvidence(peer group.DeviceID, chain []*x509.Certificate, e node.Evidence) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || !id.IsRoot() || nd == nil {
		return nil
	}
	if e.TPM == nil || len(e.Chain) == 0 {
		return errors.New("a TPM attestation without its EK certificate")
	}
	tag := group.Tag(id.GroupCA.Cert)
	if e.GroupTag != tag {
		return errors.New("a TPM attestation made for another group")
	}
	challenge, err := attest.Challenge(e.GroupTag, nil, e.Salt)
	if err != nil {
		return err
	}
	ev := attest.TPMEvidence{EKCert: e.Chain[0], EKChain: e.Chain[1:], EK: e.TPM.EK, AK: e.TPM.AK, Key: e.TPM.Key,
		Attest: e.TPM.Attest, Signature: e.TPM.Signature}
	_, cred, err := attest.CheckTPM(ev, chain[0].RawSubjectPublicKeyInfo, challenge, attest.TPMPolicy{Roots: tpmRoots})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(e.Chain[0])
	s.tpmMu.Lock()
	if s.tpmPending == nil {
		s.tpmPending = map[group.DeviceID]tpmPending{}
	}
	s.tpmPending[peer] = tpmPending{value: cred.Value, cert: chain[0].Raw, proof: hex.EncodeToString(sum[:])}
	s.tpmMu.Unlock()
	nd.SendEvidence(peer, node.Evidence{Format: node.EvidenceTPMCredential, Key: node.EvidenceMember,
		Salt: []byte{}, Chain: [][]byte{}, Credential: cred.Credential, Secret: cred.Secret})
	return nil
}

// tpmCredential opens, with this device's TPM, the credential the group's
// root sent, and sends back what it held. Only the root sends one, and the
// TPM opens one at a time: each takes the TPM that the member key's
// signatures need too.
func (s *Service) tpmCredential(peer group.DeviceID, cert *x509.Certificate, e node.Evidence) error {
	var root group.DeviceID
	var key group.KeyHash
	revoked := true
	s.recMu.Lock()
	if s.records != nil {
		root, key = s.records.RootMember()
		revoked = s.records.Revoked(key)
	}
	s.recMu.Unlock()
	if root == "" || peer != root || group.KeyHashOf(cert) != key || revoked {
		return errors.New("a TPM credential from a device that is not the group's root")
	}
	if !s.tpmOpening.TryLock() {
		return errors.New("a TPM credential while the TPM opens another")
	}
	defer s.tpmOpening.Unlock()
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	s.tpmMu.Lock()
	att := s.tpmAtt
	s.tpmMu.Unlock()
	if att == nil || nd == nil {
		return errors.New("a TPM credential, but this device sent no TPM attestation")
	}
	v, err := att.ak.Activate(att.ek, e.Credential, e.Secret)
	if err != nil {
		return err
	}
	nd.SendEvidence(peer, node.Evidence{Format: node.EvidenceTPMActivated, Key: node.EvidenceMember,
		Salt: []byte{}, Chain: [][]byte{}, Secret: v})
	return nil
}

// tpmActivated records, on the root, a peer's member key as proven in a
// TPM when it sent back the credential's value.
func (s *Service) tpmActivated(peer group.DeviceID, chain []*x509.Certificate, e node.Evidence) error {
	s.tpmMu.Lock()
	p, ok := s.tpmPending[peer]
	delete(s.tpmPending, peer)
	s.tpmMu.Unlock()
	if !ok {
		return errors.New("an activated TPM credential that this device did not send")
	}
	if subtle.ConstantTimeCompare(p.value, e.Secret) != 1 || subtle.ConstantTimeCompare(p.cert, chain[0].Raw) != 1 {
		return fmt.Errorf("%w: the TPM did not open the credential", attest.ErrInvalid)
	}
	return s.recordEvidence(peer, chain[0], attest.Result{Store: group.StoreProven, Kind: attest.KindTPM}, p.proof)
}
