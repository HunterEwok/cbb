// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/release"
	"github.com/HunterEwok/cbb/internal/testhooks"
	"github.com/HunterEwok/cbb/internal/tpmkey"
)

// The operations on attestations (docs/protocol.md, section 17,
// "Evidence" and "TPM evidence"), which need Go's checks of Android's Key
// Attestation and of the TPM's structures, and the TPM itself. cbb, the
// group's root or a device whose member key is in a TPM, asks for them;
// the requests and answers are JSON in the payload.
const (
	// OpAttestAndroid checks an Android Key Attestation a peer sent; the
	// request is an AndroidCheck, the answer a Proven.
	OpAttestAndroid = "attest-android"
	// OpAttestTPM checks a TPM attestation a peer sent; the request is a
	// TPMCheck, the answer a TPMChallenge.
	OpAttestTPM = "attest-tpm"
	// OpTPMEvidence makes this device's TPM evidence of its member key;
	// the request is an OwnEvidence, the answer an Evidence, with no
	// format where the TPM holds no EK certificate.
	OpTPMEvidence = "tpm-evidence"
	// OpTPMActivate opens a credential the group's root sent with the TPM
	// that made the last evidence; the request is the root's Evidence, the
	// answer the Evidence to send back.
	OpTPMActivate = "tpm-activate"
	// OpAttestStatus fetches the revocation list of Android attestations
	// from the mirror (section 17, "Revoked attestations"); the answer is a
	// StatusFiles, which cbb checks under its release roots.
	OpAttestStatus = "attest-status"
)

// StatusFiles are the mirror's keys.json and attest-status.json as fetched.
type StatusFiles struct {
	Keys   json.RawMessage `json:"keys"`
	Status json.RawMessage `json:"status"`
}

// statusURL is the mirror of the revocation list; CBB_TEST_STATUS_URL in
// tests.
func statusURL() string {
	if u := os.Getenv("CBB_TEST_STATUS_URL"); u != "" {
		return u
	}
	return "https://cbb.tools/attest/"
}

func fetchStatus(req *control.Message) (*control.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var f StatusFiles
	for _, x := range []struct {
		name string
		to   *json.RawMessage
	}{{"keys.json", &f.Keys}, {"attest-status.json", &f.Status}} {
		url := statusURL() + x.name
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			return nil, err
		}
		data, err := release.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", url, resp.Status)
		}
		if !json.Valid(data) {
			return nil, fmt.Errorf("%s is not JSON", url)
		}
		*x.to = data
	}
	return answer(f)
}

// The formats and the key of Evidence.
const (
	EvidenceAndroid       = "android-key"
	EvidenceTPM           = "tpm"
	EvidenceTPMCredential = "tpm-credential"
	EvidenceTPMActivated  = "tpm-activated"
	EvidenceMember        = "member"
)

// Evidence is an evidence message's object, as the member protocol carries
// it.
type Evidence struct {
	Format     string        `json:"format"`
	Key        string        `json:"key"`
	GroupTag   string        `json:"group_tag,omitempty"`
	Salt       []byte        `json:"salt"`
	Chain      [][]byte      `json:"chain"`
	TPM        *TPMStructure `json:"tpm,omitempty"`
	Credential []byte        `json:"credential,omitempty"`
	Secret     []byte        `json:"secret,omitempty"`
}

// TPMStructure is the TPM's attestation of a key in a tpm evidence.
type TPMStructure struct {
	EK        []byte `json:"ek"`
	AK        []byte `json:"ak"`
	Key       []byte `json:"key"`
	Attest    []byte `json:"attest"`
	Signature []byte `json:"signature"`
}

// AndroidCheck asks to check an Android evidence of the key SPKI (the
// sender's TLS certificate's, DER) for the group Tag, under the revoked
// serial numbers the root holds.
type AndroidCheck struct {
	Evidence Evidence `json:"evidence"`
	SPKI     []byte   `json:"spki"`
	Tag      string   `json:"tag"`
	Revoked  []string `json:"revoked,omitempty"`
}

// Proven is what an attestation shows of a key: its store and kind, why it
// is not proven, and the proof the device record keeps.
type Proven struct {
	Store string `json:"store"`
	Kind  string `json:"kind,omitempty"`
	Why   string `json:"why,omitempty"`
	Proof string `json:"proof,omitempty"`
	// Revoked tells a chain that a revoked certificate made prove nothing.
	Revoked bool `json:"revoked,omitempty"`
}

// TPMCheck asks to check a TPM evidence of the key SPKI for the group Tag.
type TPMCheck struct {
	Evidence Evidence `json:"evidence"`
	SPKI     []byte   `json:"spki"`
	Tag      string   `json:"tag"`
}

// TPMChallenge is the credential to send the device, and what the root
// expects back of it and records once it comes.
type TPMChallenge struct {
	Evidence Evidence `json:"evidence"`
	Value    []byte   `json:"value"`
	Proof    string   `json:"proof"`
}

// OwnEvidence asks for the TPM evidence of the member key Held for the
// group Tag.
type OwnEvidence struct {
	Held group.HeldKey `json:"held"`
	Tag  string        `json:"tag"`
}

// tpmAttestation is this device's: its TPM's EK and the AK that certified
// the member key.
type tpmAttestation struct {
	ek *tpmkey.Endorsement
	ak *tpmkey.AK
}

// attestation serves the attestation operations.
type attestation struct {
	keys *keys

	mu      sync.Mutex
	own     *tpmAttestation
	opening sync.Mutex // the TPM opens one credential at a time
}

// The roots attestations must lead to: Google's and the TPM makers', but
// in a build with the test hooks (internal/testhooks) the PEM files CBB_TEST_ATTEST_ROOTS (the roots' public keys,
// as the policy takes them, or their certificates) and CBB_TEST_TPM_ROOTS
// (certificates) name.
func androidRoots() ([][]byte, error) {
	f := testhooks.Getenv("CBB_TEST_ATTEST_ROOTS")
	if f == "" {
		return nil, nil
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			return out, nil
		}
		switch b.Type {
		case "PUBLIC KEY":
			out = append(out, b.Bytes)
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, c.RawSubjectPublicKeyInfo)
		}
	}
}

func tpmRoots() ([]*x509.Certificate, error) {
	f := testhooks.Getenv("CBB_TEST_TPM_ROOTS")
	if f == "" {
		return nil, nil
	}
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return attest.ParseTPMRoots(data)
}

func (a *attestation) android(req *control.Message) (*control.Message, error) {
	var r AndroidCheck
	if err := json.Unmarshal(req.Payload, &r); err != nil {
		return nil, fmt.Errorf("an attestation request that is not understood: %w", err)
	}
	e := r.Evidence
	if e.GroupTag != "" && e.GroupTag != r.Tag {
		return nil, errors.New("an attestation made for another group")
	}
	challenge, err := attest.Challenge(e.GroupTag, nil, e.Salt)
	if err != nil {
		return nil, err
	}
	roots, err := androidRoots()
	if err != nil {
		return nil, err
	}
	revoked := make(map[string]bool, len(r.Revoked))
	for _, s := range r.Revoked {
		revoked[s] = true
	}
	res, err := attest.CheckAndroid(e.Chain, r.SPKI, challenge, attest.Policy{Roots: roots, Revoked: revoked})
	if errors.Is(err, attest.ErrRevoked) {
		// The keys may still be in hardware, as the hello says, but
		// Google no longer vouches for the chain.
		return answer(Proven{Store: group.StoreHardware, Why: err.Error(), Revoked: true})
	}
	if err != nil {
		return nil, err
	}
	p := Proven{Store: res.Store, Kind: res.Kind, Why: res.Why}
	if res.Store == group.StoreProven {
		leaf := sha256.Sum256(e.Chain[0])
		p.Proof = hex.EncodeToString(leaf[:])
	}
	return answer(p)
}

func (a *attestation) tpm(req *control.Message) (*control.Message, error) {
	var r TPMCheck
	if err := json.Unmarshal(req.Payload, &r); err != nil {
		return nil, fmt.Errorf("an attestation request that is not understood: %w", err)
	}
	e := r.Evidence
	if e.TPM == nil || len(e.Chain) == 0 {
		return nil, errors.New("a TPM attestation without its EK certificate")
	}
	if e.GroupTag != r.Tag {
		return nil, errors.New("a TPM attestation made for another group")
	}
	challenge, err := attest.Challenge(e.GroupTag, nil, e.Salt)
	if err != nil {
		return nil, err
	}
	roots, err := tpmRoots()
	if err != nil {
		return nil, err
	}
	ev := attest.TPMEvidence{EKCert: e.Chain[0], EKChain: e.Chain[1:], EK: e.TPM.EK, AK: e.TPM.AK, Key: e.TPM.Key,
		Attest: e.TPM.Attest, Signature: e.TPM.Signature}
	_, cred, err := attest.CheckTPM(ev, r.SPKI, challenge, attest.TPMPolicy{Roots: roots})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(e.Chain[0])
	return answer(TPMChallenge{
		Evidence: Evidence{Format: EvidenceTPMCredential, Key: EvidenceMember, Salt: []byte{}, Chain: [][]byte{},
			Credential: cred.Credential, Secret: cred.Secret},
		Value: cred.Value, Proof: hex.EncodeToString(sum[:])})
}

func (a *attestation) evidence(req *control.Message) (*control.Message, error) {
	var r OwnEvidence
	if err := json.Unmarshal(req.Payload, &r); err != nil || r.Held.TPM == nil {
		return nil, errors.New("an evidence request that is not understood")
	}
	signer, err := a.keys.load(r.Held)
	if err != nil {
		return nil, err
	}
	k, ok := signer.(*tpmkey.Key)
	if !ok {
		return answer(Evidence{})
	}
	t := k.TPM()
	ek, err := t.Endorsement()
	if errors.Is(err, tpmkey.ErrNoEKCertificate) {
		return answer(Evidence{})
	}
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	att := a.own
	a.mu.Unlock()
	if att == nil || att.ek != ek {
		ak, err := t.NewAK()
		if err != nil {
			return nil, err
		}
		att = &tpmAttestation{ek: ek, ak: ak}
		a.mu.Lock()
		a.own = att
		a.mu.Unlock()
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	challenge, err := attest.Challenge(r.Tag, nil, salt)
	if err != nil {
		return nil, err
	}
	at, sig, err := att.ak.Certify(k, challenge)
	if err != nil {
		return nil, err
	}
	return answer(Evidence{Format: EvidenceTPM, Key: EvidenceMember, GroupTag: r.Tag, Salt: salt,
		Chain: [][]byte{ek.Cert},
		TPM:   &TPMStructure{EK: ek.Public, AK: att.ak.Public, Key: k.PublicArea(), Attest: at, Signature: sig}})
}

func (a *attestation) activate(req *control.Message) (*control.Message, error) {
	var e Evidence
	if err := json.Unmarshal(req.Payload, &e); err != nil || e.Format != EvidenceTPMCredential {
		return nil, errors.New("a TPM credential that is not understood")
	}
	if !a.opening.TryLock() {
		return nil, errors.New("a TPM credential while the TPM opens another")
	}
	defer a.opening.Unlock()
	a.mu.Lock()
	att := a.own
	a.mu.Unlock()
	if att == nil {
		return nil, errors.New("a TPM credential, but this device sent no TPM attestation")
	}
	v, err := att.ak.Activate(att.ek, e.Credential, e.Secret)
	if err != nil {
		return nil, err
	}
	return answer(Evidence{Format: EvidenceTPMActivated, Key: EvidenceMember, Salt: []byte{}, Chain: [][]byte{}, Secret: v})
}
