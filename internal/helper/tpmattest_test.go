// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/attest/attesttest"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
)

// one sends one request to s and returns its answer.
func one(t *testing.T, s *Server, op string, v any) *control.Message {
	t.Helper()
	var m control.Message
	if v == nil {
		m = control.Message{Header: control.Header{Op: op, Seq: 1}}
	} else {
		m = request(t, op, 1, v)
	}
	return exchange(t, s, m)[1]
}

// TestTPMAttestation runs the TPM evidence through the helper as cbb asks
// for it: a member key in a TPM with an EK certificate, its evidence, the
// root's check of it and the credential it sends, and the TPM opening that
// credential to the value the root expects; and what each step refuses.
func TestTPMAttestation(t *testing.T) {
	tpmtest.Start(t)
	roots := tpmtest.ProvisionEK(t)
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	var pemRoots []byte
	for _, c := range roots {
		pemRoots = append(pemRoots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	f := filepath.Join(t.TempDir(), "tpm-roots.pem")
	if err := os.WriteFile(f, pemRoots, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CBB_TEST_TPM_ROOTS", f)

	s := New("test")
	s.HandleKeys()
	got := one(t, s, OpKeyNew, nil)
	var k Key
	if err := json.Unmarshal(got.Payload, &k); err != nil || k.TPM == nil {
		t.Fatalf("key-new: %v, %+v", err, got.Header)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.Public)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	const tag = "0123456789abcdef0123456789abcdef"

	// Opening a credential before any evidence is refused.
	if got := one(t, s, OpTPMActivate, Evidence{Format: EvidenceTPMCredential}); got.Error == "" {
		t.Error("a credential opened before this device sent evidence")
	}

	got = one(t, s, OpTPMEvidence, OwnEvidence{Held: k.HeldKey, Tag: tag})
	var ev Evidence
	if err := json.Unmarshal(got.Payload, &ev); err != nil || got.Error != "" {
		t.Fatalf("tpm-evidence: %v, %q", err, got.Error)
	}
	if ev.Format != EvidenceTPM || ev.GroupTag != tag || ev.TPM == nil || len(ev.Chain) != 1 || len(ev.Salt) != 16 {
		t.Fatalf("the evidence: %+v", ev)
	}

	// The root's side.
	got = one(t, s, OpAttestTPM, TPMCheck{Evidence: ev, SPKI: spki, Tag: tag})
	var ch TPMChallenge
	if err := json.Unmarshal(got.Payload, &ch); err != nil || got.Error != "" {
		t.Fatalf("attest-tpm: %v, %q", err, got.Error)
	}
	if ch.Evidence.Format != EvidenceTPMCredential || len(ch.Value) == 0 || len(ch.Proof) != 64 {
		t.Fatalf("the challenge: %+v", ch)
	}

	// The device's TPM opens it to the value the root keeps.
	got = one(t, s, OpTPMActivate, ch.Evidence)
	var back Evidence
	if err := json.Unmarshal(got.Payload, &back); err != nil || got.Error != "" {
		t.Fatalf("tpm-activate: %v, %q", err, got.Error)
	}
	if back.Format != EvidenceTPMActivated || !bytes.Equal(back.Secret, ch.Value) {
		t.Fatalf("the TPM opened %x, the root expects %x", back.Secret, ch.Value)
	}

	// A second evidence on the same EK keeps the AK; a broken credential
	// does not open.
	if got := one(t, s, OpTPMEvidence, OwnEvidence{Held: k.HeldKey, Tag: tag}); got.Error != "" {
		t.Fatalf("a second evidence: %q", got.Error)
	}
	broken := ch.Evidence
	broken.Secret = append(bytes.Clone(broken.Secret[:len(broken.Secret)-1]), broken.Secret[len(broken.Secret)-1]^1)
	if got := one(t, s, OpTPMActivate, broken); got.Error == "" {
		t.Error("a broken credential opened")
	}

	for name, c := range map[string]struct {
		op string
		v  any
	}{
		"evidence without a TPM key":    {OpTPMEvidence, OwnEvidence{Tag: tag}},
		"evidence for another group":    {OpAttestTPM, TPMCheck{Evidence: ev, SPKI: spki, Tag: strings.Repeat("f", 32)}},
		"evidence for another key":      {OpAttestTPM, TPMCheck{Evidence: ev, SPKI: otherSPKI(t), Tag: tag}},
		"evidence without its EK chain": {OpAttestTPM, TPMCheck{Evidence: Evidence{Format: EvidenceTPM, GroupTag: tag}, SPKI: spki, Tag: tag}},
		"a credential of another form":  {OpTPMActivate, Evidence{Format: EvidenceTPM}},
		"android for another group":     {OpAttestAndroid, AndroidCheck{Evidence: Evidence{GroupTag: tag, Salt: make([]byte, 16)}, Tag: strings.Repeat("f", 32)}},
		"android with a short salt":     {OpAttestAndroid, AndroidCheck{Evidence: Evidence{GroupTag: tag, Salt: []byte{1}}, Tag: tag}},
	} {
		if got := one(t, s, c.op, c.v); got.Error == "" {
			t.Errorf("%s: answered", name)
		}
	}
	for _, op := range []string{OpAttestTPM, OpAttestAndroid, OpTPMEvidence, OpTPMActivate} {
		if got := exchange(t, s, control.Message{Header: control.Header{Op: op, Seq: 1}, Payload: []byte("{")})[1]; got.Error == "" {
			t.Errorf("%s answered a request that is not JSON", op)
		}
	}
}

// TestAndroidAttestation checks an Android chain through the helper, with
// the roots of tests: proven, and revoked when the root lists its leaf's
// serial number.
func TestAndroidAttestation(t *testing.T) {
	member, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&member.PublicKey)
	const tag = "0123456789abcdef0123456789abcdef"
	salt := bytes.Repeat([]byte{3}, 16)
	challenge := challengeOf(t, tag, salt)
	chain, root, err := attesttest.Android(&member.PublicKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: root}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CBB_TEST_ATTEST_ROOTS", f)
	s := New("test")
	s.HandleKeys()
	ev := Evidence{Format: EvidenceAndroid, Key: EvidenceMember, GroupTag: tag, Salt: salt, Chain: chain}
	got := one(t, s, OpAttestAndroid, AndroidCheck{Evidence: ev, SPKI: spki, Tag: tag})
	var p Proven
	if err := json.Unmarshal(got.Payload, &p); err != nil || got.Error != "" {
		t.Fatalf("attest-android: %v, %q", err, got.Error)
	}
	if p.Store != group.StoreProven || len(p.Proof) != 64 || p.Revoked {
		t.Fatalf("the result: %+v", p)
	}

	var serials []string
	for _, d := range chain {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			t.Fatal(err)
		}
		serials = append(serials, c.SerialNumber.Text(16))
	}
	got = one(t, s, OpAttestAndroid, AndroidCheck{Evidence: ev, SPKI: spki, Tag: tag, Revoked: serials})
	if err := json.Unmarshal(got.Payload, &p); err != nil || got.Error != "" {
		t.Fatalf("attest-android with revoked serials: %v, %q", err, got.Error)
	}
	if !p.Revoked || p.Store != group.StoreHardware {
		t.Fatalf("a revoked chain: %+v", p)
	}
}

// TestAttestStatus checks that attest-status fetches both files from the
// mirror, and refuses one that is missing or not JSON.
func TestAttestStatus(t *testing.T) {
	files := map[string]string{"/keys.json": `{"type":"keys"}`, "/attest-status.json": `{"type":"attest-status"}`}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()
	t.Setenv("CBB_TEST_STATUS_URL", srv.URL+"/")
	if statusURL() != srv.URL+"/" {
		t.Fatal("CBB_TEST_STATUS_URL is not the mirror")
	}
	s := New("test")
	s.HandleKeys()
	got := one(t, s, OpAttestStatus, nil)
	var f StatusFiles
	if err := json.Unmarshal(got.Payload, &f); err != nil || got.Error != "" {
		t.Fatalf("attest-status: %v, %q", err, got.Error)
	}
	if string(f.Keys) != files["/keys.json"] || string(f.Status) != files["/attest-status.json"] {
		t.Fatalf("the files: %s %s", f.Keys, f.Status)
	}

	files["/attest-status.json"] = "not JSON"
	if got := one(t, s, OpAttestStatus, nil); got.Error == "" {
		t.Error("a file that is not JSON was taken")
	}
	delete(files, "/keys.json")
	if got := one(t, s, OpAttestStatus, nil); got.Error == "" {
		t.Error("a missing file was taken")
	}
	t.Setenv("CBB_TEST_STATUS_URL", "")
	if !strings.HasPrefix(statusURL(), "https://") {
		t.Errorf("the mirror without the hook: %s", statusURL())
	}
}

// challengeOf is the challenge an evidence of the group tag with salt
// answers.
func challengeOf(t *testing.T, tag string, salt []byte) []byte {
	t.Helper()
	c, err := attest.Challenge(tag, nil, salt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// otherSPKI is a P-256 key no evidence names.
func otherSPKI(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}
