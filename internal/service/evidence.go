// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/release"
)

// attestRoots are the roots attestations must lead to; attest.GoogleRoots
// when nil, as everywhere but in tests.
var attestRoots [][]byte

// The revocation list's mirror (docs/protocol.md, section 17, "Revoked
// attestations"): where the root fetches keys.json and attest-status.json,
// how often, and the file in the state directory that keeps the last
// list it took. statusRoots are the root keys it checks them under,
// release.Roots but in tests.
var (
	statusURL   = "https://cbb.tools/attest/"
	statusRoots = func() [][]byte { return release.Roots }
)

// statusEvery is a variable for the tests.
var statusEvery = 24 * time.Hour

const statusFile = "attest-status.json"

// peerEvidence is the last evidence a peer sent, kept so that the root
// checks it again when the revocation list changes.
type peerEvidence struct {
	chain []*x509.Certificate
	e     node.Evidence
}

// statusKept is statusFile: the files the root took and what it has seen.
type statusKept struct {
	Keys   release.File `json:"keys"`
	Status release.File `json:"status"`
	Seen   release.Seen `json:"seen"`
}

// evidenceReceived checks the attestation a peer sent of its member key
// and, on the group's root, records what it proves in the peer's device
// record when that differs from what the record says (docs/protocol.md,
// section 17, "Evidence"). Other members ignore it.
func (s *Service) evidenceReceived(peer group.DeviceID, chain []*x509.Certificate, e node.Evidence) error {
	if len(chain) == 0 || e.Key != node.EvidenceMember {
		return nil // from a newer version
	}
	switch e.Format {
	case node.EvidenceAndroid:
		return s.androidEvidence(peer, chain, e)
	case node.EvidenceTPM:
		return s.tpmEvidence(peer, chain, e)
	case node.EvidenceTPMCredential:
		return s.tpmCredential(peer, chain[0], e)
	case node.EvidenceTPMActivated:
		return s.tpmActivated(peer, chain, e)
	}
	return nil
}

// androidEvidence checks an Android Key Attestation on the root.
func (s *Service) androidEvidence(peer group.DeviceID, chain []*x509.Certificate, e node.Evidence) error {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil || !id.IsRoot() {
		return nil
	}
	s.attMu.Lock()
	if s.attEvidence == nil {
		s.attEvidence = map[group.DeviceID]peerEvidence{}
	}
	s.attEvidence[peer] = peerEvidence{chain, e}
	revoked := s.attRevoked
	s.attMu.Unlock()
	tag := group.Tag(id.GroupCA.Cert)
	if e.GroupTag != "" && e.GroupTag != tag {
		return errors.New("an attestation made for another group")
	}
	challenge, err := attest.Challenge(e.GroupTag, nil, e.Salt)
	if err != nil {
		return err
	}
	res, err := attest.CheckAndroid(e.Chain, chain[0].RawSubjectPublicKeyInfo, challenge, attest.Policy{Roots: attestRoots, Revoked: revoked})
	if errors.Is(err, attest.ErrRevoked) {
		// The keys may still be in hardware, as the hello says, but
		// Google no longer vouches for the chain.
		res, err = attest.Result{Store: group.StoreHardware, Why: err.Error()}, nil
	}
	if err != nil {
		return err
	}
	proof := ""
	if res.Store == group.StoreProven {
		leaf := sha256.Sum256(e.Chain[0])
		proof = hex.EncodeToString(leaf[:])
	}
	return s.recordEvidence(peer, chain[0], res, proof)
}

// recordEvidence records on the root what an attestation of peer's member
// key showed, when the device's record says otherwise.
func (s *Service) recordEvidence(peer group.DeviceID, cert *x509.Certificate, res attest.Result, proof string) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || !id.IsRoot() {
		return nil
	}
	s.listMu.Lock()
	defer s.listMu.Unlock()
	rec := s.deviceRecord(peer)
	switch {
	case rec == nil || rec.Key != group.KeyHashOf(cert):
		return nil // not listed yet; it sends the evidence again when it next connects
	case res.Kind == "" && res.Store == group.StoreHardware:
		// Revoked: only a record that says proven changes.
		if rec.Store != group.StoreProven {
			return nil
		}
		res.Kind = rec.Kind
	case rec.Store == res.Store && rec.Kind == res.Kind:
		return nil
	}
	r, err := s.signRecord(id, group.RecordBody{Type: group.RecordDevice, Device: string(rec.ID), Name: rec.Name, Role: rec.Role,
		OS: rec.OS, Key: &rec.Key, Admin: rec.AdminKey, Powers: rec.Powers, Commands: rec.Commands, Store: res.Store, Kind: res.Kind, Proof: proof, Seal: rec.Seal, ForwardOnly: rec.ForwardOnly})
	if err != nil {
		return fmt.Errorf("recording what its attestation proves: %w", err)
	}
	s.publish(nd, r)
	why := ""
	if res.Why != "" {
		why = ": " + res.Why
	}
	s.logf("cbb: the attestation of %s (%s) shows its keys %s (%s)%s", rec.Name, rec.ID, res.Store, res.Kind, why)
	return nil
}

// statusLoop keeps the revocation list current on the group's root: it
// takes the one kept in the state directory, then fetches the mirror's
// when the group starts and every statusEvery after, until ctx is done.
// It does nothing while no root keys are pinned.
func (s *Service) statusLoop(ctx context.Context) {
	if len(statusRoots()) == 0 {
		return
	}
	s.loadStatus()
	t := time.NewTicker(statusEvery)
	defer t.Stop()
	for {
		s.mu.Lock()
		root := s.id != nil && s.id.IsRoot()
		s.mu.Unlock()
		if root {
			if err := s.fetchStatus(ctx); err != nil {
				s.logf("cbb: fetching the revocation list of Android attestations: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// loadStatus takes the list kept in the state directory, when it still
// checks out.
func (s *Service) loadStatus() {
	data, err := os.ReadFile(filepath.Join(s.cfg.StateDir, statusFile))
	if err != nil {
		return
	}
	var k statusKept
	if json.Unmarshal(data, &k) != nil {
		return
	}
	// A kept list is checked again from scratch: it is the one seen last.
	st, _, err := release.CheckStatus(k.Keys, k.Status, statusRoots(), s.cfg.now(), release.Seen{})
	if err != nil {
		return
	}
	s.attMu.Lock()
	s.attRevoked = st.Revoked()
	s.attMu.Unlock()
}

// fetchStatus fetches keys.json and attest-status.json from the mirror,
// takes them when they check out and are not older than the kept ones,
// and checks the connected peers' evidence again when the list changed.
func (s *Service) fetchStatus(ctx context.Context) error {
	path := filepath.Join(s.cfg.StateDir, statusFile)
	var kept statusKept
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &kept) // a broken file starts over
	}
	var files [2]release.File
	for i, name := range []string{"keys.json", "attest-status.json"} {
		if err := fetchJSON(ctx, statusURL+name, &files[i]); err != nil {
			return err
		}
	}
	st, seen, err := release.CheckStatus(files[0], files[1], statusRoots(), s.cfg.now(), kept.Seen)
	if err != nil {
		return err
	}
	if seen == kept.Seen {
		return nil // the same list
	}
	data, err := json.Marshal(statusKept{Keys: files[0], Status: files[1], Seen: seen})
	if err != nil {
		return err
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return err
	}
	s.attMu.Lock()
	s.attRevoked = st.Revoked()
	peers := make(map[group.DeviceID]peerEvidence, len(s.attEvidence))
	for id, pe := range s.attEvidence {
		peers[id] = pe
	}
	s.attMu.Unlock()
	s.logf("cbb: took the revocation list of Android attestations of %s, %d certificates", time.UnixMilli(st.TimeMS).UTC().Format(time.DateOnly), len(st.AndroidRevoked))
	for id, pe := range peers {
		if err := s.evidenceReceived(id, pe.chain, pe.e); err != nil {
			s.logf("cbb: checking the attestation of %s again: %v", id, err)
		}
	}
	return nil
}

// fetchJSON gets url, at most a little more than a release file's body,
// into v.
func fetchJSON(ctx context.Context, url string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*release.MaxBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
