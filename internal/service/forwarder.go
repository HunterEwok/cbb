// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/release"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// registerForwarderLocked keeps the running hub registered with its
// forwarder, if it has one, until ctx is done: the clients that cannot
// reach the hub directly come through the forwarder (docs/design.md, "The
// forwarder").
func (s *Service) registerForwarderLocked(ctx context.Context, h *tunnel.Hub, st *tunnel.State) {
	fw := st.Forwarder
	if fw == nil {
		s.tunFwd = nil
		return
	}
	s.tunFwd = &control.Forwarder{Endpoint: fw.Endpoint.String()}
	link := forward.Link{Endpoint: fw.Endpoint, Pin: fw.Pin}
	if fw.Project {
		// The pins keys.json gives now, which a new key of the project's
		// forwarder reaches the hub by.
		pins := s.projectPins()
		link.Pin, link.Also = pins[0], pins[1:]
	}
	cfg := forward.HubConfig{
		Link:        link,
		Key:         st.ServingKey(),
		Obfuscation: st.Obfuscation,
		VLESSID:     fw.VLESSID,
		VLESS:       func() []tunnel.VLESS { return s.hubVLESS(fw) },
		Cert: func() tls.Certificate {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.id == nil {
				return tls.Certificate{}
			}
			return s.id.ForwarderCertificate()
		},
		Authority:   s.forwarderAuthority,
		Credentials: s.hubCredentials,
		HubCert:     s.hubCert,
		Send:        h.Send,
		Allowed:     netguard.Allowed,
		Report: func(r forward.Report) {
			stale := s.entriesStale(fw, r.Err)
			s.tunMu.Lock()
			defer s.tunMu.Unlock()
			if s.tunRun == nil || s.tunRun.hub != h {
				return
			}
			f := &control.Forwarder{Endpoint: fw.Endpoint.String(), Registered: r.Registered, OverVLESS: r.OverVLESS, EntriesStale: stale}
			if r.Seen.IsValid() {
				f.Seen = r.Seen.String()
			}
			if r.Err != nil {
				f.Error, f.Detail = forwarderProblem(r.Err), r.Err.Error()
				if s.tunFwd == nil || s.tunFwd.Detail != f.Detail {
					s.logf("cbb: sync away from home: the forwarder at %v: %v", fw.Endpoint, r.Err)
				}
			} else if f.Seen != "" && (s.tunFwd == nil || s.tunFwd.Seen != f.Seen) {
				how := ""
				if r.OverVLESS {
					how = " over VLESS"
				}
				s.logf("cbb: sync away from home: registered with the forwarder at %v%s, which reaches this hub at %s", fw.Endpoint, how, f.Seen)
			}
			s.tunFwd = f
			if r.VLESS != nil && s.tunnel != nil && s.tunnel.Forwarder != nil && !s.tunnel.Forwarder.VLESS.Equal(r.VLESS) {
				s.vlessLearnedLocked(r.VLESS)
			}
		},
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		forward.Register(ctx, cfg)
	}()
}

// entriesStale reports whether a hub that could not register with fw
// (err) should be told its list of entry points is out of date: fw is the
// project's forwarder and this device holds no list that has not expired.
func (s *Service) entriesStale(fw *tunnel.ForwarderLink, err error) bool {
	return err != nil && fw.Project && s.heldEntries() == nil
}

// hubVLESS returns the ways the hub reaches its forwarder over VLESS when
// the forwarder's TCP port does not answer: what an earlier registration
// told it, then for the project's forwarder those of the signed entry
// points or the built-in one; none for a hub without VLESS, or with a
// forwarder of its own it has not reached yet.
func (s *Service) hubVLESS(fw *tunnel.ForwarderLink) []tunnel.VLESS {
	if fw.VLESSID == "" {
		return nil
	}
	var out []tunnel.VLESS
	s.tunMu.Lock()
	if st := s.tunnel; st != nil && st.Forwarder != nil && st.Forwarder.VLESS != nil {
		out = append(out, *st.Forwarder.VLESS)
	}
	s.tunMu.Unlock()
	if fw.Project {
		out = append(out, s.projectVLESS(fw.Endpoint.Addr())...)
	}
	return out
}

// projectPins returns the pins this device accepts from the project's
// forwarder: those of the keys.json of the newest release the group passed
// around, when it names any, else the built-in ones.
func (s *Service) projectPins() []string {
	var listed [][]byte
	if h := s.heldRelease(); h != nil {
		if k, err := release.VerifyKeys(h.set.Keys, s.releaseRoots(), s.cfg.now(), release.Seen{}); err == nil {
			listed = k.Forwarders(forward.ProjectHost)
		}
	}
	return forward.ProjectPins(listed)
}

// forwarderProblem is a short message for status of why the hub is not
// registered; the whole error goes to the log and to the detail.
func forwarderProblem(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused the registration"):
		return msg
	case strings.Contains(msg, "not the one given"):
		return "the forwarder's key is not the one given with -forwarder-key"
	case strings.HasPrefix(msg, "reaching the forwarder"):
		return "the forwarder could not be reached"
	}
	return "the registration with the forwarder failed"
}

// vlessLearnedLocked keeps the forwarder's VLESS settings the hub learned
// as it registered, and has the members connect again, so that each gets
// the offer with them.
func (s *Service) vlessLearnedLocked(v *tunnel.VLESS) {
	st := s.tunnel
	old := st.Forwarder.VLESS
	st.Forwarder.VLESS = v
	if err := st.Save(s.cfg.StateDir); err != nil {
		st.Forwarder.VLESS = old
		s.logf("cbb: saving the tunnel state: %v", err)
		return
	}
	s.logf("cbb: sync away from home: the hub's clients come over VLESS to the forwarder's port %d", v.Endpoint.Port())
	go func() {
		s.mu.Lock()
		nd := s.nd
		s.mu.Unlock()
		if nd != nil {
			nd.Reconnect()
		}
	}()
}

// forwarderAuthority is what a hub shows its forwarder that it may register
// the group: the key of its root or admin CA, that admin CA, and the
// group's authority records.
func (s *Service) forwarderAuthority() (crypto.Signer, *x509.Certificate, []group.Record) {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil {
		return nil, nil, nil
	}
	ca, chain := id.Signer()
	if ca == nil {
		return nil, nil, nil
	}
	var admin *x509.Certificate
	if len(chain) > 0 {
		admin = chain[0]
	}
	return ca.Key, admin, s.authorityRecords()
}

// authorityRecords returns the group's authority records for its
// forwarder or relay.
func (s *Service) authorityRecords() []group.Record {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	return s.records.AuthorityRecords()
}
