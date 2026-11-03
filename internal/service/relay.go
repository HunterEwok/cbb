// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/relay"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// joinRelayLocked keeps this device registered with its blind relay until
// ctx is done, and connects it there to the other devices of its group that
// it does not reach another way (docs/design.md, "Blind relay"). The member
// protocol's TLS runs between the two devices; the relay passes only its
// ciphertext.
func (s *Service) joinRelayLocked(ctx context.Context, run *tunRun, link tunnel.RelayLink, key tunnel.Key) {
	s.tunRelay = &control.Relay{Endpoint: link.Endpoint.String()}
	s.tunRelayed = 0
	cfg := relay.MemberConfig{
		Link: relay.Link{Endpoint: link.Endpoint, Pin: link.Pin},
		Self: s.tunSelf,
		Key:  key,
		Cert: func() tls.Certificate {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.id == nil {
				return tls.Certificate{}
			}
			return s.id.ForwarderCertificate()
		},
		Records:            s.authorityRecords,
		Credentialed:       s.relayCredentials,
		CredentialsChanged: s.credentialsChanged,
		// The relay names a device by its ID, or by its pseudonym when the
		// device registered with the group's credentials.
		Want: func(peer string) bool {
			id, ok := s.relayPeer(peer)
			if !ok {
				return false
			}
			s.mu.Lock()
			nd, near := s.nd, s.nearLocked(id)
			s.mu.Unlock()
			return nd != nil && !near && !slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.ID == id })
		},
		Dialed: func(ctx context.Context, peer string, c net.Conn) error {
			nd := s.node()
			if nd == nil {
				return errNoNode
			}
			id, ok := s.relayPeer(peer)
			if !ok {
				return fmt.Errorf("no device of the group is %s", peer)
			}
			return nd.DialConn(ctx, id, c)
		},
		Called: func(ctx context.Context, peer string, c net.Conn) error {
			nd := s.node()
			if nd == nil {
				return errNoNode
			}
			want, ok := s.relayPeer(peer)
			if !ok {
				return fmt.Errorf("no device of the group is %s", peer)
			}
			// The relay says who calls; the member certificate must say
			// the same.
			cfg := nd.ServerTLS().Clone()
			check := cfg.VerifyConnection
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				if check != nil {
					if err := check(cs); err != nil {
						return err
					}
				}
				if id, err := group.PeerID(cs); err != nil || id != want {
					return fmt.Errorf("the relay said %s calls, but the certificate is another device's", peer)
				}
				return nil
			}
			return nd.Serve(ctx, tls.Server(c, cfg))
		},
		Report: func(r relay.Report) {
			// The names stay as the relay gives them: status maps the
			// pseudonyms to devices each time (relayNames), since the
			// credential that names a peer can come after the relay reports
			// it online.
			s.tunMu.Lock()
			defer s.tunMu.Unlock()
			if s.tunRun != run {
				return
			}
			st := &control.Relay{Endpoint: link.Endpoint.String(), Connected: r.Connected, Online: r.Online}
			if r.Err != nil {
				st.Error, st.Detail = relayProblem(r.Err), r.Err.Error()
				if s.tunRelay == nil || s.tunRelay.Detail != st.Detail {
					s.logf("cbb: sync away from home: the relay at %v: %v", link.Endpoint, r.Err)
				}
			} else if r.Connected && (s.tunRelay == nil || !s.tunRelay.Connected) {
				s.logf("cbb: sync away from home: connected to the relay at %v", link.Endpoint)
			}
			s.tunRelay, s.tunRelayed = st, r.Through
		},
		Logf:    s.logf,
		Verbose: tunnelVerbose(),
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		relay.Join(ctx, cfg)
	}()
}

var errNoNode = errors.New("this device is in no group")

// node returns the member node; nil while in no group.
func (s *Service) node() *node.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nd
}

// relayProblem is a short message for status of why the device is not
// connected to its relay; the whole error goes to the log and to the
// detail.
func relayProblem(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused the registration"):
		return msg
	case strings.Contains(msg, "not the one given"):
		return "the relay's key is not the one given with -key"
	case strings.HasPrefix(msg, "reaching the relay"):
		return "the relay could not be reached"
	case strings.Contains(msg, "tunnel does not answer"):
		return "the relay's tunnel does not answer; its UDP port may be blocked"
	}
	return "the connection to the relay failed"
}

// relayNames puts the devices in place of the pseudonyms in the relay's
// online list of a, those whose server credential this device has.
func (s *Service) relayNames(a *control.Away) {
	if a == nil || a.Relay == nil {
		return
	}
	for i, name := range a.Relay.Online {
		if id, ok := s.relayPeer(name); ok {
			a.Relay.Online[i] = string(id)
		}
	}
}
