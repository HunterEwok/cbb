// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/benchtime"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/invite"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
)

// Remote invitations (docs/design.md, "Joining from another network"): the
// hub makes a one-time guest key that reaches only the pairing inside its
// tunnel, and a pairing window on a 128-bit secret whose admin confirms the
// device before it is admitted. The new device pairs through the guest
// tunnel, then offers its own tunnel key through it as a member, and from
// then on reaches the hub as an ordinary client.

const (
	// confirmWait is how long the hub waits for the admin to confirm a
	// device that used an invitation.
	confirmWait = 5 * time.Minute
	// guestGrace is how long a guest tunnel stays at most after its device
	// was admitted, for the device's first member connection, in which it
	// offers its own tunnel key. Once the hub answered that offer, the guest
	// goes as soon as that connection ends.
	guestGrace = 2 * time.Minute
	// failGrace is how long a guest tunnel stays after its invitation
	// ended without a device, for the last answer to reach the device. The
	// window is closed by then: the guest can pair no more.
	failGrace = 10 * time.Second
)

// guest is the guest tunnel of an open invitation, on the hub.
type guest struct {
	peer     tunnel.Peer
	w        *pair.Window
	admitted group.DeviceID // the device the window admitted; "" until then
	offered  bool           // the hub answered the admitted device's tunnel key
}

// hubPeerListLocked returns the hub's WireGuard peers: the clients the
// state admits, and the guests.
func (s *Service) hubPeerListLocked() []tunnel.Peer {
	peers := s.tunnel.Peers()
	for _, g := range s.guests {
		peers = append(peers, g.peer)
	}
	return peers
}

// dropGuest forgets a guest tunnel: its packets are dropped from then on.
func (s *Service) dropGuest(addr netip.Addr) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if _, ok := s.guests[addr]; !ok {
		return
	}
	delete(s.guests, addr)
	if s.tunnel != nil {
		s.hubPeersLocked()
	}
}

// invite makes a remote invitation on the hub and answers with its text,
// then asks the client to confirm the device that uses it, and reports how
// it ended. A client that hangs up cancels the invitation.
func (s *Service) invite(ctx context.Context, c net.Conn, r *control.Reader, m *control.Message) {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil {
		fail(c, s.errNoGroup())
		return
	}
	if !id.IsAdmin() {
		fail(c, s.errNotAdmitter())
		return
	}
	lifetime := invite.DefaultLifetime
	if m.Expires > 0 {
		lifetime = time.Duration(m.Expires) * time.Second
	}
	if lifetime > invite.MaxLifetime {
		fail(c, fmt.Errorf("an invitation is valid for %v at most", invite.MaxLifetime))
		return
	}

	in := &invite.Invitation{Group: group.Tag(id.GroupCA.Cert), Hub: string(id.ID), Expires: time.Now().Add(lifetime).Truncate(time.Second),
		Secret: make([]byte, pair.MinSecret)}
	rand.Read(in.Secret)
	var err error
	if in.GuestKey, err = tunnel.NewPrivateKey(); err == nil {
		in.GuestPSK, err = tunnel.NewPresharedKey()
	}
	if err != nil {
		fail(c, err)
		return
	}

	// The client's answers, and its hang-up.
	answers, hangup := make(chan bool, 1), make(chan struct{})
	go func() {
		defer close(hangup)
		for {
			a, err := r.Read()
			if err != nil {
				return
			}
			if a.Op == control.OpAnswer {
				select {
				case answers <- a.Consent:
				default:
				}
			}
		}
	}()
	var writeMu sync.Mutex
	confirm := func(ctx context.Context, req pair.Request) error {
		writeMu.Lock()
		err := reply(c, control.Header{Joining: &control.Joining{ID: string(req.Device), Name: req.Info.Name, OS: req.Info.OS, Fingerprint: req.Fingerprint}}, nil)
		writeMu.Unlock()
		if err != nil {
			return err
		}
		select {
		case yes := <-answers:
			if !yes {
				s.logf("cbb: the admin did not confirm %s (%s), which used an invitation", req.Info.Name, req.Device)
				return pair.ErrDeclined
			}
			return nil
		case <-hangup:
			return errors.New("the admin left")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	w, err := pair.Open(id, "", pair.Options{Now: benchtime.Now, Records: s.pathRecords, ClaimTimes: s.claimTimes, Taken: s.idTaken, Secret: in.Secret, Lifetime: lifetime, Confirm: confirm, ConfirmWait: confirmWait})
	if err != nil {
		fail(c, err)
		return
	}
	defer w.Close()
	addr := tunnel.GuestAddr(in.GuestKey.Public())
	g := &guest{peer: tunnel.Peer{PublicKey: in.GuestKey.Public(), PresharedKey: in.GuestPSK, Addr: addr}, w: w}

	s.tunMu.Lock()
	st, run := s.tunnel, s.tunRun
	switch {
	case st == nil || !st.IsHub:
		err = errors.New("invitations come from the group's hub, and this computer is not the hub; make it the hub with cbb global hub, or invite on the hub")
	case len(st.HubEndpoints()) == 0:
		err = errors.New("the hub has no address away from home yet; run cbb global hub with its addresses or a forwarder there")
	case run == nil || run.hub == nil:
		err = fmt.Errorf("the hub's tunnel is not running: %s", s.tunErr)
	default:
		in.HubKey, in.Endpoints, in.Obfuscation = st.ServingKey().Public(), st.HubEndpoints(), st.Obfuscation
		if s.guests == nil {
			s.guests = map[netip.Addr]*guest{}
		}
		s.guests[addr] = g
		s.hubPeersLocked()
	}
	s.tunMu.Unlock()
	if err != nil {
		fail(c, err)
		return
	}
	s.logf("cbb: an invitation is open until %s", in.Expires.Format(time.RFC3339))

	writeMu.Lock()
	err = reply(c, control.Header{Invite: in.String(), Expires: int(lifetime / time.Second)}, nil)
	writeMu.Unlock()
	if err == nil {
		select {
		case <-w.Done():
		case <-hangup:
		case <-ctx.Done():
		}
	}
	w.Close()
	res, err := s.windowResult(w)
	if err != nil {
		// The attempt that closed the window, the third that failed, still
		// sends the device its answer through the guest tunnel: the guest
		// goes a little later, or the device waits minutes for nothing.
		time.AfterFunc(failGrace, func() { s.dropGuest(addr) })
		s.logf("cbb: the invitation ended: %v", err)
		writeMu.Lock()
		fail(c, err)
		writeMu.Unlock()
		return
	}
	// The device makes its first member connection through the guest
	// tunnel, to offer its own key; then the guest goes.
	s.tunMu.Lock()
	g.admitted = res.Device
	s.tunMu.Unlock()
	time.AfterFunc(guestGrace, func() { s.dropGuest(addr) })
	writeMu.Lock()
	reply(c, control.Header{Name: res.Info.Name, Done: true}, nil)
	writeMu.Unlock()
}

// serveGuest serves, on the hub, a connection through a guest tunnel:
// the pairing of its invitation, and once that admitted a device, that
// device's member connection, nothing else.
func (s *Service) serveGuest(ctx context.Context, raw net.Conn, from netip.Addr, release func()) {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	s.tunMu.Lock()
	g := s.guests[from]
	var admitted group.DeviceID
	if g != nil {
		admitted = g.admitted
	}
	s.tunMu.Unlock()
	if g == nil || id == nil || nd == nil {
		release()
		raw.Close()
		return
	}
	cfg := &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if slices.Contains(hello.SupportedProtos, pair.Protocol) {
			// Once the invitation was used its window is closed, and
			// says so to a second device, which a failed handshake would
			// not.
			return g.w.ServerTLS(), nil
		}
		return nd.ServerTLS(), nil
	}}
	tc := tls.Server(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	release()
	if err != nil {
		raw.Close()
		return
	}
	switch tc.ConnectionState().NegotiatedProtocol {
	case pair.Protocol:
		if err := g.w.Serve(ctx, tc); err != nil {
			s.logf("cbb: a pairing attempt with an invitation: %v", err)
		}
	case group.MemberProtocol:
		peer, err := group.PeerID(tc.ConnectionState())
		if err != nil || admitted == "" || peer != admitted {
			s.logf("cbb: a member connection through a guest tunnel is not from the device it admitted; closed")
			raw.Close()
			return
		}
		if err := nd.Serve(ctx, tc); err != nil && ctx.Err() == nil {
			s.logEnd(err, "cbb: connection from %s through its guest tunnel: %v", peer, err)
		}
		// The device reaches the hub with its own key from now on.
		s.tunMu.Lock()
		offered := g.offered
		s.tunMu.Unlock()
		if offered {
			s.dropGuest(from)
		}
	default:
		raw.Close()
	}
}

// joinInvite joins the group of a remote invitation: through the guest
// tunnel to the hub, with the invitation's secret, once the hub's admin
// confirmed the device. Sync away from home is then on, with the consent
// the client asked for, and the device offers its own tunnel key to the hub
// through the guest tunnel. after runs once the join ended: with started
// when the group started.
func (s *Service) joinInvite(ctx context.Context, c net.Conn, j *pair.Joiner, m *control.Message) (id *group.Identity, after func(started bool), err error) {
	in, err := invite.Parse(m.Invite)
	if err != nil {
		return nil, nil, err
	}
	if time.Now().After(in.Expires) {
		return nil, nil, fmt.Errorf("the invitation expired at %s; ask for a new one", in.Expires.Format(time.RFC3339))
	}
	if keysInFile && !m.Consent {
		return nil, nil, errors.New("a device that joins with an invitation syncs away from home, and this one keeps its keys in files, so it needs your consent; run cbb pair -invite and read what it says")
	}
	fp, err := j.Fingerprint()
	if err != nil {
		return nil, nil, err
	}
	// The admin compares this with what the hub shows.
	if err := reply(c, control.Header{Fingerprint: fp}, nil); err != nil {
		return nil, nil, err
	}
	hubAddr, err := tunnel.Addr(in.Hub)
	if err != nil {
		return nil, nil, err
	}
	gc, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: in.GuestKey, PresharedKey: in.GuestPSK, Addr: tunnel.GuestAddr(in.GuestKey.Public()),
		HubPublicKey: in.HubKey, HubAddr: hubAddr, Endpoint: in.Endpoints[0], Obfuscation: in.Obfuscation,
		Logf: s.logf, Verbose: tunnelVerbose()})
	if err != nil {
		return nil, nil, fmt.Errorf("the tunnel to the hub could not start: %w", err)
	}
	var raw net.Conn
	for _, ep := range in.Endpoints {
		if err = gc.SetEndpoint(ep); err != nil {
			break
		}
		dctx, cancel := context.WithTimeout(ctx, 2*handshakeTimeout)
		raw, err = gc.Dial(dctx)
		cancel()
		if err == nil || ctx.Err() != nil {
			break
		}
		s.logf("cbb: the hub did not answer at %v: %v", ep, err)
	}
	if err != nil {
		gc.Close()
		return nil, nil, fmt.Errorf("the hub did not answer; check that the invitation is still valid, that the hub is on, and that its UDP port or its forwarder can be reached: %w", err)
	}
	id, err = j.JoinSecret(ctx, raw, in.Secret, confirmWait, s.saveJoined(j))
	if err != nil {
		gc.Close()
		if errors.Is(err, pair.ErrDeclined) {
			return nil, nil, errors.New("the admin did not confirm this device")
		}
		return nil, nil, err
	}
	// After the group started: turn sync away from home on, and offer the
	// key through the guest tunnel until the hub's offer comes back.
	after = func(started bool) {
		if !started {
			gc.Close()
			return
		}
		s.mu.Lock()
		nd := s.nd
		s.mu.Unlock()
		_, key, psk, err := s.awayLocked(&control.Message{Header: control.Header{Name: "on", Consent: true}}, group.Tag(id.GroupCA.Cert))
		if err != nil || nd == nil {
			s.logf("cbb: turning sync away from home on: %v", err)
			gc.Close()
			return
		}
		nd.SetTunnelKey(key, psk)
		hub := group.DeviceID(in.Hub)
		s.keepUntilHub(hub, "through the invitation's guest tunnel", func(ctx context.Context, nd *node.Node) error {
			dctx, cancel := context.WithTimeout(ctx, 2*handshakeTimeout)
			raw, err := gc.Dial(dctx)
			cancel()
			if err != nil {
				return err
			}
			return nd.DialConn(ctx, hub, raw)
		}, func() { gc.Close() })
	}
	return id, after, nil
}
