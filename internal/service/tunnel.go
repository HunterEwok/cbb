// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/benchtime"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/netguard"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/relay"
	"github.com/HunterEwok/clipboardbridge/internal/tunnel"
	"github.com/HunterEwok/clipboardbridge/internal/vless"
)

// The tunnel keys travel inside the member protocol (docs/protocol.md,
// section 11): every member offers its WireGuard public key and its own
// preshared key in its hello, each of the group's hubs admits them and
// answers with its own key and its addresses, and the member keeps the
// offers (hubs.go). Since
// it happens only inside member TLS, a device gets into the tunnel only
// after it met the hub as a member, and only with the key that member sent.
// None of it happens on a device where the user has not turned sync away
// from home on.

// The WireGuard key is sealed by the TPM where new member keys go into it.
func init() { tunnel.KeySealer = group.Sealer{} }

// loadTunnel reads the tunnel state for the group of id. Sync away from
// home is off until the user turns it on, which writes the state file; until
// then, or when the state cannot be read, the member offers no tunnel key and
// keeps no offer: it syncs at home only.
func (s *Service) loadTunnel(id *group.Identity) *tunnel.State {
	if _, err := os.Stat(filepath.Join(s.cfg.StateDir, tunnel.StateFile)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	st, err := tunnel.LoadState(s.cfg.StateDir)
	if err != nil {
		s.logf("cbb: sync away from home is off: %v", err)
		return nil
	}
	tag := group.Tag(id.GroupCA.Cert)
	if st.Group != "" && st.Group != tag {
		// It was turned on for another group; this one has to ask again.
		if err := os.Remove(filepath.Join(s.cfg.StateDir, tunnel.StateFile)); err != nil {
			s.logf("cbb: sync away from home is off: %v", err)
		} else {
			s.logf("cbb: sync away from home is off, since this device is in another group now")
		}
		return nil
	}
	if st.ForGroup(tag) {
		if err := st.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: sync away from home is off: %v", err)
			return nil
		}
	}
	return st
}

// tunnelKey returns this member's WireGuard public key and preshared key
// for its hello; nil when the tunnel state could not be read.
func tunnelKey(st *tunnel.State) (key, psk []byte) {
	if st == nil {
		return nil, nil
	}
	k := st.Key.Public()
	return k[:], st.PSK[:]
}

// tunnelKeyOffered admits the tunnel key and preshared key a peer offered,
// if this member is one of the group's hubs, and returns the offers for the
// peer: its own and those of the other hubs it passes on.
func (s *Service) tunnelKeyOffered(peer group.DeviceID, chain []*x509.Certificate, key, psk []byte) []node.TunnelOffer {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil || !st.IsHub {
		return nil
	}
	var pub, own tunnel.Key
	if len(key) != len(pub) || len(psk) != 0 && len(psk) != len(own) {
		s.logf("cbb: %s offered a tunnel key of %d bytes and a preshared key of %d", peer, len(key), len(psk))
		return nil
	}
	copy(pub[:], key)
	copy(own[:], psk)
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	m, changed, err := st.Admit(string(peer), pub, own, ders)
	if err != nil {
		s.logf("cbb: admitting the tunnel key of %s: %v", peer, err)
		return nil
	}
	if changed {
		if err := st.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the tunnel state: %v", err)
			return nil
		}
		s.logf("cbb: %s can reach this hub away from home", peer)
		s.hubPeersLocked()
		// The other hubs take this hub's clients from what it shares,
		// sent when they met; a client admitted since is shared now, so
		// that it reaches them when this hub is off.
		s.shareLocked()
	}
	offers := s.hubOffersLocked(st, peer, m.PresharedKey[:])
	if offers == nil {
		return nil
	}
	for _, g := range s.guests {
		if g.admitted == peer {
			g.offered = true
		}
	}
	return offers
}

// hubOfferLocked returns the offer of the hub whose state st is, with the
// preshared key psk (none in a hub command's result); nil while the offers
// wait for the forwarder's VLESS settings.
func (s *Service) hubOfferLocked(st *tunnel.State, psk []byte) *node.TunnelOffer {
	hub := st.ServingKey().Public()
	o := &node.TunnelOffer{HubKey: hub[:], PSK: psk}
	if !st.Next.IsZero() {
		next := st.Next.Public()
		o.NextKey = next[:]
	}
	for _, ep := range st.HubEndpoints() {
		o.Endpoints = append(o.Endpoints, ep.String())
	}
	var err error
	if st.Obfuscation != nil {
		if o.Obfuscation, err = json.Marshal(st.Obfuscation); err != nil {
			s.logf("cbb: the tunnel's obfuscation settings: %v", err)
			return nil
		}
	}
	if fw := st.Forwarder; fw != nil && fw.VLESSID != "" {
		if fw.VLESS == nil {
			// The clients may come only over VLESS, whose settings come
			// with the forwarder's answer; the offer waits for them.
			return nil
		}
		if o.VLESS, err = json.Marshal(fw.VLESS); err != nil {
			s.logf("cbb: the tunnel's VLESS settings: %v", err)
			return nil
		}
	}
	return o
}

// hubKeyAhead is how long before a hub serves with its key for a new
// period of the group's server credentials its offers give its clients
// that key.
var hubKeyAhead = benchtime.D(3 * 24 * time.Hour)

// rotateHubKey gives the hub a new WireGuard key for its clients in each
// period of the group's server credentials (docs/protocol.md, section 11,
// "The hub's key"): when a period starts, the next key, which its offers
// carry from then on, and hubKeyAhead later that key in place of the old
// one, with which the hub starts again and registers again on its
// forwarder.
func (s *Service) rotateHubKey() {
	var period string
	s.recMu.Lock()
	if s.creds != nil && s.records != nil {
		if _, p, ok := s.creds.Period(s.currentRootLocked()); ok {
			period = p.Tag
		}
	}
	s.recMu.Unlock()
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil || !st.IsHub {
		return
	}
	changed, switched, err := st.Rotate(period, s.cfg.now(), hubKeyAhead)
	if err != nil {
		s.logf("cbb: making the hub's key for the new period: %v", err)
	}
	if !changed {
		return
	}
	// The tunnel starts again with the new key before the state says so,
	// so a state on disk never names a key the hub does not serve with
	// yet; a hub that stops in between switches again at its next check.
	if switched && s.tunServing {
		s.logf("cbb: the hub serves with its key for the new period from now on")
		s.stopTunnelLocked()
		s.runTunnelLocked()
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		s.logf("cbb: saving the tunnel state: %v", err)
		return
	}
	s.sendOffersLocked()
	s.shareLocked()
}

// sendOffersLocked sends the hub's offer again to its clients that are
// connected, after it changed.
func (s *Service) sendOffersLocked() {
	st := s.tunnel
	psks := map[group.DeviceID][]byte{}
	for _, m := range st.Members {
		psks[group.DeviceID(m.Device)] = m.PresharedKey[:]
	}
	o := s.hubOfferLocked(st, nil)
	if o == nil {
		return
	}
	go func() {
		s.mu.Lock()
		nd := s.nd
		s.mu.Unlock()
		if nd == nil {
			return
		}
		nd.SendTunnel(func(dev group.DeviceID) *node.TunnelOffer {
			psk, ok := psks[dev]
			if !ok {
				return nil
			}
			c := *o
			c.PSK = psk
			return &c
		})
	}()
}

// tunnelOffered keeps an offer for this member's key: the sender's own,
// or that of another of the group's hubs the sender passes on. Only the
// group's root or an admin can be a hub, and only one may pass an offer on.
// One passed on when the sender moved the hub elsewhere (Moved) makes this
// member forget the sender's own. A hub above the one this member uses is
// tried at once.
func (s *Service) tunnelOffered(from group.DeviceID, chain []*x509.Certificate, o node.TunnelOffer) error {
	if !s.adminPeer(from, chain) {
		return errors.New("only the group's root or an admin can be its hub; the offer is ignored")
	}
	hub := from
	if o.Hub != "" {
		if !s.mayHost(o.Hub) {
			return fmt.Errorf("%s passed on the offer of %s, which is not the group's root or an admin; the offer is ignored", from, o.Hub)
		}
		hub = o.Hub
	}
	order := s.hubOrder()
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil {
		return errors.New("the tunnel is off on this device")
	}
	if string(hub) == s.tunSelf {
		return nil // this hub's own offer, passed on by another hub
	}
	if st.Relay != nil {
		return errors.New("this device meets the others at its relay, but the group has a hub too")
	}
	h, err := hubLink(hub, o)
	if err != nil {
		return err
	}
	forgot := o.Moved && len(st.ForgetHubs(func(k tunnel.HubLink) bool { return k.Device != string(from) })) > 0
	var prev tunnel.HubLink
	p := st.Hub(string(hub))
	old := p != nil
	if old {
		prev = *p
	}
	changed, err := st.SetHub(h)
	if err != nil {
		return err
	}
	if !changed && !forgot {
		return nil
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		return fmt.Errorf("saving the tunnel state: %w", err)
	}
	if forgot {
		s.logf("cbb: %s is no hub any more; the group's hub is %s", from, hub)
	} else if !old {
		s.logf("cbb: %s is one of the group's hubs for sync away from home", hub)
	}
	s.guardLocked()
	r := rankOf(order, string(hub))
	switch {
	case st.IsHub && s.tunServing:
		if r < rankOf(order, s.tunSelf) {
			s.giveWayLocked(hub, &o)
		}
	case old && !forgot && s.tunThrough && s.tunUsing == string(hub) && s.tunRun != nil && s.tunRun.hubKey == h.PublicKey && sameWay(prev, h):
		// The link up is already through the hub's new key, its next one
		// until now: it stays up, and the next try takes the new offer.
		// Starting it again at once would also cost a handshake that the
		// hub refuses as too soon after the last one, and five seconds.
	case s.tunUsing == "" || s.tunUsing == string(hub) || r < rankOf(order, s.tunUsing) || forgot && s.tunUsing == string(from):
		// The hub in use changed, or one above it came: try again.
		s.stopTunnelLocked()
		s.runTunnelLocked()
	}
	return nil
}

// sameWay tells whether two offers of a hub reach it the same way, apart
// from its keys.
func sameWay(a, b tunnel.HubLink) bool {
	return a.PresharedKey == b.PresharedKey && slices.Equal(a.Endpoints, b.Endpoints) &&
		a.Obfuscation.Equal(b.Obfuscation) && a.VLESS.Equal(b.VLESS)
}

// hubLink is what a client keeps of the offer o of the hub hub.
func hubLink(hub group.DeviceID, o node.TunnelOffer) (tunnel.HubLink, error) {
	h := tunnel.HubLink{Device: string(hub)}
	if len(o.HubKey) != len(h.PublicKey) || len(o.PSK) != len(h.PresharedKey) {
		return h, errors.New("the keys are not 32 bytes")
	}
	copy(h.PublicKey[:], o.HubKey)
	copy(h.PresharedKey[:], o.PSK)
	switch len(o.NextKey) {
	case 0:
	case len(h.Next):
		copy(h.Next[:], o.NextKey)
	default:
		return h, errors.New("the next key is not 32 bytes")
	}
	for _, e := range o.Endpoints {
		ep, err := netip.ParseAddrPort(e)
		if err != nil {
			return h, fmt.Errorf("a bad endpoint: %w", err)
		}
		h.Endpoints = append(h.Endpoints, ep)
	}
	if len(o.Obfuscation) > 0 {
		h.Obfuscation = new(tunnel.Obfuscation)
		if err := json.Unmarshal(o.Obfuscation, h.Obfuscation); err != nil {
			return h, fmt.Errorf("bad obfuscation settings: %w", err)
		}
	}
	if len(o.VLESS) > 0 {
		h.VLESS = new(tunnel.VLESS)
		if err := json.Unmarshal(o.VLESS, h.VLESS); err != nil {
			return h, fmt.Errorf("bad VLESS settings: %w", err)
		}
	}
	return h, nil
}

// mayHost reports whether the records make dev the group's root or an
// admin, which may be its hub.
func (s *Service) mayHost(dev group.DeviceID) bool {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	return s.records != nil && s.records.MayHost(dev)
}

// pruneTunnel forgets, on the hub, the members the records now refuse.
func (s *Service) pruneTunnel() {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil {
		return
	}
	if lost := st.ForgetHubs(func(h tunnel.HubLink) bool { return s.mayHost(group.DeviceID(h.Device)) }); len(lost) > 0 {
		for _, d := range lost {
			s.logf("cbb: %s is no longer the group's root or an admin; its offer as a hub is forgotten", d)
		}
		if err := st.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the tunnel state: %v", err)
		}
		if slices.Contains(lost, s.tunUsing) {
			s.stopTunnelLocked()
			s.runTunnelLocked()
		}
	}
	if len(st.Members) == 0 {
		return
	}
	gone := st.Prune(func(m tunnel.Member) bool {
		if len(m.Chain) == 0 {
			// Handed over by the old hub, not met yet: kept while the
			// records list the device.
			return s.listed(group.DeviceID(m.Device))
		}
		chain := make([]*x509.Certificate, 0, len(m.Chain))
		for _, der := range m.Chain {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return false
			}
			chain = append(chain, c)
		}
		return s.allow(group.DeviceID(m.Device), chain) == nil
	})
	if len(gone) == 0 {
		return
	}
	for _, d := range gone {
		s.logf("cbb: %s was removed from the group; the hub drops its tunnel", d)
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		s.logf("cbb: saving the tunnel state: %v", err)
	}
	s.hubPeersLocked()
}

// awayCheck is how often a member that is not reaching its hub through
// the tunnel looks again whether it has to: while the hub is on the home
// network, it syncs there without the tunnel.
const awayCheck = 5 * time.Second

// tunRun is the tunnel at work: the hub, or this member's link to it.
type tunRun struct {
	cancel  context.CancelFunc
	hub     *tunnel.Hub
	clients []*tunnel.Client // the link to the hub: one for each of its keys
	hubKey  tunnel.Key       // the hub's key of the link while it is up
	vless   *vless.Client    // the client's way to the hub's forwarder over VLESS
}

// guardLocked lets the service reach the group's hub, forwarder and relay
// on the internet while sync away from home is on, and nothing else beyond
// the home network (internal/netguard).
func (s *Service) guardLocked() {
	var dests []netip.Addr
	if st := s.tunnel; st != nil {
		dests = st.Destinations()
	}
	netguard.Set(s.tunnel != nil, dests)
}

// runTunnelLocked starts the tunnel the state asks for: the hub, or the
// link to the hub once the hub offered it. It fails closed: when the tunnel
// cannot start, the member syncs at home only and status says why.
func (s *Service) runTunnelLocked() {
	s.guardLocked()
	st, gctx := s.tunnel, s.tunCtx
	if st == nil || gctx == nil || s.tunRun != nil {
		return
	}
	self, err := tunnel.Addr(s.tunSelf)
	if err != nil {
		s.tunFailedLocked("this device has no tunnel address", err)
		return
	}
	ctx, cancel := context.WithCancel(gctx)
	if st.IsHub && !s.tunServing && len(hubsToTry(s.hubOrder(), s.tunSelf, st)) == 0 {
		s.tunServing = true // no hub above this one
	}
	switch {
	case st.IsHub && s.tunServing:
		port := st.ListenPort
		if port == 0 {
			port = tunnel.Port
		}
		h, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: st.ServingKey(), Addr: self, ListenPort: port, Peers: s.hubPeerListLocked(),
			Obfuscation: st.Obfuscation, Logf: s.logf, Verbose: tunnelVerbose()})
		if err != nil {
			cancel()
			s.tunFailedLocked(fmt.Sprintf("the hub could not listen on UDP port %d", port), err)
			return
		}
		s.tunRun = &tunRun{cancel: cancel, hub: h}
		s.tunFailedLocked("", nil)
		s.registerForwarderLocked(ctx, h, st)
		s.wg.Add(2)
		go func() {
			defer s.wg.Done()
			s.acceptTunnel(ctx, h.Listener())
		}()
		go func() {
			defer s.wg.Done()
			s.recheckHubs(ctx)
		}()
	case st.Relay != nil:
		run := &tunRun{cancel: cancel}
		s.tunRun = run
		s.tunFailedLocked("", nil)
		s.joinRelayLocked(ctx, run, *st.Relay, st.Key)
	case len(st.Hubs) > 0 || st.IsHub:
		// A client, or a hub that tries the hubs above it first.
		run := &tunRun{cancel: cancel}
		s.tunRun = run
		s.tunFailedLocked("", nil)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.reachHubs(ctx, run, st.IsHub)
		}()
	default:
		cancel() // waits for the hub's offer, which comes at home
	}
}

// stopTunnelLocked stops the hub or the link to it, with every connection
// through it.
func (s *Service) stopTunnelLocked() {
	r := s.tunRun
	if r == nil {
		return
	}
	s.tunRun, s.tunThrough, s.tunUsing, s.tunFwd, s.tunRelay, s.tunRelayed = nil, false, "", nil, nil, 0
	r.cancel()
	if r.hub != nil {
		r.hub.Close()
	}
	for _, c := range r.clients {
		c.Close()
	}
	if r.vless != nil {
		r.vless.Close()
	}
}

// tunFailedLocked keeps what went wrong for status, and logs it; an empty
// msg clears it.
func (s *Service) tunFailedLocked(msg string, err error) {
	s.tunErr, s.tunDetail = msg, ""
	if err != nil {
		s.tunDetail = err.Error()
	}
	if msg != "" {
		if err != nil {
			s.logf("cbb: sync away from home: %s: %v", msg, err)
		} else {
			s.logf("cbb: sync away from home: %s", msg)
		}
	}
}

// hubPeersLocked gives the running hub the clients the state admits now,
// and the guests of open invitations.
func (s *Service) hubPeersLocked() {
	if r := s.tunRun; r != nil && r.hub != nil {
		if err := r.hub.SetPeers(s.hubPeerListLocked()); err != nil {
			s.tunFailedLocked("the hub could not take its clients", err)
		}
	}
}

// acceptTunnel serves, on the hub, the member connections that come through
// the tunnel: the member protocol only, from the device whose WireGuard key
// the connection came with.
func (s *Service) acceptTunnel(ctx context.Context, ln net.Listener) {
	slots := make(chan struct{}, maxHandshakes)
	acceptLoop(ctx, ln, s.logf, "the tunnel", func(raw net.Conn) {
		select {
		case slots <- struct{}{}:
		default:
			raw.Close()
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveTunnelMember(ctx, raw, func() { <-slots })
		}()
	})
}

func (s *Service) serveTunnelMember(ctx context.Context, raw net.Conn, release func()) {
	from, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
	if tunnel.IsGuest(from.Addr()) {
		s.serveGuest(ctx, raw, from.Addr(), release)
		return
	}
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		release()
		raw.Close()
		return
	}
	tc := tls.Server(raw, nd.ServerTLS())
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	release()
	if err != nil {
		raw.Close()
		return
	}
	id, err := group.PeerID(tc.ConnectionState())
	if want, aerr := tunnel.Addr(string(id)); err != nil || aerr != nil || from.Addr() != want {
		s.logf("cbb: a member connection through the tunnel from %v is not from the device of that key; closed", from.Addr())
		raw.Close()
		return
	}
	if err := nd.Serve(ctx, tc); err != nil && ctx.Err() == nil {
		s.logEnd(err, "cbb: connection from %s through the tunnel: %v", id, err)
	}
}

// phoneHubWait is the longest wait between tries of a hub that is a phone,
// there only while its app is open (design.md, "The phone as the hub"): a
// try costs one handshake initiation, which the forwarder drops while the
// phone is not registered.
const phoneHubWait = 5 * time.Second

// hubWait is the longest wait between tries of the hub: short for a phone,
// which comes and goes, and maxBackoff for any other.
func (s *Service) hubWait(hub group.DeviceID) time.Duration {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return maxBackoff
	}
	for _, d := range s.records.Devices() {
		if d.ID == hub && d.Role == group.RolePhone {
			return phoneHubWait
		}
	}
	return maxBackoff
}

// tunnelVerbose tells whether the service logs WireGuard's own messages too:
// only with CBB_DEBUG=1 in its environment, since they come every few
// seconds while a tunnel is up.
func tunnelVerbose() bool { return os.Getenv("CBB_DEBUG") == "1" }

// keysInFile tells whether this device keeps its keys in files, not in
// hardware; every computer does until the keys move to a TPM or a Secure
// Enclave (docs/roadmap.md, "Device keys in hardware").
const keysInFile = true

// away turns sync away from home on or off on this device, or makes it the
// group's hub (docs/design.md, "Turning it on, step by step").
func (s *Service) away(ctx context.Context, m *control.Message) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil {
		return s.errNoGroup()
	}
	if m.Name == "move" {
		return s.moveHub(ctx, m.Device, m.Forwarder, m.ForwarderKey, m.Addrs)
	}
	if m.Name == "off" && m.Device != "" {
		return s.awayOffOn(ctx, m.Device)
	}
	if m.Name == "hub" && !id.IsAdmin() {
		return errors.New("only the group's root or an admin can be its hub, since the members take the hub's offer from them only; make this device an admin first (cbb admin on the root)")
	}
	reconnect, key, psk, err := s.awayLocked(m, group.Tag(id.GroupCA.Cert))
	if err != nil {
		return err
	}
	if reconnect {
		// The members connect again, so their hellos carry the new key or
		// the hub's new offer.
		nd.SetTunnelKey(key, psk)
		nd.Reconnect()
	}
	return nil
}

func (s *Service) awayLocked(m *control.Message, tag string) (reconnect bool, key, psk []byte, err error) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	path := filepath.Join(s.cfg.StateDir, tunnel.StateFile)
	switch m.Name {
	case "on":
		if s.tunnel != nil {
			return false, nil, nil, nil
		}
		if keysInFile && !m.Consent {
			return false, nil, nil, errors.New("this device keeps its keys in files, so sync away from home needs your consent; run cbb global on and read what it says")
		}
		st, err := s.awayOnLocked(tag)
		if err != nil {
			return false, nil, nil, err
		}
		k, p := tunnelKey(st)
		return true, k, p, nil
	case "off":
		if s.tunnel == nil {
			return false, nil, nil, nil
		}
		s.stopTunnelLocked()
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, nil, nil, err
		}
		s.tunnel = nil
		s.guardLocked()
		s.tunFailedLocked("", nil)
		s.logf("cbb: sync away from home is off; its keys are gone")
		return true, nil, nil, nil
	case "hub":
		st := s.tunnel
		if st == nil {
			return false, nil, nil, errors.New("sync away from home is off here; turn it on first: cbb global on")
		}
		if m.Port < 0 || m.Port > 65535 {
			return false, nil, nil, fmt.Errorf("a bad port %d", m.Port)
		}
		fw, eps, err := hubAddrs(m.Forwarder, m.ForwarderKey, m.Addrs)
		if err != nil {
			return false, nil, nil, err
		}
		if m.VLESS {
			if fw == nil {
				return false, nil, nil, errors.New("VLESS goes to a forwarder; give one with -forwarder and -forwarder-key")
			}
			// The group keeps its ID, and the forwarder's settings while
			// the forwarder stays the same.
			if old := st.Forwarder; old != nil && old.VLESSID != "" {
				fw.VLESSID = old.VLESSID
				if old.Endpoint == fw.Endpoint && old.Pin == fw.Pin {
					fw.VLESS = old.VLESS
				}
			} else if fw.VLESSID, err = tunnel.NewVLESSID(); err != nil {
				return false, nil, nil, err
			}
		}
		obf := st.Obfuscation
		switch {
		case !m.Obfuscate:
			obf = nil
		case obf == nil:
			// Kept as they are when the hub is set again, so its clients'
			// offers stay good.
			if obf, err = tunnel.NewObfuscation(); err != nil {
				return false, nil, nil, err
			}
		}
		old := *st
		st.IsHub, st.Endpoints, st.ListenPort, st.Forwarder, st.Relay, st.Obfuscation = true, eps, m.Port, fw, nil, obf
		if err := st.Save(s.cfg.StateDir); err != nil {
			*st = old
			return false, nil, nil, fmt.Errorf("saving the tunnel state: %w", err)
		}
		s.tunServing = false // it tries the hubs above it first
		s.stopTunnelLocked()
		s.runTunnelLocked()
		s.logf("cbb: this device is one of the group's hubs for sync away from home")
		k, p := tunnelKey(st)
		return true, k, p, nil
	case "relay":
		ep, err := netip.ParseAddrPort(m.Relay)
		if err != nil || ep.Port() == 0 {
			return false, nil, nil, fmt.Errorf("%q is not the relay's address with a port, such as 203.0.113.9:8764", m.Relay)
		}
		if err := relay.CheckPin(m.RelayKey); err != nil {
			return false, nil, nil, err
		}
		// The relay learns who talks to whom, when and how much, which a
		// hub of the group's own would not let out: the user agrees first.
		if !m.Consent {
			return false, nil, nil, errors.New("a relay learns which devices of the group talk, when and how much, and their addresses; run cbb global relay and read what it says")
		}
		// Meeting at a relay is sync away from home: it turns it on, and
		// the consent covers the keys' warning that cbb global relay then
		// shows too.
		st := s.tunnel
		if st == nil {
			if st, err = s.awayOnLocked(tag); err != nil {
				return false, nil, nil, err
			}
		}
		old := *st
		*st = tunnel.State{Key: st.Key, PSK: st.PSK, Group: st.Group, KeysInFile: st.KeysInFile,
			Relay: &tunnel.RelayLink{Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), Pin: m.RelayKey}}
		if err := st.Save(s.cfg.StateDir); err != nil {
			*st = old
			return false, nil, nil, fmt.Errorf("saving the tunnel state: %w", err)
		}
		s.stopTunnelLocked()
		s.runTunnelLocked()
		s.logf("cbb: sync away from home goes through the relay at %v", st.Relay.Endpoint)
		k, p := tunnelKey(st)
		return true, k, p, nil
	}
	return false, nil, nil, fmt.Errorf("unknown away request %q", m.Name)
}

// awayOnLocked turns sync away from home on with new keys for the group
// with the given tag.
func (s *Service) awayOnLocked(tag string) (*tunnel.State, error) {
	st, err := tunnel.NewState()
	if err != nil {
		return nil, err
	}
	st.ForGroup(tag)
	st.KeysInFile = keysInFile
	if err := st.Save(s.cfg.StateDir); err != nil {
		return nil, fmt.Errorf("saving the tunnel state: %w", err)
	}
	s.tunnel = st
	s.guardLocked()
	s.logf("cbb: sync away from home is on")
	return st, nil
}

// awayStatus describes sync away from home for status; nil while it is
// off.
func (s *Service) awayStatus() *control.Away {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil {
		return nil
	}
	a := &control.Away{Hub: st.IsHub, KeysInFile: st.KeysInFile, Error: s.tunErr, Detail: s.tunDetail}
	for _, d := range st.Destinations() {
		a.Allow = append(a.Allow, d.String())
	}
	using := st.Hub(s.tunUsing)
	if using == nil && !st.IsHub {
		if hubs := hubsToTry(s.hubOrder(), s.tunSelf, st); len(hubs) > 0 {
			using = &hubs[0]
		}
	}
	if st.IsHub {
		a.Obfuscated = st.Obfuscation != nil
		a.VLESS = st.Forwarder != nil && st.Forwarder.VLESSID != ""
		a.Standby = !s.tunServing
	} else if using != nil {
		a.Obfuscated = using.Obfuscation != nil
		a.VLESS = using.VLESS != nil
	}
	if using != nil {
		a.HubDevice, a.Through = using.Device, s.tunThrough
	}
	if st.IsHub && st.Forwarder != nil {
		a.Forwarder = &control.Forwarder{Endpoint: st.Forwarder.Endpoint.String(), Error: "the hub is not running"}
		if f := s.tunFwd; f != nil {
			c := *f
			a.Forwarder = &c
		}
	}
	switch {
	case st.IsHub:
		a.Port, a.Clients = st.ListenPort, len(st.Members)
		if a.Port == 0 {
			a.Port = tunnel.Port
		}
		for _, ep := range st.Endpoints {
			a.Endpoints = append(a.Endpoints, ep.String())
		}
	case st.Relay != nil:
		a.Relay, a.Through = &control.Relay{Endpoint: st.Relay.Endpoint.String(), Error: "the link to the relay is not running"}, s.tunRelayed > 0
		if r := s.tunRelay; r != nil {
			c := *r
			c.Online = slices.Clone(r.Online)
			a.Relay = &c
		}
	case using != nil:
		for _, ep := range using.Endpoints {
			a.Endpoints = append(a.Endpoints, ep.String())
		}
	}
	return a
}

// awayOffOn serves cbb global off -on: it turns sync away from home
// off on the member target with a command this admin signs; only that
// device's own user turns it on again (D-45).
func (s *Service) awayOffOn(ctx context.Context, target string) error {
	d, err := s.findDevice(target)
	if err != nil {
		return err
	}
	if d.Self {
		return errors.New("-on names this device; cbb global off turns it off here")
	}
	return s.commandOn(ctx, d, group.CommandBody{Type: group.CommandAwayOff})
}

// awayOff carries out an away-off command: sync away from home goes off
// here and its keys go, as with cbb global off. The members connect again
// only after the result has gone back on the connection that brought it.
func (s *Service) awayOff(body group.CommandBody) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultDone}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	reconnect, _, _, err := s.awayLocked(&control.Message{Header: control.Header{Op: control.OpAway, Name: "off"}}, group.Tag(id.GroupCA.Cert))
	if err != nil {
		res.Status, res.Reason = node.ResultFailed, err.Error()
		return res
	}
	s.logf("cbb: %s turned sync away from home off here", body.By)
	if reconnect && nd != nil {
		// The result goes back first, on the connection that brought the
		// command, and then has a moment to be read.
		res.Written = make(chan struct{})
		go func() {
			select {
			case <-res.Written:
			case <-time.After(resultWait):
			}
			time.Sleep(restartAfter)
			nd.SetTunnelKey(nil, nil)
			nd.Reconnect()
		}()
	}
	return res
}
