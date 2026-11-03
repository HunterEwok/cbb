// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// Moving the hub (docs/protocol.md, section 11, "Moving the hub"): the
// group's hub, a phone or a computer, sends an admin computer a hub
// command with its clients' keys; the computer becomes the hub and answers
// with its offer; the old hub passes that offer on to each connected
// client with the client's own preshared key, and stops being the hub.

// moveGrace is the longest the old hub waits, after it passed on the new
// hub's offer, for the connections through its tunnel to the clients it
// passed the offer to to end: it closes each one after the offer and a
// goodbye. Then it keeps the tunnel for moveLinger, so that the last
// packets arrive, and stops it. A client that missed the offer would be
// left far from home with the old hub's only.
var moveGrace = 10 * time.Second

// moveLinger is how long the old hub keeps its tunnel after the connections
// through it ended.
var moveLinger = time.Second

// moveCheck is how often the old hub looks whether those connections ended.
const moveCheck = 50 * time.Millisecond

// listed reports whether the records list the device dev as a member.
func (s *Service) listed(dev group.DeviceID) bool {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return false
	}
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return true
		}
	}
	return false
}

// hubAddrs checks a hub's forwarder and addresses, as cbb global hub and a
// hub command give them.
func hubAddrs(fwd, fwdKey string, addrs []string, projectPins []string) (*tunnel.ForwarderLink, []netip.AddrPort, error) {
	var fw *tunnel.ForwarderLink
	if fwd != "" {
		ep, err := netip.ParseAddrPort(fwd)
		if err != nil || ep.Port() == 0 {
			return nil, nil, fmt.Errorf("%q is not the forwarder's address with a port, such as 203.0.113.9:8764", fwd)
		}
		if fwdKey == forward.ProjectKey {
			// The project's forwarder, at the address the command line
			// resolved: its pin is the first one this device accepts.
			fw = &tunnel.ForwarderLink{Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), Pin: projectPins[0], Project: true}
		} else if err := forward.CheckPin(fwdKey); err != nil {
			return nil, nil, err
		} else {
			// A pin of the project's forwarder, as a hub command from a
			// phone or another hub carries it, follows its key from then on.
			fw = &tunnel.ForwarderLink{Endpoint: netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), Pin: fwdKey, Project: slices.Contains(projectPins, fwdKey)}
		}
	} else if fwdKey != "" {
		return nil, nil, errors.New("a forwarder's key without its address")
	}
	var eps []netip.AddrPort
	for _, a := range addrs {
		ep, err := netip.ParseAddrPort(a)
		if err != nil || ep.Port() == 0 {
			return nil, nil, fmt.Errorf("%q is not an address with a port, such as 203.0.113.7:8764 or [2001:db8::7]:8764", a)
		}
		eps = append(eps, netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()))
	}
	if len(eps) > 7 || (fw == nil && len(eps) > 8) {
		return nil, nil, errors.New("at most 8 addresses, the forwarder's included")
	}
	if len(eps) == 0 && fw == nil {
		return nil, nil, errors.New("the hub needs an address away from home or a forwarder")
	}
	return fw, eps, nil
}

// takeHub carries out a hub command: this computer, an admin with sync
// away from home on, becomes the group's hub with the forwarder and the
// addresses the command gives, and takes the old hub's clients whose
// devices the records list. Its result carries this hub's offer.
func (s *Service) takeHub(body group.CommandBody) node.Result {
	res := node.Result{ID: body.ID}
	refuse := func(status, why string) node.Result {
		s.logf("cbb: did not become the hub, as %s asked: %s", body.By, why)
		res.Status, res.Reason = status, why
		return res
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if !id.IsAdmin() {
		return refuse(node.ResultRefused, "this computer is no admin, and only the group's root or an admin can be its hub; make it an admin first")
	}
	o := body.Hub
	var fwd, fwdKey string
	if o.Forwarder != nil {
		fwd, fwdKey = o.Forwarder.Endpoint, o.Forwarder.Key
	}
	fw, eps, err := hubAddrs(fwd, fwdKey, o.Endpoints, s.projectPins())
	if err != nil {
		return refuse(node.ResultRefused, err.Error())
	}
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	switch {
	case st == nil:
		return refuse(node.ResultRefused, "sync away from home is off on this computer; turn it on there first (cbb global on)")
	case st.Relay != nil:
		return refuse(node.ResultRefused, "this computer meets the others at a blind relay; a group with a relay has no hub")
	}
	old := *st
	st.IsHub, st.Endpoints, st.Forwarder, st.Obfuscation = true, eps, fw, nil
	st.Members = append([]tunnel.Member(nil), old.Members...)
	// The old hub is no hub any more.
	st.Hubs = slices.DeleteFunc(slices.Clone(old.Hubs), func(h tunnel.HubLink) bool { return h.Device == string(body.By) })
	taken := 0
	for _, c := range o.Clients {
		if string(c.Device) == s.tunSelf {
			continue
		}
		if !s.listed(c.Device) {
			s.logf("cbb: the hub command hands over %s, which the records do not list; left out", c.Device)
			continue
		}
		var pub, psk tunnel.Key
		copy(pub[:], c.Key)
		copy(psk[:], c.PSK)
		changed, err := st.Take(string(c.Device), pub, psk)
		if err != nil {
			s.logf("cbb: taking the client %s from the old hub: %v", c.Device, err)
			continue
		}
		if changed {
			taken++
		}
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		*st = old
		return refuse(node.ResultFailed, fmt.Sprintf("saving the tunnel state: %v", err))
	}
	s.tunServing = true
	s.stopTunnelLocked()
	s.runTunnelLocked()
	s.shareLocked()
	s.logf("cbb: this device is the group's hub for sync away from home now, in place of %s, with %d of its clients", body.By, taken)
	offer := s.hubOfferLocked(st, nil)
	if offer == nil {
		return refuse(node.ResultFailed, "the hub has no offer yet")
	}
	res.Status, res.Tunnel = node.ResultDone, offer
	return res
}

// moveHub makes the member target, by name or device ID, the group's hub in
// place of this device, with a hub command this device signs as an admin:
// it hands over its clients, this device among them, passes the new hub's
// offer on to the connected clients and becomes the new hub's client. The
// new hub is reached through the forwarder and at the addresses given, or
// through this hub's forwarder when none are.
func (s *Service) moveHub(ctx context.Context, target, fwd, fwdKey string, addrs []string) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || nd == nil {
		return s.errNoGroup()
	}
	d, err := s.findDevice(target)
	if err != nil {
		return err
	}
	if d.Self {
		return errors.New("this device is the hub already")
	}
	ca, chain := id.Signer()
	if ca == nil {
		return errors.New("only an admin moves the hub: the group's root, an admin it made (cbb admin), or an admin phone")
	}
	if s.frozen(id) {
		return errFrozen
	}
	order := group.HubOrder{Endpoints: addrs}
	s.tunMu.Lock()
	st := s.tunnel
	if st == nil || !st.IsHub {
		s.tunMu.Unlock()
		return errors.New("this device is not the group's hub; cbb global hub makes it the hub")
	}
	switch {
	case fwd != "" && fwdKey == forward.ProjectKey:
		// The command carries a pin, which the new hub knows as the
		// project's forwarder's.
		order.Forwarder = &group.HubForwarder{Endpoint: fwd, Key: s.projectPins()[0]}
	case fwd != "":
		order.Forwarder = &group.HubForwarder{Endpoint: fwd, Key: fwdKey}
	case fwdKey != "":
		s.tunMu.Unlock()
		return errors.New("a forwarder's key without its address")
	case st.Forwarder != nil:
		order.Forwarder = &group.HubForwarder{Endpoint: st.Forwarder.Endpoint.String(), Key: st.Forwarder.Pin}
	}
	if order.Forwarder == nil && len(addrs) == 0 {
		s.tunMu.Unlock()
		return errors.New("this hub has no forwarder; give the new hub's addresses away from home, or a forwarder")
	}
	psks := map[group.DeviceID][]byte{}
	for _, m := range st.Members {
		if m.Device == d.ID {
			continue
		}
		psks[group.DeviceID(m.Device)] = m.PresharedKey[:]
		order.Clients = append(order.Clients, group.HubClient{Device: group.DeviceID(m.Device), Key: m.PublicKey[:], PSK: m.PresharedKey[:]})
	}
	// This device is the new hub's client from now on.
	selfPSK := st.PSK
	pub := st.Key.Public()
	order.Clients = append(order.Clients, group.HubClient{Device: id.ID, Key: pub[:], PSK: selfPSK[:]})
	s.tunMu.Unlock()
	if len(order.Clients) > group.MaxHubClients {
		return fmt.Errorf("this hub has more than %d clients", group.MaxHubClients-1)
	}

	now := s.cfg.now()
	body := group.CommandBody{Type: group.CommandHub, Group: group.Tag(id.GroupCA.Cert), By: id.ID, To: group.DeviceID(d.ID),
		ID: group.NewCommandID(), TimeMS: now.UnixMilli(), ExpiresMS: now.Add(group.CommandLifetime).UnixMilli(), Hub: &order}
	cmd, err := s.signCommand(body, ca, chain)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res, err := nd.SendCommand(cctx, group.DeviceID(d.ID), cmd, body.ID, nil)
	if err != nil {
		return fmt.Errorf("moving the hub to %s: %w", d.Name, err)
	}
	if res.Status != node.ResultDone {
		return fmt.Errorf("%s did not become the hub: %s", d.Name, res.Reason)
	}
	if res.Tunnel == nil {
		return fmt.Errorf("%s became the hub but sent no offer; turn sync away from home off and on again on this device", d.Name)
	}
	newHub := group.DeviceID(d.ID)
	self := *res.Tunnel
	self.PSK = selfPSK[:]
	link, err := hubLink(newHub, self)
	if err != nil {
		return fmt.Errorf("the offer of %s: %w", d.Name, err)
	}
	sent := nd.SendTunnel(func(dev group.DeviceID) *node.TunnelOffer {
		psk, ok := psks[dev]
		if !ok {
			return nil
		}
		o := *res.Tunnel
		o.PSK, o.Hub, o.Moved = psk, newHub, true
		return &o
	})
	s.logf("cbb: %s is the group's hub now; passed its offer on to %d connected clients", d.Name, len(sent))
	s.waitClientsLeft(ctx, nd, id.ID, sent)
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunnel != st {
		return nil // sync away from home was turned off meanwhile
	}
	old := *st
	*st = tunnel.State{Key: st.Key, PSK: st.PSK, Group: st.Group, KeysInFile: st.KeysInFile, Hubs: slices.Clone(st.Hubs)}
	if _, err := st.SetHub(link); err != nil {
		*st = old
		return err
	}
	if err := st.Save(s.cfg.StateDir); err != nil {
		*st = old
		return fmt.Errorf("saving the tunnel state: %w", err)
	}
	s.stopTunnelLocked()
	s.runTunnelLocked()
	return nil
}

// waitClientsLeft says goodbye, after the new hub's offer, to the clients
// the old hub passed it to that are connected through its tunnel, waits for
// up to moveGrace until those connections ended, and then for moveLinger.
// Those at home stay connected without the tunnel and need no wait.
func (s *Service) waitClientsLeft(ctx context.Context, nd *node.Node, self group.DeviceID, sent []group.DeviceID) {
	addr, err := tunnel.Addr(string(self))
	if err != nil || len(sent) == 0 {
		return
	}
	nd.SayGoodbye(sent, addr)
	deadline := time.After(moveGrace)
	tick := time.NewTicker(moveCheck)
	defer tick.Stop()
	for slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.Local == addr && slices.Contains(sent, p.ID) }) {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			s.logf("cbb: a client of this hub did not take the new hub's offer in %v; it gets it at home", moveGrace)
			return
		case <-tick.C:
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(moveLinger):
	}
}
