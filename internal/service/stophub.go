// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// Stopping a hub (docs/protocol.md, section 11, "Stopping a hub"): a hub
// stops being one, by its own user's word (cbb global hub off) or by an
// admin's hub command with a stop order (cbb global hub off -on DEVICE). It
// passes the next hub's offer on to its connected clients, as a hub that
// moves does, becomes a client with the offers it keeps, and tells the
// peers that keep its offer to forget it.

// errNoOtherHub refuses to stop the group's only hub without the user's word.
var errNoOtherHub = errors.New("the group has no other hub, so its devices away from home stop syncing until a device is a hub again; move the hub to another computer instead (cbb global move DEVICE), or stop it anyway with -yes")

// nextHub returns the first hub other than self, in the group's order,
// whose offer st keeps, the one its clients go to.
func nextHub(order []group.DeviceID, self string, st *tunnel.State) (tunnel.HubLink, bool) {
	var out []tunnel.HubLink
	for _, h := range st.Hubs {
		if h.Device != self && rankOf(order, h.Device) < len(order) && len(h.Endpoints)+boolInt(h.VLESS != nil) > 0 {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return tunnel.HubLink{}, false
	}
	slices.SortFunc(out, func(a, b tunnel.HubLink) int { return rankOf(order, a.Device) - rankOf(order, b.Device) })
	return out[0], true
}

// stopHub makes this device, a hub, stop being one. Without anyway it
// refuses while the group has no other hub.
func (s *Service) stopHub(ctx context.Context, anyway bool) error {
	order := s.hubOrder()
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	s.tunMu.Lock()
	st := s.tunnel
	if st == nil || !st.IsHub {
		s.tunMu.Unlock()
		return errors.New("this device is no hub of the group")
	}
	next, ok := nextHub(order, s.tunSelf, st)
	if !ok && !anyway {
		s.tunMu.Unlock()
		return errNoOtherHub
	}
	psks := map[group.DeviceID][]byte{}
	for _, m := range st.Members {
		if m.Device != next.Device {
			psks[group.DeviceID(m.Device)] = m.PresharedKey[:]
		}
	}
	self := group.DeviceID(s.tunSelf)
	s.tunMu.Unlock()

	if ok && nd != nil {
		o := offerOf(next)
		sent := nd.SendTunnel(func(dev group.DeviceID) *node.TunnelOffer {
			psk, ok := psks[dev]
			if !ok {
				return nil
			}
			c := o
			c.PSK, c.Hub, c.Moved = psk, group.DeviceID(next.Device), true
			return &c
		})
		s.logf("cbb: passed the offer of %s, the next hub, on to %d connected clients", next.Device, len(sent))
		s.waitClientsLeft(ctx, nd, self, sent)
	}

	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunnel != st || !st.IsHub {
		return nil // sync away from home changed meanwhile
	}
	old := *st
	*st = tunnel.State{Key: st.Key, PSK: st.PSK, Group: st.Group, KeysInFile: st.KeysInFile, Hubs: slices.Clone(st.Hubs), Retired: true}
	if err := st.Save(s.cfg.StateDir); err != nil {
		*st = old
		return fmt.Errorf("saving the tunnel state: %w", err)
	}
	s.tunServing = false
	s.stopTunnelLocked()
	s.runTunnelLocked()
	s.shareLocked()
	if ok {
		s.logf("cbb: this device is no hub of the group any more; its clients go to %s", next.Device)
	} else {
		s.logf("cbb: this device is no hub of the group any more, and the group has no other")
	}
	return nil
}

// stopHubOn makes the member target, by name or device ID, a hub, stop
// being one with a hub command this device signs as an admin. Without
// anyway it refuses while the group has no other hub this device knows.
func (s *Service) stopHubOn(ctx context.Context, target string, anyway bool) error {
	d, err := s.findDevice(target)
	if err != nil {
		return err
	}
	if d.Self {
		return errors.New("-on names this device; cbb global hub off stops it here")
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	hubs := s.knownHubs(id.ID)
	if !hubs[group.DeviceID(d.ID)] {
		return fmt.Errorf("%s is no hub of the group that this device knows", d.Name)
	}
	if len(hubs) < 2 && !anyway {
		return errNoOtherHub
	}
	if err := s.commandOn(ctx, d, group.CommandBody{Type: group.CommandHub, Hub: &group.HubOrder{Stop: true}}); err != nil {
		return err
	}
	s.logf("cbb: %s is no hub of the group any more", d.Name)
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if st := s.tunnel; st != nil && len(st.ForgetHubs(func(h tunnel.HubLink) bool { return h.Device != d.ID })) > 0 {
		if err := st.Save(s.cfg.StateDir); err != nil {
			s.logf("cbb: saving the tunnel state: %v", err)
		}
		if s.tunUsing == d.ID {
			s.stopTunnelLocked()
			s.runTunnelLocked()
		}
	}
	return nil
}

// hubStopped carries out a hub command with a stop order: this device, a
// hub, stops being one, after the result has gone back on the connection
// that brought the command, since its clients' connections end.
func (s *Service) hubStopped(body group.CommandBody) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultDone}
	s.tunMu.Lock()
	hub := s.tunnel != nil && s.tunnel.IsHub
	s.tunMu.Unlock()
	if !hub {
		res.Status, res.Reason = node.ResultRefused, "this device is no hub of the group"
		return res
	}
	s.logf("cbb: %s asked this hub to stop being one", body.By)
	res.Written = make(chan struct{})
	written := res.Written
	go func() {
		select {
		case <-written:
		case <-time.After(resultWait):
		}
		time.Sleep(restartAfter)
		if err := s.stopHub(context.Background(), true); err != nil {
			s.logf("cbb: stopping being the hub, as %s asked: %v", body.By, err)
		}
	}()
	return res
}
