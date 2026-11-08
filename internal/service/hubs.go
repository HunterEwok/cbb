// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/uptime"
	"github.com/HunterEwok/cbb/internal/vless"
)

// Several hubs (docs/protocol.md, section 11, "Several hubs"): the group's
// root and admins with a hub set are its hubs, in the order the records
// give (group.Records.HubOrder). Every member keeps the offers of all of
// them and uses the first in that order that answers; a hub serves its
// clients only while no hub above it answers, and is that hub's client
// otherwise. The hubs share their clients' keys, so each can take every
// client, and pass each other's offers on to their clients.

var (
	// upCheck is how long a member stays on a hub that is not the first
	// in the order before it tries the ones above again.
	upCheck = 5 * time.Minute
	// hubRecheck is how often a hub that serves, with hubs above it, tries
	// them as a client: a hub above that came back serves then.
	hubRecheck = 15 * time.Minute
	// standbyGrace is how long a hub that lost the hub above it keeps
	// trying the hubs above before it serves again.
	standbyGrace = time.Minute
	// briefLink is how long a connection through the tunnel to a hub must
	// last for the next try to come at once.
	briefLink = 10 * time.Second
)

// hubOrder returns the group's order of hubs.
func (s *Service) hubOrder() []group.DeviceID {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return nil
	}
	return s.records.HubOrder()
}

// knownHubs returns the group's hubs this device knows of, as the device
// lists mark them: itself while it is a hub, and the hubs in the group's
// order whose offers it keeps.
func (s *Service) knownHubs(self group.DeviceID) map[group.DeviceID]bool {
	order := s.hubOrder()
	out := map[group.DeviceID]bool{}
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil {
		return out
	}
	if st.IsHub {
		out[self] = true
	}
	for _, h := range st.Hubs {
		if rankOf(order, h.Device) < len(order) {
			out[group.DeviceID(h.Device)] = true
		}
	}
	return out
}

// rankOf returns where dev is in order; len(order) when it is not there.
func rankOf(order []group.DeviceID, dev string) int {
	if i := slices.Index(order, group.DeviceID(dev)); i >= 0 {
		return i
	}
	return len(order)
}

// hubsToTry returns, in the group's order, the offers this member tries:
// every hub it keeps an offer of, or, on a hub, those above it.
func hubsToTry(order []group.DeviceID, self string, st *tunnel.State) []tunnel.HubLink {
	limit := len(order)
	if st.IsHub {
		limit = rankOf(order, self)
	}
	var out []tunnel.HubLink
	for _, h := range st.Hubs {
		if r := rankOf(order, h.Device); r < limit && h.Device != self && len(h.Endpoints)+boolInt(h.VLESS != nil) > 0 {
			out = append(out, h)
		}
	}
	slices.SortFunc(out, func(a, b tunnel.HubLink) int { return rankOf(order, a.Device) - rankOf(order, b.Device) })
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// reachHubs connects through the tunnel, whenever this member is away
// from the hubs, to the first hub in the group's order that answers, and
// tries the hubs above it again every upCheck. On a hub (standby true) it
// tries only the hubs above this one, and when none answers, this hub
// serves. A hub found on the home network, or connected directly,
// counts as answering.
func (s *Service) reachHubs(ctx context.Context, run *tunRun, standby bool) {
	backoff := minBackoff
	// When this hub last had a hub above it: a hub that just started
	// serves after one round of tries, one that lost its hub after
	// standbyGrace.
	lost := uptime.Now() - standbyGrace
	selfAddr, _ := tunnel.Addr(s.tunSelf)
	for ctx.Err() == nil {
		s.tunMu.Lock()
		st := s.tunnel
		if st == nil || s.tunRun != run {
			s.tunMu.Unlock()
			return
		}
		hubs := hubsToTry(s.hubOrder(), s.tunSelf, st)
		s.tunMu.Unlock()
		s.mu.Lock()
		nd := s.nd
		var home []tunnel.HubLink
		for _, h := range hubs {
			if s.nearLocked(group.DeviceID(h.Device)) {
				home = append(home, h)
			}
		}
		s.mu.Unlock()
		if nd == nil {
			return
		}
		for _, p := range nd.Peers() {
			if i := slices.IndexFunc(hubs, func(h tunnel.HubLink) bool { return h.Device == string(p.ID) }); i >= 0 && p.Local != selfAddr {
				home = append(home, hubs[i])
			}
		}
		if len(home) > 0 {
			// At home with a hub: the members sync there, without the
			// tunnel, and a hub with one above it waits as its client.
			s.setUsing(run, home[0].Device, false)
			lost = uptime.Now()
			if !wait(ctx, awayCheck) {
				return
			}
			continue
		}
		reached := false
		tried := uptime.Now()
		for _, h := range hubs {
			if s.tryHub(ctx, run, nd, h, h.Device != hubs[0].Device) {
				reached = true
				break
			}
			if ctx.Err() != nil {
				return
			}
		}
		if reached {
			lost = uptime.Now()
			if lost-tried >= briefLink {
				backoff = minBackoff
				continue
			}
			// The hub ended the connection at once: each try starts a
			// tunnel from a new UDP port, and a forwarder takes only so
			// many of a group's client addresses, so the next try waits as
			// after one that got no answer.
		}
		s.setUsing(run, "", false)
		if standby && (uptime.Now()-lost >= standbyGrace || len(hubs) == 0) {
			s.serveHub(run)
			return
		}
		top := maxBackoff
		if len(hubs) > 0 {
			top = s.hubWait(group.DeviceID(hubs[0].Device))
		}
		if !wait(ctx, backoff) {
			return
		}
		backoff = min(2*backoff, top)
	}
}

// wait waits for d, and reports whether ctx is still going.
func wait(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// setUsing keeps, for status, the hub this member uses now and whether it
// is connected through the tunnel.
func (s *Service) setUsing(run *tunRun, hub string, through bool) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunRun == run {
		s.tunUsing, s.tunThrough = hub, through
	}
}

// tryHub starts the tunnel to the hub h and tries its addresses in turn;
// when one answers, it serves the member connection to the hub until it
// ends, or until upCheck when up is true, so the hubs above are tried
// again. It reports whether it reached the hub.
//
// A hub that gave its key for the next period is tried with both keys at
// once: it may have moved on to the next one while this member was away
// or while the connection was down (docs/protocol.md, section 11, "The
// hub's key"), and the key it no longer serves with gets no answer at all.
func (s *Service) tryHub(ctx context.Context, run *tunRun, nd *node.Node, h tunnel.HubLink, up bool) bool {
	self, err := tunnel.Addr(s.tunSelf)
	if err != nil {
		return false
	}
	hubAddr, err := tunnel.Addr(h.Device)
	if err != nil {
		return false
	}
	s.tunMu.Lock()
	st := s.tunnel
	if st == nil || s.tunRun != run {
		s.tunMu.Unlock()
		return false
	}
	key, psk := st.Key, h.PresharedKey
	s.tunMu.Unlock()
	// With VLESS the hub is tried over UDP first only when it speaks
	// AmneziaWG, never in plain WireGuard, and then over VLESS to its
	// forwarder; the way that worked last goes first the next time
	// (docs/protocol.md, section 11, "VLESS").
	eps := h.Endpoints
	if udpBlocked != nil {
		eps = udpBlocked(eps)
	}
	var vc *vless.Client
	defer func() { closeVLESS(vc) }()
	viaVLESS := func() bool {
		if vc == nil {
			if vc, err = vless.Dial(*h.VLESS); err != nil {
				vc = nil
				s.tunReport(run, "the way over VLESS to the hub's forwarder could not start", err)
				return false
			}
		}
		return true
	}
	if h.VLESS != nil {
		if h.Obfuscation == nil {
			eps = nil
		}
		s.tunMu.Lock()
		first := len(eps) == 0 || run.vlessFirst[h.Device]
		s.tunMu.Unlock()
		if first {
			if !viaVLESS() {
				return false
			}
			eps = append([]netip.AddrPort{vc.Addr()}, eps...)
		}
	}
	hubKeys := []tunnel.Key{h.PublicKey}
	if !h.Next.IsZero() {
		hubKeys = append(hubKeys, h.Next)
	}
	var cs []*tunnel.Client
	defer func() {
		for _, c := range cs {
			c.Close()
		}
	}()
	for _, k := range hubKeys {
		c, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: key, PresharedKey: psk, Addr: self,
			HubPublicKey: k, HubAddr: hubAddr, Endpoint: eps[0], Obfuscation: h.Obfuscation,
			Allowed: netguard.Allowed, Logf: s.logf, Verbose: tunnelVerbose()})
		if err != nil {
			s.tunReport(run, "the tunnel to the hub could not start", err)
			return false
		}
		cs = append(cs, c)
	}
	s.tunMu.Lock()
	if s.tunRun != run {
		s.tunMu.Unlock()
		return false
	}
	run.clients = cs
	s.tunMu.Unlock()
	defer func() {
		s.tunMu.Lock()
		if slices.Equal(run.clients, cs) {
			run.clients = nil
		}
		s.tunMu.Unlock()
	}()
	hub := group.DeviceID(h.Device)
	for i := 0; i < len(eps); i++ {
		ep := eps[i]
		first := dialWindow
		if vc != nil && ep == vc.Addr() {
			// VLESS opens its connection to the forwarder with the
			// first packet, and the handshakes sent meanwhile are lost.
			first = vlessFirstWindow
		}
		raw, won, err := dialAny(ctx, cs, ep, first)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			s.tunReport(run, fmt.Sprintf("no answer through the tunnel from %s at %v: the hub is off or cannot be reached, or the forwarder on the way is down", h.Device, ep), err)
			if i == len(eps)-1 && h.VLESS != nil && vc == nil && viaVLESS() {
				eps = append(eps, vc.Addr())
			}
			continue
		}
		overVLESS := vc != nil && ep == vc.Addr()
		s.tunMu.Lock()
		if run.vlessFirst == nil {
			run.vlessFirst = map[string]bool{}
		}
		run.vlessFirst[h.Device] = overVLESS
		s.tunMu.Unlock()
		// The other keys get no answer: their tunnels stop, so they do
		// not keep sending handshakes.
		s.tunMu.Lock()
		for _, c := range cs {
			if c != won {
				c.Close()
			}
		}
		cs = []*tunnel.Client{won}
		if s.tunRun == run {
			run.clients, run.hubKey = cs, won.HubKey()
		}
		s.tunMu.Unlock()
		s.setUsing(run, h.Device, true)
		s.tunReport(run, "", nil)
		cctx, cancel := ctx, context.CancelFunc(func() {})
		if up {
			cctx, cancel = context.WithTimeout(ctx, upCheck)
		}
		err = nd.DialConn(cctx, hub, raw)
		cancel()
		s.tunMu.Lock()
		run.hubKey = tunnel.Key{}
		s.tunMu.Unlock()
		s.setUsing(run, "", false)
		if err != nil && ctx.Err() == nil && cctx.Err() == nil {
			s.logf("cbb: the connection to the hub %s through the tunnel ended: %v", hub, err)
		}
		return true
	}
	return false
}

// udpBlocked, in tests, stands for a network that lets no UDP through: it
// replaces the hub's endpoints with ones that never answer.
var udpBlocked func([]netip.AddrPort) []netip.AddrPort

func closeVLESS(c *vless.Client) {
	if c != nil {
		c.Close()
	}
}

// hubClient is what dialAny needs of a tunnel client.
type hubClient interface {
	SetEndpoint(ep netip.AddrPort) error
	Dial(ctx context.Context) (net.Conn, error)
	Received() uint64
}

// dialWindow is how long a try through a client may go without a word from
// the hub, and dialWindows how many such windows it may take in all.
var (
	dialWindow  = handshakeTimeout
	dialWindows = 6
	// vlessFirstWindow is the first window over VLESS: its TLS and HTTP/2
	// to the forwarder come first.
	vlessFirstWindow = 3 * handshakeTimeout
)

// dialAny points each client at ep and dials the hub through all of them
// at once; the first connection wins, with its client, and the other tries
// end. A try ends when its client has had nothing from the hub for a
// dialWindow, or after dialWindows of them: on a slow way, such as VLESS on
// a busy machine, the handshake and the connection each can take most of a
// window, and starting over would throw away what got through and meet the
// same wait again, while a hub that does not answer still ends the try in
// one window. The first window lasts first.
func dialAny[C hubClient](ctx context.Context, cs []C, ep netip.AddrPort, first time.Duration) (net.Conn, C, error) {
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c    C
		conn net.Conn
		err  error
	}
	window, windows := dialWindow, dialWindows
	results := make(chan result, len(cs))
	for _, c := range cs {
		go func() {
			if err := c.SetEndpoint(ep); err != nil {
				results <- result{c, nil, err}
				return
			}
			cctx, cancel := context.WithCancel(dctx)
			defer cancel()
			done := make(chan struct{})
			defer close(done)
			go func() {
				t := time.NewTimer(first)
				defer t.Stop()
				seen := c.Received()
				for range windows {
					select {
					case <-done:
						return
					case <-t.C:
					}
					t.Reset(window)
					n := c.Received()
					if n == seen {
						break
					}
					seen = n
				}
				cancel()
			}()
			conn, err := c.Dial(cctx)
			results <- result{c, conn, err}
		}()
	}
	var won result
	var errs []error
	for range cs {
		r := <-results
		switch {
		case r.err != nil:
			errs = append(errs, r.err)
		case won.conn == nil:
			won = r
			cancel()
		default:
			r.conn.Close()
		}
	}
	if won.conn != nil {
		return won.conn, won.c, nil
	}
	var none C
	return nil, none, errors.Join(errs...)
}

// tunReport keeps what went wrong for status, while run is the tunnel at
// work.
func (s *Service) tunReport(run *tunRun, msg string, err error) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunRun == run {
		s.tunFailedLocked(msg, err)
	}
}

// serveHub makes this hub serve, in place of run, its link to the hubs
// above it, none of which answers.
func (s *Service) serveHub(run *tunRun) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunRun != run || s.tunnel == nil || !s.tunnel.IsHub {
		return
	}
	s.logf("cbb: no hub above this one answers; this device serves as the group's hub")
	s.tunServing = true
	s.stopTunnelLocked()
	s.runTunnelLocked()
	s.shareLocked()
}

// standbyLocked makes this hub, while it serves, try the hubs above it, as
// their client; it serves again when none answers.
func (s *Service) standbyLocked(why string) {
	st := s.tunnel
	if st == nil || !st.IsHub || !s.tunServing {
		return
	}
	if len(hubsToTry(s.hubOrder(), s.tunSelf, st)) == 0 {
		return
	}
	s.logf("cbb: %s; this hub tries the hubs above it", why)
	s.tunServing = false
	s.stopTunnelLocked()
	s.runTunnelLocked()
	s.shareLocked()
}

// recheckHubs makes the hub that serves try the hubs above it every
// hubRecheck.
func (s *Service) recheckHubs(ctx context.Context) {
	t := time.NewTicker(hubRecheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tunMu.Lock()
			s.standbyLocked("it is time to look for the hubs above this one")
			s.tunMu.Unlock()
		}
	}
}

// hubOffersLocked returns the offers this hub sends a client with the
// preshared key psk: its own, then those of the group's other hubs it
// keeps, passed on, but not the client's own.
func (s *Service) hubOffersLocked(st *tunnel.State, client group.DeviceID, psk []byte) []node.TunnelOffer {
	own := s.hubOfferLocked(st, psk)
	if own == nil {
		return nil
	}
	out := []node.TunnelOffer{*own}
	order := s.hubOrder()
	for _, h := range st.Hubs {
		if h.Device == string(client) || rankOf(order, h.Device) == len(order) {
			continue
		}
		o := offerOf(h)
		o.PSK, o.Hub = psk, group.DeviceID(h.Device)
		out = append(out, o)
	}
	return out
}

// offerOf is the offer a member keeps as h, without its preshared key.
func offerOf(h tunnel.HubLink) node.TunnelOffer {
	o := node.TunnelOffer{HubKey: h.PublicKey[:]}
	if !h.Next.IsZero() {
		o.NextKey = h.Next[:]
	}
	for _, ep := range h.Endpoints {
		o.Endpoints = append(o.Endpoints, ep.String())
	}
	if h.Obfuscation != nil {
		o.Obfuscation, _ = json.Marshal(h.Obfuscation)
	}
	if h.VLESS != nil {
		o.VLESS, _ = json.Marshal(h.VLESS)
	}
	return o
}

// hubShare is what this hub shares with peer, a device that may be a hub:
// its offer, whether it serves, and its clients, itself among them; nil
// when this device is no hub or peer may not be one.
//
// A device that stopped being a hub tells the computers and the devices
// that may be hubs instead that it is none, so that they forget its offer.
func (s *Service) hubShare(peer group.DeviceID) *node.HubShare {
	may, member := s.mayHost(peer), s.roleOfDevice(peer) == group.RoleMember
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if st := s.tunnel; st != nil && !st.IsHub && st.Retired {
		if may || member {
			return &node.HubShare{Stopped: true}
		}
		return nil
	}
	if !may {
		return nil
	}
	return s.hubShareLocked(peer)
}

// roleOfDevice is the role the records give dev, "" when they do not
// list it.
func (s *Service) roleOfDevice(dev group.DeviceID) string {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.records == nil {
		return ""
	}
	for _, d := range s.records.Devices() {
		if d.ID == dev {
			return d.Role
		}
	}
	return ""
}

func (s *Service) hubShareLocked(peer group.DeviceID) *node.HubShare {
	st := s.tunnel
	if st == nil || !st.IsHub || string(peer) == s.tunSelf {
		return nil
	}
	h := &node.HubShare{Serving: s.tunServing, Offer: s.hubOfferLocked(st, nil)}
	pub := st.Key.Public()
	h.Clients = append(h.Clients, group.HubClient{Device: group.DeviceID(s.tunSelf), Key: pub[:], PSK: st.PSK[:]})
	for _, m := range st.Members {
		if m.Device != string(peer) && len(h.Clients) < group.MaxHubClients {
			h.Clients = append(h.Clients, group.HubClient{Device: group.DeviceID(m.Device), Key: m.PublicKey[:], PSK: m.PresharedKey[:]})
		}
	}
	return h
}

// shareLocked sends the connected devices that may be hubs what this hub
// shares, once it starts or stops serving; it does so on its own, since
// the locks it takes come before tunMu.
func (s *Service) shareLocked() {
	go func() {
		s.mu.Lock()
		nd := s.nd
		s.mu.Unlock()
		if nd != nil {
			nd.SendHubs(s.hubShare)
		}
	}()
}

// hubsShared takes what another hub shared: its clients, on this hub, and
// its offer, which this member keeps as it keeps any hub's. A hub above
// this one that serves makes this hub, while it serves, its client.
func (s *Service) hubsShared(from group.DeviceID, chain []*x509.Certificate, h node.HubShare) error {
	if !s.hubPeer(from, chain) {
		return errors.New("only the group's root, an admin or a hub its records name can be its hub; ignored")
	}
	order := s.hubOrder()
	listed := map[group.DeviceID]bool{}
	s.recMu.Lock()
	if s.records != nil {
		for _, d := range s.records.Devices() {
			listed[d.ID] = true
		}
	}
	s.recMu.Unlock()
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if st == nil || st.Relay != nil {
		return nil
	}
	if h.Stopped {
		// The sender is no hub any more: its offer goes.
		lost := st.ForgetHubs(func(l tunnel.HubLink) bool { return l.Device != string(from) })
		if len(lost) == 0 {
			return nil
		}
		s.logf("cbb: %s is no hub of the group any more; its offer is forgotten", from)
		if err := st.Save(s.cfg.StateDir); err != nil {
			return fmt.Errorf("saving the tunnel state: %w", err)
		}
		if s.tunUsing == string(from) {
			s.stopTunnelLocked()
			s.runTunnelLocked()
		}
		return nil
	}
	save, peers := false, false
	if st.IsHub {
		for _, c := range h.Clients {
			if string(c.Device) == s.tunSelf || !listed[c.Device] || len(c.Key) != 32 || len(c.PSK) != 32 {
				continue
			}
			var pub, psk tunnel.Key
			copy(pub[:], c.Key)
			copy(psk[:], c.PSK)
			changed, err := st.Take(string(c.Device), pub, psk)
			if err != nil {
				s.logf("cbb: a client %s shared: %v", from, err)
				continue
			}
			save, peers = save || changed, peers || changed
		}
	}
	if h.Offer != nil {
		o := *h.Offer
		o.PSK = st.PSK[:]
		link, err := hubLink(from, o)
		if err != nil {
			return fmt.Errorf("its offer: %w", err)
		}
		changed, err := st.SetHub(link)
		if err != nil {
			return err
		}
		save = save || changed
	}
	if save {
		if err := st.Save(s.cfg.StateDir); err != nil {
			return fmt.Errorf("saving the tunnel state: %w", err)
		}
	}
	if peers {
		s.hubPeersLocked()
	}
	if h.Serving && rankOf(order, string(from)) < rankOf(order, s.tunSelf) {
		s.giveWayLocked(from, h.Offer)
	}
	return nil
}

// giveWayLocked makes this hub, while it serves, the client of from, a hub
// above it that serves or offered its tunnel. A client far from home may know only this hub,
// for instance after the hub moved here, so the hub first passes from's
// offer on to its connected clients and waits for the ones it reaches
// through its tunnel to leave, as a hub that moves does; it gives way
// after that.
func (s *Service) giveWayLocked(from group.DeviceID, offer *node.TunnelOffer) {
	st := s.tunnel
	why := fmt.Sprintf("%s, a hub above this one, serves", from)
	if st == nil || !st.IsHub || !s.tunServing || s.givingWay {
		return
	}
	if offer == nil {
		s.standbyLocked(why)
		return
	}
	psks := map[group.DeviceID][]byte{}
	for _, m := range st.Members {
		if m.Device != string(from) {
			psks[group.DeviceID(m.Device)] = m.PresharedKey[:]
		}
	}
	s.givingWay = true
	run, ctx, self := s.tunRun, s.tunCtx, group.DeviceID(s.tunSelf)
	o := *offer
	go func() {
		s.mu.Lock()
		nd := s.nd
		s.mu.Unlock()
		if nd != nil && ctx != nil {
			sent := nd.SendTunnel(func(dev group.DeviceID) *node.TunnelOffer {
				psk, ok := psks[dev]
				if !ok {
					return nil
				}
				c := o
				c.PSK, c.Hub, c.Moved = psk, from, false
				return &c
			})
			s.logf("cbb: passed the offer of %s, a hub above this one, on to %d connected clients", from, len(sent))
			s.waitClientsLeft(ctx, nd, self, sent)
		}
		s.tunMu.Lock()
		defer s.tunMu.Unlock()
		s.givingWay = false
		if s.tunRun == run {
			s.standbyLocked(why)
		}
	}()
}
