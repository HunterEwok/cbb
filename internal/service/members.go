// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/mdns"
	"github.com/HunterEwok/clipboardbridge/internal/node"
	"github.com/HunterEwok/clipboardbridge/internal/pair"
	"github.com/HunterEwok/clipboardbridge/internal/uptime"
)

const (
	handshakeTimeout = 10 * time.Second
	minBackoff       = time.Second
	maxBackoff       = 30 * time.Second
	// fallbackDial is how long a full member waits for one with a lower
	// device ID to dial it before it dials that one itself.
	fallbackDial = 30 * time.Second
)

// serveMember runs one connection to the member port (see demux.go): plain
// HTTP goes to the profile while an iPhone pairing window is open; over TLS
// the ALPN protocol that the client offers picks pairing, the member
// protocol, or, for any other, the shortcut's HTTPS. release gives up the
// connection's handshake slot: after the handshake for a member or the
// shortcut, after the attempt for pairing.
func (s *Service) serveMember(ctx context.Context, raw net.Conn, release func()) {
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	raw.SetReadDeadline(time.Now().Add(handshakeTimeout))
	raw, first, err := peek(raw)
	raw.SetReadDeadline(time.Time{})
	if err != nil {
		raw.Close()
		return
	}
	if first != recordHandshake {
		s.mu.Lock()
		profile := s.profileConns
		s.mu.Unlock()
		if profile == nil {
			raw.Close()
			return
		}
		release()
		released = true
		profile.pass(raw) // the server's own timeouts bound it from here
		return
	}
	cfg := &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case slices.Contains(hello.SupportedProtos, pair.Protocol):
			if s.window != nil {
				return s.window.ServerTLS(), nil
			}
			// Also without a window, so the joiner hears that it is closed.
			return pair.ServerTLS(s.id), nil
		case !slices.Contains(hello.SupportedProtos, group.MemberProtocol) && s.phoneTLS != nil:
			return s.phoneTLS, nil
		}
		return s.nd.ServerTLS(), nil
	}}
	tc := tls.Server(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		tc.Close()
		return
	}
	switch tc.ConnectionState().NegotiatedProtocol {
	case group.MemberProtocol:
	case pair.Protocol:
		s.mu.Lock()
		w := s.window
		s.mu.Unlock()
		if w == nil {
			pair.Refuse(ctx, tc, pair.ErrClosed)
			return
		}
		if err := w.Serve(ctx, tc); err != nil {
			s.logf("cbb: pairing attempt from %s: %v", raw.RemoteAddr(), err)
		}
		return
	default:
		s.mu.Lock()
		phone := s.phoneConns
		s.mu.Unlock()
		if phone == nil {
			tc.Close()
			return
		}
		release()
		released = true
		phone.pass(tc)
		return
	}
	release()
	released = true
	if err := s.nd.Serve(ctx, tc); err != nil {
		s.logEnd(err, "cbb: connection from %s: %v", raw.RemoteAddr(), err)
	}
}

// dialer keeps the connection to one member up.
type dialer struct {
	cancel context.CancelFunc
	addrs  []string // where discovery last saw the member, best first
	// later says the member has the lower device ID, so it dials this one:
	// this one dials only when no connection has been up for a while.
	later bool
	// fallback says this one is dialing because the member did not reach
	// it: a connection that comes up now is this one's (see unreached).
	fallback bool
}

// found handles the members that discovery found. Of two full members the
// one with the lower device ID dials, and the other one too when no
// connection between them has come up for fallbackAfter, since a firewall
// may keep the first from reaching it; node keeps the connection the lower
// ID dialed. The lite members (TXT r=lite) dial the full members, and the
// phones dial everyone. A member's dialer takes its new addresses or port on
// its next round. found also notes the holder priority each member
// publishes (TXT h) and elects the holder of clipboardbridge.local again.
func (s *Service) found(peers []mdns.Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.id == nil || s.stopping {
		return
	}
	tag := group.Tag(s.id.GroupCA.Cert)
	type target struct {
		addrs []string
		later bool
	}
	want := map[group.DeviceID]target{}
	found := s.nearby
	s.nearby = map[group.DeviceID]time.Duration{}
	s.prio = map[group.DeviceID]int{}
	for _, p := range peers {
		id, err := group.ParseDeviceID(p.ID)
		if err != nil || id == s.id.ID {
			continue
		}
		if g, _ := p.TXTValue("g"); g != tag {
			continue // another group, or an old CA
		}
		if at, ok := found[id]; ok {
			s.nearby[id] = at
		} else {
			s.nearby[id] = uptime.Now()
		}
		if h, ok := p.TXTValue("h"); ok {
			if n := parsePriority(h); n > 0 {
				s.prio[id] = n
			}
		}
		if r, _ := p.TXTValue("r"); strings.EqualFold(r, "lite") || strings.EqualFold(r, "phone") {
			continue // it dials the full members
		}
		want[id] = target{addresses(p), id < s.id.ID}
	}
	for id, d := range s.dialers {
		if t, ok := want[id]; !ok || t.later != d.later {
			d.cancel()
			delete(s.dialers, id)
		}
	}
	for id, t := range want {
		if d, ok := s.dialers[id]; ok {
			d.addrs = t.addrs
			continue
		}
		ctx, cancel := context.WithCancel(s.groupCtx)
		s.dialers[id] = &dialer{cancel: cancel, addrs: t.addrs, later: t.later}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dial(ctx, id, t.later)
		}()
	}
	s.electLocked()
}

// nearGrace is how long a member that discovery finds counts as on this
// network without a connection to it: anyone on a network can announce a
// member's name and the group's tag, so an announcement alone must not keep
// the member's tunnel or relay path closed for long.
const nearGrace = 30 * time.Second

// nearLocked reports whether discovery found the member on this network
// within nearGrace. Past it, only a connection to the member keeps the
// paths away from home closed; the callers check those.
func (s *Service) nearLocked(id group.DeviceID) bool {
	at, ok := s.nearby[id]
	return ok && uptime.Now()-at < nearGrace
}

// addresses returns a member's addresses with its port, best first.
func addresses(p mdns.Peer) []string {
	addrs := slices.Clone(p.Addrs)
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int { return rank(a) - rank(b) })
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.String(), strconv.Itoa(int(p.Port))))
	}
	return out
}

// rank orders addresses by how likely they work: IPv4 first, then routable
// IPv6, and link-local addresses last, since they need the right interface.
func rank(a netip.Addr) int {
	a = a.Unmap()
	r := 0
	if a.Is6() {
		r++
	}
	if a.IsLinkLocalUnicast() {
		r += 2
	}
	return r
}

// dial keeps a connection to a member up while it is found: it tries the
// addresses that discovery last saw in turn, and waits longer after each
// round that failed. With later, it first waits until no connection to the
// member has been up for fallbackAfter.
func (s *Service) dial(ctx context.Context, id group.DeviceID, later bool) {
	backoff := minBackoff
	letIn := false
	for ctx.Err() == nil {
		if later && !letIn && !s.waitUnconnected(ctx, id) {
			return
		}
		s.mu.Lock()
		var addrs []string
		if d := s.dialers[id]; d != nil {
			addrs = d.addrs
			d.fallback = later
		}
		nd := s.nd
		s.mu.Unlock()
		letIn = false
		for _, addr := range addrs {
			start := uptime.Now()
			err := nd.Dial(ctx, id, addr)
			if ctx.Err() != nil {
				return
			}
			if uptime.Now()-start > maxBackoff {
				backoff = minBackoff // the connection worked for a while
			}
			logConn(s.logf, id, "at "+addr, err)
			if errors.Is(err, node.ErrLetIn) {
				// The records now admit the member: connect again at
				// once, as a member, at the same address.
				letIn = true
				backoff = minBackoff
				break
			}
		}
		s.mu.Lock()
		if d := s.dialers[id]; d != nil {
			d.fallback = false
		}
		s.mu.Unlock()
		if letIn {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// waitUnconnected waits until no connection to the member id has been up
// for fallbackAfter; it reports false if ctx ended first.
func (s *Service) waitUnconnected(ctx context.Context, id group.DeviceID) bool {
	tick := min(time.Second, s.cfg.fallbackAfter)
	since := uptime.Now()
	for {
		s.mu.Lock()
		nd := s.nd
		s.mu.Unlock()
		if nd != nil && slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.ID == id }) {
			// The member dialed this one: its connections come through.
			since = uptime.Now()
			s.mu.Lock()
			delete(s.unreached, id)
			s.mu.Unlock()
		} else if uptime.Now()-since >= s.cfg.fallbackAfter {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(tick):
		}
	}
}

// dialJoined keeps a member connection up to the member that admitted this
// device at the address the user gave for the join, such as an SSH forward
// or a VPN address, which discovery cannot find. Then that member syncs
// with it at once, and when it is the group's hub it learns this device's
// tunnel key as soon as sync away from home is turned on here.
func (s *Service) dialJoined(id group.DeviceID, addr string) {
	s.keepUntilHub(id, "at "+addr+", where it joined", func(ctx context.Context, nd *node.Node) error {
		return nd.Dial(ctx, id, addr)
	}, nil)
}

// keepUntilHub keeps a member connection up to the member id with dial
// while discovery does not see that member and no other connection to it
// is up. It stops for good once this device knows the group's hub, or when
// the service stops, and then calls done, if set.
func (s *Service) keepUntilHub(id group.DeviceID, where string, dial func(context.Context, *node.Node) error, done func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.groupCtx == nil || s.stopping {
		if done != nil {
			done()
		}
		return
	}
	ctx := s.groupCtx
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if done != nil {
			defer done()
		}
		s.keepUntil(ctx, id, where, dial)
	}()
}

func (s *Service) keepUntil(ctx context.Context, id group.DeviceID, where string, dial func(context.Context, *node.Node) error) {
	knowsHub := func() bool {
		s.tunMu.Lock()
		defer s.tunMu.Unlock()
		return s.tunnel != nil && len(s.tunnel.Hubs) > 0
	}
	// The connection ends too once the hub's offer came, so the tunnel
	// takes over.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for !knowsHub() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		cancel()
	}()
	backoff := minBackoff
	for ctx.Err() == nil {
		if knowsHub() {
			return // the tunnel reaches the hub from here on
		}
		s.mu.Lock()
		nd, near := s.nd, s.nearLocked(id)
		s.mu.Unlock()
		if nd == nil {
			return
		}
		wait := awayCheck
		if !near && !slices.ContainsFunc(nd.Peers(), func(p node.Peer) bool { return p.ID == id }) {
			start := uptime.Now()
			err := dial(ctx, nd)
			if ctx.Err() != nil {
				return
			}
			if uptime.Now()-start > maxBackoff {
				backoff = minBackoff
			}
			logConn(s.logf, id, where, err)
			wait = backoff
			backoff = min(2*backoff, maxBackoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// peersChanged elects the holder of clipboardbridge.local again (see
// electLocked).
func (s *Service) peersChanged() {
	s.mu.Lock()
	s.electLocked()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		return
	}
	peers := nd.Peers()
	s.learnFrom(peers)
	s.trackSeen(peers)
	s.ensureListed()
	s.renewAdminCAs(peers)
}

// electLocked elects the holder of clipboardbridge.local among this member
// and the full members it is connected to that discovery finds with a
// holder priority: the lowest priority number, then the lowest device ID.
// A member without the iPhone CA key, as in a group whose root is a phone,
// or set to never, does not take part.
func (s *Service) electLocked() {
	if s.id == nil || s.responder == nil || s.stopping {
		return // a stopping member keeps what it had until its goodbye
	}
	me := s.priorityLocked(s.id)
	hold := me > 0
	for _, p := range s.nd.Peers() {
		if !hold {
			break
		}
		if q := s.prio[p.ID]; p.Role == node.Full && q > 0 && (q < me || q == me && p.ID < s.id.ID) {
			hold = false
		}
	}
	if hold != s.holder {
		s.holder = hold
		s.responder.SetHolder(hold)
		s.logf("cbb: holds clipboardbridge.local: %v", hold)
	}
}

// watchSleep tells the node when the machine slept: the clock that counts
// sleep moved further than the one that does not. The connections from
// before are dead, and the member must take the group's text again. A hello
// that came before this notices the sleep is written then too (see
// clip.Engine.Rejoin).
func (s *Service) watchSleep(ctx context.Context) {
	t := time.NewTicker(sleepCheckEvery)
	defer t.Stop()
	d := newSleepDetector(uptime.Now(), time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if slept, ok := d.check(uptime.Now(), time.Now()); ok {
			s.logf("cbb: the machine slept for %v", slept.Round(time.Second))
			s.mu.Lock()
			nd := s.nd
			s.mu.Unlock()
			if nd != nil {
				nd.Rejoin()
			}
		}
	}
}

const sleepCheckEvery, sleepSlack = 2 * time.Second, 3 * time.Second

// sleepDetector compares the clock that counts sleep with the one that
// does not.
type sleepDetector struct {
	lastUp   time.Duration
	lastMono time.Time
}

func newSleepDetector(up time.Duration, mono time.Time) *sleepDetector {
	return &sleepDetector{lastUp: up, lastMono: mono}
}

// check takes the two clocks now and reports how long the machine slept
// since the last check, if it did.
func (d *sleepDetector) check(up time.Duration, mono time.Time) (time.Duration, bool) {
	slept := (up - d.lastUp) - mono.Sub(d.lastMono)
	d.lastUp, d.lastMono = up, mono
	return slept, slept > sleepSlack
}

// write passes a write that the engine decided on to the watchers that
// hold a clipboard, in order. When none is connected, the next one gets it.
func (s *Service) write(w node.Write) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.Seq <= s.lastSeq {
		return
	}
	s.lastSeq = w.Seq
	s.mediaWait = nil
	media := w
	w, ok := s.mediaWritten(w)
	// A watcher that takes images or files gets such a copy whole, once
	// it has arrived; the others get its plain-text alternative, if any.
	whole := s.content != nil && media.Media != nil && (imageCopy(media.Media) || htmlCopy(media.Media) || media.Media.Files())
	if whole && !s.content.complete(media.Media) {
		s.mediaWait = &media
	}
	boards := 0
	for wt := range s.watchers {
		switch {
		case !wt.board():
			continue
		case whole && wt.takes(media.Media):
			if s.mediaWait == nil {
				wt.send(media)
			}
		case ok:
			wt.send(w)
		}
		boards++
	}
	if !ok {
		return // images or files without a text: nothing for the others
	}
	if boards == 0 {
		s.pending = &w
		return
	}
	s.pending = nil
}

// imageCopy reports whether a copy is clipboard data with an image, which
// a watcher that takes images puts into the clipboard.
func imageCopy(m *clip.Manifest) bool {
	if m == nil || m.Files() {
		return false
	}
	return slices.ContainsFunc(m.Parts, func(p clip.Part) bool { return p.Type == clip.TypePNG || p.Type == clip.TypeJPEG })
}

// htmlCopy reports whether a copy is clipboard data with formatted text,
// which a watcher that takes it puts into the clipboard with the copy's
// plain text.
func htmlCopy(m *clip.Manifest) bool {
	if m == nil || m.Files() {
		return false
	}
	return slices.ContainsFunc(m.Parts, func(p clip.Part) bool { return p.Type == clip.TypeHTML })
}

// mediaArrived gives the watchers that take images or files the copy m
// once its fetch ended, if it is still the latest write: the copy if it
// arrived, else its plain-text alternative, if any.
func (s *Service) mediaArrived(m *clip.Manifest, arrived bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.mediaWait
	if w == nil || w.Media != m || w.Seq != s.lastSeq {
		return
	}
	s.mediaWait = nil
	if !arrived {
		if w.Text == "" {
			return
		}
		w = &node.Write{Text: w.Text, Kind: clip.Text, Via: w.Via, Seq: w.Seq}
	}
	for wt := range s.watchers {
		if wt.board() && wt.takes(m) {
			wt.send(*w)
		}
	}
}

// logConn logs how a connection to a member ended: with its error, or
// closed in order.
func logConn(logf func(string, ...any), id group.DeviceID, where string, err error) {
	if err == nil {
		logf("cbb: connection to %s %s closed", id, where)
		return
	}
	logf("cbb: connection to %s %s: %v", id, where, err)
}
