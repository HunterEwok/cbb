// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package mdns is the small multicast DNS responder and browser of
// cbb (RFC 6762 and RFC 6763): Linux members publish and browse, a Mac
// and a device about to join only browse (D-32).
//
// A member publishes its service instance <device ID>._cbb._tcp.local
// with SRV and TXT records and its own host name cb-<device ID>.local. It
// finds the other members by browsing for _cbb._tcp.local.
//
// It shares UDP port 5353 with avahi-daemon or systemd-resolved, publishes
// only private IPv4, unique-local and link-local IPv6 addresses, and answers
// each query with the addresses of the interface the query arrived on.
// Names are not probed: device IDs are random.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Port is the multicast DNS port.
const Port = 5353

var (
	group4 = netip.AddrPortFrom(netip.MustParseAddr("224.0.0.251"), Port)
	group6 = netip.AddrPortFrom(netip.MustParseAddr("ff02::fb"), Port)
)

const (
	tick          = 250 * time.Millisecond
	rescanEvery   = 10 * time.Second
	maxQueryGap   = time.Hour
	announceCount = 2 // RFC 6762 section 8.3: at least two, a second apart
	maxPacket     = 9000
)

// Config configures a Responder.
type Config struct {
	ID   string   // the device ID: the instance name and the host label
	Port uint16   // the member port, published in the SRV record
	TXT  []string // key=value strings

	// OnPeers, if set, is called with the members found, whenever the set
	// or their records change. It runs on the responder's goroutine.
	OnPeers func([]Peer)

	// BrowseOnly finds members without publishing this one: for a Mac,
	// which browses for as long as its service runs, and for a device that
	// is about to join a group.
	BrowseOnly bool

	// Publish, if set, tells whether to publish this member on an
	// interface, by its name and networks; elsewhere it only browses. It is
	// asked when the interfaces change and after Recheck.
	Publish func(name string, prefixes []netip.Prefix) bool

	// Interfaces, if set, limits the responder to the interfaces it allows,
	// by name: it joins the multicast groups, publishes and browses only
	// there, and ignores packets from elsewhere. A router lists its home
	// zones, so that nothing is said or heard on the internet side.
	Interfaces func(name string) bool

	// Logf, if set, receives diagnostics.
	Logf func(format string, args ...any)

	// Now returns the current time; time.Now if nil. Tests change it.
	Now func() time.Time

	// net is the network; the system's sockets if nil.
	net transport
}

// A Responder publishes this member and browses for the others.
type Responder struct {
	cfg Config
	now func() time.Time

	mu      sync.Mutex
	z       *zone
	pending []change // record changes to announce
	kick    chan struct{}

	// sendMu orders the delayed answers before the goodbye: once stopped,
	// no answer goes out after it.
	sendMu  sync.Mutex
	stopped bool

	ran atomic.Bool // Run runs once

	// addrGen counts address changes; a delayed answer made before one is
	// dropped, so no stale address goes out after its goodbye.
	addrGen atomic.Uint64
}

// change is what to announce again.
type change struct {
	fresh   bool // announce the whole zone again
	recheck bool // ask Publish again for every interface
}

// New returns a responder; Run starts it.
func New(cfg Config) (*Responder, error) {
	if cfg.ID == "" || len(cfg.ID) > 59 || strings.Contains(cfg.ID, ".") {
		return nil, errors.New("mdns: bad device ID")
	}
	if err := checkTXT(cfg.TXT); err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Responder{cfg: cfg, now: now, z: newZone(cfg.ID, cfg.Port, cfg.TXT), kick: make(chan struct{}, 1)}, nil
}

// checkTXT checks that each string of a TXT record fits its length byte.
func checkTXT(txt []string) error {
	for _, s := range txt {
		if len(s) > 255 {
			return fmt.Errorf("mdns: a TXT string of %d bytes is longer than 255", len(s))
		}
	}
	return nil
}

// SetTXT replaces the TXT record and announces it. A record that does not
// fit is refused and the old one kept.
func (r *Responder) SetTXT(txt []string) {
	if err := checkTXT(txt); err != nil {
		r.logf("%v", err)
		return
	}
	r.mu.Lock()
	if slices.Equal(r.z.txt, txt) {
		r.mu.Unlock()
		return
	}
	z := *r.z
	z.txt = slices.Clone(txt)
	r.z = &z
	r.pending = append(r.pending, change{fresh: true})
	r.mu.Unlock()
	r.wake()
}

// Recheck asks Config.Publish again for every interface: the member
// publishes itself on those where it now may, with a goodbye on those
// where it no longer may.
func (r *Responder) Recheck() {
	r.mu.Lock()
	r.pending = append(r.pending, change{recheck: true})
	r.mu.Unlock()
	r.wake()
}

func (r *Responder) wake() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

func (r *Responder) zone() *zone {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.z
}

func (r *Responder) logf(format string, args ...any) {
	if r.cfg.Logf != nil {
		r.cfg.Logf(format, args...)
	}
}

// Run publishes the member and browses until ctx is done; then it sends
// goodbyes for all its records and returns.
//
// Run may be called only once.
func (r *Responder) Run(ctx context.Context) error {
	if r.ran.Swap(true) {
		return errors.New("mdns: a responder runs only once")
	}
	tr := r.cfg.net
	if tr == nil {
		var err error
		if tr, err = listen(r.logf, r.cfg.Interfaces); err != nil {
			return err
		}
	}
	done := make(chan struct{})
	defer close(done)
	defer tr.close()
	packets := make(chan packet, 64)
	go func() {
		defer close(packets)
		for {
			p, err := tr.read()
			if err != nil {
				return
			}
			select {
			case packets <- p:
			case <-done:
				return
			}
		}
	}()

	s := &state{r: r, tr: tr}
	start := r.now()
	s.rescan(start)
	s.nextRescan = start.Add(rescanEvery)
	s.nextQuery, s.queryGap = start, time.Second
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		now := r.now()
		s.timers(now)
		select {
		case <-ctx.Done():
			// Changes not applied yet go in first, so that the goodbye
			// covers every interface the member publishes on.
			r.mu.Lock()
			pending := r.pending
			r.pending = nil
			r.mu.Unlock()
			for _, c := range pending {
				s.apply(c, r.now())
			}
			s.goodbye()
			return nil
		case p, ok := <-packets:
			if !ok {
				return errors.New("mdns: the network connection closed")
			}
			s.handle(p, r.now())
		case <-r.kick:
			r.mu.Lock()
			pending := r.pending
			r.pending = nil
			r.mu.Unlock()
			for _, c := range pending {
				s.apply(c, r.now())
			}
		case <-ticker.C:
		}
	}
}

// state is the part of a running responder that only its goroutine uses.
type state struct {
	r          *Responder
	tr         transport
	ifaces     []iface
	cache      cache
	peers      []Peer
	announce   []announcement
	nextRescan time.Time
	nextQuery  time.Time
	queryGap   time.Duration
	sent       map[sentKey]time.Time // when each record was last multicast, per interface
	legacy     map[netip.Addr][]time.Time
}

// sentKey names a record multicast on an interface.
type sentKey struct {
	ifIndex int
	record  string
}

// recordKey identifies a record: its name, type and data.
func recordKey(r dnsmessage.Resource) string {
	var data string
	switch b := r.Body.(type) {
	case *dnsmessage.PTRResource:
		data = strings.ToLower(b.PTR.String())
	case *dnsmessage.SRVResource:
		data = fmt.Sprint(b.Priority, b.Weight, b.Port, strings.ToLower(b.Target.String()))
	case *dnsmessage.TXTResource:
		data = strings.Join(b.TXT, "\x00")
	case *dnsmessage.AResource:
		data = string(b.A[:])
	case *dnsmessage.AAAAResource:
		data = string(b.AAAA[:])
	case *dnsmessage.UnknownResource:
		data = string(b.Data)
	}
	return strings.ToLower(r.Header.Name.String()) + "/" + typeOf(r).String() + "/" + data
}

const (
	// minResend is how soon a record may be multicast again on the same
	// interface (RFC 6762 section 6).
	minResend = time.Second
	// legacyPerSecond bounds the unicast answers to one source.
	legacyPerSecond = 5
	// maxQuestions bounds the questions read from one query.
	maxQuestions = 32
	// maxRefresh bounds the refresh questions in one query.
	maxRefresh = 16
)

// markSent records that rrs were multicast on an interface now.
func (s *state) markSent(ifIndex int, rrs []rr, now time.Time) {
	if s.sent == nil {
		s.sent = map[sentKey]time.Time{}
	}
	if len(s.sent) > 4096 {
		for k, t := range s.sent {
			if now.Sub(t) > minResend {
				delete(s.sent, k)
			}
		}
	}
	for _, r := range rrs {
		s.sent[sentKey{ifIndex, recordKey(r.res)}] = now
	}
}

// recent leaves out the records multicast on the interface within the last
// second.
func (s *state) recent(ifIndex int, rrs []rr, now time.Time) []rr {
	return slices.DeleteFunc(slices.Clone(rrs), func(r rr) bool {
		t, ok := s.sent[sentKey{ifIndex, recordKey(r.res)}]
		return ok && now.Sub(t) < minResend
	})
}

// legacyAllowed reports whether a legacy unicast query from src may be
// answered now, at most a few a second per source.
func (s *state) legacyAllowed(src netip.Addr, now time.Time) bool {
	if s.legacy == nil {
		s.legacy = map[netip.Addr][]time.Time{}
	}
	if len(s.legacy) > 256 {
		clear(s.legacy)
	}
	recent := slices.DeleteFunc(s.legacy[src], func(t time.Time) bool { return now.Sub(t) >= time.Second })
	if len(recent) >= legacyPerSecond {
		s.legacy[src] = recent
		return false
	}
	s.legacy[src] = append(recent, now)
	return true
}

// announcement is one scheduled unsolicited response.
type announcement struct {
	at      time.Time
	ifIndex int // 0: every interface
	left    int
}

func (s *state) rescan(now time.Time) {
	ifaces, err := s.tr.interfaces()
	if err != nil {
		s.r.logf("mdns: listing interfaces: %v", err)
		return
	}
	if only := s.r.cfg.Interfaces; only != nil {
		ifaces = slices.DeleteFunc(ifaces, func(f iface) bool { return !only(f.name) })
	}
	for i := range ifaces {
		ifc := &ifaces[i]
		ifc.publish = !s.r.cfg.BrowseOnly && (s.r.cfg.Publish == nil || s.r.cfg.Publish(ifc.name, ifc.prefixes))
		old := slices.IndexFunc(s.ifaces, func(o iface) bool { return o.index == ifc.index })
		if old < 0 || !slices.Equal(s.ifaces[old].addrs, ifc.addrs) {
			s.r.addrGen.Add(1)
		}
		if old >= 0 && s.ifaces[old].publish && !ifc.publish {
			// No longer published here: a goodbye for all of it.
			s.sendRecords(s.ifaces[old], s.r.zone().all(s.ifaces[old].addrs), 0)
			continue
		}
		if old >= 0 && s.ifaces[old].publish && ifc.publish {
			// Addresses that went away get a goodbye, so the others do not
			// keep them, whatever they cached a moment ago.
			gone := slices.DeleteFunc(slices.Clone(s.ifaces[old].addrs), func(a netip.Addr) bool { return slices.Contains(ifc.addrs, a) })
			if len(gone) > 0 {
				z := s.r.zone()
				rrs := addrRecords(z.host, hostTTL, gone)
				s.sendRecords(*ifc, rrs, 0)
			}
		}
		if ifc.publish && (old < 0 || !s.ifaces[old].publish || !slices.Equal(s.ifaces[old].addrs, ifc.addrs)) {
			// A new interface or new addresses: announce there.
			s.announce = append(s.announce, announcement{at: now, ifIndex: ifc.index, left: announceCount})
		}
	}
	s.ifaces = ifaces
}

func (s *state) apply(c change, now time.Time) {
	if c.recheck {
		s.rescan(now)
	}
	if c.fresh {
		s.announce = append(s.announce, announcement{at: now, left: announceCount})
	}
}

func (s *state) timers(now time.Time) {
	if !now.Before(s.nextRescan) {
		s.rescan(now)
		s.nextRescan = now.Add(rescanEvery)
	}
	// Announcements.
	keep := s.announce[:0]
	for _, a := range s.announce {
		if now.Before(a.at) {
			keep = append(keep, a)
			continue
		}
		z := s.r.zone()
		for _, ifc := range s.ifaces {
			if ifc.publish && (a.ifIndex == 0 || a.ifIndex == ifc.index) {
				s.sendRecords(ifc, z.all(ifc.addrs), -1)
			}
		}
		if a.left--; a.left > 0 {
			a.at = now.Add(time.Second)
			keep = append(keep, a)
		}
	}
	s.announce = keep
	// Browsing: ask for the service at growing intervals, listing the
	// members already known so they need not answer, and refresh the
	// records of the members found before they expire.
	if !now.Before(s.nextQuery) {
		s.query([]dnsmessage.Question{{Name: name(ServiceName), Type: dnsmessage.TypePTR, Class: classIN}}, s.cache.knownServices(now, s.r.cfg.ID, s.peers))
		s.nextQuery = now.Add(s.queryGap)
		s.queryGap = min(2*s.queryGap, maxQueryGap)
	}
	if qs := s.cache.refresh(now, s.peers); len(qs) > 0 {
		for len(qs) > 0 {
			n := min(len(qs), maxRefresh)
			s.query(qs[:n], nil)
			qs = qs[n:]
		}
	}
	s.cache.expire(now)
	s.updatePeers(now)
}

// query sends a multicast query on every interface, with known answers.
func (s *state) query(qs []dnsmessage.Question, known []dnsmessage.Resource) {
	msg := dnsmessage.Message{Questions: qs, Answers: known}
	data, err := msg.Pack()
	if err != nil {
		s.r.logf("mdns: packing a query: %v", err)
		return
	}
	for _, ifc := range s.ifaces {
		s.sendAll(ifc, data)
	}
}

// sendRecords sends an unsolicited response with rrs on an interface. ttl
// -1 keeps each record's lifetime; 0 makes a goodbye.
func (s *state) sendRecords(ifc iface, rrs []rr, ttl int) {
	if len(ifc.addrs) == 0 && ttl != 0 {
		return
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}}
	for _, r := range rrs {
		res := r.res
		if ttl >= 0 {
			res.Header.TTL = uint32(ttl)
		}
		// A goodbye ends only its own record: with the cache-flush bit it
		// would also end the others of its set, such as the addresses
		// that stay.
		if r.unique && ttl != 0 {
			res.Header.Class |= cacheFlush
		}
		msg.Answers = append(msg.Answers, res)
	}
	data, err := msg.Pack()
	if err != nil {
		s.r.logf("mdns: packing a response: %v", err)
		return
	}
	if ttl != 0 {
		s.markSent(ifc.index, rrs, s.r.now())
	}
	s.sendAll(ifc, data)
}

// sendAll sends a packet to the multicast groups of the address families
// the interface has.
func (s *state) sendAll(ifc iface, data []byte) {
	if ifc.has4 {
		if err := s.tr.send(data, ifc.index, group4); err != nil {
			s.r.logf("mdns: sending on %s: %v", ifc.name, err)
		}
	}
	if ifc.has6 {
		if err := s.tr.send(data, ifc.index, group6); err != nil {
			s.r.logf("mdns: sending on %s: %v", ifc.name, err)
		}
	}
}

func (s *state) goodbye() {
	s.r.sendMu.Lock()
	defer s.r.sendMu.Unlock()
	s.r.stopped = true
	if s.r.cfg.BrowseOnly {
		return
	}
	z := s.r.zone()
	for _, ifc := range s.ifaces {
		if ifc.publish {
			s.sendRecords(ifc, z.all(ifc.addrs), 0)
		}
	}
}

func (s *state) handle(p packet, now time.Time) {
	msg, err := parse(p.data)
	if err != nil || msg.OpCode != 0 || msg.RCode != 0 {
		return
	}
	i := slices.IndexFunc(s.ifaces, func(f iface) bool { return f.index == p.ifIndex })
	if i < 0 {
		return
	}
	ifc := s.ifaces[i]
	// Only packets from the local link count (RFC 6762 section 11).
	if !onLink(ifc, p.src.Addr()) {
		return
	}
	if msg.Response {
		s.cache.add(msg, ifc.name, now)
		s.updatePeers(now)
		return
	}
	if ifc.publish {
		s.respond(msg, p, ifc, now)
	}
}

// newIface describes an interface with the given addresses and their
// networks: it publishes only the addresses Published allows.
func newIface(index int, name string, prefixes []netip.Prefix) iface {
	f := iface{index: index, name: name}
	for _, p := range prefixes {
		ip := p.Addr().Unmap()
		f.prefixes = append(f.prefixes, netip.PrefixFrom(ip, p.Bits()).Masked())
		if Published(ip) {
			f.addrs = append(f.addrs, ip)
			if ip.Is4() {
				f.has4 = true
			} else {
				f.has6 = true
			}
		}
	}
	slices.SortFunc(f.addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return f
}

func onLink(ifc iface, a netip.Addr) bool {
	a = a.Unmap()
	if a.Is6() && a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range ifc.prefixes {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// respond answers a query. A multicast answer leaves out the records sent
// on the interface within the last second; a legacy unicast answer goes to
// one source at most a few times a second.
func (s *state) respond(q *dnsmessage.Message, p packet, ifc iface, now time.Time) {
	if len(q.Questions) > maxQuestions {
		q.Questions = q.Questions[:maxQuestions]
	}
	answers, additionals := s.r.zone().answer(q, ifc.addrs)
	legacy := p.src.Port() != Port
	if !legacy {
		answers = s.recent(ifc.index, answers, now)
		additionals = s.recent(ifc.index, additionals, now)
	}
	if len(answers) == 0 || (legacy && !s.legacyAllowed(p.src.Addr(), now)) {
		return
	}
	resp := dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}}
	if legacy {
		// A legacy unicast query (RFC 6762 section 6.7) gets a unicast
		// answer that repeats the ID and the questions, with short
		// lifetimes and no cache-flush bits.
		resp.ID = q.ID
		resp.Questions = q.Questions
	}
	add := func(dst *[]dnsmessage.Resource, rrs []rr) {
		for _, r := range rrs {
			res := r.res
			if legacy {
				res.Header.TTL = min(res.Header.TTL, legacyTTL)
			} else if r.unique {
				res.Header.Class |= cacheFlush
			}
			*dst = append(*dst, res)
		}
	}
	add(&resp.Answers, answers)
	add(&resp.Additionals, additionals)
	data, err := resp.Pack()
	if err != nil {
		s.r.logf("mdns: packing an answer: %v", err)
		return
	}
	if len(data) > maxPacket {
		resp.Additionals = nil
		if data, err = resp.Pack(); err != nil {
			return
		}
	}
	if legacy {
		if err := s.tr.send(data, ifc.index, p.src); err != nil {
			s.r.logf("mdns: answering %v: %v", p.src, err)
		}
		return
	}
	s.markSent(ifc.index, answers, now)
	s.markSent(ifc.index, additionals, now)
	dst := group4
	if p.src.Addr().Is6() && !p.src.Addr().Is4In6() {
		dst = group6
	}
	gen := s.r.addrGen.Load()
	send := func() {
		s.r.sendMu.Lock()
		defer s.r.sendMu.Unlock()
		if s.r.stopped || s.r.addrGen.Load() != gen {
			return
		}
		if err := s.tr.send(data, ifc.index, dst); err != nil {
			s.r.logf("mdns: answering on %s: %v", ifc.name, err)
		}
	}
	// Answers that many responders give, such as the service's PTR
	// record, wait 20 to 120 ms, so the answers of the members do not
	// collide (RFC 6762 section 6).
	if slices.ContainsFunc(answers, func(r rr) bool { return !r.unique }) {
		time.AfterFunc(time.Duration(20+rand.IntN(100))*time.Millisecond, send)
		return
	}
	send()
}

func (s *state) updatePeers(now time.Time) {
	peers := s.cache.peers(s.r.cfg.ID, now)
	if slices.EqualFunc(peers, s.peers, func(a, b Peer) bool {
		return a.ID == b.ID && a.Port == b.Port && slices.Equal(a.TXT, b.TXT) && slices.Equal(a.Addrs, b.Addrs)
	}) {
		return
	}
	// A member lost may only have been off the network for a while, and
	// comes back without announcing itself, as when a firewall dropped its
	// packets: ask for the service again soon, at growing intervals as at
	// the start.
	if slices.ContainsFunc(s.peers, func(old Peer) bool {
		return !slices.ContainsFunc(peers, func(p Peer) bool { return p.ID == old.ID })
	}) {
		s.nextQuery, s.queryGap = now, time.Second
	}
	// A member found that was not among the peers may have lost this one
	// too, and its browse queries may be far apart by now, after the ones
	// it sent while it was off the network: announce this member once, so
	// that it finds this one as soon as this one found it.
	if len(s.announce) == 0 && slices.ContainsFunc(peers, func(p Peer) bool {
		return !slices.ContainsFunc(s.peers, func(old Peer) bool { return old.ID == p.ID })
	}) {
		s.announce = append(s.announce, announcement{at: now, left: 1})
	}
	s.peers = peers
	if s.r.cfg.OnPeers != nil {
		s.r.cfg.OnPeers(slices.Clone(peers))
	}
}
