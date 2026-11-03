// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// maxEntries bounds the cache, so a flood of records cannot exhaust
	// memory. A home group needs a few dozen.
	maxEntries = 1024
	// maxPerPacket bounds the records taken from one packet.
	maxPerPacket = 64
	// maxPeers bounds the members reported.
	maxPeers = 64
)

// A Peer is a member found by browsing.
type Peer struct {
	ID    string       // the device ID: the first label of the service instance name
	Port  uint16       // from the SRV record
	TXT   []string     // the strings of the TXT record
	Addrs []netip.Addr // link-local IPv6 addresses carry the interface as zone
}

// TXTValue returns the value of key in a TXT record of key=value strings.
func (p Peer) TXTValue(key string) (string, bool) {
	for _, s := range p.TXT {
		if k, v, ok := strings.Cut(s, "="); ok && strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

type entry struct {
	res      dnsmessage.Resource
	name     string // the lower-cased owner name
	zone     string // the interface a link-local address arrived on
	received time.Time
	expires  time.Time
	refresh  int // refresh queries sent, at 80, 85, 90 and 95 percent
	jitter   int // tenths of a percent added to each refresh point
}

// cache keeps the records of other members that browsing found.
type cache struct {
	byName map[string][]*entry
	count  int
	dirty  bool // the peers may have changed since peers last ran
	last   []Peer
}

// isDeviceID reports whether s is a device ID: 32 lowercase hex characters.
func isDeviceID(s string) bool {
	return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == ""
}

// relevant reports whether a record concerns cbb members: the
// service's PTR records, SRV and TXT records of its instances, and the
// addresses of member host names.
func relevant(name string, r dnsmessage.Resource) bool {
	switch r.Body.(type) {
	case *dnsmessage.PTRResource:
		return name == ServiceName
	case *dnsmessage.SRVResource, *dnsmessage.TXTResource:
		id, rest, _ := strings.Cut(name, ".")
		return rest == ServiceName && isDeviceID(id)
	case *dnsmessage.AResource, *dnsmessage.AAAAResource:
		label, rest, _ := strings.Cut(name, ".")
		return rest == "local." && strings.HasPrefix(label, "cb-") && isDeviceID(label[3:])
	}
	return false
}

// maxTTL is the longest lifetime a received record keeps: the one
// cbb itself gives its records of that type, so a record from a
// device that is gone expires in time.
func maxTTL(r dnsmessage.Resource) uint32 {
	switch r.Body.(type) {
	case *dnsmessage.PTRResource, *dnsmessage.TXTResource:
		return otherTTL
	}
	return hostTTL
}

func (c *cache) all() []*entry {
	out := make([]*entry, 0, c.count)
	for _, es := range c.byName {
		out = append(out, es...)
	}
	return out
}

// add stores the records of a response that arrived on the interface named
// zone.
func (c *cache) add(msg *dnsmessage.Message, zone string, now time.Time) {
	if c.byName == nil {
		c.byName = map[string][]*entry{}
	}
	records := append(slices.Clone(msg.Answers), msg.Additionals...)
	if len(records) > maxPerPacket {
		records = records[:maxPerPacket]
	}
	for _, r := range records {
		name := strings.ToLower(r.Header.Name.String())
		if !relevant(name, r) {
			continue
		}
		es := c.byName[name]
		// A record with the cache-flush bit replaces the others of its
		// name and type that arrived more than a second ago (RFC 6762
		// section 10.2).
		if r.Header.Class&cacheFlush != 0 {
			for _, e := range es {
				if typeOf(e.res) == typeOf(r) && now.Sub(e.received) > time.Second && e.expires.After(now.Add(time.Second)) {
					e.expires = now.Add(time.Second)
				}
			}
		}
		ttl := time.Duration(min(r.Header.TTL, maxTTL(r))) * time.Second
		if r.Header.TTL == 0 {
			ttl = time.Second // a goodbye
		}
		e := &entry{res: r, name: name, received: now, expires: now.Add(ttl), jitter: rand.IntN(21)}
		if _, ok := r.Body.(*dnsmessage.AAAAResource); ok {
			e.zone = zone
		}
		c.dirty = true
		if i := slices.IndexFunc(es, func(o *entry) bool { return sameRecord(o.res, r) && o.zone == e.zone }); i >= 0 {
			es[i] = e
			continue
		}
		c.byName[name] = append(es, e)
		c.count++
	}
	for c.count > maxEntries {
		c.evictOldest()
	}
}

// evictOldest drops the record received longest ago.
func (c *cache) evictOldest() {
	var oldest *entry
	for _, e := range c.all() {
		if oldest == nil || e.received.Before(oldest.received) {
			oldest = e
		}
	}
	c.remove(oldest)
}

func (c *cache) remove(e *entry) {
	es := c.byName[e.name]
	if i := slices.Index(es, e); i >= 0 {
		es = slices.Delete(es, i, i+1)
		c.count--
		c.dirty = true
	}
	if len(es) == 0 {
		delete(c.byName, e.name)
	} else {
		c.byName[e.name] = es
	}
}

// expire removes the records whose lifetime has ended.
func (c *cache) expire(now time.Time) {
	for _, e := range c.all() {
		if !now.Before(e.expires) {
			c.remove(e)
		}
	}
}

func typeOf(r dnsmessage.Resource) dnsmessage.Type {
	switch b := r.Body.(type) {
	case *dnsmessage.PTRResource:
		return dnsmessage.TypePTR
	case *dnsmessage.SRVResource:
		return dnsmessage.TypeSRV
	case *dnsmessage.TXTResource:
		return dnsmessage.TypeTXT
	case *dnsmessage.AResource:
		return dnsmessage.TypeA
	case *dnsmessage.AAAAResource:
		return dnsmessage.TypeAAAA
	case *dnsmessage.UnknownResource:
		return b.Type
	}
	return 0
}

// refresh returns the questions to ask so that the records of the members
// found do not expire while the members are still there: at 80, 85, 90 and
// 95 percent of a record's lifetime, each with up to 2 percent added at
// random, as RFC 6762 section 5.2 suggests. Only the records that make up
// a peer are refreshed, not whatever else arrived.
func (c *cache) refresh(now time.Time, peers []Peer) []dnsmessage.Question {
	names := map[string]bool{}
	for _, p := range peers {
		names[strings.ToLower(p.ID)+"."+ServiceName] = true
		names["cb-"+strings.ToLower(p.ID)+".local."] = true
	}
	var qs []dnsmessage.Question
	for _, e := range c.all() {
		if e.res.Header.TTL == 0 || e.refresh >= 4 || !(names[e.name] || e.name == ServiceName) {
			continue
		}
		life := e.expires.Sub(e.received)
		due := e.received.Add(life * time.Duration(800+50*e.refresh+e.jitter) / 1000)
		if now.Before(due) {
			continue
		}
		e.refresh++
		q := dnsmessage.Question{Name: e.res.Header.Name, Type: typeOf(e.res), Class: classIN}
		if !slices.ContainsFunc(qs, func(o dnsmessage.Question) bool {
			return o.Type == q.Type && strings.EqualFold(o.Name.String(), q.Name.String())
		}) {
			qs = append(qs, q)
		}
	}
	return qs
}

// knownServices returns the service's PTR records with more than half of
// their lifetime left, with their remaining TTL, to list as known answers
// in a browse query (RFC 6762 section 7.1). The PTR record of another
// member that is not among the members found is left out: its other
// records expired, as when it was off the network for a while, and it must
// answer again.
func (c *cache) knownServices(now time.Time, self string, peers []Peer) []dnsmessage.Resource {
	names := map[string]bool{strings.ToLower(self) + "." + ServiceName: true}
	for _, p := range peers {
		names[strings.ToLower(p.ID)+"."+ServiceName] = true
	}
	var out []dnsmessage.Resource
	for _, e := range c.byName[ServiceName] {
		left := e.expires.Sub(now)
		ptr, ok := e.res.Body.(*dnsmessage.PTRResource)
		if left <= e.expires.Sub(e.received)/2 || !ok || !names[strings.ToLower(ptr.PTR.String())] {
			continue
		}
		r := e.res
		r.Header.TTL = uint32(left / time.Second)
		r.Header.Class &^= cacheFlush
		out = append(out, r)
	}
	return out
}

// peers returns the members in the cache, except self, sorted by ID. It
// recomputes them only when the cache changed.
func (c *cache) peers(self string, now time.Time) []Peer {
	if !c.dirty {
		return c.last
	}
	c.dirty = false
	var out []Peer
	for _, e := range c.byName[ServiceName] {
		ptr := e.res.Body.(*dnsmessage.PTRResource)
		if !now.Before(e.expires) || len(out) >= maxPeers {
			continue
		}
		instance := strings.ToLower(ptr.PTR.String())
		id, rest, _ := strings.Cut(instance, ".")
		if rest != ServiceName || !isDeviceID(id) || id == strings.ToLower(self) {
			continue
		}
		if slices.ContainsFunc(out, func(p Peer) bool { return p.ID == id }) {
			continue
		}
		p := Peer{ID: id}
		var target string
		for _, f := range c.byName[instance] {
			if !now.Before(f.expires) {
				continue
			}
			switch b := f.res.Body.(type) {
			case *dnsmessage.SRVResource:
				p.Port, target = b.Port, strings.ToLower(b.Target.String())
			case *dnsmessage.TXTResource:
				p.TXT = slices.Clone(b.TXT)
			}
		}
		if target == "" {
			continue
		}
		for _, f := range c.byName[target] {
			if !now.Before(f.expires) {
				continue
			}
			var a netip.Addr
			switch b := f.res.Body.(type) {
			case *dnsmessage.AResource:
				a = netip.AddrFrom4(b.A)
			case *dnsmessage.AAAAResource:
				a = netip.AddrFrom16(b.AAAA)
				if a.IsLinkLocalUnicast() {
					a = a.WithZone(f.zone)
				}
			default:
				continue
			}
			if Published(a) && !slices.Contains(p.Addrs, a) {
				p.Addrs = append(p.Addrs, a)
			}
		}
		slices.SortFunc(p.Addrs, func(x, y netip.Addr) int { return x.Compare(y) })
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Peer) int { return strings.Compare(a.ID, b.ID) })
	c.last = out
	return out
}
