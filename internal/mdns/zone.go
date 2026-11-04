// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package mdns

import (
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/HunterEwok/cbb/internal/netguard"
)

// Names and lifetimes of the records, after RFC 6762 and RFC 6763.
const (
	ServiceName  = "_cbb._tcp.local."
	servicesName = "_services._dns-sd._udp.local."

	hostTTL    = 120  // records that name a host: SRV, A, AAAA
	otherTTL   = 4500 // PTR and TXT
	legacyTTL  = 10   // the most a legacy unicast answer may carry
	cacheFlush = 0x8000
	classIN    = dnsmessage.ClassINET
	typeNSEC   = dnsmessage.Type(47)
)

// zone is what one member publishes: its service instance, its own host
// name.
type zone struct {
	instance string // <device ID>._cbb._tcp.local.
	host     string // cb-<device ID>.local.
	port     uint16
	txt      []string
}

func newZone(id string, port uint16, txt []string) *zone {
	return &zone{
		instance: id + "." + ServiceName,
		host:     "cb-" + id + ".local.",
		port:     port,
		txt:      slices.Clone(txt),
	}
}

// Published reports whether an address may be published: private IPv4,
// unique-local IPv6 and link-local IPv6, and 100.64.0.0/10 when the
// setting CBB_HOME_CGNAT counts it as home (netguard.SetCGNAT). Other
// addresses would be reachable from outside the home network or are not
// meant for it.
func Published(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is4() {
		return a.IsPrivate() || netguard.InCGNAT(a)
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func sameName(n dnsmessage.Name, s string) bool { return strings.EqualFold(n.String(), s) }

// rr is one resource record with its owner's rules.
type rr struct {
	res    dnsmessage.Resource
	unique bool // the cache-flush bit is set on multicast answers
}

func (z *zone) ptr() rr {
	return rr{res: dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(ServiceName), Class: classIN, TTL: otherTTL},
		Body:   &dnsmessage.PTRResource{PTR: name(z.instance)},
	}}
}

func (z *zone) servicesPTR() rr {
	return rr{res: dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(servicesName), Class: classIN, TTL: otherTTL},
		Body:   &dnsmessage.PTRResource{PTR: name(ServiceName)},
	}}
}

func (z *zone) srv() rr {
	return rr{unique: true, res: dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(z.instance), Class: classIN, TTL: hostTTL},
		Body:   &dnsmessage.SRVResource{Target: name(z.host), Port: z.port},
	}}
}

func (z *zone) txtRR() rr {
	txt := z.txt
	if len(txt) == 0 {
		txt = []string{""} // a TXT record holds at least one string
	}
	return rr{unique: true, res: dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(z.instance), Class: classIN, TTL: otherTTL},
		Body:   &dnsmessage.TXTResource{TXT: txt},
	}}
}

// addrs returns the A and AAAA records of host for the addresses of one
// interface, followed by an NSEC record that says which of the two types the
// name has, so a resolver does not wait for the missing one.
func addrs(host string, ttl uint32, ips []netip.Addr) []rr {
	var out []rr
	var has4, has6 bool
	for _, ip := range ips {
		h := dnsmessage.ResourceHeader{Name: name(host), Class: classIN, TTL: ttl}
		if ip.Is4() {
			has4 = true
			out = append(out, rr{unique: true, res: dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: ip.As4()}}})
		} else {
			has6 = true
			out = append(out, rr{unique: true, res: dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}}})
		}
	}
	if has4 || has6 {
		out = append(out, nsec(host, ttl, has4, has6))
	}
	return out
}

// addrRecords returns the A and AAAA records of host for addresses,
// without the NSEC record that addrs adds.
func addrRecords(host string, ttl uint32, ips []netip.Addr) []rr {
	return slices.DeleteFunc(addrs(host, ttl, ips), func(r rr) bool { return typeOf(r.res) == typeNSEC })
}

// nsec returns the NSEC record of RFC 6762 section 6.1 for a host name that
// has A records, AAAA records or both.
func nsec(host string, ttl uint32, has4, has6 bool) rr {
	// Next domain name: the name itself, uncompressed. Then the type bit
	// map, window 0: A is type 1, AAAA is type 28.
	data := appendWireName(nil, host)
	bitmap := make([]byte, 4)
	if has4 {
		bitmap[0] |= 0x40 // type 1
	}
	if has6 {
		bitmap[3] |= 0x08 // type 28
	}
	n := len(bitmap)
	for n > 0 && bitmap[n-1] == 0 {
		n--
	}
	data = append(data, 0, byte(n))
	data = append(data, bitmap[:n]...)
	return rr{unique: true, res: dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name(host), Class: classIN, TTL: ttl},
		Body:   &dnsmessage.UnknownResource{Type: typeNSEC, Data: data},
	}}
}

// appendWireName appends a fully qualified name in DNS wire format.
func appendWireName(b []byte, s string) []byte {
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// all returns every record the zone publishes on an interface with the
// given addresses, for announcements and goodbyes.
func (z *zone) all(ips []netip.Addr) []rr {
	out := []rr{z.ptr(), z.srv(), z.txtRR()}
	out = append(out, addrs(z.host, hostTTL, ips)...)
	return out
}

// answer returns the answers and additional records for the questions of a
// query that arrived on an interface with the given addresses. Records the
// querier listed as known answers, with at least half their lifetime left,
// are left out (RFC 6762 section 7.1).
func (z *zone) answer(q *dnsmessage.Message, ips []netip.Addr) (answers, additionals []rr) {
	if len(ips) == 0 {
		return nil, nil
	}
	hostRRs := addrs(z.host, hostTTL, ips)
	for _, question := range q.Questions {
		t := question.Type
		any := t == dnsmessage.TypeALL
		switch {
		case sameName(question.Name, ServiceName) && (t == dnsmessage.TypePTR || any):
			answers = append(answers, z.ptr())
			additionals = append(additionals, z.srv(), z.txtRR())
			additionals = append(additionals, hostRRs...)
		case sameName(question.Name, servicesName) && (t == dnsmessage.TypePTR || any):
			answers = append(answers, z.servicesPTR())
		case sameName(question.Name, z.instance):
			if t == dnsmessage.TypeSRV || any {
				answers = append(answers, z.srv())
				additionals = append(additionals, hostRRs...)
			}
			if t == dnsmessage.TypeTXT || any {
				answers = append(answers, z.txtRR())
			}
		case sameName(question.Name, z.host):
			answers = append(answers, hostAnswers(hostRRs, t)...)
		}
	}
	answers = suppress(dedup(answers), q.Answers)
	additionals = suppress(dedup(additionals), q.Answers)
	// An additional record that is already an answer is not repeated.
	additionals = slices.DeleteFunc(additionals, func(a rr) bool {
		return slices.ContainsFunc(answers, func(b rr) bool { return sameRecord(a.res, b.res) })
	})
	return answers, additionals
}

// hostAnswers picks the address records a question for a host name asks
// for. A question for a type the name does not have gets the NSEC record,
// which says so.
func hostAnswers(rrs []rr, t dnsmessage.Type) []rr {
	var out, nsecRRs []rr
	for _, r := range rrs {
		switch r.res.Body.(type) {
		case *dnsmessage.AResource:
			if t == dnsmessage.TypeA || t == dnsmessage.TypeALL {
				out = append(out, r)
			}
		case *dnsmessage.AAAAResource:
			if t == dnsmessage.TypeAAAA || t == dnsmessage.TypeALL {
				out = append(out, r)
			}
		default:
			nsecRRs = append(nsecRRs, r)
		}
	}
	if len(out) == 0 && (t == dnsmessage.TypeA || t == dnsmessage.TypeAAAA) {
		return nsecRRs
	}
	return out
}

func dedup(rrs []rr) []rr {
	var out []rr
	for _, r := range rrs {
		if !slices.ContainsFunc(out, func(o rr) bool { return sameRecord(o.res, r.res) }) {
			out = append(out, r)
		}
	}
	return out
}

func suppress(rrs []rr, known []dnsmessage.Resource) []rr {
	return slices.DeleteFunc(rrs, func(r rr) bool {
		return slices.ContainsFunc(known, func(k dnsmessage.Resource) bool {
			return sameRecord(k, r.res) && k.Header.TTL >= r.res.Header.TTL/2
		})
	})
}

// sameRecord reports whether two records have the same name, type, class
// (ignoring the cache-flush bit) and data.
func sameRecord(a, b dnsmessage.Resource) bool {
	if !strings.EqualFold(a.Header.Name.String(), b.Header.Name.String()) ||
		a.Header.Class&^cacheFlush != b.Header.Class&^cacheFlush {
		return false
	}
	switch x := a.Body.(type) {
	case *dnsmessage.PTRResource:
		y, ok := b.Body.(*dnsmessage.PTRResource)
		return ok && strings.EqualFold(x.PTR.String(), y.PTR.String())
	case *dnsmessage.SRVResource:
		y, ok := b.Body.(*dnsmessage.SRVResource)
		return ok && x.Port == y.Port && x.Priority == y.Priority && x.Weight == y.Weight &&
			strings.EqualFold(x.Target.String(), y.Target.String())
	case *dnsmessage.TXTResource:
		y, ok := b.Body.(*dnsmessage.TXTResource)
		return ok && slices.Equal(x.TXT, y.TXT)
	case *dnsmessage.AResource:
		y, ok := b.Body.(*dnsmessage.AResource)
		return ok && x.A == y.A
	case *dnsmessage.AAAAResource:
		y, ok := b.Body.(*dnsmessage.AAAAResource)
		return ok && x.AAAA == y.AAAA
	case *dnsmessage.UnknownResource:
		y, ok := b.Body.(*dnsmessage.UnknownResource)
		return ok && x.Type == y.Type && string(x.Data) == string(y.Data)
	}
	return false
}
