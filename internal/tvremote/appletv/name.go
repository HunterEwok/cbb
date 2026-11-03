// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package appletv

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/HunterEwok/cbb/internal/netguard"
)

// service is the mDNS service an Apple TV announces the Companion
// protocol in; its instance name is the name the TV shows in its Settings.
const service = "_companion-link._tcp.local."

// nameWait is how long Name waits for the TV to answer.
const nameWait = 2 * time.Second

// Name asks the home network, by one mDNS query, for the name the Apple TV
// at host announces, such as "Living Room"; it returns "" when the TV does
// not answer in time or host is not on the home network. A pairing names
// the TV by it when the user gives no name.
func Name(ctx context.Context, host string) string {
	ip := hostAddr(ctx, host)
	if !ip.IsValid() || !ip.Is4() || !netguard.Home(ip) {
		return ""
	}
	q, err := query()
	if err != nil {
		return ""
	}
	// A query from a port other than 5353 gets its answers by unicast,
	// to this socket (RFC 6762, section 6.7).
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return ""
	}
	defer c.Close()
	deadline := time.Now().Add(nameWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if _, err := c.WriteToUDPAddrPort(q, netip.AddrPortFrom(netip.AddrFrom4([4]byte{224, 0, 0, 251}), 5353)); err != nil {
		return ""
	}
	// Ask the TV itself too, which answers a direct query the same way.
	c.WriteToUDPAddrPort(q, netip.AddrPortFrom(ip, 5353))
	buf := make([]byte, 9000)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return ""
		}
		if from.Addr().Unmap() != ip {
			continue
		}
		if name := instance(buf[:n]); name != "" {
			return name
		}
	}
}

// hostAddr is the address of host, an address or a name with or without
// a port.
func hostAddr(ctx context.Context, host string) netip.Addr {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap()
	}
	as, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(as) == 0 {
		return netip.Addr{}
	}
	return as[0].Unmap()
}

// query is an mDNS question for the Companion service's instances.
func query() ([]byte, error) {
	name, err := dnsmessage.NewName(service)
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}}
	return m.Pack()
}

// instance is the first Companion instance an mDNS answer names, without
// the service's part: "Living Room" of "Living Room._companion-link._tcp.local.".
func instance(msg []byte) string {
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil || !m.Response {
		return ""
	}
	for _, rs := range [][]dnsmessage.Resource{m.Answers, m.Additionals} {
		for _, r := range rs {
			p, ok := r.Body.(*dnsmessage.PTRResource)
			if !ok || !strings.EqualFold(r.Header.Name.String(), service) {
				continue
			}
			full := p.PTR.String()
			if len(full) <= len(service)+1 || !strings.EqualFold(full[len(full)-len(service)-1:], "."+service) {
				continue
			}
			if name := unescape(full[:len(full)-len(service)-1]); name != "" {
				return name
			}
		}
	}
	return ""
}

// unescape undoes the escapes dnsmessage puts in a label: \. and \\, and
// \DDD for bytes such as a space.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			n := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if n < 256 {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i+1])
		i++
	}
	return strings.TrimSpace(b.String())
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
