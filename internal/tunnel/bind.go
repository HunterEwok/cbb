// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"fmt"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/conn"

	"github.com/HunterEwok/cbb/internal/netguard"
)

// newBind returns the UDP socket for a hub or a client: wireguard-go's
// default, whose receive skips the errors that only report an ICMP message
// for an earlier packet. On Windows a UDP socket reports a "port
// unreachable" for a packet it sent, for example to a client that went
// away, as an error on its next receive, and wireguard-go stops receiving
// for good on such an error: a hub would then hear no client again.
func newBind() conn.Bind { return icmpTolerantBind{conn.NewDefaultBind()} }

type icmpTolerantBind struct{ conn.Bind }

func (b icmpTolerantBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	for i, recv := range fns {
		fns[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			for {
				n, err := recv(packets, sizes, eps)
				if err == nil || !icmpReport(err) {
					return n, err
				}
			}
		}
	}
	return fns, actual, err
}

// clientBind is a client's UDP socket: it sends only where allowed says,
// its hub or the local end of the way over VLESS. A hub's socket answers
// its clients wherever they are, since WireGuard answers only peers that
// proved the group's keys.
type clientBind struct {
	conn.Bind
	allowed func(netip.Addr) bool
}

func (b clientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if a := ep.DstIP(); !b.allowed(a) {
		return fmt.Errorf("tunnel: %v: %w", a, netguard.ErrOutside)
	}
	return b.Bind.Send(bufs, ep)
}
