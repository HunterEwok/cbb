// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"

	"github.com/HunterEwok/cbb/internal/third_party/netstack"
)

// hostOutside stands for the internet and for the services of the hub's
// own computer: TCP and UDP ports on its loopback addresses that count
// whatever reaches them.
type hostOutside struct {
	tcp, udp []netip.AddrPort
	hits     atomic.Int64
}

func newHostOutside(t *testing.T) *hostOutside {
	t.Helper()
	o := &hostOutside{}
	for _, a := range []string{"127.0.0.1:0", "[::1]:0"} {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			t.Logf("no listener on %s: %v", a, err)
			continue
		}
		t.Cleanup(func() { ln.Close() })
		o.tcp = append(o.tcp, ln.Addr().(*net.TCPAddr).AddrPort())
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				o.hits.Add(1)
				c.Close()
			}
		}()
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		o.udp = append(o.udp, pc.LocalAddr().(*net.UDPAddr).AddrPort())
		go func() {
			b := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(b); err != nil {
					return
				}
				o.hits.Add(1)
			}
		}()
	}
	if len(o.tcp) == 0 {
		t.Fatal("no loopback address to listen on")
	}
	return o
}

// anyRouteClient is a tunnel to the hub that a hostile client configures
// by hand with an IPv4 address beside its own, sending everything, IPv4
// and IPv6, to the hub.
func anyRouteClient(t *testing.T, h testHub, d testDevice) *netstack.Net {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{d.addr, netip.MustParseAddr("10.0.0.2")}, nil, MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, newBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		d.priv.hex(), h.dev.priv.Public().hex(), d.psk.hex(), h.endpoint())
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return tnet
}

// A client of a hub, sending TCP and UDP to any address through its
// tunnel, reaches only the hub's member port: neither the hub's computer
// nor the internet. The hub's stack in the process forwards nothing.
func TestTunnelReachesOnlyTheMemberPort(t *testing.T) {
	o := newHostOutside(t)
	a := newDevice(t)
	h := startHub(t, a.peer())
	n := anyRouteClient(t, h, a)

	// The tunnel works: the member port answers.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	c, err := n.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(h.dev.addr, Port))
	cancel()
	if err != nil {
		t.Fatalf("the member port through a tunnel that sends everything: %v", err)
	}
	c.Close()

	tcp := append([]netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:443"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
		netip.AddrPortFrom(h.dev.addr, 22),
		netip.AddrPortFrom(h.dev.addr, 10041),
	}, o.tcp...)
	for _, to := range tcp {
		ctx, cancel := context.WithTimeout(context.Background(), refuseWait)
		c, err := n.DialContextTCPAddrPort(ctx, to)
		cancel()
		if err == nil {
			c.Close()
			t.Errorf("a client's stream to %v was answered", to)
		}
	}
	udp := append([]netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
		netip.AddrPortFrom(h.dev.addr, 53),
		netip.AddrPortFrom(h.dev.addr, Port),
	}, o.udp...)
	for _, to := range udp {
		var from netip.AddrPort
		if to.Addr().Is4() {
			from = netip.MustParseAddrPort("10.0.0.2:0")
		} else {
			from = netip.AddrPortFrom(a.addr, 0)
		}
		pc, err := n.DialUDPAddrPort(from, to)
		if err != nil {
			continue
		}
		for range 3 {
			pc.Write([]byte("a packet"))
		}
		pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		b := make([]byte, 64)
		if k, err := pc.Read(b); err == nil {
			t.Errorf("a client's packet to %v was answered: %q", to, b[:k])
		}
		pc.Close()
	}
	time.Sleep(200 * time.Millisecond)
	if k := o.hits.Load(); k != 0 {
		t.Errorf("%d connections or packets reached the hub's computer", k)
	}
}
