// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"

	"github.com/HunterEwok/cbb/internal/third_party/netstack"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// A client of a phone's hub, sending TCP and UDP to any address through a
// tunnel it configured by hand, reaches only the app's member listener:
// no other port of the phone and nothing beyond it.
func TestPhoneHubReachesOnlyTheMemberListener(t *testing.T) {
	// The phone's other services, on its loopback address.
	var hits atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(b); err != nil {
				return
			}
			hits.Add(1)
		}
	}()

	hubPriv, _ := NewKey()
	hubPub, _ := PublicKey(hubPriv)
	clientPriv, _ := NewKey()
	clientPub, _ := PublicKey(clientPriv)
	psk, _ := tunnel.NewPresharedKey()
	clients, _ := json.Marshal([]Client{{Device: phoneID, Key: clientPub, PSK: psk[:]}})
	const hubDevice = "0123456789abcdef0123456789abcdef"
	hub, err := StartHub(hubPriv, hubDevice, echo(t), "", string(clients))
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	hubAddr, _ := tunnel.Addr(hubDevice)
	clientAddr, _ := tunnel.Addr(phoneID)

	tdev, n, err := netstack.CreateNetTUN([]netip.Addr{clientAddr, netip.MustParseAddr("10.0.0.2")}, nil, tunnel.MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		hex.EncodeToString(clientPriv), hex.EncodeToString(hubPub), hex.EncodeToString(psk[:]), hub.UDPPort())
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	// The tunnel works: the member port leads to the member listener.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	c, err := n.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(hubAddr, tunnel.Port))
	cancel()
	if err != nil {
		t.Fatalf("the member port: %v", err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("hi"))
	b := make([]byte, 2)
	if _, err := c.Read(b); err != nil || string(b) != "hi" {
		t.Fatalf("the member listener answered %q, %v", b, err)
	}
	c.Close()

	lnPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	pcPort := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	for _, to := range []netip.AddrPort{
		netip.AddrPortFrom(hubAddr, lnPort),
		netip.AddrPortFrom(hubAddr, 22),
		netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", lnPort)),
		netip.MustParseAddrPort("1.1.1.1:443"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := n.DialContextTCPAddrPort(ctx, to)
		cancel()
		if err == nil {
			c.Close()
			t.Errorf("a stream to %v was answered", to)
		}
	}
	for _, to := range []netip.AddrPort{
		netip.AddrPortFrom(hubAddr, pcPort),
		netip.AddrPortFrom(hubAddr, tunnel.Port),
		netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", pcPort)),
		netip.MustParseAddrPort("1.1.1.1:53"),
	} {
		from := netip.AddrPortFrom(clientAddr, 0)
		if to.Addr().Is4() {
			from = netip.MustParseAddrPort("10.0.0.2:0")
		}
		u, err := n.DialUDPAddrPort(from, to)
		if err != nil {
			continue
		}
		for range 3 {
			u.Write([]byte("a packet"))
		}
		u.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if k, err := u.Read(b); err == nil {
			t.Errorf("a packet to %v was answered: %q", to, b[:k])
		}
		u.Close()
	}
	time.Sleep(200 * time.Millisecond)
	if k := hits.Load(); k != 0 {
		t.Errorf("%d connections or packets reached the phone's other services", k)
	}
}
