// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"

	"github.com/HunterEwok/cbb/internal/third_party/netstack"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// The tunnel's cases (W19, W20, S3, S4, S5) play a client of the hub with a
// WireGuard of their own that, unlike the service's, routes the whole
// tunnel prefix to the hub, so that the hub's side alone decides what
// answers:
//
//	forge -state DIR -endpoint HOST:PORT ports        each TCP port of the hub that answers
//	forge -state DIR -endpoint HOST:PORT reach:ID,... whether other members answer through the hub
//	forge -state DIR -endpoint HOST:PORT stranger     a key the group does not know
//	forge -state DIR -hub-state DIR2 member           whether the hub of DIR2's offer answers
//
// Each prints one line per case: "ports: open 8764", "reach ID: no answer"
// or "reach ID: answered", "stranger: no answer" or "stranger: answered", "member: answered" or
// "member: no answer". With -hub-state, the member's own keys go to the
// hub of another device's offer, with that device's preshared key, as a
// member of another group that learned it would (W33, S8).

// tunnelCase tells whether c is one of the tunnel's cases.
func tunnelCase(c string) bool {
	name, _, _ := strings.Cut(c, ":")
	return name == "ports" || name == "reach" || name == "stranger" || name == "member"
}

// runTunnel runs the tunnel's cases as the client whose service state is in
// state, to its first hub, at endpoint or the hub's first address.
func runTunnel(state, hubState, endpoint string, cases []string) error {
	st, err := tunnel.LoadState(state)
	if err != nil {
		return err
	}
	offers := st
	if hubState != "" {
		if offers, err = tunnel.LoadState(hubState); err != nil {
			return err
		}
	}
	if len(offers.Hubs) == 0 {
		return errors.New("the state has no hub's offer")
	}
	h := offers.Hubs[0]
	ep := netip.AddrPort{}
	if endpoint != "" {
		if ep, err = netip.ParseAddrPort(endpoint); err != nil {
			return err
		}
	} else if len(h.Endpoints) > 0 {
		ep = h.Endpoints[0]
	} else {
		return errors.New("the hub's offer has no address; give -endpoint")
	}
	hubAddr, err := tunnel.Addr(h.Device)
	if err != nil {
		return err
	}
	self, err := deviceAddr(state)
	if err != nil {
		return err
	}
	for _, c := range cases {
		name, arg, _ := strings.Cut(c, ":")
		switch name {
		case "ports":
			tn, stop, err := startProbe(st.Key, h.PresharedKey, self, h, ep)
			if err != nil {
				return err
			}
			if _, err := dialTunnel(tn, netip.AddrPortFrom(hubAddr, tunnel.Port), 20*time.Second); err != nil {
				stop()
				return fmt.Errorf("the hub's member port does not answer through the tunnel: %v", err)
			}
			var open []string
			for p := 1; p <= 65535; p++ {
				// Below 10000 every port, above it a sample: the hub's
				// stack has one listener, and a closed port answers at once.
				if p > 10000 && p%97 != 0 {
					continue
				}
				if c, err := dialTunnel(tn, netip.AddrPortFrom(hubAddr, uint16(p)), 3*time.Second); err == nil {
					c.Close()
					open = append(open, strconv.Itoa(p))
				}
			}
			stop()
			fmt.Printf("ports: open %s\n", strings.Join(open, " "))
		case "member":
			tn, stop, err := startProbe(st.Key, h.PresharedKey, self, h, ep)
			if err != nil {
				return err
			}
			if c, err := dialTunnel(tn, netip.AddrPortFrom(hubAddr, tunnel.Port), 20*time.Second); err == nil {
				c.Close()
				fmt.Println("member: answered")
			} else {
				fmt.Println("member: no answer")
			}
			stop()
		case "reach":
			tn, stop, err := startProbe(st.Key, h.PresharedKey, self, h, ep)
			if err != nil {
				return err
			}
			for _, id := range strings.Split(arg, ",") {
				a, err := tunnel.Addr(id)
				if err != nil {
					stop()
					return err
				}
				if c, err := dialTunnel(tn, netip.AddrPortFrom(a, tunnel.Port), 10*time.Second); err == nil {
					c.Close()
					fmt.Printf("reach %s: answered\n", id)
				} else {
					fmt.Printf("reach %s: no answer\n", id)
				}
			}
			stop()
		case "stranger":
			key, err := tunnel.NewPrivateKey()
			if err != nil {
				return err
			}
			psk, err := tunnel.NewPresharedKey()
			if err != nil {
				return err
			}
			tn, stop, err := startProbe(key, psk, tunnel.GuestAddr(key.Public()), h, ep)
			if err != nil {
				return err
			}
			if c, err := dialTunnel(tn, netip.AddrPortFrom(hubAddr, tunnel.Port), 20*time.Second); err == nil {
				c.Close()
				fmt.Println("stranger: answered")
			} else {
				fmt.Println("stranger: no answer")
			}
			stop()
		default:
			return fmt.Errorf("no case %q", c)
		}
	}
	return nil
}

// deviceAddr is the tunnel address of the device whose state is in dir.
func deviceAddr(dir string) (netip.Addr, error) {
	id, err := loadID(dir)
	if err != nil {
		return netip.Addr{}, err
	}
	return tunnel.Addr(id)
}

// startProbe brings up a WireGuard client with key that routes the whole
// tunnel prefix to the hub h at ep.
func startProbe(key, psk tunnel.Key, self netip.Addr, h tunnel.HubLink, ep netip.AddrPort) (*netstack.Net, func(), error) {
	tdev, tn, err := netstack.CreateNetTUN([]netip.Addr{self}, nil, tunnel.MTU)
	if err != nil {
		return nil, nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	pub := h.PublicKey
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(key[:]))
	if o := h.Obfuscation; o != nil {
		fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\n", o.JC, o.JMin, o.JMax, o.S1, o.S2, o.S3, o.S4)
		for i, r := range []tunnel.Range{o.H1, o.H2, o.H3, o.H4} {
			fmt.Fprintf(&b, "h%d=%d-%d\n", i+1, r.Min, r.Max)
		}
		fmt.Fprintf(&b, "header_protection_key=%s\n", hex.EncodeToString(o.HeaderKey[:]))
	}
	fmt.Fprintf(&b, "public_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=fd00:cbb::/32\nallowed_ip=fd00:cbc::/32\n",
		hex.EncodeToString(pub[:]), hex.EncodeToString(psk[:]), ep)
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, err
	}
	return tn, dev.Close, nil
}

func dialTunnel(tn *netstack.Net, to netip.AddrPort, timeout time.Duration) (interface{ Close() error }, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return tn.DialContextTCPAddrPort(ctx, to)
}
