// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package cbbtun is the phones' tunnel to the group's hub, for sync away
// from home. gomobile binds it into a framework for the iPhone app and an
// AAR for the Android app, so the phones run the same WireGuard as the Go
// members, in the app's own process: no Network Extension and no
// VpnService.
//
// The tunnel opens a TCP port on the loopback address that leads to the
// hub's member port inside the tunnel. The kits dial it with their own
// member TLS, so another app that connects to the port reaches only the
// hub's member TLS. The API keeps to the types gomobile binds: strings,
// byte slices, integers and errors.
package cbbtun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
)

// dialTimeout bounds one connection through the tunnel to the hub.
const dialTimeout = 20 * time.Second

// NewKey returns a new WireGuard private key, 32 bytes, for the device's
// tunnel_key.
func NewKey() ([]byte, error) {
	k, err := tunnel.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return k[:], nil
}

// PublicKey returns the public key of a private key, the tunnel_key the
// device's hello carries.
func PublicKey(private []byte) ([]byte, error) {
	k, err := key(private, "private key")
	if err != nil {
		return nil, err
	}
	pub := k.Public()
	return pub[:], nil
}

// Tunnel is a running tunnel to the hub with its loopback port.
type Tunnel struct {
	client *tunnel.Client
	vless  *vless.Client // the way to the hub's forwarder over VLESS, or nil
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Start brings the tunnel up with the hub's offer (docs/protocol.md,
// section 11): the device's private key, the offer's preshared key and hub
// key, the device IDs of this device and of the hub, and one of the offer's
// endpoints ("ip:port" or "[ipv6]:port"), the offer's obfuscation
// settings as JSON, or "" for plain WireGuard, and its VLESS settings as
// JSON, or "" without VLESS. With VLESS the tunnel reaches the hub only
// over VLESS to its forwarder, and endpoint is not used. Nothing goes to
// the hub before a connection to Port.
func Start(private, psk, hubKey []byte, device, hub, endpoint, obfuscation, vlessSettings string) (*Tunnel, error) {
	priv, err := key(private, "private key")
	if err != nil {
		return nil, err
	}
	pre, err := key(psk, "preshared key")
	if err != nil {
		return nil, err
	}
	hk, err := key(hubKey, "hub key")
	if err != nil {
		return nil, err
	}
	self, err := tunnel.Addr(device)
	if err != nil {
		return nil, err
	}
	hubAddr, err := tunnel.Addr(hub)
	if err != nil {
		return nil, err
	}
	var link *tunnel.VLESS
	if vlessSettings != "" {
		link = new(tunnel.VLESS)
		if err := json.Unmarshal([]byte(vlessSettings), link); err != nil {
			return nil, fmt.Errorf("cbbtun: the VLESS settings: %w", err)
		}
		if err := link.Check(); err != nil {
			return nil, fmt.Errorf("cbbtun: the VLESS settings: %w", err)
		}
	}
	var ep netip.AddrPort
	if link == nil {
		if ep, err = netip.ParseAddrPort(endpoint); err != nil {
			return nil, fmt.Errorf("cbbtun: %q is not an endpoint: %w", endpoint, err)
		}
	}
	var obf *tunnel.Obfuscation
	if obfuscation != "" {
		obf = new(tunnel.Obfuscation)
		if err := json.Unmarshal([]byte(obfuscation), obf); err != nil {
			return nil, fmt.Errorf("cbbtun: the obfuscation settings: %w", err)
		}
	}
	var vc *vless.Client
	if link != nil {
		if vc, err = vless.Dial(*link); err != nil {
			return nil, err
		}
		ep = vc.Addr()
	}
	client, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: priv, PresharedKey: pre, Addr: self,
		HubPublicKey: hk, HubAddr: hubAddr, Endpoint: ep, Obfuscation: obf})
	if err != nil {
		closeVLESS(vc)
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		client.Close()
		closeVLESS(vc)
		return nil, fmt.Errorf("cbbtun: opening the loopback port: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &Tunnel{client: client, vless: vc, ln: ln, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
	t.wg.Add(1)
	go t.serve()
	return t, nil
}

// Port is the loopback TCP port, on 127.0.0.1, that leads to the hub.
func (t *Tunnel) Port() int { return t.ln.Addr().(*net.TCPAddr).Port }

// SetEndpoint points the tunnel at another of the hub's endpoints, for
// example when the one in use does not answer. Over VLESS there is only
// the one way, and it does nothing.
func (t *Tunnel) SetEndpoint(endpoint string) error {
	if t.vless != nil {
		return nil
	}
	ep, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return fmt.Errorf("cbbtun: %q is not an endpoint: %w", endpoint, err)
	}
	return t.client.SetEndpoint(ep)
}

// Close stops the tunnel, the loopback port and every connection through
// them.
func (t *Tunnel) Close() error {
	t.cancel()
	t.ln.Close()
	t.mu.Lock()
	for c := range t.conns {
		c.Close()
	}
	t.mu.Unlock()
	t.wg.Wait()
	err := t.client.Close()
	closeVLESS(t.vless)
	return err
}

func closeVLESS(c *vless.Client) {
	if c != nil {
		c.Close()
	}
}

func (t *Tunnel) serve() {
	defer t.wg.Done()
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		if !t.track(c) {
			c.Close()
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer t.untrack(c)
			ctx, cancel := context.WithTimeout(t.ctx, dialTimeout)
			hub, err := t.client.Dial(ctx)
			cancel()
			if err != nil {
				return
			}
			if !t.track(hub) {
				hub.Close()
				return
			}
			defer t.untrack(hub)
			splice(c, hub)
		}()
	}
}

// track keeps a connection so that Close closes it; it refuses one once the
// tunnel is closing.
func (t *Tunnel) track(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ctx.Err() != nil {
		return false
	}
	t.conns[c] = struct{}{}
	return true
}

func (t *Tunnel) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.conns, c)
	t.mu.Unlock()
	c.Close()
}

// splice copies both ways until either side ends, then closes both.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}

func key(b []byte, what string) (tunnel.Key, error) {
	var k tunnel.Key
	if len(b) != len(k) {
		return k, errors.New("cbbtun: the " + what + " is not 32 bytes")
	}
	copy(k[:], b)
	return k, nil
}
