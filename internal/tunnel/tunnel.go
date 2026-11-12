// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package tunnel carries the member protocol away from home: the group's own
// WireGuard tunnel in a star around one member, the hub (docs/design.md,
// "Sync away from home").
//
// WireGuard runs in user space inside the process (amneziawg-go, a fork of
// wireguard-go that is plain WireGuard until obfuscation is set) with an
// in-process network stack (gVisor's netstack), so the operating system sees
// only encrypted UDP on one port: there is no network interface, no route and
// no firewall rule. Behind the hub's tunnel the stack has one listening port,
// the member protocol's, and nothing else: no forwarding, no other host, so
// the tunnel cannot carry anything but cbb.
//
// Each client has exactly one tunnel address, and the hub's WireGuard drops
// every packet whose source is not the address of the key that sent it.
// Clients admit only the hub's address. A packet one client addresses to
// another reaches the hub's stack, which is not that address and does not
// forward, so clients never reach each other; the hub passes clipboard events
// at the member protocol level. Each client also has its own preshared key,
// which keeps recorded traffic safe from a future quantum computer.
package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"

	"github.com/HunterEwok/cbb/internal/third_party/netstack"
)

// Port is the member protocol's port inside the tunnel, the same as on the
// home network.
const Port = 8764

// MTU of the tunnel: 1280, the IPv6 minimum, so that the packets fit any
// path, including the extra headers of AmneziaWG or VLESS later.
const MTU = 1280

// Keepalive is the interval, in seconds, at which a client sends a packet to
// the hub when it has sent nothing else, to keep NAT mappings open.
const Keepalive = 25

// prefix holds the tunnel addresses: a unique-local /32 that never leaves
// the process, since the tunnel's network stack is private to it.
var prefix = netip.MustParsePrefix("fd00:cbb::/32")

// guestPrefix holds the addresses of guests: the one-time keys of remote
// invitations, which reach only the pairing on the hub. It is apart from the
// members' prefix, so a guest address never names a member.
var guestPrefix = netip.MustParsePrefix("fd00:cbc::/32")

// Key is a WireGuard key: a Curve25519 private or public key, or a preshared
// key.
type Key [32]byte

// NewPrivateKey returns a new private key.
func NewPrivateKey() (Key, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	return Key(k.Bytes()), nil
}

// NewPresharedKey returns a new random preshared key.
func NewPresharedKey() (Key, error) {
	var k Key
	_, err := rand.Read(k[:])
	return k, err
}

// Public returns the public key of the private key k.
func (k Key) Public() Key {
	p, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		// Any 32 bytes are a valid X25519 private key.
		panic(err)
	}
	return Key(p.PublicKey().Bytes())
}

// IsZero reports whether k is all zero, that is, unset.
func (k Key) IsZero() bool { return k == Key{} }

func (k Key) hex() string { return hex.EncodeToString(k[:]) }

// Addr returns the tunnel address of the device with the given ID (32
// lowercase hex characters): the prefix followed by the first 96 bits of
// the ID.
func Addr(deviceID string) (netip.Addr, error) {
	id, err := hex.DecodeString(deviceID)
	if err != nil || len(id) != 16 || strings.ToLower(deviceID) != deviceID {
		return netip.Addr{}, fmt.Errorf("tunnel: %q is not a device ID", deviceID)
	}
	a := prefix.Addr().As16()
	copy(a[4:], id[:12])
	return netip.AddrFrom16(a), nil
}

// GuestAddr returns the tunnel address of the guest with the public key
// pub: the guest prefix followed by the first 96 bits of SHA-256(pub).
func GuestAddr(pub Key) netip.Addr {
	sum := sha256.Sum256(pub[:])
	a := guestPrefix.Addr().As16()
	copy(a[4:], sum[:12])
	return netip.AddrFrom16(a)
}

// IsGuest reports whether a is a guest's tunnel address.
func IsGuest(a netip.Addr) bool { return guestPrefix.Contains(a) }

// inTunnel reports whether a is a member's or a guest's tunnel address.
func inTunnel(a netip.Addr) bool { return prefix.Contains(a) || guestPrefix.Contains(a) }

// Peer is a client as the hub knows it.
type Peer struct {
	PublicKey    Key
	PresharedKey Key
	Addr         netip.Addr // its one tunnel address
}

// HubConfig configures a hub.
type HubConfig struct {
	PrivateKey Key
	Addr       netip.Addr // the hub's tunnel address
	ListenPort int        // the UDP port; 0 picks a free one
	Peers      []Peer
	// Obfuscation, when set, makes the hub speak AmneziaWG with these
	// settings instead of plain WireGuard; every client needs the same.
	Obfuscation *Obfuscation
	Logf        func(format string, args ...any)
	Verbose     bool // also log WireGuard's own messages, such as each handshake
}

// Hub is the end of every client's tunnel.
type Hub struct {
	dev      *device.Device
	bind     conn.Bind
	listener net.Listener
	addr     netip.Addr
	port     int

	mu    sync.Mutex
	peers map[Key]Peer // the peers the device has now
}

// StartHub brings a hub up. Its Listener accepts the member protocol's
// connections from the clients in cfg.Peers.
func StartHub(cfg HubConfig) (*Hub, error) {
	if cfg.PrivateKey.IsZero() {
		return nil, errors.New("tunnel: the hub has no private key")
	}
	if !prefix.Contains(cfg.Addr) {
		return nil, fmt.Errorf("tunnel: %v is not a tunnel address", cfg.Addr)
	}
	if err := checkPeers(cfg.Peers, cfg.Addr); err != nil {
		return nil, err
	}
	if o := cfg.Obfuscation; o != nil {
		if err := o.Check(); err != nil {
			return nil, err
		}
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Addr}, nil, MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	// wireguard-go reports port 0 for a port it picked itself on a host
	// without IPv6, so the hub picks one first.
	port := cfg.ListenPort
	if port == 0 {
		if port, err = freeUDPPort(); err != nil {
			return nil, err
		}
	}
	bind := newBind()
	dev := device.NewDevice(tdev, bind, wgLogger(logf, "hub", cfg.Verbose))
	h := &Hub{dev: dev, bind: bind, addr: cfg.Addr, port: port, peers: map[Key]Peer{}}
	for _, p := range cfg.Peers {
		h.peers[p.PublicKey] = p
	}
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", cfg.PrivateKey.hex(), port) + cfg.Obfuscation.ipc()
	if err := dev.IpcSet(ipc + peersConfig(cfg.Peers)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: configuring the hub: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: starting the hub: %w", err)
	}
	l, err := tnet.ListenTCPAddrPort(netip.AddrPortFrom(cfg.Addr, Port))
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: listening in the hub's tunnel: %w", err)
	}
	h.listener = addrListener{l}
	return h, nil
}

// Listener accepts the member protocol's connections that come through the
// tunnel. Their remote address is the client's tunnel address.
func (h *Hub) Listener() net.Listener { return h.listener }

// UDPPort returns the UDP port the hub listens on.
func (h *Hub) UDPPort() int { return h.port }

// Send sends a packet to to from the hub's UDP port: a hub's hello to its
// forwarder, which learns from it where that port is reached.
func (h *Hub) Send(to netip.AddrPort, p []byte) error {
	ep, err := h.bind.ParseEndpoint(to.String())
	if err != nil {
		return fmt.Errorf("tunnel: %w", err)
	}
	if err := h.bind.Send([][]byte{p}, ep); err != nil {
		return fmt.Errorf("tunnel: %w", err)
	}
	return nil
}

// SetPeers replaces the hub's clients. A client left out is forgotten at
// once: its packets are dropped from then on. A client that stays keeps its
// session, so its connections through the tunnel go on.
func (h *Hub) SetPeers(peers []Peer) error {
	if err := checkPeers(peers, h.addr); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	want := make(map[Key]Peer, len(peers))
	var b strings.Builder
	for _, p := range peers {
		want[p.PublicKey] = p
	}
	for k := range h.peers {
		if _, ok := want[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k.hex())
		}
	}
	for _, p := range peers {
		if old, ok := h.peers[p.PublicKey]; !ok || old != p {
			fmt.Fprintf(&b, "public_key=%s\npreshared_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n",
				p.PublicKey.hex(), p.PresharedKey.hex(), netip.PrefixFrom(p.Addr, 128))
		}
	}
	if b.Len() == 0 {
		return nil
	}
	if err := h.dev.IpcSet(b.String()); err != nil {
		// The device may hold part of it; set them all from scratch.
		if err := h.dev.IpcSet("replace_peers=true\n" + peersConfig(peers)); err != nil {
			return fmt.Errorf("tunnel: setting the hub's peers: %w", err)
		}
	}
	h.peers = want
	return nil
}

// Close stops the hub and closes its listener and every connection through
// it.
func (h *Hub) Close() error {
	h.listener.Close()
	closeDevice(h.dev)
	return nil
}

// ClientConfig configures a client.
type ClientConfig struct {
	PrivateKey   Key
	PresharedKey Key
	Addr         netip.Addr // the client's tunnel address
	HubPublicKey Key
	HubAddr      netip.Addr     // the hub's tunnel address
	Endpoint     netip.AddrPort // where the hub's UDP port is reached
	Obfuscation  *Obfuscation   // the hub's AmneziaWG settings; nil for plain WireGuard
	// Allowed, if set, says where the client's UDP socket may send; the
	// service passes netguard.Allowed. Without it, only to Endpoint.
	Allowed func(netip.Addr) bool
	Logf    func(format string, args ...any)
	Verbose bool // also log WireGuard's own messages, such as each handshake
}

// Client is one device's tunnel to the hub.
type Client struct {
	dev     *device.Device
	net     *netstack.Net
	hubAddr netip.Addr
	hubKey  Key
}

// StartClient brings a client's tunnel up. Nothing is sent before Dial.
func StartClient(cfg ClientConfig) (*Client, error) {
	switch {
	case cfg.PrivateKey.IsZero():
		return nil, errors.New("tunnel: the client has no private key")
	case cfg.HubPublicKey.IsZero():
		return nil, errors.New("tunnel: the hub's public key is missing")
	case cfg.PresharedKey.IsZero():
		return nil, errors.New("tunnel: the preshared key is missing")
	case !inTunnel(cfg.Addr) || !prefix.Contains(cfg.HubAddr):
		return nil, errors.New("tunnel: the client's or the hub's address is not a tunnel address")
	case !cfg.Endpoint.IsValid():
		return nil, errors.New("tunnel: the hub's endpoint is missing")
	}
	if o := cfg.Obfuscation; o != nil {
		if err := o.Check(); err != nil {
			return nil, err
		}
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Addr}, nil, MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	allowed := cfg.Allowed
	if allowed == nil {
		to := cfg.Endpoint.Addr().Unmap()
		allowed = func(a netip.Addr) bool { return a.Unmap() == to }
	}
	dev := device.NewDevice(tdev, clientBind{newBind(), allowed}, wgLogger(logf, "client", cfg.Verbose))
	ipc := fmt.Sprintf("private_key=%s\n%spublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=%d\n",
		cfg.PrivateKey.hex(), cfg.Obfuscation.ipc(), cfg.HubPublicKey.hex(), cfg.PresharedKey.hex(),
		cfg.Endpoint, netip.PrefixFrom(cfg.HubAddr, 128), Keepalive)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: configuring the client: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: starting the client: %w", err)
	}
	return &Client{dev: dev, net: tnet, hubAddr: cfg.HubAddr, hubKey: cfg.HubPublicKey}, nil
}

// Dial opens a member protocol connection to the hub through the tunnel.
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	conn, err := c.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(c.hubAddr, Port))
	if err != nil {
		return nil, fmt.Errorf("tunnel: dialing the hub: %w", err)
	}
	return withAddrs(conn)
}

// Received returns how many bytes of WireGuard's the client has had from
// the hub, handshake answers included: it grows while the hub answers, even
// before a connection through the tunnel is set up.
func (c *Client) Received() uint64 {
	cfg, err := c.dev.IpcGet()
	if err != nil {
		return 0
	}
	var n uint64
	for line := range strings.SplitSeq(cfg, "\n") {
		if v, ok := strings.CutPrefix(line, "rx_bytes="); ok {
			if b, err := strconv.ParseUint(v, 10, 64); err == nil {
				n += b
			}
		}
	}
	return n
}

// SetEndpoint points the tunnel at another address of the hub, for example
// after the hub's address changed.
func (c *Client) SetEndpoint(ep netip.AddrPort) error {
	if err := c.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", c.hubKey.hex(), ep)); err != nil {
		return fmt.Errorf("tunnel: setting the hub's endpoint: %w", err)
	}
	return nil
}

// Close stops the tunnel and every connection through it.
func (c *Client) Close() error {
	closeDevice(c.dev)
	return nil
}

// closeDevice stops the peers before it closes the device. Device.Close
// closes the network stack first, while a peer may still be handing it a
// packet whose answer (such as a TCP reset) goes to the stack's outgoing
// channel, which Close closes: a data race in wireguard-go. Down waits for
// the peers' goroutines to stop.
func closeDevice(dev *device.Device) {
	dev.Down()
	dev.Close()
}

// freeUDPPort returns a UDP port that is free on IPv4 at the moment.
func freeUDPPort() (int, error) {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return 0, fmt.Errorf("tunnel: finding a free UDP port: %w", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port, nil
}

// checkPeers refuses peers that would break isolation: a missing key, a
// shared key or address, or an address outside the tunnel's prefix.
func checkPeers(peers []Peer, hub netip.Addr) error {
	keys := make(map[Key]bool, len(peers))
	addrs := make(map[netip.Addr]bool, len(peers))
	for _, p := range peers {
		switch {
		case p.PublicKey.IsZero():
			return errors.New("tunnel: a peer has no public key")
		case p.PresharedKey.IsZero():
			return errors.New("tunnel: a peer has no preshared key")
		case !inTunnel(p.Addr):
			return fmt.Errorf("tunnel: %v is not a tunnel address", p.Addr)
		case p.Addr == hub:
			return errors.New("tunnel: a peer has the hub's address")
		case keys[p.PublicKey]:
			return errors.New("tunnel: two peers have the same key")
		case addrs[p.Addr]:
			return fmt.Errorf("tunnel: two peers have the address %v", p.Addr)
		}
		keys[p.PublicKey] = true
		addrs[p.Addr] = true
	}
	return nil
}

func peersConfig(peers []Peer) string {
	var b strings.Builder
	for _, p := range peers {
		fmt.Fprintf(&b, "public_key=%s\npreshared_key=%s\nallowed_ip=%s\n",
			p.PublicKey.hex(), p.PresharedKey.hex(), netip.PrefixFrom(p.Addr, 128))
	}
	return b.String()
}

// wgLogger passes wireguard-go's errors to logf, and with verbose its other
// messages too.
func wgLogger(logf func(string, ...any), who string, verbose bool) *device.Logger {
	l := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			logf("tunnel: "+who+": "+format, args...)
		},
	}
	if verbose {
		l.Verbosef = l.Errorf
	}
	return l
}
