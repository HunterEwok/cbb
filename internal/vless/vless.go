// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package vless carries a group's WireGuard packets between a client and
// the forwarder inside VLESS, for networks that block WireGuard and
// AmneziaWG alike (docs/design.md, "Blocked networks"). It has two
// transports. With REALITY the connection is, to the network, TLS 1.3 to a
// well-known site, whose handshake the forwarder borrows. With XHTTP it is
// HTTPS to the forwarder's own site: a web server there ends the TLS with
// the site's certificate and passes one path to the forwarder, which
// listens on the loopback address. VLESS inside either carries the UDP
// packets. It adds no security of its own: the packets are the group's
// WireGuard, with the member TLS inside it.
//
// It runs Xray-core in the process. The client side is a local UDP port
// that WireGuard sends to; the forwarder's side passes every packet to the
// forwarder's own UDP port, and nowhere else, so it cannot be used as a
// proxy.
package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/HunterEwok/cbb/internal/tunnel"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/dokodemo"
	xvless "github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"

	// What the two sides use of Xray, registered by their init functions.
	// The configs are built here rather than from Xray's JSON, whose
	// package pulls in much more, some of which gomobile cannot link.
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

// ServerConfig configures the forwarder's side.
type ServerConfig struct {
	Listen string // the TCP address to listen on, such as ":443"
	// Path, if set, makes it XHTTP behind a web server, which passes the
	// path to Listen as plain HTTP; the rest is for REALITY.
	Path string
	// Dest is the site whose TLS the forwarder borrows, as host:port: a
	// probe that is not a client gets that site's answers.
	Dest       string
	ServerName string   // the name the clients' handshakes carry
	Key        [32]byte // the REALITY private key, X25519
	// To is the forwarder's own UDP port, where every packet goes.
	To netip.AddrPort
	// Mirror, if set, is the TCP address, host:port, of the mirror of the
	// releases on the forwarder's own server: a client's TCP streams go
	// there and nowhere else (docs/protocol.md, section 13, "VLESS").
	// Without it a TCP stream goes nowhere.
	Mirror string
	// Register, if set, takes a hub's registration that came over VLESS:
	// a TCP stream to RegistrationPort, from any user let in, the
	// RegistrationID too, which is let in for nothing else.
	Register func(net.Conn)
}

// RegistrationID is the VLESS user ID by which a hub that reaches its
// forwarder only over VLESS registers (docs/protocol.md, section 13,
// "VLESS"): it is no secret, and it reaches nothing but the forwarder's
// registrations, as its TCP port does.
const RegistrationID = "0cbb0000-7e91-4000-8000-000000008764"

// RegistrationPort is the port a client names for a stream to the
// forwarder's registrations; any other TCP stream goes to the mirror.
const RegistrationPort = 8764

// ShortID returns the REALITY short ID of the private key: it needs no
// keeping, and it tells nothing about the key.
func ShortID(key [32]byte) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("cbb reality short id"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// PublicKey returns the REALITY public key of the private key.
func PublicKey(key [32]byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(key[:])
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// Server is the forwarder's side, running.
type Server struct {
	inst     *core.Instance
	users    proxy.UserManager // the groups' inbound
	regUsers proxy.UserManager // the registrations' inbound; users for REALITY, which has one
	out      *toForwarder
	port     uint16
	site     string // REALITY's key for what it learns of the site: Dest and server name
	front    *front // XHTTP: the paths in front of the inbounds; nil for REALITY
}

const (
	inboundTag    = "vless-in"
	regInboundTag = "vless-registrations"
)

// Listen starts the forwarder's side with no users; AddUser lets a
// group's clients in. Over XHTTP, the path itself takes only registrations
// (RegistrationID), and a group's packets come under a path of its own
// below it (AddPath), so that the path every build carries reaches nothing
// but the registrations (docs/protocol.md, section 13, "VLESS").
func Listen(cfg ServerConfig) (*Server, error) {
	// The free ports are picked before Xray binds them, so another program
	// can take one in between: then it picks others.
	for try := 1; ; try++ {
		s, err := listenOnce(cfg)
		if err == nil || try == listenTries || !addrInUse(err) {
			return s, err
		}
	}
}

// listenTries is how many times Listen picks free ports.
const listenTries = 3

// addrInUse reports whether err is a port that another socket took.
func addrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}

func listenOnce(cfg ServerConfig) (*Server, error) {
	if cfg.Path != "" {
		if err := tunnel.CheckVLESSPath(cfg.Path); err != nil {
			return nil, err
		}
		if tunnel.RegistrationPath(cfg.Path) != cfg.Path {
			return nil, fmt.Errorf("vless: %q has a group's part", cfg.Path)
		}
	} else if err := tunnel.CheckServerName(cfg.ServerName); err != nil {
		return nil, err
	}
	listen, err := listenAddr(cfg.Listen)
	if err != nil {
		return nil, err
	}
	// Whatever a client asks for, its packets go to the forwarder's UDP
	// port and nowhere else, and a TCP stream only to the registrations or
	// the mirror (toForwarder).
	out := &toForwarder{to: cfg.To, mirror: cfg.Mirror, register: cfg.Register}
	vin := &vlessin.Config{Decryption: "none"}
	var ins []*core.InboundHandlerConfig
	var fr *front
	if cfg.Path != "" {
		// Plain HTTP: the web server in front has ended the TLS. Any host
		// it passes is taken; what matters is the path. Two inbounds on
		// the loopback, behind the paths.
		stream := func() *internet.StreamConfig {
			return xhttpStream(&splithttp.Config{Path: cfg.Path, Mode: "packet-up", ScMaxBufferedPosts: MaxBufferedPosts}, nil)
		}
		groups, err := listenAddr("127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		regs, err := listenAddr("127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		ins = []*core.InboundHandlerConfig{inboundHandler(inboundTag, groups, stream(), vin), inboundHandler(regInboundTag, regs, stream(), vin)}
		fr = &front{path: cfg.Path, groups: groups, regs: regs, paths: map[string]int{}}
	} else {
		sid, _ := hex.DecodeString(ShortID(cfg.Key))
		stream := realityStream(&reality.Config{
			Dest:        cfg.Dest,
			Type:        "tcp",
			ServerNames: []string{cfg.ServerName},
			PrivateKey:  cfg.Key[:],
			ShortIds:    [][]byte{sid},
			// No limits, as Xray's JSON has it.
			LimitFallbackUpload:   &reality.LimitFallback{},
			LimitFallbackDownload: &reality.LimitFallback{},
		})
		ins = []*core.InboundHandlerConfig{inboundHandler(inboundTag, listen, stream, vin)}
	}
	inst, err := start(ins, nil)
	if err != nil {
		return nil, err
	}
	om, _ := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if om == nil {
		inst.Close()
		return nil, errors.New("vless: no outbound manager")
	}
	if err := om.AddHandler(context.Background(), out); err != nil {
		inst.Close()
		return nil, fmt.Errorf("vless: %w", err)
	}
	s := &Server{inst: inst, out: out, port: listen.Port(), front: fr}
	if cfg.Path == "" {
		s.site = cfg.Dest + " " + cfg.ServerName
	}
	if s.users, err = usersOf(inst, inboundTag); err != nil {
		inst.Close()
		return nil, err
	}
	s.regUsers = s.users
	if fr != nil {
		if s.regUsers, err = usersOf(inst, regInboundTag); err != nil {
			inst.Close()
			return nil, err
		}
		if err := fr.start(listen); err != nil {
			inst.Close()
			return nil, err
		}
	}
	if cfg.Register != nil {
		if err := addUser(s.regUsers, RegistrationID); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// listenAddr resolves a TCP address to listen on, a free port for port 0,
// as Xray needs the port.
func listenAddr(addr string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("vless: %w", err)
	}
	if port == "0" || port == "" {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("vless: %w", err)
		}
		_, port, _ = net.SplitHostPort(l.Addr().String())
		l.Close()
	}
	if host == "" {
		host = "0.0.0.0"
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("vless: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("vless: %w", err)
	}
	return netip.AddrPortFrom(ip, uint16(p)), nil
}

// usersOf returns the users of an inbound.
func usersOf(inst *core.Instance, tag string) (proxy.UserManager, error) {
	m, _ := inst.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if m == nil {
		return nil, errors.New("vless: no inbound manager")
	}
	h, err := m.GetHandler(context.Background(), tag)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	gi, ok := h.(proxy.GetInbound)
	if !ok {
		return nil, errors.New("vless: the inbound has no users")
	}
	um, ok := gi.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, errors.New("vless: the inbound has no users")
	}
	return um, nil
}

// Ready waits until REALITY has learned how the site it borrows ends its
// handshakes, which it finds out in the background when the server starts,
// once for each ALPN a client may offer. A client that comes before that
// waits for it in steps of 5 seconds, its packets held.
func (s *Server) Ready(ctx context.Context) error {
	if s.site == "" {
		return nil // XHTTP has nothing to learn
	}
	for {
		learned := true
		for alpn := range 3 {
			v, _ := goreality.GlobalPostHandshakeRecordsLens.Load(s.site + " " + strconv.Itoa(alpn))
			if _, ok := v.([]int); !ok {
				learned = false
			}
		}
		if learned {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vless: learning the site: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Port returns the TCP port the server listens on.
func (s *Server) Port() uint16 { return s.port }

// User returns the VLESS user ID of the group whose client a packet that
// reached the forwarder from the address came from: the forwarder's side
// sends each client's packets from a port of their own.
func (s *Server) User(from netip.AddrPort) (string, bool) { return s.out.user(from) }

// AddUser lets in the clients of the group whose user ID is id.
func (s *Server) AddUser(id string) error {
	if err := tunnel.CheckVLESSID(id); err != nil {
		return err
	}
	if id == RegistrationID {
		return errors.New("vless: the registrations' user ID is no group's")
	}
	return addUser(s.users, id)
}

func addUser(um proxy.UserManager, id string) error {
	u, err := (&protocol.User{Email: id, Account: serial.ToTypedMessage(&xvless.Account{Id: id, Encryption: "none"})}).ToMemoryUser()
	if err != nil {
		return fmt.Errorf("vless: %w", err)
	}
	return um.AddUser(context.Background(), u)
}

// AddPath lets a group's packets in under its own path below the XHTTP
// path, a segment that CheckGroupPath takes; each AddPath needs its
// RemovePath. Without XHTTP it does nothing.
func (s *Server) AddPath(p string) error {
	if s.front == nil {
		return nil
	}
	if err := tunnel.CheckGroupPath(p); err != nil {
		return err
	}
	s.front.mu.Lock()
	s.front.paths[p]++
	s.front.mu.Unlock()
	return nil
}

// RemovePath takes back an AddPath.
func (s *Server) RemovePath(p string) {
	if s.front == nil {
		return
	}
	s.front.mu.Lock()
	if s.front.paths[p]--; s.front.paths[p] <= 0 {
		delete(s.front.paths, p)
	}
	s.front.mu.Unlock()
}

// RemoveUser shuts out the clients of a group.
func (s *Server) RemoveUser(id string) error {
	if id == RegistrationID {
		return nil
	}
	return s.users.RemoveUser(context.Background(), id)
}

// Close stops the server.
func (s *Server) Close() error {
	if s.front != nil {
		s.front.close()
	}
	return s.inst.Close()
}

// Client is a client's side, running: a local UDP port whose packets go to
// the forwarder inside VLESS.
type Client struct {
	inst *core.Instance
	addr netip.AddrPort
}

// Dial starts the client's side for the link. WireGuard then sends to
// Addr.
func Dial(l tunnel.VLESS) (*Client, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	// Xray needs the port; take a free one.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	pc.Close()
	// The address means nothing: the forwarder sends every packet to its
	// own port.
	in := &dokodemo.Config{
		RewriteAddress:  xnet.NewIPOrDomain(xnet.LocalHostIP),
		RewritePort:     9,
		AllowedNetworks: []xnet.Network{xnet.Network_UDP},
	}
	inst, err := startClient(l, addr, in)
	if err != nil {
		return nil, err
	}
	return &Client{inst: inst, addr: addr}, nil
}

// Stream is a client's way, over VLESS, to the mirror of the releases on
// its forwarder's server or to the forwarder's registrations: a local TCP
// port whose connections the forwarder passes there. TLS goes inside, the
// mirror's with its own name or the registration's with the forwarder's
// key pinned, so it is checked as on any other way.
type Stream struct {
	inst *core.Instance
	addr netip.AddrPort
}

// DialMirror starts the client's way to the mirror for the link.
func DialMirror(l tunnel.VLESS) (*Stream, error) { return dialStream(l, 443) }

// DialRegistration starts a hub's way to its forwarder's registrations for
// the link, whose ID it replaces with RegistrationID.
func DialRegistration(l tunnel.VLESS) (*Stream, error) {
	l.ID = RegistrationID
	if l.Transport == tunnel.TransportXHTTP {
		l.Path = tunnel.RegistrationPath(l.Path)
	}
	return dialStream(l, RegistrationPort)
}

func dialStream(l tunnel.VLESS, port uint32) (*Stream, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	addr := ln.Addr().(*net.TCPAddr).AddrPort()
	ln.Close()
	// Only the port means something: the forwarder sends a stream to its
	// registrations or its mirror.
	in := &dokodemo.Config{
		RewriteAddress:  xnet.NewIPOrDomain(xnet.LocalHostIP),
		RewritePort:     port,
		AllowedNetworks: []xnet.Network{xnet.Network_TCP},
	}
	inst, err := startClient(l, addr, in)
	if err != nil {
		return nil, err
	}
	return &Stream{inst: inst, addr: addr}, nil
}

// Addr returns the local TCP address that leads there.
func (m *Stream) Addr() netip.AddrPort { return m.addr }

// Close stops the way.
func (m *Stream) Close() error { return m.inst.Close() }

// startClient runs a client's side for the link with the local inbound in
// on addr.
func startClient(l tunnel.VLESS, addr netip.AddrPort, in *dokodemo.Config) (*core.Instance, error) {
	var stream *internet.StreamConfig
	if l.Transport == tunnel.TransportXHTTP {
		// HTTPS to the site, its certificate checked against the public
		// CAs, in a browser's ClientHello. packet-up is plain requests,
		// which every web server and proxy passes as they are.
		roots := make([]*xtls.Certificate, len(extraRoots))
		for i, r := range extraRoots {
			roots[i] = &xtls.Certificate{Certificate: r, Usage: xtls.Certificate_AUTHORITY_VERIFY}
		}
		stream = xhttpStream(xhttpClient(l.ServerName, l.Path),
			&xtls.Config{ServerName: l.ServerName, Fingerprint: "chrome", NextProtocol: []string{"h2", "http/1.1"}, Certificate: roots})
	} else {
		sid, err := hex.DecodeString(l.ShortID)
		if err != nil {
			return nil, fmt.Errorf("vless: %w", err)
		}
		stream = realityStream(&reality.Config{
			Fingerprint: "chrome",
			ServerName:  l.ServerName,
			PublicKey:   l.PublicKey,
			ShortId:     sid,
			SpiderX:     "/",
			SpiderY:     make([]int64, 10),
		})
	}
	server := endpoint(l.Endpoint)
	server.User = &protocol.User{Account: serial.ToTypedMessage(&xvless.Account{Id: l.ID, Encryption: "none"})}
	return start([]*core.InboundHandlerConfig{inboundHandler("", addr, nil, in)}, &vlessout.Config{Vnext: server}, stream)
}

// Addr returns the local UDP address WireGuard sends to.
func (c *Client) Addr() netip.AddrPort { return c.addr }

// Close stops the client's side.
func (c *Client) Close() error { return c.inst.Close() }

// extraRoots are CAs, in PEM, that the client of XHTTP trusts beside the
// public ones: only tests set them (TrustForTests).
var extraRoots [][]byte

// TrustForTests makes the clients of XHTTP trust the CA, in PEM, beside
// the public ones, for tests whose web server has a certificate of its
// own. Nothing else calls it.
func TrustForTests(pem []byte) { extraRoots = append(extraRoots, pem) }

// xhttpClient is the client's XHTTP: packet-up on path to host, with the
// connection reuse that Xray's own configuration gives a client by
// default (a few HTTP/2 connections, each dropped after a random number
// of requests and seconds), which the configuration built here would
// otherwise leave unlimited: one connection that carries everything for
// as long as the tunnel lives. The gap between two uploads is random
// within a range around Xray's fixed 30 ms, so that their rhythm is not
// a constant. The padding of each request stays Xray's, random already.
func xhttpClient(host, path string) *splithttp.Config {
	return &splithttp.Config{
		Host: host, Path: path, Mode: "packet-up",
		ScMinPostsIntervalMs: &splithttp.RangeConfig{From: 10, To: 50},
		Xmux: &splithttp.XmuxConfig{
			MaxConnections:   &splithttp.RangeConfig{From: 3, To: 3},
			HMaxRequestTimes: &splithttp.RangeConfig{From: 600, To: 900},
			HMaxReusableSecs: &splithttp.RangeConfig{From: 1800, To: 3000},
		},
	}
}

// The uploads that XHTTP's packet-up holds for a session before a client
// that owns it shows up (docs/relay-budget.md): each POST carries at most
// MaxPostBytes, and a session keeps at most MaxBufferedPosts of them for the
// 30 s that Xray waits. Xray's own defaults, 1 MB and 30, let a stranger
// with no VLESS user make the server hold about 30 MB a session. The web
// server in front refuses a larger body (site/README.md, "VLESS").
const (
	MaxPostBytes     = 32 << 10
	MaxBufferedPosts = 8
)

// xhttpStream is XHTTP with c's settings and, unless c sets its own, the
// upload size above: the client splits its uploads to fit it, and the
// server takes no more.
func xhttpStream(c *splithttp.Config, t *xtls.Config) *internet.StreamConfig {
	if c.ScMaxEachPostBytes == nil {
		c.ScMaxEachPostBytes = &splithttp.RangeConfig{From: MaxPostBytes, To: MaxPostBytes}
	}
	sc := &internet.StreamConfig{ProtocolName: "splithttp", TransportSettings: []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: serial.ToTypedMessage(c)}}}
	if t != nil {
		tm := serial.ToTypedMessage(t)
		sc.SecurityType, sc.SecuritySettings = tm.Type, []*serial.TypedMessage{tm}
	}
	return sc
}

func realityStream(c *reality.Config) *internet.StreamConfig {
	tm := serial.ToTypedMessage(c)
	return &internet.StreamConfig{ProtocolName: "tcp", SecurityType: tm.Type, SecuritySettings: []*serial.TypedMessage{tm}}
}

func endpoint(a netip.AddrPort) *protocol.ServerEndpoint {
	return &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.IPAddress(a.Addr().AsSlice())), Port: uint32(a.Port())}
}

func ports(p uint16) *xnet.PortList {
	return &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(p))}}
}

func inboundHandler(tag string, listen netip.AddrPort, stream *internet.StreamConfig, settings proto.Message) *core.InboundHandlerConfig {
	return &core.InboundHandlerConfig{
		Tag: tag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			PortList:       ports(listen.Port()),
			Listen:         xnet.NewIPOrDomain(xnet.IPAddress(listen.Addr().AsSlice())),
			StreamSettings: stream,
		}),
		ProxySettings: serial.ToTypedMessage(settings),
	}
}

// start runs Xray with the inbounds and one outbound, or none for one that
// is added afterwards, logging nothing.
func start(ins []*core.InboundHandlerConfig, out proto.Message, outStream ...*internet.StreamConfig) (*core.Instance, error) {
	sender := &proxyman.SenderConfig{}
	if len(outStream) > 0 {
		sender.StreamSettings = outStream[0]
	}
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&xlog.Config{ErrorLogType: xlog.LogType_None, AccessLogType: xlog.LogType_None}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: ins,
	}
	if out != nil {
		cfg.Outbound = []*core.OutboundHandlerConfig{{SenderSettings: serial.ToTypedMessage(sender), ProxySettings: serial.ToTypedMessage(out)}}
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("vless: %w", err)
	}
	return inst, nil
}
