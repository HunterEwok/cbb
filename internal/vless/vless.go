// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package vless carries a group's WireGuard packets between a client and
// the forwarder inside VLESS, for networks that block WireGuard and
// AmneziaWG alike (docs/design.md, "Blocked networks"). Its transport is
// XHTTP: to the network the connection is HTTPS to the forwarder's own
// site, where a web server ends the TLS with the site's certificate and
// passes one path to the forwarder, which listens on the loopback address.
// VLESS inside carries the UDP packets. It adds no security of its own: the packets are the group's
// WireGuard, with the member TLS inside it.
//
// It runs Xray-core in the process. The client side is a local UDP port
// that WireGuard sends to; the forwarder's side passes every packet to the
// forwarder's own UDP port, and nowhere else, so it cannot be used as a
// proxy.
package vless

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/HunterEwok/cbb/internal/tunnel"
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
	"github.com/xtls/xray-core/transport/internet/splithttp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"

	// What the two sides use of Xray, registered by their init functions.
	// The configs are built here rather than from Xray's JSON, whose
	// package pulls in much more.
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/transport/internet/udp"
)

// ServerConfig configures the forwarder's side.
type ServerConfig struct {
	// Listen is the TCP address to listen on, such as "127.0.0.1:3276",
	// as plain HTTP for the web server in front.
	Listen string
	// Path is the XHTTP path the web server passes to Listen.
	Path string
	// To is the forwarder's own UDP port, where every packet goes.
	To netip.AddrPort
	// Mirror, if set, is the TCP address, host:port, of the mirror of the
	// releases on the forwarder's own server: a client's TCP streams go
	// there and nowhere else (docs/protocol.md, section 13, "VLESS").
	// Without it a TCP stream goes nowhere.
	Mirror string
	// Register, if set, takes a hub's registration that came over VLESS:
	// a TCP stream to RegistrationPort, from any user let in, the
	// RegistrationID too, which is let in for nothing else. from is the
	// client's own address, which pays for the registration: the one the
	// web server in front names (FromHeader); a loopback address when it is
	// not known.
	Register func(conn net.Conn, from netip.Addr)
}

// RegistrationID is the VLESS user ID by which a hub that reaches its
// forwarder only over VLESS registers (docs/protocol.md, section 13,
// "VLESS"): it is no secret, and it reaches nothing but the forwarder's
// registrations, as its TCP port does.
const RegistrationID = "0cbb0000-7e91-4000-8000-000000008764"

// RegistrationPort is the port a client names for a stream to the
// forwarder's registrations; any other TCP stream goes to the mirror.
const RegistrationPort = 8764

// Server is the forwarder's side, running.
type Server struct {
	inst     *core.Instance
	users    proxy.UserManager // the groups' inbound
	regUsers proxy.UserManager // the registrations' inbound
	out      *toForwarder
	port     uint16
	front    *front // the paths in front of the inbounds
}

const (
	inboundTag    = "vless-in"
	regInboundTag = "vless-registrations"
)

// Listen starts the forwarder's side with no users; AddUser lets a
// group's clients in. The path itself takes only registrations
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

// addrInUse reports whether err is a port that another socket took; Xray
// may give it as text only.
func addrInUse(err error) bool {
	return errors.Is(err, errAddrInUse) || strings.Contains(err.Error(), "address already in use") ||
		strings.Contains(err.Error(), "Only one usage of each socket address")
}

func listenOnce(cfg ServerConfig) (*Server, error) {
	if err := tunnel.CheckVLESSPath(cfg.Path); err != nil {
		return nil, err
	}
	if tunnel.RegistrationPath(cfg.Path) != cfg.Path {
		return nil, fmt.Errorf("vless: %q has a group's part", cfg.Path)
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
	// Plain HTTP: the web server in front has ended the TLS. Any host it
	// passes is taken; what matters is the path. Two inbounds on the
	// loopback, behind the paths.
	stream := func() *internet.StreamConfig {
		sc := xhttpStream(&splithttp.Config{Path: cfg.Path, Mode: "packet-up", ScMaxBufferedPosts: MaxBufferedPosts}, nil)
		// The front names the client's address; only it reaches these
		// inbounds, on the loopback.
		sc.SocketSettings = &internet.SocketConfig{TrustedXForwardedFor: []string{frontHeader}}
		return sc
	}
	groups, err := listenAddr("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	regs, err := listenAddr("127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ins := []*core.InboundHandlerConfig{inboundHandler(inboundTag, groups, stream(), vin), inboundHandler(regInboundTag, regs, stream(), vin)}
	fr := &front{path: cfg.Path, groups: groups, regs: regs, paths: map[string]int{}}
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
	if s.users, err = usersOf(inst, inboundTag); err != nil {
		inst.Close()
		return nil, err
	}
	if s.regUsers, err = usersOf(inst, regInboundTag); err != nil {
		inst.Close()
		return nil, err
	}
	if err := fr.start(listen); err != nil {
		inst.Close()
		return nil, err
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
// RemovePath.
func (s *Server) AddPath(p string) error {
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
	s.front.close()
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
	l.Path = tunnel.RegistrationPath(l.Path)
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
	// HTTPS to the site, its certificate checked against the public CAs,
	// in a browser's ClientHello. packet-up is plain requests, which every
	// web server and proxy passes as they are.
	roots := make([]*xtls.Certificate, len(extraRoots))
	for i, r := range extraRoots {
		roots[i] = &xtls.Certificate{Certificate: r, Usage: xtls.Certificate_AUTHORITY_VERIFY}
	}
	stream := xhttpStream(xhttpClient(l.ServerName, l.Path),
		&xtls.Config{ServerName: l.ServerName, Fingerprint: "chrome", NextProtocol: []string{"h2", "http/1.1"}, Certificate: roots})
	server := endpoint(l.Endpoint)
	server.User = &protocol.User{Account: serial.ToTypedMessage(&xvless.Account{Id: l.ID, Encryption: "none"})}
	return start([]*core.InboundHandlerConfig{inboundHandler("", addr, nil, in)}, &vlessout.Config{Vnext: server}, stream)
}

// Addr returns the local UDP address WireGuard sends to.
func (c *Client) Addr() netip.AddrPort { return c.addr }

// Close stops the client's side.
func (c *Client) Close() error { return c.inst.Close() }

// extraRoots are CAs, in PEM, that the client of XHTTP trusts beside the
// public ones: only tests set them (TrustForTests), and the bench's
// time-scaled build (trust_benchtime.go).
var extraRoots [][]byte

// TrustForTests makes the clients of XHTTP trust the CA, in PEM, beside
// the public ones, for tests whose web server has a certificate of its
// own. Nothing else calls it but the bench's time-scaled build.
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
