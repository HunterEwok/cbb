// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/blind"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/invite"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

const (
	rustHubID   = "00112233445566778899aabbccddeeff"
	rustPhoneID = "ffeeddccbbaa99887766554433221100"
)

// TestRustPhoneTunnel runs the phones' tunnel in Rust (ffi/, the
// example tunnel-on-linux) against the Go hub: plain WireGuard,
// AmneziaWG, and VLESS with XHTTP behind a web server, each through the
// loopback port to the hub's member port and back. The key is made by
// Go, and Rust must find the same public key.
func TestRustPhoneTunnel(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	t.Run("plain", func(t *testing.T) { rustThrough(t, bin, nil, false) })
	t.Run("obfuscated", func(t *testing.T) {
		obf, err := tunnel.NewObfuscation()
		if err != nil {
			t.Fatal(err)
		}
		rustThrough(t, bin, obf, false)
	})
	t.Run("xhttp", func(t *testing.T) { rustThrough(t, bin, nil, true) })
}

// rustPhone is the running example, one request per line.
type rustPhone struct {
	in  io.WriteCloser
	out *bufio.Scanner
}

func startRustPhone(t *testing.T, bin string, env ...string) *rustPhone {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		cmd.Wait()
	})
	return &rustPhone{in: in, out: bufio.NewScanner(out)}
}

// call sends one request and returns its "ok", failing on an error.
func (p *rustPhone) call(t *testing.T, req any) map[string]any {
	t.Helper()
	ok, err := p.try(t, req)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// try sends req and returns its answer, or the error the library gave.
func (p *rustPhone) try(t *testing.T, req any) (map[string]any, error) {
	t.Helper()
	b, _ := json.Marshal(req)
	if _, err := p.in.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	if !p.out.Scan() {
		t.Fatalf("no answer to %s", b)
	}
	var a struct {
		OK    map[string]any `json:"ok"`
		Error any            `json:"error"`
	}
	if err := json.Unmarshal(p.out.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if a.Error != nil {
		return nil, fmt.Errorf("%s: %v", b, a.Error)
	}
	return a.OK, nil
}

func rustThrough(t *testing.T, bin string, obf *tunnel.Obfuscation, xhttp bool) {
	priv, _ := tunnel.NewPrivateKey()
	psk, _ := tunnel.NewPresharedKey()
	hubKey, _ := tunnel.NewPrivateKey()
	hubAddr, _ := tunnel.Addr(rustHubID)
	phoneAddr, _ := tunnel.Addr(rustPhoneID)
	hub, err := tunnel.StartHub(tunnel.HubConfig{PrivateKey: hubKey, Addr: hubAddr,
		Peers: []tunnel.Peer{{PublicKey: priv.Public(), PresharedKey: psk, Addr: phoneAddr}}, Obfuscation: obf})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	go func() {
		for {
			c, err := hub.Listener().Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	hubPub := hubKey.Public()
	offer := map[string]any{"hub_key": hubPub[:], "psk": psk[:],
		"endpoints": []string{fmt.Sprintf("127.0.0.1:%d", hub.UDPPort())}}
	if obf != nil {
		offer["obfuscation"] = obf
	}
	var env []string
	if xhttp {
		link, ca := rustXHTTP(t, uint16(hub.UDPPort()))
		offer["vless"] = link
		// The UDP address answers nothing: only VLESS reaches the hub.
		offer["endpoints"] = []string{"127.0.0.1:9"}
		f := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(f, ca, 0o600); err != nil {
			t.Fatal(err)
		}
		env = append(env, "SSL_CERT_FILE="+f)
	}

	p := startRustPhone(t, bin, env...)
	pub := p.call(t, map[string]any{"op": "public_key", "key": priv[:]})
	want := priv.Public()
	if pub["public"] != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatalf("Rust's public key %v, Go's %x", pub["public"], want)
	}
	started := p.call(t, map[string]any{"op": "start", "key": priv[:], "device": rustPhoneID, "hub": rustHubID, "offer": offer})
	id, port := started["id"], int(started["port"].(float64))

	for i := range 2 {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(45 * time.Second))
		msg := []byte(fmt.Sprintf("hello %d", i))
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("through the Rust tunnel: %v (status %v)", err, p.call(t, map[string]any{"op": "status", "id": id}))
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("got %q, want %q", got, msg)
		}
		c.Close()
	}
	if s := p.call(t, map[string]any{"op": "status", "id": id}); s["answered"] != true {
		t.Fatalf("status %v", s)
	}
	p.call(t, map[string]any{"op": "stop", "id": id})
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		c.Close()
		t.Fatal("the port still accepts after stop")
	}
}

// rustXHTTP starts VLESS over XHTTP behind a web server with a CA of its
// own in front of the hub's UDP port, and returns the offer's VLESS
// settings and the CA's certificate.
func rustXHTTP(t *testing.T, port uint16) (tunnel.VLESS, []byte) {
	t.Helper()
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	s, err := vless.Listen(vless.ServerConfig{Listen: "127.0.0.1:0", Path: path, To: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	back := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Port()).String()
	web, ca := vlesstest.WebServerCA(t, path, func() string { return back })
	id, _ := tunnel.NewVLESSID()
	if err := s.AddUser(id); err != nil {
		t.Fatal(err)
	}
	const group = "a-group-of-its-own"
	if err := s.AddPath(group); err != nil {
		t.Fatal(err)
	}
	return tunnel.VLESS{Transport: tunnel.TransportXHTTP, Endpoint: web, ServerName: vlesstest.WebName, Path: path + "/" + group, ID: id}, ca
}

// TestRustPhoneHub runs the phone's hub in Rust (ffi/) with two Go
// clients, plain and with AmneziaWG: each client's connection through its
// tunnel to the hub's member port reaches the app's member listener on the
// loopback address; a client taken off the list is cut off.
func TestRustPhoneHub(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	t.Run("plain", func(t *testing.T) { rustHub(t, bin, nil) })
	t.Run("obfuscated", func(t *testing.T) {
		obf, err := tunnel.NewObfuscation()
		if err != nil {
			t.Fatal(err)
		}
		rustHub(t, bin, obf)
	})
}

func rustHub(t *testing.T, bin string, obf *tunnel.Obfuscation) {
	member := echoServer(t)
	hubKey, _ := tunnel.NewPrivateKey()
	hubAddr, _ := tunnel.Addr(rustHubID)
	ids := []string{rustPhoneID, "0123456789abcdef0123456789abcdef"}
	type client struct {
		key, psk tunnel.Key
		addr     netip.Addr
	}
	var cs []client
	var list []map[string]any
	for _, id := range ids {
		k, _ := tunnel.NewPrivateKey()
		psk, _ := tunnel.NewPresharedKey()
		a, _ := tunnel.Addr(id)
		cs = append(cs, client{k, psk, a})
		pub := k.Public()
		list = append(list, map[string]any{"device": id, "key": pub[:], "psk": psk[:]})
	}
	req := map[string]any{"op": "hub_start", "key": hubKey[:], "device": rustHubID, "clients": list,
		"member_port": member, "listen": "127.0.0.1:0"}
	if obf != nil {
		req["obfuscation"] = obf
	}
	p := startRustPhone(t, bin)
	started := p.call(t, req)
	id, port := started["id"], int(started["udp_port"].(float64))

	var clients []*tunnel.Client
	for _, c := range cs {
		cl, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: c.key, PresharedKey: c.psk, Addr: c.addr,
			HubPublicKey: hubKey.Public(), HubAddr: hubAddr, Obfuscation: obf,
			Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))})
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		clients = append(clients, cl)
	}
	for i, cl := range clients {
		if err := echoThrough(cl, fmt.Sprintf("hello from %d", i)); err != nil {
			t.Fatalf("client %d through the Rust hub: %v (status %v)", i, err, p.call(t, map[string]any{"op": "hub_status", "id": id}))
		}
	}
	// The second client goes off the list: it is cut off, the first stays.
	p.call(t, map[string]any{"op": "hub_set_clients", "id": id, "clients": list[:1]})
	if err := echoThrough(clients[1], "still there?"); err == nil {
		t.Fatal("a client taken off the list still reaches the member port")
	}
	if err := echoThrough(clients[0], "again"); err != nil {
		t.Fatalf("the client left on the list: %v", err)
	}
	p.call(t, map[string]any{"op": "hub_stop", "id": id})
}

// TestRustPhoneHubInvite opens a remote invitation on the Rust hub: Go reads
// its text, a Go client on the guest tunnel reaches the pairing window, then
// the member port once the window admitted the device, and nothing after the
// guest is closed.
func TestRustPhoneHubInvite(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	obf, err := tunnel.NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	// Each loopback server answers with its name.
	serve := func(name string) int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Write([]byte(name))
				c.Close()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	memberPort, windowPort := serve("member"), serve("window")
	hubKey, _ := tunnel.NewPrivateKey()
	p := startRustPhone(t, bin)
	started := p.call(t, map[string]any{"op": "hub_start", "key": hubKey[:], "device": rustHubID,
		"obfuscation": obf, "member_port": memberPort, "listen": "127.0.0.1:0"})
	id, port := started["id"], int(started["udp_port"].(float64))
	ep := fmt.Sprintf("127.0.0.1:%d", port)
	inv := p.call(t, map[string]any{"op": "hub_invite", "id": id, "group": "0f1e2d3c4b5a6978",
		"endpoints": []string{ep}, "lifetime": 3600, "guest_port": windowPort})

	in, err := invite.Parse(inv["text"].(string))
	if err != nil {
		t.Fatalf("Go reads the Rust hub's invitation: %v", err)
	}
	if in.Hub != rustHubID || in.HubKey != hubKey.Public() || in.Obfuscation == nil || len(in.Endpoints) != 1 ||
		base64.StdEncoding.EncodeToString(in.Secret) != inv["secret"] || in.Expires.Unix() != int64(inv["expires"].(float64)) {
		t.Fatalf("the invitation %+v, the answer %v", in, inv)
	}
	if d := time.Until(in.Expires); d < 59*time.Minute || d > time.Hour+time.Minute {
		t.Fatalf("the invitation expires in %v", d)
	}
	hubAddr, _ := tunnel.Addr(rustHubID)
	guestPub := in.GuestKey.Public()
	cl, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: in.GuestKey, PresharedKey: in.GuestPSK,
		Addr: tunnel.GuestAddr(guestPub), HubPublicKey: in.HubKey, HubAddr: hubAddr, Obfuscation: in.Obfuscation,
		Endpoint: in.Endpoints[0]})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	reach := func(timeout time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c, err := cl.Dial(ctx)
		if err != nil {
			return "", err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(timeout))
		b, err := io.ReadAll(c)
		return string(b), err
	}
	if got, err := reach(15 * time.Second); err != nil || got != "window" {
		t.Fatalf("the guest reached %q, %v; want the window (status %v)", got, err, p.call(t, map[string]any{"op": "hub_status", "id": id}))
	}
	p.call(t, map[string]any{"op": "guest_admitted", "id": id, "guest": inv["guest"]})
	if got, err := reach(15 * time.Second); err != nil || got != "member" {
		t.Fatalf("the admitted guest reached %q, %v; want the member port", got, err)
	}
	p.call(t, map[string]any{"op": "guest_close", "id": id, "guest": inv["guest"]})
	if got, err := reach(3 * time.Second); err == nil && got != "" {
		t.Fatalf("a closed guest reached %q", got)
	}
}

// startForwarder serves a Go forwarder on the loopback until the test ends.
func startForwarder(t *testing.T, cfg forward.Config) (*forward.Forwarder, []byte) {
	t.Helper()
	fcert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen, cfg.Cert, cfg.Logf = "127.0.0.1:0", fcert, t.Logf
	f, err := forward.Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		f.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	pin, _ := base64.StdEncoding.DecodeString(forward.Pin(fcert.Leaf))
	return f, pin
}

// TestRustPhoneHubForwarder registers the Rust hub with a Go forwarder by
// cbb-forward/3, as a phone that is its group's hub does, and a Go client
// reaches the hub's member port through the forwarder: until the period's
// hubs' credential lists its server key the hub waits and dials nothing,
// and a credential that another key signed for the period's tag after the
// forwarder saw the first one is refused.
func TestRustPhoneHubForwarder(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	f, pin := startForwarder(t, forward.Config{})
	h := startRustRootHub(t, startRustPhone(t, bin))

	h.register(f.Addr().String(), pin, "")
	h.waitFor("a hub without its credential", func(r map[string]any) bool {
		e, _ := r["error"].(string)
		return strings.Contains(e, "do not list this hub yet")
	})

	h.listed(1)
	h.waitFor("the forwarder never saw the hub", func(r map[string]any) bool {
		seen, _ := r["seen"].(string)
		ap, err := netip.ParseAddrPort(seen)
		return err == nil && ap.Port() == h.udpPort
	})
	h.echoThrough(f.Addr(), "through the forwarder")

	// Another period key for the same tag.
	h.period, _ = group.NewKey()
	h.listed(2)
	h.register(f.Addr().String(), pin, "")
	h.waitFor("a credential of another period key", func(r map[string]any) bool {
		e, _ := r["error"].(string)
		return strings.Contains(e, "first")
	})
	h.p.call(t, map[string]any{"op": "hub_stop", "id": h.id})
}

// TestRustPhoneHubCredentials: the phone's hub takes only the period's
// hubs' credential alone that lists its server key (docs/protocol.md,
// section 13): a credential that lists another key, or the period
// credential beside it, is refused before anything is dialled; with its
// own the hub registers, the forwarder then knows neither the device nor
// the group, and a client gets through the forwarder.
func TestRustPhoneHubCredentials(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	f, pin := startForwarder(t, forward.Config{})
	h := startRustRootHub(t, startRustPhone(t, bin))
	other, _ := group.NewKey()
	notListed := h.hubsCredential(1, other)
	if _, err := h.p.try(t, h.credentialsRequest(notListed)); err == nil {
		t.Error("a hubs' credential that does not list the hub's server key")
	}
	root, _ := group.NewKey()
	var gid [16]byte
	rand.Read(gid[:])
	period, err := blind.SignCredential(blind.Credential{Kind: blind.TypePeriod, Group: gid, Version: 1,
		ExpiresMs: uint64(time.Now().Add(time.Hour).UnixMilli()), Tag: &h.tag, Key: blind.Point(&h.period.PublicKey)}, root)
	if err != nil {
		t.Fatal(err)
	}
	req := h.credentialsRequest(h.hubsCredential(1, h.server))
	req["credentials"] = [][]byte{period, h.hubsCredential(1, h.server)}
	if _, err := h.p.try(t, req); err == nil {
		t.Error("the period credential beside the hubs'")
	}
	h.listed(1)
	h.register(f.Addr().String(), pin, "")
	h.waitFor("the forwarder never saw the hub registered by its credential", func(r map[string]any) bool {
		seen, _ := r["seen"].(string)
		ap, err := netip.ParseAddrPort(seen)
		return err == nil && ap.Port() == h.udpPort
	})
	h.echoThrough(f.Addr(), "through the forwarder, registered by the credential")
	h.p.call(t, map[string]any{"op": "hub_stop", "id": h.id})
}

// TestRustPhoneHubOverXHTTP runs the phone's hub in Rust against a Go
// forwarder with VLESS over XHTTP behind a web server: the hub learns the
// way over VLESS from its registration; when the forwarder's TCP port no
// longer answers, it registers inside VLESS through that way, its own
// packets go there too, and a client over VLESS gets through to it.
func TestRustPhoneHubOverXHTTP(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	path, err := tunnel.NewVLESSPath()
	if err != nil {
		t.Fatal(err)
	}
	vl := freeAddr(t)
	web, ca := vlesstest.WebServerCA(t, path, func() string { return vl.String() })
	vless.TrustForTests(ca)
	f, pin := startForwarder(t, forward.Config{
		VLESS: &forward.VLESSConfig{Listen: vl.String(), XHTTP: &forward.XHTTPConfig{Host: vlesstest.WebName, Port: web.Port(), Path: path}}})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	h := startRustRootHub(t, startRustPhone(t, bin, "SSL_CERT_FILE="+caFile))
	id, _ := tunnel.NewVLESSID()

	h.listed(1)
	h.register(f.Addr().String(), pin, id)
	var learned map[string]any
	h.waitFor("the hub never learned its way over VLESS", func(r map[string]any) bool {
		learned, _ = r["vless"].(map[string]any)
		seen, _ := r["seen"].(string)
		return learned != nil && seen != ""
	})

	// The forwarder's TCP port no longer answers.
	h.register(freeAddr(t).String(), pin, id)
	h.waitFor("the forwarder never saw the hub over VLESS", func(r map[string]any) bool {
		seen, _ := r["seen"].(string)
		ap, err := netip.ParseAddrPort(seen)
		// Over VLESS the forwarder sees the hub at the port its side of
		// VLESS sends the hub's packets from.
		return err == nil && ap.Port() != h.udpPort
	})
	b, _ := json.Marshal(learned)
	var link tunnel.VLESS
	if err := json.Unmarshal(b, &link); err != nil {
		t.Fatal(err)
	}
	vc, err := vless.Dial(link)
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()
	h.echoThrough(vc.Addr(), "over VLESS")
	h.p.call(t, map[string]any{"op": "hub_stop", "id": h.id})
}

// freeAddr returns a TCP address on the loopback that nothing listens on.
func freeAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).AddrPort()
}

// rustRootHub is the phone's hub in Rust, its member listener an echo
// server, with one Go client, and its group as the forwarder sees it: the
// period's tag and period key, and the hub's server key.
type rustRootHub struct {
	t                 *testing.T
	p                 *rustPhone
	id                any
	udpPort           uint16
	dev               group.DeviceID
	tag               [16]byte
	period, server    *ecdsa.PrivateKey
	hubKey, clientKey tunnel.Key
	psk               tunnel.Key
}

// startRustRootHub starts the phone's hub in p.
func startRustRootHub(t *testing.T, p *rustPhone) *rustRootHub {
	t.Helper()
	return startRustRootHubAt(t, p, "127.0.0.1:0")
}

// startRustRootHubAt is startRustRootHub with the hub's UDP socket on
// listen.
func startRustRootHubAt(t *testing.T, p *rustPhone, listen string) *rustRootHub {
	t.Helper()
	h := &rustRootHub{t: t, p: p, dev: group.NewDeviceID()}
	rand.Read(h.tag[:])
	var err error
	if h.period, err = group.NewKey(); err != nil {
		t.Fatal(err)
	}
	if h.server, err = group.NewKey(); err != nil {
		t.Fatal(err)
	}
	h.hubKey, _ = tunnel.NewPrivateKey()
	h.clientKey, _ = tunnel.NewPrivateKey()
	h.psk, _ = tunnel.NewPresharedKey()
	pub := h.clientKey.Public()
	started := p.call(t, map[string]any{"op": "hub_start", "key": h.hubKey[:], "device": string(h.dev),
		"clients":     []map[string]any{{"device": rustPhoneID, "key": pub[:], "psk": h.psk[:]}},
		"member_port": echoServer(t), "listen": listen})
	h.id, h.udpPort = started["id"], uint16(started["udp_port"].(float64))
	return h
}

// hubsCredential is the period's hubs' credential at version v, listing
// the server keys hubs, signed by the period key.
func (h *rustRootHub) hubsCredential(v uint64, hubs ...*ecdsa.PrivateKey) []byte {
	h.t.Helper()
	c := blind.Credential{Kind: blind.TypeHubs, Group: h.tag, Version: v, ExpiresMs: uint64(time.Now().Add(time.Hour).UnixMilli())}
	for _, k := range hubs {
		c.Hubs = append(c.Hubs, blind.KeyHash(blind.AlgES256, blind.Point(&k.PublicKey)))
	}
	env, err := blind.SignCredential(c, h.period)
	if err != nil {
		h.t.Fatal(err)
	}
	return env
}

// credentialsRequest gives the hub env as its credentials, with its
// server key, which the example signs with as the app would.
func (h *rustRootHub) credentialsRequest(env []byte) map[string]any {
	h.t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(h.server)
	if err != nil {
		h.t.Fatal(err)
	}
	return map[string]any{"op": "hub_credentials", "id": h.id, "public": blind.Point(&h.server.PublicKey),
		"test_key": pkcs8, "credentials": [][]byte{env}}
}

// listed gives the hub the hubs' credential at version v that lists its
// server key.
func (h *rustRootHub) listed(v uint64) {
	h.t.Helper()
	h.p.call(h.t, h.credentialsRequest(h.hubsCredential(v, h.server)))
}

// register registers the hub with the forwarder at endpoint, with the
// group's VLESS user ID or "".
func (h *rustRootHub) register(endpoint string, pin []byte, vlessID string) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(h.server)
	if err != nil {
		h.t.Fatal(err)
	}
	req := map[string]any{"op": "hub_register", "id": h.id, "endpoint": endpoint, "pins": [][]byte{pin}, "test_key": pkcs8}
	if vlessID != "" {
		req["vless_id"] = vlessID
	}
	h.p.call(h.t, req)
}

// waitFor waits for the registration's report to satisfy ok.
func (h *rustRootHub) waitFor(what string, ok func(map[string]any) bool) {
	h.t.Helper()
	var st map[string]any
	for range 300 {
		st = h.p.call(h.t, map[string]any{"op": "hub_status", "id": h.id})
		if r, _ := st["forwarder"].(map[string]any); r != nil && ok(r) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("%s: %v", what, st)
}

// echoThrough runs the client through endpoint to the hub's member
// listener and back.
func (h *rustRootHub) echoThrough(endpoint netip.AddrPort, msg string) {
	h.t.Helper()
	hubAddr, _ := tunnel.Addr(string(h.dev))
	clientAddr, _ := tunnel.Addr(rustPhoneID)
	cl, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: h.clientKey, PresharedKey: h.psk, Addr: clientAddr,
		HubPublicKey: h.hubKey.Public(), HubAddr: hubAddr, Endpoint: endpoint})
	if err != nil {
		h.t.Fatal(err)
	}
	defer cl.Close()
	if err := echoThrough(cl, msg); err != nil {
		h.t.Fatalf("%s: %v (status %v)", msg, err, h.p.call(h.t, map[string]any{"op": "hub_status", "id": h.id}))
	}
}

// echoServer is the app's member listener in the tests: an echo server on
// the loopback address, closed with the test; it returns its port.
func echoServer(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// echoThrough sends msg through the client's tunnel to an echo server and
// checks it comes back.
func echoThrough(cl *tunnel.Client, msg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := cl.Dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != msg {
		return fmt.Errorf("got %q, want %q", got, msg)
	}
	return nil
}

// echoThroughPort dials the loopback port a dial event named and checks
// that the other end echoes a line.
func echoThroughPort(t *testing.T, port any) {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := "hello from the phone\n"
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if got, err := bufio.NewReader(c).ReadString('\n'); err != nil || got != msg {
		t.Fatalf("the phone's dial: %q, %v", got, err)
	}
}
