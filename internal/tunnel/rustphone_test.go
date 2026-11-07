// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/invite"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
	"github.com/HunterEwok/cbb/internal/vless/vlesstest"
)

const (
	rustHubID   = "00112233445566778899aabbccddeeff"
	rustPhoneID = "ffeeddccbbaa99887766554433221100"
)

// TestRustPhoneTunnel runs the phones' tunnel in Rust (lite/ffi, the
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
		t.Fatalf("%s: %v", b, a.Error)
	}
	return a.OK
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

// TestRustPhoneHub runs the phone's hub in Rust (lite/ffi) with two Go
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
	// The app's member listener: an echo server on the loopback address.
	member, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer member.Close()
	go func() {
		for {
			c, err := member.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

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
		"member_port": member.Addr().(*net.TCPAddr).Port, "listen": "127.0.0.1:0"}
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
	echo := func(cl *tunnel.Client, msg string) error {
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
	for i, cl := range clients {
		if err := echo(cl, fmt.Sprintf("hello from %d", i)); err != nil {
			t.Fatalf("client %d through the Rust hub: %v (status %v)", i, err, p.call(t, map[string]any{"op": "hub_status", "id": id}))
		}
	}
	// The second client goes off the list: it is cut off, the first stays.
	p.call(t, map[string]any{"op": "hub_set_clients", "id": id, "clients": list[:1]})
	if err := echo(clients[1], "still there?"); err == nil {
		t.Fatal("a client taken off the list still reaches the member port")
	}
	if err := echo(clients[0], "again"); err != nil {
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
