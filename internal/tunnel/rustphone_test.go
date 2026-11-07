// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel_test

import (
	"bufio"
	"bytes"
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
