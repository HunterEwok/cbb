// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
	"github.com/HunterEwok/cbb/internal/invite"
	"github.com/HunterEwok/cbb/internal/relay"
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

// TestRustPhoneHubForwarder registers the Rust hub with a Go forwarder, as a
// root phone does with its member key and its device record, and a Go
// client reaches the hub's member port through the forwarder; a hub whose
// records do not make it the root is refused.
func TestRustPhoneHubForwarder(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	fcert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: fcert, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		f.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()

	// The root phone: its member certificate and the device record its root
	// key signed.
	now := time.Now()
	root, err := group.NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	memberKey, err := group.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dev := group.NewDeviceID()
	leaf, err := root.IssueMember(dev, &memberKey.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(memberKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := memberKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	kh := group.KeyHashOf(leaf)
	own := grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: group.Tag(root.Cert), TimeMS: now.UnixMilli(),
		Device: string(dev), Name: "phone", Role: group.RolePhone, Key: &kh, HoldsRoot: true}, root.Key)

	member := echoServer(t)
	hubKey, _ := tunnel.NewPrivateKey()
	hubAddr, _ := tunnel.Addr(string(dev))
	clientKey, _ := tunnel.NewPrivateKey()
	psk, _ := tunnel.NewPresharedKey()
	clientAddr, _ := tunnel.Addr(rustPhoneID)
	pub := clientKey.Public()
	p := startRustPhone(t, bin)
	started := p.call(t, map[string]any{"op": "hub_start", "key": hubKey[:], "device": string(dev),
		"clients":     []map[string]any{{"device": rustPhoneID, "key": pub[:], "psk": psk[:]}},
		"member_port": member, "listen": "127.0.0.1:0"})
	id := started["id"]
	pin, _ := base64.StdEncoding.DecodeString(forward.Pin(fcert.Leaf))
	register := func(records []group.Record) {
		p.call(t, map[string]any{"op": "hub_register", "id": id, "endpoint": f.Addr().String(), "pins": [][]byte{pin},
			"chain": [][]byte{leaf.Raw, root.Cert.Raw}, "public": public, "records": records, "test_key": pkcs8})
	}
	// waitFor waits for the registration's report to satisfy ok.
	waitFor := func(what string, ok func(map[string]any) bool) {
		t.Helper()
		var st map[string]any
		for range 100 {
			st = p.call(t, map[string]any{"op": "hub_status", "id": id})
			if r, _ := st["forwarder"].(map[string]any); r != nil && ok(r) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: %v", what, st)
	}

	// Without its device record the phone is a plain member.
	register(nil)
	waitFor("a hub that is no admin", func(r map[string]any) bool {
		e, _ := r["error"].(string)
		return strings.Contains(e, "neither")
	})

	register([]group.Record{own})
	waitFor("the forwarder never saw the hub", func(r map[string]any) bool {
		seen, _ := r["seen"].(string)
		ap, err := netip.ParseAddrPort(seen)
		return err == nil && ap.Port() == uint16(started["udp_port"].(float64))
	})
	cl, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: clientKey, PresharedKey: psk, Addr: clientAddr,
		HubPublicKey: hubKey.Public(), HubAddr: hubAddr, Endpoint: f.Addr()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if err := echoThrough(cl, "through the forwarder"); err != nil {
		t.Fatalf("through the forwarder: %v (status %v)", err, p.call(t, map[string]any{"op": "hub_status", "id": id}))
	}
	p.call(t, map[string]any{"op": "hub_stop", "id": id})
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

// TestRustPhoneRelay links the Rust phone to a Go blind relay with two Go
// members of its group: the one with the lower ID dials the phone, whose
// connection reaches the app's member listener with a "calling" event,
// and the phone dials the other, through the port of its "dial" event.
func TestRustPhoneRelay(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	now := time.Now()
	ca, err := group.NewGroupCA(now)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen(relay.Config{Listen: "127.0.0.1:0", Keys: keys, Groups: []string{group.Tag(ca.Cert)}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var done []chan struct{}
	defer func() {
		cancel()
		for _, d := range done {
			<-d
		}
	}()
	go func() {
		r.Serve(ctx)
	}()
	link := relay.Link{Endpoint: netip.MustParseAddrPort(r.Addr().String()), Pin: keys.Pin()}

	type device struct {
		id   string
		key  *ecdsa.PrivateKey
		leaf *x509.Certificate
	}
	var ds []device
	for range 3 {
		k, err := group.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		id := group.NewDeviceID()
		leaf, err := ca.IssueMember(id, &k.PublicKey, now)
		if err != nil {
			t.Fatal(err)
		}
		ds = append(ds, device{string(id), k, leaf})
	}
	slices.SortFunc(ds, func(a, b device) int { return strings.Compare(a.id, b.id) })
	low, phone, high := ds[0], ds[1], ds[2]

	// The Go members: low dials the phone (and high), high answers it.
	dialed, called := make(chan error, 4), make(chan error, 4)
	for _, d := range []device{low, high} {
		wg, _ := tunnel.NewPrivateKey()
		cert := tls.Certificate{Certificate: [][]byte{d.leaf.Raw, ca.Cert.Raw}, PrivateKey: d.key, Leaf: d.leaf}
		cfg := relay.MemberConfig{Link: link, Self: d.id, Key: wg,
			Cert: func() tls.Certificate { return cert },
			Want: func(string) bool { return true },
			Dialed: func(ctx context.Context, peer string, c net.Conn) error {
				msg := "hello from " + d.id + "\n"
				_, err := c.Write([]byte(msg))
				if err == nil {
					var got string
					if got, err = bufio.NewReader(c).ReadString('\n'); err == nil && got != msg {
						err = fmt.Errorf("a wrong echo %q", got)
					}
				}
				if peer == phone.id {
					dialed <- err
				}
				<-ctx.Done()
				return err
			},
			Called: func(ctx context.Context, peer string, c net.Conn) error {
				got, err := bufio.NewReader(c).ReadString('\n')
				if err == nil && got != "hello from "+peer+"\n" {
					err = fmt.Errorf("a call from %s: %q", peer, got)
				}
				if err == nil {
					_, err = c.Write([]byte(got))
				}
				if peer == phone.id {
					called <- err
				}
				<-ctx.Done()
				return err
			},
			Logf: t.Logf}
		d := make(chan struct{})
		done = append(done, d)
		go func() {
			defer close(d)
			relay.Join(ctx, cfg)
		}()
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(phone.key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := phone.key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := base64.StdEncoding.DecodeString(keys.Pin())
	wg, _ := tunnel.NewPrivateKey()
	p := startRustPhone(t, bin)
	started := p.call(t, map[string]any{"op": "relay_start", "key": wg[:], "device": phone.id, "endpoint": link.Endpoint.String(),
		"pins": [][]byte{pin}, "chain": [][]byte{phone.leaf.Raw, ca.Cert.Raw}, "public": public,
		"member_port": echoServer(t), "test_key": pkcs8})
	id := started["id"]

	var calling, dialedPhone, online bool
	var last []any
	deadline := time.Now().Add(30 * time.Second)
	for !(calling && dialedPhone && online) {
		if time.Now().After(deadline) {
			t.Fatalf("calling %v, the phone dialed %v, both online %v; events %v", calling, dialedPhone, online, last)
		}
		evs, _ := p.call(t, map[string]any{"op": "test_events"})["events"].([]any)
		for _, e := range evs {
			e := e.(map[string]any)
			last = append(last, e)
			if len(last) > 20 {
				last = last[1:]
			}
			switch e["type"] {
			case "calling":
				if e["peer"] != low.id {
					t.Fatalf("a call from %v", e["peer"])
				}
				calling = true
			case "dial":
				if e["peer"] != high.id {
					t.Fatalf("a dial to %v", e["peer"])
				}
				c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(e["port"])))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				msg := "hello from " + phone.id + "\n"
				c.SetDeadline(time.Now().Add(15 * time.Second))
				if _, err := c.Write([]byte(msg)); err != nil {
					t.Fatal(err)
				}
				if got, err := bufio.NewReader(c).ReadString('\n'); err != nil || got != msg {
					t.Fatalf("the phone's dial: %q, %v", got, err)
				}
				dialedPhone = true
			case "changed":
				if on, _ := e["online"].([]any); e["connected"] == true && len(on) == 2 {
					online = true
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, ch := range []chan error{dialed, called} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("a Go member did not finish its connection with the phone")
		}
	}
	p.call(t, map[string]any{"op": "relay_stop", "id": id})
}

// TestRustPhoneRelayCredentials: the phone's link starts with its member
// certificate, then registers again with the group's server credentials
// (docs/protocol.md, section 18) at a relay that serves a fixed list of
// groups, so that it shows the period credential and the group's root; a
// Go member registers the same way, the relay knows both by pseudonyms,
// and the phone's events still name the Go member by its device ID.
func TestRustPhoneRelayCredentials(t *testing.T) {
	bin := os.Getenv("CBB_TUNNEL_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_TUNNEL_ON_LINUX is not set")
	}
	now := time.Now()
	ca, err := group.NewGroupCA(now)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen(relay.Config{Listen: "127.0.0.1:0", Keys: keys, Groups: []string{group.Tag(ca.Cert)}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.Serve(ctx)
	}()
	link := relay.Link{Endpoint: netip.MustParseAddrPort(r.Addr().String()), Pin: keys.Pin()}

	// The period, the two server keys and the lists.
	tag, _ := group.NewPeriodTag()
	periodKey, _ := group.NewKey()
	period, err := group.SignPeriod(group.Tag(ca.Cert), tag, &periodKey.PublicKey, 1, now, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := period.Open()
	phoneServer, _ := group.NewKey()
	pcServer, _ := group.NewKey()
	phoneHash, pcHash := group.PublicKeyHash(&phoneServer.PublicKey), group.PublicKeyHash(&pcServer.PublicKey)
	hubs, err := group.SignHubs(pb, []group.KeyHash{pcHash}, nil, 1, periodKey)
	if err != nil {
		t.Fatal(err)
	}
	members, err := group.SignMembers(pb, []group.KeyHash{phoneHash, pcHash}, 1, periodKey)
	if err != nil {
		t.Fatal(err)
	}
	others, err := group.SignMembers(pb, []group.KeyHash{pcHash}, 2, periodKey)
	if err != nil {
		t.Fatal(err)
	}

	pcID := string(group.NewDeviceID())
	pcCert, err := group.ServerCertificate(pcServer)
	if err != nil {
		t.Fatal(err)
	}
	wgPC, _ := tunnel.NewPrivateKey()
	pcDone := make(chan struct{})
	echoed := make(chan error, 4)
	go func() {
		defer close(pcDone)
		relay.Join(ctx, relay.MemberConfig{
			Link: link, Self: pcID, Key: wgPC,
			Cert: func() tls.Certificate { return tls.Certificate{} },
			Credentialed: func() (relay.Credentialed, bool) {
				return relay.Credentialed{Cert: pcCert, Self: group.Pseudonym(pcHash), Creds: []group.Credential{hubs, members},
					Period: period, Roots: [][]byte{ca.Cert.Raw}}, true
			},
			Want: func(string) bool { return true },
			Dialed: func(ctx context.Context, _ string, c net.Conn) error {
				// The phone's member listener echoes.
				msg := "hello from the computer\n"
				_, err := c.Write([]byte(msg))
				if err == nil {
					var got string
					if got, err = bufio.NewReader(c).ReadString('\n'); err == nil && got != msg {
						err = fmt.Errorf("a wrong echo %q", got)
					}
				}
				echoed <- err
				<-ctx.Done()
				return err
			},
			Called: func(ctx context.Context, _ string, c net.Conn) error {
				line, err := bufio.NewReader(c).ReadString('\n')
				if err == nil {
					_, err = c.Write([]byte(line))
				}
				<-ctx.Done()
				return err
			},
			Logf: t.Logf,
		})
	}()
	defer func() {
		cancel()
		<-served
		<-pcDone
	}()

	phone := string(group.NewDeviceID())
	memberKey, _ := group.NewKey()
	leaf, err := ca.IssueMember(group.DeviceID(phone), &memberKey.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := func(k *ecdsa.PrivateKey) []byte {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	point := func(k *ecdsa.PrivateKey) []byte {
		b, err := k.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pin, _ := base64.StdEncoding.DecodeString(keys.Pin())
	wg, _ := tunnel.NewPrivateKey()
	p := startRustPhone(t, bin)
	id := p.call(t, map[string]any{"op": "relay_start", "key": wg[:], "device": phone, "endpoint": link.Endpoint.String(),
		"pins": [][]byte{pin}, "chain": [][]byte{leaf.Raw, ca.Cert.Raw}, "public": point(memberKey),
		"member_port": echoServer(t), "test_key": pkcs8(memberKey)})["id"]
	defer p.call(t, map[string]any{"op": "relay_stop", "id": id})

	creds := func(cs ...group.Credential) map[string]any {
		return map[string]any{"op": "relay_credentials", "id": id, "public": point(phoneServer), "test_key": pkcs8(phoneServer),
			"credentials": cs, "roots": [][]byte{ca.Cert.Raw}, "names": map[string]string{group.Pseudonym(pcHash): pcID}}
	}
	if _, err := p.try(t, creds(hubs, others, period)); err == nil {
		t.Error("credentials whose members' list leaves the phone out")
	}
	p.call(t, creds(hubs, members, period))

	var through, online bool
	var last []any
	deadline := time.Now().Add(30 * time.Second)
	for !(through && online) {
		if time.Now().After(deadline) {
			t.Fatalf("through %v, online %v; events %v", through, online, last)
		}
		evs, _ := p.call(t, map[string]any{"op": "test_events"})["events"].([]any)
		for _, e := range evs {
			e := e.(map[string]any)
			last = append(last, e)
			if len(last) > 20 {
				last = last[1:]
			}
			switch e["type"] {
			case "calling":
				if e["peer"] != pcID {
					t.Fatalf("a call from %v, want the computer by its ID", e["peer"])
				}
				select {
				case err := <-echoed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(15 * time.Second):
					t.Fatal("the computer's call did not come through")
				}
				through = true
			case "dial":
				if e["peer"] != pcID {
					t.Fatalf("a dial to %v, want the computer by its ID", e["peer"])
				}
				echoThroughPort(t, e["port"])
				through = true
			case "changed":
				if on, _ := e["online"].([]any); e["connected"] == true && len(on) == 1 {
					if on[0] != pcID {
						t.Fatalf("online %v, want the computer by its ID", on)
					}
					online = true
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
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
