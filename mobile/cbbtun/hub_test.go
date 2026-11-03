// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/group/grouptest"
	"github.com/HunterEwok/cbb/internal/invite"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// keySigner is a member key as the kits hand it over: it signs digests.
type keySigner struct{ k *ecdsa.PrivateKey }

func (s keySigner) SignDigest(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, s.k, d) }

// rootPhone is a group made on a phone: its member certificate chain as
// Register takes it, its member key, and its own device record, signed by
// its root key, as JSON.
type rootPhone struct {
	device  string
	chain   string
	key     *ecdsa.PrivateKey
	records string
}

func newRootPhone(t *testing.T) rootPhone {
	t.Helper()
	now := time.Now()
	ca, err := group.NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := group.NewKey()
	dev := group.NewDeviceID()
	leaf, err := ca.IssueMember(dev, &key.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	k := group.KeyHashOf(leaf)
	own := grouptest.Sign(t, group.RecordBody{Type: group.RecordDevice, Group: group.Tag(ca.Cert), TimeMS: now.UnixMilli(),
		Device: string(dev), Name: "iPhone", Role: group.RolePhone, Key: &k, HoldsRoot: true}, ca.Key)
	chain, _ := json.Marshal([][]byte{leaf.Raw, ca.Cert.Raw})
	records, _ := json.Marshal([]group.Record{own})
	return rootPhone{device: string(dev), chain: string(chain), key: key, records: string(records)}
}

func startForwarder(t *testing.T) (*forward.Forwarder, string) {
	t.Helper()
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return f, forward.Pin(cert.Leaf)
}

// echo stands for the kit's member listener: it sends back what it gets.
func echo(t *testing.T) int {
	t.Helper()
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
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// status waits until the hub's status satisfies done.
func status(t *testing.T, h *Hub, done func(s map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var s map[string]any
		if err := json.Unmarshal([]byte(h.Status()), &s); err != nil {
			t.Fatal(err)
		}
		if done(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("the hub's status stayed %v", s)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestPhoneHub registers a root phone's hub with the forwarder by its
// member key alone, and a client reaches the phone's member listener
// through the forwarder and the tunnel.
func TestPhoneHub(t *testing.T) {
	f, pin := startForwarder(t)
	phone := newRootPhone(t)
	hubPriv, _ := NewKey()
	hubPub, _ := PublicKey(hubPriv)

	clientPriv, _ := NewKey()
	clientPub, _ := PublicKey(clientPriv)
	psk, _ := tunnel.NewPresharedKey()
	clients, _ := json.Marshal([]Client{{Device: phoneID, Key: clientPub, PSK: psk[:]}})

	hub, err := StartHub(hubPriv, phone.device, echo(t), "", string(clients))
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if hub.Status() != "{}" {
		t.Errorf("the status before Register: %s", hub.Status())
	}
	if err := hub.Register(f.Addr().String(), pin, phone.chain, keySigner{phone.key}, phone.records, ""); err != nil {
		t.Fatal(err)
	}
	if err := hub.Register(f.Addr().String(), pin, phone.chain, keySigner{phone.key}, phone.records, ""); err == nil {
		t.Error("a second Register succeeded")
	}
	status(t, hub, func(s map[string]any) bool { return s["seen"] != nil })

	tun, err := Start(clientPriv, psk[:], hubPub, phoneID, phone.device, f.Addr().String(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	msg := []byte("through the phone")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}

	// A client the hub drops is cut off.
	if err := hub.SetClients(""); err != nil {
		t.Fatal(err)
	}
}

// TestPhoneHubWithoutRecords checks that the forwarder refuses a phone hub
// whose records do not make its member key the root's, that Status says
// why, and that SetRecords mends it.
func TestPhoneHubWithoutRecords(t *testing.T) {
	f, pin := startForwarder(t)
	phone := newRootPhone(t)
	hubPriv, _ := NewKey()
	hub, err := StartHub(hubPriv, phone.device, echo(t), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	if err := hub.Register(f.Addr().String(), pin, phone.chain, keySigner{phone.key}, "", ""); err != nil {
		t.Fatal(err)
	}
	s := status(t, hub, func(s map[string]any) bool { return s["error"] != nil })
	if !strings.Contains(s["error"].(string), "neither") {
		t.Errorf("the error: %v", s["error"])
	}
	// With the records, the next registration is taken.
	if err := hub.SetRecords("{"); err == nil {
		t.Error("SetRecords took bad records")
	}
	if err := hub.SetRecords(phone.records); err != nil {
		t.Fatal(err)
	}
	status(t, hub, func(s map[string]any) bool { return s["registered"] == true })
}

func TestHubBadArguments(t *testing.T) {
	priv, _ := NewKey()
	if h, err := StartHub(priv[:31], hubID, 1, "", ""); err == nil {
		h.Close()
		t.Error("a short key")
	}
	if h, err := StartHub(priv, "HUB", 1, "", ""); err == nil {
		h.Close()
		t.Error("a bad device")
	}
	if h, err := StartHub(priv, hubID, 0, "", ""); err == nil {
		h.Close()
		t.Error("no member port")
	}
	if h, err := StartHub(priv, hubID, 1, "", `[{"device":"x"}]`); err == nil {
		h.Close()
		t.Error("a bad client")
	}
	h, err := StartHub(priv, hubID, 1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	phone := newRootPhone(t)
	pin := strings.Repeat("A", 43) + "="
	for name, call := range map[string]func() error{
		"bad endpoint": func() error { return h.Register("cbb.tools:8764", pin, phone.chain, keySigner{phone.key}, "", "") },
		"bad pin":      func() error { return h.Register("127.0.0.1:1", "pin", phone.chain, keySigner{phone.key}, "", "") },
		"no chain":     func() error { return h.Register("127.0.0.1:1", pin, "[]", keySigner{phone.key}, "", "") },
		"no signer":    func() error { return h.Register("127.0.0.1:1", pin, phone.chain, nil, "", "") },
		"bad records":  func() error { return h.Register("127.0.0.1:1", pin, phone.chain, keySigner{phone.key}, "{", "") },
		"bad VLESS ID": func() error { return h.Register("127.0.0.1:1", pin, phone.chain, keySigner{phone.key}, "", "x") },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: Register succeeded", name)
		}
	}
}

// says stands for a listener of the kit that says who it is and hangs up.
func says(t *testing.T, word string) int {
	t.Helper()
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
			c.Write([]byte(word))
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestPhoneHubInvitation opens a remote invitation on the phone's hub: the
// guest key in its text reaches the pairing window, then, once the window
// admitted the device, the member port, and nothing after Close.
func TestPhoneHubInvitation(t *testing.T) {
	phone := newRootPhone(t)
	hubPriv, _ := NewKey()
	hub, err := StartHub(hubPriv, phone.device, says(t, "member"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	window := says(t, "window")
	at := fmt.Sprintf(`["127.0.0.1:%d"]`, hub.UDPPort())
	for name, call := range map[string]func() (*Guest, error){
		"no lifetime":  func() (*Guest, error) { return hub.Invite("tag", at, 0, window) },
		"two days":     func() (*Guest, error) { return hub.Invite("tag", at, 2*86400, window) },
		"no port":      func() (*Guest, error) { return hub.Invite("tag", at, 3600, 0) },
		"bad endpoint": func() (*Guest, error) { return hub.Invite("tag", `["cbb.tools:8764"]`, 3600, window) },
		"no endpoints": func() (*Guest, error) { return hub.Invite("tag", `[]`, 3600, window) },
		"not JSON":     func() (*Guest, error) { return hub.Invite("tag", "127.0.0.1:1", 3600, window) },
	} {
		if _, err := call(); err == nil {
			t.Errorf("%s: Invite succeeded", name)
		}
	}
	tag := group.Tag(mustCert(t, phone.chain))
	g, err := hub.Invite(tag, at, 3600, window)
	if err != nil {
		t.Fatal(err)
	}
	in, err := invite.Parse(g.Text())
	if err != nil {
		t.Fatal(err)
	}
	if in.Hub != phone.device || in.Group != tag || !bytes.Equal(in.Secret, g.Secret()) || len(in.Secret) != 16 ||
		in.Expires.Unix() != g.Expires() || in.HubKey != mustKey(t, hubPriv).Public() {
		t.Fatalf("the invitation: %+v", in)
	}
	hubAddr, _ := tunnel.Addr(in.Hub)
	c, err := tunnel.StartClient(tunnel.ClientConfig{PrivateKey: in.GuestKey, PresharedKey: in.GuestPSK, Addr: tunnel.GuestAddr(in.GuestKey.Public()),
		HubPublicKey: in.HubKey, HubAddr: hubAddr, Endpoint: in.Endpoints[0], Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hears := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := c.Dial(ctx)
		if err != nil {
			return ""
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		b, _ := io.ReadAll(conn)
		return string(b)
	}
	if got := hears(); got != "window" {
		t.Fatalf("before the device is admitted the guest reached %q", got)
	}
	g.Admitted()
	if got := hears(); got != "member" {
		t.Fatalf("after the device was admitted the guest reached %q", got)
	}
	g.Close()
	if got := hears(); got != "" {
		t.Fatalf("after Close the guest reached %q", got)
	}
}

func mustCert(t *testing.T, chain string) *x509.Certificate {
	t.Helper()
	var ders [][]byte
	json.Unmarshal([]byte(chain), &ders)
	c, err := x509.ParseCertificate(ders[len(ders)-1])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustKey(t *testing.T, b []byte) tunnel.Key {
	t.Helper()
	k, err := key(b, "key")
	if err != nil {
		t.Fatal(err)
	}
	return k
}
