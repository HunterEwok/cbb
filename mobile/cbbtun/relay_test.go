// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package cbbtun

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/relay"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// fakeKit plays the kit for a relay: it echoes a line on each connection,
// dialed or called, and keeps which peer each called connection is.
type fakeKit struct {
	t       *testing.T
	ln      net.Listener
	mu      sync.Mutex
	calling map[int]string
	served  chan string // "dial <peer>" or "call <peer>"
	states  chan RelayState
}

func newFakeKit(t *testing.T) *fakeKit {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKit{t: t, ln: ln, calling: map[int]string{}, served: make(chan string, 8), states: make(chan RelayState, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			port := c.RemoteAddr().(*net.TCPAddr).Port
			go func() {
				// The kit checks the peer after the handshake; here, after
				// the first line.
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				k.mu.Lock()
				peer := k.calling[port]
				k.mu.Unlock()
				c.Write([]byte(line))
				k.served <- "call " + peer
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return k
}

func (k *fakeKit) Dial(peer string, port int) {
	go func() {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			k.t.Errorf("the dial's port: %v", err)
			return
		}
		msg := "hello from the phone\n"
		c.Write([]byte(msg))
		got, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || got != msg {
			k.t.Errorf("the echo through the relay: %q, %v", got, err)
			return
		}
		k.served <- "dial " + peer
	}()
}

func (k *fakeKit) Calling(peer string, localPort int) {
	k.mu.Lock()
	k.calling[localPort] = peer
	k.mu.Unlock()
}

func (k *fakeKit) Wanted(string) bool { return true }

func (k *fakeKit) Changed(state string) {
	var st RelayState
	if err := json.Unmarshal([]byte(state), &st); err != nil {
		k.t.Errorf("a state that does not decode: %s", state)
	}
	select {
	case k.states <- st:
	default:
	}
}

// computer is a Go member of the group at the relay: it echoes a line on a
// call, and on a dial sends one and expects it back.
func computer(t *testing.T, ca *group.CA, link relay.Link, id string) {
	t.Helper()
	key, _ := group.NewKey()
	leaf, err := ca.IssueMember(group.DeviceID(id), &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wg, _ := tunnel.NewPrivateKey()
	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		relay.Join(ctx, relay.MemberConfig{
			Link: link, Self: id, Key: wg,
			Cert: func() tls.Certificate { return cert },
			Want: func(string) bool { return true },
			Dialed: func(ctx context.Context, _ string, c net.Conn) error {
				c.Write([]byte("hello from " + id + "\n"))
				if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
					return err
				}
				<-ctx.Done()
				return nil
			},
			Called: func(ctx context.Context, _ string, c net.Conn) error {
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return err
				}
				c.Write([]byte(line))
				<-ctx.Done()
				return nil
			},
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// TestPhoneAtRelay: a phone meets two computers at an open relay. It dials
// the one with the higher ID and answers the one with the lower, and the
// kit learns whose each call is.
func TestPhoneAtRelay(t *testing.T) {
	keys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen(relay.Config{Listen: "127.0.0.1:0", Keys: keys, Open: true, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()
	link := relay.Link{Endpoint: netip.MustParseAddrPort(r.Addr().String()), Pin: keys.Pin()}

	ca, err := group.NewRootCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	phone := "80000000000000000000000000000000"
	low, high := "10000000000000000000000000000000", "f0000000000000000000000000000000"
	key, _ := group.NewKey()
	leaf, err := ca.IssueMember(group.DeviceID(phone), &key.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := json.Marshal([][]byte{leaf.Raw, ca.Cert.Raw})
	wg, _ := NewKey()
	kit := newFakeKit(t)
	ph, err := StartRelay(wg, phone, link.Endpoint.String(), keys.Pin(), string(chain), keySigner{key}, "", kit.ln.Addr().(*net.TCPAddr).Port, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer ph.Close()
	computer(t, ca, link, low)
	computer(t, ca, link, high)

	want := map[string]bool{"dial " + high: true, "call " + low: true}
	deadline := time.After(30 * time.Second)
	for len(want) > 0 {
		select {
		case s := <-kit.served:
			if !want[s] {
				t.Fatalf("the kit served %q, want one of %v", s, want)
			}
			delete(want, s)
		case <-deadline:
			t.Fatalf("timed out; still waiting for %v", want)
		}
	}
	for {
		select {
		case st := <-kit.states:
			if st.Connected && len(st.Online) == 2 {
				return
			}
		case <-deadline:
			t.Fatal("the kit never heard that both computers are on the relay")
		}
	}
}

// TestPhoneAtRelayWithCredentials: a phone and a computer register with
// the group's server credentials, so the relay knows them by pseudonyms;
// the kit still hears of the computer by its device ID.
func TestPhoneAtRelayWithCredentials(t *testing.T) {
	keys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen(relay.Config{Listen: "127.0.0.1:0", Keys: keys, Open: true, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		r.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()
	link := relay.Link{Endpoint: netip.MustParseAddrPort(r.Addr().String()), Pin: keys.Pin()}

	// The period, the two server keys and the lists.
	ca, err := group.NewRootCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tag, _ := group.NewPeriodTag()
	periodKey, _ := group.NewKey()
	pc, err := group.SignPeriod(group.Tag(ca.Cert), tag, &periodKey.PublicKey, 1, now, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pc.Open()
	phoneKey, _ := group.NewKey()
	pcKey, _ := group.NewKey()
	phoneHash, pcHash := group.PublicKeyHash(&phoneKey.PublicKey), group.PublicKeyHash(&pcKey.PublicKey)
	hubs, err := group.SignHubs(p, []group.KeyHash{pcHash}, nil, 1, periodKey)
	if err != nil {
		t.Fatal(err)
	}
	members, err := group.SignMembers(p, []group.KeyHash{phoneHash, pcHash}, 1, periodKey)
	if err != nil {
		t.Fatal(err)
	}

	pcID := "f0000000000000000000000000000000"
	pcCert, err := group.ServerCertificate(pcKey)
	if err != nil {
		t.Fatal(err)
	}
	wgPC, _ := tunnel.NewPrivateKey()
	pcCtx, pcCancel := context.WithCancel(context.Background())
	pcDone := make(chan struct{})
	go func() {
		defer close(pcDone)
		relay.Join(pcCtx, relay.MemberConfig{
			Link: link, Self: pcID, Key: wgPC,
			Cert: func() tls.Certificate { return tls.Certificate{} },
			Credentialed: func() (relay.Credentialed, bool) {
				return relay.Credentialed{Cert: pcCert, Self: group.Pseudonym(pcHash), Creds: []group.Credential{hubs, members}}, true
			},
			Want: func(string) bool { return true },
			Dialed: func(ctx context.Context, _ string, c net.Conn) error {
				c.Write([]byte("hello from the computer\n"))
				if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
					return err
				}
				<-ctx.Done()
				return nil
			},
			Called: func(ctx context.Context, _ string, c net.Conn) error {
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return err
				}
				c.Write([]byte(line))
				<-ctx.Done()
				return nil
			},
		})
	}()
	defer func() {
		pcCancel()
		<-pcDone
	}()

	phone := "80000000000000000000000000000000"
	memberKey, _ := group.NewKey()
	leaf, err := ca.IssueMember(group.DeviceID(phone), &memberKey.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := json.Marshal([][]byte{leaf.Raw, ca.Cert.Raw})
	wg, _ := NewKey()
	kit := newFakeKit(t)
	ph, err := StartRelay(wg, phone, link.Endpoint.String(), keys.Pin(), string(chain), keySigner{memberKey}, "", kit.ln.Addr().(*net.TCPAddr).Port, kit)
	if err != nil {
		t.Fatal(err)
	}
	defer ph.Close()
	spki, _ := x509.MarshalPKIXPublicKey(&phoneKey.PublicKey)
	creds, _ := json.Marshal([]group.Credential{hubs, members, pc})
	names, _ := json.Marshal(map[string]string{group.Pseudonym(pcHash): pcID})
	if err := ph.SetCredentials(spki, keySigner{phoneKey}, string(creds), "", string(names)); err != nil {
		t.Fatal(err)
	}
	if err := ph.SetCredentials(spki, keySigner{phoneKey}, string(creds[:len(creds)-2]), "", ""); err == nil {
		t.Error("credentials that do not decode")
	}

	deadline := time.After(30 * time.Second)
	select {
	case s := <-kit.served:
		if s != "dial "+pcID && s != "call "+pcID {
			t.Fatalf("the kit served %q, want the computer by its ID", s)
		}
	case <-deadline:
		t.Fatal("timed out waiting for the computer through the relay")
	}
	for {
		select {
		case st := <-kit.states:
			if st.Connected && len(st.Online) == 1 && st.Online[0] == pcID {
				return
			}
		case <-deadline:
			t.Fatal("the kit never heard that the computer is on the relay")
		}
	}
}

func TestRelayBadArguments(t *testing.T) {
	wg, _ := NewKey()
	kit := &fakeKit{t: t}
	for _, c := range []struct {
		name               string
		key                []byte
		endpoint, pin, dev string
		port               int
		events             RelayEvents
	}{
		{"short key", []byte{1}, "127.0.0.1:8764", pad43, okDevice, 1, kit},
		{"no port", wg, "127.0.0.1", pad43, okDevice, 1, kit},
		{"bad pin", wg, "127.0.0.1:8764", "nope", okDevice, 1, kit},
		{"bad device", wg, "127.0.0.1:8764", pad43, "phone", 1, kit},
		{"no member port", wg, "127.0.0.1:8764", pad43, okDevice, 0, kit},
		{"no events", wg, "127.0.0.1:8764", pad43, okDevice, 1, nil},
	} {
		if _, err := StartRelay(c.key, c.dev, c.endpoint, c.pin, "[]", keySigner{}, "", c.port, c.events); err == nil {
			t.Errorf("%s: no error", c.name)
		}
	}
}

const okDevice = "0123456789abcdef0123456789abcdef"

var pad43 = strings.Repeat("A", 43) + "="
