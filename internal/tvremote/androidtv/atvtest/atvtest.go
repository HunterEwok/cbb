// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package atvtest is a fake Android TV for tests: the pairing port with
// its code, and the remote port with a text field the test opens.
package atvtest

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/HunterEwok/cbb/internal/tvremote/androidtv"
	"github.com/HunterEwok/cbb/internal/tvremote/androidtv/wire"
)

// TV is the fake TV. Its ports are random; PairAddr and RemoteAddr name them.
type TV struct {
	key  *rsa.PrivateKey
	cert tls.Certificate

	pair, remote net.Listener

	mu      sync.Mutex
	code    string
	focused bool
	paired  map[[32]byte]bool
	conns   []*remoteConn
	text    []string // what came into the text field, one edit each
	keys    []uint64
	changed chan struct{}
}

type remoteConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func (c *remoteConn) send(m wire.Builder) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return wire.Write(c.conn, m)
}

// New starts a TV, closed with the test.
func New(t testing.TB) *TV {
	t.Helper()
	tv, err := Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tv.Close)
	return tv
}

// Start starts a TV whose pairing port listens at addr, the remote port
// one below; port 0 picks two free ports in a row. The bench's forge runs
// it as a TV on the network; the caller closes it.
func Start(addr string) (*TV, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	tv := &TV{
		key:     key,
		cert:    tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		paired:  map[[32]byte]bool{},
		changed: make(chan struct{}, 1),
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{tv.cert}, ClientAuth: tls.RequireAnyClientCert}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// The remote port is the one below the pairing port, as on a TV.
	for range 100 {
		if tv.pair, err = tls.Listen("tcp", net.JoinHostPort(host, port), cfg); err != nil {
			return nil, err
		}
		p := tv.pair.Addr().(*net.TCPAddr).Port
		if tv.remote, err = tls.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(p-1)), cfg); err == nil {
			break
		}
		tv.pair.Close()
		tv.pair = nil
		if port != "0" {
			return nil, err
		}
	}
	if tv.remote == nil {
		return nil, errors.New("no two ports in a row are free")
	}
	go tv.accept(tv.pair, tv.servePairing)
	go tv.accept(tv.remote, tv.serveRemote)
	return tv, nil
}

// Addr is the TV's address with its pairing port, the remote port the one
// below it.
func (tv *TV) Addr() string { return tv.pair.Addr().String() }

// Pin is the SHA-256 of the TV's certificate.
func (tv *TV) Pin() []byte {
	sum := sha256.Sum256(tv.cert.Certificate[0])
	return sum[:]
}

// Code is the code the TV shows, "" before a pairing asks for one.
func (tv *TV) Code() string {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	return tv.code
}

// Forget forgets the paired remotes, as a reset TV does.
func (tv *TV) Forget() {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	tv.paired = map[[32]byte]bool{}
}

// Focus opens a text field on the TV: it tells the connected remotes,
// and those that connect after.
func (tv *TV) Focus() {
	tv.mu.Lock()
	tv.focused = true
	conns := append([]*remoteConn(nil), tv.conns...)
	tv.mu.Unlock()
	for _, c := range conns {
		c.send(focus())
	}
}

func focus() wire.Builder {
	return wire.New().Sub(21, wire.New().Int(1, 7).Int(2, 3))
}

// Text is what came into the text field, and the keys pressed.
func (tv *TV) Text() ([]string, []uint64) {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	return append([]string(nil), tv.text...), append([]uint64(nil), tv.keys...)
}

// Wait waits until the text field has n edits and keys in all.
func (tv *TV) Wait(t testing.TB, n int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		text, keys := tv.Text()
		if len(text)+len(keys) >= n {
			return
		}
		select {
		case <-tv.changed:
		case <-deadline:
			t.Fatalf("the TV has %q and keys %v, want %d in all", text, keys, n)
		}
	}
}

// Close stops the TV.
func (tv *TV) Close() {
	tv.pair.Close()
	tv.remote.Close()
	tv.mu.Lock()
	defer tv.mu.Unlock()
	for _, c := range tv.conns {
		c.conn.Close()
	}
}

func (tv *TV) accept(l net.Listener, serve func(*tls.Conn) error) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				return
			}
			serve(tc)
		}()
	}
}

func clientCert(c *tls.Conn) *x509.Certificate {
	return c.ConnectionState().PeerCertificates[0]
}

func outer(status uint64, part int, body wire.Builder) wire.Builder {
	m := wire.New().Int(1, 2).Int(2, status)
	if part != 0 {
		m = m.Sub(numberOf(part), body)
	}
	return m
}

func (tv *TV) servePairing(c *tls.Conn) error {
	r := bufio.NewReader(c)
	steps := []struct{ ask, answer int }{{10, 11}, {20, 20}, {30, 31}}
	for _, s := range steps {
		m, err := read(r)
		if err != nil {
			return err
		}
		if !m.Has(numberOf(s.ask)) {
			return wire.Write(c, outer(400, 0, nil))
		}
		body := wire.New()
		if s.answer == 11 {
			body = body.Str(1, "Fake TV")
		}
		if s.answer == 20 {
			enc := wire.New().Int(1, 3).Int(2, 6)
			body = body.Sub(2, enc).Int(3, 1)
		}
		if s.answer == 31 {
			tv.showCode(c)
		}
		if err := wire.Write(c, outer(200, s.answer, body)); err != nil {
			return err
		}
	}
	m, err := read(r)
	if err != nil {
		return err
	}
	secret, err := m.Sub(40)
	if err != nil {
		return err
	}
	tv.mu.Lock()
	digits, _ := hex.DecodeString(tv.code)
	tv.mu.Unlock()
	client := clientCert(c).PublicKey.(*rsa.PublicKey)
	want := androidtv.Secret(client, &tv.key.PublicKey, digits[1:])
	if secret.Str(1) != string(want) {
		return wire.Write(c, outer(402, 0, nil))
	}
	tv.mu.Lock()
	tv.paired[sha256.Sum256(clientCert(c).Raw)] = true
	tv.code = ""
	tv.mu.Unlock()
	return wire.Write(c, outer(200, 41, wire.New().Bytes(1, want)))
}

// showCode makes a code whose first byte checks the rest for this client.
func (tv *TV) showCode(c *tls.Conn) {
	rest := make([]byte, 2)
	rand.Read(rest)
	client := clientCert(c).PublicKey.(*rsa.PublicKey)
	secret := androidtv.Secret(client, &tv.key.PublicKey, rest)
	tv.mu.Lock()
	tv.code = strings.ToUpper(hex.EncodeToString(append([]byte{secret[0]}, rest...)))
	tv.mu.Unlock()
}

func (tv *TV) serveRemote(c *tls.Conn) error {
	tv.mu.Lock()
	ok := tv.paired[sha256.Sum256(clientCert(c).Raw)]
	tv.mu.Unlock()
	if !ok {
		return errors.New("not paired")
	}
	rc := &remoteConn{conn: c}
	r := bufio.NewReader(c)
	// The TV's side of the start: configure, set active, start.
	if err := rc.send(wire.New().Sub(1, wire.New().Int(1, 622))); err != nil {
		return err
	}
	if m, err := read(r); err != nil || !m.Has(1) {
		return errors.New("no configure")
	}
	if err := rc.send(wire.New().Sub(2, wire.New())); err != nil {
		return err
	}
	if m, err := read(r); err != nil || !m.Has(2) {
		return errors.New("no set active")
	}
	if err := rc.send(wire.New().Sub(8, wire.New().Int(1, 42))); err != nil {
		return err
	}
	if m, err := read(r); err != nil || !m.Has(9) {
		return errors.New("no ping response")
	}
	tv.mu.Lock()
	tv.conns = append(tv.conns, rc)
	focused := tv.focused
	tv.mu.Unlock()
	if err := rc.send(wire.New().Sub(40, wire.New().Int(1, 1))); err != nil {
		return err
	}
	if focused {
		if err := rc.send(focus()); err != nil {
			return err
		}
	}
	for {
		m, err := read(r)
		if err != nil {
			return err
		}
		switch {
		case m.Has(21):
			edit, _ := m.Sub(21)
			info, _ := edit.Sub(3)
			status, _ := info.Sub(2)
			if edit.Int(1) != 7 || edit.Int(2) != 3 {
				return errors.New("an edit with the wrong counters")
			}
			tv.got(func() { tv.text = append(tv.text, status.Str(3)) })
		case m.Has(10):
			key, _ := m.Sub(10)
			tv.got(func() { tv.keys = append(tv.keys, key.Int(1)) })
		}
	}
}

func (tv *TV) got(f func()) {
	tv.mu.Lock()
	f()
	tv.mu.Unlock()
	select {
	case tv.changed <- struct{}{}:
	default:
	}
}

func read(r *bufio.Reader) (wire.Message, error) {
	b, err := wire.Read(r)
	if err != nil {
		return nil, err
	}
	return wire.Parse(b)
}

func numberOf(part int) protowire.Number { return protowire.Number(part) }
