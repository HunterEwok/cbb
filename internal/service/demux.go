// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bufio"
	"net"
	"net/netip"
	"sync"
)

// The member port is cbb's only port. Its connections are told
// apart by their first bytes: plain HTTP for the profile while an iPhone
// pairing window is open, else TLS, where the ALPN protocol the client
// offers picks pairing, the member protocol, or HTTPS for the iPhone
// shortcut.

// recordHandshake is the first byte of a TLS connection: a handshake record.
const recordHandshake = 0x16

// peekedConn is a connection whose first bytes were read ahead.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// peek reads the first byte of raw without taking it from the connection.
func peek(raw net.Conn) (net.Conn, byte, error) {
	r := bufio.NewReader(raw)
	b, err := r.Peek(1)
	if err != nil {
		return raw, 0, err
	}
	return &peekedConn{raw, r}, b[0], nil
}

// The connections a connListener holds open at once, in all and from one
// address: they gave up the member port's handshake slot, so they are
// bounded here.
const (
	maxPassed        = 32
	maxPassedAddress = 4
)

// connListener is a net.Listener that hands out the connections that the
// member port passes to it, for an http.Server.
type connListener struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once

	mu     sync.Mutex
	open   int
	fromIP map[netip.Addr]int
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{addr: addr, conns: make(chan net.Conn), done: make(chan struct{}), fromIP: map[netip.Addr]int{}}
}

// pass hands c to the server, or closes it once the listener is closed or
// holds as many connections as it may.
func (l *connListener) pass(c net.Conn) {
	var from netip.Addr
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		from = ap.Addr().Unmap()
	}
	l.mu.Lock()
	full := l.open >= maxPassed || l.fromIP[from] >= maxPassedAddress
	if !full {
		l.open++
		l.fromIP[from]++
	}
	l.mu.Unlock()
	if full {
		c.Close()
		return
	}
	c = &passedConn{Conn: c, l: l, from: from}
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

// passedConn is a connection a connListener counts until it is closed.
type passedConn struct {
	net.Conn
	l    *connListener
	from netip.Addr
	once sync.Once
}

func (c *passedConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.open--
		if c.l.fromIP[c.from]--; c.l.fromIP[c.from] <= 0 {
			delete(c.l.fromIP, c.from)
		}
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }
