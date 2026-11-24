// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// A connection through the tunnel keeps its addresses after both ends have
// closed it, on the hub's side and on the client's.
func TestConnKeepsItsAddresses(t *testing.T) {
	d, c := newDevice(t), newDevice(t)
	h, err := StartHub(HubConfig{PrivateKey: d.priv, Addr: d.addr, Peers: []Peer{c.peer()}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	client := startClient(t, testHub{h, d}, c)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialed := make(chan net.Conn, 1)
	go func() {
		conn, err := client.Dial(ctx)
		if err != nil {
			t.Error(err)
			close(dialed)
			return
		}
		dialed <- conn
	}()
	got, err := h.Listener().Accept()
	if err != nil {
		t.Fatal(err)
	}
	out, ok := <-dialed
	if !ok {
		t.FailNow()
	}
	from, to := got.RemoteAddr().String(), out.RemoteAddr().String()
	out.Close()
	// The hub reads to the client's close, then closes its own end.
	if _, err := io.ReadAll(got); err != nil {
		t.Fatal(err)
	}
	got.Close()
	for _, k := range []struct {
		name string
		conn net.Conn
		want string
	}{{"hub", got, from}, {"client", out, to}} {
		if a := k.conn.RemoteAddr(); a == nil || a.String() != k.want {
			t.Errorf("%s: remote address %v after closing, want %s", k.name, a, k.want)
		}
		if k.conn.LocalAddr() == nil {
			t.Errorf("%s: no local address after closing", k.name)
		}
	}
	if want := c.addr.String(); got.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().String() != want {
		t.Errorf("hub sees %s, want %s", got.RemoteAddr(), want)
	}
}

// fakeConn is a connection whose remote address is remote.
type fakeConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *fakeConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error         { c.closed = true; return nil }

type fakeListener struct {
	net.Listener
	conns []net.Conn
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, net.ErrClosed
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}

// The listener closes and skips a connection that has no address any more,
// and hands on the next one.
func TestAcceptSkipsAClosedConn(t *testing.T) {
	gone := &fakeConn{}
	open := &fakeConn{remote: &net.TCPAddr{Port: 1}}
	l := addrListener{&fakeListener{conns: []net.Conn{gone, open}}}
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != open.remote.String() {
		t.Fatalf("got the connection from %v", c.RemoteAddr())
	}
	if !gone.closed || open.closed {
		t.Fatalf("closed: gone %v, open %v", gone.closed, open.closed)
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after the last: %v", err)
	}
	if _, err := withAddrs(&fakeConn{}); !errors.Is(err, errNotConnected) {
		t.Fatalf("withAddrs of a closed connection: %v", err)
	}
}
