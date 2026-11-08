// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
)

// The forge speaks the member protocol's frames itself (docs/protocol.md,
// section 4), as an attacker would: a member connection with the forge's
// certificate, a hello, then the messages each case sends as they are,
// whatever a well-behaved member would send.

// dialHello connects to the member to at addr as the member id, sends a
// hello and waits for the target's.
func dialHello(id *group.Identity, to group.DeviceID, addr, system string) (fetchConn, error) {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fetchConn{}, err
	}
	tc := tls.Client(raw, id.ClientTLS(to, group.TLSOptions{}))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return fetchConn{}, err
	}
	f := fetchConn{tc}
	if err := f.write(map[string]any{"t": "hello", "role": group.RoleMember, "hello": map[string]any{
		"os": system, "wall_ms": time.Now().UnixMilli(), "name": "forge", "mode": "shared", "caps": group.AllCaps}}); err != nil {
		tc.Close()
		return fetchConn{}, err
	}
	for {
		t, _, err := f.read(10 * time.Second)
		if err != nil {
			tc.Close()
			return fetchConn{}, fmt.Errorf("waiting for the hello: %w", err)
		}
		if t == "hello" {
			return f, nil
		}
	}
}

// result is the target's answer to a command (docs/protocol.md, section
// 15).
type result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// memberConn is a member connection whose frames a goroutine reads, for
// the results of the commands sent on it.
type memberConn struct {
	f       fetchConn
	wmu     sync.Mutex
	mu      sync.Mutex
	waiting map[string]chan result
	done    chan struct{}
}

func dialMember(id *group.Identity, to group.DeviceID, addr, system string) (*memberConn, error) {
	f, err := dialHello(id, to, addr, system)
	if err != nil {
		return nil, err
	}
	m := &memberConn{f: f, waiting: map[string]chan result{}, done: make(chan struct{})}
	go m.readLoop()
	return m, nil
}

func (m *memberConn) readLoop() {
	defer close(m.done)
	for {
		t, body, err := m.f.read(time.Hour)
		if err != nil {
			return
		}
		if t != "result" {
			continue
		}
		var msg struct {
			Result *result `json:"result"`
		}
		if json.Unmarshal(body, &msg) != nil || msg.Result == nil {
			continue
		}
		m.mu.Lock()
		if ch, ok := m.waiting[msg.Result.ID]; ok {
			ch <- *msg.Result
			delete(m.waiting, msg.Result.ID)
		}
		m.mu.Unlock()
	}
}

func (m *memberConn) Close() error { return m.f.c.Close() }

func (m *memberConn) send(msg map[string]any) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	return m.f.write(msg)
}

// command sends cmd, a command whose ID is id, and waits for its result
// until ctx ends.
func (m *memberConn) command(ctx context.Context, cmd group.Record, id string) (result, error) {
	ch := make(chan result, 1)
	m.mu.Lock()
	m.waiting[id] = ch
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.waiting, id)
		m.mu.Unlock()
	}()
	if err := m.send(map[string]any{"t": "command", "command": cmd}); err != nil {
		return result{}, err
	}
	select {
	case r := <-ch:
		return r, nil
	case <-m.done:
		return result{}, errors.New("the connection to the device closed before it answered")
	case <-ctx.Done():
		return result{}, errors.New("the device did not answer in time")
	}
}

// records sends rs in one records message.
func (m *memberConn) records(rs []group.Record) error {
	return m.send(map[string]any{"t": "records", "records": rs})
}

// cert sends a member certificate and the admin CA that issued it, nil for
// the group CA, as a renewal.
func (m *memberConn) cert(cert, issuer *x509.Certificate) error {
	msg := map[string]any{"t": "cert", "cert": cert.Raw}
	if issuer != nil {
		msg["issuer"] = issuer.Raw
	}
	return m.send(msg)
}

// event sends ev, sealed, as it is, as a member passing on one it
// received.
func (m *memberConn) event(ev clip.Event) error {
	if ev.Sealed == nil {
		return errors.New("a copy that is not sealed")
	}
	return m.send(map[string]any{"t": "event", "event": ev.Sealed})
}
