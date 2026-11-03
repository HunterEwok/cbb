// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package androidtv

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/tvremote/androidtv/wire"
)

// The fields of RemoteMessage.
const (
	rmConfigure = 1
	rmSetActive = 2
	rmError     = 3
	rmPingReq   = 8
	rmPingResp  = 9
	rmKeyInject = 10
	rmImeBatch  = 21
	rmImeShow   = 22
	rmStart     = 40
)

// features are what the remote says it does: ping, keys and the IME.
const features = 1 | 2 | 4

// The key codes the remote sends (Android's KeyEvent).
const (
	keyEnter = 66
	keyShort = 3 // a press and a release
)

// ErrNoField is the TV with no text field focused: the IME takes text only
// into one.
var ErrNoField = errors.New("no text field is open on the TV: open a search or a text field first")

// Remote is the remote's connection to a paired TV.
type Remote struct {
	conn *tls.Conn

	mu      sync.Mutex // guards the fields below and writes to conn
	ime     uint64     // the IME's counter, as the TV last told it
	field   uint64     // the text field's counter
	focused bool       // a text field is open
	err     error      // why the connection ended

	started   chan struct{}
	done      chan struct{}
	focus     chan struct{} // closed when a text field opens
	focusOnce sync.Once
}

// Dial connects to the remote port of the TV at host with the client paired
// with it, its certificate pinned to pin, and waits for the TV to start the
// remote.
func Dial(ctx context.Context, host string, c Client, pin []byte) (*Remote, error) {
	if len(pin) == 0 {
		return nil, errors.New("the TV is not paired")
	}
	conn, err := dial(ctx, addr(host, true), c, pin)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the TV's remote port %d: %w", RemotePort, err)
	}
	r := &Remote{conn: conn, started: make(chan struct{}), done: make(chan struct{}), focus: make(chan struct{})}
	go r.read(bufio.NewReader(conn))
	t := time.NewTimer(stepTimeout)
	defer t.Stop()
	select {
	case <-r.started:
		return r, nil
	case <-r.done:
		return nil, r.Err()
	case <-t.C:
		conn.Close()
		return nil, errors.New("the TV did not start the remote: pair it again if it was reset")
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}
}

// read answers the TV and keeps what it says of its text field, until the
// connection ends.
func (r *Remote) read(br *bufio.Reader) {
	defer close(r.done)
	var once sync.Once
	for {
		b, err := wire.Read(br)
		if err == nil {
			err = r.handle(b, func() { once.Do(func() { close(r.started) }) })
		}
		if err != nil {
			r.mu.Lock()
			if r.err == nil {
				r.err = err
			}
			r.mu.Unlock()
			r.conn.Close()
			return
		}
	}
}

func (r *Remote) handle(b []byte, started func()) error {
	m, err := wire.Parse(b)
	if err != nil {
		return err
	}
	switch {
	case m.Has(rmConfigure):
		info := wire.New().Str(1, "CBB").Str(2, "CBB").
			Int(3, 1).Str(4, "1").Str(5, "atvremote").Str(6, "1.0.0")
		return r.send(wire.New().Sub(rmConfigure, wire.New().Int(1, features).Sub(2, info)))
	case m.Has(rmSetActive):
		return r.send(wire.New().Sub(rmSetActive, wire.New().Int(1, features)))
	case m.Has(rmPingReq):
		ping, err := m.Sub(rmPingReq)
		if err != nil {
			return err
		}
		return r.send(wire.New().Sub(rmPingResp, wire.New().Int(1, ping.Int(1))))
	case m.Has(rmStart):
		started()
	case m.Has(rmImeBatch):
		edit, err := m.Sub(rmImeBatch)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.ime, r.field, r.focused = edit.Int(1), edit.Int(2), true
		r.mu.Unlock()
		r.focusOnce.Do(func() { close(r.focus) })
	case m.Has(rmImeShow):
		show, err := m.Sub(rmImeShow)
		if err != nil {
			return err
		}
		status, err := show.Sub(2)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.field, r.focused = status.Int(1), true
		r.mu.Unlock()
		r.focusOnce.Do(func() { close(r.focus) })
	case m.Has(rmError):
		return errors.New("the TV ended the remote with an error")
	}
	return nil
}

func (r *Remote) send(m wire.Builder) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sendLocked(m)
}

func (r *Remote) sendLocked(m wire.Builder) error {
	r.conn.SetWriteDeadline(time.Now().Add(stepTimeout))
	return wire.Write(r.conn, m)
}

// Type puts text into the TV's open text field, a line at a time, with
// Enter between the lines.
func (r *Remote) Type(text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return fmt.Errorf("the connection to the TV ended: %w", r.err)
	}
	if !r.focused {
		return ErrNoField
	}
	for i, line := range strings.Split(text, "\n") {
		if i > 0 {
			key := wire.New().Int(1, keyEnter).Int(2, keyShort)
			if err := r.sendLocked(wire.New().Sub(rmKeyInject, key)); err != nil {
				return err
			}
		}
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		at := uint64(len([]rune(line)) - 1)
		status := wire.New().Int(1, at).Int(2, at).Str(3, line)
		edit := wire.New().Int(1, r.ime).Int(2, r.field).
			Sub(3, wire.New().Int(1, 1).Sub(2, status))
		if err := r.sendLocked(wire.New().Sub(rmImeBatch, edit)); err != nil {
			return err
		}
	}
	return nil
}

// WaitField waits up to wait for the TV to say a text field is open, as it
// does right after the remote starts when one is; ErrNoField if none.
func (r *Remote) WaitField(ctx context.Context, wait time.Duration) error {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-r.focus:
		return nil
	case <-r.done:
		return fmt.Errorf("the connection to the TV ended: %w", r.Err())
	case <-t.C:
		return ErrNoField
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Err is why the connection ended, nil while it is open.
func (r *Remote) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Done is closed when the connection ends.
func (r *Remote) Done() <-chan struct{} { return r.done }

// Close ends the connection.
func (r *Remote) Close() error {
	err := r.conn.Close()
	<-r.done
	return err
}
