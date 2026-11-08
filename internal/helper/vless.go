// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"encoding/json"
	"errors"
	"strconv"
	"sync"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
)

// The operations of a client's way over VLESS inside REALITY, which cbb's
// tunnel (member/src/vless.rs) cannot make itself: rustls makes no
// browser's ClientHello. The way is a local UDP port whose packets go to
// the hub's forwarder (internal/vless's Dial).
const (
	OpVLESSDial  = "vless-dial"  // payload: the hub's VLESS settings (tunnel.VLESS); answer: VLESSWay
	OpVLESSClose = "vless-close" // Name: the way's ID
)

// VLESSWay is the answer to vless-dial: the way's ID, for vless-close, and
// the local address the tunnel sends to.
type VLESSWay struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

// maxWays bounds the ways open at once: the hubs of a group with a key for
// the next period each, with room to spare.
const maxWays = 64

type ways struct {
	mu   sync.Mutex
	next int
	open map[string]*vless.Client
}

// HandleVLESS serves the ways over VLESS inside REALITY on s.
func (s *Server) HandleVLESS() {
	w := &ways{open: map[string]*vless.Client{}}
	s.Handle(OpVLESSDial, w.dial)
	s.Handle(OpVLESSClose, w.close)
}

func (w *ways) dial(req *control.Message) (*control.Message, error) {
	var l tunnel.VLESS
	if err := json.Unmarshal(req.Payload, &l); err != nil {
		return nil, errors.New("the hub's VLESS settings do not read")
	}
	if l.Transport != tunnel.TransportReality {
		return nil, errors.New("cbb-helper makes only the way over VLESS inside REALITY")
	}
	w.mu.Lock()
	full := len(w.open) >= maxWays
	w.mu.Unlock()
	if full {
		return nil, errors.New("too many ways over VLESS are open")
	}
	c, err := vless.Dial(l)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	w.next++
	id := strconv.Itoa(w.next)
	w.open[id] = c
	w.mu.Unlock()
	return answer(VLESSWay{ID: id, Addr: c.Addr().String()})
}

func (w *ways) close(req *control.Message) (*control.Message, error) {
	w.mu.Lock()
	c := w.open[req.Header.Name]
	delete(w.open, req.Header.Name)
	w.mu.Unlock()
	if c != nil {
		c.Close()
	}
	return &control.Message{}, nil
}
