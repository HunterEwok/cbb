// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/peripheral"
	"github.com/HunterEwok/cbb/internal/remotepaste"
)

// The operations of the Bluetooth keyboard and the TVs' remotes
// (internal/peripheral) for the Rust service. Their requests are a
// PeripheralRequest in the payload; keyboard, remote and peripheral-status
// answer with a PeripheralStatus, peripheral-paste with a
// peripheral.Result, keyboard-layout with a PeripheralStatus whose Refused
// says why it did not switch.
const (
	// OpKeyboard serves cbb keyboard: the request's Header as the control
	// operation keyboard has it, Text its payload.
	OpKeyboard = "keyboard"
	// OpRemote serves cbb remote, as OpKeyboard.
	OpRemote = "remote"
	// OpPeripheralStatus tells how the keyboard and the TVs stand; the
	// first request for a state folder turns its keyboard on if it is on
	// in the settings.
	OpPeripheralStatus = "peripheral-status"
	// OpPeripheralPaste types a remote paste on the keyboard's host or a
	// TV, when the user sends pastes there.
	OpPeripheralPaste = "peripheral-paste"
	// OpPeripheralStop stops a paste typed after its answer: the
	// service's records no longer take its command.
	OpPeripheralStop = "peripheral-stop"
	// OpKeyboardLayout is the quick action keyboard-layout.
	OpKeyboardLayout = "keyboard-layout"
)

// PeripheralRequest is a request of the keyboard and remote operations.
type PeripheralRequest struct {
	Dir  string `json:"dir"`  // the service's state folder
	Name string `json:"name"` // the device's name, which the keyboard and the TVs show
	OS   string `json:"os"`   // the group's name of the device's system
	// Header and Text: the control operation's header and payload, for
	// keyboard and remote.
	Header control.Header `json:"header"`
	Text   string         `json:"text,omitempty"`
	// In peripheral-paste: whether the user allows Enter, and whether the
	// command asks for Enter after the text.
	Enter     bool `json:"enter,omitempty"`
	BodyEnter bool `json:"body_enter,omitempty"`
}

// PeripheralStatus is how the keyboard and the TVs stand, and the targets
// remote pastes go to instead of the screen.
type PeripheralStatus struct {
	Keyboard *control.Keyboard `json:"keyboard,omitempty"`
	TVs      []control.TV      `json:"tvs,omitempty"`
	Targets  []string          `json:"targets,omitempty"`
	Refused  string            `json:"refused,omitempty"`
}

// peripherals are the hosts, by state folder: one for the service, which
// keeps its keyboard on BlueZ and its TV pairing between requests.
type peripherals struct {
	logw io.Writer
	bus  peripheral.BusDialer
	// logMu keeps the lines whole: requests and typing log at once.
	logMu sync.Mutex

	mu    sync.Mutex
	hosts map[string]*hostState
}

type hostState struct {
	h *peripheral.Host
	// stopped is set by peripheral-stop, for the paste typing now.
	mu      sync.Mutex
	stopped bool
}

// HandlePeripherals serves the keyboard and remote operations on s; the
// hosts log to logw.
func (s *Server) HandlePeripherals(logw io.Writer) {
	p := &peripherals{logw: logw, bus: testBus(), hosts: map[string]*hostState{}}
	s.Handle(OpKeyboard, p.keyboard)
	s.Handle(OpRemote, p.remote)
	s.Handle(OpPeripheralStatus, p.status)
	s.Handle(OpPeripheralPaste, p.paste)
	s.Handle(OpPeripheralStop, p.stop)
	s.Handle(OpKeyboardLayout, p.layout)
}

// host reads the request and returns its folder's host, made at the first
// request.
func (p *peripherals) host(req *control.Message) (*hostState, *PeripheralRequest, error) {
	var r PeripheralRequest
	if err := json.Unmarshal(req.Payload, &r); err != nil || r.Dir == "" {
		return nil, nil, errors.New("a keyboard or remote request that is not understood")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	hs := p.hosts[r.Dir]
	if hs == nil {
		h := &peripheral.Host{Dir: r.Dir, Name: r.Name, OS: r.OS, Bus: p.bus, Logf: func(format string, args ...any) {
			p.logMu.Lock()
			defer p.logMu.Unlock()
			fmt.Fprintf(p.logw, format+"\n", args...)
		}}
		hs = &hostState{h: h}
		p.hosts[r.Dir] = hs
		go h.ApplyKeyboard()
	}
	return hs, &r, nil
}

func statusOf(h *peripheral.Host) PeripheralStatus {
	return PeripheralStatus{Keyboard: h.KeyboardStatus(), TVs: h.TVStatus(), Targets: h.Targets()}
}

func (p *peripherals) keyboard(req *control.Message) (*control.Message, error) {
	hs, r, err := p.host(req)
	if err != nil {
		return nil, err
	}
	if err := hs.h.Keyboard(context.Background(), &control.Message{Header: r.Header, Payload: []byte(r.Text)}); err != nil {
		return nil, err
	}
	return answer(statusOf(hs.h))
}

func (p *peripherals) remote(req *control.Message) (*control.Message, error) {
	hs, r, err := p.host(req)
	if err != nil {
		return nil, err
	}
	if err := hs.h.Remote(context.Background(), &control.Message{Header: r.Header, Payload: []byte(r.Text)}); err != nil {
		return nil, err
	}
	return answer(statusOf(hs.h))
}

func (p *peripherals) status(req *control.Message) (*control.Message, error) {
	hs, _, err := p.host(req)
	if err != nil {
		return nil, err
	}
	return answer(statusOf(hs.h))
}

// paste types the paste; one typed after its answer goes on while remote
// paste is on in the folder's settings and the service did not stop it.
func (p *peripherals) paste(req *control.Message) (*control.Message, error) {
	hs, r, err := p.host(req)
	if err != nil {
		return nil, err
	}
	hs.mu.Lock()
	hs.stopped = false
	hs.mu.Unlock()
	still := func() bool {
		hs.mu.Lock()
		stopped := hs.stopped
		hs.mu.Unlock()
		set, err := remotepaste.Load(r.Dir)
		return !stopped && err == nil && set.On
	}
	res, ok := hs.h.Paste(r.Text, r.Enter, r.BodyEnter, still)
	if !ok {
		return answer(peripheral.Result{})
	}
	return answer(res)
}

func (p *peripherals) stop(req *control.Message) (*control.Message, error) {
	hs, _, err := p.host(req)
	if err != nil {
		return nil, err
	}
	hs.mu.Lock()
	hs.stopped = true
	hs.mu.Unlock()
	return answer(PeripheralStatus{})
}

func (p *peripherals) layout(req *control.Message) (*control.Message, error) {
	hs, _, err := p.host(req)
	if err != nil {
		return nil, err
	}
	var refusal *peripheral.Refusal
	if err := hs.h.NextKeyboardLayout(); errors.As(err, &refusal) {
		return answer(PeripheralStatus{Refused: refusal.Reason})
	} else if err != nil {
		return nil, err
	}
	return answer(statusOf(hs.h))
}
