// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/remotepaste"
)

// Remote paste (design.md, "Remote paste"; docs/protocol.md, section 15):
// an admin's signed paste command reaches this member, which hands its
// text to a watcher that can put it where the focus is: the desktop
// connector, the Mac's pasteboard agent, the tmux helper or the console
// helper. The watcher checks right before it injects that its session is
// not locked.

// The targets a watcher offers, as its watch request names them. A text
// console, and a tmux session of root, are "console".
const (
	targetDesktop = "desktop"
	targetTmux    = "tmux"
	targetConsole = "console"
)

// injectWait bounds how long a watcher may take to inject; typing takes
// typeWait more for each byte.
const (
	injectWait = 5 * time.Second
	typeWait   = 5 * time.Millisecond
)

// injectTime is how long a watcher may take to inject body's text.
func injectTime(body group.CommandBody) time.Duration {
	if body.Mode == group.PasteByTyping {
		return injectWait + time.Duration(len(body.Text))*typeWait
	}
	return injectWait
}

// An inject is a paste for a watcher, with where its answer goes.
type inject struct {
	body    group.CommandBody
	text    string
	command []string // an action's: the user's own program and arguments
	done    chan node.Result
	keys    string // the grant for the uinput helper, while a desktop session pastes it
	// noLockCheck lets the target paste where it cannot tell whether the
	// session is locked (remotepaste.Settings).
	noLockCheck bool
}

// A keysGrant lets the uinput helper press the keys of one remote paste for
// the user of the desktop session that the service handed it to: the paste
// keys once, then Enter once if the command asked for it (control.OpKeys).
// The helper presses keys anywhere, so it presses none that the service
// did not ask for, after the paste switches and the checks on the signer.
type keysGrant struct {
	uid          uint32
	enter        bool
	pasted, done bool
	until        time.Time
}

// grantKeys makes the grant of in for the user of w, a desktop session.
func (s *Service) grantKeys(in *inject, w *watcher) string {
	if w.inject != targetDesktop || !w.peer.known || w.peer.sid != "" || in.body.Type == group.CommandAction {
		return ""
	}
	var b [16]byte
	rand.Read(b[:])
	g := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.now()
	for k, old := range s.keys {
		if !now.Before(old.until) {
			delete(s.keys, k)
		}
	}
	if s.keys == nil {
		s.keys = map[string]*keysGrant{}
	}
	s.keys[g] = &keysGrant{uid: w.peer.uid, enter: in.body.Enter, until: now.Add(injectTime(in.body))}
	return g
}

// endKeys ends the grant of an inject that was answered.
func (s *Service) endKeys(g string) {
	if g == "" {
		return
	}
	s.mu.Lock()
	delete(s.keys, g)
	s.mu.Unlock()
}

// errNoKeys refuses the helper keys that no remote paste asked for.
var errNoKeys = errors.New("no remote paste asked for these keys now")

// takeKeys answers the uinput helper: whether it may press the keys of req
// ("paste" or "enter") for the user uid under grant.
func (s *Service) takeKeys(grant, req, uid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.keys[grant]
	if g == nil || !s.cfg.now().Before(g.until) || strconv.FormatUint(uint64(g.uid), 10) != uid {
		return errNoKeys
	}
	switch {
	case req == "paste" && !g.pasted:
		g.pasted = true
	case req == "enter" && g.enter && g.pasted && !g.done:
		g.done = true
	default:
		return errNoKeys
	}
	return nil
}

// errPasteOff is the refusal of a member whose user did not turn remote
// paste on.
var errPasteOff = errors.New("remote paste is off on this device; its user turns it on there with cbb paste-receive on, or in the app")

// sender is whom a command counts for in the limits per sender and the
// logs (group.Records.CommandSender).
type sender struct {
	key      string
	verified bool
}

// who names the sender in the service's log: by, marked when the records
// do not show that its device signed.
func (f sender) who(body group.CommandBody) string {
	if f.verified {
		return string(body.By)
	}
	return string(body.By) + " (unverified)"
}

// senderName is the sender's device name for a log, when the records show that
// it signed.
func (s *Service) senderName(body group.CommandBody, from sender) string {
	if !from.verified {
		return ""
	}
	return s.deviceName(body.By)
}

// pasted carries out a paste command that VerifyCommand took, from the
// sender from.
func (s *Service) pasted(body group.CommandBody, c group.Record, from sender) node.Result {
	res := node.Result{ID: body.ID}
	refuse := func(why string) node.Result {
		res.Status, res.Reason = node.ResultRefused, why
		return res
	}
	set, err := remotepaste.Load(s.cfg.StateDir)
	switch {
	case err != nil:
		res.Status, res.Reason = node.ResultFailed, fmt.Sprintf("reading the remote paste settings: %v", err)
	case s.forwardOnly():
		res = refuse(errForwardOnly.Error())
	case !set.On:
		res = refuse(errPasteOff.Error())
	case body.Kind == "secret" && s.secretsStopped():
		res = refuse("the group's records stop secrets until its root decides (cbb status says why)")
	case body.Enter && !set.Enter:
		res = refuse("this device takes pastes without Enter only; its user allows Enter with cbb paste-receive on -enter")
	case !s.pastes.Allow(from.key, s.cfg.now()):
		res = refuse("too many pastes: at most one a second and 30 a minute from one device")
	default:
		res = s.inject(body, remotepaste.Clean(body.Text), set, s.stillAllowed(c, body))
	}
	if res.Status == node.ResultDone {
		s.logf("cbb: %s pasted %d bytes here", from.who(body), len(body.Text))
	} else {
		s.logf("cbb: a paste from %s: %s: %s", from.who(body), res.Status, res.Reason)
	}
	if body.Kind != "secret" {
		e := remotepaste.Entry{TimeMS: s.cfg.now().UnixMilli(), By: string(body.By), Name: s.senderName(body, from),
			Unverified: !from.verified, Len: len(body.Text), Method: body.Mode, Enter: body.Enter, Result: res.Status, Reason: res.Reason}
		if err := remotepaste.Append(s.cfg.StateDir, e); err != nil {
			s.logf("cbb: keeping the paste log: %v", err)
		}
	}
	return res
}

// stillAllowed reports, for a paste that is typed after its answer,
// whether it may go on: remote paste is still on here and the records
// still take the command c from its signer, who may have been removed or
// frozen meanwhile.
func (s *Service) stillAllowed(c group.Record, body group.CommandBody) func() bool {
	return func() bool {
		if set, err := remotepaste.Load(s.cfg.StateDir); err != nil || !set.On {
			return false
		}
		s.mu.Lock()
		id := s.id
		s.mu.Unlock()
		if id == nil {
			return false
		}
		s.recMu.Lock()
		defer s.recMu.Unlock()
		if s.records == nil {
			return false
		}
		_, err := s.records.VerifyCommand(c, id.ID, time.UnixMilli(body.TimeMS))
		return err == nil
	}
}

// inject hands the text to the watchers that can put it in, best target
// first, until one did: a desktop session, then tmux, then a text console
// when the user allowed consoles.
func (s *Service) inject(body group.CommandBody, text string, set remotepaste.Settings, still func() bool) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultRefused}
	if text == "" {
		res.Reason = "the text has nothing that may be pasted: only control characters"
		return res
	}
	if r, ok := s.host.Paste(text, set.Enter, body.Enter, still); ok {
		return node.Result{ID: body.ID, Status: r.Status, Reason: r.Reason}
	}
	// A Bluetooth keyboard and a TV check line breaks themselves. Elsewhere
	// a line break runs what comes before it wherever the focused program
	// does not take a paste bracketed: a typed text, tmux, a console, and on
	// a desktop a shell or console window that does not ask for it (cmd.exe,
	// sh), which no target can tell. So a text with one needs the user's
	// leave for Enter on every target.
	if strings.Contains(text, "\n") && !set.Enter {
		res.Reason = "the text has a line break, which may run what comes before it, and this device takes pastes without Enter only; send it as one line, or its user allows Enter with cbb paste-receive on -enter"
		return res
	}
	order := []string{targetDesktop, targetTmux}
	if set.Console {
		order = append(order, targetConsole)
	}
	s.mu.Lock()
	var ws []*watcher
	console := false
	for _, t := range order {
		for w := range s.watchers {
			if w.inject == t {
				ws = append(ws, w)
			}
		}
	}
	for w := range s.watchers {
		console = console || w.inject == targetConsole
	}
	s.mu.Unlock()
	if len(ws) == 0 {
		res.Reason = "nothing on this device can paste: no desktop session, tmux or console helper of CBB runs here"
		if s.cfg.OS == group.OSMacOS {
			// Only the app pastes on a Mac: macOS lets an app press keys
			// once its user allowed it in Accessibility, and the service
			// and its pasteboard agent are not apps.
			res.Reason = "a Mac pastes through the CBB app, and it is not open here; its user opens it and allows it in System Settings, Privacy & Security, Accessibility"
		}
		if console && !set.Console {
			res.Reason = "only a text console is here, and its user did not allow consoles (cbb paste-receive on -console)"
		}
		return res
	}
	ws, why := s.screenUsers(ws, body.Kind == "secret")
	if len(ws) == 0 {
		res.Reason = why
		return res
	}
	var reasons []string
	for _, w := range ws {
		in := &inject{body: body, text: text, done: make(chan node.Result, 1), noLockCheck: set.NoLockCheck}
		select {
		case w.injects <- in:
		default:
			continue
		}
		select {
		case r := <-in.done:
			if r.Status == node.ResultDone {
				return node.Result{ID: body.ID, Status: node.ResultDone}
			}
			res.Status = r.Status
			reasons = append(reasons, r.Reason)
		case <-time.After(injectTime(body)):
			reasons = append(reasons, "the "+w.inject+" target did not answer")
		}
	}
	res.Reason = joinReasons(reasons)
	return res
}

// screenUsers keeps the watchers whose users may take their target's
// pastes now, and a secret paste only where the system tells who is at the
// screen; why says why none is left.
func (s *Service) screenUsers(ws []*watcher, secret bool) (kept []*watcher, why string) {
	for _, w := range ws {
		switch s.mayTake(w.peer, w.inject) {
		case allowed:
			kept = append(kept, w)
		case unchecked:
			if !secret {
				kept = append(kept, w)
				continue
			}
			why = "this device cannot tell which user is at its screen, so it takes no secret pastes; send it as a paste or a typed text"
		default:
			if why == "" {
				why = "the paste targets here run as users who are not at the screen (" + w.peer.where() + ")"
			}
		}
	}
	return kept, why
}

func joinReasons(rs []string) string {
	rs = slices.Compact(rs)
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}

// deviceName returns the name of the group's device id, "" when unknown.
func (s *Service) deviceName(id group.DeviceID) string {
	d, err := s.findDevice(string(id))
	if err != nil {
		return ""
	}
	return d.Name
}

// pasteOff turns remote paste off on this device, at an admin's paste-off
// command.
func (s *Service) pasteOff(body group.CommandBody) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultDone}
	if err := remotepaste.Save(s.cfg.StateDir, remotepaste.Settings{}); err != nil {
		res.Status, res.Reason = node.ResultFailed, err.Error()
		return res
	}
	s.logf("cbb: %s turned remote paste off here", body.By)
	return res
}

// setReceive serves cbb paste-receive: on or off here, or off on another
// member (Device) or every member (All) with a command this admin signs.
func (s *Service) setReceive(ctx context.Context, m *control.Message) error {
	switch {
	case m.Name != "on" && m.Name != "off":
		return fmt.Errorf("remote paste is on or off, not %q", m.Name)
	case m.Name == "on" && (m.Device != "" || m.All):
		return errors.New("only a device's own user turns remote paste on there")
	case m.Name == "off" && (m.Enter || m.Console || m.NoLockCheck):
		return errors.New("-enter, -console and -no-lock-check go with on")
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil {
		return s.errNoGroup()
	}
	if m.Device == "" && !m.All {
		set := remotepaste.Settings{On: m.Name == "on", Enter: m.Enter, Console: m.Console, NoLockCheck: m.NoLockCheck}
		if err := remotepaste.Save(s.cfg.StateDir, set); err != nil {
			return fmt.Errorf("saving the remote paste settings: %w", err)
		}
		s.logf("cbb: remote paste is %s here (enter %v, console %v, no lock check %v)", m.Name, set.Enter, set.Console, set.NoLockCheck)
		return nil
	}
	var targets []control.Device
	if m.All {
		devs, err := s.devices()
		if err != nil {
			return err
		}
		for _, d := range devs {
			if d.Self {
				if err := remotepaste.Save(s.cfg.StateDir, remotepaste.Settings{}); err != nil {
					return err
				}
				continue
			}
			targets = append(targets, d)
		}
	} else {
		d, err := s.findDevice(m.Device)
		if err != nil {
			return err
		}
		if d.Self {
			return remotepaste.Save(s.cfg.StateDir, remotepaste.Settings{})
		}
		targets = []control.Device{d}
	}
	var failed []string
	for _, d := range targets {
		if err := s.commandOn(ctx, d, group.CommandBody{Type: group.CommandPasteOff}); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", d.Name, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("remote paste may still be on: %s", joinReasons(failed))
	}
	return nil
}

// sendPaste serves cbb paste --on: it signs a paste command for the
// member Device and waits for its result.
func (s *Service) sendPaste(ctx context.Context, m *control.Message) error {
	method := m.Method
	if method == "" {
		method = group.PasteByClipboard
	}
	kind := m.Kind
	if kind == "" {
		kind = control.KindText
	}
	text := remotepaste.Clean(string(m.Payload))
	if text == "" {
		return errors.New("nothing to paste: the text is empty or only control characters")
	}
	d, err := s.findDevice(m.Device)
	if err != nil {
		return err
	}
	if d.Self {
		return errors.New("remote paste is for another device; this one is where you type")
	}
	return s.commandOn(ctx, d, group.CommandBody{Type: group.CommandPaste, Mode: method, Enter: m.Enter, Kind: kind, Text: text})
}

// commandOn signs body for the device d as this admin and sends it, through
// a hub of the group connected to d when this one is not.
func (s *Service) commandOn(ctx context.Context, d control.Device, body group.CommandBody) error {
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || nd == nil {
		return s.errNoGroup()
	}
	ca, chain := id.Signer()
	if ca == nil {
		return errors.New("only an admin pastes on another device, runs its actions or turns either off: the group's root, an admin it made (cbb admin), or an admin phone")
	}
	if s.frozen(id) {
		return errFrozen
	}
	now := s.cfg.now()
	body.Group, body.By, body.To = group.Tag(id.GroupCA.Cert), id.ID, group.DeviceID(d.ID)
	body.ID, body.TimeMS, body.ExpiresMS = group.NewCommandID(), now.UnixMilli(), now.Add(group.CommandLifetime).UnixMilli()
	cmd, err := s.signCommand(body, ca, chain)
	if err != nil {
		return err
	}
	wait := injectTime(body)
	if body.Type == group.CommandAction {
		wait = actionWait
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second+wait)
	defer cancel()
	res, err := nd.SendCommand(ctx, group.DeviceID(d.ID), cmd, body.ID, s.hubOrder())
	if err != nil {
		return fmt.Errorf("%s: %w", d.Name, err)
	}
	if res.Status != node.ResultDone {
		return fmt.Errorf("%s %s it: %s", d.Name, res.Status, res.Reason)
	}
	return nil
}

// pasteStatus describes remote paste here for cbb status; s.mu is held.
func (s *Service) pasteStatusLocked() *control.Paste {
	set, err := remotepaste.Load(s.cfg.StateDir)
	if err != nil {
		return nil
	}
	p := &control.Paste{On: set.On, Enter: set.Enter, Console: set.Console, NoLockCheck: set.NoLockCheck}
	for w := range s.watchers {
		if w.inject != "" && !slices.Contains(p.Targets, w.inject) {
			p.Targets = append(p.Targets, w.inject)
		}
	}
	p.Targets = append(p.Targets, s.host.Targets()...)
	slices.Sort(p.Targets)
	return p
}

// secretsStopped reports whether the records stop secrets to this device
// (group.Records.NoSecretsTo): it then takes no secret paste either.
func (s *Service) secretsStopped() bool {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	return id != nil && s.noSecretsTo(id.ID)
}
