// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
)

// syncFile says that sync is off, and until when, in the state directory
// (design.md, "Sync on or off"); without it, sync is on.
const syncFile = "sync.json"

// syncState is what sync.json holds.
type syncState struct {
	Off     bool  `json:"off"`
	UntilMS int64 `json:"until_ms,omitempty"` // when it turns on again; 0 for until turned on
}

// loadSync gives e the sync state saved in dir.
func loadSync(dir string, e *clip.Engine) error {
	data, err := os.ReadFile(filepath.Join(dir, syncFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st syncState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("%s: %w", syncFile, err)
	}
	e.SetSync(!st.Off, fromUnixMS(st.UntilMS))
	return nil
}

// saveSync writes e's sync state to dir; sync on removes the file.
func saveSync(dir string, e *clip.Engine) error {
	on, until := e.Sync()
	path := filepath.Join(dir, syncFile)
	if on {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(syncState{Off: true, UntilMS: unixMS(until)})
	if err != nil {
		return err
	}
	return atomicfile.Write(path, data, 0o600)
}

// parseSync reads "on" or "off", as cbb sync takes them.
func parseSync(name string) (bool, error) {
	switch name {
	case "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("sync is on or off, not %q", name)
}

// setSync turns sync on, or off for forMS milliseconds (0 for until it is
// turned on), and saves it.
func (s *Service) setSync(on bool, forMS int64) error {
	e := s.engine()
	if e == nil {
		return s.errNoGroup()
	}
	if forMS < 0 || forMS > group.MaxMute.Milliseconds() {
		return fmt.Errorf("sync turns off for at most %v; leave the time out to turn it off until cbb sync on", group.MaxMute)
	}
	var until time.Time
	if !on && forMS > 0 {
		until = s.cfg.now().Add(time.Duration(forMS) * time.Millisecond)
	}
	e.SetSync(on, until)
	if err := saveSync(s.cfg.StateDir, e); err != nil {
		return fmt.Errorf("saving sync on or off: %w", err)
	}
	switch {
	case on:
		s.logf("cbb: sync is on: copies go to the group and come from it")
	case until.IsZero():
		s.logf("cbb: sync is off until it is turned on: the clipboard is this device's own")
	default:
		s.logf("cbb: sync is off until %s: the clipboard is this device's own", until.Format(time.DateTime))
	}
	return nil
}

// pasteText is what cbb paste prints: the local clipboard's text while
// sync is on, and the group's current text while it is off, so that the
// group's text is at hand there on request.
func pasteText(e *clip.Engine) (string, clip.Kind, bool) {
	if e.Mode().Receives() {
		text, kind, _, ok := e.Local()
		return text, kind, ok
	}
	ev, ok := e.Current()
	if ev.Kind == clip.Media {
		// Images or files: their plain-text alternative, if any.
		return ev.Text, clip.Text, ok && ev.Text != ""
	}
	return ev.Text, ev.Kind, ok
}

// hasMedia reports whether cbb paste -o has images or files to save.
func hasMedia(e *clip.Engine) bool {
	if e.Mode().Receives() {
		_, _, _, ok := e.LocalMedia()
		return ok
	}
	ev, ok := e.Current()
	return ok && ev.Media != nil
}

// maxCommandIDs bounds the replay cache of commands; a command lives at
// most group.CommandLifetime, so this many from a sender in that time is
// far more than any admin sends.
const maxCommandIDs = 4096

// errSignedBeforeStart refuses a command signed before the service started.
var errSignedBeforeStart = errors.New("this device started after the command was signed, so it may have carried it out already; send it again")

// command carries out a command a member sent (docs/protocol.md, section
// 15): one that an admin signed for this device in its group, that has not
// expired and was not carried out before.
func (s *Service) command(peer group.DeviceID, c group.Record) node.Result {
	refused := func(err error) node.Result {
		s.logf("cbb: refused a command from %s: %v", peer, err)
		return node.Result{Status: node.ResultRefused, Reason: err.Error()}
	}
	s.mu.Lock()
	id, secret := s.id, s.sealSecret
	s.mu.Unlock()
	if id == nil {
		return refused(s.errNoGroup())
	}
	now := s.cfg.now()
	s.recMu.Lock()
	if s.records == nil {
		s.recMu.Unlock()
		return refused(errors.New("this device has no records of its group yet"))
	}
	body, err := s.records.VerifyCommand(c, id.ID, now)
	var from sender
	if err == nil {
		from.key, from.verified = s.records.CommandSender(c, body.By)
	}
	sealedToMe := false
	for _, d := range s.records.Devices() {
		if d.ID == id.ID {
			sealedToMe = len(d.Seal) > 0
		}
	}
	s.recMu.Unlock()
	if err == nil {
		err = body.Open(secret)
	}
	if err == nil && body.Type == group.CommandPaste && !body.Opened && sealedToMe {
		// The records give this device a key for sealed messages, so every
		// sender seals a paste to it: one in the open was read on its way
		// (docs/protocol.md, section 15, "Sealed commands").
		err = errors.New("a paste for this device must be sealed to its key, and this one came in the open")
	}
	if err != nil {
		return refused(err)
	}
	if body.Opened {
		s.logf("cbb: opened a sealed %s command from %s", body.Type, peer)
	}
	if body.TimeMS < s.startedMS {
		// It may have been carried out before the restart, which the
		// replay cache does not remember.
		return refused(errSignedBeforeStart)
	}
	res := node.Result{ID: body.ID}
	s.mu.Lock()
	if s.commands == nil {
		s.commands = map[string]time.Time{}
	}
	for k, exp := range s.commands {
		if !exp.After(now) {
			delete(s.commands, k)
		}
	}
	_, again := s.commands[body.ID]
	full := len(s.commands) >= maxCommandIDs
	if !again && !full {
		s.commands[body.ID] = time.UnixMilli(body.ExpiresMS)
	}
	s.mu.Unlock()
	switch {
	case again:
		res.Status, res.Reason = node.ResultRefused, "this command was carried out already"
		return res
	case full:
		res.Status, res.Reason = node.ResultRefused, "too many commands; try again in a minute"
		return res
	}
	switch body.Type {
	case group.CommandHub:
		if body.Hub != nil && body.Hub.Stop {
			return s.hubStopped(body)
		}
		return s.takeHub(body)
	case group.CommandPaste:
		return s.pasted(body, c, from)
	case group.CommandPasteOff:
		return s.pasteOff(body)
	case group.CommandAction:
		return s.act(body, c, from)
	case group.CommandActionsOff:
		return s.actionsOff(body)
	case group.CommandAwayOff:
		return s.awayOff(body)
	case group.CommandMute, group.CommandUnmute:
		return s.muteCommand(body)
	}
	m, err := clip.ParseMode(body.Mode)
	if err != nil {
		res.Status, res.Reason = node.ResultRefused, err.Error()
		return res
	}
	if err := s.setSync(m == clip.Shared, 0); err != nil {
		res.Status, res.Reason = node.ResultFailed, err.Error()
		return res
	}
	s.logf("cbb: %s turned sync %s here", body.By, onOff(m == clip.Shared))
	res.Status = node.ResultDone
	return res
}

// setSyncOn turns sync on or off on the member target, by name or device
// ID, with a mode command this device signs as an admin.
func (s *Service) setSyncOn(ctx context.Context, target string, on bool) error {
	name := clip.Own.String()
	if on {
		name = clip.Shared.String()
	}
	s.mu.Lock()
	id, nd := s.id, s.nd
	s.mu.Unlock()
	if id == nil || nd == nil {
		return s.errNoGroup()
	}
	d, err := s.findDevice(target)
	if err != nil {
		return err
	}
	if d.Self {
		return s.setSync(on, 0)
	}
	ca, chain := id.Signer()
	if ca == nil {
		return errors.New("only an admin turns sync on or off on another device: the group's root, an admin it made (cbb admin), or an admin phone")
	}
	if s.frozen(id) {
		return errFrozen
	}
	now := s.cfg.now()
	body := group.CommandBody{Type: group.CommandMode, Group: group.Tag(id.GroupCA.Cert), By: id.ID, To: group.DeviceID(d.ID),
		ID: group.NewCommandID(), TimeMS: now.UnixMilli(), ExpiresMS: now.Add(group.CommandLifetime).UnixMilli(), Mode: name}
	cmd, err := s.signCommand(body, ca, chain)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := nd.SendCommand(ctx, group.DeviceID(d.ID), cmd, body.ID, s.hubOrder())
	if err != nil {
		return fmt.Errorf("turning sync %s on %s: %w", onOff(on), d.Name, err)
	}
	if res.Status != node.ResultDone {
		return fmt.Errorf("%s did not turn sync %s: %s", d.Name, onOff(on), res.Reason)
	}
	s.logf("cbb: turned sync %s on %s", onOff(on), d.Name)
	return nil
}
