// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
)

// modeFile holds the sync mode, in the state directory. A device that made
// or joined its group gets one at once, with own; without one, the device
// shares.
const modeFile = "mode"

// loadMode reads the sync mode from dir.
func loadMode(dir string) (clip.Mode, error) {
	b, err := os.ReadFile(filepath.Join(dir, modeFile))
	if errors.Is(err, os.ErrNotExist) {
		return clip.Shared, nil
	}
	if err != nil {
		return clip.Shared, err
	}
	m, err := clip.ParseMode(strings.TrimSpace(string(b)))
	if err != nil {
		return clip.Shared, fmt.Errorf("%s: %w", modeFile, err)
	}
	return m, nil
}

// saveMode writes the sync mode to dir.
func saveMode(dir string, m clip.Mode) error {
	return atomicfile.Write(filepath.Join(dir, modeFile), []byte(m.String()+"\n"), 0o600)
}

// newDeviceMode gives a device that just made or joined a group the sync
// mode of a new device, own, unless it has a mode from an earlier group.
func (s *Service) newDeviceMode() error {
	_, err := os.Stat(filepath.Join(s.cfg.StateDir, modeFile))
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m := clip.Own
	if s.cfg.newMode != nil {
		m = *s.cfg.newMode
	}
	if err := saveMode(s.cfg.StateDir, m); err != nil {
		return fmt.Errorf("saving the sync mode: %w", err)
	}
	return nil
}

// setMode changes the sync mode and saves it.
func (s *Service) setMode(name string) error {
	m, err := clip.ParseMode(name)
	if err != nil {
		return err
	}
	e := s.engine()
	if e == nil {
		return s.errNoGroup()
	}
	if err := saveMode(s.cfg.StateDir, m); err != nil {
		return fmt.Errorf("saving the sync mode: %w", err)
	}
	e.SetMode(m)
	s.logf("cbb: the sync mode is %s now", m)
	return nil
}

// pasteText is what cbb paste prints: the local clipboard's text in a mode
// that takes the group's copies, and the group's current text in one that
// keeps its clipboard to itself, so that the group's text is at hand there
// on request.
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
	if _, err := clip.ParseMode(body.Mode); err != nil {
		res.Status, res.Reason = node.ResultRefused, err.Error()
		return res
	}
	if err := s.setMode(body.Mode); err != nil {
		res.Status, res.Reason = node.ResultFailed, err.Error()
		return res
	}
	s.logf("cbb: %s set the sync mode to %s", body.By, body.Mode)
	res.Status = node.ResultDone
	return res
}

// setModeOn has the member target, by name or device ID, take the sync
// mode name, with a command this device signs as an admin.
func (s *Service) setModeOn(ctx context.Context, target, name string) error {
	if _, err := clip.ParseMode(name); err != nil {
		return err
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
		return s.setMode(name)
	}
	ca, chain := id.Signer()
	if ca == nil {
		return errors.New("only an admin sets the sync mode of another device: the group's root, an admin it made (cbb admin), or an admin phone")
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
		return fmt.Errorf("setting the sync mode of %s: %w", d.Name, err)
	}
	if res.Status != node.ResultDone {
		return fmt.Errorf("%s did not take the sync mode: %s", d.Name, res.Reason)
	}
	s.logf("cbb: set the sync mode of %s to %s", d.Name, name)
	return nil
}
