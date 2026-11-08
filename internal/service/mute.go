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
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
)

// muteFile holds an admin's mute of this device (design.md, "Muting a
// device"), in the state directory.
const muteFile = "mute.json"

// muteState is what mute.json holds: the end of the mute, in Unix
// milliseconds, 0 for until it is lifted.
type muteState struct {
	Mute *int64 `json:"mute,omitempty"`
}

// unixMS is t in Unix milliseconds, 0 for the zero time.
func unixMS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// fromUnixMS is unixMS backwards.
func fromUnixMS(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// loadMute gives e the mute saved in dir.
func loadMute(dir string, e *clip.Engine) error {
	data, err := os.ReadFile(filepath.Join(dir, muteFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st muteState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("%s: %w", muteFile, err)
	}
	if st.Mute != nil {
		e.SetMute(fromUnixMS(*st.Mute))
	}
	return nil
}

// saveMute writes e's mute to dir.
func saveMute(dir string, e *clip.Engine) error {
	var st muteState
	if muted, until := e.Muted(); muted {
		ms := unixMS(until)
		st.Mute = &ms
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, muteFile), data, 0o600)
}

// muteUntil is the end of a mute for ms from now, the zero time for 0.
func (s *Service) muteUntil(ms int64) (time.Time, error) {
	if ms < 0 || ms > group.MaxMute.Milliseconds() {
		return time.Time{}, fmt.Errorf("a mute lasts at most %v; leave the time out to mute until cbb unmute", group.MaxMute)
	}
	if ms == 0 {
		return time.Time{}, nil
	}
	return s.cfg.now().Add(time.Duration(ms) * time.Millisecond), nil
}

// muteOp carries out the control operations mute and unmute: an admin
// mutes a device or ends its mute, with a command it signs, or at once
// when the device is this one.
func (s *Service) muteOp(ctx context.Context, m *control.Message) error {
	on := m.Op == control.OpMute
	s.mu.Lock()
	e, id := s.eng, s.id
	s.mu.Unlock()
	if e == nil || id == nil {
		return s.errNoGroup()
	}
	until, err := s.muteUntil(m.ForMS)
	if err != nil {
		return err
	}
	if m.Device == "" {
		return errors.New("name the device to mute with -on; cbb sync off turns this device's own sync off")
	}
	d, err := s.findDevice(m.Device)
	if err != nil {
		return err
	}
	if ca, _ := id.Signer(); ca == nil {
		return errors.New("only an admin mutes a device or ends its mute: the group's root, an admin it made (cbb admin), or an admin phone; cbb sync off turns this device's own sync off")
	}
	if s.frozen(id) {
		return errFrozen
	}
	if d.Self {
		return s.setMuted(e, on, until, id.ID)
	}
	body := group.CommandBody{Type: group.CommandUnmute}
	if on {
		body = group.CommandBody{Type: group.CommandMute, ForMS: m.ForMS}
	}
	return s.commandOn(ctx, d, body)
}

// setMuted mutes this device until until at the admin by's order, or ends
// its mute, saves it, and
// connects to the members again, once res is written when it is a
// command's result, so that their hellos show it.
func (s *Service) setMuted(e *clip.Engine, on bool, until time.Time, by group.DeviceID, res ...*node.Result) error {
	if on {
		e.SetMute(until)
	} else {
		e.Unmute()
	}
	if err := saveMute(s.cfg.StateDir, e); err != nil {
		return fmt.Errorf("saving the mute: %w", err)
	}
	switch {
	case !on:
		s.logf("cbb: %s ended the mute: this device's copies reach the group again", by)
	case until.IsZero():
		s.logf("cbb: %s muted this device until an admin unmutes it", by)
	default:
		s.logf("cbb: %s muted this device until %s", by, until.Format(time.DateTime))
	}
	s.mu.Lock()
	nd := s.nd
	s.mu.Unlock()
	if nd == nil {
		return nil
	}
	var written chan struct{}
	if len(res) > 0 {
		written = make(chan struct{})
		res[0].Written = written
	}
	go func() {
		if written != nil {
			select {
			case <-written:
			case <-time.After(resultWait):
			}
		}
		time.Sleep(restartAfter)
		nd.Reconnect()
	}()
	return nil
}

// muteCommand carries out a mute or unmute command an admin sent.
func (s *Service) muteCommand(body group.CommandBody) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultDone}
	s.mu.Lock()
	e := s.eng
	s.mu.Unlock()
	if e == nil {
		res.Status, res.Reason = node.ResultFailed, s.errNoGroup().Error()
		return res
	}
	var until time.Time
	if body.ForMS > 0 {
		until = s.cfg.now().Add(time.Duration(body.ForMS) * time.Millisecond)
	}
	if err := s.setMuted(e, body.Type == group.CommandMute, until, body.By, &res); err != nil {
		res.Status, res.Reason = node.ResultFailed, err.Error()
	}
	return res
}
