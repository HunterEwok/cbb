// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/remotepaste"
)

// A remote paste of images or files (docs/protocol.md, section 15): the
// sender makes a copy of them in the group as any copy, and its paste
// command names that copy's event ID. This member waits for the copy,
// fetches its parts, and hands the paste to a desktop watcher whose
// clipboard takes them: the watcher fetches them with paste-media, writes
// its clipboard and presses the paste keys, so that a chat or a document
// gets the image or the files. tmux and a text console take only text.

// Paste waits: how long the copy has to arrive and its parts to be
// fetched, and how long a watcher has to write them and press the keys.
// Together they stay within a command's lifetime, after which the members
// in between no longer pass its result back.
var (
	copyWait      = 20 * time.Second
	copyPasteWait = 8 * time.Second
)

// copyPoll is how often the service looks whether the copy arrived.
var copyPoll = 50 * time.Millisecond

// pasteCopy carries out a paste of the group's copy of images or files
// that body names, once the switches and the limits took it.
func (s *Service) pasteCopy(body group.CommandBody, set remotepaste.Settings) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultRefused}
	ctx, cancel := context.WithTimeout(context.Background(), copyWait)
	defer cancel()
	ev, why := s.copyToPaste(ctx, body)
	if why != "" {
		res.Reason = why
		return res
	}
	s.mu.Lock()
	var ws []*watcher
	textOnly := false
	for w := range s.watchers {
		switch {
		case w.inject == targetDesktop && w.takes(ev.Media):
			ws = append(ws, w)
		case w.inject != "":
			textOnly = true
		}
	}
	s.mu.Unlock()
	if len(ws) == 0 {
		switch {
		case s.cfg.OS == group.OSMacOS:
			res.Reason = "a Mac pastes images and files through the CBB app, and it is not open here or does not take them yet"
		case textOnly:
			res.Reason = "the paste targets here take only text: tmux, a text console, or a desktop whose clipboard takes no images or files"
		default:
			res.Reason = "nothing on this device can paste images or files: no desktop session of CBB runs here"
		}
		return res
	}
	ws, why = s.screenUsers(ws, false)
	if len(ws) == 0 {
		res.Reason = why
		return res
	}
	var blob *clip.Blob
	if ev.Sealed != nil {
		blob = ev.Sealed.Blob
	}
	s.setMedia(&mediaCopy{m: ev.Media, key: ev.Key, blob: blob}, group.DeviceID(ev.Origin), s.groupContext())
	if err := s.waitMedia(ctx, nil, ev.Media); err != nil {
		res.Status = node.ResultFailed
		res.Reason = "the copy's images or files did not arrive here"
		if !errors.Is(err, context.DeadlineExceeded) {
			res.Reason += ": " + err.Error()
		}
		return res
	}
	var reasons []string
	for _, w := range ws {
		in := &inject{body: body, text: body.Text, done: make(chan node.Result, 1), noLockCheck: set.NoLockCheck}
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
		case <-time.After(copyPasteWait):
			reasons = append(reasons, "the "+w.inject+" target did not answer")
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "the paste targets here are busy; try again")
	}
	res.Reason = joinReasons(reasons)
	return res
}

// copyToPaste waits until the copy that body names is the group's current
// copy here and checks it: images or files that this device reads, sealed
// to the device that signed the paste too, so that a paste never puts in a
// copy that its sender could not read. why says why not.
func (s *Service) copyToPaste(ctx context.Context, body group.CommandBody) (ev clip.Event, why string) {
	t := time.NewTicker(copyPoll)
	defer t.Stop()
	for {
		if e := s.engine(); e != nil {
			if cur, ok := e.Current(); ok && cur.ID == body.Text {
				ev = cur
				break
			}
		}
		select {
		case <-ctx.Done():
			return ev, "the copy to paste did not arrive here, or a newer copy replaced it"
		case <-t.C:
		}
	}
	switch {
	case ev.Unread:
		return ev, "this device cannot read the copy to paste"
	case ev.Kind != clip.Media || ev.Media == nil:
		return ev, "the copy to paste holds no images or files"
	case ev.Sealed == nil || !slices.ContainsFunc(ev.Sealed.Wraps, func(w clip.Wrap) bool { return w.To == string(body.By) }):
		return ev, "the copy to paste was not sealed to the device that sent the paste"
	}
	return ev, ""
}
