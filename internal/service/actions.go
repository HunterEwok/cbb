// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/actions"
	"github.com/HunterEwok/clipboardbridge/internal/control"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/node"
)

// Quick actions (design.md, "Quick actions"; docs/protocol.md, section
// 15): an admin's signed action command names one of this member's
// actions, which runs only when its user turned it on here, for that kind
// of signer, within the limits per sender.

// actionWait bounds how long a preset may take to start.
const actionWait = 20 * time.Second

// restartAfter is how long the service waits before it restarts at an
// admin's request, so that the result reaches the sender first.
const restartAfter = 500 * time.Millisecond

// resultWait bounds the wait for a result to be written before what comes
// after it, such as a restart, happens anyway: the connection that brought
// the command may have ended.
const resultWait = 10 * time.Second

// ErrRestart is what Run returns when an admin had the service restart:
// systemd, launchd and the Windows service manager start it again after a
// failure.
var ErrRestart = errors.New("restarting at an admin's request")

// act carries out an action command that VerifyCommand took; c is the
// command, for its signer, from the sender from.
func (s *Service) act(body group.CommandBody, c group.Record, from sender) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultRefused}
	set, err := actions.Load(s.cfg.StateDir)
	switch {
	case err != nil:
		res.Status, res.Reason = node.ResultFailed, fmt.Sprintf("reading the quick actions: %v", err)
	case !set.Has(body.Action):
		res.Reason = fmt.Sprintf("this device has no action %q", body.Action)
	default:
		s.recMu.Lock()
		dev, root, ok := s.records.CommandSigner(c)
		s.recMu.Unlock()
		signer := actions.Signer{Root: root}
		if ok {
			signer.Role, signer.Store = dev.Role, dev.Store
		}
		if err := actions.Check(set.Get(body.Action), signer); err != nil {
			res.Reason = err.Error()
		} else if !s.actionLimit.Allow(from.key, s.cfg.now()) {
			res.Reason = "too many actions: at most one a second and 30 a minute from one device"
		} else {
			res = s.runAction(body, set.Get(body.Action))
		}
	}
	if res.Status == node.ResultDone {
		s.logf("cbb: %s ran the action %s here", from.who(body), body.Action)
	} else {
		s.logf("cbb: the action %s from %s: %s: %s", body.Action, from.who(body), res.Status, res.Reason)
	}
	e := actions.Entry{TimeMS: s.cfg.now().UnixMilli(), By: string(body.By), Name: s.senderName(body, from),
		Unverified: !from.verified, Action: body.Action, Result: res.Status, Reason: res.Reason}
	if err := actions.Append(s.cfg.StateDir, e); err != nil {
		s.logf("cbb: keeping the action log: %v", err)
	}
	return res
}

// runAction runs an action that passed the checks: a preset, or one of
// the user's own, which runs in the user's session.
func (s *Service) runAction(body group.CommandBody, a actions.Action) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultDone}
	if body.Action == actions.Restart {
		if s.restart == nil {
			res.Status, res.Reason = node.ResultFailed, "the service is not running"
			return res
		}
		res.Written = make(chan struct{})
		go func() {
			select {
			case <-res.Written:
			case <-time.After(resultWait):
			}
			time.Sleep(restartAfter)
			select {
			case s.restart <- struct{}{}:
			default:
			}
		}()
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionWait)
	defer cancel()
	var err error
	if body.Action == actions.Layout {
		err = s.nextKeyboardLayout()
	} else if len(a.Command) > 0 {
		err = sessionRunner{s}.run(ctx, body.Action, a.Command)
	} else {
		err = s.cfg.runner.Run(ctx, body.Action)
	}
	var r *actions.Refusal
	switch {
	case err == nil:
	case errors.As(err, &r):
		res.Status, res.Reason = node.ResultRefused, r.Reason
	default:
		res.Status, res.Reason = node.ResultFailed, err.Error()
	}
	return res
}

// actionsOff turns every quick action off here, at an admin's command.
func (s *Service) actionsOff(body group.CommandBody) node.Result {
	res := node.Result{ID: body.ID, Status: node.ResultDone}
	if err := s.allActionsOff(); err != nil {
		res.Status, res.Reason = node.ResultFailed, err.Error()
		return res
	}
	s.logf("cbb: %s turned the quick actions off here", body.By)
	return res
}

// allActionsOff turns every action off here. The rights the user granted
// stay until cbb action enable or disable runs again here, as root; with
// the actions off the service uses none of them.
func (s *Service) allActionsOff() error {
	set, err := actions.Load(s.cfg.StateDir)
	if err != nil {
		return err
	}
	set.AllOff()
	return actions.Save(s.cfg.StateDir, set)
}

// setAction serves cbb action enable and disable: only this device's own
// user sets its actions.
func (s *Service) setAction(m *control.Message) error {
	if len(m.Actions) != 1 {
		return errors.New("set one action at a time")
	}
	a := m.Actions[0]
	by, err := actions.ParseKinds(strings.Join(a.By, ","))
	if err != nil {
		return err
	}
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()
	if id == nil {
		return s.errNoGroup()
	}
	set, err := actions.Load(s.cfg.StateDir)
	if err != nil {
		return err
	}
	command := a.Command
	switch {
	case len(command) > 0:
		if err := actions.CheckOwn(a.Name, command); err != nil {
			return err
		}
		if !set.Has(a.Name) && len(set.Own()) >= actions.MaxOwn {
			return fmt.Errorf("this device has %d actions of its user's own already, the most it keeps", actions.MaxOwn)
		}
	case actions.IsPreset(a.Name):
	case set.Has(a.Name):
		command = set.Get(a.Name).Command // enable or disable keeps it
	default:
		return fmt.Errorf("this device has no action %q; the presets are %s, and cbb action add adds your own", a.Name, strings.Join(actions.Presets, ", "))
	}
	set.Set(actions.Action{Name: a.Name, On: a.On, By: by, AnyKey: a.AnyKey, Command: command})
	if err := actions.Save(s.cfg.StateDir, set); err != nil {
		return fmt.Errorf("saving the quick actions: %w", err)
	}
	s.logf("cbb: the action %s is %s here (by %v, any key %v)", a.Name, onOff(a.On), by, a.AnyKey)
	return nil
}

// removeAction serves cbb action remove: the user's own action goes.
func (s *Service) removeAction(m *control.Message) error {
	set, err := actions.Load(s.cfg.StateDir)
	if err != nil {
		return err
	}
	if !set.Remove(m.Name) {
		if actions.IsPreset(m.Name) {
			return fmt.Errorf("%s is a preset, which stays; cbb action disable %s turns it off", m.Name, m.Name)
		}
		return fmt.Errorf("this device has no action of its user's own named %q", m.Name)
	}
	if err := actions.Save(s.cfg.StateDir, set); err != nil {
		return fmt.Errorf("saving the quick actions: %w", err)
	}
	s.logf("cbb: the action %s is removed here", m.Name)
	return nil
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// actionStatus lists this device's actions for cbb status: every preset,
// as its user set it.
func (s *Service) actionStatus() []control.Action {
	set, err := actions.Load(s.cfg.StateDir)
	if err != nil {
		return nil
	}
	var out []control.Action
	for _, p := range actions.Presets {
		a := set.Get(p)
		out = append(out, control.Action{Name: a.Name, On: a.On, By: a.By, AnyKey: a.AnyKey})
	}
	for _, a := range set.Own() {
		out = append(out, control.Action{Name: a.Name, On: a.On, By: a.By, AnyKey: a.AnyKey, Command: a.Command})
	}
	return out
}

// runActionOn serves cbb action -on: it signs an action command for the
// member Device and waits for its result.
func (s *Service) runActionOn(ctx context.Context, m *control.Message) error {
	if !group.ValidActionName(m.Name) {
		return fmt.Errorf("%q is not an action's name", m.Name)
	}
	d, err := s.findDevice(m.Device)
	if err != nil {
		return err
	}
	if d.Self {
		return errors.New("an action runs on another device; here, do it yourself")
	}
	return s.commandOn(ctx, d, group.CommandBody{Type: group.CommandAction, Action: m.Name})
}

// actionsOffOn serves cbb action off -on DEVICE or -all, on an admin.
func (s *Service) actionsOffOn(ctx context.Context, m *control.Message) error {
	var targets []control.Device
	switch {
	case m.All:
		devs, err := s.devices()
		if err != nil {
			return err
		}
		for _, d := range devs {
			if d.Self {
				if err := s.allActionsOff(); err != nil {
					return err
				}
				continue
			}
			targets = append(targets, d)
		}
	case m.Device != "":
		d, err := s.findDevice(m.Device)
		if err != nil {
			return err
		}
		if d.Self {
			return s.allActionsOff()
		}
		targets = []control.Device{d}
	default:
		return s.allActionsOff()
	}
	var failed []string
	for _, d := range targets {
		if err := s.commandOn(ctx, d, group.CommandBody{Type: group.CommandActionsOff}); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", d.Name, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("quick actions may still be on: %s", joinReasons(failed))
	}
	return nil
}

// sessionRunner runs the presets in the signed-in user's session, through
// the agent that offers them, as on a Mac and on Windows.
type sessionRunner struct{ s *Service }

func (r sessionRunner) Run(ctx context.Context, name string) error { return r.run(ctx, name, nil) }

// run hands the action name to an agent: a preset, or with command the
// user's own.
func (r sessionRunner) run(ctx context.Context, name string, command []string) error {
	s := r.s
	s.mu.Lock()
	var ws []*watcher
	for w := range s.watchers {
		if w.act {
			ws = append(ws, w)
		}
	}
	s.mu.Unlock()
	if len(ws) == 0 {
		return &actions.Refusal{Reason: "nobody is signed in here with CBB's agent running, and the actions run in the user's session"}
	}
	ws = slices.DeleteFunc(ws, func(w *watcher) bool { return s.mayTake(w.peer, targetAct) != allowed })
	if len(ws) == 0 {
		return &actions.Refusal{Reason: "CBB's agent runs here only as users who are not signed in at the screen, and the actions run in that user's session"}
	}
	body := group.CommandBody{Type: group.CommandAction, Action: name}
	var reasons []string
	for _, w := range ws {
		in := &inject{body: body, command: command, done: make(chan node.Result, 1)}
		select {
		case w.injects <- in:
		default:
			continue
		}
		select {
		case res := <-in.done:
			switch res.Status {
			case node.ResultDone:
				return nil
			case node.ResultRefused:
				return &actions.Refusal{Reason: res.Reason}
			}
			reasons = append(reasons, res.Reason)
		case <-ctx.Done():
			return errors.New("the agent did not answer")
		}
	}
	if len(reasons) == 0 {
		return errors.New("the agent is busy")
	}
	return errors.New(joinReasons(reasons))
}

// actionsOn lists the actions that are on here, for the hello.
func (s *Service) actionsOn() []string {
	set, err := actions.Load(s.cfg.StateDir)
	if err != nil {
		return nil
	}
	return set.On()
}
