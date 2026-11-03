// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/tvremote"
	"github.com/HunterEwok/cbb/internal/tvremote/androidtv"
	"github.com/HunterEwok/cbb/internal/tvremote/appletv"
	"github.com/HunterEwok/cbb/internal/tvremote/roku"
)

// The TVs' own remotes (docs/roadmap.md, item 25, way 2; internal/tvremote):
// the service pairs with an Android TV or an Apple TV as its remote, or takes a Roku the
// user allowed, types on it what cbb remote type gives it, and, when the
// user sends them there, the remote pastes of the group's admins. A TV is
// reached only on the home network.

// targetTV is a TV's remote as a paste target, which no watcher offers.
const targetTV = "tv"

// tvPairWait is how long a pairing waits for the code or PIN the TV shows.
const tvPairWait = 2 * time.Minute

// tvState is the TV pairing in progress, one at a time: with an Android
// TV (pairing) or an Apple TV (apple).
type tvState struct {
	mu      sync.Mutex
	pairing *androidtv.Pairing
	apple   *appletv.Pairing
	host    string
	name    string // the name the user gave, or ""
	timer   *time.Timer
}

// tvKind is the TV's kind as a user names it.
func tvKind(t string) string {
	switch t {
	case tvremote.AndroidTV:
		return "Android TV"
	case tvremote.AppleTV:
		return "Apple TV"
	case tvremote.Roku:
		return "Roku"
	}
	return t
}

// tvError is a TV's failure: the TV and its protocol for the user, with
// the cause as the detail.
func tvError(t tvremote.TV, what string, err error) error {
	if tvIsState(err) || errors.Is(err, tvremote.ErrOutside) || errors.Is(err, appletv.ErrRefused) || errors.Is(err, appletv.ErrBusy) {
		return fmt.Errorf("%s (%s): %w", t.Name, tvKind(t.Kind), err)
	}
	return &pair.CauseError{Msg: fmt.Sprintf("%s %s (%s)", what, t.Name, tvKind(t.Kind)), Err: err}
}

// tvIsState is a failure that is the TV's state, not a fault: no text
// field open, ECP off, or a TV that forgot this remote.
func tvIsState(err error) bool {
	return errors.Is(err, androidtv.ErrNoField) || errors.Is(err, roku.ErrOff) ||
		errors.Is(err, appletv.ErrNoField) || errors.Is(err, appletv.ErrNotPaired)
}

// remote carries out cbb remote: Name "" (the status), "add" (Address
// the TV, Value its kind, NewName its name; Consent for a Roku), "code"
// (Code, the one the TV shows), "cancel", "remove", "pastes" (Value on or
// off) and "type" (the payload), the last three for the TV Device.
func (s *Service) remote(ctx context.Context, m *control.Message) error {
	st, err := tvremote.Load(s.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("reading the TVs: %w", err)
	}
	switch m.Name {
	case "":
		return nil
	case "add":
		return s.addTV(ctx, &st, m)
	case "code":
		return s.tvCode(&st, m.Code)
	case "cancel":
		s.endTVPairing()
		return nil
	case "remove", "pastes", "type":
	default:
		return fmt.Errorf("cbb remote takes add, code, cancel, remove, pastes or type, not %q", m.Name)
	}
	i, err := st.Find(m.Device)
	if err != nil {
		return err
	}
	t := st.TVs[i]
	switch m.Name {
	case "remove":
		st.TVs = append(st.TVs[:i], st.TVs[i+1:]...)
	case "pastes":
		on := m.Value == "on"
		if !on && m.Value != "off" {
			return fmt.Errorf("cbb remote pastes takes on or off, not %q", m.Value)
		}
		for j := range st.TVs {
			st.TVs[j].Pastes = on && j == i
		}
	case "type":
		text := strings.ReplaceAll(string(m.Payload), "\r\n", "\n")
		if err := tvremote.Type(ctx, t, st.Client, text); err != nil {
			return tvError(t, "typing on", err)
		}
		return nil
	}
	if err := tvremote.Save(s.cfg.StateDir, st); err != nil {
		return fmt.Errorf("saving the TVs: %w", err)
	}
	s.logf("cbb: the TV %s (%s): %s %s", t.Name, tvKind(t.Kind), m.Name, m.Value)
	return nil
}

// addTV adds a Roku at once, and starts pairing with an Android TV or an
// Apple TV, which then shows the code or PIN that cbb remote code takes.
func (s *Service) addTV(ctx context.Context, st *tvremote.State, m *control.Message) error {
	host, err := tvremote.CheckHost(ctx, m.Address)
	if err != nil {
		return err
	}
	kind := m.Value
	if kind == "" {
		kind = tvremote.AndroidTV
	}
	switch kind {
	case tvremote.Roku:
		if !m.Consent {
			return errors.New("a Roku takes keys over plain HTTP: the text crosses the home network unencrypted, and anyone on it can type on the Roku too; add it with -consent if that is all right")
		}
		name, err := roku.New(host, tvDial).Name(ctx)
		if err != nil {
			return tvError(tvremote.TV{Name: host, Kind: kind}, "reaching", err)
		}
		if m.NewName != "" {
			name = m.NewName
		}
		if err := st.Put(tvremote.TV{Name: name, Kind: kind, Host: host}); err != nil {
			return err
		}
		if err := tvremote.Save(s.cfg.StateDir, *st); err != nil {
			return fmt.Errorf("saving the TVs: %w", err)
		}
		s.logf("cbb: added the Roku %s at %s", name, host)
		return nil
	case tvremote.AppleTV:
		s.endTVPairing()
		name := m.NewName
		if name == "" {
			// The name the TV shows in its Settings, as it announces it.
			name = appleTVName(ctx, host)
		}
		p, err := appletv.Pair(ctx, host, "CBB "+s.cfg.Name)
		if err != nil {
			return tvError(tvremote.TV{Name: host, Kind: kind}, "pairing with", err)
		}
		s.tv.mu.Lock()
		defer s.tv.mu.Unlock()
		s.tv.apple, s.tv.host, s.tv.name = p, host, name
		s.tv.timer = time.AfterFunc(tvPairWait, s.endTVPairing)
		return nil
	case tvremote.AndroidTV:
	default:
		return fmt.Errorf("the TV's kind is %s, %s or %s, not %q", tvremote.AndroidTV, tvremote.AppleTV, tvremote.Roku, kind)
	}
	if st.Client == nil {
		c, err := androidtv.NewClient("CBB " + s.cfg.Name)
		if err != nil {
			return err
		}
		st.Client = &c
		if err := tvremote.Save(s.cfg.StateDir, *st); err != nil {
			return fmt.Errorf("saving the TVs: %w", err)
		}
	}
	s.endTVPairing()
	p, err := androidtv.Pair(ctx, host, *st.Client, "CBB "+s.cfg.Name)
	if err != nil {
		return tvError(tvremote.TV{Name: host, Kind: kind}, "pairing with", err)
	}
	s.tv.mu.Lock()
	defer s.tv.mu.Unlock()
	s.tv.pairing, s.tv.host, s.tv.name = p, host, m.NewName
	s.tv.timer = time.AfterFunc(tvPairWait, s.endTVPairing)
	return nil
}

// tvCode finishes the pairing with the code the TV shows.
func (s *Service) tvCode(st *tvremote.State, code string) error {
	s.tv.mu.Lock()
	p, apple, host, name := s.tv.pairing, s.tv.apple, s.tv.host, s.tv.name
	s.tv.mu.Unlock()
	if apple != nil {
		return s.appleCode(st, apple, host, name, code)
	}
	if p == nil {
		return errors.New("no TV is pairing: start with cbb remote add")
	}
	pin, err := p.Finish(code)
	if errors.Is(err, androidtv.ErrCode) {
		s.endTVPairing()
		return fmt.Errorf("%w; start again with cbb remote add", err)
	}
	s.endTVPairing()
	if name == "" {
		name = p.TV
	}
	if name == "" {
		name = host
	}
	t := tvremote.TV{Name: name, Kind: tvremote.AndroidTV, Host: host, Pin: pin}
	if err != nil {
		return tvError(t, "pairing with", err)
	}
	if err := st.Put(t); err != nil {
		return err
	}
	if err := tvremote.Save(s.cfg.StateDir, *st); err != nil {
		return fmt.Errorf("saving the TVs: %w", err)
	}
	s.logf("cbb: paired with the Android TV %s at %s", name, host)
	return nil
}

// appleCode finishes the pairing with an Apple TV with the PIN it shows.
func (s *Service) appleCode(st *tvremote.State, p *appletv.Pairing, host, name, pin string) error {
	cr, err := p.Finish(pin)
	s.endTVPairing()
	if name == "" {
		name = host
	}
	t := tvremote.TV{Name: name, Kind: tvremote.AppleTV, Host: host, Apple: &cr}
	if errors.Is(err, appletv.ErrCode) {
		return fmt.Errorf("%w; start again with cbb remote add -appletv", err)
	}
	if err != nil {
		return tvError(t, "pairing with", err)
	}
	if err := st.Put(t); err != nil {
		return err
	}
	if err := tvremote.Save(s.cfg.StateDir, *st); err != nil {
		return fmt.Errorf("saving the TVs: %w", err)
	}
	s.logf("cbb: paired with the Apple TV %s at %s", name, host)
	return nil
}

// endTVPairing ends the pairing in progress, if any.
func (s *Service) endTVPairing() {
	s.tv.mu.Lock()
	defer s.tv.mu.Unlock()
	if s.tv.pairing != nil {
		s.tv.pairing.Close()
	}
	if s.tv.apple != nil {
		s.tv.apple.Close()
	}
	if s.tv.timer != nil {
		s.tv.timer.Stop()
	}
	s.tv.pairing, s.tv.apple, s.tv.host, s.tv.name, s.tv.timer = nil, nil, "", "", nil
}

// tvStatus describes the TVs for cbb status.
func (s *Service) tvStatus() []control.TV {
	st, err := tvremote.Load(s.cfg.StateDir)
	if err != nil {
		return nil
	}
	var out []control.TV
	for _, t := range st.TVs {
		out = append(out, control.TV{Name: t.Name, Kind: t.Kind, Host: t.Host, Pastes: t.Pastes})
	}
	s.tv.mu.Lock()
	switch {
	case s.tv.pairing != nil:
		out = append(out, control.TV{Name: s.tv.name, Kind: tvremote.AndroidTV, Host: s.tv.host, Pairing: true})
	case s.tv.apple != nil:
		out = append(out, control.TV{Name: s.tv.name, Kind: tvremote.AppleTV, Host: s.tv.host, Pairing: true})
	}
	s.tv.mu.Unlock()
	return out
}

// appleTVName finds the name an Apple TV announces by mDNS; tests stand
// in for it.
var appleTVName = appletv.Name

// tvDial connects to a TV: only on the home network (tvremote.Dialer). A
// variable for the tests.
var tvDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
	return tvremote.Dialer().DialContext(ctx, network, addr)
}

// tvPastes is whether remote pastes go to a TV.
func (s *Service) tvPastes() bool {
	st, err := tvremote.Load(s.cfg.StateDir)
	if err != nil {
		return false
	}
	_, ok := st.Pasting()
	return ok
}

// tvPaste types a remote paste on the TV the user sends pastes to; ok is
// false when there is none. A line break presses Enter there (on an Apple
// TV it ends a field of one line), so a text
// with one is refused unless the user allowed Enter. An Android TV takes
// the text at once; a Roku takes it key by key, so its answer is done once
// typing starts, and typing stops when still says the paste may no longer
// go on or the user sends pastes elsewhere.
func (s *Service) tvPaste(body group.CommandBody, text string, enter bool, still func() bool) (node.Result, bool) {
	st, err := tvremote.Load(s.cfg.StateDir)
	if err != nil {
		return node.Result{}, false
	}
	t, ok := st.Pasting()
	if !ok {
		return node.Result{}, false
	}
	res := node.Result{ID: body.ID, Status: node.ResultRefused}
	if strings.Contains(text, "\n") && !enter {
		res.Reason = fmt.Sprintf("the text has a line break, which the TV %s takes as Enter, and this device takes pastes without Enter only; send it as one line", t.Name)
		return res, true
	}
	if body.Enter {
		text += "\n"
	}
	ctx, cancel := context.WithTimeout(context.Background(), injectWait)
	defer cancel()
	switch t.Kind {
	case tvremote.Roku:
		c := roku.New(t.Host, tvDial)
		if _, err := c.Name(ctx); err != nil {
			return s.tvRefused(res, t, err), true
		}
		on := func() bool {
			st, err := tvremote.Load(s.cfg.StateDir)
			if err != nil {
				return false
			}
			now, ok := st.Pasting()
			return ok && now.Host == t.Host && still()
		}
		typ := func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, time.Minute+time.Duration(len(text))*100*time.Millisecond)
			defer cancel()
			return c.Type(ctx, text)
		}
		if !s.typeLater("the Roku "+t.Name, on, typ) {
			res.Reason = fmt.Sprintf("the Roku %s is still typing the last paste; send this one when it is done", t.Name)
			return res, true
		}
	default:
		if err := tvremote.Type(ctx, t, st.Client, text); err != nil {
			return s.tvRefused(res, t, err), true
		}
	}
	return node.Result{ID: body.ID, Status: node.ResultDone}, true
}

// tvRefused is the answer to a paste the TV did not take: refused when it
// is the TV's state (no text field, ECP off, a TV that forgot this remote),
// failed otherwise.
func (s *Service) tvRefused(res node.Result, t tvremote.TV, err error) node.Result {
	if !tvIsState(err) {
		res.Status = node.ResultFailed
	}
	res.Reason = tvError(t, "typing on", err).Error()
	return res
}
