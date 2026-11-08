// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package peripheral

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/tvremote"
	"github.com/HunterEwok/cbb/internal/tvremote/androidtv"
	"github.com/HunterEwok/cbb/internal/tvremote/appletv"
	"github.com/HunterEwok/cbb/internal/tvremote/roku"
)

// The TVs' own remotes (docs/roadmap.md, item 25, way 2; internal/tvremote):
// the host pairs with an Android TV or an Apple TV as its remote, or takes a Roku the
// user allowed, types on it what cbb remote type gives it, and, when the
// user sends them there, the remote pastes of the group's admins. A TV is
// reached only on the home network.

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

// Remote carries out cbb remote: Name "" (the status), "add" (Address
// the TV, Value its kind, NewName its name; Consent for a Roku), "code"
// (Code, the one the TV shows), "cancel", "remove", "pastes" (Value on or
// off) and "type" (the payload), the last three for the TV Device.
func (h *Host) Remote(ctx context.Context, m *control.Message) error {
	st, err := tvremote.Load(h.Dir)
	if err != nil {
		return fmt.Errorf("reading the TVs: %w", err)
	}
	switch m.Name {
	case "":
		return nil
	case "add":
		return h.addTV(ctx, &st, m)
	case "code":
		return h.tvCode(&st, m.Code)
	case "cancel":
		h.endTVPairing()
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
	if err := tvremote.Save(h.Dir, st); err != nil {
		return fmt.Errorf("saving the TVs: %w", err)
	}
	h.Logf("cbb: the TV %s (%s): %s %s", t.Name, tvKind(t.Kind), m.Name, m.Value)
	return nil
}

// addTV adds a Roku at once, and starts pairing with an Android TV or an
// Apple TV, which then shows the code or PIN that cbb remote code takes.
func (h *Host) addTV(ctx context.Context, st *tvremote.State, m *control.Message) error {
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
		name, err := roku.New(host, TVDial).Name(ctx)
		if err != nil {
			return tvError(tvremote.TV{Name: host, Kind: kind}, "reaching", err)
		}
		if m.NewName != "" {
			name = m.NewName
		}
		if err := st.Put(tvremote.TV{Name: name, Kind: kind, Host: host}); err != nil {
			return err
		}
		if err := tvremote.Save(h.Dir, *st); err != nil {
			return fmt.Errorf("saving the TVs: %w", err)
		}
		h.Logf("cbb: added the Roku %s at %s", name, host)
		return nil
	case tvremote.AppleTV:
		h.endTVPairing()
		name := m.NewName
		if name == "" {
			// The name the TV shows in its Settings, as it announces it.
			name = AppleTVName(ctx, host)
		}
		p, err := appletv.Pair(ctx, host, "CBB "+h.Name)
		if err != nil {
			return tvError(tvremote.TV{Name: host, Kind: kind}, "pairing with", err)
		}
		h.tv.mu.Lock()
		defer h.tv.mu.Unlock()
		h.tv.apple, h.tv.host, h.tv.name = p, host, name
		h.tv.timer = time.AfterFunc(tvPairWait, h.endTVPairing)
		return nil
	case tvremote.AndroidTV:
	default:
		return fmt.Errorf("the TV's kind is %s, %s or %s, not %q", tvremote.AndroidTV, tvremote.AppleTV, tvremote.Roku, kind)
	}
	if st.Client == nil {
		c, err := androidtv.NewClient("CBB " + h.Name)
		if err != nil {
			return err
		}
		st.Client = &c
		if err := tvremote.Save(h.Dir, *st); err != nil {
			return fmt.Errorf("saving the TVs: %w", err)
		}
	}
	h.endTVPairing()
	p, err := androidtv.Pair(ctx, host, *st.Client, "CBB "+h.Name)
	if err != nil {
		return tvError(tvremote.TV{Name: host, Kind: kind}, "pairing with", err)
	}
	h.tv.mu.Lock()
	defer h.tv.mu.Unlock()
	h.tv.pairing, h.tv.host, h.tv.name = p, host, m.NewName
	h.tv.timer = time.AfterFunc(tvPairWait, h.endTVPairing)
	return nil
}

// tvCode finishes the pairing with the code the TV shows.
func (h *Host) tvCode(st *tvremote.State, code string) error {
	h.tv.mu.Lock()
	p, apple, host, name := h.tv.pairing, h.tv.apple, h.tv.host, h.tv.name
	h.tv.mu.Unlock()
	if apple != nil {
		return h.appleCode(st, apple, host, name, code)
	}
	if p == nil {
		return errors.New("no TV is pairing: start with cbb remote add")
	}
	pin, err := p.Finish(code)
	if errors.Is(err, androidtv.ErrCode) {
		h.endTVPairing()
		return fmt.Errorf("%w; start again with cbb remote add", err)
	}
	h.endTVPairing()
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
	if err := tvremote.Save(h.Dir, *st); err != nil {
		return fmt.Errorf("saving the TVs: %w", err)
	}
	h.Logf("cbb: paired with the Android TV %s at %s", name, host)
	return nil
}

// appleCode finishes the pairing with an Apple TV with the PIN it shows.
func (h *Host) appleCode(st *tvremote.State, p *appletv.Pairing, host, name, pin string) error {
	cr, err := p.Finish(pin)
	h.endTVPairing()
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
	if err := tvremote.Save(h.Dir, *st); err != nil {
		return fmt.Errorf("saving the TVs: %w", err)
	}
	h.Logf("cbb: paired with the Apple TV %s at %s", name, host)
	return nil
}

// endTVPairing ends the pairing in progress, if any.
func (h *Host) endTVPairing() {
	h.tv.mu.Lock()
	defer h.tv.mu.Unlock()
	if h.tv.pairing != nil {
		h.tv.pairing.Close()
	}
	if h.tv.apple != nil {
		h.tv.apple.Close()
	}
	if h.tv.timer != nil {
		h.tv.timer.Stop()
	}
	h.tv.pairing, h.tv.apple, h.tv.host, h.tv.name, h.tv.timer = nil, nil, "", "", nil
}

// TVStatus describes the TVs for cbb status.
func (h *Host) TVStatus() []control.TV {
	st, err := tvremote.Load(h.Dir)
	if err != nil {
		return nil
	}
	var out []control.TV
	for _, t := range st.TVs {
		out = append(out, control.TV{Name: t.Name, Kind: t.Kind, Host: t.Host, Pastes: t.Pastes})
	}
	h.tv.mu.Lock()
	switch {
	case h.tv.pairing != nil:
		out = append(out, control.TV{Name: h.tv.name, Kind: tvremote.AndroidTV, Host: h.tv.host, Pairing: true})
	case h.tv.apple != nil:
		out = append(out, control.TV{Name: h.tv.name, Kind: tvremote.AppleTV, Host: h.tv.host, Pairing: true})
	}
	h.tv.mu.Unlock()
	return out
}

// AppleTVName finds the name an Apple TV announces by mDNS; tests stand
// in for it.
var AppleTVName = appletv.Name

// TVDial connects to a TV: only on the home network (tvremote.Dialer). A
// variable for the tests.
var TVDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
	return tvremote.Dialer().DialContext(ctx, network, addr)
}

// tvPastes is whether remote pastes go to a TV.
func (h *Host) tvPastes() bool {
	st, err := tvremote.Load(h.Dir)
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
func (h *Host) tvPaste(text string, enter, bodyEnter bool, still func() bool) (Result, bool) {
	st, err := tvremote.Load(h.Dir)
	if err != nil {
		return Result{}, false
	}
	t, ok := st.Pasting()
	if !ok {
		return Result{}, false
	}
	res := Result{Status: Refused}
	if strings.Contains(text, "\n") && !enter {
		res.Reason = fmt.Sprintf("the text has a line break, which the TV %s takes as Enter, and this device takes pastes without Enter only; send it as one line", t.Name)
		return res, true
	}
	if bodyEnter {
		text += "\n"
	}
	ctx, cancel := context.WithTimeout(context.Background(), pasteWait)
	defer cancel()
	switch t.Kind {
	case tvremote.Roku:
		c := roku.New(t.Host, TVDial)
		if _, err := c.Name(ctx); err != nil {
			return h.tvRefused(res, t, err), true
		}
		on := func() bool {
			st, err := tvremote.Load(h.Dir)
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
		if !h.typeLater("the Roku "+t.Name, on, typ) {
			res.Reason = fmt.Sprintf("the Roku %s is still typing the last paste; send this one when it is done", t.Name)
			return res, true
		}
	default:
		if err := tvremote.Type(ctx, t, st.Client, text); err != nil {
			return h.tvRefused(res, t, err), true
		}
	}
	return Result{Status: Done}, true
}

// tvRefused is the answer to a paste the TV did not take: refused when it
// is the TV's state (no text field, ECP off, a TV that forgot this remote),
// failed otherwise.
func (h *Host) tvRefused(res Result, t tvremote.TV, err error) Result {
	if !tvIsState(err) {
		res.Status = Failed
	}
	res.Reason = tvError(t, "typing on", err).Error()
	return res
}
