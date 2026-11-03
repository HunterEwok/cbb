// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/ei"
)

// Remote paste on GNOME and KDE (design.md, "Remote paste"): their
// compositors give no client a virtual keyboard, so the keys go through the
// RemoteDesktop portal, which hands out an ei connection to the compositor.
// The device's user allows it once in the portal's dialog; the restore
// token the portal returns keeps the consent, so later sessions start
// without asking. The keys follow the user's layout, so the portal only
// pastes (Shift+Insert after the clipboard write) and presses Enter: both
// are the same key on every layout.

const (
	portalBus       = "org.freedesktop.portal.Desktop"
	portalPath      = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	portalRemote    = "org.freedesktop.portal.RemoteDesktop"
	portalRequest   = "org.freedesktop.portal.Request"
	portalKeyboard  = uint32(1) // the device type
	portalPersist   = uint32(2) // until the user revokes it
	portalAnswer    = 2 * time.Second
	portalTokenFile = "portal-restore-token"
)

// portal is a RemoteDesktop session's keyboard, set up at the first paste.
type portal struct {
	logf  func(string, ...any)
	state string // the directory of the restore token

	mu       sync.Mutex
	kbd      *ei.Keyboard
	starting chan struct{} // closed when a start ends; nil when none runs
	declined bool          // the user said no in the dialog
	err      error         // why the last start failed
	conn     *dbus.Conn
}

// newPortal returns the portal's keyboard, or nil when the session has no
// RemoteDesktop portal that hands out ei connections (version 2).
func newPortal(logf func(string, ...any)) *portal {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil
	}
	p := portalOn(conn, logf)
	if p == nil {
		conn.Close()
	}
	return p
}

// portalOn is newPortal on the bus conn, which the portal then owns.
func portalOn(conn *dbus.Conn, logf func(string, ...any)) *portal {
	v, err := conn.Object(portalBus, portalPath).GetProperty(portalRemote + ".version")
	if err != nil {
		return nil
	}
	if n, ok := v.Value().(uint32); !ok || n < 2 {
		return nil
	}
	dir, _ := stateDir()
	return &portal{logf: logf, state: dir, conn: conn}
}

// stateDir is the user's directory for cbb's own files.
func stateDir() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "cbb"), nil
}

// ready returns once the session's keyboard is there, starting the
// session if none runs. When the start needs the user's answer in the
// portal's dialog, it refuses meanwhile, so the sender knows to paste
// again once they allowed it.
func (p *portal) ready() error {
	p.mu.Lock()
	if p.kbd == nil && !p.declined && p.starting == nil {
		p.starting = make(chan struct{})
		go p.start(p.starting)
	}
	kbd, declined, starting := p.kbd, p.declined, p.starting
	p.mu.Unlock()
	switch {
	case declined:
		return &connector.Refusal{Reason: "the user of this desktop declined remote paste in the dialog; it asks again after they sign in again"}
	case kbd != nil:
		return nil
	}
	select {
	case <-starting:
	case <-time.After(portalAnswer):
		return &connector.Refusal{Reason: "this desktop asks its user once to allow remote paste, in a dialog on the device; paste again after they allow it"}
	}
	p.mu.Lock()
	kbd, declined, err := p.kbd, p.declined, p.err
	p.mu.Unlock()
	switch {
	case declined:
		return &connector.Refusal{Reason: "the user of this desktop declined remote paste in the dialog"}
	case kbd == nil:
		return fmt.Errorf("starting the RemoteDesktop portal: %w", err)
	}
	return nil
}

// press presses the keys on the session's keyboard, which ready made.
func (p *portal) press(keys []ei.Key) error {
	p.mu.Lock()
	kbd := p.kbd
	p.mu.Unlock()
	if kbd == nil {
		return errors.New("the RemoteDesktop session ended")
	}
	if err := kbd.Press(keys); err != nil {
		p.mu.Lock()
		if p.kbd == kbd {
			p.kbd = nil // the next paste starts a new session
		}
		p.mu.Unlock()
		kbd.Close()
		return err
	}
	return nil
}

// start sets up a session and its keyboard, then closes done.
func (p *portal) start(done chan struct{}) {
	kbd, declined, err := p.session()
	p.mu.Lock()
	p.kbd, p.declined, p.err, p.starting = kbd, declined, err, nil
	p.mu.Unlock()
	if err != nil {
		p.logf("cbb: the RemoteDesktop portal: %v", err)
	}
	close(done)
}

var errDeclined = errors.New("the user declined")

// session runs the portal's requests: a session, the keyboard, the start
// (the dialog, unless the restore token stands for the user's yes), and
// the ei connection.
func (p *portal) session() (*ei.Keyboard, bool, error) {
	obj := p.conn.Object(portalBus, portalPath)
	res, err := p.request(obj, "CreateSession", map[string]dbus.Variant{"session_handle_token": dbus.MakeVariant(token())})
	if err != nil {
		return nil, false, err
	}
	handle, _ := res["session_handle"].Value().(string)
	if handle == "" {
		return nil, false, errors.New("CreateSession returned no session")
	}
	session := dbus.ObjectPath(handle)
	opts := map[string]dbus.Variant{"types": dbus.MakeVariant(portalKeyboard), "persist_mode": dbus.MakeVariant(portalPersist)}
	if t := p.restoreToken(); t != "" {
		opts["restore_token"] = dbus.MakeVariant(t)
	}
	if _, err := p.request(obj, "SelectDevices", opts, session); err != nil {
		return nil, false, err
	}
	res, err = p.request(obj, "Start", map[string]dbus.Variant{}, session, "")
	if errors.Is(err, errDeclined) {
		return nil, true, err
	}
	if err != nil {
		return nil, false, err
	}
	if t, ok := res["restore_token"].Value().(string); ok && t != "" {
		p.saveToken(t)
	}
	var fd dbus.UnixFD
	if err := obj.Call(portalRemote+".ConnectToEIS", 0, session, map[string]dbus.Variant{}).Store(&fd); err != nil {
		return nil, false, fmt.Errorf("ConnectToEIS: %w", err)
	}
	kbd, err := ei.Dial(int(fd), "CBB", 5*time.Second)
	return kbd, false, err
}

// request calls a portal method that answers with a Request's Response
// signal, and waits for it; options gets its handle_token.
func (p *portal) request(obj dbus.BusObject, method string, options map[string]dbus.Variant, args ...any) (map[string]dbus.Variant, error) {
	tok := token()
	options["handle_token"] = dbus.MakeVariant(tok)
	sender := strings.ReplaceAll(strings.TrimPrefix(p.conn.Names()[0], ":"), ".", "_")
	path := dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/portal/desktop/request/%s/%s", sender, tok))
	match := []dbus.MatchOption{dbus.WithMatchObjectPath(path), dbus.WithMatchInterface(portalRequest), dbus.WithMatchMember("Response")}
	if err := p.conn.AddMatchSignal(match...); err != nil {
		return nil, err
	}
	defer p.conn.RemoveMatchSignal(match...)
	signals := make(chan *dbus.Signal, 4)
	p.conn.Signal(signals)
	defer p.conn.RemoveSignal(signals)
	call := obj.Call(portalRemote+"."+method, 0, append(args, options)...)
	if call.Err != nil {
		return nil, fmt.Errorf("%s: %w", method, call.Err)
	}
	timeout := time.After(10 * time.Minute) // the user may take a while in the dialog
	for {
		select {
		case s := <-signals:
			if s.Path != path || len(s.Body) < 2 {
				continue
			}
			code, _ := s.Body[0].(uint32)
			results, _ := s.Body[1].(map[string]dbus.Variant)
			switch code {
			case 0:
				return results, nil
			case 1:
				return nil, errDeclined
			default:
				return nil, fmt.Errorf("%s ended with code %d", method, code)
			}
		case <-timeout:
			return nil, fmt.Errorf("%s: no answer", method)
		}
	}
}

var tokens struct {
	sync.Mutex
	n int
}

// token makes a handle token, unique in this process.
func token() string {
	tokens.Lock()
	defer tokens.Unlock()
	tokens.n++
	return fmt.Sprintf("cbb%d_%d", os.Getpid(), tokens.n)
}

func (p *portal) restoreToken() string {
	if p.state == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(p.state, portalTokenFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (p *portal) saveToken(t string) {
	if p.state == "" {
		return
	}
	if err := os.MkdirAll(p.state, 0o700); err == nil {
		err = os.WriteFile(filepath.Join(p.state, portalTokenFile), []byte(t+"\n"), 0o600)
		if err != nil {
			p.logf("cbb: keeping the portal's restore token: %v", err)
		}
	}
}

// close ends the keyboard's connection and the bus connection, which ends
// the session.
func (p *portal) close() {
	p.mu.Lock()
	kbd := p.kbd
	p.kbd = nil
	p.mu.Unlock()
	if kbd != nil {
		kbd.Close()
	}
	p.conn.Close()
}
