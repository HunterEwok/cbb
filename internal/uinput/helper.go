// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package uinput

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/cbb/internal/connector"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/lockcheck"
)

// Socket is where the helper listens. The connection is one line from the
// desktop connector, "paste GRANT" (Shift+Insert) or "enter GRANT", GRANT
// the grant of the service's inject, and one line back: "ok",
// "refused REASON" or "error MESSAGE".
const Socket = "/run/cbb-keys/keys"

// The keys of each request.
var requests = map[string][]Key{
	"paste": {{KeyLeftShift, true}, {KeyInsert, true}, {KeyInsert, false}, {KeyLeftShift, false}},
	"enter": {{KeyEnter, true}, {KeyEnter, false}},
}

// names name the keys of each request in the log.
var names = map[string]string{"paste": "Shift+Insert", "enter": "Enter"}

// Presser presses keys: a Keyboard, or a fake in tests.
type Presser interface {
	Press([]Key) error
}

// Helper serves the desktop connectors' requests.
type Helper struct {
	Keys Presser
	Logf func(string, ...any)
	// Check says why the user uid may not have keys pressed now, or "";
	// nil checks logind's active session (Allowed).
	Check func(uid uint32) string
	// Grant says why the service did not ask for the keys of req for the
	// user uid under grant, or ""; nil asks the service (AskService). The
	// keys go only to a remote paste the service took and handed to a
	// desktop session of that user, as its switches allow.
	Grant func(uid uint32, req, grant string) string

	mu sync.Mutex // one paste at a time
}

// Serve answers on ln until ctx ends.
func (h *Helper) Serve(ctx context.Context, ln *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go h.serve(c)
	}
}

func (h *Helper) serve(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	req, grant, _ := strings.Cut(strings.TrimSpace(line), " ")
	answer := func(s string) { fmt.Fprintln(c, s) }
	keys, ok := requests[req]
	if !ok {
		answer("error the keys helper presses paste or enter, not " + strconv.Quote(req))
		return
	}
	if grant == "" {
		answer("refused the keys helper presses keys only for a remote paste; the desktop connector is older than the helper, so log out and in again after an update")
		return
	}
	uid, err := peerUID(c)
	if err != nil {
		answer("error " + err.Error())
		return
	}
	check, granted := h.Check, h.Grant
	if check == nil {
		check = Allowed
	}
	if granted == nil {
		granted = AskService
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if why := granted(uid, req, grant); why != "" {
		h.Logf("cbb: refused %s for user %d: %s", names[req], uid, why)
		answer("refused " + why)
		return
	}
	if why := check(uid); why != "" {
		h.Logf("cbb: refused %s for user %d: %s", names[req], uid, why)
		answer("refused " + why)
		return
	}
	if err := h.Keys.Press(keys); err != nil {
		h.Logf("cbb: pressing %s: %v", names[req], err)
		answer("error " + err.Error())
		return
	}
	h.Logf("cbb: pressed %s for user %d", names[req], uid)
	answer("ok")
}

func peerUID(c *net.UnixConn) (uint32, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, fmt.Errorf("reading the caller: %w", cerr)
	}
	return cred.Uid, nil
}

// Allowed says why the keys may not go to the user uid now, or "": they go
// only to the user of the graphical session active on the computer's own
// screen (seat0), never to a login screen, and not while it is locked.
func Allowed(uid uint32) string {
	id := lockcheck.ActiveSession("seat0")
	if id == "" {
		return "no session is active on this computer's screen"
	}
	p := lockcheck.Show(id, "User", "Type", "Class", "LockedHint")
	switch {
	case !strings.HasPrefix(p["Class"], "user"): // user, or systemd's user-early and user-light; not greeter or lock-screen
		return "the login screen is showing"
	case p["User"] != strconv.FormatUint(uint64(uid), 10):
		return "the keys go only to the user of the session on the screen"
	case p["Type"] != "x11" && p["Type"] != "wayland":
		return "the session on the screen is not graphical"
	case p["LockedHint"] == "yes":
		return "the session is locked"
	}
	if name := lockcheck.Locker(true); name != "" {
		return "the screen is locked (" + name + " runs)"
	}
	return ""
}

// AskService asks the service, on its control socket, whether it handed a
// remote paste to a desktop session of the user uid under grant whose keys
// req may be pressed now (control.OpKeys); it says why not, or "".
func AskService(uid uint32, req, grant string) string {
	c, err := control.DialFor(control.OpKeys)
	if err != nil {
		return "the keys helper cannot reach the service: " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Do(&control.Message{Header: control.Header{Op: control.OpKeys, Name: req, Value: strconv.FormatUint(uint64(uid), 10), Keys: grant}})
	if err != nil {
		return err.Error()
	}
	return ""
}

// Ask asks the helper at socket to press the keys of req, "paste" or
// "enter", for the inject whose grant is grant. A refusal comes back as a
// connector.Refusal.
func Ask(ctx context.Context, socket, req, grant string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("the keys helper: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, req, grant); err != nil {
		return fmt.Errorf("the keys helper: %w", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return fmt.Errorf("the keys helper did not answer: %w", err)
	}
	kind, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
	switch kind {
	case "ok":
		return nil
	case "refused":
		return &connector.Refusal{Reason: rest}
	case "error":
		return errors.New("the keys helper: " + rest)
	}
	return fmt.Errorf("the keys helper answered %q", line)
}
