// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"fmt"
	"net"
	"syscall"
)

// A peer is the user at the other end of a control connection, as the
// system tells it. A watcher that offers a paste target or runs the quick
// actions gets them only when its user may take them (mayTake): the control
// socket's group is for the clipboard, while a remote paste goes to the
// screen or the console of one user (docs/protocol.md, section 8).
type peer struct {
	known   bool
	uid     uint32 // on Unix
	sid     string // on Windows, the user's SID
	session uint32 // on Windows, the session of its process
	// why says, for a peer not known, what the system did not tell.
	why string
}

// String names the user for the log.
func (p peer) String() string {
	switch {
	case !p.known && p.why != "":
		return "a user the system does not name (" + p.why + ")"
	case !p.known:
		return "a user the system does not name"
	case p.sid != "":
		return fmt.Sprintf("%s in session %d", p.sid, p.session)
	}
	return fmt.Sprintf("uid %d", p.uid)
}

// A verdict says whether a watcher's user may take what goes to a target.
type verdict int

const (
	refused   verdict = iota
	unchecked         // the system does not tell who is at the screen
	allowed
)

// targetAct stands for the quick actions in mayTake.
const targetAct = "act"

// mayTake says whether p may take the remote pastes of target (desktop,
// tmux or console), or the actions with targetAct: root and the service's
// own account take every one; the console only them; the others the user at
// the screen, as atScreen tells.
func (s *Service) mayTake(p peer, target string) verdict {
	switch {
	case !p.known:
		return refused
	case p.privileged():
		return allowed
	case target == targetConsole:
		return refused
	}
	return s.cfg.atScreen(p, target)
}

// rawConn returns the connection's file descriptor, for its peer's
// credentials.
func rawConn(c net.Conn) (syscall.RawConn, bool) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, false
	}
	raw, err := sc.SyscallConn()
	return raw, err == nil
}
