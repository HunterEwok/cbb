// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package control

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SocketPath returns the control socket to use: $CBB_SOCKET, or
// DefaultSocket.
func SocketPath() string {
	if p := os.Getenv("CBB_SOCKET"); p != "" {
		return p
	}
	return DefaultSocket
}

// AdminSocketPath returns the admin socket to use: $CBB_ADMIN_SOCKET, or
// the admin socket next to SocketPath.
func AdminSocketPath() string {
	if p := os.Getenv("CBB_ADMIN_SOCKET"); p != "" {
		return p
	}
	return AdminSocketFor(SocketPath())
}

// AdminSocketFor returns where the service whose control socket is at path
// listens for the operations that change the group (IsAdmin).
func AdminSocketFor(path string) string {
	return filepath.Join(filepath.Dir(path), adminSocketName)
}

// IsAdmin reports whether an operation changes the group or this device's
// place in it, so that only the administrator of the computer may ask for
// it: on the admin socket, which only root (Administrators on Windows) and
// the service's own account may reach. The clipboard and the status stay on
// the control socket for the members of the service's group.
func IsAdmin(op string) bool {
	switch op {
	case OpCopy, OpPaste, OpCopyMedia, OpPasteMedia, OpCopiedMedia, OpPart, OpData, OpConfig, OpStatus, OpDevices, OpWatch, OpCopied, OpClipboard, OpAnswer, OpReply, OpWrite, OpInject, OpInjected, OpAct, OpActed, OpRelease, OpReleaseGet, OpReleaseHeld, OpEntries, OpEntriesGet, OpKeys:
		return false
	}
	return true
}

// NeedsAdmin reports whether the service takes the request h only on its
// admin socket: IsAdmin of its operation, except turning this device's own
// sync on or off, which changes nothing for the group (design.md, "Sync on
// or off").
func NeedsAdmin(h Header) bool {
	if h.Op == OpSync && h.Device == "" {
		return false
	}
	return IsAdmin(h.Op)
}

// DialFor connects to the socket that takes the operation op: the admin
// socket for an operation that changes the group, the control socket for
// the others.
func DialFor(op string) (*Client, error) {
	if IsAdmin(op) {
		return dialAdmin(AdminSocketPath())
	}
	return Dial(SocketPath())
}

// DialAt is DialFor for the service whose control socket is at path.
func DialAt(path, op string) (*Client, error) {
	if IsAdmin(op) {
		return dialAdmin(AdminSocketFor(path))
	}
	return Dial(path)
}

func dialAdmin(path string) (*Client, error) {
	return dial(path, "this command changes the group, so only the administrator may run it; "+adminHint)
}

// A Client is a connection to the service.
type Client struct {
	c net.Conn
	r *Reader
}

// Dial connects to the service.
func Dial(path string) (*Client, error) {
	return dial(path, "no permission to use the CBB service; "+permissionHint)
}

func dial(path, denied string) (*Client, error) {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, &DialError{Msg: denied, Denied: true, Err: err}
		}
		return nil, &DialError{Msg: "the CBB service is not running; " + startHint, Err: err}
	}
	SetBuffers(c)
	return &Client{c: c, r: NewReader(c)}, nil
}

// socketBuffer is the size of a control connection's socket buffers.
const socketBuffer = 1 << 20

// SetBuffers gives a control connection socket buffers of 1 MiB each way.
// A Unix socket's are 8 KiB on macOS, so a copy of files there woke the
// sender and the service a hundred times or more for each MiB. The system
// may give less, and an error leaves the defaults.
func SetBuffers(c net.Conn) {
	if u, ok := c.(*net.UnixConn); ok {
		u.SetReadBuffer(socketBuffer)
		u.SetWriteBuffer(socketBuffer)
	}
}

// A DialError is a connection to the service that failed: Denied when the
// socket's permissions keep this user out, else the service is not
// running. Msg is for the user, and Err is the error underneath, which
// cbb shows only in debug mode (CBB_DEBUG).
type DialError struct {
	Msg    string
	Denied bool
	Err    error
}

func (e *DialError) Error() string { return e.Msg }

func (e *DialError) Unwrap() error { return e.Err }

// Close closes the connection.
func (c *Client) Close() error { return c.c.Close() }

// SetDeadline sets the deadline for sending and receiving.
func (c *Client) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }

// Send sends a message.
func (c *Client) Send(m *Message) error { return Write(c.c, m) }

// Receive reads the next message. An answer with an error becomes the
// error.
func (c *Client) Receive() (*Message, error) {
	m, err := c.r.Read()
	if err != nil {
		return nil, err
	}
	if m.Error != "" {
		return m, &RequestError{Msg: m.Error, Detail: m.Detail}
	}
	return m, nil
}

// A RequestError is a request the service refused or could not do: Msg for
// the user, and Detail, when there is one, for debugging.
type RequestError struct {
	Msg, Detail string
}

func (e *RequestError) Error() string { return e.Msg }

// Do sends a request and returns its single answer.
func (c *Client) Do(m *Message) (*Message, error) {
	if err := c.Send(m); err != nil {
		return nil, err
	}
	return c.Receive()
}
