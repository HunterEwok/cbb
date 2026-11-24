// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux || freebsd

// Package wl is a minimal Wayland client: the wire protocol, the core
// objects it needs (display, registry, callback, seat) and nothing that
// draws. The desktop connector uses it for the data-control protocols.
//
// A Wayland message is a 32-bit object ID, a 32-bit word with the size in
// its upper and the opcode in its lower half, and the arguments, each
// padded to 4 bytes; file descriptors travel beside the bytes as SCM_RIGHTS.
// Integers are in the host's byte order.
package wl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// Display is a connection to a Wayland compositor.
type Display struct {
	conn *net.UnixConn

	wmu sync.Mutex // writes

	mu       sync.Mutex
	nextID   uint32
	handlers map[uint32]Handler
	fds      []int // descriptors received and not yet taken by an event
	rbuf     []byte
}

// Handler receives the events of one object.
type Handler func(opcode uint16, args *Args) error

// Error is a protocol error the compositor reported.
type Error struct {
	Object  uint32
	Code    uint32
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("wayland: protocol error %d on object %d: %s", e.Code, e.Object, e.Message)
}

// The display is object 1.
const displayID = 1

// Connect connects to the compositor named by $WAYLAND_DISPLAY in
// $XDG_RUNTIME_DIR, as every Wayland client does.
func Connect() (*Display, error) {
	name := os.Getenv("WAYLAND_DISPLAY")
	if name == "" {
		name = "wayland-0"
	}
	path := name
	if !filepath.IsAbs(name) {
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			return nil, errors.New("wayland: XDG_RUNTIME_DIR is not set")
		}
		path = filepath.Join(dir, name)
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("wayland: %w", err)
	}
	d := &Display{conn: c, nextID: displayID + 1, handlers: map[uint32]Handler{}}
	d.handlers[displayID] = d.displayEvent
	return d, nil
}

// Close closes the connection and any descriptors not taken.
func (d *Display) Close() error {
	d.mu.Lock()
	for _, fd := range d.fds {
		unix.Close(fd)
	}
	d.fds = nil
	d.mu.Unlock()
	return d.conn.Close()
}

// NewID allocates an object ID for a new object and registers its handler.
func (d *Display) NewID(h Handler) uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.nextID
	d.nextID++
	if h != nil {
		d.handlers[id] = h
	}
	return id
}

// SetHandler sets the handler of an object the compositor created, such as
// a data offer.
func (d *Display) SetHandler(id uint32, h Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[id] = h
}

// Forget removes an object's handler, after it was destroyed.
func (d *Display) Forget(id uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.handlers, id)
}

func (d *Display) displayEvent(op uint16, a *Args) error {
	switch op {
	case 0: // error
		obj, code, msg := a.Uint(), a.Uint(), a.String()
		if a.Err != nil {
			return a.Err
		}
		return &Error{Object: obj, Code: code, Message: msg}
	case 1: // delete_id
		id := a.Uint()
		d.Forget(id)
	}
	return a.Err
}

// Request builds and sends a request.
type Request struct {
	buf []byte
	fds []int
}

// Uint appends an unsigned integer, an object or a new ID.
func (r *Request) Uint(v uint32) *Request {
	r.buf = binary.NativeEndian.AppendUint32(r.buf, v)
	return r
}

// String appends a string.
func (r *Request) String(s string) *Request {
	r.buf = binary.NativeEndian.AppendUint32(r.buf, uint32(len(s)+1))
	r.buf = append(r.buf, s...)
	r.buf = append(r.buf, 0)
	for len(r.buf)%4 != 0 {
		r.buf = append(r.buf, 0)
	}
	return r
}

// FD attaches a file descriptor.
func (r *Request) FD(fd int) *Request {
	r.fds = append(r.fds, fd)
	return r
}

// Send sends a request with the given opcode to object id.
func (d *Display) Send(id uint32, opcode uint16, r *Request) error {
	if r == nil {
		r = &Request{}
	}
	size := 8 + len(r.buf)
	if size > 4096 {
		return errors.New("wayland: request too large")
	}
	msg := make([]byte, 0, size)
	msg = binary.NativeEndian.AppendUint32(msg, id)
	msg = binary.NativeEndian.AppendUint32(msg, uint32(size)<<16|uint32(opcode))
	msg = append(msg, r.buf...)
	var oob []byte
	if len(r.fds) > 0 {
		oob = unix.UnixRights(r.fds...)
	}
	d.wmu.Lock()
	defer d.wmu.Unlock()
	_, _, err := d.conn.WriteMsgUnix(msg, oob, nil)
	return err
}

// Args reads the arguments of an event. The first error sticks in Err and
// makes every later read return zero values.
type Args struct {
	d   *Display
	b   []byte
	Err error
}

func (a *Args) take(n int) []byte {
	if a.Err != nil {
		return nil
	}
	if len(a.b) < n {
		a.Err = errors.New("wayland: event too short")
		return nil
	}
	v := a.b[:n]
	a.b = a.b[n:]
	return v
}

// Uint reads an unsigned integer, an object or a new ID.
func (a *Args) Uint() uint32 {
	b := a.take(4)
	if b == nil {
		return 0
	}
	return binary.NativeEndian.Uint32(b)
}

// String reads a string.
func (a *Args) String() string {
	n := int(a.Uint())
	if n == 0 {
		return ""
	}
	padded := (n + 3) &^ 3
	b := a.take(padded)
	if b == nil {
		return ""
	}
	if b[n-1] != 0 {
		a.Err = errors.New("wayland: string without its terminating zero")
		return ""
	}
	return string(b[:n-1])
}

// FD takes the next file descriptor that arrived; the caller closes it.
func (a *Args) FD() int {
	if a.Err != nil {
		return -1
	}
	a.d.mu.Lock()
	defer a.d.mu.Unlock()
	if len(a.d.fds) == 0 {
		a.Err = errors.New("wayland: an event expects a file descriptor that did not arrive")
		return -1
	}
	fd := a.d.fds[0]
	a.d.fds = a.d.fds[1:]
	return fd
}

// Dispatch reads and handles events until at least one was handled.
func (d *Display) Dispatch() error {
	buf := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(28*4))
	for {
		if handled, err := d.handleBuffered(); handled || err != nil {
			return err
		}
		n, oobn, _, _, err := d.conn.ReadMsgUnix(buf, oob)
		if err != nil {
			return err
		}
		if oobn > 0 {
			msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				return err
			}
			for _, m := range msgs {
				fds, err := unix.ParseUnixRights(&m)
				if err != nil {
					continue
				}
				d.mu.Lock()
				d.fds = append(d.fds, fds...)
				d.mu.Unlock()
			}
		}
		if n == 0 {
			return errors.New("wayland: the compositor closed the connection")
		}
		d.rbuf = append(d.rbuf, buf[:n]...)
	}
}

// handleBuffered handles the complete events in the read buffer.
func (d *Display) handleBuffered() (bool, error) {
	handled := false
	for len(d.rbuf) >= 8 {
		id := binary.NativeEndian.Uint32(d.rbuf)
		word := binary.NativeEndian.Uint32(d.rbuf[4:])
		size, op := int(word>>16), uint16(word)
		if size < 8 {
			return handled, errors.New("wayland: bad event size")
		}
		if len(d.rbuf) < size {
			break
		}
		body := d.rbuf[8:size]
		d.mu.Lock()
		h := d.handlers[id]
		d.mu.Unlock()
		var err error
		if h != nil {
			err = h(op, &Args{d: d, b: body})
		}
		d.rbuf = d.rbuf[size:]
		handled = true
		if err != nil {
			return handled, err
		}
	}
	if len(d.rbuf) == 0 {
		d.rbuf = nil
	}
	return handled, nil
}

// Roundtrip sends a sync request and handles events until it is done, so
// that every event of the requests before it has arrived.
func (d *Display) Roundtrip() error {
	done := false
	id := d.NewID(func(op uint16, a *Args) error {
		done = true
		return a.Err
	})
	defer d.Forget(id)
	if err := d.Send(displayID, 0, (&Request{}).Uint(id)); err != nil {
		return err
	}
	for !done {
		if err := d.Dispatch(); err != nil {
			return err
		}
	}
	return nil
}

// Synced sends a sync request and returns a channel closed when it is
// done, while another goroutine dispatches the events: by then the
// compositor has handled every request before it, and the handlers have
// run for every event it sent before.
func (d *Display) Synced() (<-chan struct{}, error) {
	done := make(chan struct{})
	var id uint32
	id = d.NewID(func(op uint16, a *Args) error {
		d.Forget(id)
		close(done)
		return a.Err
	})
	if err := d.Send(displayID, 0, (&Request{}).Uint(id)); err != nil {
		d.Forget(id)
		return nil, err
	}
	return done, nil
}

// Global is an object the compositor announces in the registry.
type Global struct {
	Name      uint32
	Interface string
	Version   uint32
}

// Registry is the compositor's list of globals.
type Registry struct {
	d       *Display
	id      uint32
	Globals []Global
}

// GetRegistry asks for the registry and waits until it has every global.
func (d *Display) GetRegistry() (*Registry, error) {
	r := &Registry{d: d}
	r.id = d.NewID(func(op uint16, a *Args) error {
		switch op {
		case 0: // global
			g := Global{Name: a.Uint(), Interface: a.String(), Version: a.Uint()}
			if a.Err == nil {
				r.Globals = append(r.Globals, g)
			}
		case 1: // global_remove
			name := a.Uint()
			for i, g := range r.Globals {
				if g.Name == name {
					r.Globals = append(r.Globals[:i], r.Globals[i+1:]...)
					break
				}
			}
		}
		return a.Err
	})
	if err := d.Send(displayID, 1, (&Request{}).Uint(r.id)); err != nil {
		return nil, err
	}
	if err := d.Roundtrip(); err != nil {
		return nil, err
	}
	return r, nil
}

// Find returns the first global with the interface, and false if none.
func (r *Registry) Find(iface string) (Global, bool) {
	for _, g := range r.Globals {
		if g.Interface == iface {
			return g, true
		}
	}
	return Global{}, false
}

// Bind binds a global at a version no higher than max and returns the new
// object's ID, which events reach through h.
func (r *Registry) Bind(g Global, max uint32, h Handler) uint32 {
	v := min(g.Version, max)
	id := r.d.NewID(h)
	r.d.Send(r.id, 0, (&Request{}).Uint(g.Name).String(g.Interface).Uint(v).Uint(id))
	return id
}
