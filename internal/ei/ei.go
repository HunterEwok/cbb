// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

// Package ei is a client of the ei protocol (libei's wire protocol,
// https://gitlab.freedesktop.org/libinput/libei, proto/protocol.xml) that
// only sends keys: the RemoteDesktop portal of GNOME and KDE hands out a
// connection to its EIS server, and remote paste presses Shift+Insert and
// Enter through it (design.md, "Remote paste").
//
// The wire format is Wayland's with 64-bit object IDs: a header of the
// object ID, the message length and the opcode, then arguments padded to 4
// bytes, in the machine's byte order.
package ei

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The interfaces and versions this client speaks.
var interfaces = []struct {
	name    string
	version uint32
}{{"ei_connection", 1}, {"ei_callback", 1}, {"ei_pingpong", 1}, {"ei_seat", 1}, {"ei_device", 1}, {"ei_keyboard", 1}}

// Opcodes from protocol.xml.
const (
	hsReqHandshakeVersion = 0
	hsReqFinish           = 1
	hsReqContextType      = 2
	hsReqName             = 3
	hsReqInterfaceVersion = 4
	hsEvHandshakeVersion  = 0
	hsEvConnection        = 2

	connEvDisconnected = 0
	connEvSeat         = 1
	connEvPing         = 3
	pingReqDone        = 0

	seatReqBind      = 1
	seatEvCapability = 2
	seatEvDone       = 3
	seatEvDevice     = 4

	devReqStartEmulating = 1
	devReqStopEmulating  = 2
	devReqFrame          = 3
	devEvInterface       = 5
	devEvResumed         = 7
	devEvPaused          = 8

	kbdReqKey = 1

	contextSender = 2
)

// Evdev key codes (linux/input-event-codes.h), the same on every layout.
const (
	KeyEnter     = 28
	KeyLeftShift = 42
	KeyInsert    = 110
)

// A Key is a key event: a press or a release of an evdev code.
type Key struct {
	Code  uint32
	Press bool
}

// Keyboard is a keyboard device of an EIS server.
type Keyboard struct {
	c *net.UnixConn

	wmu sync.Mutex // one message at a time

	mu       sync.Mutex
	cond     *sync.Cond
	ended    bool  // the connection ended
	err      error // the connection ended
	serial   uint32
	seats    map[uint64]uint64 // seat ID to its keyboard capability mask
	devices  map[uint64]*device
	keyboard *device // the device with a keyboard that is resumed, or nil
	sequence uint32
}

type device struct {
	id       uint64
	keyboard uint64 // its ei_keyboard object, 0 if none
	resumed  bool
}

// Dial connects to the EIS server on the socket fd, which it takes over,
// and waits until the server gives it a keyboard, at most wait.
func Dial(fd int, name string, wait time.Duration) (*Keyboard, error) {
	f := fdFile(fd)
	fc, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("ei: %w", err)
	}
	c, ok := fc.(*net.UnixConn)
	if !ok {
		fc.Close()
		return nil, errors.New("ei: the portal's descriptor is not a Unix socket")
	}
	k := &Keyboard{c: c, seats: map[uint64]uint64{}, devices: map[uint64]*device{}}
	k.cond = sync.NewCond(&k.mu)
	go k.read(name)
	deadline := time.AfterFunc(wait, func() {
		k.mu.Lock()
		k.cond.Broadcast()
		k.mu.Unlock()
	})
	defer deadline.Stop()
	start := time.Now()
	k.mu.Lock()
	defer k.mu.Unlock()
	for k.keyboard == nil && k.err == nil && time.Since(start) < wait {
		k.cond.Wait()
	}
	switch {
	case k.err != nil:
		c.Close()
		return nil, k.err
	case k.keyboard == nil:
		c.Close()
		return nil, errors.New("ei: the server gave no keyboard")
	}
	return k, nil
}

func fdFile(fd int) *os.File { return os.NewFile(uintptr(fd), "eis") }

// Close ends the connection.
func (k *Keyboard) Close() error { return k.c.Close() }

// Press sends the keys in order, each in a frame of its own, and returns
// once they are written.
func (k *Keyboard) Press(keys []Key) error {
	k.mu.Lock()
	dev, err, serial := k.keyboard, k.err, k.serial
	k.sequence++
	seq := k.sequence
	k.mu.Unlock()
	if err != nil {
		return err
	}
	if dev == nil {
		return errors.New("ei: the keyboard is paused")
	}
	if err := k.send(dev.id, devReqStartEmulating, u32(serial), u32(seq)); err != nil {
		return err
	}
	for _, key := range keys {
		state := uint32(0)
		if key.Press {
			state = 1
		}
		if err := k.send(dev.keyboard, kbdReqKey, u32(key.Code), u32(state)); err != nil {
			return err
		}
		if err := k.send(dev.id, devReqFrame, u32(serial), u64(now())); err != nil {
			return err
		}
	}
	return k.send(dev.id, devReqStopEmulating, u32(serial))
}

func now() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e6 + uint64(ts.Nsec)/1e3
}

// The argument encoders.
func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.NativeEndian.AppendUint64(nil, v) }
func str(s string) []byte {
	b := u32(uint32(len(s) + 1))
	b = append(b, s...)
	b = append(b, 0)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func (k *Keyboard) send(id uint64, op uint32, args ...[]byte) error {
	msg := binary.NativeEndian.AppendUint64(nil, id)
	n := 16
	for _, a := range args {
		n += len(a)
	}
	msg = binary.NativeEndian.AppendUint32(msg, uint32(n))
	msg = binary.NativeEndian.AppendUint32(msg, op)
	for _, a := range args {
		msg = append(msg, a...)
	}
	k.wmu.Lock()
	defer k.wmu.Unlock()
	_, err := k.c.Write(msg)
	return err
}

// args reads the arguments of one event.
type args struct {
	b   []byte
	err error
}

func (a *args) take(n int) []byte {
	if a.err != nil || len(a.b) < n {
		a.err = errors.New("ei: an event is shorter than its arguments")
		return make([]byte, n)
	}
	v := a.b[:n]
	a.b = a.b[n:]
	return v
}
func (a *args) u32() uint32 { return binary.NativeEndian.Uint32(a.take(4)) }
func (a *args) u64() uint64 { return binary.NativeEndian.Uint64(a.take(8)) }
func (a *args) str() string {
	n := int(a.u32())
	if n == 0 {
		return ""
	}
	b := a.take((n + 3) &^ 3)
	return string(b[:n-1])
}

// read handles the server's events until the connection ends.
func (k *Keyboard) read(name string) {
	err := k.loop(name)
	k.mu.Lock()
	if k.err == nil {
		k.err = err
	}
	k.keyboard = nil
	k.ended = true
	k.cond.Broadcast()
	k.mu.Unlock()
}

// Wait returns once the connection has ended, by the server or a failure.
func (k *Keyboard) Wait() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for !k.ended {
		k.cond.Wait()
	}
}

func (k *Keyboard) loop(name string) error {
	var conn uint64
	kinds := map[uint64]string{0: "ei_handshake"}
	buf := make([]byte, 0, 4096)
	oob := make([]byte, unix.CmsgSpace(4*4))
	tmp := make([]byte, 4096)
	for {
		for len(buf) >= 16 {
			id := binary.NativeEndian.Uint64(buf)
			size := int(binary.NativeEndian.Uint32(buf[8:]))
			op := binary.NativeEndian.Uint32(buf[12:])
			if size < 16 {
				return errors.New("ei: bad message length")
			}
			if len(buf) < size {
				break
			}
			a := &args{b: buf[16:size]}
			if err := k.event(kinds, &conn, id, op, a, name); err != nil {
				return err
			}
			if a.err != nil {
				return a.err
			}
			buf = buf[size:]
		}
		n, oobn, _, _, err := k.c.ReadMsgUnix(tmp, oob)
		if err != nil {
			return fmt.Errorf("ei: the connection ended: %w", err)
		}
		if oobn > 0 { // keymaps and the like, which this client does not use
			if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
				for _, m := range msgs {
					fds, _ := unix.ParseUnixRights(&m)
					for _, fd := range fds {
						unix.Close(fd)
					}
				}
			}
		}
		if n == 0 {
			return errors.New("ei: the server closed the connection")
		}
		buf = append(buf, tmp[:n]...)
	}
}

func (k *Keyboard) event(kinds map[uint64]string, conn *uint64, id uint64, op uint32, a *args, name string) error {
	switch kinds[id] {
	case "ei_handshake":
		switch op {
		case hsEvHandshakeVersion:
			a.u32()
			if err := k.send(0, hsReqHandshakeVersion, u32(1)); err != nil {
				return err
			}
			if err := k.send(0, hsReqContextType, u32(contextSender)); err != nil {
				return err
			}
			if err := k.send(0, hsReqName, str(name)); err != nil {
				return err
			}
			for _, i := range interfaces {
				if err := k.send(0, hsReqInterfaceVersion, str(i.name), u32(i.version)); err != nil {
					return err
				}
			}
			return k.send(0, hsReqFinish)
		case hsEvConnection:
			k.setSerial(a.u32())
			*conn = a.u64()
			kinds[*conn] = "ei_connection"
		}
	case "ei_connection":
		switch op {
		case connEvDisconnected:
			k.setSerial(a.u32())
			reason := a.u32()
			why := a.str()
			return fmt.Errorf("ei: the server disconnected (reason %d): %s", reason, why)
		case connEvSeat:
			seat := a.u64()
			kinds[seat] = "ei_seat"
		case connEvPing:
			ping := a.u64()
			a.u32()
			return k.send(ping, pingReqDone, u64(0))
		}
	case "ei_seat":
		switch op {
		case seatEvCapability:
			mask := a.u64()
			if a.str() == "ei_keyboard" {
				k.mu.Lock()
				k.seats[id] = mask
				k.mu.Unlock()
			}
		case seatEvDone:
			k.mu.Lock()
			mask, ok := k.seats[id]
			k.mu.Unlock()
			if ok {
				return k.send(id, seatReqBind, u64(mask))
			}
		case seatEvDevice:
			dev := a.u64()
			kinds[dev] = "ei_device"
			k.mu.Lock()
			k.devices[dev] = &device{id: dev}
			k.mu.Unlock()
		}
	case "ei_device":
		k.mu.Lock()
		defer k.mu.Unlock()
		d := k.devices[id]
		switch op {
		case devEvInterface:
			obj := a.u64()
			iface := a.str()
			a.u32()
			kinds[obj] = iface
			if iface == "ei_keyboard" && d != nil {
				d.keyboard = obj
			}
		case devEvResumed:
			k.serial = a.u32()
			if d != nil {
				d.resumed = true
				if d.keyboard != 0 && k.keyboard == nil {
					k.keyboard = d
					k.cond.Broadcast()
				}
			}
		case devEvPaused:
			k.serial = a.u32()
			if d != nil {
				d.resumed = false
				if k.keyboard == d {
					k.keyboard = nil
				}
			}
		}
	}
	return nil
}

func (k *Keyboard) setSerial(s uint32) {
	k.mu.Lock()
	k.serial = s
	k.mu.Unlock()
}
