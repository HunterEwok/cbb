// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// The control socket's cases (U11): forge [-socket PATH] control:CASE...
// sends the service what no cbb sends and prints one line per case, "CASE:
// closed", "CASE: answered: ERROR" or "CASE: answered", and last whether
// the service still answers a status request.

// controlCase tells whether the argument names a control socket case.
func controlCase(arg string) bool { return strings.HasPrefix(arg, "control:") }

func runControl(path string, cases []string) error {
	if path == "" {
		path = control.SocketPath()
	}
	for _, c := range cases {
		name, ok := strings.CutPrefix(c, "control:")
		if !ok {
			return fmt.Errorf("%s is no control socket case", c)
		}
		var send []byte
		hold := 0
		switch {
		case name == "junk":
			send = []byte("this is no header\n")
		case name == "long":
			// A header over 64 KiB with no end of line.
			send = []byte(`{"op":"status","name":"` + strings.Repeat("x", 70<<10))
		case name == "big":
			send = []byte(`{"op":"copy","len":2097152}` + "\n")
		case name == "negative":
			send = []byte(`{"op":"copy","len":-1}` + "\n")
		case name == "unknown":
			send = []byte(`{"op":"frobnicate"}` + "\n")
		case name == "admin":
			// An operation that changes the group, on the socket for
			// everyone.
			send = []byte(`{"op":"revoke","name":"nobody"}` + "\n")
		case name == "short":
			// A payload shorter than its header says, then the end.
			send = []byte(`{"op":"copy","len":100}` + "\n" + "only ten b")
		case strings.HasPrefix(name, "idle-"):
			n, err := strconv.Atoi(strings.TrimPrefix(name, "idle-"))
			if err != nil {
				return err
			}
			hold = n
		default:
			return fmt.Errorf("unknown control socket case %s", name)
		}
		if hold > 0 {
			// Connections of one user that send nothing, all open at once:
			// the service keeps a user's first 64 and closes the rest, a
			// status request of the same user waits for a free place, and
			// answers once the idle ones are gone.
			var conns []net.Conn
			for range hold {
				c, err := net.Dial("unix", path)
				if err != nil {
					break
				}
				conns = append(conns, c)
			}
			time.Sleep(time.Second)
			closed := 0
			one := make([]byte, 1)
			for _, c := range conns {
				c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if _, err := c.Read(one); !isTimeout(err) {
					closed++
				}
			}
			held := "answered while open"
			if err := status(path); err != nil {
				held = "refused while open"
			}
			for _, c := range conns {
				c.Close()
			}
			time.Sleep(500 * time.Millisecond)
			after := "answered after"
			if err := status(path); err != nil {
				after = "after: " + err.Error()
			}
			fmt.Printf("%s: %d open, %d closed, status %s, %s\n", name, len(conns), closed, held, after)
			continue
		}
		fmt.Printf("%s: %s\n", name, exchange(path, send))
	}
	if err := status(path); err != nil {
		fmt.Printf("status: %v\n", err)
	} else {
		fmt.Println("status: answered")
	}
	return nil
}

// exchange sends b, closes the writing side and reads one answer.
func exchange(path string, b []byte) string {
	c, err := net.Dial("unix", path)
	if err != nil {
		return "no connection: " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(b); err != nil {
		return "closed"
	}
	c.(*net.UnixConn).CloseWrite()
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		if errors.Is(err, net.ErrClosed) || len(line) == 0 {
			return "closed"
		}
		return "broken: " + err.Error()
	}
	var h control.Header
	if err := json.Unmarshal(line, &h); err != nil {
		return "answered junk: " + string(line)
	}
	if h.Error != "" {
		return "answered: " + h.Error
	}
	return "answered"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// status asks the service for its status, as cbb status does.
func status(path string) error {
	c, err := control.Dial(path)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpStatus}})
	if err == nil && m.Status == nil {
		err = errors.New("no status in the answer")
	}
	return err
}
