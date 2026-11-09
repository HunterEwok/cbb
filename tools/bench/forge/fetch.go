// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
)

// The fetch limits (O15, docs/protocol.md section 4, "Content"): forge
// fetch:SHA256 connects as a member over member TLS, asks the target for
// the part SHA256 (which it must hold, of at least 1 MiB and a byte) and
// prints one line per case:
//
//	window: N chunks, B bytes, padded
//	over: no answer
//	after-over: answered
//	flood: closed after N gets
//
// window asks for 1 MiB and checks that every chunk's frame is a multiple
// of 16 KiB; over asks for a byte more than 1 MiB, which the target drops;
// flood sends 80 gets at once, and the target closes the connection after
// 64 waiting.

const (
	fetchWindow = 1 << 20
	fetchPad    = 16 << 10
	fetchGets   = 80
)

func fetchCase(arg string) bool { return strings.HasPrefix(arg, "fetch:") }

// fetchConn is a member TLS connection that speaks the member protocol's
// frames.
type fetchConn struct{ c *tls.Conn }

func (f fetchConn) write(m map[string]any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = f.c.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...))
	return err
}

// read returns the next frame: binary with its padded length, or JSON's
// type.
func (f fetchConn) read(d time.Duration) (typ string, body []byte, err error) {
	f.c.SetReadDeadline(time.Now().Add(d))
	var h [4]byte
	if _, err := io.ReadFull(f.c, h[:]); err != nil {
		return "", nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	bin := n&(1<<31) != 0
	n &^= 1 << 31
	if n > 8<<20 {
		return "", nil, fmt.Errorf("a frame of %d bytes", n)
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(f.c, body); err != nil {
		return "", nil, err
	}
	if bin {
		return "chunk", body, nil
	}
	var m struct {
		T string `json:"t"`
	}
	json.Unmarshal(body, &m)
	return m.T, body, nil
}

func runFetch(state string, to group.DeviceID, addr, arg string) error {
	sum, err := hex.DecodeString(strings.TrimPrefix(arg, "fetch:"))
	if err != nil || len(sum) != 32 {
		return fmt.Errorf("fetch:SHA256 in hex, not %q", arg)
	}
	id, err := group.Load(state)
	if err != nil {
		return err
	}
	f, err := dialHello(id, to, addr, "linux")
	if err != nil {
		return err
	}
	defer f.c.Close()
	get := func(length int64) error {
		return f.write(map[string]any{"t": "get", "get": map[string]any{"sha256": sum, "offset": 0, "length": length}})
	}
	// chunks reads chunks until want bytes came or nothing comes for wait.
	chunks := func(want int, wait time.Duration) (n, got int, unpadded int, err error) {
		for got < want {
			t, body, err := f.read(wait)
			if err != nil {
				return n, got, unpadded, err
			}
			switch t {
			case "chunk":
				if len(body) < 44 {
					return n, got, unpadded, errors.New("a chunk too short")
				}
				n++
				got += int(binary.BigEndian.Uint32(body[40:44]))
				if len(body)%fetchPad != 0 {
					unpadded++
				}
			case "missing":
				return n, got, unpadded, errors.New("the target does not hold the part")
			}
		}
		return n, got, unpadded, nil
	}

	if err := get(fetchWindow); err != nil {
		return err
	}
	n, got, unpadded, err := chunks(fetchWindow, 10*time.Second)
	switch {
	case err != nil:
		fmt.Printf("window: failed: %v (%d chunks, %d bytes)\n", err, n, got)
	case unpadded > 0 || got != fetchWindow:
		fmt.Printf("window: %d chunks, %d bytes, %d not padded\n", n, got, unpadded)
	default:
		fmt.Printf("window: %d chunks, %d bytes, padded\n", n, got)
	}

	if err := get(fetchWindow + 1); err != nil {
		return err
	}
	if n, got, _, err := chunks(1, 3*time.Second); n > 0 || got > 0 {
		fmt.Printf("over: answered with %d bytes\n", got)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		fmt.Println("over: no answer")
	} else {
		fmt.Printf("over: %v\n", err)
	}
	// The connection still serves after the dropped get.
	if err := get(fetchPad); err != nil {
		return err
	}
	if _, got, _, err := chunks(fetchPad, 10*time.Second); err == nil && got == fetchPad {
		fmt.Println("after-over: answered")
	} else {
		fmt.Printf("after-over: %v (%d bytes)\n", err, got)
	}

	var burst []byte
	for range fetchGets {
		b, _ := json.Marshal(map[string]any{"t": "get", "get": map[string]any{"sha256": sum, "offset": 0, "length": fetchWindow}})
		burst = append(append(burst, binary.BigEndian.AppendUint32(nil, uint32(len(b)))...), b...)
	}
	if _, err := f.c.Write(burst); err != nil {
		fmt.Printf("flood: closed while sending: %v\n", err)
		return nil
	}
	// Read until the target closes; a connection that keeps serving all
	// 80 MiB is not closed.
	deadline := time.Now().Add(60 * time.Second)
	total := 0
	for time.Now().Before(deadline) {
		_, body, err := f.read(10 * time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			fmt.Printf("flood: closed after %d gets, %d bytes served\n", fetchGets, total)
			return nil
		}
		total += len(body)
	}
	fmt.Printf("flood: still open, %d bytes served\n", total)
	return nil
}
