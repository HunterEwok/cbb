// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command udprelay runs on the emulator's phone for the bench's phone suite
// (tools/bench, phoneUDP): it takes TCP connections on -listen, which the
// bench reaches through adb forward, and passes the datagrams each one
// carries to the UDP port -to on the phone, and the answers back. Each
// datagram goes as two bytes of length, big-endian, then its bytes; each
// connection is one sender, with a UDP socket of its own.
//
// The emulator's console redirects UDP (adb emu redir) to its user-mode
// network, which an image whose only network is the emulator's Wi-Fi never
// gets; TCP through adb reaches every image.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "where the bench's connections come, through adb forward")
	to := flag.String("to", "", "the phone's UDP address the datagrams go to, such as 127.0.0.1:8764")
	flag.Parse()
	if *to == "" {
		fmt.Fprintln(os.Stderr, "udprelay: -to is needed")
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "udprelay:", err)
		os.Exit(1)
	}
	// The bench reads the port from the first line.
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	for {
		c, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "udprelay:", err)
			os.Exit(1)
		}
		go serve(c, *to)
	}
}

// serve passes the datagrams of the connection c to the address to and
// the answers back, until either side ends.
func serve(c net.Conn, to string) {
	defer c.Close()
	u, err := net.Dial("udp", to)
	if err != nil {
		fmt.Fprintln(os.Stderr, "udprelay:", err)
		return
	}
	defer u.Close()
	go func() {
		defer c.Close()
		b := make([]byte, 64*1024)
		for {
			n, err := u.Read(b)
			if err != nil {
				return
			}
			if writeFrame(c, b[:n]) != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(c)
	for {
		d, err := readFrame(r)
		if err != nil {
			return
		}
		if _, err := u.Write(d); err != nil {
			return
		}
	}
}

// writeFrame writes d as one frame: its length in two bytes, then d.
func writeFrame(w io.Writer, d []byte) error {
	if len(d) > 0xffff {
		return fmt.Errorf("a datagram of %d bytes", len(d))
	}
	b := make([]byte, 2+len(d))
	binary.BigEndian.PutUint16(b, uint16(len(d)))
	copy(b[2:], d)
	_, err := w.Write(b)
	return err
}

// readFrame reads one frame that writeFrame wrote.
func readFrame(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	d := make([]byte, binary.BigEndian.Uint16(n[:]))
	_, err := io.ReadFull(r, d)
	return d, err
}
