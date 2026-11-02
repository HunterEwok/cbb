// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

func TestPeerEnded(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", resetErrnos[0])}
	for _, c := range []struct {
		err  error
		want bool
	}{
		{io.EOF, true},
		{fmt.Errorf("reading a frame: %w", io.ErrUnexpectedEOF), true},
		{reset, true},
		{fmt.Errorf("serve: %w", reset), true},
		{x509.UnknownAuthorityError{}, false},
		{errors.New("the peer is not a member of this group"), false},
	} {
		if got := peerEnded(c.err); got != c.want {
			t.Errorf("peerEnded(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestLogRepeat(t *testing.T) {
	t.Setenv("CBB_DEBUG", "0")
	var lines []string
	s := &Service{logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
	for range 3 {
		s.logRepeat("cbb: refused %s", "a")
	}
	s.logRepeat("cbb: refused %s", "b")
	if len(lines) != 2 {
		t.Fatalf("logged %q, want one line for a and one for b", lines)
	}
	t.Setenv("CBB_DEBUG", "1")
	s.logRepeat("cbb: refused %s", "a")
	if len(lines) != 3 {
		t.Fatalf("with CBB_DEBUG=1 logged %q, want the repeat too", lines)
	}
}
