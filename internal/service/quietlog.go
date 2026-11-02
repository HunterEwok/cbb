// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"syscall"
	"time"
)

// peerEnded tells whether err only says that the peer closed or reset a
// member connection: a phone's system does so whenever its app goes to the
// background. Such an end is logged only with CBB_DEBUG=1; a failed handshake
// or a refused peer is logged always.
func peerEnded(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && slices.Contains(resetErrnos, errno)
}

// logEnd logs a member connection's end, unless it is only the peer's
// close or reset and CBB_DEBUG is not 1.
func (s *Service) logEnd(err error, format string, args ...any) {
	if peerEnded(err) && os.Getenv("CBB_DEBUG") != "1" {
		return
	}
	s.logf(format, args...)
}

// repeatQuiet is how long logRepeat keeps a line it logged from coming
// again: a watcher that is refused tries again every few seconds.
const repeatQuiet = 10 * time.Minute

// logRepeat logs a line unless the same line was logged within
// repeatQuiet; with CBB_DEBUG=1 it logs every one.
func (s *Service) logRepeat(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if os.Getenv("CBB_DEBUG") != "1" {
		s.repeatMu.Lock()
		now := time.Now()
		if s.repeated == nil {
			s.repeated = map[string]time.Time{}
		}
		last, seen := s.repeated[line]
		if seen && now.Sub(last) < repeatQuiet {
			s.repeatMu.Unlock()
			return
		}
		for l, t := range s.repeated {
			if now.Sub(t) >= repeatQuiet {
				delete(s.repeated, l)
			}
		}
		s.repeated[line] = now
		s.repeatMu.Unlock()
	}
	s.logf("%s", line)
}
