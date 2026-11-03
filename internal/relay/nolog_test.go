// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/HunterEwok/cbb/internal/group"
)

// logLines collects what a server logs.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// holding fails t for each line that holds one of what.
func (l *logLines) holding(t *testing.T, what ...string) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) == 0 {
		t.Error("the server logged nothing; the test checks nothing")
	}
	for _, line := range l.lines {
		for _, w := range what {
			if strings.Contains(line, w) {
				t.Errorf("the log holds %q: %s", w, line)
			}
		}
	}
}

// TestNoLogs checks that a relay, even with wireguard-go's own messages on
// as with CBB_DEBUG, logs no address, no group tag, no device ID and no
// WireGuard peer while two devices meet through it and one leaves.
func TestNoLogs(t *testing.T) {
	g := newGroup(t)
	var logs logLines
	_, link := startWith(t, Config{Groups: []string{group.Tag(g.Cert)}, Logf: logs.logf, Verbose: true})
	a, b := newDevice(t, g), newDevice(t, g)
	if a.id > b.id {
		a, b = b, a
	}
	ja := join(t, link, a)
	jb := join(t, link, b)
	receive(t, ja.dialed, "a's dial")
	receive(t, jb.called, "b's answer")
	jb.stop()
	<-jb.done
	waitFor(t, "a sees b gone", func() bool {
		r := ja.last()
		return r.Connected && len(r.Online) == 0
	})
	logs.holding(t, "127.0.0.1", "peer(", group.Tag(g.Cert), a.id, b.id)
}
