// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"encoding/json"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestAgentEndsWithTheChannel: an agent request runs until cbb closes the
// channel, and one without a socket is refused.
func TestAgentEndsWithTheChannel(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skip("the agent links the system's own clipboard here")
	}
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	s := New("v")
	s.HandleAgent(io.Discard)
	body, _ := json.Marshal(AgentRequest{Socket: "/nonexistent/control.sock"})
	done := make(chan map[uint64]*control.Message, 1)
	go func() {
		done <- exchange(t, s,
			control.Message{Header: control.Header{Op: OpAgent, Seq: 1}, Payload: body},
			control.Message{Header: control.Header{Op: OpAgent, Seq: 2}, Payload: []byte(`{}`)},
		)
	}()
	select {
	case got := <-done:
		if got[1] == nil || got[1].Error != "" {
			t.Errorf("the agent's answer: %+v", got[1])
		}
		if got[2] == nil || got[2].Error == "" {
			t.Errorf("an agent request without a socket was taken: %+v", got[2])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent outlived its channel")
	}
}
