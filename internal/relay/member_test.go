// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestAsk checks the wait for the relay to join a dial or an answer: the
// relay's answer, its refusal, and a registration that ends meanwhile.
func TestAsk(t *testing.T) {
	relayAnswers := func(n note) func(net.Conn) {
		return func(c net.Conn) {
			var req request
			if readLine(c, &req, time.Second) == nil && req.Answer == "ticket" {
				writeLine(c, n, time.Second)
			}
		}
	}
	for _, tc := range []struct {
		name  string
		relay func(net.Conn)
		want  string
	}{
		{"joined", relayAnswers(note{OK: true}), ""},
		{"refused", relayAnswers(note{Error: "no such call"}), "the relay: no such call"},
	} {
		a, b := net.Pipe()
		go tc.relay(b)
		err := ask(context.Background(), a, request{Answer: "ticket"})
		if got := ""; err != nil {
			got = err.Error()
			if got != tc.want {
				t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
			}
		} else if tc.want != "" {
			t.Errorf("%s: no error, want %q", tc.name, tc.want)
		}
		a.Close()
		b.Close()
	}

	// The relay dropped the registration, so it says nothing more on the
	// connection; the next registration waits for this answer to end, so
	// the answer must end with the registration, not at its timeout.
	a, b := net.Pipe()
	defer b.Close()
	took := make(chan struct{})
	go func() {
		var req request
		readLine(b, &req, time.Second)
		close(took)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ask(ctx, a, request{Answer: "ticket"}) }()
	<-took
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("an answer when its registration ends: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an answer still waits for the relay after its registration ended")
	}
}

// A device answers at most as many calls at once as the relay keeps
// waiting for it.
func TestCallsBounded(t *testing.T) {
	s := &session{}
	for range maxCalls {
		if !s.takeCall() {
			t.Fatal("a call refused within the limit")
		}
	}
	if s.takeCall() {
		t.Fatal("a call taken past the limit")
	}
	s.endCall()
	if !s.takeCall() {
		t.Fatal("a call refused after one ended")
	}
}
