// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package peripheral

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/tvremote"
)

// TestTypeLater checks that a paste typed after its answer goes one at a
// time on a target and stops once it may no longer go on.
func TestTypeLater(t *testing.T) {
	defer func(d time.Duration) { TypingCheck = d }(TypingCheck)
	TypingCheck = 10 * time.Millisecond
	free := make(chan string, 4)
	s := &Host{Logf: t.Logf, typed: func(target string) { free <- target }}
	var allowed atomic.Bool
	allowed.Store(true)
	stopped := make(chan error, 1)
	typ := func(ctx context.Context) error {
		<-ctx.Done()
		stopped <- ctx.Err()
		return ctx.Err()
	}
	if !s.typeLater("kb", allowed.Load, typ) {
		t.Fatal("the first paste was refused")
	}
	if s.typeLater("kb", allowed.Load, typ) {
		t.Error("a second paste was taken while the first types")
	}
	if !s.typeLater("tv", allowed.Load, func(context.Context) error { return nil }) {
		t.Error("another target was refused")
	}
	if got := <-free; got != "tv" {
		t.Errorf("%s stopped typing, want tv", got)
	}
	allowed.Store(false) // remote paste off, or the signer removed
	if err := <-stopped; err != context.Canceled {
		t.Errorf("typing ended with %v", err)
	}
	if got := <-free; got != "kb" {
		t.Errorf("%s stopped typing, want kb", got)
	}
	if !s.typeLater("kb", func() bool { return true }, func(context.Context) error { return nil }) {
		t.Fatal("the keyboard stays busy after typing stopped")
	}
}

// A paste typed on a Roku after its answer stops once the paste may no
// longer go on: tvPaste hands still to typeLater.
func TestTVPasteStopsWhenNotAllowed(t *testing.T) {
	defer func(d time.Duration) { TypingCheck = d }(TypingCheck)
	TypingCheck = 10 * time.Millisecond
	defer func(d func(context.Context, string, string) (net.Conn, error)) { TVDial = d }(TVDial)
	TVDial = (&net.Dialer{}).DialContext
	var keys atomic.Int32
	pressed := make(chan struct{}, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/query/device-info":
			w.Write([]byte(`<?xml version="1.0"?><device-info><user-device-name>Living room</user-device-name></device-info>`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/keypress/"):
			keys.Add(1)
			select {
			case pressed <- struct{}{}:
			default:
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := tvremote.Save(dir, tvremote.State{TVs: []tvremote.TV{{Name: "tv", Kind: tvremote.Roku, Host: srv.Listener.Addr().String(), Pastes: true}}}); err != nil {
		t.Fatal(err)
	}
	free := make(chan string, 1)
	s := &Host{Dir: dir, Logf: t.Logf, typed: func(target string) { free <- target }}
	var allowed atomic.Bool
	allowed.Store(true)
	text := strings.Repeat("a", 400) // 8 s at a Roku's pace
	res, ok := s.tvPaste(text, false, false, allowed.Load)
	if !ok || res.Status != Done {
		t.Fatalf("tvPaste: %v %+v", ok, res)
	}
	for range 3 {
		<-pressed
	}
	allowed.Store(false)
	// Once the TV is free again, its typing has ended: no key goes after.
	<-free
	if n := keys.Load(); n >= int32(len(text)) {
		t.Fatalf("all %d keys went, though the paste was no longer allowed", n)
	}
}
