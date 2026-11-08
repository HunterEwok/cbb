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
	s := &Host{Logf: t.Logf}
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
	allowed.Store(false) // remote paste off, or the signer removed
	select {
	case err := <-stopped:
		if err != context.Canceled {
			t.Errorf("typing ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("typing went on after the paste may no longer go on")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !s.typeLater("kb", func() bool { return true }, func(context.Context) error { return nil }) {
		if time.Now().After(deadline) {
			t.Fatal("the keyboard stays busy after typing stopped")
		}
		time.Sleep(10 * time.Millisecond)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/query/device-info":
			w.Write([]byte(`<?xml version="1.0"?><device-info><user-device-name>Living room</user-device-name></device-info>`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/keypress/"):
			keys.Add(1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := tvremote.Save(dir, tvremote.State{TVs: []tvremote.TV{{Name: "tv", Kind: tvremote.Roku, Host: srv.Listener.Addr().String(), Pastes: true}}}); err != nil {
		t.Fatal(err)
	}
	s := &Host{Dir: dir, Logf: t.Logf}
	var allowed atomic.Bool
	allowed.Store(true)
	text := strings.Repeat("a", 400) // 8 s at a Roku's pace
	res, ok := s.tvPaste(text, false, false, allowed.Load)
	if !ok || res.Status != Done {
		t.Fatalf("tvPaste: %v %+v", ok, res)
	}
	for keys.Load() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	allowed.Store(false)
	time.Sleep(200 * time.Millisecond)
	stopped := keys.Load()
	time.Sleep(300 * time.Millisecond)
	if n := keys.Load(); n != stopped || n >= int32(len(text)) {
		t.Fatalf("%d keys, then %d, after the paste was no longer allowed", stopped, n)
	}
}
