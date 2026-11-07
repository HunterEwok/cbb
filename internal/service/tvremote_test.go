// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/tvremote/androidtv/atvtest"
	appletvtest "github.com/HunterEwok/cbb/internal/tvremote/appletv/atvtest"
)

// TestRemote: cbb remote against a fake Android TV and a fake Roku:
// pairing with the code, typing, a remote paste sent to the TV, and
// removing it.
func TestRemote(t *testing.T) {
	tv := atvtest.New(t)
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })

	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "add", Address: "8.8.8.8"}, ""); err == nil || !strings.Contains(err.Error(), "home network") {
		t.Errorf("a TV outside the home network: %v", err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "code", Code: "123456"}, ""); err == nil {
		t.Error("a code with no pairing was taken")
	}
	// Adding an Android TV makes the remote's 2048-bit RSA key, which takes
	// far longer than one request's usual deadline on an emulated CPU (the
	// linux/mips job under QEMU).
	c := deck.dial(t)
	c.SetDeadline(time.Now().Add(3 * time.Minute))
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpRemote, Name: "add", Address: tv.Addr()}})
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if tvs := m.Status.TVs; len(tvs) != 1 || !tvs[0].Pairing {
		t.Fatalf("pairing: %+v", tvs)
	}
	m, err = deck.do(t, control.Header{Op: control.OpRemote, Name: "code", Code: tv.Code()}, "")
	if err != nil {
		t.Fatal(err)
	}
	if tvs := m.Status.TVs; len(tvs) != 1 || tvs[0].Name != "Fake TV" || tvs[0].Kind != "androidtv" || tvs[0].Pairing {
		t.Fatalf("paired: %+v", tvs)
	}

	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "type"}, "hi"); err == nil || !strings.Contains(err.Error(), "no text field") {
		t.Errorf("typing with no text field: %v", err)
	}
	tv.Focus()
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "type"}, "hi"); err != nil {
		t.Fatal(err)
	}
	tv.Wait(t, 1)

	// A remote paste goes to the TV, and a line break needs Enter.
	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "pastes", Device: "fake tv", Value: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if p := deck.status(t).Paste; !slices.Contains(p.Targets, targetTV) {
		t.Errorf("the paste targets: %v", p.Targets)
	}
	paste := func(text string) error {
		time.Sleep(time.Second) // one paste a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "deck"}, text)
		return err
	}
	if err := paste("Wi-Fi 42"); err != nil {
		t.Fatal(err)
	}
	tv.Wait(t, 2)
	if text, _ := tv.Text(); !slices.Equal(text, []string{"hi", "Wi-Fi 42"}) {
		t.Errorf("the TV got %q", text)
	}
	if err := paste("a\nb"); err == nil || !strings.Contains(err.Error(), "takes as Enter") {
		t.Errorf("two lines: %v", err)
	}
	// A TV that was reset refuses the remote: the error names it.
	tv.Forget()
	if err := paste("x"); err == nil || !strings.Contains(err.Error(), "Fake TV (Android TV)") {
		t.Errorf("a reset TV: %v", err)
	}

	m, err = deck.do(t, control.Header{Op: control.OpRemote, Name: "remove", Device: "Fake TV"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Status.TVs) != 0 || slices.Contains(m.Status.Paste.Targets, targetTV) {
		t.Errorf("after remove: %+v, %v", m.Status.TVs, m.Status.Paste.Targets)
	}
}

// TestRemoteAppleTV: cbb remote against a fake Apple TV: pairing with its
// PIN, typing, a remote paste sent to it, and a TV that forgot the remote.
func TestRemoteAppleTV(t *testing.T) {
	tv := appletvtest.New(t)
	var h hub
	pi := startService(t, &h, "pi")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 })

	add := control.Header{Op: control.OpRemote, Name: "add", Address: tv.Addr(), Value: "appletv", NewName: "Lounge"}
	m, err := deck.do(t, add, "")
	if err != nil {
		t.Fatal(err)
	}
	if tvs := m.Status.TVs; len(tvs) != 1 || !tvs[0].Pairing || tvs[0].Kind != "appletv" {
		t.Fatalf("pairing: %+v", tvs)
	}
	wrong := "0000"
	if tv.PIN() == wrong {
		wrong = "1111"
	}
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "code", Code: wrong}, ""); err == nil || !strings.Contains(err.Error(), "not the PIN") {
		t.Errorf("a wrong PIN: %v", err)
	}
	if _, err := deck.do(t, add, ""); err != nil {
		t.Fatal(err)
	}
	m, err = deck.do(t, control.Header{Op: control.OpRemote, Name: "code", Code: tv.PIN()}, "")
	if err != nil {
		t.Fatal(err)
	}
	if tvs := m.Status.TVs; len(tvs) != 1 || tvs[0].Name != "Lounge" || tvs[0].Kind != "appletv" || tvs[0].Pairing {
		t.Fatalf("paired: %+v", tvs)
	}
	if names := tv.Names(); len(names) != 1 || names[0] != "CBB deck" {
		t.Errorf("the TV knows the remote as %q", names)
	}

	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "type"}, "hi"); err == nil || !strings.Contains(err.Error(), "no text field") {
		t.Errorf("typing with no text field: %v", err)
	}
	tv.Focus()
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "type"}, "\u041f\u0440\u0438\u0432\u0435\u0442"); err != nil {
		t.Fatal(err)
	}

	if _, err := deck.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "pastes", Device: "lounge", Value: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	paste := func(text string) error {
		time.Sleep(time.Second) // one paste a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "deck"}, text)
		return err
	}
	if err := paste("Wi-Fi 42"); err != nil {
		t.Fatal(err)
	}
	tv.Wait(t, 2)
	if text := tv.Text(); !slices.Equal(text, []string{"\u041f\u0440\u0438\u0432\u0435\u0442", "Wi-Fi 42"}) {
		t.Errorf("the TV got %q", text)
	}
	tv.Forget()
	if err := paste("x"); err == nil || !strings.Contains(err.Error(), "Lounge (Apple TV)") || !strings.Contains(err.Error(), "pair it again") {
		t.Errorf("a reset TV: %v", err)
	}
}

// TestRemoteAppleTVName: an Apple TV added without a name gets the one it
// announces by mDNS, and its address when it announces none.
func TestRemoteAppleTVName(t *testing.T) {
	for _, announced := range []string{"Den TV", ""} {
		tv := appletvtest.New(t)
		defer func(f func(context.Context, string) string) { appleTVName = f }(appleTVName)
		appleTVName = func(context.Context, string) string { return announced }
		var h hub
		deck := startService(t, &h, "deck")
		if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "add", Address: tv.Addr(), Value: "appletv"}, ""); err != nil {
			t.Fatal(err)
		}
		m, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "code", Code: tv.PIN()}, "")
		if err != nil {
			t.Fatal(err)
		}
		want := announced
		if want == "" {
			want = tv.Addr()
		}
		if tvs := m.Status.TVs; len(tvs) != 1 || tvs[0].Name != want {
			t.Errorf("announced %q: the TV is %+v, want the name %q", announced, tvs, want)
		}
	}
}

// TestRemoteRoku: a Roku needs the user's consent, and types key by key.
func TestRemoteRoku(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	roku := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/query/device-info":
			w.Write([]byte(`<device-info><user-device-name>Bedroom</user-device-name></device-info>`))
		case strings.HasPrefix(r.URL.Path, "/keypress/"):
			mu.Lock()
			keys = append(keys, strings.TrimPrefix(r.URL.Path, "/keypress/"))
			mu.Unlock()
		}
	}))
	defer roku.Close()
	var h hub
	deck := startService(t, &h, "deck")
	addr := strings.TrimPrefix(roku.URL, "http://")
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "add", Address: addr, Value: "roku"}, ""); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Errorf("a Roku without consent: %v", err)
	}
	m, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "add", Address: addr, Value: "roku", Consent: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if tvs := m.Status.TVs; len(tvs) != 1 || tvs[0].Name != "Bedroom" || tvs[0].Kind != "roku" {
		t.Fatalf("added: %+v", tvs)
	}
	if _, err := deck.do(t, control.Header{Op: control.OpRemote, Name: "type", Device: "bedroom"}, "ok\n"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"Lit_o", "Lit_k", "Enter"}; !slices.Equal(keys, want) {
		t.Errorf("keys %q, want %q", keys, want)
	}
}
