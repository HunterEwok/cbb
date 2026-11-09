// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/actions"
	"github.com/HunterEwok/cbb/internal/blekeyboard"
	"github.com/HunterEwok/cbb/internal/blekeyboard/bluetest"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/keyboard"
	"github.com/HunterEwok/cbb/internal/peripheral"
)

// TestLitePeripherals checks the Bluetooth keyboard and a TV's remote on
// the Rust service, which cbb-helper runs for it: cbb keyboard and cbb
// remote, a remote paste on the keyboard's host and on a Roku, and the
// quick action keyboard-layout.
func TestLitePeripherals(t *testing.T) {
	bin := liteBin(t)
	helper := filepath.Join(t.TempDir(), "cbb-helper")
	if out, err := exec.Command("go", "build", "-o", helper, "github.com/HunterEwok/cbb/cmd/cbb-helper").CombinedOutput(); err != nil {
		t.Fatalf("go build cbb-helper: %v\n%s", err, out)
	}
	f := bluetest.Start(t)
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinLite(t, bin, pi)
	lite := startLiteEnv(t, bin, dir, []string{"CBB_HELPER=" + helper, "CBB_TEST_BLUEZ=" + f.Addr}, "-no-mdns", "-no-listen", "-peer", pi.addr())
	waitFor(t, "connected", func() bool { return len(pi.status(t).Peers) == 1 && len(lite.status(t).Peers) == 1 })

	// A Linux computer with cbb-helper can be the keyboard, so its status
	// shows one, off, as Go's KeyboardStatus.
	if k := lite.status(t).Keyboard; k == nil || k.On || k.Layout != "us" {
		t.Fatalf("the keyboard before on: %+v, want off", k)
	}
	m, err := lite.do(t, control.Header{Op: control.OpKeyboard, Name: "on", Keyboard: &control.Keyboard{Layout: "us", Rate: 60, Pastes: true}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if k := m.Status.Keyboard; k == nil || !k.On || k.Layout != "us" || !k.Pastes {
		t.Fatalf("after on: %+v", k)
	}
	if _, err := lite.do(t, control.Header{Op: control.OpKeyboard, Name: "pair"}, ""); err != nil {
		t.Fatal(err)
	}
	if k := lite.status(t).Keyboard; k == nil || k.VisibleUntilMS == 0 {
		t.Errorf("not visible after pair: %+v", k)
	}
	reports, stop := f.Subscribe(t)
	want := func(text string) {
		t.Helper()
		rs, _ := keyboard.US.Reports(text)
		for i, w := range rs {
			select {
			case v := <-reports:
				if !slices.Equal(v, w[:]) {
					t.Fatalf("%q, report %d: %x, want %x", text, i, v, w)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%q, report %d did not come", text, i)
			}
		}
	}
	if _, err := lite.do(t, control.Header{Op: control.OpKeyboard, Name: "type"}, "ok\r\n"); err != nil {
		t.Fatal(err)
	}
	want("ok\n")

	// A remote paste goes to the host, and a line break needs Enter.
	if _, err := lite.do(t, control.Header{Op: control.OpReceive, Name: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if p := lite.status(t).Paste; p == nil || !slices.Contains(p.Targets, peripheral.TargetKeyboard) {
		t.Errorf("the paste targets: %+v", p)
	}
	paste := func(text string) error {
		time.Sleep(time.Second) // one paste a second from one sender
		_, err := pi.do(t, control.Header{Op: control.OpPasteOn, Device: "lite"}, text)
		return err
	}
	if err := paste("Wi-Fi 42"); err != nil {
		t.Fatal(err)
	}
	want("Wi-Fi 42")
	if err := paste("a\nb"); err == nil || !strings.Contains(err.Error(), "types as Enter") {
		t.Errorf("two lines: %v", err)
	}
	stop()

	// The quick action keyboard-layout.
	if _, err := lite.do(t, control.Header{Op: control.OpActionSet, Actions: []control.Action{{Name: actions.Layout, On: true}}}, ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second) // one action a second from one sender
	if _, err := pi.do(t, control.Header{Op: control.OpActionOn, Device: "lite", Name: actions.Layout}, ""); err != nil {
		t.Fatal(err)
	}
	if set, err := blekeyboard.Load(dir); err != nil || set.Layout != keyboard.RU {
		t.Errorf("after keyboard-layout: %+v, %v", set, err)
	}
	if _, err := lite.do(t, control.Header{Op: control.OpKeyboard, Name: "off"}, ""); err != nil {
		t.Fatal(err)
	}

	// A Roku takes the pastes once the user sends them there.
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
	addr := strings.TrimPrefix(roku.URL, "http://")
	if _, err := lite.do(t, control.Header{Op: control.OpRemote, Name: "add", Address: addr, Value: "roku"}, ""); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Errorf("a Roku without consent: %v", err)
	}
	m, err = lite.do(t, control.Header{Op: control.OpRemote, Name: "add", Address: addr, Value: "roku", Consent: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if tvs := m.Status.TVs; len(tvs) != 1 || tvs[0].Name != "Bedroom" || tvs[0].Kind != "roku" {
		t.Fatalf("added: %+v", tvs)
	}
	if _, err := lite.do(t, control.Header{Op: control.OpRemote, Name: "pastes", Device: "bedroom", Value: "on"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := paste("hi"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Roku has the paste", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Equal(keys, []string{"Lit_h", "Lit_i"})
	})
	if tvs := lite.status(t).TVs; len(tvs) != 1 || !tvs[0].Pastes {
		t.Errorf("the status's TVs: %+v", tvs)
	}
}
