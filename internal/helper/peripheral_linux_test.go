// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package helper

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/blekeyboard"
	"github.com/HunterEwok/cbb/internal/blekeyboard/bluetest"
	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/keyboard"
	"github.com/HunterEwok/cbb/internal/peripheral"
	"github.com/HunterEwok/cbb/internal/remotepaste"
)

// peripheralStatus reads a peripheral answer, failing on an error.
func peripheralStatus(t *testing.T, what string, m *control.Message) PeripheralStatus {
	t.Helper()
	if m == nil || m.Error != "" {
		t.Fatalf("%s: %+v", what, m)
	}
	var st PeripheralStatus
	if err := json.Unmarshal(m.Payload, &st); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return st
}

// TestPeripherals: the helper's Bluetooth keyboard and TV remote for the
// Rust service, against the fake BlueZ and a stand-in Roku: the keyboard
// turned on and typing, a remote paste on its host, a paste stopped, the
// quick action keyboard-layout, a Roku added and taking a paste, and
// requests that do not read.
func TestPeripherals(t *testing.T) {
	check := peripheral.TypingCheck
	peripheral.TypingCheck = 20 * time.Millisecond
	t.Cleanup(func() { peripheral.TypingCheck = check })
	f := bluetest.Start(t)
	t.Setenv("CBB_TEST_BLUEZ", f.Addr)
	dir := t.TempDir()
	var log bytes.Buffer
	s := New("test")
	s.HandlePeripherals(&log)
	req := func(op string, seq uint64, r PeripheralRequest) control.Message {
		r.Dir, r.Name, r.OS = dir, "pi", "linux"
		return request(t, op, seq, r)
	}

	// Nothing on yet; a request without the state folder does not read.
	got := exchange(t, s,
		req(OpPeripheralStatus, 1, PeripheralRequest{}),
		request(t, OpPeripheralStatus, 2, PeripheralRequest{Name: "pi"}),
		control.Message{Header: control.Header{Op: OpKeyboard, Seq: 3}, Payload: []byte("{")},
	)
	if st := peripheralStatus(t, "status", got[1]); st.Keyboard != nil && st.Keyboard.On {
		t.Errorf("a keyboard on before on: %+v", st.Keyboard)
	}
	for _, seq := range []uint64{2, 3} {
		if got[seq].Error == "" {
			t.Errorf("request %d without a state folder was taken", seq)
		}
	}

	// On, and typing.
	got = exchange(t, s, req(OpKeyboard, 4, PeripheralRequest{Header: control.Header{Op: control.OpKeyboard, Name: "on", Keyboard: &control.Keyboard{Layout: "us", Rate: 60, Pastes: true}}}))
	if k := peripheralStatus(t, "on", got[4]).Keyboard; k == nil || !k.On || k.Layout != "us" || !k.Pastes {
		t.Fatalf("after on: %+v", k)
	}
	reports, stop := f.Subscribe(t)
	defer stop()
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
	got = exchange(t, s, req(OpKeyboard, 5, PeripheralRequest{Header: control.Header{Op: control.OpKeyboard, Name: "type"}, Text: "ok"}))
	peripheralStatus(t, "type", got[5])
	want("ok")

	// A remote paste goes to the host while remote paste is on, and the
	// status lists the keyboard as a target.
	if err := remotepaste.Save(dir, remotepaste.Settings{On: true}); err != nil {
		t.Fatal(err)
	}
	got = exchange(t, s,
		req(OpPeripheralStatus, 6, PeripheralRequest{}),
		req(OpPeripheralPaste, 7, PeripheralRequest{Text: "Wi-Fi 42"}),
	)
	if st := peripheralStatus(t, "status", got[6]); !slices.Contains(st.Targets, peripheral.TargetKeyboard) {
		t.Errorf("the paste targets: %q", st.Targets)
	}
	var res peripheral.Result
	if err := json.Unmarshal(got[7].Payload, &res); err != nil || got[7].Error != "" {
		t.Fatalf("paste: %v, %+v", err, got[7].Header)
	}
	want("Wi-Fi 42")

	// The service stops the pastes when remote paste goes off.
	got = exchange(t, s, req(OpPeripheralStop, 8, PeripheralRequest{}))
	peripheralStatus(t, "stop", got[8])

	// A paste typed after its answer stops once remote paste is off: the
	// service checks the switch before it sends one, the helper while it
	// types.
	if err := remotepaste.Save(dir, remotepaste.Settings{}); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("secret ", 40)
	all, _ := keyboard.US.Reports(long)
	exchange(t, s, req(OpPeripheralPaste, 9, PeripheralRequest{Text: long}))
	typed := 0
	for quiet := false; !quiet; {
		select {
		case <-reports:
			typed++
		case <-time.After(time.Second):
			quiet = true
		}
	}
	if typed >= len(all) {
		t.Errorf("a paste went on with remote paste off: %d of %d reports", typed, len(all))
	}

	// The quick action keyboard-layout moves to the next layout.
	got = exchange(t, s, req(OpKeyboardLayout, 10, PeripheralRequest{}))
	if st := peripheralStatus(t, "layout", got[10]); st.Refused != "" {
		t.Fatalf("keyboard-layout refused: %s", st.Refused)
	}
	if set, err := blekeyboard.Load(dir); err != nil || set.Layout != keyboard.RU {
		t.Errorf("after keyboard-layout: %+v, %v", set, err)
	}
	got = exchange(t, s, req(OpKeyboard, 11, PeripheralRequest{Header: control.Header{Op: control.OpKeyboard, Name: "off"}}))
	if k := peripheralStatus(t, "off", got[11]).Keyboard; k != nil && k.On {
		t.Errorf("after off: %+v", k)
	}
	// Off, the layout cannot change.
	got = exchange(t, s, req(OpKeyboardLayout, 12, PeripheralRequest{}))
	if got[12].Error == "" && peripheralStatus(t, "layout off", got[12]).Refused == "" {
		t.Error("keyboard-layout with the keyboard off neither failed nor was refused")
	}

	// A Roku on the home network takes the pastes once the user sends them there.
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
	got = exchange(t, s,
		req(OpRemote, 13, PeripheralRequest{Header: control.Header{Op: control.OpRemote, Name: "add", Address: addr, Value: "roku"}}),
	)
	if !strings.Contains(got[13].Error, "plain HTTP") {
		t.Errorf("a Roku without consent: %q", got[13].Error)
	}
	got = exchange(t, s, req(OpRemote, 14, PeripheralRequest{Header: control.Header{Op: control.OpRemote, Name: "add", Address: addr, Value: "roku", Consent: true}}))
	if tvs := peripheralStatus(t, "add", got[14]).TVs; len(tvs) != 1 || tvs[0].Name != "Bedroom" {
		t.Fatalf("added: %+v", tvs)
	}
	got = exchange(t, s, req(OpRemote, 15, PeripheralRequest{Header: control.Header{Op: control.OpRemote, Name: "pastes", Device: "bedroom", Value: "on"}}))
	peripheralStatus(t, "pastes", got[15])
	if err := remotepaste.Save(dir, remotepaste.Settings{On: true}); err != nil {
		t.Fatal(err)
	}
	exchange(t, s, req(OpPeripheralPaste, 16, PeripheralRequest{Text: "hi"}))
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		done := slices.Equal(keys, []string{"Lit_h", "Lit_i"})
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Roku has %q", keys)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
