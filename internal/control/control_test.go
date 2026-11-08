// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package control

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/clip"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msgs := []*Message{
		{Header: Header{Op: OpCopy, Kind: "secret"}, Payload: []byte("line one\nline two\x00 with a NUL")},
		{Header: Header{Op: OpPaste}},
		{Header: Header{Op: OpReply, Status: &Status{Device: "d", Peers: []Device{{ID: "p", SkewMS: -7}}}}},
		{Header: Header{Op: OpWrite, Seq: 9}, Payload: []byte(strings.Repeat("x", 1<<20))},
	}
	for _, m := range msgs {
		if err := Write(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReader(&buf)
	var read []*Message
	for i, want := range msgs {
		got, err := r.Read()
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if got.Op != want.Op || got.Kind != want.Kind || got.Seq != want.Seq || !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("message %d: got %+v", i, got.Header)
		}
		read = append(read, got)
	}
	if st := read[2].Status; st == nil || st.Device != "d" || len(st.Peers) != 1 || st.Peers[0].SkewMS != -7 {
		t.Errorf("the status did not survive: %+v", st)
	}
	if _, err := r.Read(); err == nil {
		t.Error("read past the end")
	}
}

func TestLimits(t *testing.T) {
	if err := Write(&bytes.Buffer{}, &Message{Header: Header{Op: OpCopy}, Payload: make([]byte, maxPayload+1)}); err == nil {
		t.Error("wrote a payload over the limit")
	}
	if err := Write(&bytes.Buffer{}, &Message{Header: Header{Op: strings.Repeat("x", maxHeader)}}); err == nil {
		t.Error("wrote a header over the limit")
	}
	// Each input fails only for the reason it is named after: the long
	// header is valid JSON, and the long payload is all there.
	for name, input := range map[string]string{
		"a header over the limit": `{"op":"` + strings.Repeat("x", maxHeader) + `"}` + "\n",
		"bad JSON":                "{nope\n",
		"negative length":         `{"op":"copy","len":-1}` + "\n",
		"length over the limit":   fmt.Sprintf(`{"op":"copy","len":%d}`+"\n", maxPayload+1) + strings.Repeat("x", maxPayload+1),
		"payload cut short":       `{"op":"copy","len":10}` + "\nabc",
	} {
		if _, err := NewReader(strings.NewReader(input)).Read(); err == nil {
			t.Errorf("%s: read without an error", name)
		}
	}
}

func TestSocketPath(t *testing.T) {
	t.Setenv("CBB_SOCKET", "")
	if SocketPath() != DefaultSocket {
		t.Errorf("SocketPath() = %q", SocketPath())
	}
	t.Setenv("CBB_SOCKET", "/tmp/x.sock")
	if SocketPath() != "/tmp/x.sock" {
		t.Errorf("SocketPath() = %q", SocketPath())
	}
}

func TestDialErrors(t *testing.T) {
	_, err := Dial("/nonexistent/cbb.sock")
	if err == nil || !strings.Contains(err.Error(), "not running") || !strings.Contains(err.Error(), "start it") {
		t.Errorf("Dial of a missing socket: %v", err)
	}
	// The cause is for debug mode only, never in the message itself.
	var de *DialError
	if !errors.As(err, &de) || de.Err == nil || strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("Dial of a missing socket: %#v", err)
	}
}

func TestNames(t *testing.T) {
	// The names on the socket are the engine's own.
	for _, name := range []string{ViaCopy, ViaPhone, ViaUniversal} {
		var v clip.Via
		if err := v.UnmarshalText([]byte(name)); err != nil {
			t.Errorf("via %q: %v", name, err)
		}
	}
	for _, name := range []string{KindText, KindSecret} {
		var k clip.Kind
		if err := k.UnmarshalText([]byte(name)); err != nil {
			t.Errorf("kind %q: %v", name, err)
		}
	}
}

// TestNeedsAdmin: this device's own sync is on either socket; another
// device's sync and a mute only on the admin socket.
func TestNeedsAdmin(t *testing.T) {
	if NeedsAdmin(Header{Op: OpSync, Name: "off"}) {
		t.Error("turning this device's sync off needs the admin socket")
	}
	if !NeedsAdmin(Header{Op: OpSync, Name: "off", Device: "beta"}) || !NeedsAdmin(Header{Op: OpMute, Device: "beta"}) || !NeedsAdmin(Header{Op: OpUnmute, Device: "beta"}) {
		t.Error("another device's sync or mute does not need the admin socket")
	}
}
