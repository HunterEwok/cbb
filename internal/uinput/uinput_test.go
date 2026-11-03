// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package uinput

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/HunterEwok/cbb/internal/connector"
)

type fakeKeys struct {
	mu   sync.Mutex
	keys []Key
	err  error
}

func (f *fakeKeys) Press(ks []Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.keys = append(f.keys, ks...)
	return nil
}

func (f *fakeKeys) pressed() []Key {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.keys)
}

// TestHelper checks the helper's requests: the keys of a paste and of
// Enter for a caller the check lets through under a grant of the service, a
// refusal with its reason, and nothing else.
func TestHelper(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "keys")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	keys := &fakeKeys{}
	var mu sync.Mutex
	why, callers := "", []uint32(nil)
	h := &Helper{Keys: keys, Logf: t.Logf, Check: func(uid uint32) string {
		mu.Lock()
		defer mu.Unlock()
		callers = append(callers, uid)
		return why
	}, Grant: func(uid uint32, req, grant string) string {
		if grant != "g1" || uid != uint32(os.Getuid()) {
			return "no remote paste asked for these keys now"
		}
		return ""
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	if err := Ask(ctx, sock, "paste", "g1"); err != nil {
		t.Fatal(err)
	}
	if err := Ask(ctx, sock, "enter", "g1"); err != nil {
		t.Fatal(err)
	}
	want := []Key{{KeyLeftShift, true}, {KeyInsert, true}, {KeyInsert, false}, {KeyLeftShift, false}, {KeyEnter, true}, {KeyEnter, false}}
	if got := keys.pressed(); !slices.Equal(got, want) {
		t.Errorf("pressed %v, want %v", got, want)
	}
	mu.Lock()
	if len(callers) != 2 || callers[0] != uint32(os.Getuid()) {
		t.Errorf("the check saw callers %v, want this process's user %d", callers, os.Getuid())
	}
	why = "the session is locked"
	mu.Unlock()

	var r *connector.Refusal
	if err := Ask(ctx, sock, "paste", "g1"); !errors.As(err, &r) || r.Reason != "the session is locked" {
		t.Errorf("a paste while locked: %v", err)
	}
	// Keys that the service did not grant, or with no grant, as an older
	// desktop connector asks.
	for _, g := range []string{"g2", ""} {
		if err := Ask(ctx, sock, "paste", g); !errors.As(err, &r) || !strings.Contains(r.Reason, "remote paste") {
			t.Errorf("a paste with the grant %q: %v", g, err)
		}
	}
	if err := Ask(ctx, sock, "type", "rm -rf /"); err == nil || errors.As(err, &r) || !strings.Contains(err.Error(), "not") {
		t.Errorf("another request: %v", err)
	}
	if got := keys.pressed(); len(got) != len(want) {
		t.Errorf("keys pressed after a refusal: %v", got[len(want):])
	}

	mu.Lock()
	why = ""
	mu.Unlock()
	keys.mu.Lock()
	keys.err = errors.New("the device is gone")
	keys.mu.Unlock()
	if err := Ask(ctx, sock, "enter", "g1"); err == nil || errors.As(err, &r) || !strings.Contains(err.Error(), "the device is gone") {
		t.Errorf("a failed press: %v", err)
	}
}

// TestKeyboard checks the uinput keyboard against the kernel: the keys it
// presses come out of its event device. It needs a writable /dev/uinput
// and the event devices, as root: CI's desktop job runs it with sudo and
// CBB_TEST_UINPUT=1, which makes a missing device a failure.
func TestKeyboard(t *testing.T) {
	if f, err := os.OpenFile(Device, os.O_WRONLY, 0); err != nil {
		if os.Getenv("CBB_TEST_UINPUT") == "1" {
			t.Fatal(err)
		}
		t.Skipf("no uinput: %v", err)
	} else {
		f.Close()
	}
	name := "CBB test " + time.Now().Format("150405.000")
	k, err := Open(Device, name)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	var dev string
	names, _ := filepath.Glob("/sys/class/input/event*/device/name")
	for _, n := range names {
		if b, err := os.ReadFile(n); err == nil && strings.TrimSpace(string(b)) == name {
			dev = "/dev/input/" + filepath.Base(filepath.Dir(filepath.Dir(n)))
		}
	}
	if dev == "" {
		t.Fatal("the keyboard has no event device")
	}
	f, err := os.Open(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	press := []Key{{KeyLeftShift, true}, {KeyInsert, true}, {KeyInsert, false}, {KeyLeftShift, false}, {KeyEnter, true}, {KeyEnter, false}}
	if err := k.Press(press); err != nil {
		t.Fatal(err)
	}
	f.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []Key
	var ev event
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&ev)), unsafe.Sizeof(ev))
	for len(got) < len(press) {
		if _, err := f.Read(buf); err != nil {
			t.Fatalf("reading the event device after %v: %v", got, err)
		}
		if ev.typ == evKey {
			got = append(got, Key{Code: ev.code, Press: ev.value == 1})
		}
	}
	if !slices.Equal(got, press) {
		t.Errorf("the event device got %v, want %v", got, press)
	}
}
