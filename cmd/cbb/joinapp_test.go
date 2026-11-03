// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

func TestPairForApp(t *testing.T) {
	appFilePoll = 10 * time.Millisecond
	t.Cleanup(func() { appFilePoll = time.Second })
	// The service answers with where, then waits: until the phone came
	// (done) or the app hung up.
	serve := func(done chan struct{}, hungUp chan struct{}) {
		fakeHandler(t, func(m *control.Message, r *control.Reader, c net.Conn) {
			if m.Op == control.OpStatus {
				inGroup(c, "")
				return
			}
			answer(c, control.Message{Header: control.Header{Addrs: []string{"192.168.1.20:40123"}, Fingerprint: "q83vEjRWeJA"}})
			gone := make(chan struct{})
			go func() { r.Read(); close(gone) }()
			select {
			case <-done:
				answer(c, control.Message{Header: control.Header{Done: true}})
			case <-gone:
				close(hungUp)
			}
		})
	}
	file := filepath.Join(t.TempDir(), "join.json")

	// The phone comes: the file holds the code, and cbb says it joined.
	done, hungUp := make(chan struct{}), make(chan struct{})
	serve(done, hungUp)
	os.WriteFile(file, nil, 0o600)
	var stdout, stderr bytes.Buffer
	exit := make(chan int, 1)
	go func() { exit <- run([]string{"pair", "-app", file}, strings.NewReader(""), &stdout, &stderr) }()
	j := waitForJoinFile(t, file)
	if !strings.HasPrefix(j.QR, "cbb://join?") || j.Expires != 300 || j.Port == 0 {
		t.Errorf("the file holds %+v", j)
	}
	close(done)
	if code := <-exit; code != 0 || !strings.Contains(stdout.String(), "Joined the group") {
		t.Errorf("pair -app: %d, %s%s", code, stdout.String(), stderr.String())
	}

	// The app removes the file: cbb hangs up, which cancels the join.
	done, hungUp = make(chan struct{}), make(chan struct{})
	serve(done, hungUp)
	os.WriteFile(file, nil, 0o600)
	stderr.Reset()
	go func() { exit <- run([]string{"pair", "-app", file}, strings.NewReader(""), &stdout, &stderr) }()
	waitForJoinFile(t, file)
	os.Remove(file)
	if code := <-exit; code == 0 || !strings.Contains(stderr.String(), "cancelled") {
		t.Errorf("pair -app after the file went: %d, %s", code, stderr.String())
	}
	select {
	case <-hungUp:
	case <-time.After(5 * time.Second):
		t.Error("cbb did not hang up")
	}

	// cbb writes only over a file the app made.
	if code := run([]string{"pair", "-app", filepath.Join(t.TempDir(), "none")}, strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Error("pair -app wrote a file that was not there")
	}
	if code := run([]string{"pair", "-app", file, "-code"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Errorf("pair -app -code: %d", code)
	}
}

func waitForJoinFile(t *testing.T, path string) AppJoin {
	t.Helper()
	for range 500 {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			var j AppJoin
			if err := json.Unmarshal(data, &j); err != nil {
				t.Fatalf("the file holds %q: %v", data, err)
			}
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cbb wrote nothing into the file")
	return AppJoin{}
}

// TestOpenAppFile checks that cbb pair -app, which runs as the
// administrator, writes only over a regular file of the app's: never
// through a symbolic link put in its place, nor into a folder.
func TestOpenAppFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "join")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openAppFile(file)
	if err != nil {
		t.Fatalf("the app's own file: %v", err)
	}
	f.Close()
	if _, err := openAppFile(dir); err == nil {
		t.Error("opened a folder")
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(other, link); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	if f, err := openAppFile(link); err == nil {
		f.Close()
		t.Error("opened a symbolic link")
	}
}
