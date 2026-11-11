// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommandKeys: cbb forward makes its key on the first run, keeps it,
// and prints the pin users give the hub; it takes only flags, and a damaged
// key file stops it.
func TestCommandKeys(t *testing.T) {
	key := filepath.Join(t.TempDir(), "forward.pem")
	var pins []string
	for range 2 {
		var stdout, stderr bytes.Buffer
		if code := Command([]string{"-key", key, "-show-key"}, &stdout, &stderr, ""); code != 0 {
			t.Fatalf("-show-key: %d, %s", code, stderr.String())
		}
		pins = append(pins, strings.TrimSpace(stdout.String()))
	}
	if pins[0] == "" || pins[0] != pins[1] {
		t.Errorf("the pins of two runs: %q", pins)
	}
	var stdout, stderr bytes.Buffer
	if code := Command([]string{"extra"}, &stdout, &stderr, key); code != 2 || !strings.Contains(stderr.String(), "takes only flags") {
		t.Errorf("an argument: %d, %q", code, stderr.String())
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := Command([]string{"-key", bad, "-show-key"}, &stdout, &stderr, ""); code != 1 || stderr.Len() == 0 {
		t.Errorf("a damaged key: %d, %q", code, stderr.String())
	}
}

// TestXHTTPPathKept: the forwarder makes the path of its XHTTP once and
// keeps it in the key file beside the key, and takes one transport of VLESS
// at a time.
func TestXHTTPPathKept(t *testing.T) {
	key := filepath.Join(t.TempDir(), "forward.pem")
	var stdout, stderr bytes.Buffer
	if code := Command([]string{"-key", key, "-show-key"}, &stdout, &stderr, ""); code != 0 {
		t.Fatalf("-show-key: %d, %s", code, stderr.String())
	}
	first, err := LoadXHTTPPath(key)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := LoadXHTTPPath(key); err != nil || again != first {
		t.Errorf("the path of a second run: %q, %v; the first was %q", again, err, first)
	}
	if _, err := LoadCert(key); err != nil {
		t.Errorf("the key file after the path: %v", err)
	}
	stderr.Reset()
	// REALITY is gone: an old command line stops rather than running
	// without the VLESS it asked for.
	args := []string{"-key", key, "-state", "none", "-vless-site", "www.example.com"}
	if code := Command(args, &stdout, &stderr, ""); code != 2 || !strings.Contains(stderr.String(), "vless-site") {
		t.Errorf("-vless-site: %d, %q", code, stderr.String())
	}
}
