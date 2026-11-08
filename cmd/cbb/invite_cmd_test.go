// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
)

// TestInvite writes the invitation to a file of its own, asks before each
// device that uses it, and deletes the file at the end.
func TestInvite(t *testing.T) {
	out := filepath.Join(t.TempDir(), "guest.cbb")
	var seen []byte // what the invitation file held while it was open
	answers := make(chan *control.Message, 2)
	got := fakeHandler(t, func(m *control.Message, r *control.Reader, c net.Conn) {
		if m.Op != control.OpInvite {
			return
		}
		answer(c, control.Message{Header: control.Header{Invite: "the-invitation", Expires: 3600}})
		j := &control.Joining{ID: "0123456789abcdef", Name: "stranger", OS: "linux", Fingerprint: "sha256:00112233445566778899"}
		for range 2 {
			answer(c, control.Message{Header: control.Header{Joining: j}})
			a, err := r.Read()
			if err != nil {
				return
			}
			if seen == nil {
				// The command wrote the file before it read what came.
				seen, _ = os.ReadFile(out)
			}
			answers <- a
		}
		answer(c, control.Message{Header: control.Header{Name: "stranger", Done: true}})
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"invite", "-for", "2h", "-o", out}, strings.NewReader("no\nyes\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("invite: %d, %s", code, stderr.String())
	}
	if m := request(t, got); m.Op != control.OpInvite || m.Expires != 7200 {
		t.Errorf("invite sent %+v", m.Header)
	}
	if m := request(t, answers); m.Op != control.OpAnswer || m.Consent {
		t.Errorf("the first answer, no, sent %+v", m.Header)
	}
	if m := request(t, answers); m.Op != control.OpAnswer || !m.Consent {
		t.Errorf("the second answer, yes, sent %+v", m.Header)
	}
	if string(seen) != "the-invitation\n" {
		t.Errorf("the invitation file held %q", seen)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the invitation file is still there: %v", err)
	}
	for _, want := range []string{"cbb pair -invite " + out, "stranger (Linux, device 0123456789abcdef) used the invitation", "Not admitted.", "stranger joined the group."} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("no %q in\n%s", want, stdout.String())
		}
	}
}

func TestInviteRefusals(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "taken.cbb")
	if err := os.WriteFile(existing, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCommandCases(t, []commandCase{
		{name: "more than a day", args: []string{"invite", "-for", "25h"}, code: 2, stderr: "valid for up to 24h"},
		{name: "no time", args: []string{"invite", "-for", "0s"}, code: 2},
		{name: "an argument", args: []string{"invite", "x"}, code: 2},
		{name: "refused", args: []string{"invite"}, answer: control.Header{Error: "only an admin invites"}, check: sent(control.OpInvite, nil), code: 1, stderr: "only an admin invites"},
		// A file already there is never overwritten.
		{name: "the file is there", args: []string{"invite", "-o", existing}, answer: control.Header{Invite: "x", Expires: 60},
			check: sent(control.OpInvite, nil), code: 1, stderr: "writing the invitation"},
	})
	if b, _ := os.ReadFile(existing); string(b) != "mine" {
		t.Errorf("the file there became %q", b)
	}
}

func TestConfigCommand(t *testing.T) {
	media := control.Header{Status: &control.Status{Media: &control.Media{MaxCopy: 200 << 20, MaxCopyAway: 20 << 20}}}
	runCommandCases(t, []commandCase{
		{name: "show", args: []string{"config"}, answer: media, check: sent(control.OpConfig, func(m *control.Message) bool { return m.Name == "" && m.Value == "" }),
			stdout: "max-copy       200 MiB"},
		{name: "set", args: []string{"config", "max-copy-away", "20MiB"}, answer: media,
			check: sent(control.OpConfig, func(m *control.Message) bool { return m.Name == "max-copy-away" && m.Value == "20MiB" }), stdout: "max-copy-away  20 MiB"},
		{name: "in no group", args: []string{"config"}, check: sent(control.OpConfig, nil), code: 1, stderr: "in no group"},
		{name: "refused", args: []string{"config", "max-copy", "lots"}, answer: control.Header{Error: "not a size"}, check: sent(control.OpConfig, nil), code: 1, stderr: "not a size"},
		{name: "one argument", args: []string{"config", "max-copy"}, code: 2, stderr: "usage: cbb config"},
	})
}

// TestServerKeys: cbb relay and cbb forward make their keys on the first
// run, keep them, and print the pin users give the hub.
func TestServerKeys(t *testing.T) {
	for _, server := range []string{"relay", "forward"} {
		t.Run(server, func(t *testing.T) {
			key := filepath.Join(t.TempDir(), server+".pem")
			var pins []string
			for range 2 {
				var stdout, stderr bytes.Buffer
				if code := run([]string{server, "-key", key, "-show-key"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
					t.Fatalf("%s -show-key: %d, %s", server, code, stderr.String())
				}
				pins = append(pins, strings.TrimSpace(stdout.String()))
			}
			if pins[0] == "" || pins[0] != pins[1] {
				t.Errorf("the pins of two runs: %q", pins)
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{server, "extra"}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "takes only flags") {
				t.Errorf("%s with an argument: %d, %q", server, code, stderr.String())
			}
			bad := filepath.Join(t.TempDir(), "bad.pem")
			if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
				t.Fatal(err)
			}
			stderr.Reset()
			if code := run([]string{server, "-key", bad, "-show-key"}, strings.NewReader(""), &stdout, &stderr); code != 1 || stderr.Len() == 0 {
				t.Errorf("%s with a damaged key: %d, %q", server, code, stderr.String())
			}
		})
	}
}

// TestForwardXHTTPPath: cbb forward makes the path of its XHTTP once and
// keeps it in the key file, and takes one transport of VLESS at a time.
func TestForwardXHTTPPath(t *testing.T) {
	key := filepath.Join(t.TempDir(), "forward.pem")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"forward", "-key", key, "-show-key"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("forward -show-key: %d, %s", code, stderr.String())
	}
	first, err := forward.LoadXHTTPPath(key)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := forward.LoadXHTTPPath(key); err != nil || again != first {
		t.Errorf("the path of a second run: %q, %v; the first was %q", again, err, first)
	}
	if _, err := forward.LoadCert(key); err != nil {
		t.Errorf("the key file after the path: %v", err)
	}
	stderr.Reset()
	if code := run([]string{"forward", "-key", key, "-vless-site", "www.example.com", "-vless-xhttp", "cbb.tools"}, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "not both") {
		t.Errorf("both transports: %d, %q", code, stderr.String())
	}
}

// TestUpdateUsage: the flags of cbb update that are refused before it looks
// at anything on the system.
func TestUpdateUsage(t *testing.T) {
	runCommandCases(t, []commandCase{
		{name: "unknown flag", args: []string{"update", "-now"}, code: 2, stderr: "usage: cbb update"},
		{name: "-to without a version", args: []string{"update", "-to"}, code: 2, stderr: "-to needs a version"},
		{name: "-auto maybe", args: []string{"update", "-auto", "maybe"}, code: 2, stderr: "-auto takes on or off"},
		{name: "-installed-by a stranger", args: []string{"update", "-installed-by", "snap"}, code: 2, stderr: "-installed-by takes get"},
		{name: "two modes", args: []string{"update", "-check", "-auto", "on"}, code: 2, stderr: "usage: cbb update"},
		{name: "check and timer", args: []string{"update", "-check", "-timer"}, code: 2, stderr: "usage: cbb update"},
		{name: "mirror and to", args: []string{"update", "-mirror", "-to", "0.6.1"}, code: 2, stderr: "usage: cbb update"},
	})
}
