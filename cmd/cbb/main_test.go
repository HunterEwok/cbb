// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		// The output must contain these strings; an empty string means no output.
		stdout, stderr string
	}{
		{name: "no command", args: nil, code: 2, stderr: "Usage: cbb"},
		{name: "version", args: []string{"version"}, code: 0, stdout: "cbb "},
		{name: "version flag", args: []string{"--version"}, code: 0, stdout: "cbb "},
		{name: "version with an argument", args: []string{"version", "extra"}, code: 2, stderr: "takes no arguments"},
		{name: "help", args: []string{"help"}, code: 0, stdout: "Usage: cbb"},
		{name: "help flag", args: []string{"-h"}, code: 0, stdout: "Usage: cbb"},
		{name: "unknown command", args: []string{"frobnicate"}, code: 2, stderr: `unknown command "frobnicate"`},
		{name: "remove -h", args: []string{"remove", "-h"}, code: 2, stderr: "usage: cbb remove"},
		{name: "takeover -h", args: []string{"takeover", "-help"}, code: 2, stderr: "usage: cbb takeover"},
		{name: "freeze -h", args: []string{"freeze", "--help"}, code: 2, stderr: "usage: cbb freeze"},
		{name: "unfreeze -h", args: []string{"unfreeze", "-h"}, code: 2, stderr: "usage: cbb unfreeze"},
		{name: "holder -h", args: []string{"holder", "-h"}, code: 2, stderr: "usage: cbb holder"},
		{name: "service with an argument", args: []string{"service", "extra"}, code: 2, stderr: "takes only flags"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, strings.NewReader(""), &stdout, &stderr); code != tt.code {
				t.Errorf("exit code = %d, want %d", code, tt.code)
			}
			checkOutput(t, "stdout", stdout.String(), tt.stdout)
			checkOutput(t, "stderr", stderr.String(), tt.stderr)
		})
	}
}

func checkOutput(t *testing.T, stream, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want no output", stream, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s = %q, want it to contain %q", stream, got, want)
	}
}
