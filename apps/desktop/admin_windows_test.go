// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Every argument is a literal: a name with quotes and $ runs nothing.
func TestPSScript(t *testing.T) {
	s := psScript(`C:\Program Files\cbb\cbb.exe`, []string{"rename", "ab12", "Bob's $(x)"}, "", true, `C:\T\o.txt`)
	want := "$env:CBB_DEBUG = '1'\n& 'C:\\Program Files\\cbb\\cbb.exe' 'rename' 'ab12' 'Bob''s $(x)' *> 'C:\\T\\o.txt'\nexit $LASTEXITCODE\n"
	if s != want {
		t.Errorf("psScript =\n%s\nwant\n%s", s, want)
	}
	if s := psScript("cbb", []string{"global", "on"}, `C:\T\i.txt`, false, "o"); !strings.HasPrefix(s, `Get-Content -Raw -LiteralPath 'C:\T\i.txt' | & 'cbb'`) {
		t.Errorf("with input: %q", s)
	}
}

// PowerShell runs the encoded script as written, and a name with any of
// its single quotes stays one literal.
func TestEncodePS(t *testing.T) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePS("$x = 'no'; Write-Output 'Bob''s $x'")).Output()
	if err != nil {
		t.Skip("no powershell:", err)
	}
	if got := strings.TrimSpace(string(out)); got != "Bob's $x" {
		t.Errorf("powershell printed %q", got)
	}
	name := "a\u2018; Write-Output pwned; \u2019b\u201a\u201b'"
	out, err = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePS("[Console]::OutputEncoding = [Text.Encoding]::UTF8; Write-Output "+psQuote(name))).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != name {
		t.Errorf("powershell printed %q, want %q", got, name)
	}
}

// Each of PowerShell's single quotes is doubled.
func TestPSQuote(t *testing.T) {
	if got, want := psQuote("a\u2018b\u2019c\u201ad\u201be'f"), "'a\u2018\u2018b\u2019\u2019c\u201a\u201ad\u201b\u201be''f'"; got != want {
		t.Errorf("psQuote = %q, want %q", got, want)
	}
}

// The elevated PowerShell is the system's own, by its full path.
func TestPowershellFromTheSystem(t *testing.T) {
	p, err := powershellPath()
	if err != nil {
		t.Fatal(err)
	}
	sys, _ := windows.GetSystemDirectory()
	if !filepath.IsAbs(p) || !strings.EqualFold(p, filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")) {
		t.Fatalf("%s", p)
	}
}
