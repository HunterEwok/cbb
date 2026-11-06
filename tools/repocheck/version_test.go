// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
)

func TestCheckAndroidVersion(t *testing.T) {
	const changelog = "# Changelog\n\n## [Unreleased]\n\n## [0.12.3] - 2026-12-01\n\n## [0.5.0] - 2026-10-26\n"
	tests := []struct {
		name       string
		properties string
		changelog  string
		want       []string
	}{
		{name: "the last release", properties: "# comment\nversionName=0.12.3\nversionCode=1203\n", changelog: changelog},
		{name: "an older release", properties: "versionName=0.5.0\nversionCode=500\n", changelog: changelog, want: []string{`versionName is "0.5.0", the last release in CHANGELOG.md is 0.12.3`, `versionCode is "500", want 1203`}},
		{name: "a wrong code", properties: "versionName=0.12.3\nversionCode=123\n", changelog: changelog, want: []string{`versionCode is "123", want 1203`}},
		{name: "no release yet", properties: "versionName=0.1.0\nversionCode=100\n", changelog: "# Changelog\n\n## [Unreleased]\n", want: []string{"no released version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkAndroidVersion(map[string][]byte{androidVersion: []byte(tt.properties), "CHANGELOG.md": []byte(tt.changelog)})
			if len(got) != len(tt.want) {
				t.Fatalf("got %q, want %d problem(s)", got, len(tt.want))
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], w)
				}
			}
		})
	}
	if got := checkAndroidVersion(map[string][]byte{"CHANGELOG.md": []byte(changelog)}); got != nil {
		t.Errorf("without the file: %q", got)
	}
}

func TestCheckSpecVersions(t *testing.T) {
	const changelog = "# Changelog\n\n## [Unreleased]\n\n## [0.12.3] - 2026-12-01\n"
	const spec = "apps/silica/packaging/aurora5/tools.cbb.aurora.spec"
	tests := []struct {
		name string
		spec string
		want string
	}{
		{name: "the last release", spec: "Name: x\nVersion:    0.12.3\nRelease: 1\n"},
		{name: "the next release", spec: "Version: 0.13.0\n", want: `Version is "0.13.0", the last release in CHANGELOG.md is 0.12.3`},
		{name: "no version", spec: "Name: x\n", want: "no Version line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSpecVersions(map[string][]byte{spec: []byte(tt.spec), "CHANGELOG.md": []byte(changelog)})
			if tt.want == "" {
				if got != nil {
					t.Fatalf("got %q", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tt.want) {
				t.Fatalf("got %q, want one problem containing %q", got, tt.want)
			}
		})
	}
	if got := checkSpecVersions(map[string][]byte{"CHANGELOG.md": []byte(changelog)}); got != nil {
		t.Errorf("without a spec: %q", got)
	}
}
