// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestProjectAddresses checks the copies of the update servers' addresses
// that the Android app, the installers and release-sign carry against
// cbb's own (member/src/update.rs): a build of its own changes them all
// (docs/own-build.md), and a copy left behind would update it from this
// project's releases.
func TestProjectAddresses(t *testing.T) {
	read := func(file string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		// A Windows checkout may end its lines in CR LF.
		return strings.ReplaceAll(string(data), "\r\n", "\n")
	}
	cbb := read("member/src/update.rs")
	constant := func(name string) string {
		m := regexp.MustCompile(`const ` + name + `: &str = "([^"]+)";`).FindStringSubmatch(cbb)
		if m == nil {
			t.Fatalf("member/src/update.rs: no %s", name)
		}
		return m[1]
	}
	github, mirror, channelFiles := constant("GITHUB"), constant("MIRROR"), constant("CHANNEL_FILES")
	repo := strings.TrimSuffix(github, "/releases")
	slug := strings.TrimPrefix(repo, "https://github.com/")
	if repo == github || slug == repo {
		t.Fatalf("GITHUB %s is not the releases of a GitHub repository", github)
	}
	for file, want := range map[string][]string{
		"apps/android/app/src/main/kotlin/tools/cbb/ApkUpdate.kt": {
			`private const val GITHUB = "` + github + `"`,
			`private const val MIRROR = "` + mirror + `"`,
			`private const val CHANNEL_FILES = "` + channelFiles + `"`,
		},
		"packaging/get.sh": {
			"\nrepo=" + repo + "\n",
			"\nchannel_files=" + channelFiles + "\n",
			"--repo " + slug + " ",
		},
		"packaging/windows/get.ps1": {
			"$repo = '" + repo + "'",
			"$channelFiles = '" + channelFiles + "'",
			"'--repo', '" + slug + "'",
		},
		"tools/release-sign/publish.go": {
			`const defaultRepo = "` + slug + `"`,
		},
	} {
		text := read(file)
		for _, w := range want {
			if !strings.Contains(text, w) {
				t.Errorf("%s: no %q", file, w)
			}
		}
	}
	if channelFiles != "https://raw.githubusercontent.com/"+slug+"/channel" {
		t.Errorf("CHANNEL_FILES %s is not the branch channel of %s", channelFiles, slug)
	}
}
