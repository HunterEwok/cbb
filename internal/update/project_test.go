// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProjectAddresses checks the copies of the update servers' addresses
// that the lite member, the Android app, the installers and release-sign
// carry: a build of its own changes them all (docs/own-build.md), and a
// copy left behind would update it from this project's releases.
func TestProjectAddresses(t *testing.T) {
	repo := strings.TrimSuffix(GitHub, "/releases")
	slug := strings.TrimPrefix(repo, "https://github.com/")
	for file, want := range map[string][]string{
		"member/src/update.rs": {
			`const GITHUB: &str = "` + GitHub + `";`,
			`pub const MIRROR: &str = "` + Mirror + `";`,
			`const CHANNEL_FILES: &str = "` + ChannelFiles + `";`,
		},
		"apps/android/app/src/main/kotlin/tools/cbb/ApkUpdate.kt": {
			`private const val GITHUB = "` + GitHub + `"`,
			`private const val MIRROR = "` + Mirror + `"`,
			`private const val CHANNEL_FILES = "` + ChannelFiles + `"`,
		},
		"packaging/get.sh": {
			"\nrepo=" + repo + "\n",
			"\nchannel_files=" + ChannelFiles + "\n",
			"--repo " + slug + " ",
		},
		"packaging/windows/get.ps1": {
			"$repo = '" + repo + "'",
			"$channelFiles = '" + ChannelFiles + "'",
			"'--repo', '" + slug + "'",
		},
		"tools/release-sign/publish.go": {
			`const defaultRepo = "` + slug + `"`,
		},
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		// A Windows checkout may end its lines in CR LF.
		text := strings.ReplaceAll(string(data), "\r\n", "\n")
		for _, w := range want {
			if !strings.Contains(text, w) {
				t.Errorf("%s: no %q", file, w)
			}
		}
	}
	if ChannelFiles != "https://raw.githubusercontent.com/"+slug+"/channel" {
		t.Errorf("ChannelFiles %s is not the branch channel of %s", ChannelFiles, slug)
	}
}
