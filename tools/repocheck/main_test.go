// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const header = "// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 HunterEwok\n\n"

// copied is the start of a Go file copied from another project.
const copied = "// Copyright 2026 The Go Authors. All rights reserved.\n// Use of this source code is governed by a BSD-style\n// license that can be found in the LICENSE file.\n\npackage cpace\n"

// cyrillicWord is a Russian word, written with escapes so that this file
// itself stays free of Cyrillic letters.
const cyrillicWord = "\u043f\u0440\u0438\u0432\u0435\u0442"

func TestCheck(t *testing.T) {
	tests := []struct {
		name, file, content string
		// The problems must contain these strings, in order; none means no problems.
		want []string
	}{
		{name: "English text", file: "README.md", content: "# cbb\n\nOne clipboard.\n"},
		{name: "symbols are fine", file: "docs/design.md", content: "Mac \u2192 Linux, 10\u201320 s, \u2318C\n"},
		{
			name: "Cyrillic text", file: "docs/notes.md", content: "line one\n" + cyrillicWord + "\n",
			want: []string{"docs/notes.md:2: Cyrillic letter"},
		},
		{
			name: "two Cyrillic lines", file: "a.txt", content: cyrillicWord + "\nok\n" + cyrillicWord,
			want: []string{"a.txt:1:", "a.txt:3:"},
		},
		{name: "binary file", file: "logo.png", content: "\x89PNG\x00\x00" + cyrillicWord},
		{name: "an ELF program", file: "forge", content: "\x7fELF\x02\x01\x01\x00", want: []string{"forge:1: a compiled program (ELF)"}},
		{name: "a Mach-O program", file: "cbb", content: "\xcf\xfa\xed\xfe\x0c\x00\x00\x01", want: []string{"cbb:1: a compiled program (Mach-O)"}},
		{name: "a universal Mach-O program", file: "cbb", content: "\xca\xfe\xba\xbe\x00\x00\x00\x02", want: []string{"cbb:1: a compiled program (Mach-O)"}},
		{name: "a WebAssembly module", file: "internal/core/cbb_core.wasm", content: "\x00asm\x01\x00\x00\x00\x01", want: []string{"internal/core/cbb_core.wasm:1: a compiled program (WebAssembly)"}},
		{name: "a Java class", file: "A.class", content: "\xca\xfe\xba\xbe\x00\x00\x00\x41"},
		{name: "a PE program", file: "cbb.exe", content: "MZ" + strings.Repeat("\x00", 0x3a) + "\x40\x00\x00\x00PE\x00\x00", want: []string{"cbb.exe:1: a compiled program (PE)"}},
		{name: "text starting with MZ", file: "notes.txt", content: "MZ is a prefix\n"},
		{name: "a large file", file: "big.png", content: "\x89PNG" + strings.Repeat("\x00", 1<<20), want: []string{"big.png:1: 1048580 bytes, over the limit"}},
		{name: "a String Catalog", file: "apps/ios/CBB/Resources/Localizable.xcstrings", content: `{"ru":"` + cyrillicWord + `"}`},
		{name: "an Android translation", file: "apps/android/app/src/main/res/values-ru/strings.xml", content: "<string>" + cyrillicWord + "</string>\n"},
		{
			name: "the default Android strings", file: "apps/android/app/src/main/res/values/strings.xml", content: "<string>" + cyrillicWord + "</string>\n",
			want: []string{"strings.xml:1: Cyrillic letter"},
		},
		{name: "an Aurora app translation", file: "apps/silica/translations/cbb-ru.ts", content: "<translation>" + cyrillicWord + "</translation>\n"},
		{name: "a tray app translation", file: "apps/desktop/frontend/l10n/ru.json", content: `{"Fetch":"` + cyrillicWord + `"}`},
		{name: "a website translation", file: "site/l10n/ru.json", content: `{"Download":"` + cyrillicWord + `"}`},
		{name: "a translated guide page", file: "site/docs/ru/guide/keys.md", content: cyrillicWord + "\n"},
		{name: "a translated picture", file: "docs/images/ru/group.svg", content: "<text>" + cyrillicWord + "</text>\n"},
		{name: "the texts of the pictures", file: "tools/diagrams/l10n/ru.json", content: `{"Phone":"` + cyrillicWord + `"}`},
		{name: "a store translation", file: "apps/android/app/fastlane/metadata/android/ru-RU/full_description.txt", content: cyrillicWord + "\n"},
		{
			name: "the English store text", file: "apps/android/app/fastlane/metadata/android/en-US/title.txt", content: cyrillicWord + "\n",
			want: []string{"title.txt:1: Cyrillic letter"},
		},
		{
			name: "the tray app's script", file: "apps/desktop/frontend/app.js", content: `t("` + cyrillicWord + `")`,
			want: []string{"app.js:1: Cyrillic letter"},
		},
		{name: "Go file with the header", file: "x.go", content: header + "package x\n"},
		{name: "header with a year range", file: "x.go", content: strings.Replace(header, "2026", "2026-2027", 1) + "package x\n"},
		{name: "header with CRLF line ends", file: "x.go", content: strings.ReplaceAll(header, "\n", "\r\n") + "package x\r\n"},
		{
			name: "Go file without a header", file: "x.go", content: "package x\n",
			want: []string{"x.go:1: missing license header"},
		},
		{
			name: "another license", file: "x.go", content: strings.Replace(header, "AGPL-3.0-only", "MIT", 1) + "package x\n",
			want: []string{"x.go:1: missing license header"},
		},
		{
			name: "another copyright holder", file: "x.go", content: strings.Replace(header, "HunterEwok", "Someone", 1) + "package x\n",
			want: []string{"x.go:1: missing license header"},
		},
		{
			name: "one line only", file: "x.go", content: "// SPDX-License-Identifier: AGPL-3.0-only",
			want: []string{"x.go:1: missing license header"},
		},
		{name: "generated Go file", file: "gen.go", content: "// Code generated by wayland-scanner. DO NOT EDIT.\n\npackage gen\n"},
		{name: "generated marker on a later line before the package clause", file: "gen.go", content: "// Package gen is generated.\n//\n// Code generated by stringer. DO NOT EDIT.\n\npackage gen\n"},
		{
			name: "generated marker after the package clause", file: "x.go", content: "package x\n\n// Code generated by hand. DO NOT EDIT.\n",
			want: []string{"x.go:1: missing license header"},
		},
		{
			name: "generated marker inside a string", file: "x.go", content: "package x\n\nconst tmpl = `\n// Code generated by tool. DO NOT EDIT.\n`\n",
			want: []string{"x.go:1: missing license header"},
		},
		{name: "header rule is for Go only", file: "script.sh", content: "#!/bin/sh\necho ok\n"},
		{
			name: "both rules", file: "x.go", content: "package x\n\n// " + cyrillicWord + "\n",
			want: []string{"x.go:3: Cyrillic letter", "x.go:1: missing license header"},
		},
		{name: "copied code", file: "internal/third_party/cpace/cpace.go", content: copied},
		{name: "copied code in a subdirectory", file: "internal/third_party/cpace/sub/x.go", content: copied},
		{
			name: "copied code without a license", file: "internal/third_party/other/x.go", content: copied,
			want: []string{"internal/third_party/other/x.go:1: copied code without internal/third_party/other/LICENSE"},
		},
		{
			name: "copied code without its notice", file: "internal/third_party/cpace/x.go", content: "package cpace\n",
			want: []string{"internal/third_party/cpace/x.go:1: copied code must keep its copyright notice"},
		},
		{
			name: "Cyrillic in copied code", file: "internal/third_party/cpace/x.go", content: copied + "// " + cyrillicWord + "\n",
			want: []string{"internal/third_party/cpace/x.go:6: Cyrillic letter"},
		},
		{
			name: "generated copied code without a license", file: "internal/third_party/gen/x.go", content: "// Code generated by tool. DO NOT EDIT.\n\npackage gen\n",
			want: []string{"internal/third_party/gen/x.go:1: copied code without internal/third_party/gen/LICENSE"},
		},
		{name: "generated copied code with a license", file: "internal/third_party/cpace/gen.go", content: "// Code generated by tool. DO NOT EDIT.\n\npackage cpace\n"},
		{
			name: "a file directly in third_party is the project's own", file: "internal/third_party/x.go", content: copied,
			want: []string{"internal/third_party/x.go:1: missing license header"},
		},
		{
			name: "a directory named like third_party", file: "my_third_party/x/y.go", content: copied,
			want: []string{"my_third_party/x/y.go:1: missing license header"},
		},
		{name: "Rust file with the header", file: "member/src/main.rs", content: header + "fn main() {}\n"},
		{
			name: "Rust file without a header", file: "member/src/x.rs", content: "fn main() {}\n",
			want: []string{"member/src/x.rs:1: missing license header"},
		},
		{
			name: "a Rust file is never taken as generated", file: "x.rs", content: "// Code generated by tool. DO NOT EDIT.\n\nfn f() {}\n",
			want: []string{"x.rs:1: missing license header"},
		},
		{name: "copied Rust code", file: "internal/third_party/cpace/mod.rs", content: copied},
		{
			name: "copied Rust code without its notice", file: "internal/third_party/cpace/x.rs", content: "fn f() {}\n",
			want: []string{"x.rs:1: copied code must keep its copyright notice"},
		},
	}
	listed := map[string]bool{"internal/third_party/cpace/LICENSE": true}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := check(tt.file, []byte(tt.content), listed)
			if len(got) != len(tt.want) {
				t.Fatalf("check() = %q, want %d problem(s) containing %q", got, len(tt.want), tt.want)
			}
			for i, want := range tt.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], want)
				}
			}
		})
	}
}

func TestCheckRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(repo, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	runGit("init", "-q")
	write("README.md", "# English\n")
	write("sub/ok.go", header+"package sub\n")
	write("third_party/pkg/LICENSE", "BSD\n")
	write("third_party/pkg/pkg.go", copied)
	write("third_party/gone/LICENSE", "BSD\n")
	write("third_party/gone/gone.go", copied)
	write("deleted.md", "removed below\n")
	write(".gitignore", "ignored.md\n")
	runGit("add", "-A")
	runGit("-c", "user.name=test", "-c", "user.email=test@example.org", "commit", "-q", "-m", "initial")

	// A deletion that is not committed yet is skipped, not reported.
	if err := os.Remove(filepath.Join(repo, "deleted.md")); err != nil {
		t.Fatal(err)
	}
	// A copied package whose LICENSE was deleted in the working tree is
	// reported, even though git still lists the LICENSE.
	if err := os.Remove(filepath.Join(repo, "third_party/gone/LICENSE")); err != nil {
		t.Fatal(err)
	}
	// New files are checked before they are committed; ignored files are not.
	write("sub/new.md", "line\n"+cyrillicWord+"\n")
	write("sub/noheader.go", "package sub\n")
	write("ignored.md", cyrillicWord+"\n")
	// A symbolic link is checked by its target path, not by the target's content.
	if err := os.Symlink(cyrillicWord+".txt", filepath.Join(repo, "link")); err != nil {
		t.Fatal(err)
	}

	// Run from a subdirectory: the whole repository must be checked.
	t.Chdir(filepath.Join(repo, "sub"))
	problems, checked, err := checkRepo("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"link:1: Cyrillic letter", "sub/new.md:2: Cyrillic letter", "sub/noheader.go:1: missing license header",
		"third_party/gone/gone.go:1: copied code without third_party/gone/LICENSE"}
	if len(problems) != len(want) {
		t.Fatalf("checkRepo() problems = %q, want %d containing %q", problems, len(want), want)
	}
	for i, w := range want {
		if !strings.Contains(problems[i], w) {
			t.Errorf("problem %d = %q, want it to contain %q", i, problems[i], w)
		}
	}
	// .gitignore, README.md, link, sub/new.md, sub/noheader.go, sub/ok.go,
	// third_party/pkg/LICENSE, third_party/pkg/pkg.go, third_party/gone/gone.go
	if checked != 9 {
		t.Errorf("checked = %d files, want 9", checked)
	}
}
