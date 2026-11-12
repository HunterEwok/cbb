// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
)

// installerCatalogs returns a catalog for each of the project's languages
// with the same lines.
func installerCatalogs(lines string) map[string][]byte {
	c := map[string][]byte{}
	for _, l := range installerLanguages {
		c["packaging/l10n/"+l+".tsv"] = []byte(lines)
	}
	return c
}

func TestCheckInstallerL10n(t *testing.T) {
	const script = "packaging/linux/install.sh"
	const lib = ". \"$cbb_l10n.sh\"\n"
	tests := []struct {
		name    string
		files   map[string]string
		catalog string
		want    []string // substrings of the problems, in order; none means no problems
	}{
		{
			name:    "translated",
			files:   map[string]string{script: lib + "say \"Starting on port %s\" \"$port\"\nfail 'run it as root'\n"},
			catalog: "Starting on port %s\tX %s\nrun it as root\tY\n",
		},
		{
			name:    "PowerShell",
			files:   map[string]string{"packaging/windows/install.ps1": ". (Join-Path $PSScriptRoot 'l10n.ps1')\nWrite-Host (T 'It''s %s' $x)\nWrite-Host (T -Text 'At %s %s' $x $y)\n"},
			catalog: "It's %s\tX %s\nAt %s %s\tY %s %s\n",
		},
		{
			name:  "a script without the library is not checked",
			files: map[string]string{"packaging/other.sh": "say \"Hello\"\n"},
		},
		{
			name:  "a forwarded text is not a text",
			files: map[string]string{script: lib + "fail() { say \"$@\"; }\n"},
		},
		{
			name:  "a variable in a text",
			files: map[string]string{script: lib + "say \"port $port\"\n"},
			want:  []string{script + ":2: a translated text names a variable"},
		},
		{
			name:  "a directive other than %s",
			files: map[string]string{script: lib + "say \"%d files\" 3\n"},
			want:  []string{script + ":2: the directive %d"},
		},
		{
			name:    "missing from the catalogs",
			files:   map[string]string{script: lib + "say \"Done\"\n"},
			catalog: "",
			want:    []string{"packaging/l10n/ar.tsv: no translation of the text at " + script + ":2"},
		},
		{
			name:    "a stale catalog line",
			files:   map[string]string{script: lib + "say \"Done\"\n"},
			catalog: "Done\tX\nGone\tY\n",
			want:    []string{"packaging/l10n/ar.tsv:2: no script says \"Gone\""},
		},
		{
			name:    "a different count of %s",
			files:   map[string]string{script: lib + "say \"At %s\" \"$x\"\n"},
			catalog: "At %s\tX\n",
			want:    []string{"packaging/l10n/ar.tsv:1: 0 %s in the translation and 1 in the English text"},
		},
		{
			name:    "translated twice",
			files:   map[string]string{script: lib + "say \"Done\"\n"},
			catalog: "Done\tX\nDone\tY\n",
			want:    []string{"packaging/l10n/ar.tsv:2: the text is translated twice"},
		},
		{
			name:    "a line without a tab",
			files:   map[string]string{script: lib + "say \"Done\"\n"},
			catalog: "Done\tX\nbroken\n",
			want:    []string{"packaging/l10n/ar.tsv:2: a line is the English text, one tab and its translation"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents := installerCatalogs(tt.catalog)
			for name, data := range tt.files {
				contents[name] = []byte(data)
			}
			problems := checkInstallerL10n(contents)
			all := strings.Join(problems, "\n")
			if len(tt.want) == 0 {
				if len(problems) != 0 {
					t.Fatalf("problems:\n%s", all)
				}
				return
			}
			rest := all
			for _, w := range tt.want {
				i := strings.Index(rest, w)
				if i < 0 {
					t.Fatalf("problems do not contain %q (in order):\n%s", w, all)
				}
				rest = rest[i+len(w):]
			}
		})
	}
}

func TestCheckInstallerL10nLanguages(t *testing.T) {
	contents := installerCatalogs("")
	contents["packaging/l10n/xx.tsv"] = nil
	delete(contents, "packaging/l10n/sw.tsv")
	problems := strings.Join(checkInstallerL10n(contents), "\n")
	if !strings.Contains(problems, "not for the project's languages") {
		t.Fatalf("a missing catalog is not reported:\n%s", problems)
	}
}

func TestCheckAppStrings(t *testing.T) {
	if got := checkAppStrings(map[string][]byte{"README.md": nil}); got != nil {
		t.Errorf("a tree without apps/l10n: %q", got)
	}
	contents := map[string][]byte{"apps/l10n/en.json": []byte(`{"Paste": {"in": ["tray"]}}`)}
	for _, l := range installerLanguages {
		contents["apps/l10n/"+l+".json"] = []byte(`{"Paste": "` + l + `"}`)
	}
	src := checkAppStrings(contents)
	if len(src) == 0 || !strings.Contains(strings.Join(src, "\n"), "apps/desktop/frontend/l10n/ru.json:1: not what tools/strings makes") {
		t.Fatalf("a missing generated file: %q", src)
	}
	contents["apps/l10n/ru.json"] = []byte(`{}`)
	if got := strings.Join(checkAppStrings(contents), "\n"); !strings.Contains(got, `no translation of "Paste"`) {
		t.Errorf("a missing translation: %q", got)
	}
}
