// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
)

func TestCheckDocs(t *testing.T) {
	files := map[string][]byte{
		"README.md":          []byte("# Read me\n"),
		"docs/design.md":     []byte("# Design\n\n## The iPhone button\n\n## Sync away from home (planned)\n\n## Notes\n\n## Notes\n\n```sh\n# not a heading\n```\n"),
		"member/src/main.rs": []byte("fn main() {}\n"),
	}
	tests := []struct {
		name, file, content string
		want                []string
	}{
		{name: "a file", file: "docs/a.md", content: "[d](design.md) [r](../README.md) [l](../member/src/main.rs)\n"},
		{name: "a directory", file: "README.md", content: "[core](member/src/)\n"},
		{name: "web and mail links", file: "README.md", content: "[w](https://example.org/x.md) [m](mailto:a@example.org)\n"},
		{name: "anchors", file: "docs/a.md", content: "[a](design.md#the-iphone-button) [b](design.md#sync-away-from-home-planned) [c](design.md#notes-1)\n"},
		{name: "an anchor in the same file", file: "docs/design.md", content: "# Design\n\n## Build\n\nSee [build](#build).\n"},
		{
			name: "a missing file", file: "docs/a.md", content: "ok\n[x](missing.md)\n",
			want: []string{"docs/a.md:2: link to missing.md, which is not in the repository"},
		},
		{
			name: "a missing anchor", file: "docs/a.md", content: "[x](design.md#roadmap)\n",
			want: []string{"docs/a.md:1: link to design.md#roadmap: docs/design.md has no heading for #roadmap"},
		},
		{
			name: "a heading inside code", file: "docs/a.md", content: "[x](design.md#not-a-heading)\n",
			want: []string{"has no heading for #not-a-heading"},
		},
		{name: "a translated page keeps its original's links", file: "site/docs/ru/guide/a.md", content: "[x](design.md#roadmap) [y](missing.md)\n"},
		{name: "not Markdown", file: "a.sh", content: "# [x](missing.md)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			all := map[string][]byte{tt.file: []byte(tt.content)}
			for k, v := range files {
				if _, ok := all[k]; !ok {
					all[k] = v
				}
			}
			got := checkDocs(tt.file, []byte(tt.content), all)
			if len(got) != len(tt.want) {
				t.Fatalf("checkDocs() = %q, want %d problems containing %q", got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], w)
				}
			}
		})
	}
}

// TestCheckOldName finds the old names in every spelling and in any file,
// the changelog and code included, and leaves the new name alone.
func TestCheckOldName(t *testing.T) {
	short, long := "clip"+"bridge", "Clip"+"board "+"Bridge"
	for _, c := range []struct {
		file, content string
		want          int
	}{
		{"docs/a.md", "Run " + short + " join.\n", 1},
		{"docs/a.md", "Install " + long + ".\n", 1},
		{"CHANGELOG.md", "x\n" + short + " is gone.\n", 1},
		{"docs/a.md", "```sh\nrm -rf /var/lib/" + strings.ToLower(strings.ReplaceAll(long, " ", "")) + "\n```\n", 1},
		{"a.go", "import \"github.com/HunterEwok/" + strings.ToLower(strings.ReplaceAll(long, " ", "")) + "/x\"\n", 1},
		{"a.swift", "import " + strings.ReplaceAll(long, " ", "") + "Kit\n", 1},
		{"a.kt", strings.ToLower(strings.ReplaceAll(long, " ", "_")) + "\n", 1},
		{"docs/a.md", "Copy Beyond Borders, `cbb`, cbb.local, CBBKit and a clipboard.\n", 0},
	} {
		got := checkOldName(c.file, []byte(c.content))
		if len(got) != c.want {
			t.Errorf("checkOldName(%q, %q) = %q, want %d problems", c.file, c.content, got, c.want)
		}
		for _, p := range got {
			if !strings.Contains(p, "an old name") {
				t.Errorf("problem %q", p)
			}
		}
	}
}

func TestSlug(t *testing.T) {
	for heading, want := range map[string]string{
		"Sync away from home (planned)":       "sync-away-from-home-planned",
		"9. The phone as the root":            "9-the-phone-as-the-root",
		"The holder of `cbb.local`":           "the-holder-of-cbblocal",
		"Android: the clipboard without taps": "android-the-clipboard-without-taps",
		"Mac → Linux":                         "mac--linux",
	} {
		if got := slug(heading); got != want {
			t.Errorf("slug(%q) = %q, want %q", heading, got, want)
		}
	}
}

// libRs is a stand-in for member/src/lib.rs: the match that runs the
// commands, and the functions two of them call.
const libRs = `fn main() {
            let res = match cmd {
                "pair" if in_group(&g) => admit_cli::pair(&g, rest),
                "copy" => cmd_copy(&g, rest),
                "freeze" | "unfreeze" => cli::freeze(&g, rest, cmd == "freeze"),
                "version" | "-version" => {
                    Ok(())
                }
                "cbb" if !rest.is_empty() => {
                    std::process::exit(2)
                }
            };
}

fn cmd_copy(g: &Global, args: &[String]) -> Result<()> {
    for a in args {
        match flag(a) {
            Some("secret") | Some("x") => {}
            Some("from") if true => {}
            _ => {}
        }
    }
    match args.first().map(String::as_str) {
        Some("words") => {}
        _ => {}
    }
    if word.as_deref() != Some("off") {}
}
`

func TestCheckCommands(t *testing.T) {
	files := map[string][]byte{
		"member/src/lib.rs":     []byte(libRs),
		"docs/reference/cli.md": []byte("`cbb copy` sends. `cbb freeze` freezes.\n\n## Installers\n\n`cbb version` prints.\n"),
	}
	got := checkCommands(files)
	want := []string{"cbb pair", "cbb unfreeze"}
	if len(got) != len(want) {
		t.Fatalf("checkCommands() = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], "the command "+w+" ") {
			t.Errorf("problem %d = %q, want it to name %q", i, got[i], w)
		}
	}
}

func TestCheckEnv(t *testing.T) {
	files := map[string][]byte{
		"internal/a.go":                 []byte(`v := os.Getenv("CBB_PORT"); w := os.Getenv("CBB_GONE"); x.atoms["CBB_SELECTION"]`),
		"packaging/get.sh":              []byte(`attestation=${CBB_ATTESTATION:-check}; echo $CBB_SHELL`),
		"packaging/w/get.ps1":           []byte(`if ($env:CBB_VERIFY -eq 'skip') {}`),
		"packaging/x.service":           []byte("Environment=CBB_UNIT=\n"),
		"internal/third_party/lib/x.go": []byte(`os.Getenv("CBB_COPIED")`),
		"docs/reference/config.md":      []byte("`CBB_PORT` and `CBB_ATTESTATION`, `CBB_VERIFY`."),
	}
	got := checkEnv(files)
	want := []string{"CBB_GONE", "CBB_SHELL", "CBB_UNIT"}
	if len(got) != len(want) {
		t.Fatalf("checkEnv() = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], "variable "+w+" ") {
			t.Errorf("problem %d = %q, want it to name %s", i, got[i], w)
		}
	}
}

func TestCheckIndex(t *testing.T) {
	files := map[string][]byte{
		"docs/README.md":           []byte("[a](guide/a.md) [d](decisions/README.md#top)"),
		"docs/guide/a.md":          []byte("[b](b.md)"),
		"docs/guide/b.md":          nil,
		"docs/decisions/README.md": []byte("[1](0001-x.md)"),
		"docs/decisions/0001-x.md": nil,
		"docs/images/x.svg":        nil,
	}
	got := checkIndex(files)
	if len(got) != 1 || !strings.HasPrefix(got[0], "docs/guide/b.md:1:") {
		t.Fatalf("checkIndex() = %q, want only docs/guide/b.md", got)
	}
}

func TestCheckPlanned(t *testing.T) {
	files := map[string][]byte{
		"CHANGELOG.md":    []byte("## [Unreleased]\n\nplanned for 0.4\n\n## [0.5.0] - 2026-10-26\n"),
		"docs/roadmap.md": []byte("1. **Planned for 0.5.** x\n2. planned for 0.6\n3. planned for 0.10\n4. Planned for 0.4.\n"),
	}
	got := checkPlanned(files)
	if len(got) != 2 || !strings.HasPrefix(got[0], "docs/roadmap.md:1:") || !strings.HasPrefix(got[1], "docs/roadmap.md:4:") {
		t.Fatalf("checkPlanned() = %q, want lines 1 and 4 of docs/roadmap.md", got)
	}
}

func TestCheckFlags(t *testing.T) {
	files := map[string][]byte{
		"member/src/lib.rs":       []byte(libRs),
		"member/src/admit_cli.rs": []byte("pub fn pair(g: &Global, args: &[String]) -> Result<()> {\n    match flag(&args[0]) {\n        Some(\"admin\") => {}\n        _ => {}\n    }\n}\n"),
		"docs/reference/cli.md":   []byte("| `cbb copy [-secret]` | from a file with `-from` |\n| `cbb pair` | |\n\nAlso -admin, but not about the command.\n"),
	}
	got := checkFlags(files)
	want := []string{"the flag -admin of cbb pair ", "the flag -x of cbb copy "}
	if len(got) != len(want) {
		t.Fatalf("checkFlags() = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Errorf("problem %d = %q, want it to name %q", i, got[i], w)
		}
	}
}

func TestCheckPorts(t *testing.T) {
	files := map[string][]byte{
		"internal/mdns/mdns.go":       []byte("const Port = 5353\n"),
		"internal/service/service.go": []byte("const (\n\tMemberPort = 8764\n\tbacklog = 32\n)\n"),
		"cmd/cbb-forward/main.go":     []byte(`v := fs.String("vless-listen", ":443", "")`),
		"member/src/tunnel.rs":        []byte("const MEMBER_PORT: u16 = 8765;\n"),
		"internal/third_party/x/x.go": []byte("const Port = 9999\n"),
		"internal/service/x_test.go":  []byte("const testPort = 1234\n"),
		"docs/reference/devices.md":   []byte("# Devices\n\n## Ports\n\n| TCP 8764 | | UDP 5353 |\n\n## Files\n\n443\n"),
	}
	got := checkPorts(files)
	want := []string{"the port 443 ", "the port 8765 "}
	if len(got) != len(want) {
		t.Fatalf("checkPorts() = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Errorf("problem %d = %q, want it to name %q", i, got[i], w)
		}
	}
}

func TestCheckOps(t *testing.T) {
	files := map[string][]byte{
		"internal/control/control.go": []byte("const (\n\tOpCopy       = \"copy\" // a copy\n\tOpPasteOn = \"paste_on\"\n\tOpNew = \"new\"\n\tOpThaw = \"thaw\"\n\tOpPart = \"part\"\n)\n"),
		"docs/protocol.md":            []byte("# P\n\n## 7. Before\n\n`new`\n\n## 8. Local control socket\n\nparts as `part` messages\n\n## 9. After\n\n| `new` | |\n"),
		"docs/core-api.md":            []byte("# C\n\n### The member's operations\n\n| `op` | where |\n|---|---|\n| `copy` | both |\n| `paste_on` | computer |\n| `thaw` | computer |\n\n## Operations\n\n| `new` | |\n"),
	}
	got := checkOps(files)
	if len(got) != 1 || !strings.Contains(got[0], "operation new ") {
		t.Fatalf("checkOps() = %q, want one problem naming new", got)
	}
}

func TestCheckStyle(t *testing.T) {
	files := map[string][]byte{
		"docs/guide/a.md": []byte("Simply run it.\n`cbb simply` and [setup](easy.md) and \"easy\"\n```\neasy\n```\nIt is easy.\nSee https://example.com/easy and /usr/share/easy.\nIn `a\neasy b` too.\n"),
		"docs/design.md":  []byte("It cannot simply go inside it.\n"),
	}
	got := checkStyle(files)
	want := []string{"docs/guide/a.md:1: \"Simply\"", "docs/guide/a.md:6: \"easy\"", "docs/guide/a.md:7: \"easy\""}
	if len(got) != len(want) {
		t.Fatalf("checkStyle() = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("problem %d = %q, want it to start with %q", i, got[i], w)
		}
	}
}

func TestCheckOpsHeader(t *testing.T) {
	files := map[string][]byte{
		"internal/control/control.go": []byte("type Header struct {\n\tOp string `json:\"op\"`\n\tLen int `json:\"len,omitempty\"` // the length\n\tRelayKey string `json:\"relay_key,omitempty\"`\n}\n\ntype Other struct {\n\tX int `json:\"x\"`\n}\n"),
		"docs/protocol.md":            []byte("# P\n\n## 8. Local control socket\n\n| `op` | string |\n\n## 9. After\n\n`len`\n"),
		"docs/core-api.md":            []byte("# C\n\n### The member's operations\n\n| `away` | computer | `relay`, `relay_key` | |\n\n## After\n\n`len`\n"),
	}
	got := checkOps(files)
	if len(got) != 1 || !strings.Contains(got[0], "header field len ") {
		t.Fatalf("checkOps() = %q, want one problem naming len", got)
	}
}

// TestCheckGoneName finds the names of what the project removed, outside
// the files that tell its history, and leaves today's names alone.
func TestCheckGoneName(t *testing.T) {
	tag, tunnel, dir := "cbb"+"wasm", "go"+"mobile", "internal/"+"core"
	for _, c := range []struct {
		file, content string
		want          int
	}{
		{"a.go", "//go:build " + tag + "\n", 1},
		{"docs/a.md", "The phones bind Go with " + tunnel + ".\n", 1},
		{"a.go", "import \"github.com/HunterEwok/cbb/" + dir + "\"\n", 1},
		{"CHANGELOG.md", dir + " is gone.\n", 0},
		{"docs/decisions.md", "| D-1 | " + tunnel + " |\n", 0},
		{"a.swift", "import CCbbCore\n", 0},
		{"a.go", "the Rust core in " + dir + "s and internal/coreapi\n", 0},
	} {
		got := checkGoneName(c.file, []byte(c.content))
		if len(got) != c.want {
			t.Errorf("checkGoneName(%q, %q) = %q, want %d problems", c.file, c.content, got, c.want)
		}
	}
}
