// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"strings"
	"testing"
)

func TestCheckProtocolRefs(t *testing.T) {
	protocol := "# Protocol\n\n### Contents\n\n- [1. Names](#1-names)\n- [2. Records](#2-records)\n\n## 1. Names\n\n### Ports\n\n## 2. Records\n\n#### The joiner listens (for the phone)\n\n" +
		"**Two numbers.** A record ...\n\nSee section 2, \"Two numbers\", and section 1, \"Hosts\".\n"
	files := map[string][]byte{
		"docs/protocol.md": []byte(protocol),
		"a.go": []byte("// docs/protocol.md, section 1, \"Ports\"; protocol.md, sections 1 and 2;\n" +
			"// protocol.md, section 2, \"The joiner\n// listens\"; protocol.md section 2, \"Two numbers\"\n"),
		"b.rs":         []byte("//! one\n//! (docs/protocol.md, section 3) and\n//! (docs/protocol.md,\n//! section 2, \"Ports\")\n"),
		"CHANGELOG.md": []byte("- Old (protocol.md, section 9).\n"),
	}
	got := checkProtocolRefs(files)
	want := []string{
		"b.rs:2: refers to section 3 of",
		"b.rs:3: refers to \"Ports\" in section 2",
		"docs/protocol.md:18: refers to \"Hosts\" in section 1",
	}
	if len(got) != len(want) {
		t.Fatalf("checkProtocolRefs = %q, want %d problems", got, len(want))
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) {
			t.Errorf("problem %d = %q, want it to contain %q", i, got[i], w)
		}
	}
}

func TestCheckProtocolContents(t *testing.T) {
	protocol := "### Contents\n\n- [1. Names](#1-names)\n\n## 1. Names\n\n## 2. Records\n"
	got := checkProtocolRefs(map[string][]byte{"docs/protocol.md": []byte(protocol)})
	if len(got) != 1 || !strings.Contains(got[0], "- [2. Records](#2-records)") {
		t.Fatalf("checkProtocolRefs = %q, want the missing section reported", got)
	}
}
