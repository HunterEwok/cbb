// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokensFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", tokensFile))
	if err != nil {
		t.Fatal(err)
	}
	swift, kotlin, js, err := generate(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(swift), "name: \"terminal\",") || strings.Count(string(swift), "PalettePair(") != 10 {
		t.Errorf("not ten colours, terminal first, in\n%s", swift)
	}
	if !strings.Contains(string(kotlin), "name = \"terminal\",") || !strings.Contains(string(kotlin), "accent = Color(0xFF3DFF8A),") {
		t.Errorf("no terminal palette in\n%s", kotlin)
	}
	if !strings.Contains(string(js), "name: \"terminal\",") || !strings.Contains(string(js), "accent: \"#3DFF8A\",") {
		t.Errorf("no terminal palette in\n%s", js)
	}
	light, dark, err := generateHarmony(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(light), `{ "name": "accent", "value": "#0A7A3E" }`) || !strings.Contains(string(dark), `{ "name": "accent", "value": "#3DFF8A" }`) {
		t.Errorf("no terminal colours for HarmonyOS in\n%s\n%s", light, dark)
	}
}

func TestContrast(t *testing.T) {
	if m, _ := mix("#FFFFFF", "#000000", 0.5); m != "#808080" {
		t.Errorf("half white over black is %s, want #808080", m)
	}
	if r, _ := contrast("#000000", "#FFFFFF"); r < 20.9 || r > 21.1 {
		t.Errorf("black on white is %.2f:1, want 21:1", r)
	}
	low := Palette{Background: "#000000", Surface: "#000000", Text: "#333333", TextDim: "#FFFFFF", Accent: "#FFFFFF", OnAccent: "#000000", Danger: "#FFFFFF", Grid: "#000000"}
	if err := checkContrast("low", low); err == nil || !strings.Contains(err.Error(), "text has a contrast") {
		t.Errorf("low contrast passed: %v", err)
	}
	if _, _, _, err := generate([]byte(`{"colors":[{"name":"amber","dark":"#FFB000","light":"#8A5A00"}],"radius":{},"spacing":{}}`)); err == nil {
		t.Error("a file without terminal first passed")
	}
	if _, _, _, err := generate([]byte(`{"colors":[],"extra":1}`)); err == nil {
		t.Error("an unknown field passed")
	}
}
