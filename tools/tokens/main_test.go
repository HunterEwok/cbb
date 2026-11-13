// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"fmt"
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
	if strings.Count(string(swift), "        Theme(\n") != 11 || !strings.Contains(string(swift), "name: \"board\",") || strings.Index(string(swift), "\"board\"") > strings.Index(string(swift), "\"blueprint\"") {
		t.Errorf("not eleven themes, board first, in\n%s", swift)
	}
	if !strings.Contains(string(swift), "material: .glass") || !strings.Contains(string(swift), "line: Color(rgb: 0x3E6E99)") {
		t.Errorf("no style or line in\n%s", swift)
	}
	if !strings.Contains(string(kotlin), "name = \"blueprint\",") || !strings.Contains(string(kotlin), "accent = Color(0xFF7FD1FF),") ||
		!strings.Contains(string(kotlin), "material = Material.FLAT") {
		t.Errorf("no blueprint theme in\n%s", kotlin)
	}
	if !strings.Contains(string(js), "name: \"blueprint\",") || !strings.Contains(string(js), "accent: \"#7FD1FF\",") ||
		!strings.Contains(string(js), "export const spacing = { large: 24, medium: 16, small: 8 };") {
		t.Errorf("no blueprint theme in\n%s", js)
	}
}

const okTheme = `{"name":"blueprint","style":{"fonts":{"display":"A","body":"A","mono":"B"},"radius":{"button":3,"card":3,"tile":3,"chip":2},
"stroke":1,"material":"flat","grid":true,"dashedOff":true,"upperLabels":true},
"dark":{"background":"#000000","surface":"#000000","grid":"#111111","line":"#333333","text":"#FFFFFF","textDim":"#AAAAAA","accent":"#7FD1FF","onAccent":"#000000","danger":"#FF9B8A"},
"light":{"background":"#FFFFFF","surface":"#FFFFFF","grid":"#EEEEEE","line":"#999999","text":"#000000","textDim":"#555555","accent":"#0B5CAD","onAccent":"#FFFFFF","danger":"#B3261E"}}`

func TestGenerate(t *testing.T) {
	if _, _, _, err := generate([]byte(`{"default":"blueprint","themes":[` + okTheme + `],"spacing":{"small":8}}`)); err != nil {
		t.Fatalf("a good file failed: %v", err)
	}
	// The default comes first, wherever the file lists it.
	two := `{"default":"precise","themes":[` + okTheme + `,` + strings.Replace(okTheme, `"blueprint"`, `"precise"`, 1) + `]}`
	if swift, _, _, err := generate([]byte(two)); err != nil || strings.Index(string(swift), `"precise"`) > strings.Index(string(swift), `"blueprint"`) {
		t.Errorf("the default is not first (%v):\n%s", err, swift)
	}
	for _, c := range []struct{ name, file, want string }{
		{"no default", `{"default":"glass","themes":[` + okTheme + `]}`, "not one of the themes"},
		{"repeated", `{"default":"blueprint","themes":[` + okTheme + `,` + okTheme + `]}`, "repeated"},
		{"unknown field", `{"themes":[],"extra":1}`, "unknown field"},
		{"material", `{"default":"blueprint","themes":[` + strings.Replace(okTheme, `"flat"`, `"wood"`, 1) + `]}`, "unknown material"},
		{"font", `{"default":"blueprint","themes":[` + strings.Replace(okTheme, `"mono":"B"`, `"mono":""`, 1) + `]}`, "font is missing"},
		{"radius", `{"default":"blueprint","themes":[` + strings.Replace(okTheme, `"card":3`, `"card":-1`, 1) + `]}`, "out of range"},
		{"colour", `{"default":"blueprint","themes":[` + strings.Replace(okTheme, `"#111111"`, `"grey"`, 1) + `]}`, "not #RRGGBB"},
		{"contrast", `{"default":"blueprint","themes":[` + strings.Replace(okTheme, `"textDim":"#AAAAAA"`, `"textDim":"#222222"`, 1) + `]}`, "dim text has a contrast"},
	} {
		if _, _, _, err := generate([]byte(c.file)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", c.name, err, c.want)
		}
	}
}

// TestHarmony: the HarmonyOS app's colours are the default theme's, light
// and dark.
func TestHarmony(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", tokensFile))
	if err != nil {
		t.Fatal(err)
	}
	light, dark, err := generateHarmony(data)
	if err != nil {
		t.Fatal(err)
	}
	var tk Tokens
	if err := json.Unmarshal(data, &tk); err != nil {
		t.Fatal(err)
	}
	var def Theme
	for _, th := range tk.Themes {
		if th.Name == tk.Default {
			def = th
		}
	}
	want := func(hex string) string { return fmt.Sprintf(`{ "name": "accent", "value": %q }`, hex) }
	if !strings.Contains(string(light), want(def.Light.Accent)) || !strings.Contains(string(dark), want(def.Dark.Accent)) {
		t.Errorf("not the default theme's colours for HarmonyOS in\n%s\n%s", light, dark)
	}
}

func TestContrast(t *testing.T) {
	if r, _ := contrast("#000000", "#FFFFFF"); r < 20.9 || r > 21.1 {
		t.Errorf("black on white is %.2f:1, want 21:1", r)
	}
	low := Palette{Background: "#000000", Surface: "#000000", Text: "#333333", TextDim: "#FFFFFF", Accent: "#FFFFFF", OnAccent: "#000000", Danger: "#FFFFFF", Grid: "#000000", Line: "#000000"}
	if err := checkContrast("low", low); err == nil || !strings.Contains(err.Error(), "text has a contrast") {
		t.Errorf("low contrast passed: %v", err)
	}
}
