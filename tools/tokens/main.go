// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command tokens turns the apps' design tokens (apps/design/tokens.json)
// into Swift for the iPhone and Mac apps, Kotlin for the Android app and
// JavaScript for the tray app. Each theme has a style (faces, corners,
// lines, material) and a palette for the dark and the light appearance;
// every palette must meet WCAG AA contrast for text, 4.5:1, on the
// background and on a surface, the accent included, which the apps write
// badges and links in.
//
//	go run ./tools/tokens          rewrite the generated files
//	go run ./tools/tokens -check   fail if they are out of date
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	tokensFile = "apps/design/tokens.json"
	swiftFile  = "apps/ios/CBB/Theme/Tokens.swift"
	kotlinFile = "apps/android/shared/src/main/kotlin/tools/cbb/Tokens.kt"
	jsFile     = "apps/desktop/frontend/tokens.js"
)

// Palette is one theme's colours for the dark or the light appearance,
// "#RRGGBB".
type Palette struct {
	Dark       bool   `json:"-"`
	Background string `json:"background"`
	Surface    string `json:"surface"`
	Grid       string `json:"grid"`
	Line       string `json:"line"`
	Text       string `json:"text"`
	TextDim    string `json:"textDim"`
	Accent     string `json:"accent"`
	OnAccent   string `json:"onAccent"`
	Danger     string `json:"danger"`
}

// colour is one named colour of a palette.
type colour struct{ name, hex string }

// colours lists a palette's colours in the order the generated files give them.
func (p Palette) colours() []colour {
	return []colour{
		{"background", p.Background}, {"surface", p.Surface}, {"grid", p.Grid}, {"line", p.Line},
		{"text", p.Text}, {"textDim", p.TextDim}, {"accent", p.Accent}, {"onAccent", p.OnAccent},
		{"danger", p.Danger},
	}
}

// Style is what a theme draws besides its colours: the faces, the corners,
// the width of its lines (0: none), its material ("flat", "glass",
// "liquid" or "metal"), whether large surfaces show a grid, whether
// something off or waiting is drawn dashed and whether small labels are in
// capitals.
type Style struct {
	Fonts struct {
		Display string `json:"display"`
		Body    string `json:"body"`
		Mono    string `json:"mono"`
	} `json:"fonts"`
	Radius struct {
		Button float64 `json:"button"`
		Card   float64 `json:"card"`
		Tile   float64 `json:"tile"`
		Chip   float64 `json:"chip"`
	} `json:"radius"`
	Stroke      float64 `json:"stroke"`
	Material    string  `json:"material"`
	Grid        bool    `json:"grid"`
	DashedOff   bool    `json:"dashedOff"`
	UpperLabels bool    `json:"upperLabels"`
}

// materials are the materials a theme may name.
var materials = map[string]bool{"flat": true, "glass": true, "liquid": true, "metal": true}

// Theme is one of the themes the user picks in Settings.
type Theme struct {
	Name  string  `json:"name"`
	Style Style   `json:"style"`
	Dark  Palette `json:"dark"`
	Light Palette `json:"light"`
}

// Tokens is the whole file. Default names the theme a new install starts
// with; the generated files list it first.
type Tokens struct {
	Default string             `json:"default"`
	Themes  []Theme            `json:"themes"`
	Spacing map[string]float64 `json:"spacing"`
}

func main() {
	check := flag.Bool("check", false, "fail if the generated files are out of date")
	flag.Parse()
	data, err := os.ReadFile(tokensFile)
	if err != nil {
		fail(err)
	}
	swift, kotlin, js, err := generate(data)
	if err != nil {
		fail(err)
	}
	for _, f := range []struct {
		path string
		out  []byte
	}{{swiftFile, swift}, {kotlinFile, kotlin}, {jsFile, js}} {
		if *check {
			have, _ := os.ReadFile(f.path)
			if !bytes.Equal(have, f.out) {
				fail(fmt.Errorf("%s is out of date; run go run ./tools/tokens", f.path))
			}
			continue
		}
		if err := os.WriteFile(f.path, f.out, 0o644); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tokens:", err)
	os.Exit(1)
}

// generate checks the tokens and returns the Swift, the Kotlin and the
// JavaScript file.
func generate(data []byte) (swift, kotlin, js []byte, err error) {
	var t Tokens
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, nil, nil, err
	}
	seen := map[string]bool{}
	for i := range t.Themes {
		th := &t.Themes[i]
		if th.Name == "" || seen[th.Name] {
			return nil, nil, nil, fmt.Errorf("the theme %q is unnamed or repeated", th.Name)
		}
		seen[th.Name] = true
		if err := checkStyle(th.Name, th.Style); err != nil {
			return nil, nil, nil, err
		}
		th.Dark.Dark = true
		for _, p := range []struct {
			name string
			p    Palette
		}{{th.Name + " dark", th.Dark}, {th.Name + " light", th.Light}} {
			for _, c := range p.p.colours() {
				if _, _, _, err := rgb(c.hex); err != nil {
					return nil, nil, nil, fmt.Errorf("%s.%s: %w", p.name, c.name, err)
				}
			}
			if err := checkContrast(p.name, p.p); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	at := slices.IndexFunc(t.Themes, func(th Theme) bool { return th.Name == t.Default })
	if at < 0 {
		return nil, nil, nil, fmt.Errorf("the default theme %q is not one of the themes", t.Default)
	}
	t.Themes = append([]Theme{t.Themes[at]}, slices.Delete(slices.Clone(t.Themes), at, at+1)...)
	return generateSwift(t), generateKotlin(t), generateJS(t), nil
}

// checkStyle checks a theme's style.
func checkStyle(name string, s Style) error {
	f := s.Fonts
	if f.Display == "" || f.Body == "" || f.Mono == "" {
		return fmt.Errorf("%s: a font is missing", name)
	}
	r := s.Radius
	for _, v := range []float64{r.Button, r.Card, r.Tile, r.Chip, s.Stroke} {
		if v < 0 || v > 40 {
			return fmt.Errorf("%s: a radius or the stroke is out of range", name)
		}
	}
	if !materials[s.Material] {
		return fmt.Errorf("%s: unknown material %q", name, s.Material)
	}
	return nil
}

const header = "// SPDX-" + "License-Identifier: AGPL-3.0-only\n" +
	"// Code generated by go run ./tools/tokens from apps/design/tokens.json; DO NOT EDIT.\n\n"

// half is a theme's palette for one appearance.
type half struct {
	field string
	p     Palette
}

func halves(th Theme) []half { return []half{{"dark", th.Dark}, {"light", th.Light}} }

func generateSwift(t Tokens) []byte {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("import SwiftUI\n\n")
	b.WriteString("enum Tokens {\n")
	b.WriteString("    /// The themes offered in Settings, the default first.\n")
	b.WriteString("    static let themes: [Theme] = [\n")
	for _, th := range t.Themes {
		s := th.Style
		fmt.Fprintf(&b, "        Theme(\n            name: %q,\n", th.Name)
		b.WriteString("            style: ThemeStyle(\n")
		fmt.Fprintf(&b, "                display: %q, body: %q, mono: %q,\n", s.Fonts.Display, s.Fonts.Body, s.Fonts.Mono)
		fmt.Fprintf(&b, "                radiusButton: %s, radiusCard: %s, radiusTile: %s, radiusChip: %s,\n",
			num(s.Radius.Button), num(s.Radius.Card), num(s.Radius.Tile), num(s.Radius.Chip))
		fmt.Fprintf(&b, "                stroke: %s, material: .%s, grid: %v, dashedOff: %v, upperLabels: %v\n",
			num(s.Stroke), s.Material, s.Grid, s.DashedOff, s.UpperLabels)
		b.WriteString("            ),\n")
		for i, h := range halves(th) {
			fmt.Fprintf(&b, "            %s: Palette(\n                dark: %v,\n", h.field, h.p.Dark)
			cs := h.p.colours()
			for j, c := range cs {
				sep := ","
				if j == len(cs)-1 {
					sep = ""
				}
				fmt.Fprintf(&b, "                %s: Color(rgb: 0x%s)%s\n", c.name, strings.ToUpper(c.hex[1:]), sep)
			}
			if i == 1 {
				b.WriteString("            )\n")
			} else {
				b.WriteString("            ),\n")
			}
		}
		b.WriteString("        ),\n")
	}
	b.WriteString("    ]\n")
	for _, k := range sortedKeys(t.Spacing) {
		fmt.Fprintf(&b, "    static let spacing%s: CGFloat = %s\n", strings.ToUpper(k[:1])+k[1:], num(t.Spacing[k]))
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func generateKotlin(t Tokens) []byte {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("package tools.cbb\n\n")
	b.WriteString("import androidx.compose.ui.graphics.Color\n")
	b.WriteString("import androidx.compose.ui.unit.dp\n\n")
	b.WriteString("object Tokens {\n")
	b.WriteString("    /** The themes offered in Settings, the default first. */\n")
	b.WriteString("    val themes = listOf(\n")
	for _, th := range t.Themes {
		s := th.Style
		fmt.Fprintf(&b, "        Theme(\n            name = %q,\n", th.Name)
		b.WriteString("            style = ThemeStyle(\n")
		fmt.Fprintf(&b, "                display = %q, body = %q, mono = %q,\n", s.Fonts.Display, s.Fonts.Body, s.Fonts.Mono)
		fmt.Fprintf(&b, "                radiusButton = %s.dp, radiusCard = %s.dp, radiusTile = %s.dp, radiusChip = %s.dp,\n",
			num(s.Radius.Button), num(s.Radius.Card), num(s.Radius.Tile), num(s.Radius.Chip))
		fmt.Fprintf(&b, "                stroke = %s.dp, material = Material.%s, grid = %v, dashedOff = %v, upperLabels = %v,\n",
			num(s.Stroke), strings.ToUpper(s.Material), s.Grid, s.DashedOff, s.UpperLabels)
		b.WriteString("            ),\n")
		for _, h := range halves(th) {
			fmt.Fprintf(&b, "            %s = Palette(\n                dark = %v,\n", h.field, h.p.Dark)
			for _, c := range h.p.colours() {
				fmt.Fprintf(&b, "                %s = Color(0xFF%s),\n", c.name, strings.ToUpper(c.hex[1:]))
			}
			b.WriteString("            ),\n")
		}
		b.WriteString("        ),\n")
	}
	b.WriteString("    )\n")
	for _, k := range sortedKeys(t.Spacing) {
		fmt.Fprintf(&b, "    val spacing%s = %s.dp\n", strings.ToUpper(k[:1])+k[1:], num(t.Spacing[k]))
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func generateJS(t Tokens) []byte {
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("// The themes offered in Settings, the default first.\n")
	b.WriteString("export const themes = [\n")
	for _, th := range t.Themes {
		s := th.Style
		fmt.Fprintf(&b, "  {\n    name: %q,\n    style: {\n", th.Name)
		fmt.Fprintf(&b, "      display: %q, body: %q, mono: %q,\n", s.Fonts.Display, s.Fonts.Body, s.Fonts.Mono)
		fmt.Fprintf(&b, "      radiusButton: %s, radiusCard: %s, radiusTile: %s, radiusChip: %s,\n",
			num(s.Radius.Button), num(s.Radius.Card), num(s.Radius.Tile), num(s.Radius.Chip))
		fmt.Fprintf(&b, "      stroke: %s, material: %q, grid: %v, dashedOff: %v, upperLabels: %v,\n",
			num(s.Stroke), s.Material, s.Grid, s.DashedOff, s.UpperLabels)
		b.WriteString("    },\n")
		for _, h := range halves(th) {
			fmt.Fprintf(&b, "    %s: {\n", h.field)
			for _, c := range h.p.colours() {
				fmt.Fprintf(&b, "      %s: %q,\n", c.name, strings.ToUpper(c.hex))
			}
			b.WriteString("    },\n")
		}
		b.WriteString("  },\n")
	}
	b.WriteString("];\n")
	b.WriteString("export const spacing = {")
	for i, k := range sortedKeys(t.Spacing) {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, " %s: %s", k, num(t.Spacing[k]))
	}
	b.WriteString(" };\n")
	return []byte(b.String())
}

func checkContrast(name string, p Palette) error {
	for _, c := range []struct {
		what, fg, bg string
		min          float64
	}{
		{"text", p.Text, p.Background, 4.5},
		{"text on a surface", p.Text, p.Surface, 4.5},
		{"dim text", p.TextDim, p.Background, 4.5},
		{"text on the accent", p.OnAccent, p.Accent, 4.5},
		{"danger", p.Danger, p.Background, 4.5},
		{"dim text on a surface", p.TextDim, p.Surface, 4.5},
		{"danger on a surface", p.Danger, p.Surface, 4.5},
		// The apps write badges, links and the actions of a card in the
		// accent: text, so text's contrast.
		{"accent text", p.Accent, p.Background, 4.5},
		{"accent text on a surface", p.Accent, p.Surface, 4.5},
	} {
		r, err := contrast(c.fg, c.bg)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if r < c.min {
			return fmt.Errorf("%s: %s has a contrast of %.2f:1, below %.1f:1", name, c.what, r, c.min)
		}
	}
	return nil
}

// contrast is the WCAG 2 contrast ratio of two colours.
func contrast(a, b string) (float64, error) {
	la, err := luminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := luminance(b)
	if err != nil {
		return 0, err
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), nil
}

func luminance(hex string) (float64, error) {
	r, g, b, err := rgb(hex)
	if err != nil {
		return 0, err
	}
	lin := func(c float64) float64 {
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b), nil
}

func rgb(hex string) (r, g, b float64, err error) {
	if len(hex) != 7 || hex[0] != '#' {
		return 0, 0, 0, fmt.Errorf("%q is not #RRGGBB", hex)
	}
	v, err := strconv.ParseUint(hex[1:], 16, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%q is not #RRGGBB", hex)
	}
	return float64(v>>16&0xff) / 255, float64(v>>8&0xff) / 255, float64(v&0xff) / 255, nil
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
