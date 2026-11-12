// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command tokens turns the apps' design tokens (apps/design/tokens.json)
// into Swift for the iPhone and Mac apps, Kotlin for the Android app,
// JavaScript for the tray app and the HarmonyOS app's colour resources
// (the default accent, light and dark): each
// accent colour on the dark and the light base gives a palette, and every
// palette must meet WCAG AA contrast: 4.5:1 for text, 3:1 for the accent
// against the background.
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
	"sort"
	"strconv"
	"strings"
)

const (
	tokensFile = "apps/design/tokens.json"
	swiftFile  = "apps/ios/CBB/Theme/Tokens.swift"
	kotlinFile = "apps/android/shared/src/main/kotlin/tools/cbb/Tokens.kt"
	jsFile     = "apps/desktop/frontend/tokens.js"
	// The HarmonyOS app's colours, the light ones by default and the dark
	// ones in the dark theme.
	harmonyLight = "apps/harmony/entry/src/main/resources/base/element/color.json"
	harmonyDark  = "apps/harmony/entry/src/main/resources/dark/element/color.json"
	// The watch's, the dark ones only, as watches show.
	harmonyWatch = "apps/harmony/wearable/src/main/resources/base/element/color.json"
)

// Palette is one theme's colours, "#RRGGBB", derived from a base and an
// accent.
type Palette struct {
	Dark       bool
	Background string
	Surface    string
	Grid       string
	Text       string
	TextDim    string
	Accent     string
	OnAccent   string
	Danger     string
}

// colour is one named colour of a palette.
type colour struct{ name, hex string }

// colours lists a palette's colours in the order the generated files give them.
func (p Palette) colours() []colour {
	return []colour{
		{"background", p.Background}, {"surface", p.Surface}, {"grid", p.Grid}, {"text", p.Text},
		{"textDim", p.TextDim}, {"accent", p.Accent}, {"onAccent", p.OnAccent}, {"danger", p.Danger},
	}
}

// Base is the neutral half of a palette for the dark or the light
// appearance; the tints say how much of the accent each derived colour
// takes in.
type Base struct {
	Background     string  `json:"background"`
	Surface        string  `json:"surface"`
	Text           string  `json:"text"`
	TextDim        string  `json:"textDim"`
	OnAccent       string  `json:"onAccent"`
	Danger         string  `json:"danger"`
	BackgroundTint float64 `json:"backgroundTint"`
	SurfaceTint    float64 `json:"surfaceTint"`
	GridTint       float64 `json:"gridTint"`
}

// Accent is one of the colours the user picks in Settings, for the dark
// and the light appearance.
type Accent struct {
	Name  string `json:"name"`
	Dark  string `json:"dark"`
	Light string `json:"light"`
}

// Tokens is the whole file.
type Tokens struct {
	Colors []Accent `json:"colors"`
	Base   struct {
		Dark  Base `json:"dark"`
		Light Base `json:"light"`
	} `json:"base"`
	Radius  map[string]float64 `json:"radius"`
	Spacing map[string]float64 `json:"spacing"`
}

// pair is an accent's two palettes.
type pair struct {
	name        string
	dark, light Palette
}

// palette derives the palette of an accent on a base.
func palette(dark bool, b Base, accent string) (Palette, error) {
	bg, err := mix(accent, b.Background, b.BackgroundTint)
	if err != nil {
		return Palette{}, err
	}
	surface, err := mix(accent, b.Surface, b.SurfaceTint)
	if err != nil {
		return Palette{}, err
	}
	grid, err := mix(accent, b.Surface, b.GridTint)
	if err != nil {
		return Palette{}, err
	}
	return Palette{
		Dark: dark, Background: bg, Surface: surface, Grid: grid, Text: b.Text, TextDim: b.TextDim,
		Accent: accent, OnAccent: b.OnAccent, Danger: b.Danger,
	}, nil
}

// mix is t of a over b.
func mix(a, b string, t float64) (string, error) {
	ar, ag, ab, err := rgb(a)
	if err != nil {
		return "", err
	}
	br, bg, bb, err := rgb(b)
	if err != nil {
		return "", err
	}
	c := func(x, y float64) int { return int(math.Round((y + (x-y)*t) * 255)) }
	return fmt.Sprintf("#%02X%02X%02X", c(ar, br), c(ag, bg), c(ab, bb)), nil
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
	light, dark, err := generateHarmony(data)
	if err != nil {
		fail(err)
	}
	for _, f := range []struct {
		path string
		out  []byte
	}{{swiftFile, swift}, {kotlinFile, kotlin}, {jsFile, js}, {harmonyLight, light}, {harmonyDark, dark}, {harmonyWatch, dark}} {
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
	if len(t.Colors) == 0 || t.Colors[0].Name != "terminal" {
		return nil, nil, nil, fmt.Errorf("the first colour, the default, must be terminal")
	}
	seen := map[string]bool{}
	var pairs []pair
	for _, a := range t.Colors {
		if a.Name == "" || seen[a.Name] {
			return nil, nil, nil, fmt.Errorf("the colour %q is unnamed or repeated", a.Name)
		}
		seen[a.Name] = true
		dark, err := palette(true, t.Base.Dark, a.Dark)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s.dark: %w", a.Name, err)
		}
		light, err := palette(false, t.Base.Light, a.Light)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s.light: %w", a.Name, err)
		}
		for _, p := range []struct {
			name string
			p    Palette
		}{{a.Name + " dark", dark}, {a.Name + " light", light}} {
			for _, c := range p.p.colours() {
				if _, _, _, err := rgb(c.hex); err != nil {
					return nil, nil, nil, fmt.Errorf("%s.%s: %w", p.name, c.name, err)
				}
			}
			if err := checkContrast(p.name, p.p); err != nil {
				return nil, nil, nil, err
			}
		}
		pairs = append(pairs, pair{a.Name, dark, light})
	}
	return generateSwift(t, pairs), generateKotlin(t, pairs), generateJS(t, pairs), nil
}

// generateHarmony returns the HarmonyOS app's colour resources of the
// default accent: the light palette and the dark one. JSON takes no
// comment, so they do not say that they are generated.
func generateHarmony(data []byte) (light, dark []byte, err error) {
	if _, _, _, err := generate(data); err != nil {
		return nil, nil, err
	}
	var t Tokens
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, nil, err
	}
	l, err := palette(false, t.Base.Light, t.Colors[0].Light)
	if err != nil {
		return nil, nil, err
	}
	d, err := palette(true, t.Base.Dark, t.Colors[0].Dark)
	if err != nil {
		return nil, nil, err
	}
	return harmonyColours(l), harmonyColours(d), nil
}

// harmonyColours writes a palette as the app's colour names: online and
// offline are the accent and the dim text.
func harmonyColours(p Palette) []byte {
	var b strings.Builder
	b.WriteString("{\n  \"color\": [\n")
	for i, c := range [][2]string{
		{"start_window_background", p.Background}, {"background", p.Background}, {"surface", p.Surface},
		{"grid", p.Grid}, {"text", p.Text}, {"secondary", p.TextDim}, {"accent", p.Accent},
		{"on_accent", p.OnAccent}, {"error", p.Danger}, {"online", p.Accent}, {"offline", p.TextDim},
	} {
		if i > 0 {
			b.WriteString(",\n")
		}
		fmt.Fprintf(&b, "    { \"name\": %q, \"value\": %q }", c[0], c[1])
	}
	b.WriteString("\n  ]\n}\n")
	return []byte(b.String())
}

func generateSwift(t Tokens, pairs []pair) []byte {
	var b strings.Builder
	b.WriteString("// SPDX-" + "License-Identifier: AGPL-3.0-only\n")
	b.WriteString("// Code generated by go run ./tools/tokens from apps/design/tokens.json; DO NOT EDIT.\n\n")
	b.WriteString("import SwiftUI\n\n")
	b.WriteString("enum Tokens {\n")
	b.WriteString("    /// The colours offered in Settings, the default first.\n")
	b.WriteString("    static let colors: [PalettePair] = [\n")
	palette := func(field string, p Palette, last bool) {
		fmt.Fprintf(&b, "            %s: Palette(\n                dark: %v,\n", field, p.Dark)
		cs := p.colours()
		for i, c := range cs {
			sep := ","
			if i == len(cs)-1 {
				sep = ""
			}
			fmt.Fprintf(&b, "                %s: Color(rgb: 0x%s)%s\n", c.name, strings.ToUpper(c.hex[1:]), sep)
		}
		if last {
			b.WriteString("            )\n")
		} else {
			b.WriteString("            ),\n")
		}
	}
	for _, p := range pairs {
		fmt.Fprintf(&b, "        PalettePair(\n            name: %q,\n", p.name)
		palette("dark", p.dark, false)
		palette("light", p.light, true)
		b.WriteString("        ),\n")
	}
	b.WriteString("    ]\n")
	for _, group := range []struct {
		prefix string
		values map[string]float64
	}{{"radius", t.Radius}, {"spacing", t.Spacing}} {
		for _, k := range sortedKeys(group.values) {
			fmt.Fprintf(&b, "    static let %s%s: CGFloat = %s\n", group.prefix, strings.ToUpper(k[:1])+k[1:], num(group.values[k]))
		}
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func generateKotlin(t Tokens, pairs []pair) []byte {
	var b strings.Builder
	b.WriteString("// SPDX-" + "License-Identifier: AGPL-3.0-only\n")
	b.WriteString("// Code generated by go run ./tools/tokens from apps/design/tokens.json; DO NOT EDIT.\n\n")
	b.WriteString("package tools.cbb\n\n")
	b.WriteString("import androidx.compose.ui.graphics.Color\n")
	b.WriteString("import androidx.compose.ui.unit.dp\n\n")
	b.WriteString("object Tokens {\n")
	b.WriteString("    /** The colours offered in Settings, the default first. */\n")
	b.WriteString("    val colors = listOf(\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "        PalettePair(\n            name = %q,\n", p.name)
		for _, half := range []struct {
			field string
			p     Palette
		}{{"dark", p.dark}, {"light", p.light}} {
			fmt.Fprintf(&b, "            %s = Palette(\n                dark = %v,\n", half.field, half.p.Dark)
			for _, c := range half.p.colours() {
				fmt.Fprintf(&b, "                %s = Color(0xFF%s),\n", c.name, strings.ToUpper(c.hex[1:]))
			}
			b.WriteString("            ),\n")
		}
		b.WriteString("        ),\n")
	}
	b.WriteString("    )\n")
	for _, group := range []struct {
		prefix string
		values map[string]float64
	}{{"radius", t.Radius}, {"spacing", t.Spacing}} {
		for _, k := range sortedKeys(group.values) {
			fmt.Fprintf(&b, "    val %s%s = %s.dp\n", group.prefix, strings.ToUpper(k[:1])+k[1:], num(group.values[k]))
		}
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func generateJS(t Tokens, pairs []pair) []byte {
	var b strings.Builder
	b.WriteString("// SPDX-" + "License-Identifier: AGPL-3.0-only\n")
	b.WriteString("// Code generated by go run ./tools/tokens from apps/design/tokens.json; DO NOT EDIT.\n\n")
	b.WriteString("// The colours offered in Settings, the default first.\n")
	b.WriteString("export const colors = [\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "  {\n    name: %q,\n", p.name)
		for _, half := range []struct {
			field string
			p     Palette
		}{{"dark", p.dark}, {"light", p.light}} {
			fmt.Fprintf(&b, "    %s: {\n", half.field)
			for _, c := range half.p.colours() {
				fmt.Fprintf(&b, "      %s: %q,\n", c.name, strings.ToUpper(c.hex))
			}
			b.WriteString("    },\n")
		}
		b.WriteString("  },\n")
	}
	b.WriteString("];\n")
	for _, group := range []struct {
		name   string
		values map[string]float64
	}{{"radius", t.Radius}, {"spacing", t.Spacing}} {
		fmt.Fprintf(&b, "export const %s = {", group.name)
		for i, k := range sortedKeys(group.values) {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, " %s: %s", k, num(group.values[k]))
		}
		b.WriteString(" };\n")
	}
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
		{"the accent", p.Accent, p.Background, 3},
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
