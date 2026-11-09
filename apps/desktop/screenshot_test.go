// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Screenshot regressions (U18, docs/testing.md, "The apps' languages,
// accessibility and screenshots"): the window's views in English, Arabic
// and Chinese, dark and light, compared with the pictures in
// testdata/screenshots. Glyphs depend on the fonts, so the window is drawn
// in the Noto fonts (fonts-noto-core, fonts-noto-mono and
// fonts-droid-fallback on Debian and Ubuntu) and only on Linux; without
// them the test is skipped, except in CI. A picture may differ from its
// reference in a few pixels, as two builds of Chrome smooth text a little
// differently, not more.
//
// After a change to the window, write the pictures again and look at them:
//
//	CBB_UPDATE_SCREENSHOTS=1 go test -run 'TestWindow/screenshots' .
//
// A failed comparison leaves the new picture and a picture of the
// difference in $CBB_SCREENSHOT_OUT (by default a directory the test names).

// screenshotFonts are the font families the pictures are drawn in.
var screenshotFonts = []string{"Noto Sans", "Noto Sans Arabic", "Noto Sans Hebrew", "Noto Sans Devanagari", "Droid Sans Fallback", "Noto Sans Mono"}

// screenshotStyle draws every text in those fonts and stops whatever moves.
var screenshotStyle = `
* { font-family: "Noto Sans", "Noto Sans Arabic", "Noto Sans Hebrew", "Noto Sans Devanagari", "Droid Sans Fallback", sans-serif !important; }
.mono, code, .name, .mono * { font-family: "Noto Sans Mono", "Droid Sans Fallback", monospace !important; }
*, *::before, *::after { animation: none !important; transition: none !important; caret-color: transparent !important; }
`

// screenshotCases are the languages and appearances pictured.
var screenshotCases = []struct{ lang, look string }{
	{"en", "dark"}, {"en", "light"}, {"ar", "dark"}, {"zh", "light"},
}

// Two pixels differ when a channel differs by more than pixelTolerance; a
// picture matches when at most maxDiffering of its pixels differ.
const (
	pixelTolerance = 48
	maxDiffering   = 0.003
)

func (w *window) screenshots(t *testing.T) {
	w.t = t
	if runtime.GOOS != "linux" {
		t.Skip("the reference pictures are drawn on Linux")
	}
	if missing := missingFonts(); len(missing) > 0 {
		if os.Getenv("CI") != "" {
			t.Fatalf("the screenshots need the fonts %q", missing)
		}
		t.Skipf("the screenshots need the fonts %q", missing)
	}
	update := os.Getenv("CBB_UPDATE_SCREENSHOTS") != ""
	out := os.Getenv("CBB_SCREENSHOT_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "cbb-screenshots")
	}
	w.page.call(t, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 920, "height": 640, "deviceScaleFactor": 1, "mobile": false}, nil)
	defer w.page.call(t, "Emulation.clearDeviceMetricsOverride", map[string]any{}, nil)

	for _, c := range screenshotCases {
		w.page.call(t, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": c.look}}}, nil)
		w.open(c.lang)
		w.eval(fmt.Sprintf(`(() => { const s = document.createElement("style"); s.textContent = %q; document.head.append(s); return document.fonts.ready.then(() => true); })()`, screenshotStyle), nil)
		w.wait(`$all("#devices .tile").length === 14`)
		shoot := func(view string) {
			name := fmt.Sprintf("%s-%s-%s.png", view, c.lang, c.look)
			got := w.capture(t)
			ref := filepath.Join("testdata", "screenshots", name)
			if update {
				if err := os.MkdirAll(filepath.Dir(ref), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(ref, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(ref)
			if err != nil {
				t.Errorf("%s: no reference picture (write them with CBB_UPDATE_SCREENSHOTS=1): %v", name, err)
				return
			}
			share, diff, err := comparePNG(want, got)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			if share > maxDiffering {
				os.MkdirAll(out, 0o755)
				os.WriteFile(filepath.Join(out, name), got, 0o644)
				if diff != nil {
					var b bytes.Buffer
					png.Encode(&b, diff)
					os.WriteFile(filepath.Join(out, "diff-"+name), b.Bytes(), 0o644)
				}
				t.Errorf("%s: %.2f%% of the pixels differ from the reference; the new picture and the difference are in %s", name, share*100, out)
			}
		}
		shoot("devices")
		w.eval(`$click('#devices .tile[data-id="win"]')`, nil)
		w.wait(`!$q("#detail").hidden && $q("#detail .detail-head")`)
		shoot("card")
		w.eval(`$click("#close")`, nil)
		w.wait(`$q("#detail").hidden`)
		w.eval(`$click("#settings")`, nil)
		w.wait(`$q("#settings-dialog").open`)
		shoot("settings")
		w.eval(`$click('#settings-dialog menu button')`, nil)
	}
	w.page.call(t, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{}}, nil)
}

// capture takes a PNG of the page as it is.
func (w *window) capture(t *testing.T) []byte {
	t.Helper()
	// Nothing focused, so no focus ring is pictured.
	w.eval(`document.activeElement?.blur(); true`, nil)
	var r struct {
		Data string `json:"data"`
	}
	w.page.call(t, "Page.captureScreenshot", map[string]any{"format": "png"}, &r)
	b, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// comparePNG returns the share of pixels that differ between two PNGs and
// a picture of where: the differing pixels red over a faint copy of want.
func comparePNG(want, got []byte) (float64, image.Image, error) {
	a, err := png.Decode(bytes.NewReader(want))
	if err != nil {
		return 0, nil, fmt.Errorf("the reference: %w", err)
	}
	b, err := png.Decode(bytes.NewReader(got))
	if err != nil {
		return 0, nil, fmt.Errorf("the new picture: %w", err)
	}
	if a.Bounds() != b.Bounds() {
		return 1, nil, fmt.Errorf("the picture is %v, the reference %v", b.Bounds().Size(), a.Bounds().Size())
	}
	diff := image.NewRGBA(a.Bounds())
	differing := 0
	for y := a.Bounds().Min.Y; y < a.Bounds().Max.Y; y++ {
		for x := a.Bounds().Min.X; x < a.Bounds().Max.X; x++ {
			ca, cb := color.RGBAModel.Convert(a.At(x, y)).(color.RGBA), color.RGBAModel.Convert(b.At(x, y)).(color.RGBA)
			if far(ca.R, cb.R) || far(ca.G, cb.G) || far(ca.B, cb.B) || far(ca.A, cb.A) {
				differing++
				diff.Set(x, y, color.RGBA{255, 0, 0, 255})
				continue
			}
			g := uint8((uint16(ca.R) + uint16(ca.G) + uint16(ca.B)) / 12)
			diff.Set(x, y, color.RGBA{g, g, g, 255})
		}
	}
	return float64(differing) / float64(a.Bounds().Dx()*a.Bounds().Dy()), diff, nil
}

func far(x, y uint8) bool {
	if x > y {
		return x-y > pixelTolerance
	}
	return y-x > pixelTolerance
}

// missingFonts lists the families of screenshotFonts fontconfig lacks.
func missingFonts() []string {
	out, err := exec.Command("fc-list", ":", "family").Output()
	if err != nil {
		return screenshotFonts
	}
	var have []string
	for _, line := range strings.Split(string(out), "\n") {
		have = append(have, strings.Split(line, ",")...)
	}
	var missing []string
	for _, f := range screenshotFonts {
		if !slices.Contains(have, f) {
			missing = append(missing, f)
		}
	}
	return missing
}
