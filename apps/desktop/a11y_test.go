// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The window in every language and for every reader (docs/testing.md, "The
// apps' languages, accessibility and screenshots"): each of the project's
// eight languages lays out without English left over, clipped text or a
// page wider than the window, Arabic and Hebrew from right to left; every
// control has a name a screen reader reads; text keeps WCAG AA contrast in
// every colour and appearance; at twice the text size nothing is cut off;
// and the keyboard reaches every control with a visible focus.

// projectLanguages are the languages every app speaks (docs/apps.md).
var projectLanguages = []string{"ar", "en", "es", "he", "hi", "ru", "sw", "zh"}

// rtlLanguages are those written from right to left.
var rtlLanguages = []string{"ar", "he"}

// layoutChecks are the page's checks of what a reader sees, in the helpers'
// style: each returns a list of what is wrong, empty when all is well.
const layoutChecks = `
var $visible = (e) => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none"; };
var $label = (e) => (e.id ? "#" + e.id : e.tagName.toLowerCase() + (e.className && typeof e.className === "string" ? "." + e.className.trim().split(/\s+/).join(".") : "")) + " " + JSON.stringify((e.textContent || e.getAttribute("aria-label") || "").trim().slice(0, 40));
// The top layer: an open modal dialog, else the page.
var $layer = () => [...document.querySelectorAll("dialog[open]")].pop() ?? document.body;
// Text an element holds itself, not in its children.
var $ownText = (e) => [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim() !== "");
// clipped: text cut off where the page does not mean to end it with "…",
// text out of the window, and a page wider than the window.
var $clipped = () => {
  const out = [];
  const root = $layer();
  for (const e of root.querySelectorAll("*")) {
    if (!$visible(e) || !$ownText(e)) continue;
    const s = getComputedStyle(e);
    const hides = (v) => v === "hidden" || v === "clip";
    if (hides(s.overflowX) && s.textOverflow !== "ellipsis" && e.scrollWidth > e.clientWidth + 1) out.push("cut off across: " + $label(e));
    if (hides(s.overflowY) && e.scrollHeight > e.clientHeight + 2 && s.webkitLineClamp === "none") out.push("cut off below: " + $label(e));
    const r = e.getBoundingClientRect();
    if (r.right > innerWidth + 1 || r.left < -1) out.push("out of the window: " + $label(e));
  }
  if (document.documentElement.scrollWidth > innerWidth + 1) out.push("the page is " + document.documentElement.scrollWidth + " px wide in a window of " + innerWidth);
  return out;
};
// sideways: text set to one side whatever the language's direction.
var $sideways = () => {
  const out = [];
  for (const e of $layer().querySelectorAll("*")) {
    if (!$visible(e) || !$ownText(e) || e.closest(".mono, code, .code, input")) continue;
    const a = getComputedStyle(e).textAlign;
    if (a === "left" || a === "right") out.push(a + ": " + $label(e));
  }
  return out;
};
// WCAG's relative luminance and contrast of CSS colours.
var $rgba = (c) => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
var $over = (top, under) => [0, 1, 2].map((i) => top[i] * top[3] + under[i] * (1 - top[3])).concat(1);
var $lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
var $ratio = (a, b) => { const x = $lum(a), y = $lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
// The colour behind an element: its and its ancestors' backgrounds laid
// over each other, down to the page's.
var $behind = (e) => {
  const layers = [];
  for (let x = e; x; x = x.parentElement) {
    const c = $rgba(getComputedStyle(x).backgroundColor);
    if (c && c[3] > 0) { layers.push(c); if (c[3] >= 1) break; }
  }
  let bg = $rgba(getComputedStyle(document.documentElement).backgroundColor) ?? [255, 255, 255, 1];
  if (bg[3] < 1) bg = $over(bg, [255, 255, 255, 1]);
  for (const c of layers.reverse()) bg = $over(c, bg);
  return bg;
};
// lowContrast: text below 4.5:1 against what is behind it, or 3:1 for large
// text; a disabled control is exempt, as WCAG has it.
var $lowContrast = () => {
  const out = [];
  for (const e of $layer().querySelectorAll("*")) {
    if (!$visible(e) || !$ownText(e) || e.closest(":disabled")) continue;
    const s = getComputedStyle(e);
    let fg = $rgba(s.color);
    if (!fg) continue;
    let alpha = 1;
    for (let x = e; x; x = x.parentElement) alpha *= Number(getComputedStyle(x).opacity);
    const bg = $behind(e);
    fg = $over([fg[0], fg[1], fg[2], fg[3] * alpha], bg);
    const size = parseFloat(s.fontSize), bold = Number(s.fontWeight) >= 700;
    const need = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
    const r = $ratio(fg, bg);
    if (r < need) out.push(r.toFixed(2) + ":1 (needs " + need + "): " + $label(e));
  }
  return out;
};
// controls: the visible controls of the top layer.
var $controls = () => [...$layer().querySelectorAll("button, input, select, textarea, a[href], [tabindex]")].filter((e) => $visible(e) && !e.disabled && e.tabIndex >= 0);
// focusShown: whether the focused element draws its focus.
var $focusShown = (e) => { const s = getComputedStyle(e); return (s.outlineStyle !== "none" && parseFloat(s.outlineWidth) > 0) || (s.boxShadow && s.boxShadow !== "none"); };
`

// check evaluates one of layoutChecks and reports what it found.
func (w *window) check(t *testing.T, what, js string) {
	t.Helper()
	var bad []string
	w.eval(layoutChecks+js, &bad)
	for _, b := range bad {
		t.Errorf("%s: %s", what, b)
	}
}

// views opens each of the window's views in turn, runs see in it and
// closes it again: the devices, a device's card, this computer's card,
// Settings and Add a device.
func (w *window) views(t *testing.T, see func(view string)) {
	t.Helper()
	w.wait(`$all("#devices .tile").length === 14`)
	see("the devices")
	w.eval(`$click('#devices .tile[data-id="win"]')`, nil)
	w.wait(`!$q("#detail").hidden && $q("#detail .detail-head")`)
	see("a device's card")
	w.eval(`$click('#devices .tile[data-id="self"]')`, nil)
	w.wait(`!$q("#detail").hidden && $q('#devices .tile[data-id="self"]').classList.contains("selected")`)
	see("this computer's card")
	w.eval(`$click("#close")`, nil)
	w.wait(`$q("#detail").hidden`)
	w.eval(`$click("#settings")`, nil)
	w.wait(`$q("#settings-dialog").open`)
	see("Settings")
	w.eval(`$click('#settings-dialog menu button')`, nil)
	w.wait(`!$q("#settings-dialog").open`)
	w.eval(`$click("#add")`, nil)
	w.wait(`$q("#add-dialog").open`)
	see("Add a device")
	w.eval(`$q("#add-dialog").close(); true`, nil)
	w.wait(`!$q("#add-dialog").open`)
}

// languages (A9): in each of the eight languages every text of the page is
// translated, nothing is cut off or out of the window, Arabic and Hebrew
// run from right to left and the header with them, and every control has a
// name in that language.
func (w *window) languages(t *testing.T) {
	if got := languages(); !slices.Equal(got, projectLanguages) {
		t.Fatalf("the window speaks %q, not the project's %q", got, projectLanguages)
	}
	for _, lang := range projectLanguages {
		t.Run(lang, func(t *testing.T) {
			w.t = t
			d := w.open(lang)
			rtl := slices.Contains(rtlLanguages, lang)
			dir := map[bool]string{false: "ltr", true: "rtl"}[rtl]
			w.wait(fmt.Sprintf(`document.documentElement.lang === %q && document.documentElement.dir === %q`, lang, dir))

			// The header runs with the language: Settings at the end of the line.
			var settings struct{ Left, Width float64 }
			w.eval(`(() => { const r = $q("#settings").getBoundingClientRect(); return {left: r.left, width: innerWidth}; })()`, &settings)
			if atRight := settings.Left > settings.Width/2; atRight == rtl {
				t.Errorf("Settings is on the %s in %s", map[bool]string{false: "left", true: "right"}[atRight], dir)
			}

			if lang != "en" {
				var left []string
				w.eval(`$all("[data-t]").filter((e) => e.textContent === e.dataset.en && /[A-Za-z]{3}/.test(e.dataset.en)).map((e) => e.dataset.en)`, &left)
				if len(left) > 0 {
					t.Errorf("these stay English: %q", left)
				}
				var sync, head string
				w.eval(`$q("#sync").getAttribute("aria-label")`, &sync)
				if want := d.T("Sync is on"); sync != want || want == "Sync is on" {
					t.Errorf("the sync switch says %q, not %q", sync, want)
				}
				w.eval(`$h()`, &head)
				if want := goFormat(d.T("%d of %d online"), w.svc.online(), 14); head != want {
					t.Errorf("the headline says %q, not %q", head, want)
				}
			}

			w.views(t, func(view string) {
				w.check(t, view, `$clipped()`)
				if rtl {
					w.check(t, view, `$sideways()`)
				}
				w.namedControls(t, view, d)
			})
		})
	}
}

// axNode is a node of the browser's accessibility tree.
type axNode struct {
	Ignored bool `json:"ignored"`
	Role    struct {
		Value string `json:"value"`
	} `json:"role"`
	Name struct {
		Value string `json:"value"`
	} `json:"name"`
	BackendDOMNodeID int `json:"backendDOMNodeId"`
}

// interactiveRoles are the roles of controls a screen reader announces by
// their name.
var interactiveRoles = []string{"button", "link", "textbox", "searchbox", "combobox", "checkbox", "switch", "radio", "menuitem", "slider", "spinbutton", "tab"}

// namedControls (U14): every control the accessibility tree shows has a
// name, as VoiceOver, Narrator and Orca read it, and in a translated
// window the name of an icon button is not its English.
func (w *window) namedControls(t *testing.T, view string, d *Desk) {
	t.Helper()
	var tree struct {
		Nodes []axNode `json:"nodes"`
	}
	w.page.call(t, "Accessibility.getFullAXTree", map[string]any{}, &tree)
	controls := 0
	for _, n := range tree.Nodes {
		if n.Ignored || !slices.Contains(interactiveRoles, n.Role.Value) {
			continue
		}
		controls++
		if strings.TrimSpace(n.Name.Value) == "" {
			t.Errorf("%s: a %s without a name (%s)", view, n.Role.Value, w.describe(n.BackendDOMNodeID))
		}
	}
	if controls == 0 {
		t.Errorf("%s: the accessibility tree has no controls", view)
	}
	if d.lang != "en" {
		var english []string
		w.eval(`$all("[data-t-title]").filter((e) => $visible(e) && e.getAttribute("aria-label") === e.dataset.tTitle).map((e) => e.dataset.tTitle)`, &english)
		for _, e := range english {
			t.Errorf("%s: a control is named %q in English", view, e)
		}
	}
}

// describe names a DOM node of the accessibility tree for a message.
func (w *window) describe(backend int) string {
	var r struct {
		Node struct {
			NodeName   string   `json:"nodeName"`
			Attributes []string `json:"attributes"`
		} `json:"node"`
	}
	if err := w.page.do("DOM.describeNode", map[string]any{"backendNodeId": backend}, &r); err != nil {
		return err.Error()
	}
	return strings.ToLower(r.Node.NodeName) + " " + strings.Join(r.Node.Attributes, " ")
}

// contrast (U15): every text of every view keeps WCAG AA contrast with
// what is behind it, in each of the ten colours on the dark and the light
// base.
func (w *window) contrast(t *testing.T) {
	w.t = t
	w.open("en")
	var colors []string
	w.eval(`import("./tokens.js").then((m) => m.colors.map((c) => c.name))`, &colors)
	for _, look := range []string{"dark", "light"} {
		for _, c := range colors {
			w.eval(fmt.Sprintf(`$click("#settings"); $click('[data-appearance="%s"]'); $click('[data-color="%s"]'); $click('#settings-dialog menu button')`, look, c), nil)
			w.wait(`!$q("#settings-dialog").open`)
			w.views(t, func(view string) {
				w.check(t, fmt.Sprintf("%s in %s, %s", c, look, view), `$lowContrast()`)
			})
		}
	}
	w.eval(`$click("#settings"); $click('[data-appearance="system"]'); $click('[data-color="terminal"]'); $click('#settings-dialog menu button')`, nil)
}

// largeText (U16): with the system's text at twice its size (Windows'
// "Make text bigger", GNOME's Large Text and the browser's zoom all enlarge
// the whole page) the window at its starting size is half as wide and high
// in CSS pixels; nothing is cut off and the page is no wider than the
// window, in English and in Arabic.
func (w *window) largeText(t *testing.T) {
	w.t = t
	// main.go opens the window at 920 by 640.
	w.page.call(t, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 460, "height": 320, "deviceScaleFactor": 2, "mobile": false}, nil)
	defer w.page.call(t, "Emulation.clearDeviceMetricsOverride", map[string]any{}, nil)
	for _, lang := range []string{"en", "ar"} {
		w.open(lang)
		w.views(t, func(view string) {
			w.check(t, lang+", "+view, `$clipped()`)
		})
	}
}

// keyboard (U17): Tab reaches every control of the header and of Settings,
// and the focused one shows it.
func (w *window) keyboard(t *testing.T) {
	w.t = t
	w.open("en")
	w.wait(`$all("#devices .tile").length === 14`)
	w.tabThrough(t, "the header", `[...document.querySelectorAll("header button")].filter((e) => $visible(e))`)
	w.eval(`$click("#settings")`, nil)
	w.wait(`$q("#settings-dialog").open`)
	w.tabThrough(t, "Settings", `$controls()`)
	w.eval(`$click('#settings-dialog menu button')`, nil)
}

// tabThrough presses Tab until the focus comes round again and checks that
// it met every control the expression lists and drew each focus.
func (w *window) tabThrough(t *testing.T, where, want string) {
	t.Helper()
	var wanted []string
	w.eval(layoutChecks+`(`+want+`).map($label)`, &wanted)
	met := map[string]bool{}
	for range 200 {
		for _, typ := range []string{"rawKeyDown", "keyUp"} {
			w.page.call(t, "Input.dispatchKeyEvent", map[string]any{"type": typ, "key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9}, nil)
		}
		var at struct {
			Label string
			Shown bool
		}
		w.eval(layoutChecks+`(() => { const e = document.activeElement; return e && e !== document.body ? {label: $label(e), shown: $focusShown(e)} : {label: "", shown: true}; })()`, &at)
		if at.Label == "" {
			continue
		}
		if !at.Shown && !met[at.Label] {
			t.Errorf("%s: the focus on %s does not show", where, at.Label)
		}
		if met[at.Label] && len(met) >= len(wanted) {
			break
		}
		met[at.Label] = true
	}
	for _, c := range wanted {
		if !met[c] {
			got, _ := json.Marshal(mapKeys(met))
			t.Errorf("%s: Tab never reaches %s (it reached %s)", where, c, got)
		}
	}
}

// goFormat fills a translation as the window's t does: %s and %d in order,
// %1$s and %2$d by their place.
func goFormat(s string, args ...any) string {
	return fmt.Sprintf(regexp.MustCompile(`%(\d+)\$[sd]`).ReplaceAllString(strings.NewReplacer("%d", "%v", "%s", "%v").Replace(s), "%[$1]v"), args...)
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
