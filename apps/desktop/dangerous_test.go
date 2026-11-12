// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// The sheet of the dangerous screens (docs/testing.md, "The dangerous
// screens"): every screen of the window where a person decides something
// the group's safety depends on, in each of the project's eight languages,
// as one HTML file to leaf through. A person checks it (a native speaker
// for each language); this only draws it. It is written when
// CBB_DANGEROUS_SHEET names a directory:
//
//	CBB_DANGEROUS_SHEET=/tmp/sheet go test -run 'TestWindow/dangerous' .
//
// and CI's tray job uploads it as the dangerous-screens artifact.

// dangerousScreen is one screen of the sheet: what it decides, and how to
// bring it up from the devices' view and close it again.
type dangerousScreen struct {
	id, title string
	// setUp changes the service and the window until the screen shows;
	// the picture is taken of what is open then.
	setUp func(w *window, lang string)
	// tearDown closes what setUp opened.
	tearDown func(w *window)
}

// dangerousShot is a screen in a language: its picture and its words, so
// that a reviewer can quote them.
type dangerousShot struct {
	Screen, Lang string
	JPEG         []byte
	Text         string
}

func (w *window) dangerous(t *testing.T) {
	out := os.Getenv("CBB_DANGEROUS_SHEET")
	if out == "" {
		t.Skip("CBB_DANGEROUS_SHEET names no directory for the sheet")
	}
	w.t = t
	if runtime.GOOS != "linux" {
		t.Skip("the sheet is drawn on Linux")
	}
	if missing := missingFonts(); len(missing) > 0 {
		t.Fatalf("the sheet needs the fonts %q", missing)
	}
	t.Setenv("CBB_DEBUG", "0")
	w.page.call(t, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 920, "height": 640, "deviceScaleFactor": 1, "mobile": false}, nil)
	defer w.page.call(t, "Emulation.clearDeviceMetricsOverride", map[string]any{}, nil)
	w.page.call(t, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": "dark"}}}, nil)
	defer w.page.call(t, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{}}, nil)

	old := adminRun
	adminRun = fakeDangerousRun
	defer func() { adminRun = old }()

	var shots []dangerousShot
	for _, lang := range projectLanguages {
		for _, s := range dangerousScreens {
			w.open(lang)
			w.eval(fmt.Sprintf(`(() => { const s = document.createElement("style"); s.textContent = %q; document.head.append(s); return document.fonts.ready.then(() => true); })()`, screenshotStyle), nil)
			s.setUp(w, lang)
			// The open dialog's words, or the alerts' when none is open.
			var text string
			w.eval(`(() => { const d = $all("dialog[open]").pop(); return (d ?? $q("#alerts")).innerText.trim(); })()`, &text)
			shots = append(shots, dangerousShot{Screen: s.id, Lang: lang, JPEG: toJPEG(t, w.capture(t)), Text: text})
			s.tearDown(w)
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "dangerous-screens.html")
	phone := phoneShots(t, filepath.Join(out, "android"))
	if err := os.WriteFile(path, dangerousSheet(shots, phone), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("the sheet of %d pictures, %d of them Android's, is %s", len(shots)+len(phone), len(phone), path)
}

// dangerousScreens are the screens of the sheet, in the order a person
// meets them.
var dangerousScreens = []dangerousScreen{
	{
		id: "join-digits", title: "Joining a group: the six digits the phone compares",
		setUp: func(w *window, _ string) {
			w.svc.mu.Lock()
			w.svc.status.Group = ""
			w.svc.mu.Unlock()
			w.open(w.desk.Load().lang)
			w.eval(fmt.Sprintf(`(() => { const s = document.createElement("style"); s.textContent = %q; document.head.append(s); return document.fonts.ready.then(() => true); })()`, screenshotStyle), nil)
			w.wait(`$q("#join") && !$q("#join").disabled`)
			w.eval(`$click("#join")`, nil)
			w.wait(`$q("#join-dialog").open && $q("#join-digits").textContent === "123 456"`)
		},
		tearDown: func(w *window) {
			w.eval(`$q("#join-dialog").close(); true`, nil)
			w.wait(`!$q("#join-dialog").open`)
			w.desk.Load().CancelJoin()
			w.svc.mu.Lock()
			w.svc.status.Group = "cbb-7f3a"
			w.svc.mu.Unlock()
		},
	},
	{
		id: "invite-fingerprint", title: "An invitation used: admit the device only if its fingerprint is the same",
		setUp: func(w *window, _ string) {
			w.wait(`!$q("#add").hidden`)
			w.eval(`$click("#add")`, nil)
			w.wait(`$q("#add-dialog").open`)
			w.eval(`$click("#invite")`, nil)
			w.wait(`$q("#invite-dialog").open && !$q("#invite-ask").hidden && $q("#invite-fingerprint").textContent !== ""`)
		},
		tearDown: func(w *window) {
			w.eval(`$q("#invite-dialog").close(); true`, nil)
			w.wait(`!$q("#invite-dialog").open`)
			// Ended here too, not only by the dialog's close: the next
			// window may come before the window's own call.
			d := w.desk.Load()
			d.CancelInvite()
			for deadline := time.Now().Add(10 * time.Second); d.InviteState().Running && time.Now().Before(deadline); {
				time.Sleep(20 * time.Millisecond)
			}
		},
	},
	{
		id: "remove", title: "Removing a device",
		setUp: func(w *window, _ string) {
			w.wait(`$all("#devices .tile").length === 14`)
			w.eval(`$click('.tile[data-id="tv"]')`, nil)
			w.wait(`!$q("#detail").hidden && $q('[data-action="remove"]')`)
			w.eval(`$click('[data-action="remove"]')`, nil)
			w.wait(`$q("#confirm").open`)
		},
		tearDown: closeConfirm,
	},
	{
		id: "admin", title: "Making a computer an admin, whose key is a file",
		setUp: func(w *window, _ string) {
			w.wait(`$all("#devices .tile").length === 14`)
			w.eval(`$click('.tile[data-id="srv"]')`, nil)
			w.wait(`!$q("#detail").hidden && $q('[data-action="admin"]')`)
			w.eval(`$click('[data-action="admin"]')`, nil)
			w.wait(`$q("#confirm").open`)
		},
		tearDown: closeConfirm,
	},
	{
		id: "alerts", title: "The takeover warning and the owners split: a claim waits, admins removed each other, two claims, a key with two histories",
		setUp: func(w *window, _ string) {
			w.svc.mu.Lock()
			w.svc.status.Stop = "full"
			w.svc.status.Claims = []control.Claim{{By: "iPhone", State: "pending", LeftMS: 70 * 3600 * 1000}}
			w.svc.status.Conflicts = []control.Conflict{
				{Kind: "admins", Devices: []string{"MacBook", "Windows PC"}},
				{Kind: "claims", Devices: []string{"iPhone", "Pixel"}},
				{Kind: "two_histories", Devices: []string{"Home server"}},
			}
			w.svc.mu.Unlock()
			w.wait(`$all("#alerts .alert").length === 5`)
		},
		tearDown: func(w *window) {
			w.svc.mu.Lock()
			w.svc.status.Stop, w.svc.status.Claims, w.svc.status.Conflicts = "", nil, nil
			w.svc.mu.Unlock()
			w.wait(`$q("#alerts").hidden`)
		},
	},
	{
		id: "void-histories", title: "Voiding both histories of a key",
		setUp: func(w *window, _ string) {
			w.svc.mu.Lock()
			w.svc.status.Conflicts = []control.Conflict{{Kind: "two_histories", Devices: []string{"Home server"}}}
			w.svc.mu.Unlock()
			w.wait(`$all("#alerts .buttons button").length === 1`)
			w.eval(`$click("#alerts .buttons button")`, nil)
			w.wait(`$q("#confirm").open`)
		},
		tearDown: func(w *window) {
			closeConfirm(w)
			w.svc.mu.Lock()
			w.svc.status.Conflicts = nil
			w.svc.mu.Unlock()
			w.wait(`$q("#alerts").hidden`)
		},
	},
	{
		id: "recovery", title: "Claiming the group with the recovery key",
		setUp: func(w *window, _ string) {
			w.eval(`$click("#settings")`, nil)
			w.wait(`$q("#settings-dialog").open && $q("#advanced-recovery")`)
			w.eval(`$click("#advanced-recovery")`, nil)
			w.wait(`$q("#confirm").open && !$q("#confirm-input").hidden`)
		},
		tearDown: closeConfirm,
	},
	{
		id: "taken-over", title: "This device's group was taken over",
		setUp: func(w *window, _ string) {
			w.svc.mu.Lock()
			w.svc.status.Why = []control.WhyReason{{Code: "taken_over", Level: "stop", Device: "iPhone"}}
			w.svc.mu.Unlock()
			// The dialog shows the status the window last read: opened
			// again until it has read the new one.
			w.wait(`(() => { const d = $q("#why-dialog"); if (!d.open) $click("#advanced-why"); if ($q("#why-list").textContent.includes("iPhone")) return true; d.close(); return false; })()`)
		},
		tearDown: func(w *window) {
			w.eval(`$q("#why-dialog").close(); true`, nil)
			w.svc.mu.Lock()
			w.svc.status.Why = nil
			w.svc.mu.Unlock()
		},
	},
}

func closeConfirm(w *window) {
	w.eval(`$q("#confirm").close(); true`, nil)
	w.wait(`!$q("#confirm").open`)
}

// fakeDangerousRun stands for cbb as the administrator: cbb pair -app and
// cbb invite -app write what the real ones write and wait until the window
// removes the file; anything else is cancelled, as a closed prompt.
func fakeDangerousRun(args []string, _ string, _ bool) error {
	var file string
	var line any
	switch {
	case len(args) == 3 && args[0] == "pair" && args[1] == "-app":
		file = args[2]
		line = map[string]any{"qr": "cbb://join?code=123456&addr=192.168.1.20%3A8764&fp=q83vEjRWeJA", "expires": 300, "port": 8764}
	case len(args) >= 4 && args[0] == "invite":
		for i := range args[:len(args)-1] {
			if args[i] == "-app" {
				file = args[i+1]
			}
		}
		line = appInvite{Invite: "cbb://invite?g=cbb-7f3a&h=203.0.113.9%3A8764&t=q83vEjRWeJA", Expires: inviteSeconds,
			Joining: &InviteJoining{Name: "Anna's laptop", OS: "Windows", Fingerprint: "3F9A 1C2E 88B0 D45E 7A19"}}
	default:
		return errCancelled
	}
	if file == "" {
		return errCancelled
	}
	b, err := json.Marshal(line)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, append(b, '\n'), 0o600); err != nil {
		return err
	}
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(file); err != nil {
			return &adminError{msg: "cancelled"}
		}
	}
	return &adminError{msg: "cancelled"}
}

// toJPEG makes a PNG a JPEG, a tenth of its size, for the sheet.
func toJPEG(t *testing.T, b []byte) []byte {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// dangerousSheet is the HTML page: a section for each screen, the eight
// languages in it, each picture with its words under it; a click on a
// picture shows it whole.
func dangerousSheet(shots, phone []dangerousShot) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dangerous screens</title>
<style>
:root { color-scheme: light dark; --bg: #fff; --fg: #1d1d1f; --dim: #6e6e73; --line: #d2d2d7; }
@media (prefers-color-scheme: dark) { :root { --bg: #161618; --fg: #f5f5f7; --dim: #a1a1a6; --line: #3a3a3c; } }
body { margin: 0 auto; max-width: 1400px; padding: 16px; background: var(--bg); color: var(--fg); font: 15px/1.45 system-ui, sans-serif; }
h1 { font-size: 24px; } h2 { font-size: 18px; margin-top: 40px; border-top: 1px solid var(--line); padding-top: 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
figure { margin: 0; } figcaption { color: var(--dim); font-size: 13px; }
img { width: 100%; border: 1px solid var(--line); border-radius: 6px; cursor: zoom-in; }
img.big { position: fixed; inset: 0; margin: auto; width: auto; max-width: 100vw; max-height: 100vh; cursor: zoom-out; z-index: 1; }
pre { white-space: pre-wrap; font: 12px/1.4 ui-monospace, monospace; color: var(--dim); max-height: 12em; overflow: auto; }
.lang { font-weight: 600; color: var(--fg); }
</style>
</head>
<body>
<h1>Dangerous screens</h1>
<p>Every screen of the tray app and of the Android app where a person decides something the group's safety depends on, in the project's eight languages, drawn by their UI tests (apps/desktop/dangerous_test.go, apps/android/app/src/test/kotlin/tools/cbb/DangerousScreensTest.kt). For a person to read: does each language say the same as the English, as plainly, and does nothing hide the danger? A click on a picture shows it whole.</p>
`)
	for _, s := range dangerousScreens {
		section(&b, s.id, s.title, shots)
	}
	if len(phone) > 0 {
		b.WriteString("<h1 id=\"android\">Android</h1>\n")
	}
	for _, s := range phoneScreens {
		section(&b, s.id, s.title, phone)
	}
	b.WriteString(`<script>document.addEventListener("click", (e) => { if (e.target.tagName === "IMG") e.target.classList.toggle("big"); });</script>
</body>
</html>
`)
	return []byte(b.String())
}

// section writes a screen's heading and its pictures in every language.
func section(b *strings.Builder, id, title string, shots []dangerousShot) {
	var n int
	for _, sh := range shots {
		if sh.Screen == id {
			n++
		}
	}
	if n == 0 {
		return
	}
	fmt.Fprintf(b, "<h2 id=%q>%s</h2>\n<div class=\"grid\">\n", id, html.EscapeString(title))
	for _, sh := range shots {
		if sh.Screen != id {
			continue
		}
		fmt.Fprintf(b, "<figure><img alt=\"%s, %s\" src=\"data:image/jpeg;base64,%s\"><figcaption><span class=\"lang\">%s</span><pre>%s</pre></figcaption></figure>\n",
			html.EscapeString(title), sh.Lang, base64.StdEncoding.EncodeToString(sh.JPEG), sh.Lang, html.EscapeString(sh.Text))
	}
	b.WriteString("</div>\n")
}

// phoneScreens are the Android app's screens of the sheet, which
// DangerousScreensTest draws into the android folder beside the sheet.
var phoneScreens = []struct{ id, title string }{
	{"invite-fingerprint", "An invitation used: admit the device only if its fingerprint is the same"},
	{"remove", "Removing a device"},
	{"remove-root", "Removing the root phone: taking the group over"},
	{"alerts", "The takeover warning and the owners split: a claim waits, admins removed each other, two claims, a key with two histories"},
	{"recovery-sheet", "The recovery sheet, shown once"},
	{"recovery-kept", "Closing the recovery sheet: did you keep it?"},
}

// phoneShots reads the Android pictures and words in dir, if it is there,
// each picture halved, as the phone's are drawn at three pixels a point.
func phoneShots(t *testing.T, dir string) []dangerousShot {
	t.Helper()
	var out []dangerousShot
	for _, s := range phoneScreens {
		for _, lang := range projectLanguages {
			name := filepath.Join(dir, s.id+"-"+lang)
			b, err := os.ReadFile(name + ".png")
			if err != nil {
				continue
			}
			img, err := png.Decode(bytes.NewReader(b))
			if err != nil {
				t.Fatalf("%s.png: %v", name, err)
			}
			text, _ := os.ReadFile(name + ".txt")
			var j bytes.Buffer
			if err := jpeg.Encode(&j, half(img), &jpeg.Options{Quality: 85}); err != nil {
				t.Fatal(err)
			}
			out = append(out, dangerousShot{Screen: s.id, Lang: lang, JPEG: j.Bytes(), Text: string(text)})
		}
	}
	return out
}

// half is img at half its size, each pixel the mean of four.
func half(img image.Image) image.Image {
	r := img.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, r.Dx()/2, r.Dy()/2))
	for y := 0; y < r.Dy()/2; y++ {
		for x := 0; x < r.Dx()/2; x++ {
			var sum [4]uint32
			for _, d := range [][2]int{{0, 0}, {1, 0}, {0, 1}, {1, 1}} {
				c := color.RGBAModel.Convert(img.At(r.Min.X+2*x+d[0], r.Min.Y+2*y+d[1])).(color.RGBA)
				sum[0] += uint32(c.R)
				sum[1] += uint32(c.G)
				sum[2] += uint32(c.B)
				sum[3] += uint32(c.A)
			}
			dst.Set(x, y, color.RGBA{uint8(sum[0] / 4), uint8(sum[1] / 4), uint8(sum[2] / 4), uint8(sum[3] / 4)})
		}
	}
	return dst
}
