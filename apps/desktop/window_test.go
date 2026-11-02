// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/HunterEwok/clipboardbridge/internal/control"
)

// The window's tests (docs/testbench-catalogue.md, A5, A8, A9, A15, A16,
// U12) run frontend/ in a headless Chrome or Edge, as WebView2 runs it on
// Windows, against the real Desk: a stand-in for Wails' runtime passes each
// call to Desk's method over HTTP, a stand-in service answers on the
// control socket, and adminRun records what would run as the
// administrator. The browser is driven over the DevTools protocol. Without
// a browser the test is skipped, except in CI, where it fails.

// winRuntime is the stand-in for /wails/runtime.js.
const winRuntime = `export const Call = {
  ByName: async (name, ...args) => {
    const r = await fetch("/call/" + name, { method: "POST", body: JSON.stringify(args) });
    const text = await r.text();
    if (!r.ok) throw new Error(text);
    return text ? JSON.parse(text) : null;
  },
};
`

func TestWindow(t *testing.T) {
	exe := findBrowser(t)
	svc := newFakeService(t)
	w := &window{t: t, svc: svc}
	srv := httptest.NewServer(w.handler())
	t.Cleanup(srv.Close)
	w.page = startBrowser(t, exe)
	w.url = srv.URL + "/index.html"

	t.Run("themes", w.themes)
	t.Run("collections", w.collections)
	t.Run("russian", w.russian)
	t.Run("errors", w.errors)
	t.Run("admin", w.admin)
}

// window is the page under test and what stands around it.
type window struct {
	t    *testing.T
	svc  *fakeService
	page *cdpPage
	url  string
	desk atomic.Pointer[Desk]
	// ran lists what adminRun was asked to run; fail is its next answer.
	mu   sync.Mutex
	ran  [][]string
	fail error
}

func (w *window) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/wails/runtime.js", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/javascript")
		io.WriteString(rw, winRuntime)
	})
	mux.HandleFunc("/call/", func(rw http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/call/main.Desk.")
		out, err := callDesk(w.desk.Load(), name, r.Body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(out)
	})
	mux.Handle("/", http.FileServer(http.Dir("frontend")))
	return mux
}

// callDesk calls Desk's method by name with the JSON arguments, as Wails'
// binding does, and returns its first result as JSON.
func callDesk(d *Desk, name string, body io.Reader) ([]byte, error) {
	m := reflect.ValueOf(d).MethodByName(name)
	if !m.IsValid() {
		return nil, fmt.Errorf("Desk has no method %s", name)
	}
	var raw []json.RawMessage
	if err := json.NewDecoder(body).Decode(&raw); err != nil {
		return nil, err
	}
	if len(raw) != m.Type().NumIn() {
		return nil, fmt.Errorf("%s takes %d arguments, not %d", name, m.Type().NumIn(), len(raw))
	}
	args := make([]reflect.Value, len(raw))
	for i, a := range raw {
		v := reflect.New(m.Type().In(i))
		if err := json.Unmarshal(a, v.Interface()); err != nil {
			return nil, fmt.Errorf("%s argument %d: %w", name, i, err)
		}
		args[i] = v.Elem()
	}
	var result any
	for _, o := range m.Call(args) {
		if e, ok := o.Interface().(error); ok || o.Type() == reflect.TypeFor[error]() {
			if e != nil {
				return nil, e
			}
			continue
		}
		result = o.Interface()
	}
	return json.Marshal(result)
}

// open loads the window over a new Desk in lang and waits for its first
// picture.
func (w *window) open(lang string) *Desk {
	d := &Desk{socket: w.svc.path, lang: lang, tr: translations(lang),
		settings:     Settings{Color: "terminal", Appearance: "system", Layout: "tiles"},
		settingsPath: filepath.Join(w.t.TempDir(), "desktop.json")}
	w.desk.Store(d)
	w.page.call(w.t, "Page.navigate", map[string]any{"url": w.url}, nil)
	w.wait(`document.readyState === "complete" && $h() !== ""`)
	return d
}

// eval evaluates JavaScript in the page (with the helpers of pageHelpers)
// and decodes its value into out, if out is not nil.
func (w *window) eval(js string, out any) {
	w.t.Helper()
	if err := w.page.eval(js, out); err != nil {
		w.t.Fatalf("%v\nin: %s", err, js)
	}
}

// wait waits until the JavaScript expression is true.
func (w *window) wait(js string) {
	w.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		var ok bool
		if last = w.page.eval("!!("+js+")", &ok); last == nil && ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	var body string
	w.page.eval(`document.body.innerText`, &body)
	w.t.Fatalf("still not true after 15 s: %s (%v)\nthe window says:\n%s", js, last, body)
}

// pageHelpers are short names the tests' JavaScript uses.
const pageHelpers = `
var $q = (s) => document.querySelector(s);
var $all = (s) => [...document.querySelectorAll(s)];
var $h = () => $q("#headline")?.textContent ?? "";
var $click = (s) => { const e = $q(s); if (!e) throw new Error("no " + s); e.click(); return true; };
var $clickText = (s, text) => { const all = $all(s), e = all.find((x) => x.textContent.trim() === text); if (!e) throw new Error("no " + s + " " + text + " among " + JSON.stringify(all.map((x) => x.textContent.trim()))); e.click(); return true; };
var $answer = (text) => { $q("#confirm-input").value = text; return $click("#confirm-ok"); };
var $order = () => $all("#devices .tiles > .cell").map((c) => c.dataset.ref);
var $search = (text) => { const s = $q("#search"); s.value = text; s.dispatchEvent(new Event("input", {bubbles: true})); return true; };
var $css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim().toUpperCase();
`

// themes (A15): the ten colours in Dark, Light and System, kept in the
// settings; tiles, a list and the orbit; every kind of device its own icon.
func (w *window) themes(t *testing.T) {
	w.t = t
	d := w.open("en")
	// The 13 devices and this computer, first.
	w.wait(`$all("#devices .tile").length === 14 && $q("#devices .tile").dataset.id === "self"`)
	var icons int
	w.eval(`new Set($all('#devices .tile:not([data-id="self"]) svg').map((s) => s.innerHTML)).size`, &icons)
	if icons != 12 {
		t.Errorf("the 13 devices of 12 kinds show %d different icons", icons)
	}

	type pair struct{ Background, Accent string }
	type color struct {
		Name        string
		Dark, Light pair
	}
	var colors []color
	w.eval(`import("./tokens.js").then((m) => m.colors)`, &colors)
	if len(colors) != 10 {
		t.Fatalf("Settings offers %d colours, not ten", len(colors))
	}
	w.eval(`$click("#settings")`, nil)
	for _, look := range []string{"dark", "light"} {
		w.eval(fmt.Sprintf(`$click('[data-appearance="%s"]')`, look), nil)
		for _, c := range colors {
			w.eval(fmt.Sprintf(`$click('[data-color="%s"]')`, c.Name), nil)
			want := c.Dark
			if look == "light" {
				want = c.Light
			}
			var got pair
			w.eval(`({background: $css("--background"), accent: $css("--accent")})`, &got)
			if got.Background != strings.ToUpper(want.Background) || got.Accent != strings.ToUpper(want.Accent) {
				t.Errorf("%s in %s: the window's background and accent are %s and %s, not %s and %s",
					c.Name, look, got.Background, got.Accent, want.Background, want.Accent)
			}
		}
	}
	// System follows the system's choice.
	w.eval(`$click('[data-appearance="system"]'); $click('[data-color="terminal"]')`, nil)
	for _, look := range []string{"dark", "light"} {
		w.page.call(t, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": look}}}, nil)
		want := colors[0].Dark.Background
		if look == "light" {
			want = colors[0].Light.Background
		}
		w.wait(fmt.Sprintf(`$css("--background") === %q`, strings.ToUpper(want)))
	}
	w.eval(`$click('#settings-dialog menu button')`, nil)
	w.waitSettings(d, func(s Settings) bool { return s.Appearance == "system" && s.Color == "terminal" })

	w.eval(`$click('[data-layout="list"]')`, nil)
	w.wait(`$all("#devices .list .row").length === 14`)
	w.eval(`$click('[data-layout="orbit"]')`, nil)
	w.wait(`$q("#devices").classList.contains("fixed") && $all("#devices [data-id]").length === 13`)
	w.eval(`$click('[data-layout="tiles"]')`, nil)
	w.wait(`$all("#devices .tiles .tile").length === 14`)
	w.waitSettings(d, func(s Settings) bool { return s.Layout == "tiles" })
}

// waitSettings waits until desktop.json holds what ok wants.
func (w *window) waitSettings(d *Desk, ok func(Settings) bool) {
	w.t.Helper()
	var s Settings
	for range 50 {
		s = Settings{}
		if data, err := os.ReadFile(d.settingsPath); err == nil && json.Unmarshal(data, &s) == nil && ok(s) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	w.t.Fatalf("desktop.json holds %+v", s)
}

// collections (A8): a new collection from a device's menu, another device
// moved in, its page, a rename, the keyboard's move, Ungroup, Back to the
// group's order; the search and the filters with more than 12 devices.
func (w *window) collections(t *testing.T) {
	w.t = t
	d := w.open("en")
	w.wait(`$all("#devices .tile").length === 14`)
	w.eval(`$click("#arrange")`, nil)
	w.wait(`$all(".cell.arranging").length === 13`)

	w.eval(`$click('[data-menu="d:win"]')`, nil)
	w.wait(`$q("#tile-menu").open`)
	w.eval(`$clickText("#tile-menu-items button", "New collection…")`, nil)
	w.wait(`$q("#confirm").open`)
	w.eval(`$answer("Work")`, nil)
	w.wait(`$all("[data-open]").some((e) => e.textContent.includes("Work"))`)
	var id string
	w.eval(`$all("[data-open]")[0].dataset.open`, &id)

	w.eval(`$click('[data-menu="d:mac"]')`, nil)
	w.wait(`$q("#tile-menu").open`)
	w.eval(`$clickText("#tile-menu-items button", "Move to Work")`, nil)
	w.wait(`$q('[data-open]')?.textContent.includes("1 of 2 online")`)
	w.waitSettings(d, func(s Settings) bool {
		if s.Arrangement == nil {
			return false
		}
		b, _ := json.Marshal(s.Arrangement)
		return strings.Contains(string(b), `"Work"`) && strings.Contains(string(b), `"mac"`) && strings.Contains(string(b), `"win"`)
	})

	// Alt and an arrow key move the focused tile.
	var before, after []string
	w.eval(`$order()`, &before)
	w.eval(`$q('.cell[data-ref="d:tv"] .tile').focus(); document.dispatchEvent(new KeyboardEvent("keydown", {key: "ArrowLeft", altKey: true, bubbles: true})); true`, nil)
	w.wait(`$order().indexOf("d:tv") === ` + fmt.Sprint(indexOf(before, "d:tv")-1))
	w.eval(`$order()`, &after)
	if len(after) != len(before) {
		t.Errorf("the keyboard's move changed the tiles from %q to %q", before, after)
	}

	// The collection's page, then a rename from its menu.
	w.eval(`$click("#arrange-done")`, nil)
	w.wait(`!$q(".cell.arranging")`)
	w.eval(fmt.Sprintf(`$click('[data-open="%s"]')`, id), nil)
	w.wait(`$q(".collection-head h2")?.textContent === "Work" && $all("#devices .tile").length === 2`)
	w.eval(fmt.Sprintf(`$click('[data-menu="c:%s"]')`, id), nil)
	w.wait(`$q("#tile-menu").open`)
	w.eval(`$clickText("#tile-menu-items button", "Rename collection…")`, nil)
	w.wait(`$q("#confirm").open && $q("#confirm-input").value === "Work"`)
	w.eval(`$answer("Office")`, nil)
	w.wait(`$q(".collection-head h2")?.textContent === "Office"`)
	w.eval(`$click("#collection-back")`, nil)

	// Ungroup, then back to the group's order.
	w.eval(`$click("#arrange")`, nil)
	w.eval(fmt.Sprintf(`$click('[data-menu="c:%s"]')`, id), nil)
	w.wait(`$q("#tile-menu").open`)
	w.eval(`$clickText("#tile-menu-items button", "Ungroup")`, nil)
	w.wait(`!$q("[data-open]") && $all("#devices .tile").length === 14`)
	var group []string
	for _, dev := range w.svc.devices {
		if !dev.Self {
			group = append(group, "d:"+dev.ID)
		}
	}
	w.eval(`$order()`, &before)
	if reflect.DeepEqual(before, group) {
		t.Fatalf("the tiles are in the group's order before Back to the group's order: %q", before)
	}
	w.wait(`$q("#arrange-reset")`)
	w.eval(`$click("#arrange-reset")`, nil)
	groupJSON, _ := json.Marshal(group)
	w.wait(`JSON.stringify($order()) === ` + "`" + string(groupJSON) + "`")
	w.eval(`$click("#arrange-done")`, nil)

	// The search finds by name and system; the filters by state.
	w.eval(`$search("macOS")`, nil)
	w.wait(`$all("#devices .tile").length === 1 && $q('#devices .tile[data-id="mac"]')`)
	w.eval(`$search("zzz")`, nil)
	w.wait(`$all("#devices .tile").length === 0 && $q("#devices").textContent.includes("No devices match.")`)
	w.eval(`$search("")`, nil)
	w.eval(`$click('[data-filter="attention"]')`, nil)
	w.wait(`$all("#devices .tile").length === 1 && $q('#devices .tile[data-id="win"]')`)
	w.eval(`$click('[data-filter="online"]')`, nil)
	w.wait(fmt.Sprintf(`$all("#devices .tile").length === %d`, w.svc.online()))
	w.eval(`$click('[data-filter="online"]')`, nil)
	w.wait(`$all("#devices .tile").length === 14`)
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// russian (A9): in Russian every text of the page is translated, and so
// are the headline and the buttons.
func (w *window) russian(t *testing.T) {
	w.t = t
	d := w.open("ru")
	w.wait(`document.documentElement.lang === "ru"`)
	var left []string
	w.eval(`$all("[data-t]").filter((e) => e.textContent === e.dataset.en).map((e) => e.dataset.en)`, &left)
	if len(left) > 0 {
		t.Errorf("in Russian these stay English: %q", left)
	}
	var send, head string
	w.eval(`$q("#send").textContent`, &send)
	if want := d.T("Send the clipboard"); send != want || want == "Send the clipboard" {
		t.Errorf("the send button says %q, not %q", send, want)
	}
	w.eval(`$h()`, &head)
	if want := fmt.Sprintf(strings.ReplaceAll(d.T("%d of %d online"), "%d", "%v"), w.svc.online(), 14); head != want {
		t.Errorf("the headline says %q, not %q", head, want)
	}
}

// errors (U12, A16): a service that does not answer is one plain line;
// "Show error details" adds the error underneath, and taking it off takes
// it away; never a bare "something went wrong".
func (w *window) errors(t *testing.T) {
	w.t = t
	t.Setenv("CBB_DEBUG", "0")
	w.svc.stop()
	defer w.svc.start()
	w.open("en")
	plain := "The Clipboard Bridge service is not running on this computer."
	w.wait(`$h() === "The service does not answer"`)
	w.wait(fmt.Sprintf(`$q(".notice p").textContent === %q`, plain))

	w.eval(`$click("#settings"); $click("#details")`, nil)
	w.eval(`$click('#settings-dialog menu button')`, nil)
	w.wait(fmt.Sprintf(`$q(".notice p").textContent.startsWith(%q + "\n\n")`, plain))
	var detail string
	w.eval(`$q(".notice p").textContent`, &detail)
	if len(strings.TrimSpace(strings.TrimPrefix(detail, plain))) < 5 {
		t.Errorf("with details on the message is %q, with no error underneath", detail)
	}
	w.eval(`$click("#settings"); $click("#details")`, nil)
	w.eval(`$click('#settings-dialog menu button')`, nil)
	w.wait(fmt.Sprintf(`$q(".notice p").textContent === %q`, plain))

	var body string
	w.eval(`document.body.innerText`, &body)
	if regexp.MustCompile(`(?i)something went wrong`).MatchString(body) {
		t.Errorf("the window says something went wrong: %q", body)
	}
	w.svc.start()
	w.wait(`$h() === "` + fmt.Sprintf("%d of %d online", w.svc.online(), 14) + `"`)
}

// admin (A5, the window's side): an admin's rename asks for the name and
// runs cbb rename as the administrator; a prompt closed changes nothing
// and says nothing; a dialog cancelled runs nothing; cbb's own error is
// shown in a line.
func (w *window) admin(t *testing.T) {
	w.t = t
	t.Setenv("CBB_DEBUG", "0")
	old := adminRun
	adminRun = func(args []string, _, _ bool) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.ran = append(w.ran, args)
		err := w.fail
		w.fail = nil
		return err
	}
	defer func() { adminRun = old }()
	ran := func() [][]string {
		w.mu.Lock()
		defer w.mu.Unlock()
		r := w.ran
		w.ran = nil
		return r
	}
	w.open("en")
	w.wait(`$all("#devices .tile").length === 14`)
	w.eval(`$click('.tile[data-id="tv"]')`, nil)
	w.wait(`!$q("#detail").hidden && $q('[data-action="rename"]')`)

	w.eval(`$click('[data-action="rename"]')`, nil)
	w.wait(`$q("#confirm").open && $q("#confirm-input").value === "Living room TV"`)
	w.eval(`$answer("Den TV")`, nil)
	w.wait(`$q("#message").textContent === "Renamed."`)
	if r := ran(); !reflect.DeepEqual(r, [][]string{{"rename", "tv", "Den TV"}}) {
		t.Errorf("rename ran %q", r)
	}

	w.mu.Lock()
	w.fail = errCancelled
	w.mu.Unlock()
	w.eval(`$click('[data-action="rename"]')`, nil)
	w.wait(`$q("#confirm").open`)
	w.eval(`$answer("Other TV")`, nil)
	w.wait(`$q("#message").textContent === ""`)
	if r := ran(); len(r) != 1 {
		t.Errorf("a closed prompt ran %q", r)
	}

	w.eval(`$click('[data-action="remove"]')`, nil)
	w.wait(`$q("#confirm").open && $q("#confirm-title").textContent === "Remove Living room TV?"`)
	w.eval(`$clickText("#confirm menu button", "Cancel")`, nil)
	w.wait(`!$q("#confirm").open`)
	time.Sleep(300 * time.Millisecond)
	if r := ran(); len(r) != 0 {
		t.Errorf("a cancelled dialog ran %q", r)
	}

	w.mu.Lock()
	w.fail = cbbFailed("Detail: refused by the records\ncbb: no device named tv in the group\n", "exit status 1")
	w.mu.Unlock()
	w.eval(`$click('[data-action="remove"]')`, nil)
	w.wait(`$q("#confirm").open`)
	w.eval(`$click("#confirm-ok")`, nil)
	w.wait(`$q("#message").textContent === "no device named tv in the group"`)
	if r := ran(); !reflect.DeepEqual(r, [][]string{{"revoke", "tv"}}) {
		t.Errorf("remove ran %q", r)
	}

	// Making a computer an admin warns that its key is a file.
	w.eval(`$click('.tile[data-id="srv"]')`, nil)
	w.wait(`$q('[data-action="admin"]')`)
	w.eval(`$click('[data-action="admin"]')`, nil)
	w.wait(`$q("#confirm").open && $q("#confirm-text").textContent.includes("file")`)
	w.eval(`$click("#confirm-ok")`, nil)
	w.wait(`$q("#message").textContent === "It is an admin now."`)
	if r := ran(); !reflect.DeepEqual(r, [][]string{{"admin", "-allow-file-key", "srv"}}) {
		t.Errorf("make it an admin ran %q", r)
	}
}

// fakeService answers the window's status and devices requests on a
// control socket, and can stop listening, as a service that is not
// running.
type fakeService struct {
	t       *testing.T
	path    string
	status  control.Status
	devices []control.Device
	mu      sync.Mutex
	ln      net.Listener
}

func newFakeService(t *testing.T) *fakeService {
	dir, err := os.MkdirTemp("", "cbbui")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := &fakeService{t: t, path: filepath.Join(dir, "c.sock"),
		status: control.Status{Device: "self", Group: "cbb-7f3a", Role: "full", OS: "linux", Mode: "shared"},
		devices: []control.Device{
			{ID: "self", Name: "This PC", Role: "full", OS: "linux", Admin: true, Root: true, Self: true, Online: true, Listed: true},
			{ID: "mac", Name: "MacBook", Role: "full", OS: "macos", OSVersion: "26.1", Online: true, Listed: true},
			{ID: "win", Name: "Windows PC", Role: "full", OS: "windows", Admin: true, Frozen: true, Listed: true},
			{ID: "iphone", Name: "iPhone", Role: "phone", OS: "ios", Admin: true, Online: true, Listed: true},
			{ID: "pixel", Name: "Pixel", Role: "phone", OS: "android", Online: true, Listed: true},
			{ID: "ipad", Name: "iPad", Role: "phone", OS: "ios", Form: "tablet", Listed: true},
			{ID: "tv", Name: "Living room TV", Role: "full", OS: "linux", Form: "tv", Online: true, Listed: true},
			{ID: "nano", Name: "Nano", Role: "lite", Listed: true},
			{ID: "srv", Name: "Home server", Role: "full", OS: "linux", Form: "server", Online: true, Listed: true},
			{ID: "gate", Name: "Router", Role: "full", OS: "linux", Form: "router", Listed: true},
			{ID: "deck", Name: "Steam Deck", Role: "full", OS: "linux", Form: "console", Online: true, Listed: true},
			{ID: "watch", Name: "Watch", Role: "watch", OS: "watchos", Listed: true},
			{ID: "next", Name: "ZX Next", Role: "lite", Form: "retro", Listed: true},
			{ID: "box", Name: "Box", Role: "full", OS: "linux", Form: "other", Listed: true},
		}}
	s.start()
	t.Cleanup(s.stop)
	return s
}

// online counts the devices online, this one with them.
func (s *fakeService) online() int {
	n := 0
	for _, d := range s.devices {
		if d.Online || d.Self {
			n++
		}
	}
	return n
}

func (s *fakeService) start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return
	}
	os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		s.t.Fatal(err)
	}
	s.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
}

func (s *fakeService) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
		s.ln = nil
		os.Remove(s.path)
	}
}

func (s *fakeService) serve(c net.Conn) {
	defer c.Close()
	m, err := control.NewReader(c).Read()
	if err != nil {
		return
	}
	a := &control.Message{Header: control.Header{Done: true}}
	switch m.Op {
	case control.OpStatus:
		st := s.status
		a.Status = &st
	case control.OpDevices:
		a.Devices = s.devices
	default:
		a.Error = "the stand-in service does not do " + m.Op
	}
	control.Write(c, a)
}

// findBrowser finds Chrome, Chromium or Edge: CBB_UI_BROWSER, else the
// usual places.
func findBrowser(t *testing.T) string {
	if p := os.Getenv("CBB_UI_BROWSER"); p != "" {
		return p
	}
	var places []string
	switch runtime.GOOS {
	case "windows":
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if dir := os.Getenv(env); dir != "" {
				places = append(places, filepath.Join(dir, `Google\Chrome\Application\chrome.exe`), filepath.Join(dir, `Microsoft\Edge\Application\msedge.exe`))
			}
		}
	case "darwin":
		places = append(places, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")
	default:
		for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"} {
			if p, err := exec.LookPath(name); err == nil {
				places = append(places, p)
			}
		}
		if m, _ := filepath.Glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome"); len(m) > 0 {
			places = append(places, m...)
		}
	}
	for _, p := range places {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatal("no Chrome, Chromium or Edge for the window's tests; set CBB_UI_BROWSER")
	}
	t.Skip("no Chrome, Chromium or Edge; set CBB_UI_BROWSER to run the window's tests")
	return ""
}

// cdpPage is one page of the browser, driven over the DevTools protocol.
type cdpPage struct {
	mu sync.Mutex
	c  *websocket.Conn
	id int
}

// startBrowser starts the browser headless and opens a page.
func startBrowser(t *testing.T, exe string) *cdpPage {
	ctx, cancel := context.WithCancel(context.Background())
	// The profile is not t.TempDir: the browser's helpers may still write
	// to it for a moment after it ends.
	profile, err := os.MkdirTemp("", "cbbui-browser")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
		"--no-default-browser-check", "--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", exe, err)
	}
	var page *cdpPage
	t.Cleanup(func() {
		if page != nil {
			page.do("Browser.close", nil, nil) // ends its helpers too
		}
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cancel()
			<-done
		}
		cancel()
		for range 20 {
			if os.RemoveAll(profile) == nil {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	})
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if _, rest, ok := strings.Cut(sc.Text(), "DevTools listening on "); ok {
				found <- rest
			}
		}
	}()
	// Edge started from an elevated console starts itself again without the
	// rights and ends, so its stderr never names the address; the profile's
	// DevToolsActivePort does in both cases.
	var host string
	deadline := time.Now().Add(30 * time.Second)
	for host == "" {
		select {
		case ws := <-found:
			host = strings.SplitN(strings.TrimPrefix(ws, "ws://"), "/", 2)[0]
		case <-time.After(200 * time.Millisecond):
			if b, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort")); err == nil {
				if port, _, _ := strings.Cut(string(b), "\n"); strings.TrimSpace(port) != "" {
					host = "127.0.0.1:" + strings.TrimSpace(port)
				}
			}
			if host == "" && time.Now().After(deadline) {
				t.Fatalf("%s gave no DevTools address in 30 s", exe)
			}
		}
	}
	req, _ := http.NewRequest(http.MethodPut, "http://"+host+"/json/new?about:blank", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var target struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&target); err != nil || target.WebSocketDebuggerURL == "" {
		t.Fatalf("a new page: %v %+v", err, target)
	}
	c, _, err := websocket.Dial(ctx, target.WebSocketDebuggerURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadLimit(64 << 20)
	page = &cdpPage{c: c}
	return page
}

// call sends one DevTools command and decodes its result into out.
func (p *cdpPage) call(t *testing.T, method string, params any, out any) {
	t.Helper()
	if err := p.do(method, params, out); err != nil {
		t.Fatalf("%s: %v", method, err)
	}
}

func (p *cdpPage) do(method string, params any, out any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p.id++
	msg, _ := json.Marshal(map[string]any{"id": p.id, "method": method, "params": params})
	if err := p.c.Write(ctx, websocket.MessageText, msg); err != nil {
		return err
	}
	for {
		_, data, err := p.c.Read(ctx)
		if err != nil {
			return err
		}
		var r struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &r) != nil || r.ID != p.id {
			continue // an event
		}
		if r.Error != nil {
			return errors.New(r.Error.Message)
		}
		if out != nil {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	}
}

// eval evaluates the expression after pageHelpers, waiting for a promise,
// and decodes its value.
func (p *cdpPage) eval(js string, out any) error {
	var r struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exception *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := p.do("Runtime.evaluate", map[string]any{"expression": pageHelpers + js, "awaitPromise": true, "returnByValue": true}, &r); err != nil {
		return err
	}
	if r.Exception != nil {
		return fmt.Errorf("%s %s", r.Exception.Text, r.Exception.Exception.Description)
	}
	if out != nil && len(r.Result.Value) > 0 {
		return json.Unmarshal(r.Result.Value, out)
	}
	return nil
}
