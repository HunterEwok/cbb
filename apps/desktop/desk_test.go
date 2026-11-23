// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

func TestPickLanguage(t *testing.T) {
	for _, c := range []struct {
		prefs []string
		want  string
	}{
		{[]string{"", "ru_RU.UTF-8"}, "ru"},
		{[]string{"ru-RU", "en-US"}, "ru"},
		{[]string{"C", "en_GB.UTF-8"}, "en"},
		{[]string{"de_DE.UTF-8"}, "en"},
		{nil, "en"},
	} {
		if got := pickLanguage(c.prefs); got != c.want {
			t.Errorf("pickLanguage(%q) = %q, want %q", c.prefs, got, c.want)
		}
	}
}

func TestCbbFailed(t *testing.T) {
	e := cbbFailed("Detail: dial unix: refused\r\ncbb: no device named nope in the group\r\n", "exit 1")
	if e.msg != "no device named nope in the group" || !strings.Contains(e.detail, "Detail: dial unix") {
		t.Errorf("cbbFailed = %+v", e)
	}
	if e := cbbFailed("  ", "exit 1"); e.msg != "exit 1" {
		t.Errorf("cbbFailed with no output = %+v", e)
	}
}

// Each failure has its own words, and the error underneath only with
// details on.
func TestDescribe(t *testing.T) {
	off, on := false, true
	d := &Desk{tr: map[string]string{}}
	d.settings.Details = &off
	notRunning := &control.DialError{Msg: "not running", Err: errors.New("dial unix /run/x: no such file")}
	if got := d.describe(notRunning); got != "The CBB service is not running on this computer." {
		t.Errorf("not running, details off: %q", got)
	}
	d.settings.Details = &on
	if got := d.describe(notRunning); !strings.HasSuffix(got, "\n\ndial unix /run/x: no such file") {
		t.Errorf("not running, details on: %q", got)
	}
	if got := d.describe(&control.DialError{Msg: "no permission", Denied: true}); !strings.HasPrefix(got, "No permission") {
		t.Errorf("denied: %q", got)
	}
	if got := d.describe(&control.RequestError{Msg: "refused", Detail: "why"}); got != "refused\n\nwhy" {
		t.Errorf("refused: %q", got)
	}
	d.tr = map[string]string{"Something failed on this computer.": "X"}
	if got := d.describe(errors.New("boom")); got != "X\n\nboom" {
		t.Errorf("other: %q", got)
	}
}

// Every text the window and the tray show has its Russian.
func TestTranslations(t *testing.T) {
	var ru map[string]string
	data, err := os.ReadFile(filepath.Join("frontend", "l10n", "ru.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &ru); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for file, re := range map[string]*regexp.Regexp{
		"frontend/app.js":     regexp.MustCompile(`\bt\("([^"]+)"`),
		"frontend/index.html": regexp.MustCompile(`data-t>([^<]+)<|data-t-title="([^"]+)"`),
		"desk.go":             regexp.MustCompile(`d\.T\("([^"]+)"\)|false, "([^"]+)"\)|true, "([^"]+)"\)`),
		"join.go":             regexp.MustCompile(`d\.T\("([^"]+)"\)`),
		"invite.go":           regexp.MustCompile(`d\.T\("([^"]+)"\)`),
		"admit.go":            regexp.MustCompile(`"([A-Z][^"]+\.)"`),
		"admin_linux.go":      regexp.MustCompile(`deniedText = "([^"]+)"|msg: "([^"]+)"`),
		"admin_windows.go":    regexp.MustCompile(`deniedText = "([^"]+)"|msg: "([^"]+)"`),
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			for _, k := range m[1:] {
				if k != "" {
					keys[k] = true
				}
			}
		}
	}
	var missing []string
	for k := range keys {
		if _, ok := ru[k]; !ok && !strings.HasPrefix(k, "pkexec is not installed") {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("no Russian for:\n%s", strings.Join(missing, "\n"))
	}
	if len(keys) < 60 {
		t.Errorf("found only %d texts; the patterns miss them", len(keys))
	}
}

// The window's arrangement: the member keeps it and answers view, the
// window draws what it answers, and a change that does not fit says so.
func TestDeskArrange(t *testing.T) {
	svc := newFakeService(t)
	off := false
	d := &Desk{socket: svc.path, tr: map[string]string{}, settingsPath: filepath.Join(t.TempDir(), "desktop.json")}
	d.settings.Details = &off
	st := d.State()
	if st.Custom || len(st.Arranged) != len(svc.devices) || st.Arranged[0].Device != "self" {
		t.Fatalf("default: %+v", st.Arranged)
	}
	d.Arrange(ArrangeOp{Op: "new", Name: "Office", Devices: []string{"win", "iphone"}})
	st = d.snapshot()
	var office *Collection
	for _, it := range st.Arranged {
		if it.Collection != nil {
			office = it.Collection
		}
	}
	if !st.Custom || office == nil || office.Name != "Office" || len(office.Devices) != 2 {
		t.Fatalf("after new: %+v", st.Arranged)
	}
	if b, _ := json.Marshal(svc.arranged()); !strings.Contains(string(b), `"Office"`) {
		t.Errorf("the member keeps %s", b)
	}
	// The window's own settings never hold the order.
	if err := d.SaveSettings(Settings{Layout: "list", Details: &off}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(d.settingsPath); err != nil || strings.Contains(string(data), "Office") {
		t.Fatalf("saved: %s, %v", data, err)
	}
	d.Arrange(ArrangeOp{Op: "rename", Collection: office.ID, Name: strings.Repeat("x", 65)})
	if d.message != "The tiles stay as they were: that change does not fit." {
		t.Errorf("refused: %q", d.message)
	}
	// Back to the group's order.
	d.Arrange(ArrangeOp{Op: "ungroup", Collection: office.ID})
	if st := d.State(); st.Custom && len(st.Arranged) != len(svc.devices) {
		t.Errorf("after ungroup: %+v", st.Arranged)
	}
}

// TestOwnMute: this computer itself is muted and unmuted on the control
// socket, without the administrator; another device takes cbb as the
// administrator.
func TestOwnMute(t *testing.T) {
	d := &Desk{tr: map[string]string{}}
	if _, ok := d.ownMute("me", false, 0); ok {
		t.Fatal("a request for this computer before its status")
	}
	d.status = &control.Status{Device: "me", Group: "g1"}
	if h, ok := d.ownMute("me", false, 0); !ok || h.Op != control.OpUnmute || h.Device != "me" {
		t.Fatalf("unmute of this computer: %+v, %v", h, ok)
	}
	if h, ok := d.ownMute("me", true, 60000); !ok || h.Op != control.OpMute || h.ForMS != 60000 {
		t.Fatalf("mute of this computer: %+v, %v", h, ok)
	}
	if _, ok := d.ownMute("a", false, 0); ok {
		t.Fatal("another device on the control socket")
	}
}

// TestDeskActions: each button runs cbb as the administrator with its
// arguments and answer, and the window then says what happened; a run the
// user cancelled says nothing, one that failed says why.
func TestDeskActions(t *testing.T) {
	type run struct {
		args  []string
		input string
	}
	var runs []run
	var fail error
	old := adminRun
	adminRun = func(args []string, input string, _ bool) error {
		runs = append(runs, run{append([]string(nil), args...), input})
		return fail
	}
	t.Cleanup(func() { adminRun = old })
	off := false
	d := &Desk{tr: map[string]string{}, socket: filepath.Join(t.TempDir(), "none.sock")}
	d.settings.Details = &off
	for _, c := range []struct {
		do    func()
		args  string
		input string
		says  string
	}{
		{d.CreateGroup, "new", "", "The group is made: this computer is its main device. Add a device with the + button."},
		{d.Leave, "leave -yes", "", "Left the group. This computer can join a group again."},
		{func() { d.Freeze("mac") }, "freeze mac", "", "Frozen."},
		{func() { d.Unfreeze("mac") }, "unfreeze mac", "", "Unfrozen."},
		{func() { d.MakeHub("mac", false, true) }, "global hub -on mac -forward-only", "", "It is a hub now that only passes the copies on, and reads none of them."},
		{func() { d.MakeHub("mac", false, false) }, "global hub -on mac", "", "It is a hub now."},
		{func() { d.MakeHub("", true, false) }, "global hub -firewall no -away-on", "yes\n", "It is a hub now."},
		{func() { d.MakeHub("", false, false) }, "global hub -firewall no", "", "It is a hub now."},
		{func() { d.StopHub("") }, "global hub off -yes", "", "It is no hub any more."},
		{func() { d.StopHub("srv") }, "global hub off -on srv -yes", "", "It is no hub any more."},
		{d.Resolve, "resolve", "", "Both histories are void. The device signs its records again by itself."},
		{func() { d.Recover("  word word word \n", nil, false) }, "recovery", "word word word\n", "This computer is the group's main device now."},
		{func() { d.Recover("123456", []string{"a1b2c3d4"}, true) }, "recovery -leave a1b2c3d4 -yubikey", "123456\n", "This computer is the group's main device now."},
		{func() { d.SetTTL(900000, 0) }, "ttl 900s -", "", "Saved. Every device of the group follows it."},
		{func() { d.SetTTL(0, 15000) }, "ttl - 15s", "", "Saved. Every device of the group follows it."},
		{func() { d.SetKeyLevel("files") }, "keys files", "", "Saved. Every device of the group follows it."},
		{d.Update, "update", "", "CBB is updated."},
		{func() { d.Unmute("mac") }, "unmute -on mac", "", "It is no longer muted."},
	} {
		runs = nil
		c.do()
		if len(runs) != 1 || strings.Join(runs[0].args, " ") != c.args || runs[0].input != c.input {
			t.Errorf("ran %+v, want cbb %s with %q", runs, c.args, c.input)
		}
		if d.message != c.says {
			t.Errorf("cbb %s: the window says %q", c.args, d.message)
		}
	}
	fail = errCancelled
	d.Update()
	if d.message != "" {
		t.Errorf("after a cancel the window says %q", d.message)
	}
	fail = &adminError{msg: "the release does not verify"}
	d.Update()
	if d.message == "" || d.message == "CBB is updated." {
		t.Errorf("after a failure the window says %q", d.message)
	}
}

// TestDeskOwnUnmute: this computer is unmuted on the control socket.
func TestDeskOwnUnmute(t *testing.T) {
	svc := newFakeService(t)
	old := adminRun
	adminRun = func(args []string, _ string, _ bool) error {
		t.Errorf("cbb %v as the administrator", args)
		return nil
	}
	t.Cleanup(func() { adminRun = old })
	d := &Desk{tr: map[string]string{}, socket: svc.path, status: &control.Status{Device: "self", Group: "cbb-7f3a"}}
	d.Unmute("self")
	if got := svc.requests(); len(got) != 1 || got[0].Op != control.OpUnmute || got[0].Device != "self" {
		t.Errorf("the service heard %+v", got)
	}
	if d.message != "It is no longer muted." {
		t.Errorf("the window says %q", d.message)
	}
}

// TestHeadline: the tray's line for each state, and its glyph.
func TestHeadline(t *testing.T) {
	d := &Desk{tr: map[string]string{}}
	devices := []control.Device{{ID: "a", Self: true}, {ID: "b", Online: true}, {ID: "c"}}
	for _, c := range []struct {
		s           State
		line, glyph string
	}{
		{State{Problem: "no answer"}, "The service does not answer", "tray"},
		{State{}, "This computer is in no group yet", "tray"},
		{State{Status: &control.Status{}}, "This computer is in no group yet", "tray"},
		{State{Status: &control.Status{Group: "g"}, Devices: devices}, "2 of 3 online", "tray-online"},
		{State{Status: &control.Status{Group: "g"}, Devices: devices[:1]}, "1 of 1 online", "tray-group"},
	} {
		if got := d.headline(c.s); got != c.line {
			t.Errorf("%+v: %q, want %q", c.s, got, c.line)
		}
		if got := trayState(c.s); got != c.glyph {
			t.Errorf("%+v: glyph %q, want %q", c.s, got, c.glyph)
		}
		if len(trayIcon(c.glyph, "white")) == 0 || len(trayIcon(c.glyph, "black")) == 0 {
			t.Errorf("no picture for %s", c.glyph)
		}
	}
}

// TestBug: a report the service keeps is asked about in release mode and
// goes when allowed; in debug mode it shows whole and is dropped; nothing
// waits, nothing is asked.
func TestBug(t *testing.T) {
	svc := newFakeService(t)
	off, on := false, true
	d := &Desk{tr: map[string]string{}, socket: svc.path}
	d.settings.Details = &off
	if o := d.Bug(); o != nil {
		t.Fatalf("an offer with no report: %+v", o)
	}
	svc.bug = []byte(`{"action":"ask","offer_always":true,"fixed_in":"0.6.1","report":{"details":"index out of range"}}`)
	o := d.Bug()
	if o == nil || !o.OfferAlways || o.FixedIn != "0.6.1" || !strings.Contains(o.Report, "\n  \"details\": \"index out of range\"") {
		t.Fatalf("the offer: %+v", o)
	}
	d.BugAllow(true)
	got := svc.requests()
	if last := got[len(got)-1]; last.Op != control.OpBugAllow || string(last.Payload) != `{"always":true}` {
		t.Errorf("allowed: %+v", last)
	}
	// Debug mode: the message shows the break, and the report is dropped.
	d.settings.Details = &on
	if o := d.Bug(); o != nil {
		t.Errorf("an offer in debug mode: %+v", o)
	}
	if !strings.HasSuffix(d.message, "\n\nindex out of range") {
		t.Errorf("the window says %q", d.message)
	}
	got = svc.requests()
	if last := got[len(got)-1]; last.Op != control.OpBugCancel {
		t.Errorf("in debug mode: %+v", last)
	}
	// A report the core would not make again stops waiting, unasked.
	d.settings.Details = &off
	svc.bug = []byte(`{"action":"drop","report":{}}`)
	if o := d.Bug(); o != nil {
		t.Errorf("an offer to drop: %+v", o)
	}
	svc.bug = []byte(`not json`)
	if o := d.Bug(); o != nil {
		t.Errorf("an offer from a broken answer: %+v", o)
	}
	// A service that does not answer: nothing asked, nothing breaks.
	svc.stop()
	if o := d.Bug(); o != nil {
		t.Errorf("an offer with no service: %+v", o)
	}
	d.BugAllow(false)
	d.BugCancel()
}
