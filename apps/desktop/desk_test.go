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
