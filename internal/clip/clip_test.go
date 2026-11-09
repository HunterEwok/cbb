// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/hlc"
)

// Device IDs of the test members.
var (
	idA = strings.Repeat("a", 32)
	idB = strings.Repeat("b", 32)
)

// testWall is the wall clock of the test events, in milliseconds since the
// Unix epoch.
const testWall = 1_761_024_000_000

func TestReceivedValidation(t *testing.T) {
	good := Event{ID: NewID(), Origin: idB, Time: hlc.Timestamp{Wall: testWall}, Kind: Text, Text: "ok"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(e *Event){
		"short ID":            func(e *Event) { e.ID = "abc" },
		"upper-case ID":       func(e *Event) { e.ID = strings.Repeat("A", 32) },
		"bad origin":          func(e *Event) { e.Origin = "b" },
		"no timestamp":        func(e *Event) { e.Time = hlc.Timestamp{} },
		"past the end":        func(e *Event) { e.Time.Wall = hlc.MaxWall + 1 },
		"unknown kind":        func(e *Event) { e.Kind = 7 },
		"unknown via":         func(e *Event) { e.Via = 7 },
		"negative age":        func(e *Event) { e.Age = -1 },
		"empty text":          func(e *Event) { e.Text = "" },
		"invalid UTF-8":       func(e *Event) { e.Text = "\xff" },
		"text over the limit": func(e *Event) { e.Text = strings.Repeat("x", MaxText+1) },
		"unread, not sealed":  func(e *Event) { e.Unread = true },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ev := good
			mutate(&ev)
			if err := ev.Validate(); err == nil {
				t.Error("Validate() succeeded, want an error")
			}
		})
	}
	t.Run("the mark of a secret", func(t *testing.T) {
		ev := good
		ev.Kind, ev.Text = Secret, ""
		if !ev.IsMark() {
			t.Fatal("a secret without its text is not a mark")
		}
		if err := ev.Validate(); err != nil {
			t.Error(err)
		}
	})
}

func TestJSON(t *testing.T) {
	ev := Event{ID: NewID(), Origin: idA, Via: Universal, Time: hlc.Timestamp{Wall: 5, Logical: 2}, Age: 42, Kind: Secret, Text: "t"}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kind":"secret"`, `"time":"5.2"`, `"via":"universal-clipboard"`, `"age_ms":42`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON %s lacks %s", b, want)
		}
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, ev) {
		t.Errorf("round trip = %+v, %v; want %+v", back, err, ev)
	}
	plain, _ := json.Marshal(Event{Via: Copy, Kind: Text})
	if strings.Contains(string(plain), "via") {
		t.Errorf("a plain copy should omit via: %s", plain)
	}
	var e Event
	for _, bad := range []string{`{"kind":"image"}`, `{"via":"fax"}`, `{"time":"1"}`} {
		if err := json.Unmarshal([]byte(bad), &e); err == nil {
			t.Errorf("Unmarshal(%s) succeeded", bad)
		}
	}
}
