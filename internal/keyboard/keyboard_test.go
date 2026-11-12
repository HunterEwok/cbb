// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package keyboard

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestVectors checks the layouts against testdata/interop/keyboard.json,
// which the Rust core's keyboard tests write: the Nano, the Android phone
// and a Linux computer type alike.
func TestVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "keyboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Candidates string                        `json:"candidates"`
		Layouts    map[string]map[string][2]byte `json:"layouts"`
		Texts      []struct {
			Layout     string   `json:"layout"`
			Text       string   `json:"text"`
			Reports    []string `json:"reports"`
			Untypeable []string `json:"untypeable"`
		} `json:"texts"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Layouts) != len(Layouts) {
		t.Fatalf("%d layouts in the vectors, %d here", len(v.Layouts), len(Layouts))
	}
	for _, l := range Layouts {
		keys, ok := v.Layouts[string(l)]
		if !ok {
			t.Fatalf("no layout %s in the vectors", l)
		}
		for _, r := range v.Candidates {
			want, has := keys[string(r)]
			got, ok := l.Key(r)
			if ok != has || (ok && (got.Modifiers != want[0] || got.Usage != want[1])) {
				t.Errorf("%s U+%04X: %v %v, want %v %v", l, r, got, ok, want, has)
			}
		}
	}
	for _, c := range v.Texts {
		l := Layout(c.Layout)
		reports, ok := l.Reports(c.Text)
		if c.Reports != nil {
			var got []string
			for _, r := range reports {
				got = append(got, hex.EncodeToString(r[:]))
			}
			if !ok || !slices.Equal(got, c.Reports) {
				t.Errorf("%s %q: %v %v, want %v", l, c.Text, got, ok, c.Reports)
			}
			continue
		}
		var un []string
		for _, r := range l.Untypeable(c.Text) {
			un = append(un, string(r))
		}
		if ok || !slices.Equal(un, c.Untypeable) {
			t.Errorf("%s %q: typeable %v, untypeable %q, want %q", l, c.Text, ok, un, c.Untypeable)
		}
	}
}

func TestReports(t *testing.T) {
	r, ok := US.Reports("aA\r\n")
	want := [][8]byte{{0, 0, 0x04}, Release, {LeftShift, 0, 0x04}, Release, {0, 0, Enter}, Release}
	if !ok || !slices.Equal(r, want) {
		t.Fatalf("%v %v", r, ok)
	}
	if !US.Known() || Layout("de").Known() {
		t.Fatal("Known")
	}
}
