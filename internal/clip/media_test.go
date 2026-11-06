// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/hlc"
)

func part(typ, path string, b string) Part {
	sum := sha256.Sum256([]byte(b))
	return Part{Type: typ, Path: path, Size: int64(len(b)), SHA256: sum[:]}
}

func manifest(parts ...Part) *Manifest {
	m := &Manifest{Parts: parts}
	for _, p := range parts {
		m.Size += p.Size
	}
	return m
}

func TestManifestValidate(t *testing.T) {
	png, html := part(TypePNG, "", "png bytes"), part(TypeHTML, "", "<b>x</b>")
	file, dir := part("", "photos/a.jpg", "jpeg"), Part{Path: "photos", Dir: true}
	for _, m := range []*Manifest{manifest(png), manifest(png, html), manifest(dir, file), manifest(part("", "empty.txt", ""))} {
		if err := m.Validate(); err != nil {
			t.Errorf("Validate(%+v): %v", m.Parts, err)
		}
	}
	tooMany := make([]Part, MaxTypes+1)
	for i := range tooMany {
		tooMany[i] = png
	}
	bad := map[string]*Manifest{
		"no parts":        {},
		"mixed":           manifest(png, file),
		"mixed the other": manifest(file, png),
		"unknown type":    manifest(part("image/gif", "", "gif")),
		"twice":           manifest(png, png),
		"same path":       manifest(file, file),
		"too many types":  manifest(tooMany...),
		"no hash":         manifest(Part{Type: TypePNG, Size: 1}),
		"folder size":     manifest(Part{Path: "d", Dir: true, Size: 1}),
		"bad size":        {Size: 1, Parts: []Part{png}},
		"too large":       manifest(Part{Type: TypePNG, Size: MaxMedia + 1, SHA256: png.SHA256}),
		"inside a file":   manifest(part("", "a.txt", "x"), part("", "a.txt/b", "y")),
		"dot dot":         manifest(part("", "../etc/passwd", "x")),
		"absolute":        manifest(part("", "/etc/passwd", "x")),
		"backslash":       manifest(part("", `a\b`, "x")),
		"reserved":        manifest(part("", "dir/con.txt", "x")),
	}
	for name, m := range bad {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: Validate(%+v) succeeded", name, m.Parts)
		}
	}
	// 140 folders of 15 names of 250 bytes: more than MaxPaths together.
	var paths []Part
	for i := range 140 {
		names := make([]string, 15)
		for j := range names {
			names[j] = strings.Repeat("d", 247) + fmt.Sprintf("%03d", i)
		}
		paths = append(paths, Part{Path: strings.Join(names, "/"), Dir: true})
	}
	if err := manifest(paths...).Validate(); err == nil || !strings.Contains(err.Error(), "paths") {
		t.Errorf("paths of more than %d bytes: %v", MaxPaths, err)
	}
}

func TestNames(t *testing.T) {
	for _, name := range []string{"a.txt", "R\u00e9sum\u00e9 2026.pdf", "con", "LPT9.log", "a.", "a ", "", ".", "..", "a/b", "a:b", "tab\there", strings.Repeat("\u00e9", 200), "\xff",
		// Near the limit: a reserved base and a dot at the end both add to it.
		"CON." + strings.Repeat("a", 249) + ".x", "con." + strings.Repeat("a", 250) + ".", strings.Repeat("a", 254) + ".", strings.Repeat("a", 255), strings.Repeat("\u00e9", 127) + " "} {
		clean := CleanName(name)
		if err := CheckName(clean); err != nil {
			t.Errorf("CleanName(%q) = %q: %v", name, clean, err)
		}
		if CheckName(name) == nil && clean != name && !device(name) {
			t.Errorf("CleanName(%q) = %q, changed a valid name", name, clean)
		}
	}
	// The same as the kits' tests.
	for given, want := range map[string]string{
		strings.Repeat("x", 300):                 strings.Repeat("x", 255),
		"CON." + strings.Repeat("a", 249) + ".x": "CON_." + strings.Repeat("a", 249),
		strings.Repeat("a", 254) + ".":           strings.Repeat("a", 254),
	} {
		if got := CleanName(given); got != want {
			t.Errorf("CleanName(%q) = %q, want %q", given, got, want)
		}
	}
	for _, name := range []string{"CON", "nul.txt", "com1", "Lpt3.doc"} {
		if CheckName(name) == nil {
			t.Errorf("CheckName(%q) took a name Windows reserves", name)
		}
	}
	for _, name := range []string{"console", "com0", "lpt", "comX"} {
		if err := CheckName(name); err != nil {
			t.Errorf("CheckName(%q): %v", name, err)
		}
	}
}

func TestMediaEvents(t *testing.T) {
	w := newWorld()
	a, b := w.member(idA), w.member(idB)
	join(t, w, a, idB, nil)
	join(t, w, b, idA, nil)
	m := manifest(part(TypePNG, "", "screenshot"))
	ev, ok, err := a.CopiedMedia(m, "", Copy)
	if err != nil || !ok || ev.Kind != Media || ev.Media != m || ev.Text != "" {
		t.Fatalf("CopiedMedia() = %+v, %v, %v", ev, ok, err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := a.CopiedMedia(manifest(part(TypePNG, "", "screenshot")), "", Copy); ok {
		t.Error("copying the same image again made a new event")
	}
	if got, _, _, ok := a.LocalMedia(); !ok || got != m {
		t.Errorf("LocalMedia() = %v, %v", got, ok)
	}
	if _, _, _, ok := a.Local(); ok {
		t.Error("Local() returned a text for an image without one")
	}
	// A text after the image is a new copy, and the image is no longer local.
	mustCopy(t, a, "then a text")
	if _, _, _, ok := a.LocalMedia(); ok {
		t.Error("LocalMedia() after a text")
	}

	// The other member writes it, and its watcher's report is an echo.
	res := mustReceive(t, b, ev)
	if !res.Write {
		t.Fatalf("a live media event was not written: %+v", res)
	}
	if cur, _ := b.Current(); cur.Kind != Media || cur.Media.Parts[0].Type != TypePNG {
		t.Errorf("current = %+v", cur)
	}
	if _, ok, _ := b.CopiedMedia(manifest(part(TypePNG, "", "screenshot")), "", Copy); ok {
		t.Error("the echo of a written image made a new event")
	}
	if _, ok, _ := b.Copied("screenshot", Text, Copy); !ok {
		t.Error("a text that equals nothing written made no event")
	}

	// Files with a text alternative: Local gives the text.
	files := manifest(Part{Path: "docs", Dir: true}, part("", "docs/a.txt", "a"))
	ev, res, err = b.SendMedia(files, "docs", Copy)
	if err != nil || !res.Write || ev.Text != "docs" {
		t.Fatalf("SendMedia() = %+v, %+v, %v", ev, res, err)
	}
	if text, kind, _, ok := b.Local(); !ok || text != "docs" || kind != Text {
		t.Errorf("Local() = %q, %v, %v", text, kind, ok)
	}
	if _, res, _ := b.SendMedia(files, "docs", Copy); res.Write {
		t.Error("SendMedia() asked to write what the clipboard holds")
	}
	if _, _, err := b.SendMedia(files, strings.Repeat("x", MaxAltText+1), Copy); err == nil {
		t.Error("a text alternative over the limit was taken")
	}
	if _, _, err := b.CopiedMedia(&Manifest{}, "", Copy); err == nil {
		t.Error("an empty manifest was taken")
	}
}

func TestMediaValidation(t *testing.T) {
	w := newWorld()
	good := Event{ID: NewID(), Origin: idB, Time: hlc.Timestamp{Wall: w.wall}, Kind: Media, Media: manifest(part(TypeJPEG, "", "j"))}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	noManifest := good
	noManifest.Media = nil
	textWithManifest := good
	textWithManifest.Kind = Text
	textWithManifest.Text = "x"
	longText := good
	longText.Text = strings.Repeat("x", MaxAltText+1)
	badManifest := good
	badManifest.Media = &Manifest{Size: 2, Parts: good.Media.Parts}
	for name, ev := range map[string]Event{"no manifest": noManifest, "text with a manifest": textWithManifest, "long text": longText, "bad manifest": badManifest} {
		if err := ev.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
	b, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"kind":"media"`, `"media":{"size":1,"parts":[{"type":"image/jpeg","size":1,"sha256":"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON %s lacks %s", b, want)
		}
	}
	var back Event
	if err := json.Unmarshal(b, &back); err != nil || back.Validate() != nil || back.Media.key() != good.Media.key() {
		t.Errorf("round trip %+v, %v", back, err)
	}
}

// TestStrictManifests checks the manifests of testdata/interop/strict.json,
// which every member reads alike: a folder has no hash, not even an empty
// or a null one.
func TestStrictManifests(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "strict.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Manifests []struct {
			Name  string `json:"name"`
			Body  []byte `json:"body"`
			Valid bool   `json:"valid"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(data, &v); err != nil || len(v.Manifests) == 0 {
		t.Fatalf("no manifests: %v", err)
	}
	for _, c := range v.Manifests {
		_, err := ParseManifest(c.Body)
		if (err == nil) != c.Valid {
			t.Errorf("manifest %q: valid %v, got %v", c.Name, c.Valid, err)
		}
	}
}

// TestStrictGeneratedManifests checks the manifests of
// testdata/interop/strict-generated-*.json, which internal/group writes from
// the tables of docs/protocol.md.
func TestStrictGeneratedManifests(t *testing.T) {
	type file struct {
		Manifests []struct {
			Name  string `json:"name"`
			Rule  string `json:"rule"`
			Body  []byte `json:"body"`
			Valid bool   `json:"valid"`
		} `json:"manifests"`
	}
	var v file
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "interop", "strict-generated-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no generated vectors: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var part file
		if err := json.Unmarshal(data, &part); err != nil {
			t.Fatal(err)
		}
		v.Manifests = append(v.Manifests, part.Manifests...)
	}
	if len(v.Manifests) == 0 {
		t.Fatal("no manifests")
	}
	for _, c := range v.Manifests {
		_, err := ParseManifest(c.Body)
		if (err == nil) != c.Valid {
			t.Errorf("manifest %q (%s): valid %v, got %v", c.Name, c.Rule, c.Valid, err)
		}
	}
}

var update = flag.Bool("update", false, "write testdata/interop/media-names.json")

// A nameVector is a name a system or a sender may give, with whether
// CheckName takes it in a manifest, the name a receiver writes it under
// (SaveName, for a name CheckName takes) and the name CleanName makes of
// it.
type nameVector struct {
	Name  string `json:"name"`
	Valid bool   `json:"valid"`
	Save  string `json:"save,omitempty"`
	Clean string `json:"clean"`
}

// TestNameVectors checks testdata/interop/media-names.json, which the lite
// core and both kits read too (go test -update writes it): the device names
// of Windows that a manifest may hold are renamed when written and when a
// sender cleans a name, never refused.
func TestNameVectors(t *testing.T) {
	var v []nameVector
	for _, name := range []string{
		"report.pdf", "CON", "con.txt", "nul.tar.gz", "Aux", "PRN.", "com1", "LPT9.log",
		"COM0", "lpt0.txt", "COM\u00b9", "lpt\u00b2.doc", "COM\u00b3.x.y", "COM\u2074", "COM10", "COMx", "LPT",
		"CONIN$", "conout$.log", "CONIN", "CONERR$",
		"CON .txt", "nul  .x", "COM1 .txt", "com0 ", " CON.txt", "CON_.txt",
		"con\u0131n$", "\u017fom1", "CON.\u0301", "CON\u0301.txt", "\uff23\uff2f\uff2e",
		"console", "comX.txt",
	} {
		c := nameVector{Name: name, Valid: CheckName(name) == nil, Clean: CleanName(name)}
		if c.Valid {
			c.Save = SaveName(name)
		}
		v = append(v, c)
	}
	want, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	path := filepath.Join("..", "..", "testdata", "interop", "media-names.json")
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatal("media-names.json is not what the rules give: run go test ./internal/clip -run TestNameVectors -update")
	}
	for _, c := range v {
		if CheckName(c.Clean) != nil || device(c.Clean) {
			t.Errorf("CleanName(%q) = %q, which a receiver refuses or renames", c.Name, c.Clean)
		}
		if c.Valid && (CheckName(c.Save) != nil || device(c.Save)) {
			t.Errorf("SaveName(%q) = %q, which a receiver refuses or renames", c.Name, c.Save)
		}
	}
	// Names Windows reserves beyond the first list are taken in a manifest
	// and renamed, so that the copies of earlier members still arrive.
	for _, name := range []string{"COM0", "CONIN$", "CON .txt", "lpt\u00b9"} {
		if err := CheckName(name); err != nil {
			t.Errorf("CheckName(%q): %v", name, err)
		}
		if SaveName(name) == name {
			t.Errorf("SaveName(%q) kept a device name", name)
		}
	}
	if got := SavePath("a/COM0/CON .txt"); got != "a/COM0_/CON _.txt" {
		t.Errorf("SavePath = %q", got)
	}
}
