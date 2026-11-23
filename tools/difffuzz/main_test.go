// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vectors = "../../testdata/interop"

// TestGenerateSeeded checks that a seed gives one corpus and that its bodies
// are changed ones, of every kind.
func TestGenerateSeeded(t *testing.T) {
	a, err := generate(vectors, 7, 2000)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := generate(vectors, 7, 2000)
	c, _ := generate(vectors, 8, 2000)
	enc := func(l []Case) []byte {
		j, _ := json.Marshal(l)
		return j
	}
	if !bytes.Equal(enc(a), enc(b)) {
		t.Fatal("one seed gave two corpora")
	}
	if bytes.Equal(enc(a), enc(c)) {
		t.Fatal("two seeds gave one corpus")
	}
	base, _ := seeds(vectors)
	kinds := map[string]int{}
	for _, x := range a[len(base):] {
		kinds[x.Kind]++
	}
	for _, k := range []string{"command", "manifest", "keys", "release", "channel", "attest-status"} {
		if kinds[k] == 0 {
			t.Errorf("no changed %s", k)
		}
	}
}

// TestSeedsPad checks that a vector's padding goes into its seed, as the
// readers' tests apply it.
func TestSeedsPad(t *testing.T) {
	dir := t.TempDir()
	gen := `{"commands":[{"name":"c","rule":"r","valid":false,"body":"e30=","pad":2,"pad_at":1}],"manifests":[{"name":"m","rule":"r","valid":false,"body":"e30="}]}`
	files := `{"releases":[{"name":"k","rule":"r","valid":false,"kind":"keys","body":"e30="}]}`
	for f, data := range map[string]string{"strict-generated-1.json": gen, "strict-files.json": files} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := seeds(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []Case{{Kind: "command", Body: []byte("{aa}")}, {Kind: "manifest", Body: []byte("{}")}, {Kind: "keys", Body: []byte("{}")}}
	if len(got) != len(want) {
		t.Fatalf("%d seeds, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || !bytes.Equal(got[i].Body, want[i].Body) {
			t.Errorf("seed %d: %s %q, want %s %q", i, got[i].Kind, got[i].Body, want[i].Kind, want[i].Body)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "strict-files.json"), []byte(`{"releases":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := seeds(dir); err == nil {
		t.Error("took a file with no releases")
	}
}

// TestWriteSeeds checks that the seeds of the fuzz targets go to a
// directory of each target, the api target's requests among them.
func TestWriteSeeds(t *testing.T) {
	out := t.TempDir()
	if err := writeSeeds(vectors, out); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"command", "wire", "release", "api", "sheet", "yubikey_object", "welcome_fields", "welcome_parts"} {
		files, err := os.ReadDir(filepath.Join(out, target))
		if err != nil || len(files) == 0 {
			t.Errorf("no seeds for %s: %v", target, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "api", "1"))
	if err != nil || !strings.Contains(string(data), `"op":"version"`) {
		t.Errorf("the api's first seed: %s %v", data, err)
	}
}

// TestMembers checks that an object splits into its members as written.
func TestMembers(t *testing.T) {
	o, ok := members([]byte(` { "a" : 1, "b":{"c":[1, 2]} ,"a":"x"}`))
	if !ok || len(o) != 3 || o[0].name != `"a"` || string(o[1].value) != `{"c":[1, 2]}` {
		t.Fatalf("%q %v", o, ok)
	}
	if got := string(o.bytes()); got != `{"a":1,"b":{"c":[1, 2]},"a":"x"}` {
		t.Fatal(got)
	}
	for _, bad := range []string{`[]`, `{"a":1`, `{"a":1}x`, `{"a"}`} {
		if _, ok := members([]byte(bad)); ok {
			t.Errorf("%s split", bad)
		}
	}
}

// TestCompare checks that compare passes when all agree and fails, naming
// the case, when one reads it otherwise; a skip agrees with anything.
func TestCompare(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus.jsonl")
	if err := writeCorpus(corpus, []Case{{Kind: "manifest", Body: []byte("{}")}, {Kind: "keys", Body: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	a := write("a", "refused\ntaken\n")
	b1, b2 := write("b1", "refused\nskip\n"), write("b2", "skip\ntaken\n")
	c := write("c", "refused\nskip\n")
	d := write("d", "taken x=1\ntaken\n")
	var out strings.Builder
	if ok, err := compare(&out, corpus, []string{"a=" + a, "b=" + b1 + "," + b2, "c=" + c}, 5, "", nil); err != nil || !ok {
		t.Fatalf("%v %v\n%s", ok, err, out.String())
	}
	out.Reset()
	fails := filepath.Join(dir, "fails.jsonl")
	if ok, err := compare(&out, corpus, []string{"a=" + a, "d=" + d}, 5, fails, nil); err != nil || ok {
		t.Fatalf("%v %v", ok, err)
	}
	if !strings.Contains(out.String(), "case 1 (manifest)") || !strings.Contains(out.String(), "taken x=1") {
		t.Fatal(out.String())
	}
	out.Reset()
	if ok, err := compare(&out, corpus, []string{"a=" + a, "d=" + d}, 5, "", []string{"manifest"}); err != nil || !ok {
		t.Fatalf("a kind only reported failed: %v %v", ok, err)
	}
	if !strings.Contains(out.String(), "case 1 (manifest)") {
		t.Fatal("a kind only reported was not printed")
	}
	if l, err := readCorpus(fails); err != nil || len(l) != 1 || l[0].Kind != "manifest" {
		t.Fatalf("failures %v %v", l, err)
	}
	if _, err := compare(&out, corpus, []string{"a=" + write("short", "refused\n")}, 5, "", nil); err == nil {
		t.Fatal("took verdicts for fewer cases")
	}
	if err := checkFields("command", "taken type=00 group=00"); err == nil {
		t.Fatal("took a command's verdict with other fields")
	}
	if err := checkFields("command", "taken type= group= by= to= id= time_ms=1 expires_ms=2 mode= enter=0 kind= text= action="); err != nil {
		t.Fatal(err)
	}
}
