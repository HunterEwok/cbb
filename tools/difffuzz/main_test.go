// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vectors = "../../testdata/interop"

// TestGenerateSeeded checks that a seed gives one corpus and that its bodies
// are changed ones, of every kind.
func TestGenerateSeeded(t *testing.T) {
	a, err := generate(vectors, 7, 2000, 50)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := generate(vectors, 7, 2000, 50)
	c, _ := generate(vectors, 8, 2000, 50)
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
	for _, k := range []string{"record", "command", "manifest", "credential", "keys", "release", "channel", "attest-status", "set"} {
		if kinds[k] == 0 {
			t.Errorf("no changed %s", k)
		}
	}
}

// TestSeedsMutants checks that the bodies of strict-mutants-*.json are
// record seeds too, after those of the other files.
func TestSeedsMutants(t *testing.T) {
	dir := t.TempDir()
	files, err := filepath.Glob(filepath.Join(vectors, "strict-generated-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no generated vectors: %v", err)
	}
	for _, f := range append(files, filepath.Join(vectors, "strict-files.json")) {
		f = filepath.Base(f)
		data, err := os.ReadFile(filepath.Join(vectors, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	base, err := seeds(dir)
	if err != nil {
		t.Fatal(err)
	}
	mutant := `{"records":[{"name":"m","rule":"mutant","valid":false,"body":"e30=","pad":2,"pad_at":1}]}`
	if err := os.WriteFile(filepath.Join(dir, "strict-mutants-1.json"), []byte(mutant), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := seeds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(base)+1 {
		t.Fatalf("%d seeds, want %d", len(got), len(base)+1)
	}
	if last := got[len(got)-1]; last.Kind != "record" || string(last.Body) != "{aa}" {
		t.Fatalf("seed %s %q", last.Kind, last.Body)
	}
}

// TestSetSources checks the three forms a file of record sets takes.
func TestSetSources(t *testing.T) {
	dir := t.TempDir()
	set := `{"name":"%s","group_ca":"Y2E=","records":[{"body":"e30=","sig":"c2ln"}]}`
	files := map[string]string{
		"one.json":   fmt.Sprintf(set, "x"),
		"cases.json": `{"cases":[` + fmt.Sprintf(set, "a") + `,` + fmt.Sprintf(set, "b") + `]}`,
		"list.json":  `[` + fmt.Sprintf(set, "c") + `]`,
		"none.json":  `{"records":[]}`,
	}
	for f, data := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := setSources(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range got {
		names = append(names, s.name)
	}
	if want := "cases/a cases/b list/c one"; strings.Join(names, " ") != want {
		t.Fatalf("sets %q, want %q", strings.Join(names, " "), want)
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
	if err := checkFields("record", "taken type=00 group=00"); err == nil {
		t.Fatal("took a record's verdict with other fields")
	}
	if err := checkFields("credential", "taken type= group= version=1 expires_ms=2 tag= key= hubs= admins= members="); err != nil {
		t.Fatal(err)
	}
}
