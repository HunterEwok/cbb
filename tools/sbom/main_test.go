// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func decode(t *testing.T, data []byte) BOM {
	t.Helper()
	var b BOM
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDocumentIsSortedOnceAndStable(t *testing.T) {
	comps := []Component{
		{Name: "b", Version: "1", Purl: "pkg:cargo/b@1"},
		{Name: "a", Version: "1", Purl: "pkg:cargo/a@1"},
		{Name: "b", Version: "1", Purl: "pkg:cargo/b@1"},
	}
	one, err := Document("x", "0.6.0", comps)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Document("x", "0.6.0", []Component{comps[1], comps[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatal("the same components in another order made another document")
	}
	b := decode(t, one)
	if b.BOMFormat != "CycloneDX" || b.SpecVersion != "1.6" || !strings.HasPrefix(b.SerialNumber, "urn:uuid:") {
		t.Fatalf("header %+v", b)
	}
	if len(b.Components) != 2 || b.Components[0].Purl != "pkg:cargo/a@1" || b.Components[0].Type != "library" {
		t.Fatalf("components %+v", b.Components)
	}
	if len(b.Dependencies) != 1 || b.Dependencies[0].Ref != "root" || len(b.Dependencies[0].DependsOn) != 2 {
		t.Fatalf("dependencies %+v", b.Dependencies)
	}
	other, err := Document("x", "0.6.1", comps)
	if err != nil {
		t.Fatal(err)
	}
	if decode(t, other).SerialNumber == b.SerialNumber {
		t.Fatal("another version kept the serial number")
	}
	if _, err := Document("x", "1", []Component{{Name: "no purl"}}); err == nil {
		t.Fatal("a component without a purl was taken")
	}
}

func TestPurlEscapes(t *testing.T) {
	if got := purl("golang", "github.com/a/b", "v2.0.0+incompatible"); got != "pkg:golang/github.com/a/b@v2.0.0%2Bincompatible" {
		t.Fatal(got)
	}
}

func TestGoModules(t *testing.T) {
	info := &debug.BuildInfo{
		GoVersion: "go1.27.3",
		Main:      debug.Module{Path: "github.com/HunterEwok/cbb"},
		Deps: []*debug.Module{
			{Path: "golang.org/x/sys", Version: "v0.49.0", Sum: "h1:abc="},
			{Path: "example.com/old", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/new", Version: "v1.1.0"}},
			{Path: "example.com/local", Version: "v1.0.0", Replace: &debug.Module{Path: "../local"}},
		},
	}
	got := GoModules(info)
	want := []string{"pkg:golang/stdlib@1.27.3", "pkg:golang/golang.org/x/sys@v0.49.0", "pkg:golang/example.com/new@v1.1.0"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, w := range want {
		if got[i].Purl != w {
			t.Fatalf("component %d is %s, want %s", i, got[i].Purl, w)
		}
	}
	if got[1].Properties[0].Value != "h1:abc=" {
		t.Fatalf("the sum is lost: %+v", got[1])
	}
}

// TestGoReadsArchives runs the command on this test's own program, plain
// and in a tar.gz as the release's archives hold it.
func TestGoReadsArchives(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		mode int64
		data []byte
	}{{"x/README", 0o644, []byte("text")}, {"x/install.sh", 0o755, []byte("#!/bin/sh\n")}, {"x/cbb", 0o755, prog}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	archive := filepath.Join(dir, "x.tar.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "go.cdx.json")
	if err := run("go", []string{"-o", out, "-version", "v0.6.0", archive, exe}, goCmd); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	b := decode(t, data)
	if b.Metadata.Component.Version != "0.6.0" {
		t.Fatalf("version %q", b.Metadata.Component.Version)
	}
	if len(b.Components) == 0 || !strings.HasPrefix(b.Components[0].Purl, "pkg:golang/") {
		t.Fatalf("components %+v", b.Components)
	}
	text := filepath.Join(dir, "text")
	os.WriteFile(text, []byte("no program"), 0o644)
	if err := run("go", []string{"-o", out, text}, goCmd); err == nil {
		t.Fatal("a file without a Go program made a document")
	}
}

const metadata = `{
  "packages": [
    {"id": "path+file:///w#app@0.1.0", "name": "app", "version": "0.1.0", "source": null, "license": "AGPL-3.0-only"},
    {"id": "path+file:///w/core#core@0.1.0", "name": "core", "version": "0.1.0", "source": null},
    {"id": "registry+x#serde@1.0.0", "name": "serde", "version": "1.0.0", "source": "registry+x", "license": "MIT OR Apache-2.0"},
    {"id": "registry+x#cc@1.0.0", "name": "cc", "version": "1.0.0", "source": "registry+x"},
    {"id": "registry+x#proptest@1.0.0", "name": "proptest", "version": "1.0.0", "source": "registry+x"},
    {"id": "registry+x#libc@0.2.0", "name": "libc", "version": "0.2.0", "source": "registry+x"}
  ],
  "resolve": {"nodes": [
    {"id": "path+file:///w#app@0.1.0", "deps": [
      {"pkg": "path+file:///w/core#core@0.1.0", "dep_kinds": [{"kind": null}]},
      {"pkg": "registry+x#cc@1.0.0", "dep_kinds": [{"kind": "build"}]},
      {"pkg": "registry+x#proptest@1.0.0", "dep_kinds": [{"kind": "dev"}]}
    ]},
    {"id": "path+file:///w/core#core@0.1.0", "deps": [
      {"pkg": "registry+x#serde@1.0.0", "dep_kinds": [{"kind": "dev"}, {"kind": null}]},
      {"pkg": "registry+x#libc@0.2.0", "dep_kinds": [{"kind": null}]}
    ]},
    {"id": "registry+x#serde@1.0.0", "deps": [{"pkg": "registry+x#libc@0.2.0", "dep_kinds": [{"kind": null}]}]}
  ]}
}`

func TestCargoCrates(t *testing.T) {
	sums := LockChecksums("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\nchecksum = \"aa\"\n\n[[package]]\nname = \"libc\"\nversion = \"0.2.0\"\n")
	if sums["serde 1.0.0"] != "aa" || sums["libc 0.2.0"] != "" {
		t.Fatalf("sums %v", sums)
	}
	got, err := CargoCrates([]byte(metadata), "app", sums)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]Component{}
	for _, c := range got {
		names[c.Name] = c
	}
	if len(got) != 2 || names["serde"].Purl != "pkg:cargo/serde@1.0.0" || names["libc"].Name == "" {
		t.Fatalf("crates %+v: want serde and libc, not the workspace's, build or dev ones", got)
	}
	if names["serde"].Hashes[0].Content != "aa" || names["serde"].Licenses[0].Expression != "MIT OR Apache-2.0" {
		t.Fatalf("serde %+v", names["serde"])
	}
	if _, err := CargoCrates([]byte(metadata), "nope", sums); err == nil {
		t.Fatal("an unknown package was taken")
	}
}

func TestSwiftPackages(t *testing.T) {
	got, err := SwiftPackages([]byte(`{"pins":[{"identity":"swift-crypto","kind":"remoteSourceControl",
		"location":"https://github.com/apple/swift-crypto.git","state":{"revision":"da9d","version":"4.5.2"}}],"version":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Purl != "pkg:swift/github.com/apple/swift-crypto@4.5.2" {
		t.Fatalf("got %+v", got)
	}
	for _, bad := range []string{`{"pins":[],"version":1}`, `{"pins":[{"identity":"x","location":"x","state":{}}],"version":2}`, `[`} {
		if _, err := SwiftPackages([]byte(bad)); err == nil {
			t.Fatalf("%s was taken", bad)
		}
	}
}

func TestGradleModules(t *testing.T) {
	got, err := GradleModules("androidx.core:core:1.17.0\n\ncom.google.code.gson:gson:2.11.0\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Purl != "pkg:maven/androidx.core/core@1.17.0" || got[0].Group != "androidx.core" {
		t.Fatalf("got %+v", got)
	}
	for _, bad := range []string{"", "a:b", "a::c", "a:b:c:d"} {
		if _, err := GradleModules(bad); err == nil {
			t.Fatalf("%q was taken", bad)
		}
	}
}
