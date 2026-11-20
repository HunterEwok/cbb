// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/release"
)

// zxnext adds the ZX Spectrum Next's archive to a draft, as the release
// workflow's zxnext job does, with the dot command's content given.
func (g *fakeGitHub) zxnext(tag, dot string) {
	g.t.Helper()
	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "zxnext/", Mode: 0o755, Typeflag: tar.TypeDir})
	for _, f := range [][2]string{{"CBB", dot}, {"CBB.OVL", "overlay"}, {"CBB.DRV", "driver"}, {"cbb", "pi"}, {"LIST", "list " + dot}} {
		tw.WriteHeader(&tar.Header{Name: "zxnext/" + f[0], Mode: 0o644, Size: int64(len(f[1])), Typeflag: tar.TypeReg})
		tw.Write([]byte(f[1]))
	}
	tw.Close()
	gz.Close()
	d := g.release(tag)
	write(g.t, filepath.Join(d, zxnextArchive), tgz.Bytes())
	var sums strings.Builder
	entries, _ := os.ReadDir(d)
	for _, e := range entries {
		if e.Name() != "SHA256SUMS" && !provenance(e.Name()) {
			fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(must(os.ReadFile(filepath.Join(d, e.Name())))), e.Name())
		}
	}
	write(g.t, filepath.Join(d, "SHA256SUMS"), []byte(sums.String()))
}

// TestMirror keeps a mirror of the releases a pre-release and two
// releases long, as cbb.tools does.
func TestMirror(t *testing.T) {
	g := newFakeGitHub(t)
	k := testKeys(t)
	keyFlags := []string{"-root", "file:" + k.root1, "-release-key", "file:" + k.release}
	pub := func(extra ...string) {
		t.Helper()
		if err := publish(append(append([]string{}, keyFlags...), extra...)); err != nil {
			t.Fatal(err)
		}
	}
	out, zx := t.TempDir(), t.TempDir()
	run := func(extra ...string) string {
		t.Helper()
		return string(call(t, mirror, append([]string{"-out", out, "-from", g.channel(), "-releases", g.dir, "-zxnext", zx}, extra...)...))
	}
	// LIST tells which release the Next's files came from: on a file
	// system that ignores case (Windows, macOS) the Pi's cbb and the dot
	// command CBB are one file, while cbb.tools keeps them apart.
	zxList := func() string { return string(must(os.ReadFile(filepath.Join(zx, "LIST")))) }

	// Before any release the mirror has nothing to take.
	if mirror([]string{"-out", out, "-from", g.channel(), "-releases", g.dir}) == nil {
		t.Fatal("mirrored without a keys.json")
	}

	// A pre-release has no channel file: only keys.json, and the
	// pre-release when asked for.
	g.draft("v0.6.0-rc.1")
	g.zxnext("v0.6.0-rc.1", "rc1")
	pub("-version", "0.6.0-rc.1", "-channel", "cbb.tools="+k.channelPub)
	if got := run(); !strings.Contains(got, "no stable.json") {
		t.Errorf("mirror printed %q", got)
	}
	if _, err := os.Stat(filepath.Join(out, "v0.6.0-rc.1")); err == nil {
		t.Error("mirrored a pre-release nobody asked for")
	}
	run("-version", "v0.6.0-rc.1")
	if zxList() != "list rc1" || string(must(os.ReadFile(filepath.Join(zx, "CBB.DRV")))) != "driver" {
		t.Errorf("the Next's files are %q", zxList())
	}
	// SIGNED holds keys.json and the release's zxnext.json, which the
	// Pi's cbb takes for these files.
	zxSigned := func() release.ZXNext {
		t.Helper()
		lines := strings.Split(strings.TrimSpace(string(must(os.ReadFile(filepath.Join(zx, zxnextSigned))))), "\n")
		if len(lines) != 2 {
			t.Fatalf("SIGNED has %d lines", len(lines))
		}
		var keys, list release.File
		if json.Unmarshal([]byte(lines[0]), &keys) != nil || json.Unmarshal([]byte(lines[1]), &list) != nil {
			t.Fatal("SIGNED holds no signed files")
		}
		z, err := release.CheckZXNext(keys, list, pinnedRoots(), now(), "")
		if err != nil {
			t.Fatal(err)
		}
		return z
	}
	if z := zxSigned(); z.Version != "0.6.0-rc.1" || z.Files[0].Name != "CBB" || z.Files[0].Size != 3 {
		t.Errorf("SIGNED lists %+v", z)
	}

	// The release the channel names, and its min_from, which stays.
	g.draft("v0.6.0")
	g.zxnext("v0.6.0", "060")
	pub("-version", "0.6.0")
	g.draft("v0.6.1")
	pub("-version", "0.6.1", "-min-from", "0.6.0")
	os.RemoveAll(filepath.Join(out, "v0.6.0"))
	if got := run(); !strings.Contains(got, "names 0.6.1") {
		t.Errorf("mirror printed %q", got)
	}
	for _, v := range []string{"v0.6.0", "v0.6.1"} {
		d := t.TempDir()
		for _, name := range []string{"keys.json", "stable.json"} {
			copyFile(filepath.Join(out, name), filepath.Join(d, name))
		}
		entries, _ := os.ReadDir(filepath.Join(out, v))
		for _, e := range entries {
			copyFile(filepath.Join(out, v, e.Name()), filepath.Join(d, e.Name()))
		}
		if v == "v0.6.1" {
			call(t, verify, d)
		} else if _, err := os.Stat(filepath.Join(d, zxnextArchive)); err != nil {
			t.Errorf("%s was not mirrored: %v", v, err)
		}
	}
	// 0.6.1 has no Next's files: they stay those of 0.6.0, a newer
	// release than the pre-release.
	if zxList() != "list 060" {
		t.Errorf("the Next's files are %q", zxList())
	}
	if z := zxSigned(); z.Version != "0.6.0" {
		t.Errorf("SIGNED lists %+v", z)
	}
	// A zxnext.json that does not list the files the mirror unpacked
	// leaves no SIGNED, nor does a release without one.
	zj := filepath.Join(out, "v0.6.0", zxnextName)
	good := must(os.ReadFile(zj))
	other := filepath.Join(out, "v0.6.0-rc.1", zxnextName)
	copyFile(other, zj)
	run()
	if _, err := os.Stat(filepath.Join(zx, zxnextSigned)); err == nil {
		t.Error("SIGNED holds a list of other files")
	}
	os.Remove(zj)
	run()
	if _, err := os.Stat(filepath.Join(zx, zxnextSigned)); err == nil {
		t.Error("SIGNED without a zxnext.json")
	}
	write(t, zj, good)
	run()
	zxSigned()

	// The mirror never goes back to an older channel file than it serves.
	branchStable := filepath.Join(g.channel(), "stable.json")
	newer := must(os.ReadFile(filepath.Join(out, "stable.json")))
	call(t, extend, "-key", "file:"+k.channel, "-out", t.TempDir(), "-from", g.channel(), "-releases", g.dir)
	renewed := t.TempDir()
	call(t, extend, "-key", "file:"+k.channel, "-out", renewed, "-from", g.channel(), "-releases", g.dir)
	run("-from", g.channel()+","+renewed)
	if bytes.Equal(must(os.ReadFile(filepath.Join(out, "stable.json"))), newer) {
		t.Error("the renewed stable.json was not taken")
	}
	taken := must(os.ReadFile(filepath.Join(out, "stable.json")))
	run()
	if !bytes.Equal(must(os.ReadFile(filepath.Join(out, "stable.json"))), taken) || bytes.Equal(taken, must(os.ReadFile(branchStable))) {
		t.Error("the mirror went back to the branch's older stable.json")
	}

	// A file changed on the server after signing is not mirrored.
	g.draft("v0.6.2")
	pub("-version", "0.6.2")
	write(t, filepath.Join(g.release("v0.6.2"), "sbom-go.cdx.json"), []byte(`{"changed":1}`))
	if mirror([]string{"-out", out, "-from", g.channel(), "-releases", g.dir}) == nil {
		t.Error("mirrored a changed file")
	}
	if _, err := os.Stat(filepath.Join(out, "v0.6.2")); err == nil {
		t.Error("a release that failed is in the mirror")
	}
	if !bytes.Equal(must(os.ReadFile(filepath.Join(out, "stable.json"))), taken) {
		t.Error("the channel file names a release the mirror lacks")
	}
}

func TestReadZXNextRefusesOtherPaths(t *testing.T) {
	for _, name := range []string{"zxnext/../x", "other/CBB", "zxnext/sub/CBB", "zxnext/.hidden", `zxnext/a\..\x`, "zxnext/C:x"} {
		var tgz bytes.Buffer
		gz := gzip.NewWriter(&tgz)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
		tw.Close()
		gz.Close()
		p := write(t, filepath.Join(t.TempDir(), zxnextArchive), tgz.Bytes())
		if _, err := readZXNext(p); err == nil {
			t.Errorf("read %s", name)
		}
	}
}
