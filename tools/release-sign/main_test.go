// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/release"
)

// call runs a command and returns what it wrote.
func call(t *testing.T, cmd func([]string) error, args ...string) []byte {
	t.Helper()
	var out bytes.Buffer
	stdout = &out
	defer func() { stdout = os.Stdout }()
	if err := cmd(args); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.Bytes()
}

func write(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newKey(t *testing.T, dir, name string) (priv, pub string) {
	t.Helper()
	k, err := release.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	// Both halves in one file; the public keys named, as roots.pem names
	// a root.
	priv = write(t, filepath.Join(dir, name+".key"), must(release.MarshalSignerPEM(k)))
	pub = write(t, filepath.Join(dir, name+".pem"), must(release.PublicPEM(k, name)))
	return priv, pub
}

func archives(t *testing.T, dir string) {
	t.Helper()
	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		mode int64
	}{{"cbb/cbb", 0o755}, {"cbb/LICENSE", 0o644}, {"cbb/packaging/linux/install.sh", 0o755}} {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: 4, Typeflag: tar.TypeReg})
		tw.Write([]byte("data"))
	}
	tw.Close()
	gz.Close()
	write(t, filepath.Join(dir, "cbb-linux-amd64.tar.gz"), tgz.Bytes())
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	for _, name := range []string{"cbb/cbb.exe", "cbb/cbbw.exe", "cbb/LICENSE"} {
		w, _ := zw.Create(name)
		w.Write([]byte(name))
	}
	zw.Close()
	write(t, filepath.Join(dir, "cbb-windows-amd64.zip"), z.Bytes())
	// A software bill of materials is JSON, and one of the release's files.
	write(t, filepath.Join(dir, "sbom-go.cdx.json"), []byte(`{"bomFormat":"CycloneDX"}`))
	var sums strings.Builder
	for _, name := range []string{"cbb-linux-amd64.tar.gz", "cbb-windows-amd64.zip", "sbom-go.cdx.json"} {
		sum := sha256.Sum256(must(os.ReadFile(filepath.Join(dir, name))))
		fmt.Fprintf(&sums, "%x  %s\n", sum, name)
	}
	write(t, filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()))
}

// TestFlow makes, signs and checks a release as docs/maintaining.md
// describes, with keys in files.
func TestFlow(t *testing.T) {
	keysDir, dist := t.TempDir(), t.TempDir()
	root1, root1Pub := newKey(t, keysDir, "root-1")
	_, root2Pub := newKey(t, keysDir, "root-2")
	rk, rkPub := newKey(t, keysDir, "release")
	archives(t, dist)

	body := write(t, filepath.Join(keysDir, "release.body"),
		call(t, manifest, "-version", "v0.6.0", "-min-from", "0.5.0", "-docker", "ghcr.io/x/cbb@sha256:"+strings.Repeat("ab", 32), dist))
	var r release.Release
	if err := json.Unmarshal(must(os.ReadFile(body)), &r); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Asset("sbom-go.cdx.json"); r.Version != "0.6.0" || len(r.Files) != 4 || !ok {
		t.Fatalf("the manifest is %+v", r)
	}
	tgz, _ := r.Asset("cbb-linux-amd64.tar.gz")
	if len(tgz.Binaries) != 1 || tgz.Binaries[0].Name != "cbb/cbb" {
		t.Errorf("the tar.gz lists %+v", tgz.Binaries)
	}
	z, _ := r.Asset("cbb-windows-amd64.zip")
	if len(z.Binaries) != 2 {
		t.Errorf("the zip lists %+v", z.Binaries)
	}

	write(t, filepath.Join(dist, "release.json"), call(t, sign, "-key", "file:"+rk, body))
	kb := write(t, filepath.Join(keysDir, "keys.body"), call(t, keys, "-seq", "1", "release key 1="+rkPub))
	write(t, filepath.Join(dist, "keys.json"), call(t, sign, "-key", "file:"+root1, kb))
	cb := write(t, filepath.Join(keysDir, "stable.body"), call(t, channel, "-seq", "1", filepath.Join(dist, "release.json")))
	write(t, filepath.Join(dist, "stable.json"), call(t, sign, "-key", "file:"+rk, cb))

	out := call(t, verify, "-roots", root1Pub+","+root2Pub, dist)
	if !strings.Contains(string(out), "0.6.0 stable") {
		t.Errorf("verify printed %q", out)
	}

	// A file changed after signing, or keys.json signed by the release key,
	// fails.
	write(t, filepath.Join(dist, "SHA256SUMS"), []byte("other\n"))
	if verify([]string{"-roots", root1Pub, dist}) == nil {
		t.Error("verify took a changed file")
	}
	write(t, filepath.Join(dist, "SHA256SUMS"), []byte("sums\n"))
	write(t, filepath.Join(dist, "keys.json"), call(t, sign, "-key", "file:"+rk, kb))
	if verify([]string{"-roots", root1Pub, dist}) == nil {
		t.Error("verify took keys.json signed by the release key")
	}
}

func TestDrill(t *testing.T) {
	dist, roots := t.TempDir(), filepath.Join(t.TempDir(), "roots.pem")
	archives(t, dist)
	call(t, drill, "-version", "0.6.0", dist, roots)
	data := must(os.ReadFile(roots))
	r1, _ := pem.Decode(data)
	r2, _ := pem.Decode(data[len(pem.EncodeToMemory(r1)):])
	for i, b := range []*pem.Block{r1, r2} {
		write(t, roots+string(rune('1'+i)), pem.EncodeToMemory(b))
	}
	call(t, verify, "-roots", roots+"1,"+roots+"2", dist)
}

// Each envelope of drill -envelopes is taken by verify as the readers'
// vectors say.
func TestDrillEnvelopes(t *testing.T) {
	dist, roots, envs := t.TempDir(), filepath.Join(t.TempDir(), "roots.pem"), t.TempDir()
	archives(t, dist)
	call(t, drill, "-version", "0.6.0", "-envelopes", envs, dist, roots)
	list := strings.Split(strings.TrimSpace(string(must(os.ReadFile(filepath.Join(envs, "list"))))), "\n")
	if len(list) != 63 {
		t.Fatalf("%d envelopes", len(list))
	}
	for _, line := range list {
		f := strings.SplitN(line, " ", 3)
		write(t, filepath.Join(dist, "release.json"), must(os.ReadFile(filepath.Join(envs, f[0]+".json"))))
		if err := verify([]string{"-roots", roots, dist}); (err == nil) != (f[1] == "true") {
			t.Errorf("%s: verify: %v", f[2], err)
		}
	}
	// keys.json's body at the largest a reader takes, and one byte more.
	for n, ok := range map[int]bool{release.MaxBody: true, release.MaxBody + 1: false} {
		call(t, drill, "-version", "0.6.0", "-pad-keys", fmt.Sprint(n), dist, roots)
		if err := verify([]string{"-roots", roots, dist}); (err == nil) != ok {
			t.Errorf("a body of %d bytes: verify: %v", n, err)
		}
	}
	if drill([]string{"-envelopes", envs, "-fault", "null", dist, roots}) == nil {
		t.Error("drill took -envelopes with -fault")
	}
}

// Each fault of drill -fault gives files that verify refuses, as the
// installers' tests expect of get.sh and get.ps1.
func TestDrillFaults(t *testing.T) {
	for _, fault := range drillFaults {
		dist, roots := t.TempDir(), filepath.Join(t.TempDir(), "roots.pem")
		archives(t, dist)
		call(t, drill, "-version", "0.6.0", "-fault", fault, dist, roots)
		// Under all the drill's roots, so that only the fault refuses it.
		if verify([]string{"-roots", roots, dist}) == nil {
			t.Errorf("%s: verify took it", fault)
		}
	}
}

func TestSignRefusesABadBody(t *testing.T) {
	dir := t.TempDir()
	k, _ := newKey(t, dir, "k")
	body := write(t, filepath.Join(dir, "body"), []byte(`{"v":1,"type":"keys","seq":1,"time_ms":1,"expires_ms":2,"keys":[]}`))
	if sign([]string{"-key", "file:" + k, body}) == nil {
		t.Error("signed keys.json without keys")
	}
	if _, err := signer("gpg:x"); err == nil {
		t.Error("took an unknown signer")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestCheckSums(t *testing.T) {
	dir := t.TempDir()
	archives(t, dir)
	sum := func(name string) string {
		s := sha256.Sum256(must(os.ReadFile(filepath.Join(dir, name))))
		return fmt.Sprintf("%x", s)
	}
	r := release.Release{Files: []release.Asset{
		{Name: "cbb-linux-amd64.tar.gz", SHA256: sum("cbb-linux-amd64.tar.gz")},
		{Name: "cbb-windows-amd64.zip", SHA256: sum("cbb-windows-amd64.zip")},
		{Name: "SHA256SUMS", SHA256: sum("SHA256SUMS")},
	}}
	if err := checkSums(dir, r); err != nil {
		t.Fatalf("good sums: %v", err)
	}
	// The manifest names a sum SHA256SUMS does not give.
	r.Files[1].SHA256 = strings.Repeat("0", 64)
	if checkSums(dir, r) == nil {
		t.Error("took a manifest that disagrees with SHA256SUMS")
	}
	r.Files[1].SHA256 = sum("cbb-windows-amd64.zip")
	// A line whose file changed.
	write(t, filepath.Join(dir, "cbb-windows-amd64.zip"), []byte("other"))
	if checkSums(dir, r) == nil {
		t.Error("took a file SHA256SUMS gives another sum")
	}
	write(t, filepath.Join(dir, "SHA256SUMS"), []byte("not a sum\n"))
	if checkSums(dir, r) == nil {
		t.Error("took a line that is no sum")
	}
}
