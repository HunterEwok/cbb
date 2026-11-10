// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The bench's release feed (docs/testbench-catalogue.md, section 0.1,
// "feed"): releases of the build under test, in the format of the real one
// (docs/protocol.md, section 16), signed by tools/release-sign with the
// bench's own throwaway keys in files, never the project's. Each release is
// a folder of its own with keys.json, stable.json, release.json, the
// archives and SHA256SUMS side by side, which cbb update and get.sh take
// with CBB_RELEASE_DIR and CBB_RELEASE_ROOTS.

// feed holds the run's keys and its built programs.
type feed struct {
	dir   string // the run's work folder on the controller
	rs    string // tools/release-sign, built
	roots string // the root keys' public PEM file, CBB_RELEASE_ROOTS
	seq   int    // the channel file's next seq
}

// newFeed builds release-sign and makes the root and release keys.
// remove deletes the feed's folder with its builds; each feed holds
// close to 1 GiB.
func (fd *feed) remove() {
	if fd != nil {
		os.RemoveAll(fd.dir)
	}
}

func newFeed(ctx context.Context) (fd *feed, err error) {
	dir, err := os.MkdirTemp("", "cbbbench-feed")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	fd = &feed{dir: dir, rs: filepath.Join(dir, "release-sign"), roots: filepath.Join(dir, "roots.pem"), seq: 1}
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", fd.rs, "./tools/release-sign").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run the bench at the repository's top: building tools/release-sign: %v: %s", err, out)
	}
	for _, name := range []string{"root1", "root2", "release", "other"} {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(fd.key(name), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
	}
	var roots []byte
	for _, name := range []string{"root1", "root2"} {
		pub, err := fd.sign(ctx, "public", "-key", "file:"+fd.key(name))
		if err != nil {
			return nil, err
		}
		roots = append(roots, pub...)
	}
	return fd, os.WriteFile(fd.roots, roots, 0o644)
}

func (fd *feed) key(name string) string { return filepath.Join(fd.dir, name+".pem") }

// sign runs release-sign and returns what it printed.
func (fd *feed) sign(ctx context.Context, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, fd.rs, args...)
	var stderr strings.Builder
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("release-sign %s: %v: %s", args[0], err, stderr.String())
	}
	return out, nil
}

// build builds the Rust cbb at version for goarch, with cbb-helper of
// the same version beside it (the service refuses a helper of another),
// and packs them as the release does (packaging/archive.sh) into a new
// folder, which it returns, under the archive name of the CPU name. Only
// this computer's CPU is built: for another, the program is this one's
// marked for that CPU, which no kernel here runs, as another CPU's program
// under this one's name makes a build that never starts. Each version
// rebuilds only the crate that carries it, in target/benchfeed.
func (fd *feed) build(ctx context.Context, version, goarch, name string) (string, error) {
	out := filepath.Join(fd.dir, "v"+version+"-"+goarch+"-"+name)
	bins := filepath.Join(fd.dir, "bin-"+version+"-"+goarch)
	for _, d := range []string{out, bins} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", err
		}
	}
	c := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-X github.com/HunterEwok/cbb/internal/version.Version=v"+version, "-o", filepath.Join(bins, "cbb-helper"), "./cmd/cbb-helper")
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	if b, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building cbb-helper %s: %v: %s", version, err, b)
	}
	c = exec.CommandContext(ctx, "cargo", "build", "-q", "--locked", "--release", "--bin", "cbb", "--target-dir", "target/benchfeed")
	c.Env = append(os.Environ(), "CBB_VERSION="+version)
	if b, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building cbb %s: %v: %s", version, err, b)
	}
	prog, err := os.ReadFile("target/benchfeed/release/cbb")
	if err != nil {
		return "", err
	}
	if goarch != goarchOf() {
		// The ELF header's e_machine: AArch64 or x86-64.
		if len(prog) < 20 {
			return "", fmt.Errorf("cbb is %d bytes", len(prog))
		}
		prog[18], prog[19] = map[string]byte{"arm64": 0xb7, "amd64": 0x3e}[goarch], 0
	}
	bin := filepath.Join(bins, "cbb")
	if err := os.WriteFile(bin, prog, 0o755); err != nil {
		return "", err
	}
	if b, err := exec.CommandContext(ctx, "sh", "packaging/archive.sh", bin, "linux", name, out).CombinedOutput(); err != nil {
		return "", fmt.Errorf("packing cbb %s: %v: %s", version, err, b)
	}
	return out, nil
}

// releaseOpts change what publish signs, for the refusals.
type releaseOpts struct {
	minFrom  string
	keyDays  int    // keys.json's lifetime; 0 is release-sign's own
	chanDays int    // stable.json's lifetime
	keysBy   string // the root key that signs keys.json, root1 by default
	relBy    string // the key that signs release.json and stable.json, release by default
}

// publish signs the archives in built as release version into a folder of
// its own named name, and returns it.
func (fd *feed) publish(ctx context.Context, built, name, version string, o releaseOpts) (string, error) {
	dir := filepath.Join(fd.dir, "feed-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(built)
	if err != nil {
		return "", err
	}
	var sums strings.Builder
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(built, e.Name()))
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			return "", err
		}
		s := sha256.Sum256(data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), e.Name())
	}
	args := []string{"manifest", "-version", version, "-channel", "stable"}
	if o.minFrom != "" {
		args = append(args, "-min-from", o.minFrom)
	}
	body, err := fd.sign(ctx, append(args, built)...)
	if err != nil {
		return "", err
	}
	relBy, keysBy := o.relBy, o.keysBy
	if relBy == "" {
		relBy = "release"
	}
	if keysBy == "" {
		keysBy = "root1"
	}
	steps := []struct {
		file   string
		body   []byte
		signer string
	}{{"release.json", body, relBy}}
	pub, err := fd.sign(ctx, "public", "-key", "file:"+fd.key("release"))
	if err != nil {
		return "", err
	}
	pubFile := filepath.Join(fd.dir, "release.pub")
	if err := os.WriteFile(pubFile, pub, 0o644); err != nil {
		return "", err
	}
	kargs := []string{"keys", "-seq", "1"}
	if o.keyDays != 0 {
		kargs = append(kargs, "-days", fmt.Sprint(o.keyDays))
	}
	keys, err := fd.sign(ctx, append(kargs, "bench="+pubFile)...)
	if err != nil {
		return "", err
	}
	steps = append(steps, struct {
		file   string
		body   []byte
		signer string
	}{"keys.json", keys, keysBy})
	for _, s := range steps {
		f := filepath.Join(fd.dir, name+"-"+s.file+".body")
		if err := os.WriteFile(f, s.body, 0o644); err != nil {
			return "", err
		}
		signed, err := fd.sign(ctx, "sign", "-key", "file:"+fd.key(s.signer), f)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, s.file), signed, 0o644); err != nil {
			return "", err
		}
	}
	cargs := []string{"channel", "-seq", fmt.Sprint(fd.seq)}
	fd.seq++
	if o.chanDays != 0 {
		cargs = append(cargs, "-days", fmt.Sprint(o.chanDays))
	}
	ch, err := fd.sign(ctx, append(cargs, filepath.Join(dir, "release.json"))...)
	if err != nil {
		return "", err
	}
	f := filepath.Join(fd.dir, name+"-stable.json.body")
	if err := os.WriteFile(f, ch, 0o644); err != nil {
		return "", err
	}
	signed, err := fd.sign(ctx, "sign", "-key", "file:"+fd.key(relBy), f)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "stable.json"), signed, 0o644); err != nil {
		return "", err
	}
	return dir, os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644)
}

// tamper changes one byte in the middle of the file name in dir, after it
// was signed.
func tamper(dir, name string) error {
	p := filepath.Join(dir, name)
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	data[len(data)/2] ^= 0xff
	return os.WriteFile(p, data, 0o644)
}

// toDevice copies the feed's folder dir to /feed/NAME on d, and the roots
// to /feed/roots.pem.
func (fd *feed) toDevice(ctx context.Context, d *Device, dir string) (string, error) {
	at := "/feed/" + filepath.Base(dir)
	if _, err := Run(ctx, d, "mkdir -p /feed && rm -rf "+at, ""); err != nil {
		return "", err
	}
	if _, err := docker(ctx, "cp", dir, d.Container+":"+at); err != nil {
		return "", err
	}
	_, err := docker(ctx, "cp", fd.roots, d.Container+":/feed/roots.pem")
	return at, err
}

// feedEnv is the environment that points cbb update and get.sh at the
// feed's folder at on the device.
func feedEnv(at string) string {
	return "CBB_RELEASE_DIR=" + at + " CBB_RELEASE_ROOTS=/feed/roots.pem "
}
