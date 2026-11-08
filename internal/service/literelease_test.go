// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// writeRoots writes the signer's roots as the PEM file CBB_RELEASE_ROOTS
// names and returns the Rust member's environment for it.
func writeRoots(t *testing.T, signer *releaseSigner) []string {
	t.Helper()
	return []string{signer.rootsEnv(t)}
}

// TestLiteRelease: a signed release passes between the Go service and the
// Rust one both ways, the Rust member keeps it across a restart and takes
// no older or forged one.
func TestLiteRelease(t *testing.T) {
	bin := liteBin(t)
	signer := newReleaseSigner(t)
	env := writeRoots(t, signer)
	var h hub
	desk := startEnv(t, &h, "desk", signer.rootsEnv(t))
	dir := joinFull(t, bin, desk)
	args := []string{"-no-mdns", "-no-listen", "-peer", desk.addr()}
	rust := startLiteEnv(t, bin, dir, env, args...)
	status := func() *control.Status {
		m, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		if err != nil || m.Status == nil {
			t.Fatalf("status: %v", err)
		}
		return m.Status
	}
	waitFor(t, "the Rust member connected", func() bool { return len(status().Peers) == 1 })

	if _, err := desk.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.1", 2))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust member holds 0.6.1", func() bool { return status().Release == "0.6.1" })
	if _, err := rust.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.0", 1))); err == nil {
		t.Error("the Rust member took an older channel file")
	}
	forged := signer.sign(t, "0.6.2", 3)
	forged.Release.Sig[len(forged.Release.Sig)-1] ^= 1
	if _, err := rust.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, forged)); err == nil {
		t.Error("the Rust member took a forged release")
	}
	if _, err := rust.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, newReleaseSigner(t).sign(t, "0.6.2", 3))); err == nil {
		t.Error("the Rust member took a release under other roots")
	}

	if _, err := rust.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.2", 3))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the desk holds 0.6.2 from the Rust member", func() bool { return desk.status(t).Release == "0.6.2" })

	rust.stop()
	rust = startLiteEnv(t, bin, dir, env, args...)
	waitFor(t, "the Rust member holds 0.6.2 after a restart", func() bool {
		m, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status != nil && m.Status.Release == "0.6.2"
	})
}

// TestLiteReleaseArchives passes an archive of the held release between
// the Go service and the Rust one both ways, as cbb update hands it over
// and asks for it; a file the release does not list is refused, and a
// newer release drops it.
func TestLiteReleaseArchives(t *testing.T) {
	bin := liteBin(t)
	signer := newReleaseSigner(t)
	env := writeRoots(t, signer)
	var h hub
	desk := startEnv(t, &h, "desk", signer.rootsEnv(t))
	dir := joinFull(t, bin, desk)
	rust := startLiteEnv(t, bin, dir, env, "-no-mdns", "-no-listen", "-peer", desk.addr())
	waitFor(t, "the Rust member connected", func() bool {
		m, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status != nil && len(m.Status.Peers) == 1
	})

	data := bytes.Repeat([]byte("cbb 0.6.1 "), 300_000)
	sum := hexSum(data)
	if _, err := desk.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.signArchive(t, "0.6.1", 2, data))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Rust member holds 0.6.1", func() bool {
		m, err := rust.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && m.Status != nil && m.Status.Release == "0.6.1"
	})
	if _, err := getArchive(t, rust, sum); err == nil {
		t.Fatal("the Rust member got an archive no member holds")
	}
	if err := putArchive(t, rust, hexSum([]byte("other")), []byte("other")); err == nil {
		t.Error("the Rust member took a file the release does not list")
	}
	if err := putArchive(t, rust, sum, data[1:]); err == nil {
		t.Error("the Rust member took a short archive")
	}

	// From the Go service to the Rust one.
	if err := putArchive(t, desk, sum, data); err != nil {
		t.Fatal(err)
	}
	got, err := getArchive(t, rust, sum)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the Rust member got %d bytes, %v", len(got), err)
	}
	if _, err := os.Stat(filepath.Join(dir, releaseFilesDir, sum)); err != nil {
		t.Errorf("the Rust member does not keep the archive it fetched: %v", err)
	}

	// From the Rust service to the Go one, under a newer release.
	data2 := bytes.Repeat([]byte("cbb 0.6.2 "), 200_000)
	sum2 := hexSum(data2)
	if _, err := rust.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.signArchive(t, "0.6.2", 3, data2))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the desk holds 0.6.2", func() bool { return desk.status(t).Release == "0.6.2" })
	if _, err := os.Stat(filepath.Join(dir, releaseFilesDir, sum)); !os.IsNotExist(err) {
		t.Errorf("the Rust member keeps the archive of 0.6.1: %v", err)
	}
	if err := putArchive(t, rust, sum2, data2); err != nil {
		t.Fatal(err)
	}
	if got, err := getArchive(t, desk, sum2); err != nil || !bytes.Equal(got, data2) {
		t.Fatalf("the desk got %d bytes, %v", len(got), err)
	}
	if m, err := rust.do(t, control.Header{Op: control.OpReleaseWant}, ""); err != nil || string(m.Payload) != "null" {
		t.Errorf("a Rust member that is no hub wants %q: %v", m.Payload, err)
	}
}
