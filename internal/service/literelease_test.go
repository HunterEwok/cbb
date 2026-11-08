// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// TestLiteRelease: a signed release passes between the Go service and the
// Rust one both ways, the Rust member keeps it across a restart and takes
// no older or forged one.
func TestLiteRelease(t *testing.T) {
	bin := liteBin(t)
	signer := newReleaseSigner(t)
	roots := signer.roots(t)
	pemFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: roots[0]}), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"CBB_RELEASE_ROOTS=" + pemFile}
	var h hub
	desk := startWith(t, &h, "desk", "linux", func(c *Config) { c.ReleaseRoots = roots })
	dir := joinFull(t, bin, desk)
	args := []string{"-no-mdns", "-full", "-no-listen", "-peer", desk.addr()}
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
