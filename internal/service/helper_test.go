// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/tpmkey/tpmtest"
)

// TestAloneHelper: the Rust member starts cbb-helper as its child, which
// says hello over its inherited pipes, and the helper ends with the member
// (docs/design.md, "The service and its helper"). CBB_TEST_ALONE names the Rust
// member's binary.
func TestAloneHelper(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	helper := filepath.Join(t.TempDir(), "cbb-helper")
	if out, err := exec.Command("go", "build", "-tags", "testhooks", "-o", helper, "github.com/HunterEwok/cbb/cmd/cbb-helper").CombinedOutput(); err != nil {
		t.Fatalf("go build cbb-helper: %v\n%s", err, out)
	}
	s := startAloneEnv(t, bin, t.TempDir(), []string{"CBB_HELPER=" + helper})
	deadline := time.Now().Add(20 * time.Second)
	for !s.logged("cbb-helper runs: cbb ") {
		if time.Now().After(deadline) {
			t.Fatal("the Rust member never said that cbb-helper runs")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !running(helper) {
		t.Fatal("cbb-helper does not run beside the Rust member")
	}
	s.stop()
	deadline = time.Now().Add(10 * time.Second)
	for running(helper) {
		if time.Now().After(deadline) {
			t.Fatal("cbb-helper kept running after the Rust member stopped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// running says whether a process runs the program at path.
func running(path string) bool {
	procs, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, p := range procs {
		if exe, err := os.Readlink(p); err == nil && exe == path {
			return true
		}
	}
	return false
}

// TestAloneTPM: with cbb-helper beside it, the Rust member joins with its
// member key in the TPM, swtpm here: keys.json keeps the TPM's blob and
// no key, and the member's handshakes and copies
// are signed through the helper.
func TestAloneTPM(t *testing.T) {
	bin := os.Getenv("CBB_TEST_ALONE")
	if bin == "" {
		t.Skip("CBB_TEST_ALONE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the Rust member's tests run on Linux")
	}
	// swtpm takes one client at a time: only the Rust member's helper uses
	// it, so the test's own Go member finds no TPM.
	tpmtest.Start(t)
	sim := "CBB_TPM_SIMULATOR=" + os.Getenv("CBB_TPM_SIMULATOR")
	t.Setenv("CBB_TPM_SIMULATOR", "")
	group.ReopenTPM()
	t.Cleanup(group.ReopenTPM)
	helper := filepath.Join(t.TempDir(), "cbb-helper")
	if out, err := exec.Command("go", "build", "-tags", "testhooks", "-o", helper, "github.com/HunterEwok/cbb/cmd/cbb-helper").CombinedOutput(); err != nil {
		t.Fatalf("go build cbb-helper: %v\n%s", err, out)
	}
	t.Setenv("CBB_HELPER", helper)
	var h hub
	pi := startService(t, &h, "pi")
	dir := joinAloneEnv(t, bin, pi, []string{sim})
	var f struct {
		Member struct {
			PKCS8 string          `json:"pkcs8"`
			TPM   json.RawMessage `json:"tpm"`
		} `json:"member"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "keys.json")) // src/own.rs
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Member.PKCS8 != "" || len(f.Member.TPM) == 0 {
		t.Fatalf("keys.json keeps the key %d characters, the TPM blob %q (%v)", len(f.Member.PKCS8), f.Member.TPM, err)
	}
	small := startAloneEnv(t, bin, dir, []string{sim}, "-no-mdns", "-peer", pi.addr())
	waitFor(t, "the Rust member connected", func() bool {
		st, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1
	})
	if _, err := small.do(t, control.Header{Op: control.OpCopy}, "signed in the TPM"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pi has the copy", func() bool { return pi.paste(t) == "signed in the TPM" })

	// The secrets in files the TPM seals too: the local key, under which
	// the sealing keys of each epoch are kept (src/set.rs, src/epochs.rs),
	// and the tunnel key, which a restart opens again.
	if _, err := small.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatalf("cbb global on: %v", err)
	}
	sealed := func(name, plain, blob string) {
		t.Helper()
		var f map[string]json.RawMessage
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || json.Unmarshal(raw, &f) != nil || f[plain] != nil || f[blob] == nil {
			t.Errorf("%s keeps %q in the file or not %q in the TPM (%v):\n%s", name, plain, blob, err, raw)
		}
	}
	sealed("local.json", "secret", "tpm")
	sealed("tunnel.json", "key", "key_tpm")
	small.stop()
	small = startAloneEnv(t, bin, dir, []string{sim}, "-no-mdns", "-peer", pi.addr())
	waitFor(t, "the Rust member connected again with its sealed keys", func() bool {
		st, err := small.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil && st.Status != nil && len(st.Status.Peers) == 1 && st.Status.Away != nil
	})
}
