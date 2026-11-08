// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/release"
)

// signEntries signs entry points with seq whose ways in to the project's
// forwarder are at path, under the signer's keys.json.
func (s *releaseSigner) signEntries(t *testing.T, seq uint64, path string) string {
	t.Helper()
	key, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute).UnixMilli()
	life := (30 * 24 * time.Hour).Milliseconds()
	keys, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: max(s.keysSeq, 1), TimeMS: at, ExpiresMS: at + life,
		Keys: []release.Key{{Key: key, Name: "test"}}}, s.root)
	if err != nil {
		t.Fatal(err)
	}
	e, err := release.Sign(release.Entries{V: 1, Type: release.TypeEntries, Seq: seq, TimeMS: at, ExpiresMS: at + life,
		Forwarders: []release.EntryForwarder{{Name: forward.ProjectHost,
			VLESS: []release.EntryVLESS{{Transport: "xhttp", ServerName: "cbb.tools", Port: 8443, Path: path}}}}}, s.key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(node.EntriesSet{Keys: keys, Entries: e})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestEntriesSpread hands signed entry points to one member, as cbb update
// does: the other gets them, takes no older or forged ones, and a hub of
// the project's forwarder registers over VLESS through them.
func TestEntriesSpread(t *testing.T) {
	signer := newReleaseSigner(t)
	var h hub
	pi := startEnv(t, &h, "pi", signer.rootsEnv(t))
	pc := startEnv(t, &h, "pc", signer.rootsEnv(t))
	pairWith(t, pi, pc)
	waitFor(t, "pc is connected", func() bool { return len(pi.status(t).Peers) == 1 })

	if _, err := pi.do(t, control.Header{Op: control.OpEntries}, signer.signEntries(t, 2, "/second-path-1")); err != nil {
		t.Fatal(err)
	}
	held := func(s *testService) uint64 {
		m, err := s.do(t, control.Header{Op: control.OpEntriesGet}, "")
		if err != nil {
			return 0
		}
		var set node.EntriesSet
		var e release.Entries
		if json.Unmarshal(m.Payload, &set) != nil || json.Unmarshal(set.Entries.Body, &e) != nil {
			return 0
		}
		return e.Seq
	}
	waitFor(t, "pc holds the entry points", func() bool { return held(pc) == 2 })
	if _, err := pc.do(t, control.Header{Op: control.OpEntries}, signer.signEntries(t, 1, "/first-path-01")); err == nil || held(pc) != 2 {
		t.Error("pc took older entry points")
	}
	other := newReleaseSigner(t)
	if _, err := pc.do(t, control.Header{Op: control.OpEntries}, other.signEntries(t, 3, "/forged-path-1")); err == nil {
		t.Error("pc took entry points signed under other roots")
	}
}

// TestLiteEntries: a lite member takes the signed entry points a computer
// passes it, keeps them and says in its hello that it holds them, so the
// computer does not send them again.
func TestLiteEntries(t *testing.T) {
	bin := os.Getenv("CBB_LITE")
	if bin == "" {
		t.Skip("CBB_LITE is not set")
	}
	signer := newReleaseSigner(t)
	var h hub
	pi := startEnv(t, &h, "pi", signer.rootsEnv(t))
	dir := joinLite(t, bin, pi)
	pemFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: signer.roots(t)[0]}), 0o644); err != nil {
		t.Fatal(err)
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	lite := startLiteEnv(t, bin, dir, []string{"CBB_RELEASE_ROOTS=" + pemFile}, "-no-mdns", "-port", strconv.Itoa(port), "-peer", pi.addr())
	waitFor(t, "the lite member answers", func() bool {
		_, err := lite.do(t, control.Header{Op: control.OpStatus}, "")
		return err == nil
	})
	waitFor(t, "the lite member connected", func() bool { return len(lite.status(t).Peers) == 1 })
	if _, err := pi.do(t, control.Header{Op: control.OpEntries}, signer.signEntries(t, 2, "/second-path-1")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the lite member keeps the entry points", func() bool {
		data, err := os.ReadFile(filepath.Join(dir, "entries.json"))
		var set node.EntriesSet
		var e release.Entries
		return err == nil && json.Unmarshal(data, &set) == nil && json.Unmarshal(set.Entries.Body, &e) == nil && e.Seq == 2
	})
	// It writes the file before the line reaches its log, which can come
	// later under emulation.
	waitFor(t, "the lite member logs the entry points it took", func() bool { return lite.logged("took newer entry points") })
	// Forged ones it drops.
	other := newReleaseSigner(t)
	if _, err := pi.do(t, control.Header{Op: control.OpEntries}, other.signEntries(t, 3, "/forged-path-1")); err == nil {
		t.Error("pi took entry points signed under other roots")
	}
}
