// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/attest"
	"github.com/HunterEwok/cbb/internal/attest/attesttest"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/release"
)

// TestFFIPhoneAttest: a root phone whose app signs through the core keeps
// the evidence an Android peer sends, records what it proves when its app
// hands it the root key (manage action attest), takes the revocation list
// its app fetched, and records the peer's keys as only in hardware once
// the list revokes the chain's attestation key (docs/protocol.md, section
// 17).
func TestFFIPhoneAttest(t *testing.T) {
	if os.Getenv("CBB_PHONE_ON_LINUX") == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	// The release root that signs the list's keys, and the attestation
	// roots in place of Google's.
	dir := t.TempDir()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	statusKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootSPKI, _ := x509.MarshalPKIXPublicKey(&rootKey.PublicKey)
	statusSPKI, _ := x509.MarshalPKIXPublicKey(&statusKey.PublicKey)
	releaseRoots := filepath.Join(dir, "release-roots.pem")
	if err := os.WriteFile(releaseRoots, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rootSPKI}), 0o644); err != nil {
		t.Fatal(err)
	}
	attestRoots := filepath.Join(dir, "attest-roots.pem")
	t.Setenv("CBB_RELEASE_ROOTS", releaseRoots)
	t.Setenv("CBB_TEST_ATTEST_ROOTS", attestRoots)

	var h hub
	next, in, _, laptop, _, laptopID := rootPhoneWithLaptop(t, &h)
	call := phoneCall(t, next, in)
	laptop.stop()
	id := mustLoad(t, laptop.dir)

	salt := make([]byte, 16)
	challenge, _ := attest.Challenge("", nil, salt)
	chain, root, err := attesttest.Android(id.Cert.PublicKey, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attestRoots, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: root}), 0o644); err != nil {
		t.Fatal(err)
	}

	// The laptop's identity plays an Android phone that the phone dials and
	// that sends its evidence after the hellos.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		c := tls.Server(raw, id.ServerTLS(group.TLSOptions{}))
		if err := c.Handshake(); err != nil {
			t.Logf("the fake phone's handshake: %v", err)
			return
		}
		send := func(m map[string]any) {
			data, _ := json.Marshal(m)
			c.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(data))), data...))
		}
		send(map[string]any{"t": "hello", "role": "phone", "hello": map[string]any{"wall_ms": time.Now().UnixMilli()}})
		send(map[string]any{"t": "evidence", "evidence": map[string]any{"format": "android-key", "key": "member", "salt": salt, "chain": chain}})
		io.Copy(io.Discard, c)
	}()
	call("found", map[string]any{"key": "android", "addrs": []string{ln.Addr().String()}})
	waitFor(t, "the phone keeps the evidence", func() bool { return call("attest", nil)["pending"] == float64(1) })
	fmt.Fprintln(in, `MANAGE {"action":"attest"}`)
	if got := next("MANAGED "); got != `{"ok":{"pending":0,"recorded":1}}` {
		t.Fatalf("recording the attestation: %s", got)
	}
	ln.Close()

	// The real laptop takes the records and shows its keys proven.
	laptop = restartService(t, &h, laptop)
	call("found", map[string]any{"key": "laptop", "addrs": []string{laptop.addr()}})
	store := func() string {
		for _, d := range laptop.devices(t) {
			if d.ID == laptopID {
				return d.Store
			}
		}
		return ""
	}
	waitUpTo(t, 30*time.Second, "the laptop's keys are proven", func() bool { return store() == group.StoreProven })

	// The list revokes the chain's attestation key.
	ca, err := x509.ParseCertificate(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	keys, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: now, ExpiresMS: now + 3600_000,
		Keys: []release.Key{{Key: statusSPKI, Name: "status", Use: release.UseStatus}}}, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	status, err := release.Sign(release.Status{V: 1, Type: release.TypeStatus, Seq: 1, TimeMS: now, ExpiresMS: now + 3600_000,
		AndroidRevoked: []string{ca.SerialNumber.Text(16)}}, statusKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := call("attest_status", map[string]any{"keys": keys, "status": status}); got["revoked"] != float64(1) || got["pending"] != float64(1) {
		t.Fatalf("taking the list: %v", got)
	}
	fmt.Fprintln(in, `MANAGE {"action":"attest"}`)
	if got := next("MANAGED "); got != `{"ok":{"pending":0,"recorded":1}}` {
		t.Fatalf("recording the revoked attestation: %s", got)
	}
	waitUpTo(t, 30*time.Second, "the laptop's keys are only in hardware", func() bool { return store() == group.StoreHardware })
}
