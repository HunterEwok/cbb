// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/refused"
)

// TestRefusedGroupsList: an open relay refuses a group on the operator's
// list, drops the devices of one put on it, takes back one taken off it,
// and serves every other group all the while (docs/relay-budget.md,
// "Abuse reports").
func TestRefusedGroupsList(t *testing.T) {
	ga, gb := newGroup(t), newGroup(t)
	tagA, tagB := group.Tag(ga.Cert), group.Tag(gb.Cert)
	path := filepath.Join(t.TempDir(), "refused-groups")
	write := func(s string, age time.Duration) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		mt := time.Now().Add(-age)
		if err := os.Chtimes(path, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	write(tagA+" reported 2026-11-09\n", 2*time.Minute)
	list, err := refused.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r, link := startWith(t, Config{Open: true, Refused: list})
	reg := func(d device) (*tls.Conn, error) {
		tc, _, _, err := register(context.Background(), MemberConfig{Link: link, Key: d.key, Cert: func() tls.Certificate { return d.cert }})
		if err == nil {
			t.Cleanup(func() { tc.Close() })
		}
		return tc, err
	}

	if _, err := reg(newDevice(t, ga)); err == nil || !strings.Contains(err.Error(), refused.Message) {
		t.Fatalf("a refused group: %v", err)
	}
	tcB, err := reg(newDevice(t, gb))
	if err != nil {
		t.Fatalf("another group: %v", err)
	}

	write(tagB+"\n", time.Minute)
	r.reloadRefused()
	tcB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tcB.Read(make([]byte, 1)); err == nil {
		t.Fatal("a group put on the list keeps its registration")
	}
	waitFor(t, "the refused group dropped", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.groups[tagB] == nil
	})
	if _, err := reg(newDevice(t, ga)); err != nil {
		t.Fatalf("a group taken off the list: %v", err)
	}
	if g, n := r.Stats(); g != 1 || n != 1 {
		t.Fatalf("the relay holds %d groups and %d devices, want 1 and 1", g, n)
	}
}
