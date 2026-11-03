// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/budget"
	"github.com/HunterEwok/cbb/internal/group"
)

func testVersions(t *testing.T, file string) *versions {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := newVersions(file, k)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func periodOf(tag string, version uint64, expires time.Time) *group.Presented {
	var s group.KeyHash
	rand.Read(s[:])
	return &group.Presented{Tag: tag, Signer: s, Hubs: &group.CredentialBody{Version: version, ExpiresMS: expires.UnixMilli()}}
}

// withVersion is p's period, with another version of the credential.
func withVersion(p *group.Presented, version uint64) *group.Presented {
	q := *p
	q.Hubs = &group.CredentialBody{Version: version, ExpiresMS: p.Hubs.ExpiresMS}
	return &q
}

func nth(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(10 + i>>18), byte(i >> 10), byte(i>>8) & 3, 1})
}

// TestVersionsKeepsGroupsAgainstNewTags checks that registrations with new
// period tags never push out what the table kept for a group: from one
// network only networkTags of them are taken, past the bound of the table
// they are refused, and the group's older credential is refused throughout;
// an entry goes only once its credential has expired.
func TestVersionsKeepsGroupsAgainstNewTags(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	expires := now.Add(group.PeriodLifetime)
	victim := periodOf("victim", 5, expires)
	genuine := netip.MustParseAddr("192.0.2.7")
	if err := v.check(victim, genuine); err != nil {
		t.Fatal(err)
	}
	if err := v.keep(victim, genuine); err != nil {
		t.Fatal(err)
	}

	// One network floods fresh tags.
	flood := netip.MustParseAddr("198.51.100.9")
	taken := 0
	for i := 0; i < 2*networkTags; i++ {
		p := periodOf(fmt.Sprintf("flood-%d", i), 1, expires)
		if v.check(p, flood) == nil {
			if err := v.keep(p, flood); err != nil {
				t.Fatal(err)
			}
			taken++
		} else if err := v.keep(p, flood); !errors.Is(err, errTableFull) {
			t.Fatalf("keep past the network's share: %v", err)
		}
	}
	if taken != networkTags {
		t.Fatalf("the flooding network added %d entries, want %d", taken, networkTags)
	}
	// Other networks fill the table to its bound.
	for i := 0; len(v.entries) < rememberedGroups; i++ {
		p := periodOf(fmt.Sprintf("n-%d", i), 1, expires)
		if err := v.keep(p, nth(i+1)); err != nil {
			t.Fatalf("keep %d: %v", i, err)
		}
	}
	if err := v.check(periodOf("one-more", 1, expires), nth(1<<20)); !errors.Is(err, errTableFull) {
		t.Fatalf("a new tag in a full table: %v, want refused", err)
	}
	if got := len(v.entries); got != rememberedGroups {
		t.Fatalf("table size %d, want %d", got, rememberedGroups)
	}
	// The group's entry is still there: its older credential is refused, a
	// newer one and a renewal of the same are taken.
	if err := v.check(withVersion(victim, 4), genuine); err == nil {
		t.Fatal("an older credential of the group was accepted")
	}
	if err := v.check(withVersion(victim, 6), genuine); err != nil {
		t.Fatalf("a newer credential of the group: %v", err)
	}
	if err := v.keep(withVersion(victim, 6), genuine); err != nil {
		t.Fatalf("keeping a newer credential in a full table: %v", err)
	}
	// Once the credentials have expired the room is free again.
	now = expires.Add(time.Hour)
	p := periodOf("after", 1, now.Add(time.Hour))
	if err := v.check(p, flood); err != nil {
		t.Fatalf("a new tag once the entries expired: %v", err)
	}
	if err := v.keep(p, flood); err != nil {
		t.Fatal(err)
	}
	if len(v.entries) != 1 || v.nets.Held(flood, budget.Network) != 1 || v.nets.Held(flood, budget.All) != 1 {
		t.Fatalf("after expiry the table holds %d entries, counted as\n%s\nwant 1 of the flooding network", len(v.entries), v.nets)
	}
}

// TestVersionsKeepsTheLongestExpiry checks that an entry outlasts every
// credential recorded for it, not only the newest.
func TestVersionsKeepsTheLongestExpiry(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	a := netip.MustParseAddr("192.0.2.7")
	p := periodOf("p", 1, now.Add(48*time.Hour))
	if err := v.keep(p, a); err != nil {
		t.Fatal(err)
	}
	if err := v.keep(withVersion(&group.Presented{Tag: "p", Signer: p.Signer, Hubs: &group.CredentialBody{ExpiresMS: now.Add(time.Hour).UnixMilli()}}, 2), a); err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	v.pruneLocked()
	if err := v.check(withVersion(p, 1), a); err == nil {
		t.Fatal("the entry was forgotten before its longest credential expired")
	}
}

// TestVersionsBoundsAnEntrysLife checks that a credential claiming to last
// longer than a period holds its entry no longer than a period.
func TestVersionsBoundsAnEntrysLife(t *testing.T) {
	v := testVersions(t, "")
	now := time.Now()
	v.now = func() time.Time { return now }
	if err := v.keep(periodOf("far", 1, now.AddDate(100, 0, 0)), netip.MustParseAddr("192.0.2.7")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(group.PeriodLifetime + time.Hour)
	v.mu.Lock()
	v.pruneLocked()
	n := len(v.entries)
	v.mu.Unlock()
	if n != 0 {
		t.Errorf("an entry outlasts a period: %d left", n)
	}
}

// TestVersionsWriteLeavesTheLock checks that keeping a credential does not
// write the file, that the file follows within the delay and when the table
// is flushed, and that what was written is read back.
func TestVersionsWriteLeavesTheLock(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json")
	v := testVersions(t, file)
	v.delay = 50 * time.Millisecond
	a := netip.MustParseAddr("192.0.2.7")
	p := periodOf("p", 3, time.Now().Add(time.Hour))
	if err := v.keep(p, a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("keep wrote the file at once")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(file); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the file was not written within the delay")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A change right before the end is written by flush.
	q := periodOf("q", 1, time.Now().Add(time.Hour))
	v.delay = time.Hour
	if err := v.keep(q, a); err != nil {
		t.Fatal(err)
	}
	if err := v.flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]versionEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[v.hash([]byte("p"))].Version != 3 || got[v.hash([]byte("q"))].Expires == 0 {
		t.Fatalf("the file holds %v", got)
	}

}
