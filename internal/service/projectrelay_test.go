// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/relay"
	"github.com/HunterEwok/cbb/internal/release"
)

// signRelayKeys signs entry points under a keys.json at keysSeq that
// certifies the given keys as the project's relay's.
func (s *releaseSigner) signRelayKeys(t *testing.T, seq uint64, relays ...relay.Keys) string {
	t.Helper()
	return s.signRelay(t, seq, nil, relays...)
}

// signRelay does the same with the addresses entries.json gives the relay.
func (s *releaseSigner) signRelay(t *testing.T, seq uint64, endpoints []string, relays ...relay.Keys) string {
	t.Helper()
	s.keysSeq = seq
	var set node.EntriesSet
	if err := json.Unmarshal([]byte(s.signEntries(t, seq, "/relay-path-01")), &set); err != nil {
		t.Fatal(err)
	}
	var k release.Keys
	if err := json.Unmarshal(set.Keys.Body, &k); err != nil {
		t.Fatal(err)
	}
	if endpoints != nil {
		var e release.Entries
		if err := json.Unmarshal(set.Entries.Body, &e); err != nil {
			t.Fatal(err)
		}
		e.Relays = []release.EntryRelay{{Name: relay.ProjectHost, Endpoints: endpoints}}
		var err error
		if set.Entries, err = release.Sign(e, s.key); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range relays {
		k.Keys = append(k.Keys, release.Key{Key: r.Cert.Leaf.RawSubjectPublicKeyInfo, Name: relay.ProjectHost, Use: release.UseRelay})
	}
	var err error
	if set.Keys, err = release.Sign(k, s.root); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestProjectRelayNewKey sets a device to the project's relay, whose key
// the signed keys.json gives, then changes the relay's key: once a newer
// keys.json names the new key, the device registers again by itself. Then
// the relay moves, and entries.json says where to.
func TestProjectRelayNewKey(t *testing.T) {
	signer := newReleaseSigner(t)
	var h hub
	pi := startEnv(t, &h, "pi", func(c *Config) {
		c.ReleaseRoots = signer.roots(t)
		c.lookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "relay.example.org" {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return nil, errors.New("tests look up no other names")
		}
	}, signer.rootsEnv(t), "CBB_TEST_RESOLVE=relay.example.org=127.0.0.1")
	deck := startService(t, &h, "deck")
	pairWith(t, pi, deck)
	group := pi.status(t).Group
	serve := func(keys relay.Keys, at string) (*relay.Relay, func()) {
		r, err := relay.Listen(relay.Config{Listen: at, Keys: keys, Groups: []string{group}, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		served := make(chan struct{})
		go func() {
			defer close(served)
			r.Serve(ctx)
		}()
		return r, func() {
			cancel()
			<-served
		}
	}
	oldKeys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := relay.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, stop := serve(oldKeys, "127.0.0.1:0")
	at := r.Addr().String()

	if _, err := pi.do(t, control.Header{Op: control.OpEntries}, signer.signRelayKeys(t, 1, oldKeys)); err != nil {
		t.Fatal(err)
	}
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: at, RelayKey: relay.Project, Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	connected := func() bool {
		a := pi.status(t).Away
		return a != nil && a.Relay != nil && a.Relay.Connected
	}
	waitUpTo(t, 60*time.Second, "the pi registers with the relay's listed key", connected)

	// The relay changes its key; the device refuses the new one until
	// keys.json names it, then takes it without being set again.
	stop()
	_, stop = serve(newKeys, at)
	waitUpTo(t, 60*time.Second, "the pi says the key is unknown", func() bool {
		a := pi.status(t).Away
		return a != nil && a.Relay != nil && !a.Relay.Connected && a.Relay.Error != "" && a.Relay.Detail != ""
	})
	if _, err := pi.do(t, control.Header{Op: control.OpEntries}, signer.signRelayKeys(t, 2, oldKeys, newKeys)); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 90*time.Second, "the pi registers with the new key", connected)
	if a := pi.status(t).Away; a.Relay.Error != "" {
		t.Errorf("an error left in status: %q", a.Relay.Error)
	}

	// It moves to another port under a name of its own.
	stop()
	moved, stop := serve(newKeys, "127.0.0.1:0")
	defer stop()
	_, port, _ := net.SplitHostPort(moved.Addr().String())
	if _, err := pi.do(t, control.Header{Op: control.OpEntries}, signer.signRelay(t, 3, []string{"relay.example.org:" + port}, newKeys)); err != nil {
		t.Fatal(err)
	}
	waitUpTo(t, 90*time.Second, "the pi registers where the relay moved", func() bool {
		a := pi.status(t).Away
		return connected() && a.Relay.Endpoint == moved.Addr().String()
	})
}
