// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package netid

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestID(t *testing.T) {
	key := []byte("key")
	home := []netip.Prefix{netip.MustParsePrefix("192.168.0.225/24"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("2001:db8:1::5/64")}
	id := ID(key, home, "aa:bb:cc:dd:ee:ff")
	if id == "" || len(id) != 32 {
		t.Fatalf("ID %q", id)
	}
	// Another address on the same network, another IPv6 prefix: the same.
	if got := ID(key, []netip.Prefix{netip.MustParsePrefix("192.168.0.7/24"), netip.MustParsePrefix("2001:db8:2::5/64")}, "aa:bb:cc:dd:ee:ff"); got != id {
		t.Error("the ID changed with the address or the IPv6 prefix")
	}
	// The same subnet behind another gateway (a café's router), another
	// key: different.
	if ID(key, home, "11:22:33:44:55:66") == id || ID([]byte("other"), home, "aa:bb:cc:dd:ee:ff") == id {
		t.Error("another gateway or key gives the same ID")
	}
	if ID(key, []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}, "") != "" {
		t.Error("a link-local address alone names a network")
	}
}

var update = flag.Bool("update", false, "write testdata/interop/go-netid.json")

// netidVectors is testdata/interop/go-netid.json: the IDs ID gives a key
// for some networks, for the Rust service's networks.rs to agree with.
type netidVectors struct {
	Key   []byte `json:"key"`
	Cases []struct {
		Prefixes []string `json:"prefixes"`
		Gateway  string   `json:"gateway"`
		ID       string   `json:"id"`
	} `json:"cases"`
}

// TestIDVectors writes (with -update, under a new random key) and checks
// testdata/interop/go-netid.json.
func TestIDVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-netid.json")
	if *update {
		v := netidVectors{Key: make([]byte, 32)}
		if _, err := rand.Read(v.Key); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			prefixes []string
			gateway  string
		}{
			{[]string{"192.168.0.225/24", "fe80::1/64", "2001:db8:1::5/64"}, "aa:bb:cc:dd:ee:ff"},
			{[]string{"192.168.0.225/24", "fe80::1/64", "2001:db8:1::5/64"}, ""},
			{[]string{"2001:db8:1::5/64", "fd00:1:2:3::9/64"}, ""},
			{[]string{"192.168.0.7/24", "2001:db8:2::5/64"}, "aa:bb:cc:dd:ee:ff"},
			{[]string{"192.168.0.225/24", "fe80::1/64", "2001:db8:1::5/64"}, "11:22:33:44:55:66"},
			{[]string{"fe80::1/64"}, ""},
		} {
			v.Cases = append(v.Cases, struct {
				Prefixes []string `json:"prefixes"`
				Gateway  string   `json:"gateway"`
				ID       string   `json:"id"`
			}{c.prefixes, c.gateway, ID(v.Key, prefixes(c.prefixes), c.gateway)})
		}
		data, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v netidVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) != 6 {
		t.Fatalf("the file has %d cases", len(v.Cases))
	}
	for _, c := range v.Cases {
		if got := ID(v.Key, prefixes(c.Prefixes), c.Gateway); got != c.ID {
			t.Errorf("%v %q: %q, the file says %q", c.Prefixes, c.Gateway, got, c.ID)
		}
	}
}

func prefixes(ss []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}
