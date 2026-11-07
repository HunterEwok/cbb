// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// The front takes the client's address from the web server in front only
// when the request comes from the loopback, as from that web server.
func TestFrontClientAddress(t *testing.T) {
	for _, c := range []struct {
		remote, header, want string
	}{
		{"127.0.0.1:4000", "203.0.113.7", "203.0.113.7"},
		{"[::1]:4000", "2001:db8::7", "2001:db8::7"},
		{"127.0.0.1:4000", "", "127.0.0.1"},
		{"127.0.0.1:4000", "not an address", "127.0.0.1"},
		{"198.51.100.2:4000", "203.0.113.7", "198.51.100.2"},
		{"[::ffff:198.51.100.2]:4000", "", "198.51.100.2"},
	} {
		r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
		if c.header != "" {
			r.Header.Set(FromHeader, c.header)
		}
		if got := clientOf(r); got != netip.MustParseAddr(c.want) {
			t.Errorf("from %s naming %q: %v, want %s", c.remote, c.header, got, c.want)
		}
	}
}

// An upload to a session that no download has opened pays from its
// source's uploads and from all sources' together; one to a session whose
// download is open, which reads it at once, pays nothing
// (docs/relay-budget.md, "XHTTP").
func TestFrontUploadsPayBySource(t *testing.T) {
	f := &front{}
	now := time.Now()
	taken := func(from netip.Addr, session string, n int) int {
		got := 0
		for i := range n {
			if f.mayUpload(fmt.Sprintf("r/%s%d", session, i), from, now) {
				got++
			}
		}
		return got
	}
	one := netip.MustParseAddr("198.51.100.1")
	if got := taken(one, "a", 1000); got != int(uploadRates[0].Burst) {
		t.Errorf("one address took %d uploads, want %v", got, uploadRates[0].Burst)
	}
	// Another address of its IPv6 /64 pays from the same network.
	if got := taken(netip.MustParseAddr("2001:db8:1:1::1"), "b", 1000) + taken(netip.MustParseAddr("2001:db8:1:1::2"), "c", 1000); got != int(uploadRates[1].Burst) {
		t.Errorf("one network took %d uploads, want %v", got, uploadRates[1].Burst)
	}
	// Sources in many wide networks together take no more than all
	// sources' share.
	total := int(uploadRates[0].Burst + uploadRates[1].Burst)
	for i := range 64 {
		total += taken(netip.AddrFrom4([4]byte{10, byte(i), 0, 1}), "d", 1000)
	}
	if total != int(uploadsAll.Burst) {
		t.Errorf("all sources took %d uploads, want %v", total, uploadsAll.Burst)
	}
	// A session whose download is open still takes its uploads.
	f.opened("r/open", 1)
	for range 100 {
		if !f.mayUpload("r/open", one, now) {
			t.Fatal("an upload to a session with its download open was refused")
		}
	}
	f.opened("r/open", -1)
	if f.mayUpload("r/open", one, now) {
		t.Error("an upload to a closed session passed with nothing left")
	}
	// The units come back with time.
	if !f.mayUpload("r/later", one, now.Add(10*time.Second)) {
		t.Error("an upload was refused after the source had waited")
	}
}
