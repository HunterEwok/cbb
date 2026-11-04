// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"testing"

	"github.com/HunterEwok/cbb/internal/netguard"
)

// TestHubDialsItsForwarder: a hub without Allowed, as a phone's, which
// keeps no list of the group's servers, reaches its forwarder at a public
// address and nothing else; the service's netguard.Allowed still decides
// for a computer.
func TestHubDialsItsForwarder(t *testing.T) {
	netguard.Set(false, nil)
	t.Cleanup(func() { netguard.Set(false, nil) })
	fw := netip.MustParseAddrPort("203.0.113.10:8764")
	phone := HubConfig{Link: Link{Endpoint: fw}}.control()
	if err := phone("tcp4", fw.String(), nil); err != nil {
		t.Fatalf("a phone's hub may not dial its forwarder: %v", err)
	}
	if err := phone("tcp6", "[::ffff:203.0.113.10]:8764", nil); err != nil {
		t.Fatalf("a phone's hub may not dial its forwarder as a mapped address: %v", err)
	}
	for _, to := range []string{"203.0.113.11:8764", "1.1.1.1:443", "[2001:db8::1]:8764", "not an address"} {
		if err := phone("tcp", to, nil); !errors.Is(err, netguard.ErrOutside) {
			t.Errorf("a phone's hub dials %s: %v", to, err)
		}
	}

	computer := HubConfig{Link: Link{Endpoint: fw}, Allowed: netguard.Allowed}.control()
	if err := computer("tcp4", fw.String(), nil); !errors.Is(err, netguard.ErrOutside) {
		t.Errorf("a computer's hub dials its forwarder with sync away from home off: %v", err)
	}
	netguard.Set(true, []netip.Addr{fw.Addr()})
	if err := computer("tcp4", fw.String(), nil); err != nil {
		t.Errorf("a computer's hub may not dial its forwarder with sync away from home on: %v", err)
	}
}

// TestHubRegistrationRefused: the registration dials through Allowed, and
// its refusal is the one reported.
func TestHubRegistrationRefused(t *testing.T) {
	cfg := HubConfig{
		Link:    Link{Endpoint: netip.MustParseAddrPort("127.0.0.1:9")},
		Cert:    func() tls.Certificate { return tls.Certificate{} },
		Allowed: func(netip.Addr) bool { return false },
	}
	if err := registerOnce(context.Background(), cfg, func(Report) {}); !errors.Is(err, netguard.ErrOutside) {
		t.Fatalf("registration: %v, want the address refused", err)
	}
}
