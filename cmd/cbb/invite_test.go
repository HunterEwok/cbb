// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/invite"
	"github.com/HunterEwok/cbb/internal/tunnel"
)

// TestPairInvite joins with an invitation as the service takes it: the
// join on the admin socket, the status after it on a connection of its
// own. It was refused on the control socket before. The service's network
// keeps the invitation's addresses until it knows the group's servers;
// an empty status took them away, and the device could reach no hub.
func TestPairInvite(t *testing.T) {
	key := func() tunnel.Key {
		k, err := tunnel.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	in := &invite.Invitation{
		Group: "0f1e2d3c4b5a6978", Hub: "0123456789abcdef0123456789abcdef", HubKey: key().Public(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:8764")},
		GuestKey:  key(), GuestPSK: key(), Secret: bytes.Repeat([]byte{7}, 16),
		Expires: time.Now().Add(time.Hour).Truncate(time.Second),
	}
	old := serverWait
	t.Cleanup(func() { serverWait = old })
	serverWait = 600 * time.Millisecond
	for _, tc := range []struct {
		name  string
		allow []string
		want  []netip.Addr
	}{
		{"servers unknown", nil, []netip.Addr{hubAddr}},
		{"servers known", []string{"198.51.100.9"}, []netip.Addr{fwdAddr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeUnit(t, true)
			path := filepath.Join(t.TempDir(), "invite.cbb")
			if err := os.WriteFile(path, []byte(in.String()+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			got := fakeHandler(t, func(m *control.Message, _ *control.Reader, c net.Conn) {
				switch m.Op {
				case control.OpJoin:
					answer(c, control.Message{Header: control.Header{Fingerprint: "abcd"}})
					answer(c, control.Message{Header: control.Header{Done: true}})
				case control.OpStatus:
					st := &control.Status{Role: "full", Group: in.Group, Away: &control.Away{HubDevice: in.Hub, Allow: tc.allow}}
					answer(c, control.Message{Header: control.Header{Status: st, Done: true}})
				}
			})
			var stdout, stderr bytes.Buffer
			if code := run([]string{"pair", "-invite", path}, strings.NewReader("yes\n"), &stdout, &stderr); code != 0 {
				t.Fatalf("pair -invite: %d, %s", code, stderr.String())
			}
			if m := request(t, got); m.Op != control.OpJoin || m.Invite != in.String() || !m.Consent {
				t.Errorf("pair -invite sent %+v", m.Header)
			}
			if m := request(t, got); m.Op != control.OpStatus {
				t.Errorf("after the join it asked %+v", m.Header)
			}
			if stderr.Len() != 0 || !strings.Contains(stdout.String(), "Joined the group") {
				t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
			}
			if g := linuxLimit.granted(); !g.on || !slices.Equal(g.addrs, tc.want) {
				t.Errorf("the service may reach %v, want %v", g, tc.want)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("the used invitation is still there: %v", err)
			}
		})
	}
}

// TestGlobalOffAway asks before turning sync away from home off on a device
// that reaches its hub only through the tunnel: its new keys would reach
// the hub only at home.
func TestGlobalOffAway(t *testing.T) {
	got := fakeHandler(t, func(m *control.Message, _ *control.Reader, c net.Conn) {
		st := &control.Status{Role: "full", Group: "0f1e2d3c4b5a6978", Away: &control.Away{HubDevice: "deck", Through: true}}
		answer(c, control.Message{Header: control.Header{Status: st, Done: true}})
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"global", "off"}, strings.NewReader("no\n"), &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "only once it is at home") {
		t.Fatalf("off, answered no: %d, %q, %q", code, stdout.String(), stderr.String())
	}
	if m := request(t, got); m.Op != control.OpStatus {
		t.Fatalf("it asked %+v", m.Header)
	}
	select {
	case m := <-got:
		t.Fatalf("it went on with %+v", m.Header)
	default:
	}
	stdout.Reset()
	if code := run([]string{"global", "off", "-yes"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("off -yes: %d, %q", code, stderr.String())
	}
	request(t, got) // its status
	if m := request(t, got); m.Op != control.OpAway || m.Name != "off" {
		t.Errorf("off -yes sent %+v", m.Header)
	}
}
