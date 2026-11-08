// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// unconfined makes this computer one without a limit on the service's
// network and without a hub firewall to change, whatever the system the
// test runs on has.
func unconfined(t *testing.T) {
	t.Helper()
	oldLimit, oldFW := limit, hubFW
	t.Cleanup(func() { limit, hubFW = oldLimit, oldFW })
	limit, hubFW = nil, nil
}

func TestWriteAwayStates(t *testing.T) {
	unconfined(t)
	for _, c := range []struct {
		name  string
		debug string
		a     control.Away
		want  []string
		not   []string
	}{
		{name: "a hub reached directly", a: control.Away{Hub: true, Port: 8764, Clients: 3, Obfuscated: true, Endpoints: []string{"203.0.113.7:8764"}},
			want: []string{"this device is the hub, on UDP port 8764, for 3 devices.", "Obfuscated", "Reached at 203.0.113.7:8764.", "forward UDP port 8764"}},
		{name: "a hub without an address", a: control.Away{Hub: true, Port: 8764},
			want: []string{"The hub has no address away from home"}},
		{name: "registered, port seen", a: control.Away{Hub: true, Port: 8764, VLESS: true, Forwarder: &control.Forwarder{Endpoint: "198.51.100.9:8764", Registered: true, Seen: "203.0.113.7:40000"}},
			want: []string{"reach the forwarder over VLESS, which looks like HTTPS", "Registered with the forwarder at 198.51.100.9:8764, which reaches this hub at 203.0.113.7:40000."},
			not:  []string{"tunnel goes inside VLESS"}},
		{name: "registered, port not heard", a: control.Away{Hub: true, Forwarder: &control.Forwarder{Endpoint: "f:1", Registered: true}},
			want: []string{"it has not heard the hub's UDP port yet"}},
		{name: "registering", a: control.Away{Hub: true, Forwarder: &control.Forwarder{Endpoint: "f:1"}},
			want: []string{"Registering with the forwarder at f:1."}},
		{name: "not registered, release", debug: "0", a: control.Away{Hub: true, Forwarder: &control.Forwarder{Endpoint: "f:1", Error: "the forwarder refused the group", Detail: "tls: bad certificate"}},
			want: []string{"Not registered with the forwarder at f:1: the forwarder refused the group."}, not: []string{"bad certificate"}},
		{name: "not registered, debug", debug: "1", a: control.Away{Hub: true, Forwarder: &control.Forwarder{Endpoint: "f:1", Error: "the forwarder refused the group", Detail: "tls: bad certificate"}},
			want: []string{"Detail: tls: bad certificate"}},
		{name: "a standby hub looking", a: control.Away{Hub: true, Standby: true},
			want: []string{"It looks for the hubs above it, and serves if none answers."}},
		{name: "relay, through", a: control.Away{Through: true, Relay: &control.Relay{Endpoint: "r:1", Connected: true, Online: []string{"a"}}},
			want: []string{"connected to the relay at r:1 and through it to other devices."}},
		{name: "relay, alone", a: control.Away{Relay: &control.Relay{Endpoint: "r:1", Connected: true}},
			want: []string{"no other device of the group is there now."}},
		{name: "relay, with others", a: control.Away{Relay: &control.Relay{Endpoint: "r:1", Connected: true, Online: []string{"a", "b"}}},
			want: []string{"with 2 other devices of the group there."}},
		{name: "relay, connecting", a: control.Away{Relay: &control.Relay{Endpoint: "r:1"}},
			want: []string{"connecting to the relay at r:1."}},
		{name: "relay, failed, debug", debug: "1", a: control.Away{Relay: &control.Relay{Endpoint: "r:1", Error: "the relay is full", Detail: "quota"}},
			want: []string{"not connected to the relay at r:1: the relay is full.", "Detail: quota"}},
		{name: "relay, failed, release", debug: "0", a: control.Away{Relay: &control.Relay{Endpoint: "r:1", Error: "the relay is full", Detail: "quota"}},
			not: []string{"quota"}},
		{name: "waiting for the hub", a: control.Away{}, want: []string{"waiting to meet the group's hub on the home network"}},
		{name: "through the tunnel", a: control.Away{HubDevice: "deck", Through: true}, want: []string{"connected to the hub deck through the tunnel."}},
		{name: "over VLESS", a: control.Away{HubDevice: "deck", VLESS: true},
			want: []string{"reached over VLESS through its forwarder", "the tunnel goes inside VLESS"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("CBB_DEBUG", c.debug)
			var b strings.Builder
			writeAway(&b, &c.a)
			for _, w := range c.want {
				if !strings.Contains(b.String(), w) {
					t.Errorf("no %q in %q", w, b.String())
				}
			}
			for _, w := range c.not {
				if strings.Contains(b.String(), w) {
					t.Errorf("%q in %q", w, b.String())
				}
			}
		})
	}
}

func TestGlobalCommand(t *testing.T) {
	unconfined(t)
	inGroup := func(a *control.Away) control.Header {
		return control.Header{Status: &control.Status{Role: "member", OS: "linux", Group: "g", Away: a}}
	}
	lookup := lookupNetIP
	t.Cleanup(func() { lookupNetIP = lookup })
	lookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "cbb.tools" {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("2001:db8::20"), netip.MustParseAddr("198.51.100.20")}, nil
	}
	project := func(m *control.Message) bool {
		return m.Forwarder == "198.51.100.20:8764" && m.ForwarderKey == "default" && len(m.Addrs) == 0
	}
	runCommandCases(t, []commandCase{
		{name: "status", args: []string{"global"}, answer: inGroup(&control.Away{HubDevice: "deck", Through: true}), check: sent(control.OpStatus, nil), stdout: "connected to the hub deck"},
		{name: "status off", args: []string{"global"}, answer: inGroup(nil), check: sent(control.OpStatus, nil), stdout: "Sync away from home: off"},
		{name: "status in no group", args: []string{"global"}, answer: control.Header{Status: &control.Status{}}, check: sent(control.OpStatus, nil), code: 1, stderr: "in no group"},
		{name: "on, declined", args: []string{"global", "on"}, stdin: "no\n", code: 1, stdout: "Nothing changed."},
		{name: "on", args: []string{"global", "on"}, stdin: "yes\n", answer: inGroup(&control.Away{}),
			check: sent(control.OpAway, func(m *control.Message) bool { return m.Name == "on" && m.Consent }), stdout: "waiting to meet the group's hub"},
		{name: "off elsewhere", args: []string{"global", "off", "-on", "tv"},
			check: sent(control.OpAway, func(m *control.Message) bool { return m.Name == "off" && m.Device == "tv" })},
		{name: "hub", args: []string{"global", "hub", "-port", "9000", "-firewall", "no", "-obfuscate", "203.0.113.7:9000"},
			answer: inGroup(&control.Away{Hub: true, Port: 9000, Endpoints: []string{"203.0.113.7:9000"}}),
			check: sent(control.OpAway, func(m *control.Message) bool {
				return m.Name == "hub" && m.Port == 9000 && m.Obfuscate && strings.Join(m.Addrs, ",") == "203.0.113.7:9000"
			}),
			stdout: "The hub does not have to stay on."},
		{name: "hub through a forwarder", args: []string{"global", "hub", "-forwarder", "198.51.100.9:8764", "-forwarder-key", "KEY", "-vless"},
			check: sent(control.OpAway, func(m *control.Message) bool {
				return m.Forwarder == "198.51.100.9:8764" && m.ForwarderKey == "KEY" && m.VLESS && len(m.Addrs) == 0
			})},
		{name: "hub without an address goes through the project's forwarder", args: []string{"global", "hub"},
			check: sent(control.OpAway, project), stdout: "cbb.tools is at 198.51.100.20:8764."},
		{name: "hub through the project's forwarder", args: []string{"global", "hub", "-forwarder", "default", "-vless"},
			check: sent(control.OpAway, func(m *control.Message) bool { return project(m) && m.VLESS })},
		{name: "the project's forwarder takes no key", args: []string{"global", "hub", "-forwarder", "default", "-forwarder-key", "K"},
			code: 1, stderr: "takes no -forwarder-key"},
		{name: "default is no key of another forwarder", args: []string{"global", "hub", "-forwarder", "198.51.100.9:8764", "-forwarder-key", "default"},
			code: 1, stderr: "goes with -forwarder default"},
		{name: "hub with sync away from home, declined", args: []string{"global", "hub", "-away-on"}, stdin: "no\n", code: 1, stdout: "Nothing changed."},
		{name: "hub with sync away from home", args: []string{"global", "hub", "-away-on", "-firewall", "no"}, stdin: "yes\n",
			answer: inGroup(&control.Away{Hub: true}),
			check:  sent(control.OpAway, func(m *control.Message) bool { return m.Name == "hub" && m.Consent && project(m) })},
		{name: "hub off", args: []string{"global", "hub", "off"}, answer: inGroup(&control.Away{}),
			check:  sent(control.OpAway, func(m *control.Message) bool { return m.Name == "hub-off" && m.Device == "" && !m.Force }),
			stdout: "no hub of the group any more"},
		{name: "hub off anyway elsewhere", args: []string{"global", "hub", "off", "-on", "desk", "-yes"},
			check:  sent(control.OpAway, func(m *control.Message) bool { return m.Name == "hub-off" && m.Device == "desk" && m.Force }),
			stdout: "desk is no hub of the group any more."},
		{name: "hub off takes no address", args: []string{"global", "hub", "off", "203.0.113.8:8764"}, code: 2},
		{name: "hub elsewhere", args: []string{"global", "hub", "-on", "desk"},
			check: sent(control.OpAway, func(m *control.Message) bool { return m.Device == "desk" && project(m) }), stdout: "desk is a hub of the group now."},
		{name: "hub elsewhere at an address", args: []string{"global", "hub", "-on", "desk", "203.0.113.8:8764"},
			check: sent(control.OpAway, func(m *control.Message) bool {
				return m.Name == "hub" && m.Device == "desk" && m.Forwarder == "" && strings.Join(m.Addrs, ",") == "203.0.113.8:8764"
			})},
		{name: "hub elsewhere takes none of this hub's settings", args: []string{"global", "hub", "-on", "desk", "-obfuscate"}, code: 2, stderr: "-on takes only"},
		{name: "hub keeps its settings", args: []string{"global", "hub", "-keep", "-obfuscate"},
			check: sent(control.OpAway, func(m *control.Message) bool {
				return m.Name == "hub" && m.Keep && m.Obfuscate && m.Forwarder == "" && len(m.Addrs) == 0
			})},
		{name: "-keep is for this hub", args: []string{"global", "hub", "-on", "desk", "-keep"}, code: 2, stderr: "-keep changes this hub"},
		{name: "hub with a strange firewall", args: []string{"global", "hub", "-firewall", "maybe", "a:1"}, code: 2},
		{name: "move", args: []string{"global", "move", "desk", "203.0.113.8:8764"},
			check: sent(control.OpAway, func(m *control.Message) bool {
				return m.Device == "desk" && strings.Join(m.Addrs, ",") == "203.0.113.8:8764"
			})},
		{name: "move to the project's forwarder", args: []string{"global", "move", "desk", "-forwarder", "default"},
			check: sent(control.OpAway, func(m *control.Message) bool { return m.Device == "desk" && project(m) })},
		{name: "move without a device", args: []string{"global", "move", "-forwarder", "x:1"}, code: 2},
		{name: "relay, declined", args: []string{"global", "relay", "198.51.100.9:8765", "-key", "K"}, stdin: "no\n",
			answer: inGroup(&control.Away{}), check: sent(control.OpStatus, nil), code: 1, stdout: "A blind relay is a meeting point"},
		{name: "relay", args: []string{"global", "relay", "-key", "K", "-yes", "198.51.100.9:8765"},
			check: sent(control.OpAway, func(m *control.Message) bool { return m.Relay == "198.51.100.9:8765" && m.RelayKey == "K" && m.Consent })},
		{name: "relay without a key", args: []string{"global", "relay", "198.51.100.9:8765"}, code: 2},
		{name: "the project's relay takes no key", args: []string{"global", "relay", "default", "-key", "K"}, code: 2, stderr: "takes no -key"},
		{name: "the project's relay", args: []string{"global", "relay", "default", "-yes"},
			check: sent(control.OpAway, func(m *control.Message) bool {
				return m.Relay == "198.51.100.20:8765" && m.RelayKey == "default" && m.Consent
			})},
		{name: "default is no key of another relay", args: []string{"global", "relay", "198.51.100.9:8765", "-key", "default"}, code: 2, stderr: "goes with the project's relay"},
		{name: "allow without a limit", args: []string{"global", "allow"}, answer: inGroup(nil), check: sent(control.OpStatus, nil), stdout: "has no limit outside the program"},
		{name: "allow with an argument", args: []string{"global", "allow", "x"}, code: 2},
		{name: "on with an argument", args: []string{"global", "on", "x"}, code: 2},
		{name: "refused", args: []string{"global", "on"}, stdin: "yes\n", answer: control.Header{Error: "this device is in no group"}, check: sent(control.OpAway, nil), code: 1, stderr: "in no group"},
		{name: "unknown", args: []string{"global", "sideways"}, code: 2, stderr: "usage: cbb global"},
	})
}
