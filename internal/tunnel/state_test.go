// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tunnel

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

func pubKey(t *testing.T) Key {
	t.Helper()
	k, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.Public()
}

func TestLoadStateMakesAKey(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Key.IsZero() {
		t.Fatal("no key")
	}
	fi, err := os.Stat(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("the state file has mode %v", fi.Mode().Perm())
	}
	again, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Key != s.Key {
		t.Error("the key changed between loads")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	s.Group = "0f1e2d3c4b5a6978"
	s.IsHub = true
	s.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:8764"), netip.MustParseAddrPort("192.0.2.1:8764")}
	if s.Obfuscation, err = NewObfuscation(); err != nil {
		t.Fatal(err)
	}
	a := newDevice(t)
	if _, _, err := s.Admit(a.id, pubKey(t), Key{}, [][]byte{[]byte("cert")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != s.Key || got.Group != s.Group || !got.IsHub || len(got.Endpoints) != 2 || got.Endpoints[0] != s.Endpoints[0] ||
		!got.Obfuscation.Equal(s.Obfuscation) {
		t.Errorf("loaded %+v, saved %+v", got, s)
	}
	if len(got.Members) != 1 || got.Members[0].PublicKey != s.Members[0].PublicKey ||
		got.Members[0].PresharedKey != s.Members[0].PresharedKey || string(got.Members[0].Chain[0]) != "cert" {
		t.Errorf("loaded members %+v, saved %+v", got.Members, s.Members)
	}

	// A client's side.
	c, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	hub := newDevice(t)
	link := HubLink{Device: hub.id, PublicKey: hub.priv.Public(), PresharedKey: a.psk, Endpoints: s.Endpoints, Obfuscation: s.Obfuscation}
	if _, err := c.SetHub(link); err != nil {
		t.Fatal(err)
	}
	cdir := t.TempDir()
	if err := c.Save(cdir); err != nil {
		t.Fatal(err)
	}
	gotC, err := LoadState(cdir)
	if err != nil {
		t.Fatal(err)
	}
	if h := gotC.Hub(hub.id); h == nil || h.Device != hub.id || h.PublicKey != link.PublicKey || h.PresharedKey != link.PresharedKey || len(h.Endpoints) != 2 ||
		!h.Obfuscation.Equal(link.Obfuscation) {
		t.Errorf("loaded hub %+v, saved %+v", h, link)
	}
	if gotC.PSK != c.PSK || c.PSK.IsZero() {
		t.Error("the client's own preshared key did not load")
	}

	// A device that meets the others at a relay.
	r, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	r.Relay = &RelayLink{Endpoint: netip.MustParseAddrPort("198.51.100.9:8764"), Pin: "AAAA"}
	rdir := t.TempDir()
	if err := r.Save(rdir); err != nil {
		t.Fatal(err)
	}
	gotR, err := LoadState(rdir)
	if err != nil {
		t.Fatal(err)
	}
	if gotR.Relay == nil || *gotR.Relay != *r.Relay {
		t.Errorf("loaded relay %+v, saved %+v", gotR.Relay, r.Relay)
	}
}

func TestBadStateFiles(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":            "{",
		"unknown version":     `{"v":2,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`,
		"no key":              `{"v":1}`,
		"short key":           `{"v":1,"key":"AQEB"}`,
		"member twice":        `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","members":[{"device":"0123456789abcdef0123456789abcdef","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","chain":["AA=="]},{"device":"0123456789abcdef0123456789abcdef","key":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","chain":["AA=="]}]}`,
		"member, no PSK":      `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","members":[{"device":"0123456789abcdef0123456789abcdef","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","chain":["AA=="]}]}`,
		"relay and hub":       `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","is_hub":true,"relay":{"endpoint":"198.51.100.9:8764","key":"AAAA"}}`,
		"relay, no key":       `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","relay":{"endpoint":"198.51.100.9:8764","key":""}}`,
		"obfuscation, no hub": `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","obfuscation":{"jc":4,"jmin":50,"jmax":200,"s1":20,"s2":30,"s3":20,"s4":20,"h1":"100-200","h2":"300-400","h3":"500-600","h4":"700-800","header_protection_key":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="}}`,
		"obfuscation, bad":    `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","is_hub":true,"obfuscation":{"jc":4,"jmin":50,"jmax":200,"s1":20,"s2":30,"s3":20,"s4":20,"h1":"100-200","h2":"150-400","h3":"500-600","h4":"700-800","header_protection_key":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="}}`,
		"hub, bad device":     `{"v":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","hubs":[{"device":"x","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}]}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, StateFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(dir); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestAdmit(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	a, b := newDevice(t), newDevice(t)
	keyA := pubKey(t)
	chain := [][]byte{[]byte("cert a")}
	m, changed, err := s.Admit(a.id, keyA, Key{}, chain)
	if err != nil || !changed || m.PresharedKey.IsZero() {
		t.Fatalf("Admit = %+v, %v, %v", m, changed, err)
	}
	psk := m.PresharedKey

	// The same key again: nothing changes, the preshared key stays.
	m, changed, err = s.Admit(a.id, keyA, Key{}, chain)
	if err != nil || changed || m.PresharedKey != psk {
		t.Errorf("Admit again = %+v, %v, %v", m, changed, err)
	}
	// A renewed certificate: the chain changes, the preshared key stays.
	renewed := [][]byte{[]byte("cert a, renewed")}
	m, changed, err = s.Admit(a.id, keyA, Key{}, renewed)
	if err != nil || !changed || m.PresharedKey != psk || string(s.Members[0].Chain[0]) != "cert a, renewed" {
		t.Errorf("Admit renewed = %+v, %v, %v", m, changed, err)
	}
	// A new key gets a new preshared key.
	m, changed, err = s.Admit(a.id, pubKey(t), Key{}, renewed)
	if err != nil || !changed || m.PresharedKey == psk {
		t.Errorf("Admit new key = %+v, %v, %v", m, changed, err)
	}
	// The client's own preshared key is the one the hub uses.
	own := pubKey(t)
	m, changed, err = s.Admit(a.id, m.PublicKey, own, renewed)
	if err != nil || !changed || m.PresharedKey != own {
		t.Errorf("Admit with its own preshared key = %+v, %v, %v", m, changed, err)
	}
	if _, changed, _ = s.Admit(a.id, m.PublicKey, own, renewed); changed {
		t.Error("the same keys again changed the client")
	}
	if len(s.Members) != 1 {
		t.Errorf("%d members, want 1", len(s.Members))
	}

	// Refused: another device's key, the hub's own key, no key, no chain,
	// a bad device ID.
	for name, try := range map[string]func() error{
		"another device's key": func() error { _, _, err := s.Admit(b.id, s.Members[0].PublicKey, Key{}, chain); return err },
		"the hub's key":        func() error { _, _, err := s.Admit(b.id, s.Key.Public(), Key{}, chain); return err },
		"no key":               func() error { _, _, err := s.Admit(b.id, Key{}, Key{}, chain); return err },
		"no chain":             func() error { _, _, err := s.Admit(b.id, pubKey(t), Key{}, nil); return err },
		"bad device":           func() error { _, _, err := s.Admit("nope", pubKey(t), Key{}, chain); return err },
	} {
		if try() == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	if len(s.Members) != 1 {
		t.Errorf("%d members after refusals, want 1", len(s.Members))
	}

	if _, _, err := s.Admit(b.id, pubKey(t), Key{}, chain); err != nil {
		t.Fatal(err)
	}
	peers := s.Peers()
	if len(peers) != 2 {
		t.Fatalf("%d peers, want 2", len(peers))
	}
	if want, _ := Addr(b.id); peers[1].Addr != want {
		t.Errorf("peer address %v, want %v", peers[1].Addr, want)
	}
}

func TestPrune(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	a, b := newDevice(t), newDevice(t)
	for _, d := range []testDevice{a, b} {
		if _, _, err := s.Admit(d.id, pubKey(t), Key{}, [][]byte{[]byte(d.id)}); err != nil {
			t.Fatal(err)
		}
	}
	gone := s.Prune(func(m Member) bool { return string(m.Chain[0]) != b.id })
	if len(gone) != 1 || gone[0] != b.id {
		t.Errorf("pruned %v, want [%s]", gone, b.id)
	}
	if len(s.Members) != 1 || s.Members[0].Device != a.id {
		t.Errorf("members %+v, want only %s", s.Members, a.id)
	}
}

func TestSetHub(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	hub := newDevice(t)
	link := HubLink{Device: hub.id, PublicKey: hub.priv.Public(), PresharedKey: hub.psk,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:8764")}}
	if changed, err := s.SetHub(link); err != nil || !changed {
		t.Fatalf("SetHub = %v, %v", changed, err)
	}
	if changed, err := s.SetHub(link); err != nil || changed {
		t.Errorf("SetHub again = %v, %v", changed, err)
	}
	moved := link
	moved.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.2:8764")}
	if changed, err := s.SetHub(moved); err != nil || !changed || s.Hubs[0].Endpoints[0] != moved.Endpoints[0] || len(s.Hubs) != 1 {
		t.Errorf("SetHub with a new address = %v, %v", changed, err)
	}
	obf, err := NewObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	hidden := moved
	hidden.Obfuscation = obf
	if changed, err := s.SetHub(hidden); err != nil || !changed || !s.Hubs[0].Obfuscation.Equal(obf) {
		t.Errorf("SetHub with obfuscation = %v, %v", changed, err)
	}

	bad := func(f func(*HubLink)) HubLink {
		l := link
		f(&l)
		return l
	}
	for name, l := range map[string]HubLink{
		"bad device":      bad(func(l *HubLink) { l.Device = "x" }),
		"no key":          bad(func(l *HubLink) { l.PublicKey = Key{} }),
		"no PSK":          bad(func(l *HubLink) { l.PresharedKey = Key{} }),
		"own key":         bad(func(l *HubLink) { l.PublicKey = s.Key.Public() }),
		"port 0":          bad(func(l *HubLink) { l.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:0")} }),
		"invalid address": bad(func(l *HubLink) { l.Endpoints = []netip.AddrPort{{}} }),
		"many endpoints":  bad(func(l *HubLink) { l.Endpoints = make([]netip.AddrPort, maxEndpoints+1) }),
		"bad obfuscation": bad(func(l *HubLink) { l.Obfuscation = &Obfuscation{JC: 1} }),
	} {
		if _, err := s.SetHub(l); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s.Hubs[0].Endpoints[0] != moved.Endpoints[0] {
		t.Error("a refused offer changed the hub")
	}

	// Another hub's offer is kept beside the first, and forgotten alone.
	other := newDevice(t)
	if changed, err := s.SetHub(HubLink{Device: other.id, PublicKey: other.priv.Public(), PresharedKey: hub.psk}); err != nil || !changed || len(s.Hubs) != 2 {
		t.Fatalf("another hub: %v, %v, %d hubs", changed, err, len(s.Hubs))
	}
	if gone := s.ForgetHubs(func(h HubLink) bool { return h.Device != hub.id }); !slices.Equal(gone, []string{hub.id}) || s.Hub(hub.id) != nil || s.Hub(other.id) == nil {
		t.Errorf("forgetting a hub: %v, %+v", gone, s.Hubs)
	}
}

// TestLegacyHub checks that a state from before several hubs, with one
// hub's offer and no preshared key of its own, is not read.
func TestLegacyHub(t *testing.T) {
	dir := t.TempDir()
	hub, key := newDevice(t), newDevice(t).priv
	data := fmt.Sprintf(`{"v":1,"key":%q,"to_hub":{"device":%q,"key":%q,"psk":%q,"endpoints":["192.0.2.1:8764"]}}`,
		b64(key), hub.id, b64(hub.priv.Public()), b64(hub.psk))
	if err := os.WriteFile(filepath.Join(dir, StateFile), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadState(dir); err == nil {
		t.Fatalf("loaded %+v", s)
	}
}

func b64(k Key) string { return base64.StdEncoding.EncodeToString(k[:]) }

func TestForGroup(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	key := s.Key
	if !s.ForGroup("aaaaaaaaaaaaaaaa") {
		t.Error("a new group did not change the state")
	}
	s.IsHub = true
	if _, _, err := s.Admit(newDevice(t).id, pubKey(t), Key{}, [][]byte{[]byte("c")}); err != nil {
		t.Fatal(err)
	}
	if s.ForGroup("aaaaaaaaaaaaaaaa") {
		t.Error("the same group changed the state")
	}
	if !s.ForGroup("bbbbbbbbbbbbbbbb") || s.IsHub || len(s.Members) != 0 || s.Key != key || s.Group != "bbbbbbbbbbbbbbbb" {
		t.Errorf("after another group: %+v", s)
	}
}

func TestKeyText(t *testing.T) {
	k := pubKey(t)
	b, err := k.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var got Key
	if err := got.UnmarshalText(b); err != nil || got != k {
		t.Errorf("round trip: %v, %x", err, got)
	}
	for _, bad := range []string{"", "AQEB", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB", "!!!"} {
		if err := got.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
}

func TestDestinations(t *testing.T) {
	ap := netip.MustParseAddrPort
	a := netip.MustParseAddr
	fw := &ForwarderLink{Endpoint: ap("198.51.100.9:8764"), VLESS: &VLESS{Endpoint: ap("198.51.100.9:443")}}
	for name, c := range map[string]struct {
		st   State
		want []netip.Addr
	}{
		"off":               {State{}, nil},
		"hub alone":         {State{IsHub: true, Endpoints: []netip.AddrPort{ap("203.0.113.7:8764")}}, nil},
		"hub, forwarder":    {State{IsHub: true, Forwarder: fw}, []netip.Addr{a("198.51.100.9")}},
		"relay":             {State{Relay: &RelayLink{Endpoint: ap("[2001:db8::5]:8764")}}, []netip.Addr{a("2001:db8::5")}},
		"client":            {State{Hubs: []HubLink{{Endpoints: []netip.AddrPort{ap("203.0.113.7:8764"), ap("[::ffff:198.51.100.9]:9000")}}}}, []netip.Addr{a("203.0.113.7"), a("198.51.100.9")}},
		"client over VLESS": {State{Hubs: []HubLink{{VLESS: &VLESS{Endpoint: ap("198.51.100.10:443")}}}}, []netip.Addr{a("198.51.100.10")}},
		"two hubs":          {State{Hubs: []HubLink{{Endpoints: []netip.AddrPort{ap("203.0.113.7:8764")}}, {Endpoints: []netip.AddrPort{ap("203.0.113.8:8764")}}}}, []netip.Addr{a("203.0.113.7"), a("203.0.113.8")}},
		"hub with a hub":    {State{IsHub: true, Forwarder: fw, Hubs: []HubLink{{Endpoints: []netip.AddrPort{ap("203.0.113.8:8764")}}}}, []netip.Addr{a("198.51.100.9"), a("203.0.113.8")}},
	} {
		if got := c.st.Destinations(); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// TestTake checks the clients a hub takes from another hub: with the keys
// they have and no chain, new keys while it has not met them, never with
// another's key or the hub's own, and a chain once they meet the hub, after
// which what other hubs share changes nothing.
func TestTake(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	dev, pub, psk := "0123456789abcdef0123456789abcdef", pubKey(t), pubKey(t)
	if changed, err := s.Take(dev, pub, psk); err != nil || !changed {
		t.Fatalf("take: %v, %v", changed, err)
	}
	if changed, err := s.Take(dev, pub, psk); err != nil || changed {
		t.Errorf("taking a client it keeps: %v, %v", changed, err)
	}
	pub, psk = pubKey(t), pubKey(t)
	if changed, err := s.Take(dev, pub, psk); err != nil || !changed || s.Members[0].PublicKey != pub {
		t.Errorf("taking new keys of a client it has not met: %v, %v", changed, err)
	}
	for name, try := range map[string]func() error{
		"another's key": func() error { _, err := s.Take("fedcba9876543210fedcba9876543210", pub, psk); return err },
		"the hub's key": func() error { _, err := s.Take("fedcba9876543210fedcba9876543210", s.Key.Public(), psk); return err },
		"no psk":        func() error { _, err := s.Take("fedcba9876543210fedcba9876543210", pubKey(t), Key{}); return err },
		"bad device":    func() error { _, err := s.Take("nope", pubKey(t), psk); return err },
	} {
		if try() == nil {
			t.Errorf("%s: taken", name)
		}
	}
	dir := t.TempDir()
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Errorf("a taken client without a chain does not load: %v", err)
	}
	m, changed, err := s.Admit(dev, pub, Key{}, [][]byte{{1}})
	if err != nil || !changed || m.PresharedKey != psk || len(m.Chain) != 1 {
		t.Errorf("meeting the hub: %+v, %v, %v", m, changed, err)
	}
	if changed, err := s.Take(dev, pubKey(t), pubKey(t)); err != nil || changed {
		t.Errorf("taking a client it met: %v, %v", changed, err)
	}
}

func TestServingAndNextKeys(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_000_000)
	s.IsHub = true
	next, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	s.Next, s.NextFor, s.NextAt = next, "p1", now.Add(time.Hour)
	if s.ServingKey() != s.Key {
		t.Error("the hub serves with the next key ahead of time")
	}

	// The next key and when it starts survive a restart.
	dir := t.TempDir()
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Next != next || got.NextFor != "p1" || !got.NextAt.Equal(now.Add(time.Hour)) || !got.Serving.IsZero() {
		t.Fatalf("loaded next %v for %q at %v, serving %v", got.Next, got.NextFor, got.NextAt, got.Serving)
	}

	got.Serving, got.ServingFor = got.Next, got.NextFor
	got.Next, got.NextFor, got.NextAt = Key{}, "", time.Time{}
	if got.ServingKey() != next {
		t.Fatalf("serving %v, not the next key", got.ServingKey())
	}
	if err := got.Save(dir); err != nil {
		t.Fatal(err)
	}
	again, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Serving != next || again.ServingFor != "p1" || again.Key != s.Key {
		t.Errorf("loaded serving %v for %q", again.Serving, again.ServingFor)
	}

	// A client offering one of the hub's keys is refused.
	a := newDevice(t)
	if _, _, err := again.Admit(a.id, next.Public(), Key{}, [][]byte{[]byte("cert")}); err == nil {
		t.Error("admitted a client with the hub's serving key")
	}
	if _, err := again.SetHub(HubLink{Device: a.id, PublicKey: pubKey(t), PresharedKey: a.psk, Next: next.Public()}); err == nil {
		t.Error("kept a hub whose next key is this device's own")
	}
}
