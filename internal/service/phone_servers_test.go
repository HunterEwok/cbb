// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/forward"
)

// rootPhoneWithLaptop runs a phone's app (phone-on-linux) as the root of a
// group of 0.6 of its own, which a laptop joins by its home window, and
// returns the phone, its directory, the laptop and their device IDs. The
// Live member keeps the group's server credentials itself, so the app
// starts no servers (cbb_member_servers).
func rootPhoneWithLaptop(t *testing.T, h *hub) (next func(string) string, in io.Writer, dir string, laptop *testService, phoneID, laptopID string) {
	t.Helper()
	return rootPhoneWithLaptopArgs(t, h)
}

// rootPhoneWithLaptopArgs is rootPhoneWithLaptop with more arguments for
// the phone.
func rootPhoneWithLaptopArgs(t *testing.T, h *hub, args ...string) (next func(string) string, in io.Writer, dir string, laptop *testService, phoneID, laptopID string) {
	t.Helper()
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	dir = t.TempDir()
	next, w := phoneOnLinux(t, bin, append([]string{"-name", "root phone", "-group06", "-dir", dir}, args...)...)
	phoneID = strings.Fields(next("Group "))[0]
	laptop = joinPhoneWindow(t, h, next, w, "laptop")
	laptopID = laptop.status(t).Device
	call := phoneCall(t, next, w)
	call("found", map[string]any{"key": "laptop", "addrs": []string{laptop.addr()}})
	waitFor(t, "the phone connected to the laptop", func() bool {
		fmt.Fprintln(w, "PEERS")
		return next("PEERS ") == "1"
	})
	return next, w, dir, laptop, phoneID, laptopID
}

// TestFFIPhoneServersRelay: the root phone sets the group's relay, which it
// signs in the group's settings (D-121), and with the root key that hands
// over signs the period of the group's credentials for it, which was due
// (docs/protocol.md, section 18), as the Rust root does by itself
// (TestAloneRelayRoot): with sync away from home on, it and the laptop meet
// at the relay, and the root setting none again leaves it.
func TestFFIPhoneServersRelay(t *testing.T) {
	var h hub
	next, in, _, laptop, phoneID, laptopID := rootPhoneWithLaptop(t, &h)
	call := phoneCall(t, next, in)
	if st := call("away_status", nil); st["period_due"] != true {
		t.Fatalf("the root phone's first period is not due: %v", st)
	}
	r, keys := startRelay(t, laptop.status(t).RelayGroup)
	// Setting the relay hands the root key over, which renews the
	// credentials' period that is due for it.
	fmt.Fprintf(in, "MANAGE {\"action\":\"relay\",\"relays\":[%q]}\n", r.Addr().String()+" "+keys.Pin())
	if got := next("MANAGED "); got != fmt.Sprintf(`{"ok":{"relays":[%q]}}`, r.Addr().String()) {
		t.Fatalf("setting the group's relay: %s", got)
	}
	if st := call("away_status", nil); st["period_due"] != false || st["period_overdue"] != false {
		t.Fatalf("the root phone did not renew the credentials with the relay: %v", st)
	}
	call("away", map[string]any{"on": true})
	if _, err := laptop.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatalf("cbb global on on the laptop: %v", err)
	}
	waitUpTo(t, 60*time.Second, "both meet at the relay", func() bool {
		b := laptop.status(t).Away
		a, _ := call("away_status", nil)["away"].(map[string]any)
		relay, _ := a["relay"].(map[string]any)
		online, _ := relay["online"].([]any)
		return relay["connected"] == true && len(online) == 1 && online[0] == laptopID &&
			b != nil && b.Relay != nil && b.Relay.Connected && slices.Equal(b.Relay.Online, []string{phoneID})
	})

	// No relay again: the phone meets the group at none.
	fmt.Fprintln(in, `MANAGE {"action":"relay","relays":[]}`)
	if got := next("MANAGED "); got != `{"ok":{"relays":[]}}` {
		t.Fatalf("setting no relay: %s", got)
	}
	waitUpTo(t, 30*time.Second, "the phone leaves the relay", func() bool {
		a, _ := call("away_status", nil)["away"].(map[string]any)
		return a["relay"] == nil
	})
}

// TestFFIPhoneHub: an admin phone is a hub of the group (on the records of
// 0.6 a phone is one only with an admin key), registered with the
// forwarder the root named for it, and the root computer keeps its offer at the forwarder's
// address; stopping the hub hands its clients to the group's next hub, so
// the group's only hub stops without anyway (D-122).
func TestFFIPhoneHub(t *testing.T) {
	cert, err := forward.NewCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := forward.Listen(forward.Config{Listen: "127.0.0.1:0", Cert: cert, Logf: t.Logf, StateFile: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		f.Serve(ctx)
	}()
	defer func() {
		cancel()
		<-served
	}()

	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	var h hub
	pi, next, in := adminPhone(t, bin, &h)
	var phoneID string
	for _, d := range pi.devices(t) {
		if d.Name == "member phone" {
			phoneID = d.ID
		}
	}
	call := phoneCall(t, next, in)
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	// The root names the phone's forwarder, which makes the group's
	// credentials for it; the phone keeps it as its setting and serves
	// through it once its own switch is on, never before.
	if _, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "member phone", Forwarder: f.Addr().String(),
		ForwarderKey: forward.Pin(cert.Leaf)}, ""); err != nil {
		t.Fatal(err)
	}
	var set map[string]any
	waitUpTo(t, 30*time.Second, "the phone keeps the root's forwarder", func() bool {
		set = call("away_status", nil)
		rf, _ := set["root_forwarder"].(map[string]any)
		return rf["endpoint"] == f.Addr().String()
	})
	if a, _ := set["away"].(map[string]any); a["hub"] == true {
		t.Fatalf("the root's command switched the phone's hub on: %v", set)
	}
	call("hub", map[string]any{"vless_off": true})
	waitUpTo(t, 30*time.Second, "the phone registered with the forwarder", func() bool {
		a, _ := call("away_status", nil)["away"].(map[string]any)
		fw, _ := a["forwarder"].(map[string]any)
		return a["hub"] == true && fw["registered"] == true
	})
	waitUpTo(t, 30*time.Second, "the root keeps the phone's offer at the forwarder", func() bool {
		hl := tunnelState(t, pi).Hub(phoneID)
		return hl != nil && len(hl.Endpoints) == 1 && hl.Endpoints[0].String() == f.Addr().String()
	})

	// The group's only hub stops: its clients go to the next hub in the
	// order, as on every hub of 0.6, so no anyway is asked for.
	if a := call("hub_off", nil)["away"].(map[string]any); a["hub"] == true {
		t.Fatalf("the phone is still a hub: %v", a)
	}
}
