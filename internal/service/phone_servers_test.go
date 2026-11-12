// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"encoding/json"
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
// group of its own that admits a laptop, with the member serving the
// servers (cbb_member_servers), and returns the phone, its directory, the
// laptop and their device IDs.
func rootPhoneWithLaptop(t *testing.T, h *hub) (next func(string) string, in io.Writer, dir string, laptop *testService, phoneID, laptopID string) {
	t.Helper()
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	dir = t.TempDir()
	next, w := phoneOnLinux(t, bin, "-name", "root phone", "-new-group", "-dir", dir)
	phoneID = strings.Fields(next("Group "))[0]
	laptop, qr := listeningJoin(t, h, "laptop")
	fmt.Fprintln(w, "ADMIT "+qr)
	laptopID = next("ADMITTED ")
	if got := next("ADMIT DONE "); got != "true" {
		t.Fatalf("the laptop did not confirm its join: %q", got)
	}
	joinedIdentity(t, laptop, laptopID)
	fmt.Fprintln(w, "SERVERS")
	if got := next("SERVERS "); got != `{"ok":{}}` {
		t.Fatalf("serving the servers: %s", got)
	}
	call := phoneCall(t, next, w)
	call("found", map[string]any{"key": "laptop", "addrs": []string{laptop.addr()}})
	waitFor(t, "the phone connected to the laptop", func() bool {
		fmt.Fprintln(w, "PEERS")
		return next("PEERS ") == "1"
	})
	return next, w, dir, laptop, phoneID, laptopID
}

// TestFFIPhoneServersRelay: a root phone whose member serves the servers
// signs the period of the group's server credentials when its app hands
// it the root key (docs/protocol.md, section 18), its own server key and
// the hubs' and members' credentials, and meets the laptop at a blind
// relay with them.
func TestFFIPhoneServersRelay(t *testing.T) {
	var h hub
	next, in, dir, laptop, phoneID, laptopID := rootPhoneWithLaptop(t, &h)
	call := phoneCall(t, next, in)
	if due := call("servers", nil)["period_due"]; due != true {
		t.Fatalf("the root phone's first period is not due: %v", due)
	}
	fmt.Fprintln(in, `MANAGE {"action":"period"}`)
	if got := next("MANAGED "); got != `{"ok":{"period_due":false}}` {
		t.Fatalf("signing the period: %s", got)
	}
	// The laptop's server key comes back, and the phone lists both in the
	// hubs' and the members' credentials.
	waitUpTo(t, 30*time.Second, "the root phone keeps the group's credentials", func() bool {
		raw, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
		var all []json.RawMessage
		return err == nil && json.Unmarshal(raw, &all) == nil && len(all) == 5
	})

	r, keys := startRelay(t, laptop.status(t).Group)
	call("relay", map[string]any{"relay": r.Addr().String(), "key": keys.Pin()})
	if _, err := laptop.do(t, control.Header{Op: control.OpAway, Name: "relay", Relay: r.Addr().String(), RelayKey: keys.Pin(), Consent: true}, ""); err != nil {
		t.Fatalf("cbb global relay on the laptop: %v", err)
	}
	waitUpTo(t, 60*time.Second, "both meet at the relay", func() bool {
		b := laptop.status(t).Away
		a := call("away_status", nil)["away"]
		relay, _ := a.(map[string]any)["relay"].(map[string]any)
		online, _ := relay["online"].([]any)
		return relay["connected"] == true && len(online) == 1 && online[0] == laptopID &&
			b != nil && b.Relay != nil && b.Relay.Connected && slices.Equal(b.Relay.Online, []string{phoneID})
	})

	// Leaving the relay turns sync away from home on again without it.
	a := call("relay", map[string]any{"relay": ""})["away"].(map[string]any)
	if a["relay"] != nil {
		t.Fatalf("the phone still meets the group at the relay: %v", a)
	}
}

// TestFFIPhoneHub: a root phone whose member serves the servers is the
// group's hub, registered with its forwarder, and the laptop keeps its
// offer at the forwarder's address.
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

	var h hub
	next, in, _, laptop, phoneID, _ := rootPhoneWithLaptop(t, &h)
	call := phoneCall(t, next, in)
	if _, err := laptop.do(t, control.Header{Op: control.OpAway, Name: "on", Consent: true}, ""); err != nil {
		t.Fatal(err)
	}
	call("hub", map[string]any{"forwarder": f.Addr().String(), "key": forward.Pin(cert.Leaf), "vless_off": true})
	waitUpTo(t, 30*time.Second, "the phone registered with the forwarder", func() bool {
		a, _ := call("away_status", nil)["away"].(map[string]any)
		fw, _ := a["forwarder"].(map[string]any)
		return a["hub"] == true && fw["registered"] == true
	})
	waitUpTo(t, 30*time.Second, "the laptop keeps the phone's offer at the forwarder", func() bool {
		hl := tunnelState(t, laptop).Hub(phoneID)
		return hl != nil && len(hl.Endpoints) == 1 && hl.Endpoints[0].String() == f.Addr().String()
	})

	// A phone that is the group's only hub stops being one only anyway.
	fmt.Fprintln(in, `CALL {"op":"hub_off"}`)
	if got := next("ANSWER "); !strings.Contains(got, "no other hub") {
		t.Fatalf("stopping the only hub: %s", got)
	}
	if a := call("hub_off", map[string]any{"anyway": true})["away"].(map[string]any); a["hub"] == true {
		t.Fatalf("the phone is still a hub: %v", a)
	}
}
