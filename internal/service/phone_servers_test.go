// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
)

// phoneOnLinuxBin is the phone app's example phone-on-linux, as
// CBB_PHONE_ON_LINUX names it; the test skips without it, as the phone
// helpers do.
func phoneOnLinuxBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("CBB_PHONE_ON_LINUX")
	if bin == "" {
		t.Skip("CBB_PHONE_ON_LINUX is not set")
	}
	return bin
}

// rootPhoneWithLaptop runs a phone's app (phone-on-linux) as the root of a
// group of 0.6 of its own, which a laptop joins by its home window, and
// returns the phone, its directory, the laptop and their device IDs. The
// Live member keeps the group's server credentials itself.
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

// TestFFIPhoneIsNoHub: a hub is a computer, a router or a board, never a
// phone (D-134). The root names no forwarder for an admin phone, the
// group's records make it no hub, and the phone's member knows no hub
// command to start one.
func TestFFIPhoneIsNoHub(t *testing.T) {
	var h hub
	pi, next, in := adminPhone(t, phoneOnLinuxBin(t), &h)
	var phoneID string
	for _, d := range pi.devices(t) {
		if d.Name == "member phone" {
			phoneID = d.ID
		}
	}
	if phoneID == "" {
		t.Fatal("the admin phone is not in the group")
	}
	_, err := pi.do(t, control.Header{Op: control.OpAway, Name: "hub", Device: "member phone", Forwarder: "127.0.0.1:1",
		ForwarderKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}, "")
	if err == nil || !strings.Contains(err.Error(), "hub") {
		t.Fatalf("the root named a forwarder for a phone: %v", err)
	}
	if hl := tunnelState(t, pi).Hub(phoneID); hl != nil {
		t.Fatalf("the root keeps an offer of the phone as a hub: %+v", hl)
	}
	for _, op := range []string{"hub", "hub_off"} {
		req, err := json.Marshal(map[string]any{"op": op, "args": map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(in, "CALL %s\n", req)
		var ans struct {
			OK    map[string]any `json:"ok"`
			Error map[string]any `json:"error"`
		}
		if err := json.Unmarshal([]byte(next("ANSWER ")), &ans); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if ans.Error == nil {
			t.Fatalf("the phone took %s: %v", op, ans.OK)
		}
	}
	a, _ := phoneCall(t, next, in)("away_status", nil)["away"].(map[string]any)
	if a["hub"] == true {
		t.Fatalf("the phone says it is a hub: %v", a)
	}
}
