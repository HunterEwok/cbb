// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/HunterEwok/cbb/internal/control"
)

// A command against a fake service: what it sends, what it prints and its
// exit code.
type commandCase struct {
	name   string
	args   []string
	stdin  string
	answer control.Header // the service's answer; Done is set
	// check looks at the request; nil when the command must send none.
	check  func(t *testing.T, m *control.Message)
	code   int
	stdout string // must contain; empty for any
	stderr string // must contain; empty for any
}

func runCommandCases(t *testing.T, cases []commandCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := c.answer
			a.Done = true
			got := fakeService(t, control.Message{Header: a})
			var stdout, stderr bytes.Buffer
			code := run(c.args, strings.NewReader(c.stdin), &stdout, &stderr)
			if code != c.code {
				t.Errorf("cbb %s: exit code %d, want %d; stdout %q, stderr %q", strings.Join(c.args, " "), code, c.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), c.stdout) {
				t.Errorf("stdout %q, want it to contain %q", stdout.String(), c.stdout)
			}
			if !strings.Contains(stderr.String(), c.stderr) {
				t.Errorf("stderr %q, want it to contain %q", stderr.String(), c.stderr)
			}
			select {
			case m := <-got:
				if c.check == nil {
					t.Errorf("sent %+v, want no request", m.Header)
				} else {
					c.check(t, m)
				}
			default:
				if c.check != nil {
					t.Error("sent no request")
				}
			}
		})
	}
}

// sent checks a request's operation and the fields want names.
func sent(op string, want func(m *control.Message) bool) func(t *testing.T, m *control.Message) {
	return func(t *testing.T, m *control.Message) {
		t.Helper()
		if m.Op != op || want != nil && !want(m) {
			t.Errorf("sent %+v, want op %s with the right fields", m.Header, op)
		}
	}
}

func TestDeviceCommands(t *testing.T) {
	refused := control.Header{Error: "only the group's root makes admins"}
	runCommandCases(t, []commandCase{
		{name: "remove", args: []string{"remove", "laptop"}, answer: control.Header{Name: "laptop"},
			check: sent(control.OpRevoke, func(m *control.Message) bool { return m.Name == "laptop" }), stdout: "Removed laptop from the group"},
		{name: "remove refused", args: []string{"remove", "laptop"}, answer: control.Header{Error: "no device laptop in the group"},
			check: sent(control.OpRevoke, nil), code: 1, stderr: "no device laptop in the group"},
		{name: "rename", args: []string{"rename", "laptop", " work "}, answer: control.Header{Name: "laptop"},
			check: sent(control.OpRename, func(m *control.Message) bool { return m.Name == "laptop" && m.NewName == " work " }), stdout: "Renamed laptop to work."},
		{name: "rename without a new name", args: []string{"rename", "laptop"}, code: 2, stderr: "usage: cbb rename"},
		{name: "takeover delay", args: []string{"takeover", "-delay", "24h"}, answer: control.Header{},
			check: sent(control.OpDelay, func(m *control.Message) bool { return m.Value == "24h" }), stdout: "now waits 24h"},
		{name: "takeover delay without a duration", args: []string{"takeover", "-delay"}, code: 2, stderr: "usage: cbb takeover -delay"},
		{name: "key level", args: []string{"keys", "hardware"}, answer: control.Header{Below: []string{"desk"}},
			check: sent(control.OpKeyLevel, func(m *control.Message) bool { return m.Value == "hardware" }), stdout: "Below it: desk."},
		{name: "key level shown", args: []string{"keys"}, answer: control.Header{Status: &control.Status{Group: "g", KeyLevel: "files"}},
			check: sent(control.OpStatus, nil), stdout: "Key level files"},
		{name: "key level with two", args: []string{"keys", "files", "hardware"}, code: 2, stderr: "usage: cbb keys"},
		{name: "incoming", args: []string{"incoming", "90s"}, answer: control.Header{Done: true},
			check: sent(control.OpIncoming, func(m *control.Message) bool { return m.Value == "90s" }), stdout: "for 1m30s after it arrives"},
		{name: "incoming shown", args: []string{"incoming"}, answer: control.Header{Status: &control.Status{Group: "g", IncomingMS: 3600_000}},
			check: sent(control.OpStatus, nil), stdout: "for 1h after it arrives"},
		{name: "incoming not a duration", args: []string{"incoming", "soon"}, code: 2, stderr: "usage: cbb incoming"},
		{name: "hubs", args: []string{"global", "hubs", "deck", "pi"}, answer: control.Header{},
			check: sent(control.OpHubs, func(m *control.Message) bool { return slices.Equal(m.Hubs, []string{"deck", "pi"}) }), stdout: "deck, pi, in this order"},
		{name: "hubs without a device", args: []string{"global", "hubs"}, code: 2, stderr: "usage: cbb global hubs"},
		{name: "freeze", args: []string{"freeze", "desk"}, answer: control.Header{Name: "desk"},
			check: sent(control.OpFreeze, func(m *control.Message) bool { return m.Name == "desk" }), stdout: "Froze desk"},
		{name: "unfreeze", args: []string{"unfreeze", "desk"}, answer: control.Header{Name: "desk"},
			check: sent(control.OpThaw, nil), stdout: "Unfroze desk: it is an admin again."},
		{name: "resolve", args: []string{"resolve"}, answer: control.Header{Name: "desk"},
			check: sent(control.OpResolve, nil), stdout: "Voided both histories of desk"},
		{name: "resolve with an argument", args: []string{"resolve", "desk"}, code: 2, stderr: "usage: cbb resolve"},
		{name: "admin", args: []string{"admin", "desk"}, answer: control.Header{Name: "desk"},
			check: sent(control.OpAdmin, func(m *control.Message) bool { return m.Name == "desk" && !m.Consent }), stdout: "desk is an admin now"},
		{name: "admin with a file key", args: []string{"admin", "-allow-file-key", "desk"}, answer: control.Header{Name: "desk"},
			check: sent(control.OpAdmin, func(m *control.Message) bool { return m.Consent }), stdout: "guard it"},
		{name: "admin refused", args: []string{"admin", "desk"}, answer: refused, check: sent(control.OpAdmin, nil), code: 1, stderr: "only the group's root"},
		{name: "admin without a device", args: []string{"admin"}, code: 2, stderr: "usage: cbb admin"},
		{name: "takeover", args: []string{"takeover", "old"}, answer: control.Header{Name: "old"},
			check: sent(control.OpTakeover, func(m *control.Message) bool { return m.Name == "old" }), stdout: "Claimed the group from old"},
	})
}

func TestSyncAndNetwork(t *testing.T) {
	inG := func(st control.Status) control.Header {
		st.Role, st.OS, st.Group = "full", "linux", "g1"
		return control.Header{Status: &st}
	}
	runCommandCases(t, []commandCase{
		{name: "sync", args: []string{"sync"}, answer: inG(control.Status{Mode: "shared"}), check: sent(control.OpStatus, nil), stdout: "Sync is on"},
		{name: "sync in no group", args: []string{"sync"}, answer: control.Header{Status: &control.Status{Role: "full", OS: "linux"}},
			check: sent(control.OpStatus, nil), code: 1, stderr: "in no group"},
		{name: "sync with no status", args: []string{"sync"}, check: sent(control.OpStatus, nil), code: 1, stderr: "sent no status"},
		{name: "sync off", args: []string{"sync", "off"}, answer: inG(control.Status{Mode: "own"}),
			check: sent(control.OpSync, func(m *control.Message) bool { return m.Name == "off" && m.Device == "" && m.ForMS == 0 }), stdout: "Sync is off until cbb sync on"},
		{name: "sync off for an hour", args: []string{"sync", "-for", "1h", "off"}, answer: inG(control.Status{Mode: "own", SyncUntilMS: 1}),
			check: sent(control.OpSync, func(m *control.Message) bool { return m.Name == "off" && m.ForMS == 3600000 }), stdout: "Sync is off until"},
		{name: "sync off, then the time", args: []string{"sync", "off", "-for", "15m"}, answer: inG(control.Status{Mode: "own", SyncUntilMS: 1}),
			check: sent(control.OpSync, func(m *control.Message) bool { return m.Name == "off" && m.ForMS == 900000 }), stdout: "Sync is off until"},
		{name: "sync on with a time", args: []string{"sync", "on", "-for", "15m"}, code: 2, stderr: "-for goes with cbb sync off"},
		{name: "sync on", args: []string{"sync", "on"}, answer: inG(control.Status{Mode: "shared"}),
			check: sent(control.OpSync, func(m *control.Message) bool { return m.Name == "on" }), stdout: "Sync is on"},
		{name: "sync elsewhere", args: []string{"sync", "-on", "tv", "off"},
			check: sent(control.OpSync, func(m *control.Message) bool { return m.Name == "off" && m.Device == "tv" }), stdout: "Sync is off on tv now."},
		{name: "sync -on without on or off", args: []string{"sync", "-on", "tv"}, code: 2, stderr: "usage: cbb sync"},
		{name: "sync with a mode", args: []string{"sync", "own"}, code: 2, stderr: "usage: cbb sync"},
		{name: "sync on for a while", args: []string{"sync", "-for", "1h", "on"}, code: 2, stderr: "-for goes with cbb sync off"},
		{name: "sync off elsewhere for a while", args: []string{"sync", "-on", "tv", "-for", "1h", "off"}, code: 2, stderr: "-for goes with cbb sync off"},
		{name: "network", args: []string{"network"}, check: sent(control.OpNetwork, nil), stdout: "publishes itself and takes connections here"},
		{name: "network refused", args: []string{"network"}, answer: control.Header{Error: "this network is not known"}, check: sent(control.OpNetwork, nil), code: 1, stderr: "not known"},
		{name: "network with an argument", args: []string{"network", "x"}, code: 2, stderr: "usage: cbb network"},
	})
}

func TestSyncLine(t *testing.T) {
	for _, tc := range []struct {
		st   control.Status
		want string
	}{
		{control.Status{Mode: "shared"}, "the group's copies come here."},
		{control.Status{Mode: "own"}, "Sync is off until cbb sync on"},
		{control.Status{Mode: "own", SyncUntilMS: 1_800_000_000_000}, "Sync is off until 20"},
	} {
		if got := syncLine(&tc.st); !strings.Contains(got, tc.want) {
			t.Errorf("syncLine(%+v) = %q, want %q in it", tc.st, got, tc.want)
		}
	}
}

func TestQuietLine(t *testing.T) {
	if got := quietLine(&control.Status{Quiet: []string{"wlan0"}}); got != "" {
		t.Errorf("in no group: %q", got)
	}
	if got := quietLine(&control.Status{Group: "g", Quiet: []string{"wlan0", "eth1"}}); !strings.Contains(got, "Quiet on wlan0, eth1") {
		t.Errorf("quiet line %q", got)
	}
}

func TestActionCommands(t *testing.T) {
	// A program is given by its full path, which differs on Windows.
	prog := "/usr/bin/backup"
	if runtime.GOOS == "windows" {
		prog = `C:\Tools\backup.exe`
	}
	list := control.Header{Status: &control.Status{Role: "full", OS: "linux", Group: "g", Actions: []control.Action{
		{Name: "lock", On: true},
		{Name: "reboot", On: true, By: []string{"root", "phone"}},
		{Name: "shutdown", On: true, AnyKey: true},
		{Name: "sleep"},
		{Name: "backup", On: true, Command: []string{"/usr/bin/backup", "--now"}},
	}}}
	runCommandCases(t, []commandCase{
		{name: "list", args: []string{"action"}, answer: list, check: sent(control.OpStatus, nil), stdout: "lock             on, for every admin\n"},
		{name: "list in no group", args: []string{"action"}, answer: control.Header{Status: &control.Status{}}, check: sent(control.OpStatus, nil), code: 1, stderr: "in no group"},
		{name: "run on another device", args: []string{"action", "-on", "desk", "lock"},
			check: sent(control.OpActionOn, func(m *control.Message) bool { return m.Device == "desk" && m.Name == "lock" }), stdout: "desk ran lock."},
		{name: "run refused", args: []string{"action", "-on", "desk", "lock"}, answer: control.Header{Error: "lock is off on desk"},
			check: sent(control.OpActionOn, nil), code: 1, stderr: "lock is off on desk"},
		{name: "a name without -on", args: []string{"action", "lock"}, code: 2, stderr: "usage: cbb action"},
		// Answering anything but yes changes nothing and sends nothing.
		{name: "enable declined", args: []string{"action", "enable", "reboot", "-by", "root"}, stdin: "no\n", code: 1,
			stdout: "Turning reboot on lets the group's admins of the kinds root whose keys are in hardware"},
		{name: "enable a bad kind", args: []string{"action", "enable", "lock", "-by", "toaster"}, code: 1, stderr: "toaster"},
		{name: "enable with an argument", args: []string{"action", "enable", "lock", "extra"}, code: 2, stderr: "usage: cbb action"},
		{name: "disable with -yes", args: []string{"action", "disable", "lock", "-yes"}, code: 2, stderr: "usage: cbb action"},
		{name: "enable without a name", args: []string{"action", "enable"}, code: 2, stderr: "usage: cbb action"},
		{name: "add declined", args: []string{"action", "add", "backup", "--", prog}, stdin: "\n", code: 1,
			stdout: "run " + prog + " as the user signed in here"},
		{name: "add", args: []string{"action", "add", "backup", "-by", "phone", "-yes", "--", prog, "--now"},
			check: sent(control.OpActionSet, func(m *control.Message) bool {
				return len(m.Actions) == 1 && m.Actions[0].Name == "backup" && m.Actions[0].On &&
					strings.Join(m.Actions[0].Command, " ") == prog+" --now" && strings.Join(m.Actions[0].By, ",") == "phone"
			}),
			stdout: "backup: on, for phone: " + prog + " --now."},
		{name: "add with yes typed", args: []string{"action", "add", "backup", "--", prog}, stdin: "YES\n",
			check: sent(control.OpActionSet, nil), stdout: "backup: on, for every admin"},
		{name: "add refused", args: []string{"action", "add", "backup", "-yes", "--", prog}, answer: control.Header{Error: "too many actions"},
			check: sent(control.OpActionSet, nil), code: 1, stderr: "too many actions"},
		{name: "add without a program", args: []string{"action", "add", "backup", "-yes"}, code: 1},
		{name: "add without a name", args: []string{"action", "add"}, code: 2, stderr: "usage: cbb action"},
		{name: "remove", args: []string{"action", "remove", "backup"},
			check: sent(control.OpActionDel, func(m *control.Message) bool { return m.Name == "backup" }), stdout: "The action backup is removed."},
		{name: "remove without a name", args: []string{"action", "remove"}, code: 2, stderr: "usage: cbb action"},
		{name: "off elsewhere", args: []string{"action", "off", "-on", "desk"},
			check: sent(control.OpActionOff, func(m *control.Message) bool { return m.Device == "desk" && !m.All }), stdout: "off on desk."},
		{name: "off everywhere", args: []string{"action", "off", "-all"},
			check: sent(control.OpActionOff, func(m *control.Message) bool { return m.All }), stdout: "off on every device of the group."},
		{name: "off with both", args: []string{"action", "off", "-all", "-on", "desk"}, code: 2, stderr: "usage: cbb action"},
		{name: "off refused", args: []string{"action", "off", "-all"}, answer: control.Header{Error: "only admins"}, check: sent(control.OpActionOff, nil), code: 1, stderr: "only admins"},
	})
}

func TestActionLine(t *testing.T) {
	for _, c := range []struct {
		a    control.Action
		want string
	}{
		{control.Action{Name: "lock"}, "off"},
		{control.Action{Name: "backup", Command: []string{"b", "-x"}}, "off: b -x"},
		{control.Action{Name: "lock", On: true}, "on, for every admin"},
		{control.Action{Name: "reboot", On: true}, "on, for every admin, keys in hardware only"},
		{control.Action{Name: "reboot", On: true, AnyKey: true, By: []string{"root"}}, "on, for root"},
	} {
		if got := actionLine(c.a); got != c.want {
			t.Errorf("actionLine(%+v) = %q, want %q", c.a, got, c.want)
		}
	}
}

func TestOnActions(t *testing.T) {
	if got := onActions(nil); got != nil {
		t.Errorf("no status: %v", got)
	}
	st := &control.Status{Actions: []control.Action{{Name: "lock", On: true}, {Name: "sleep"}, {Name: "reboot", On: true}}}
	if got := strings.Join(onActions(st), ","); got != "lock,reboot" {
		t.Errorf("on: %s", got)
	}
}
