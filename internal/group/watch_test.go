// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto/x509"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
)

// watchRecord is the root's record of a watch whose admin CA is w: the
// watch has no member key, so the record names the admin key twice.
func watchRecord(t *testing.T, root *CA, w *CA, name string) Record {
	t.Helper()
	key := KeyHashOf(w.Cert)
	dev := DeviceID(strings.TrimPrefix(w.Cert.Subject.CommonName, "cbb admin "))
	r, err := signRecord(RecordBody{Type: RecordDevice, Group: Tag(root.Cert), TimeMS: nextTime(), Device: string(dev), Name: name, Role: RoleWatch, OS: OSWatchOS, Key: &key, Admin: &key,
		Powers: []string{authority.PowerFreeze, authority.PowerRemove}, Commands: []string{CommandAction, CommandActionsOff, CommandAwayOff, CommandPasteOff}, Store: StoreHardware}, root.Key)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type watchVectors struct {
	Cases []watchCase `json:"cases"`
}

type watchCase struct {
	Name     string          `json:"name"`
	GroupCA  []byte          `json:"group_ca"`
	Records  []Record        `json:"records"`
	Dropped  int             `json:"dropped,omitempty"` // records that stay out of the set
	Devices  []watchDevice   `json:"devices"`
	Keys     []watchKey      `json:"keys"`
	Chains   []rootChain     `json:"chains,omitempty"`
	Roots    [][]byte        `json:"roots,omitempty"` // the roots after the group CA
	Hubs     []DeviceID      `json:"hubs"`
	Self     DeviceID        `json:"self,omitempty"`
	NowMS    int64           `json:"now_ms,omitempty"`
	Commands []commandVector `json:"commands,omitempty"`
	Digest   string          `json:"digest"`
}

type watchDevice struct {
	ID    DeviceID `json:"id"`
	Name  string   `json:"name"`
	Role  string   `json:"role"`
	Admin bool     `json:"admin"`
}

type watchKey struct {
	Name    string  `json:"name"`
	Key     KeyHash `json:"key"`
	Revoked bool    `json:"revoked"`
	Frozen  bool    `json:"frozen"`
	Watch   bool    `json:"watch"`
}

// What each case of v2-watch.json must say, whatever the file holds.
var (
	wantWatchRevoked = map[string]map[string]bool{
		"phone root":    {"the laptop": true},
		"frozen watch":  {"the laptop": true},
		"computer root": {},
	}
	wantWatchFrozen = map[string]map[string]bool{
		"phone root":    {"pc1": true, "pc1's device": true},
		"frozen watch":  {"the watch": true},
		"computer root": {},
	}
)

// TestGoWatchVectors checks what a watch's admin key may do: the powers and
// commands the root's record gives it (docs/protocol.md, section 10, "Who signs
// what"). In a phone's group the watch freezes an admin computer and
// removes an ordinary device, but neither removes an admin, admits a
// device, certifies one, is a hub, nor signs more than the commands that
// turn things off and run quick actions; an admin computer freezes it, and
// an admin computer does not remove it. In a group whose root is a
// computer, a watch does not take the group over. With -update it writes
// the cases as testdata/interop/v2-watch.json, which the Rust core reads.
func TestGoWatchVectors(t *testing.T) {
	var v watchVectors
	for _, name := range []string{"phone root", "frozen watch", "computer root"} {
		v.Cases = append(v.Cases, makeWatchCase(t, name))
	}
	writeV2Vectors(t, "v2-watch.json", v)
	for _, c := range v.Cases {
		for _, cmd := range c.Commands {
			body, err := parseCommandBody(cmd.Command.Body)
			if err != nil {
				t.Fatal(err)
			}
			if cmd.OK != (WatchCommand(body.Type) || cmd.Name == "away-off from the root") {
				t.Errorf("%s: %s: ok %v", c.Name, cmd.Name, cmd.OK)
			}
		}
	}
	for _, c := range v.Cases {
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		s := NewRecords(ca)
		rs := slices.Clone(c.Records)
		slices.Reverse(rs)
		if _, errs := s.AddAll(rs); len(errs) != c.Dropped {
			t.Errorf("%s: %d records left out, in order %d: %v", c.Name, len(errs), c.Dropped, errs)
		}
		if s.Digest() != c.Digest {
			t.Errorf("%s: the digest differs", c.Name)
		}
		if got, want := mustJSON(t, watchDevices(s)), mustJSON(t, c.Devices); got != want {
			t.Errorf("%s: devices %s, the file has %s", c.Name, got, want)
		}
		for _, k := range c.Keys {
			got := watchKey{Name: k.Name, Key: k.Key, Revoked: s.Revoked(k.Key), Frozen: s.Frozen(k.Key), Watch: s.Watch(k.Key)}
			if got != k {
				t.Errorf("%s: %s is %+v, the file says %+v", c.Name, k.Name, got, k)
			}
			if k.Revoked != wantWatchRevoked[c.Name][k.Name] || k.Frozen != wantWatchFrozen[c.Name][k.Name] || k.Watch != (k.Name == "the watch") {
				t.Errorf("%s: the file says %+v", c.Name, k)
			}
		}
		for _, ch := range c.Chains {
			var chain []*x509.Certificate
			for _, der := range ch.Chain {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				chain = append(chain, cert)
			}
			if (s.Refused(chain) != nil) != ch.Refused || ch.Refused != (ch.Name == "a device the watch certified") {
				t.Errorf("%s: %s refused %v, the file says %v", c.Name, ch.Name, s.Refused(chain) != nil, ch.Refused)
			}
		}
		var roots [][]byte
		for _, r := range s.Roots() {
			roots = append(roots, r.Raw)
		}
		if mustJSON(t, roots) != mustJSON(t, c.Roots) || len(c.Roots) != 0 {
			t.Errorf("%s: %d roots after the group CA, the file has %d", c.Name, len(roots), len(c.Roots))
		}
		if got, want := mustJSON(t, s.HubOrder()), mustJSON(t, c.Hubs); got != want {
			t.Errorf("%s: hubs %s, the file has %s", c.Name, got, want)
		}
		for _, d := range s.Devices() {
			if d.Role == RoleWatch && (slices.Contains(c.Hubs, d.ID) || s.MayHost(d.ID)) {
				t.Errorf("%s: the watch may be a hub", c.Name)
			}
		}
		l := s.CredentialLists()
		for _, k := range c.Keys {
			if k.Watch && (slices.Contains(l.Admins, k.Key) || slices.Contains(l.Members, k.Key) || slices.Contains(l.Hubs, k.Key)) {
				t.Errorf("%s: a server credential lists the watch", c.Name)
			}
		}
		for _, cmd := range c.Commands {
			_, err := s.VerifyCommand(cmd.Command, c.Self, time.UnixMilli(c.NowMS))
			if (err == nil) != cmd.OK {
				t.Errorf("%s: %s: VerifyCommand = %v, the file says ok %v", c.Name, cmd.Name, err, cmd.OK)
			}
		}
	}
}

func watchDevices(s *Records) []watchDevice {
	var out []watchDevice
	for _, d := range s.Devices() {
		out = append(out, watchDevice{ID: d.ID, Name: d.Name, Role: d.Role, Admin: d.Admin})
	}
	return out
}

func makeWatchCase(t *testing.T, name string) watchCase {
	t.Helper()
	pg := newPhoneGroup(t)
	g := pg.root.Cert
	w, pc1, pc2 := adminCA(t, pg.root), pg.a, pg.b
	wChain, pc2Chain := []*x509.Certificate{w.Cert}, []*x509.Certificate{pc2.Cert}
	wKey, pc1Key, pc2Key := KeyHashOf(w.Cert), KeyHashOf(pc1.Cert), KeyHashOf(pc2.Cert)
	holder, m1, m2, laptop, tablet, tv := member(t, pg.root), member(t, pc1), member(t, pc2), member(t, pg.root), member(t, pg.root), member(t, w)
	rootRole := RolePhone
	if name == "computer root" {
		rootRole = RoleMember
	}
	all := []Record{
		ownRecord(t, pg.root, holder, "root", rootRole),
		watchRecord(t, pg.root, w, "watch"),
		computerAdminRecord(t, pg, m1, "pc1", pc1Key),
		computerAdminRecord(t, pg, m2, "pc2", pc2Key),
		deviceRecord(t, g, pg.root, nil, laptop, "laptop", 2),
		deviceRecord(t, g, pg.root, nil, tablet, "tablet", 2),
	}
	c := watchCase{Name: name, GroupCA: g.Raw}
	keys := []struct {
		name string
		key  KeyHash
	}{
		{"the root", KeyHashOf(g)}, {"the watch", wKey}, {"pc1", pc1Key}, {"pc1's device", KeyHashOf(m1)},
		{"pc2", pc2Key}, {"the laptop", KeyHashOf(laptop)}, {"the tablet", KeyHashOf(tablet)},
	}
	switch name {
	case "phone root":
		all = append(all,
			// It freezes an admin computer and removes an ordinary device.
			freezeRecord(t, g, w, wChain, []KeyHash{pc1Key}),
			revokeRecord(t, g, w, wChain, []KeyHash{KeyHashOf(laptop)}),
			// It removes no admin, admits nobody and thaws nothing.
			revokeRecord(t, g, w, wChain, []KeyHash{pc2Key}),
			deviceRecord(t, g, w, wChain, tv, "tv", 3),
			// An admin computer does not remove it.
			revokeRecord(t, g, pc2, pc2Chain, []KeyHash{wKey}),
		)
		c.Chains = append(c.Chains, rootChain{Name: "a device the watch certified", Chain: [][]byte{tv.Raw, w.Cert.Raw}},
			rootChain{Name: "the tablet", Chain: [][]byte{tablet.Raw}})
		self := member(t, pg.root)
		c.Self = DeviceID(self.Subject.CommonName)
		all = append(all, deviceRecord(t, g, pg.root, nil, self, "my computer", 1))
		c.NowMS = 1_800_000_000_000
		known := NewRecords(g)
		known.AddAll(all)
		cmd := func(signer *CA, chain []*x509.Certificate, typ string) Record {
			b := CommandBody{Type: typ, Group: Tag(g), By: c.Self, To: c.Self, ID: NewCommandID(), TimeMS: c.NowMS, ExpiresMS: c.NowMS + CommandLifetime.Milliseconds()}
			switch typ {
			case CommandMode:
				b.Mode = "own"
			case CommandPaste:
				b.Mode, b.Kind, b.Text = PasteByClipboard, "text", "ls"
			case CommandAction:
				b.Action = "lock"
			}
			r, err := SignCommand(b, signer.Key, chain...)
			if err != nil {
				t.Fatal(err)
			}
			// A command's by is its signer's device when the records show it.
			if dev, _, ok := known.CommandSigner(r); ok && dev.ID != b.By {
				b.By = dev.ID
				if r, err = SignCommand(b, signer.Key, chain...); err != nil {
					t.Fatal(err)
				}
			}
			return r
		}
		for _, typ := range []string{CommandPasteOff, CommandActionsOff, CommandAwayOff, CommandAction, CommandMode, CommandPaste} {
			c.Commands = append(c.Commands, commandVector{Name: typ + " from the watch", Command: cmd(w, wChain, typ), OK: WatchCommand(typ)})
		}
		c.Commands = append(c.Commands, commandVector{Name: "away-off from the root", Command: cmd(pg.root, nil, CommandAwayOff), OK: true})
	case "frozen watch":
		// An admin computer freezes the watch, keeping what it did before.
		before := revokeRecord(t, g, w, wChain, []KeyHash{KeyHashOf(laptop)})
		freeze := freezeRecord(t, g, pc2, pc2Chain, []KeyHash{wKey})
		all = append(all, before, freeze,
			// What the watch removes once it is frozen does not count, nor
			// does an admin computer's thaw of it.
			revokeRecord(t, g, w, wChain, []KeyHash{KeyHashOf(tablet)}),
			thawRecord(t, g, pc1, []*x509.Certificate{pc1.Cert}, []KeyHash{freeze.ID()}),
		)
	case "computer root":
		// The watch claims the group for a root of its own; nothing signed
		// under that root counts.
		next := newRoot(t)
		all = append(all,
			claimRecord(t, g, w, wChain, next.Cert),
			revokeRecord(t, g, next, nil, []KeyHash{KeyHashOf(holder), KeyHashOf(laptop)}),
		)
	}
	s := NewRecords(g)
	_, errs := s.AddAll(all)
	s.SetClock(afterDelay)
	c.Records, c.Dropped, c.Digest = all, len(errs), s.Digest()
	c.Devices, c.Hubs = watchDevices(s), s.HubOrder()
	if c.Hubs == nil {
		c.Hubs = []DeviceID{}
	}
	for _, k := range keys {
		c.Keys = append(c.Keys, watchKey{Name: k.name, Key: k.key, Revoked: s.Revoked(k.key), Frozen: s.Frozen(k.key), Watch: s.Watch(k.key)})
	}
	for i, ch := range c.Chains {
		var chain []*x509.Certificate
		for _, der := range ch.Chain {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			chain = append(chain, cert)
		}
		c.Chains[i].Refused = s.Refused(chain) != nil
	}
	return c
}
