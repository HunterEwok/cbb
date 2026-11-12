// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
)

// heads keeps, for each signer of the tests, the record it signed last
// and the group of it, so that the records a test signs one after another
// form the chains of version 2 (docs/protocol.md, section 10, "Chains and numbers").
var heads = struct {
	sync.Mutex
	m     map[KeyHash]authority.Head
	group map[KeyHash]string
}{m: map[KeyHash]authority.Head{}, group: map[KeyHash]string{}}

// signRecord signs body as the next record of key for the tests: seq and
// prev follow the key's last test record, and a removal, freeze or claim
// saw every record signed for its group until now. adminCA, if any, is the
// first of chain.
func signRecord(body RecordBody, key crypto.Signer, chain ...*x509.Certificate) (Record, error) {
	signer, err := authority.PublicKeyHash(key.Public())
	if err != nil {
		return Record{}, err
	}
	heads.Lock()
	defer heads.Unlock()
	h := heads.m[signer]
	body.Seq = h.Seq + 1
	if h.Seq > 0 {
		prev := h.ID
		body.Prev = &prev
	}
	switch body.Type {
	case RecordRevoke, RecordFreeze, RecordClaim:
		if body.Seen == nil {
			body.Seen = []authority.Seen{{Key: signer, Seq: h.Seq}}
			for k, o := range heads.m {
				if k != signer && heads.group[k] == body.Group {
					body.Seen = append(body.Seen, authority.Seen{Key: k, Seq: o.Seq})
				}
			}
		}
	}
	var adminCA *x509.Certificate
	if len(chain) > 0 {
		adminCA = chain[0]
	}
	r, err := authority.Sign(body, key, adminCA)
	if err != nil {
		return Record{}, err
	}
	heads.m[signer] = authority.Head{Key: signer, Seq: body.Seq, ID: r.ID()}
	heads.group[signer] = body.Group
	return r, nil
}

// v2Case is a case of testdata/interop/v2-records.json.
type v2Case struct {
	Name        string   `json:"name"`
	GroupCA     []byte   `json:"group_ca"`
	Group       string   `json:"group"`
	NowMS       int64    `json:"now_ms"`
	TimeUnknown bool     `json:"time_unknown"`
	Records     []Record `json:"records"`
	FirstSeen   []struct {
		Record KeyHash `json:"record"`
		MS     int64   `json:"ms"`
	} `json:"first_seen"`
	State string `json:"state"`
}

// checkV2Cases checks that a Records set given each case of
// testdata/interop/v2-records.json whose name starts with one of prefixes
// says the case's state, byte for byte: the set's own checks take every
// record of the vectors, and its state is the one rule's (internal/authority).
// A case where the member does not know the time is for the core's tests.
func checkV2Cases(t *testing.T, prefixes ...string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "v2-records.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []v2Case `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range f.Cases {
		if c.TimeUnknown || !slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(c.Name, p) }) {
			continue
		}
		n++
		ca, err := x509.ParseCertificate(c.GroupCA)
		if err != nil {
			t.Fatal(err)
		}
		s := NewRecords(ca)
		s.tag = c.Group
		s.SetClock(func() time.Time { return time.UnixMilli(c.NowMS) })
		// The set leaves out a record that does not verify or is of
		// another group, which the state of the whole input lists as
		// ignored.
		refused := map[string]bool{}
		for _, r := range c.Records {
			if _, err := s.Add(r); err != nil {
				refused[r.ID().String()] = true
			}
		}
		clear(s.firstSeen)
		for _, fs := range c.FirstSeen {
			s.firstSeen[fs.Record] = fs.MS
		}
		s.st = nil
		got, err := s.State().Encode()
		if err != nil {
			t.Fatal(err)
		}
		var gotV, wantV map[string]any
		if json.Unmarshal(got, &gotV) != nil || json.Unmarshal([]byte(c.State), &wantV) != nil {
			t.Fatalf("%s: a state does not read", c.Name)
		}
		if ig, ok := wantV["ignored"].([]any); ok && len(refused) > 0 {
			ig = slices.DeleteFunc(ig, func(e any) bool {
				m, _ := e.(map[string]any)
				id, _ := m["record"].(string)
				return refused[id]
			})
			if len(ig) == 0 {
				delete(wantV, "ignored")
			} else {
				wantV["ignored"] = ig
			}
		}
		if !reflect.DeepEqual(gotV, wantV) || len(refused) == 0 && string(got) != c.State {
			t.Errorf("%s:\n got %s\nwant %s", c.Name, got, c.State)
		}
	}
	if n == 0 {
		t.Fatalf("no case starts with %q", prefixes)
	}
}

// computerPowers are the powers the root gives an admin computer, takeover
// among them when the root is a computer (docs/protocol.md, section 10, "Who signs
// what").
func computerPowers(takeover bool) []string {
	p := []string{authority.PowerAdmit, authority.PowerFreeze, authority.PowerHub, authority.PowerRemove, authority.PowerRenew}
	if takeover {
		p = append(p, authority.PowerTakeover)
	}
	return p
}

// claimRecord is an admin's claim to take the group over with root.
func claimRecord(t *testing.T, group *x509.Certificate, signer *CA, chain []*x509.Certificate, root *x509.Certificate) Record {
	t.Helper()
	r, err := signRecord(RecordBody{Type: RecordClaim, Group: Tag(group), TimeMS: nextTime(), Root: root.Raw}, signer.Key, chain...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// afterDelay returns a clock past the default takeover delay.
func afterDelay() time.Time {
	return time.Now().Add(time.Duration(authority.DefaultDelay+1000) * time.Millisecond)
}

// writeV2Vectors writes v as testdata/interop/name with -update: the
// vectors in records v:2 that the phone kits read once they ask the core.
func writeV2Vectors(t *testing.T, name string, v any) {
	t.Helper()
	if !*update {
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("..", "..", "testdata", "interop", name), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// v1Records signs bodies of version 1 as members before 0.6 wrote them,
// under the group CA root: a device record, a revocation, and the root
// record by which cbb upgrade gave a legacy group a root.
func v1Records(t *testing.T, root *CA) []Record {
	t.Helper()
	tag := Tag(root.Cert)
	dev := NewDeviceID()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	bodies := []string{
		fmt.Sprintf(`{"by":%q,"device":%q,"group":%q,"key":%q,"name":"pi","role":"full","time_ms":1,"type":"device","v":1}`, dev, dev, tag, key),
		fmt.Sprintf(`{"group":%q,"keys":[%q],"time_ms":2,"type":"revoke","v":1}`, tag, key),
		fmt.Sprintf(`{"group":%q,"root":%q,"time_ms":3,"type":"root","v":1}`, tag, base64.StdEncoding.EncodeToString(root.Cert.Raw)),
	}
	var out []Record
	for _, b := range bodies {
		sum := sha256.Sum256([]byte(b))
		sig, err := root.Key.Sign(rand.Reader, sum[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Record{Body: []byte(b), Sig: sig})
	}
	return out
}

// checkV1Refused checks that a set refuses every record of version 1 that
// v1Records signs: there is no migration, and a member that holds records
// of version 1 refuses them (docs/records-v2.md).
func checkV1Refused(t *testing.T) {
	t.Helper()
	root, err := NewRootCA(t0)
	if err != nil {
		t.Fatal(err)
	}
	s := NewRecords(root.Cert)
	for i, r := range v1Records(t, root) {
		if ok, err := s.Add(r); ok || err == nil {
			t.Errorf("record %d of version 1 taken", i)
		}
	}
}
