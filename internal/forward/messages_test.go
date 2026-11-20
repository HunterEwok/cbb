// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/HunterEwok/cbb/internal/blind"
)

// formatRow is a row of testdata/format/messages3.json.
type formatRow struct {
	Name    string `json:"name"`
	T       uint64 `json:"t"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// forwarderRows are the vectors' rows of the forwarder's messages.
func forwarderRows(t testing.TB) (take, refuse []formatRow) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "format", "messages3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ Take, Refuse []formatRow }
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, r := range v.Take {
		if r.T >= tChallenge && r.T <= tSeen {
			take = append(take, r)
		}
	}
	for _, r := range v.Refuse {
		if len(r.Rule) > 8 && r.Rule[:8] == "forward/" {
			refuse = append(refuse, r)
		}
	}
	return take, refuse
}

// unpadded is a frame's message without its padding, as the vectors write
// it.
func unpadded(t *testing.T, frame []byte) []byte {
	t.Helper()
	_, m, err := blind.Message(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	var out []blind.Pair
	for _, p := range m.Map {
		if p.Key != 1 {
			out = append(out, p)
		}
	}
	return blind.Encode(blind.Map(out...))
}

// TestForwarderVectors holds the forwarder's messages to the format's
// vectors (testdata/format/messages3.json): each message taken reads, and
// the forwarder's and the hub's writers give it again byte for byte; each
// refused one is refused by its rule.
func TestForwarderVectors(t *testing.T) {
	take, refuse := forwarderRows(t)
	if len(take) < 5 || len(refuse) < 2 {
		t.Fatalf("%d rows taken and %d refused: the vectors lost the forwarder's", len(take), len(refuse))
	}
	seenTypes := map[uint64]bool{}
	for _, r := range take {
		b, err := hex.DecodeString(r.Message)
		if err != nil {
			t.Fatal(err)
		}
		m, err := blind.Decode(b)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		seenTypes[r.T] = true
		var again []byte
		switch r.T {
		case tChallenge:
			e, _ := m.Get(2)
			again = msgChallenge(e.Bytes)
		case tRegister:
			reg, err := readRegister(r.T, m)
			if err != nil {
				t.Fatalf("%s: %v", r.Name, err)
			}
			// The format takes any settings of its table; the forwarder
			// refuses the ones it cannot route by, as unusable.
			if _, ok := m.Get(4); ok && (reg.Obfuscation == nil || reg.BadObfuscation != (reg.Obfuscation.Check() != nil)) {
				t.Fatalf("%s: obfuscation %+v, unusable %v", r.Name, reg.Obfuscation, reg.BadObfuscation)
			}
			if again, err = msgRegister(*reg); err != nil {
				t.Fatalf("%s: %v", r.Name, err)
			}
		default:
			a, err := readAnswer(r.T, m)
			if err != nil {
				t.Fatalf("%s: %v", r.Name, err)
			}
			switch r.T {
			case tRegistered:
				var w *way
				if a.VLESS != nil {
					w = a.VLESS
					if _, ok := m.Get(4); ok {
						if p, _ := m.Get(4); !hasField(p, 2) {
							w.Port = 0 // written only when the vector writes it
						}
					}
				}
				again = msgRegistered(a.ID, a.Mask, w)
			case tError:
				again = msgError(a.Error)
			case tSeen:
				again = msgSeen(netip.MustParseAddrPort(a.Seen))
			}
		}
		if got := unpadded(t, again); !bytes.Equal(got, b) {
			t.Errorf("%s: written again as\n%x\nwant\n%x", r.Name, got, b)
		}
	}
	for _, ty := range []uint64{tChallenge, tRegister, tRegistered, tError, tSeen} {
		if !seenTypes[ty] {
			t.Errorf("no vector of t %d", ty)
		}
	}
	for _, r := range refuse {
		b, err := hex.DecodeString(r.Message)
		if err != nil {
			t.Fatal(err)
		}
		m, err := blind.Decode(b)
		if err != nil {
			if string(blind.Rule(r.Rule)) != err.Error() {
				t.Errorf("%s: %v, want %s", r.Name, err, r.Rule)
			}
			continue
		}
		tv, _ := m.Get(blind.FieldT)
		if tv.Uint == tRegister {
			_, err = readRegister(tv.Uint, m)
		} else {
			_, err = readAnswer(tv.Uint, m)
		}
		if err == nil || err.Error() != r.Rule {
			t.Errorf("%s: %v, want %s", r.Name, err, r.Rule)
		}
	}
}

func hasField(v blind.Value, k uint16) bool {
	_, ok := v.Get(k)
	return ok
}

// TestSeenWrittenOnce checks that the forwarder writes where it sees a hub
// in the one form a hub takes, whatever form it holds the address in.
func TestSeenWrittenOnce(t *testing.T) {
	for _, s := range []string{"198.51.100.7:40000", "[::ffff:198.51.100.7]:40000", "[2001:db8::7%eth0]:40000", "[2001:db8:0:0:0:0:0:7]:40000"} {
		frame := msgSeen(netip.MustParseAddrPort(s))
		_, m, err := blind.Message(frame[4:])
		if err != nil {
			t.Fatal(err)
		}
		a, err := readAnswer(tSeen, m)
		if err != nil {
			t.Errorf("%s written as one a hub refuses: %v", s, err)
			continue
		}
		if !canonicalAddr(a.Seen) {
			t.Errorf("%s written as %q", s, a.Seen)
		}
	}
}

// TestObfuscationVectors holds the forwarder's reader of the table
// `obfuscation` to the format's vectors (messages3.json, "maps"): it takes
// the settings the format takes and refuses the others.
func TestObfuscationVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "format", "messages3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Maps []struct {
			Name, Table, Value, Rule string
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range v.Maps {
		if r.Table != "obfuscation" {
			continue
		}
		n++
		raw, err := hex.DecodeString(r.Value)
		if err != nil {
			t.Fatal(err)
		}
		m, err := blind.Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if o, _ := obfuscationOf(m); (o != nil) != (r.Rule == "") {
			t.Errorf("%s: read as %+v, the format's rule %q", r.Name, o, r.Rule)
		}
	}
	if n < 3 {
		t.Fatalf("%d vectors of the table obfuscation", n)
	}
}
