// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/blind"
)

// FuzzForwardWire routes the packets anyone may send to the forwarder's
// UDP port, from a stranger and from a registered hub's endpoint: a packet
// goes only to an endpoint the forwarder knows, and none makes it panic.
func FuzzForwardWire(f *testing.F) {
	var pub [32]byte
	f.Add(initiation(pub, 1))
	f.Add(make([]byte, responseSize))
	f.Add(make([]byte, cookieSize))
	f.Add(append([]byte{msgData, 0, 0, 0}, make([]byte, dataMinSize)...))
	f.Add(make([]byte, helloMin))
	cert, _ := NewCert()
	fw, err := Listen(Config{Listen: "127.0.0.1:0", Cert: cert})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { fw.Close() })
	hubA, hubB := netip.MustParseAddrPort("198.51.100.1:8764"), netip.MustParseAddrPort("198.51.100.2:8764")
	_, pubA := fakeReg(fw, "a", hubA)
	fakeReg(fw, "b", hubB)
	f.Add(initiation(pubA, 7))
	client := netip.MustParseAddrPort("203.0.113.5:40000")
	now := time.Now()
	f.Fuzz(func(t *testing.T, p []byte) {
		messageType(p)
		if h, ok := openHello(&fw.mask, p); ok {
			readHello(h)
		}
		for _, from := range []netip.AddrPort{client, hubA} {
			to, ok := fw.route(from, append([]byte{}, p...), now)
			if ok && to != hubA && to != hubB && to != client {
				t.Fatalf("a packet from %v went to %v", from, to)
			}
		}
	})
}

// FuzzRegister reads any frame as the forwarder reads a hub's
// registration and as a hub reads the forwarder's answers, seeded with the
// format's messages of cbb-forward/3 (testdata/format/messages3.json):
// nothing panics, a registration taken is written again by the hub's
// writer as one that reads back the same, and an answer taken is written
// again as the same message.
func FuzzRegister(f *testing.F) {
	take, refuse := forwarderRows(f)
	for _, r := range append(take, refuse...) {
		b, err := hex.DecodeString(r.Message)
		if err != nil {
			f.Fatal(err)
		}
		v, err := blind.Decode(b)
		if err != nil {
			continue
		}
		f.Add(blind.WriteFrame(v.Map...)[4:])
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ty, m, err := blind.Message(b)
		if err != nil {
			return
		}
		if r, err := readRegister(ty, m); err == nil {
			again, err := msgRegister(*r)
			if err != nil {
				t.Fatalf("a registration taken is not written again: %v", err)
			}
			ty2, m2, err := blind.Message(again[4:])
			if err != nil {
				t.Fatalf("written again as a frame that breaks the format: %v", err)
			}
			r2, err := readRegister(ty2, m2)
			if err != nil || r2.Key != r.Key || r2.Proof != r.Proof || r2.VLESS != r.VLESS ||
				r2.BadObfuscation != r.BadObfuscation || len(r2.Credentials) != len(r.Credentials) {
				t.Fatalf("written again, reads as %+v, %v; was %+v", r2, err, r)
			}
			for i := range r.Credentials {
				if !bytes.Equal(r.Credentials[i], r2.Credentials[i]) {
					t.Fatalf("credential %d written again differs", i)
				}
			}
		}
		a, err := readAnswer(ty, m)
		if err != nil {
			return
		}
		var again []byte
		switch ty {
		case tError:
			again = msgError(a.Error)
		case tSeen:
			again = msgSeen(netip.MustParseAddrPort(a.Seen))
		default:
			return
		}
		_, m2, err := blind.Message(again[4:])
		if err != nil {
			t.Fatalf("an answer written again breaks the format: %v", err)
		}
		a2, err := readAnswer(ty, m2)
		if a.Error == "" || len(a.Error) > maxReason {
			// The forwarder writes no empty reason, nor a longer one.
			a.Error = a2.Error
		}
		if err != nil || a2.Error != a.Error || a2.Seen != a.Seen {
			t.Fatalf("an answer written again reads as %+v, %v; was %+v", a2, err, a)
		}
	})
}
