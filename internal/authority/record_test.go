// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
	"github.com/HunterEwok/clipboardbridge/internal/group"
	"github.com/HunterEwok/clipboardbridge/internal/seal"
)

const tag = "0123456789abcdef"

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func hashOf(t *testing.T, pub crypto.PublicKey) authority.Hash {
	t.Helper()
	h, err := authority.PublicKeyHash(pub)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fixture is a root and one admin CA under it.
type fixture struct {
	root     *group.CA
	adminKey *ecdsa.PrivateKey
	adminCA  *x509.Certificate
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Now()
	root, err := group.NewRootCA(now)
	if err != nil {
		t.Fatal(err)
	}
	ak := newKey(t)
	ca, err := root.IssueAdmin(group.NewDeviceID(), &ak.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{root: root, adminKey: ak, adminCA: ca}
}

func (f fixture) rootKey(h authority.Hash) crypto.PublicKey {
	if authority.KeyHashOf(f.root.Cert) == h {
		return f.root.Cert.PublicKey
	}
	return nil
}

func ptr[T any](v T) *T { return &v }

func deviceBody(t *testing.T) authority.Body {
	k := hashOf(t, &newKey(t).PublicKey)
	return authority.Body{Type: authority.TypeDevice, Group: tag, Seq: 1, TimeMS: 1, Device: string(group.NewDeviceID()), Name: "Laptop", Role: "full", OS: "linux", Key: &k}
}

func TestSignVerify(t *testing.T) {
	f := newFixture(t)
	k := hashOf(t, &newKey(t).PublicKey)
	prev := authority.Hash{1}
	bodies := []authority.Body{
		deviceBody(t),
		{Type: authority.TypeDevice, Group: tag, Seq: 2, Prev: &prev, TimeMS: 5, Device: strings.Repeat("a", 32), Name: "Phone", Role: "phone", Key: &k, Admin: &k,
			Powers: []string{authority.PowerTakeover, authority.PowerAdmit}, Commands: []string{"paste", "mode"}, HoldsRoot: true},
		func() authority.Body {
			b := deviceBody(t)
			b.Seal = sealKey(t)
			return b
		}(),
		{Type: authority.TypeRevoke, Group: tag, Seq: 1, Keys: []authority.Hash{{3}, {2}}, Seen: []authority.Seen{{Key: authority.Hash{9}, Seq: 0}, {Key: authority.Hash{4}, Seq: 7}}},
		{Type: authority.TypeFreeze, Group: tag, Seq: 1, Keys: []authority.Hash{{2}}, Seen: []authority.Seen{{Key: authority.Hash{2}, Seq: 3}}},
		{Type: authority.TypeThaw, Group: tag, Seq: 1, Records: []authority.Hash{{5}}},
		{Type: authority.TypeClaim, Group: tag, Seq: 1, Root: f.root.Cert.Raw, Seen: []authority.Seen{{Key: authority.Hash{2}, Seq: 3}}},
		{Type: authority.TypeResolve, Group: tag, Seq: 1, Records: []authority.Hash{{5}, {6}}},
		{Type: authority.TypeSettings, Group: tag, Seq: 1, TakeoverDelayMS: ptr(int64(0))},
		{Type: authority.TypeSettings, Group: tag, Seq: 1},
		{Type: authority.TypeSettings, Group: tag, Seq: 1, KeyLevel: "files"},
		{Type: authority.TypeCheckpoint, Group: tag, Seq: 1, Heads: []authority.Head{{Key: authority.Hash{2}, Seq: 4, ID: authority.Hash{7}}, {Key: authority.Hash{1}, Seq: 1, ID: authority.Hash{8}}}},
		bigCheckpoint(),
		{Type: authority.TypeHubs, Group: tag, Seq: 1, Hubs: []string{strings.Repeat("b", 32), strings.Repeat("a", 32)}},
		{Type: authority.TypeRecovery, Group: tag, Seq: 1, Admin: ptr(authority.KeyHashOf(f.adminCA)), Cert: f.adminCA.Raw},
		{Type: authority.TypeHandover, Group: tag, Seq: 1, Admin: &authority.Hash{6}},
	}
	for _, b := range bodies {
		for _, admin := range []bool{false, true} {
			key, ca := crypto.Signer(f.root.Key), (*x509.Certificate)(nil)
			if admin {
				key, ca = f.adminKey, f.adminCA
			}
			r, err := authority.Sign(b, key, ca)
			if err != nil {
				t.Fatalf("%s: %v", b.Type, err)
			}
			s, err := authority.Verify(r, f.rootKey)
			if err != nil {
				t.Fatalf("%s %s: %v", b.Type, r.Body, err)
			}
			if s.ID != r.ID() || (s.AdminCA != nil) != admin {
				t.Errorf("%s: wrong ID or admin CA", b.Type)
			}
		}
	}
}

func TestVerifyRefuses(t *testing.T) {
	f := newFixture(t)
	r, err := authority.Sign(deviceBody(t), f.adminKey, f.adminCA)
	if err != nil {
		t.Fatal(err)
	}
	other := newFixture(t)
	for name, mod := range map[string]func(authority.Record) authority.Record{
		"another admin CA": func(r authority.Record) authority.Record {
			r.Chain = [][]byte{other.adminCA.Raw}
			return r
		},
		"no chain, not a root": func(r authority.Record) authority.Record {
			r.Chain = nil
			return r
		},
		"two in the chain": func(r authority.Record) authority.Record {
			r.Chain = append(r.Chain, f.root.Cert.Raw)
			return r
		},
		"a bad signature": func(r authority.Record) authority.Record {
			r.Sig = append([]byte{}, r.Sig...)
			r.Sig[len(r.Sig)-1] ^= 1
			return r
		},
	} {
		if _, err := authority.Verify(mod(r), f.rootKey); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	// The root's own key signs with an empty chain; claiming the admin CA
	// as signer with the root's signature fails.
	rr, err := authority.Sign(deviceBody(t), f.root.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	rr.Chain = [][]byte{f.adminCA.Raw}
	if _, err := authority.Verify(rr, f.rootKey); err == nil {
		t.Error("a root's body under an admin CA is taken")
	}
}

func TestParseBodyRefuses(t *testing.T) {
	f := newFixture(t)
	r, err := authority.Sign(deviceBody(t), f.root.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	good := string(r.Body)
	if _, err := authority.ParseBody([]byte(good)); err != nil {
		t.Fatalf("the signed body %s is refused: %v", good, err)
	}
	insert := func(field string) string { return strings.Replace(good, `"group"`, field+`,"group"`, 1) }
	for name, body := range map[string]string{
		"an unknown field":           strings.Replace(good, `{`, `{"aaa":1,`, 1),
		"a field of another type":    insert(`"keys":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]`),
		"an empty field":             strings.Replace(good, `"device"`, `"commands":[],"device"`, 1),
		"an empty string":            insert(`"admin":""`),
		"holds_root false":           strings.Replace(good, `"key"`, `"holds_root":false,"key"`, 1),
		"not canonical":              strings.Replace(good, `{`, `{ `, 1),
		"version 1":                  strings.Replace(good, `"v":2`, `"v":1`, 1),
		"another algorithm":          strings.Replace(good, `"alg":"es256"`, `"alg":"es384"`, 1),
		"no algorithm":               strings.Replace(good, `"alg":"es256",`, ``, 1),
		"seq 0":                      strings.Replace(good, `"seq":1`, `"seq":0`, 1),
		"seq 2 without prev":         strings.Replace(good, `"seq":1`, `"seq":2`, 1),
		"an unknown role":            strings.Replace(good, `"role":"full"`, `"role":"linux"`, 1),
		"an unknown os":              strings.Replace(good, `"os":"linux"`, `"os":"beos"`, 1),
		"powers without admin":       strings.Replace(good, `"role"`, `"powers":["admit"],"role"`, 1),
		"a name with a control char": strings.Replace(good, `"Laptop"`, `"Lap\u0007top"`, 1),
	} {
		if body == good {
			t.Fatalf("%s: the body did not change", name)
		}
		if _, err := authority.ParseBody([]byte(body)); err == nil {
			t.Errorf("%s: %s is taken", name, body)
		}
	}
	if _, err := authority.ParseBody([]byte(strings.Replace(good, `"Laptop"`, `"`+strings.Repeat("x", 9000)+`"`, 1))); err == nil {
		t.Error("a body over 8 KiB is taken")
	}
}

// bigCheckpoint is a checkpoint over MaxBody and under MaxCheckpointBody.
func bigCheckpoint() authority.Body {
	b := authority.Body{Type: authority.TypeCheckpoint, Group: tag, Seq: 1, Heads: []authority.Head{{Key: authority.Hash{1}, Seq: 1, ID: authority.Hash{2}}}}
	for i := 0; i < 400; i++ {
		b.Keep = append(b.Keep, authority.Hash{byte(i), byte(i >> 8)})
	}
	return b
}

func TestSignRefuses(t *testing.T) {
	f := newFixture(t)
	for name, b := range map[string]authority.Body{
		"unsorted powers twice": func() authority.Body {
			b := deviceBody(t)
			b.Admin, b.Powers = b.Key, []string{"admit", "admit"}
			return b
		}(),
		"an unknown power": func() authority.Body {
			b := deviceBody(t)
			b.Admin, b.Powers = b.Key, []string{"everything"}
			return b
		}(),
		"a delay over 7 days":            {Type: authority.TypeSettings, Group: tag, Seq: 1, TakeoverDelayMS: ptr(int64(authority.MaxDelay + 1))},
		"a negative delay":               {Type: authority.TypeSettings, Group: tag, Seq: 1, TakeoverDelayMS: ptr(int64(-1))},
		"an unknown key level":           {Type: authority.TypeSettings, Group: tag, Seq: 1, KeyLevel: "tpm"},
		"revoke without seen":            {Type: authority.TypeRevoke, Group: tag, Seq: 1, Keys: []authority.Hash{{1}}},
		"a claim without root":           {Type: authority.TypeClaim, Group: tag, Seq: 1, Seen: []authority.Seen{{Key: authority.Hash{1}}}},
		"seen twice":                     {Type: authority.TypeRevoke, Group: tag, Seq: 1, Keys: []authority.Hash{{1}}, Seen: []authority.Seen{{Key: authority.Hash{1}}, {Key: authority.Hash{1}, Seq: 2}}},
		"keys twice":                     {Type: authority.TypeRevoke, Group: tag, Seq: 1, Keys: []authority.Hash{{1}, {1}}, Seen: []authority.Seen{{Key: authority.Hash{1}}}},
		"an unknown type":                {Type: "root", Group: tag, Seq: 1},
		"a checkpoint without heads":     {Type: authority.TypeCheckpoint, Group: tag, Seq: 1, Keep: []authority.Hash{{1}}},
		"a head with seq 0":              {Type: authority.TypeCheckpoint, Group: tag, Seq: 1, Heads: []authority.Head{{Key: authority.Hash{1}, ID: authority.Hash{2}}}},
		"heads twice":                    {Type: authority.TypeCheckpoint, Group: tag, Seq: 1, Heads: []authority.Head{{Key: authority.Hash{1}, Seq: 1}, {Key: authority.Hash{1}, Seq: 2}}},
		"hubs empty":                     {Type: authority.TypeHubs, Group: tag, Seq: 1},
		"hubs twice":                     {Type: authority.TypeHubs, Group: tag, Seq: 1, Hubs: []string{strings.Repeat("a", 32), strings.Repeat("a", 32)}},
		"a hub not a device ID":          {Type: authority.TypeHubs, Group: tag, Seq: 1, Hubs: []string{strings.Repeat("A", 32)}},
		"a recovery without admin":       {Type: authority.TypeRecovery, Group: tag, Seq: 1},
		"a recovery with a key":          {Type: authority.TypeRecovery, Group: tag, Seq: 1, Admin: &authority.Hash{6}, Key: &authority.Hash{7}},
		"a recovery without cert":        {Type: authority.TypeRecovery, Group: tag, Seq: 1, Admin: &authority.Hash{6}},
		"a recovery cert of another key": {Type: authority.TypeRecovery, Group: tag, Seq: 1, Admin: &authority.Hash{6}, Cert: f.adminCA.Raw},
		"a handover without admin":       {Type: authority.TypeHandover, Group: tag, Seq: 1},
		"a handover with seen":           {Type: authority.TypeHandover, Group: tag, Seq: 1, Admin: &authority.Hash{6}, Seen: []authority.Seen{{Key: authority.Hash{2}, Seq: 3}}},
		"17 hubs": func() authority.Body {
			b := authority.Body{Type: authority.TypeHubs, Group: tag, Seq: 1}
			for i := range authority.MaxHubs + 1 {
				b.Hubs = append(b.Hubs, fmt.Sprintf("%032x", i))
			}
			return b
		}(),
		"a seal one byte short": func() authority.Body {
			b := deviceBody(t)
			b.Seal = sealKey(t)[1:]
			return b
		}(),
		"a seal one byte long": func() authority.Body {
			b := deviceBody(t)
			b.Seal = append(sealKey(t), 0)
			return b
		}(),
		"a seal on a revoke": {Type: authority.TypeRevoke, Group: tag, Seq: 1, Keys: []authority.Hash{{1}}, Seen: []authority.Seen{{Key: authority.Hash{1}}}, Seal: make([]byte, authority.SealKeySize)},
		"a device over 8 KiB": func() authority.Body {
			b := deviceBody(t)
			b.Proof = strings.Repeat("a", authority.MaxBody)
			return b
		}(),
		"a checkpoint over 64 KiB": func() authority.Body {
			b := bigCheckpoint()
			for len(b.Keep)*40 < authority.MaxCheckpointBody {
				b.Keep = append(b.Keep, authority.Hash{byte(len(b.Keep)), byte(len(b.Keep) >> 8), 1})
			}
			return b
		}(),
	} {
		if _, err := authority.Sign(b, f.root.Key, nil); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// sealKey returns a new public key for sealed messages.
func sealKey(t *testing.T) []byte {
	t.Helper()
	secret, err := seal.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	k, err := seal.PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestSealKeySize keeps the records' size of a seal that of internal/seal.
func TestSealKeySize(t *testing.T) {
	if authority.SealKeySize != seal.PublicKeySize {
		t.Fatalf("SealKeySize %d, seal.PublicKeySize %d", authority.SealKeySize, seal.PublicKeySize)
	}
}
