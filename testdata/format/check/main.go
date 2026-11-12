// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command check reads the vectors of the 0.6 format (testdata/format) with a second,
// independent implementation: fxamacker/cbor for the bytes, Go's crypto for the
// signatures and the container. It checks the format level only (the profile,
// envelopes, signatures, IDs, frames, the copy's signature, the container);
// field rules are left to the implementations.
//
// It is its own Go module, so that the reader it uses (fxamacker/cbor) is
// not one of cbb's dependencies, and the Rust core's tests are checked
// against a reader that shares no code with them.
//
// Run: cd testdata/format/check && go run . ..
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

var (
	dm  cbor.DecMode
	em  cbor.EncMode
	n   = elliptic.P256().Params().N
	bad int
)

func init() {
	var err error
	dm, err = cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  9, // our own walk enforces 8
		MaxArrayElements: 4096,
		MaxMapPairs:      4096,
		UTF8:             cbor.UTF8RejectInvalid,
		IntDec:           cbor.IntDecConvertNone,
		DefaultMapType:   nil,
	}.DecMode()
	must(err)
	em, err = cbor.CoreDetEncOptions().EncMode()
	must(err)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fail(f string, a ...any) {
	bad++
	fmt.Printf("FAIL "+f+"\n", a...)
}

// strict decodes b by the profile and returns the value.
func strict(b []byte) (any, error) {
	if len(b) > 0 {
		// fxamacker decodes a lone break or reserved byte with its own error; fine.
	}
	var v any
	if err := dm.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	if err := walk(v, 0); err != nil {
		return nil, err
	}
	again, err := em.Marshal(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, errors.New("not in deterministic form")
	}
	return v, nil
}

func walk(v any, depth int) error {
	switch x := v.(type) {
	case uint64:
		if x >= 1<<63 {
			return errors.New("int range")
		}
	case []byte, string:
	case []any:
		if depth >= 8 {
			return errors.New("depth")
		}
		for _, e := range x {
			if err := walk(e, depth+1); err != nil {
				return err
			}
		}
	case map[any]any:
		if depth >= 8 {
			return errors.New("depth")
		}
		for k, e := range x {
			ku, ok := k.(uint64)
			if !ok || ku > 65535 {
				return errors.New("map key")
			}
			if err := walk(e, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("type %T not in the profile", v)
	}
	return nil
}

func load(dir, name string, v any) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	must(err)
	must(json.Unmarshal(b, v))
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func es256(key []byte, label string, data, sig []byte) error {
	if len(sig) != 64 {
		return errors.New("signature size")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	half := new(big.Int).Rsh(n, 1)
	if r.Sign() == 0 || r.Cmp(n) >= 0 || s.Sign() == 0 || s.Cmp(half) > 0 {
		return errors.New("signature range or high S")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), key) //nolint:staticcheck
	if x == nil {
		return errors.New("key")
	}
	pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	h := sha256.Sum256(append(append([]byte(label), 0), data...))
	if !ecdsa.Verify(pk, h[:], r, s) {
		return errors.New("verify")
	}
	return nil
}

type keyRow struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	KeyHash string `json:"key_hash"`
	ID16    string `json:"id16"`
}

var byHash = map[string][]byte{} // key hash hex -> pub

func keyHash(k any) ([]byte, []byte, error) {
	a, ok := k.([]any)
	if !ok || len(a) != 2 {
		return nil, nil, errors.New("key shape")
	}
	enc, err := em.Marshal(a)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(enc)
	pub, _ := a[1].([]byte)
	return h[:], pub, nil
}

// envelope checks [body, sig] and returns the body map.
func envelope(b []byte, label string, signerKey func(map[any]any) ([]byte, error)) (map[any]any, []byte, error) {
	v, err := strict(b)
	if err != nil {
		return nil, nil, fmt.Errorf("cbor: %w", err)
	}
	a, ok := v.([]any)
	if !ok || (len(a) != 2 && len(a) != 3) {
		return nil, nil, errors.New("env/shape")
	}
	body, ok1 := a[0].([]byte)
	sig, ok2 := a[1].([]byte)
	if !ok1 || !ok2 {
		return nil, nil, errors.New("env/shape")
	}
	if len(a) == 3 {
		// sig2 is not fixed: a later algorithm's signature, up to 4 KiB.
		if s2, ok := a[2].([]byte); !ok {
			return nil, nil, errors.New("env/shape")
		} else if len(s2) > 4096 {
			return nil, nil, errors.New("env/sig2")
		}
	}
	bv, err := strict(body)
	if err != nil {
		return nil, nil, fmt.Errorf("body cbor: %w", err)
	}
	m, ok := bv.(map[any]any)
	if !ok {
		return nil, nil, errors.New("body not a map")
	}
	_, hasSigner2 := m[uint64(8)]
	if (len(a) == 3) != hasSigner2 {
		return nil, nil, errors.New("env/shape")
	}
	pub, err := signerKey(m)
	if err != nil {
		return nil, nil, err
	}
	if err := es256(pub, label, body, sig); err != nil {
		return nil, nil, fmt.Errorf("sig: %w", err)
	}
	return m, body, nil
}

// keyOf holds each test key's encoding by its name.
var keyOf = map[string][]byte{}

func bySignerHash(m map[any]any) ([]byte, error) {
	h, _ := m[uint64(3)].([]byte)
	pub, ok := byHash[hex.EncodeToString(h)]
	if !ok {
		return nil, errors.New("unknown signer")
	}
	return pub, nil
}

func bySignerKey(m map[any]any) ([]byte, error) {
	_, pub, err := keyHash(m[uint64(3)])
	return pub, err
}

type signedFile struct {
	Label string `json:"label"`
	Take  []struct {
		Name     string `json:"name"`
		Verdict  string `json:"verdict"`
		Body     string `json:"body"`
		ID       string `json:"id"`
		Envelope string `json:"envelope"`
		SealAD   string `json:"seal_ad"`
		Orders   string `json:"orders"`
	} `json:"take"`
	Refuse []struct {
		Name     string `json:"name"`
		Rule     string `json:"rule"`
		Envelope string `json:"envelope"`
	} `json:"refuse"`
}

func formatRule(rule string) bool {
	for _, p := range []string{"cbor/", "env/", "sig/"} {
		if strings.HasPrefix(rule, p) {
			return true
		}
	}
	return false
}

func checkSigned(dir, file string, sk func(map[any]any) ([]byte, error)) {
	var f signedFile
	load(dir, file, &f)
	ok, skipped := 0, 0
	for _, t := range f.Take {
		m, body, err := envelope(unhex(t.Envelope), f.Label, sk)
		if t.Verdict == "hold" && err != nil && strings.Contains(err.Error(), "env/shape") {
			// a body naming signer2 with two elements: held by the rules, refused here only by shape
		}
		if err != nil && t.Verdict == "hold" {
			// "second signer named" has two elements on purpose: the rules hold it;
			// the format reader sees a shape mismatch. Report it so the spec states it.
			fmt.Printf("note %s / %s: %v (held by the rules)\n", file, t.Name, err)
			continue
		}
		if err != nil {
			fail("%s / %s: %v", file, t.Name, err)
			continue
		}
		if typ, _ := m[uint64(1)].(uint64); f.Label == "cbb record v3" && typ == 1 && !nameOK(m[uint64(11)]) {
			fail("%s / %s: its name is refused", file, t.Name)
		}
		if typ, _ := m[uint64(1)].(uint64); f.Label == "cbb record v3" && typ == 9 && !ownHeadBefore(m) {
			fail("%s / %s: it names its own key at or above its seq", file, t.Name)
		}
		if t.Body != "" && hex.EncodeToString(body) != t.Body {
			fail("%s / %s: body differs", file, t.Name)
		}
		if t.ID != "" {
			id := sha256.Sum256(body)
			if hex.EncodeToString(id[:]) != t.ID {
				fail("%s / %s: id differs", file, t.Name)
			}
		}
		if t.SealAD != "" {
			mm := map[any]any{}
			for k, v := range m {
				if k != uint64(15) {
					mm[k] = v
				}
			}
			enc, _ := em.Marshal(mm)
			if hex.EncodeToString(append(append([]byte(f.Label), 0), enc...)) != t.SealAD {
				fail("%s / %s: seal AD differs", file, t.Name)
			}
		}
		if t.Orders != "" {
			if _, err := strict(unhex(t.Orders)); err != nil {
				fail("%s / %s: orders: %v", file, t.Name, err)
			}
		}
		ok++
	}
	for _, r := range f.Refuse {
		m, _, err := envelope(unhex(r.Envelope), f.Label, sk)
		if r.Rule == "records/checkpoint/own-head" {
			if err != nil || ownHeadBefore(m) {
				fail("%s / %s: its heads hold", file, r.Name)
			} else {
				ok++
			}
			continue
		}
		if r.Rule == "records/device/name" {
			// names: checked here by themselves, apart from the rules
			if err != nil || nameOK(m[uint64(11)]) {
				fail("%s / %s: its name holds", file, r.Name)
			} else {
				ok++
			}
			continue
		}
		if formatRule(r.Rule) {
			if err == nil {
				fail("%s / %s: taken, want refused (%s)", file, r.Name, r.Rule)
			} else {
				ok++
			}
		} else {
			skipped++
		}
	}
	fmt.Printf("%-18s %d checked, %d field-level refusals left to the implementations\n", file, ok, skipped)
}

func main() {
	dir := os.Args[1]

	var keys struct {
		GroupID string   `json:"group_id"`
		Keys    []keyRow `json:"keys"`
	}
	load(dir, "keys.json", &keys)
	for _, k := range keys.Keys {
		v, err := strict(unhex(k.Key))
		must(err)
		h, pub, err := keyHash(v)
		must(err)
		if hex.EncodeToString(h) != k.KeyHash || hex.EncodeToString(h[:16]) != k.ID16 {
			fail("keys.json %s: hash", k.Name)
		}
		byHash[k.KeyHash] = pub
		keyOf[k.Name] = unhex(k.Key)
	}
	// The Group ID commits to the first root key and the recovery key
	// (rule 33).
	gid := sha256.Sum256(append(append([]byte("cbb group v3\x00"), keyOf["root"]...), keyOf["recovery"]...))
	if hex.EncodeToString(gid[:16]) != keys.GroupID {
		fail("group id is not that of the root key and the recovery key")
	}

	var prof struct {
		Vectors []struct {
			Name  string `json:"name"`
			Hex   string `json:"hex"`
			Valid bool   `json:"valid"`
			Rule  string `json:"rule"`
		} `json:"vectors"`
	}
	load(dir, "profile.json", &prof)
	for _, v := range prof.Vectors {
		_, err := strict(unhex(v.Hex))
		if v.Valid && err != nil {
			fail("profile %s: refused: %v", v.Name, err)
		}
		if !v.Valid && err == nil {
			fail("profile %s: taken, want %s", v.Name, v.Rule)
		}
	}
	fmt.Printf("%-18s %d checked\n", "profile.json", len(prof.Vectors))

	checkSigned(dir, "records.json", bySignerHash)
	// os numbers: one this version does not name is taken and shown as unknown
	osNames := []string{"", "linux", "windows", "macos", "ios", "android", "aurora", "sailfish", "watchos", "wearos", "none", "harmonyos"}
	var rs struct {
		Take []struct {
			Name   string `json:"name"`
			Body   string `json:"body"`
			Os     uint64 `json:"os"`
			OsName string `json:"os_name"`
		} `json:"take"`
	}
	load(dir, "records.json", &rs)
	for _, t := range rs.Take {
		if t.OsName == "" {
			continue
		}
		v, err := strict(unhex(t.Body))
		must(err)
		got, _ := v.(map[any]any)[uint64(17)].(uint64)
		name := "unknown"
		if got < uint64(len(osNames)) && osNames[got] != "" {
			name = osNames[got]
		}
		if got != t.Os || name != t.OsName {
			fail("records %s: os %d %s", t.Name, got, name)
		}
	}
	checkSigned(dir, "statements.json", bySignerHash)
	checkSigned(dir, "commands.json", bySignerHash)
	checkSigned(dir, "credentials.json", bySignerKey)

	// grants: one signed envelope, by the root, or by an admin whose key
	// the root's record in field 3 makes an admin with admit
	var g struct {
		Group string `json:"group"`
		Take  []struct {
			Name    string `json:"name"`
			Leaf    string `json:"leaf"`
			Message string `json:"message"`
		} `json:"take"`
		Refuse []struct {
			Name     string `json:"name"`
			Rule     string `json:"rule"`
			Leaf     string `json:"leaf"`
			Message  string `json:"message"`
			Recovery uint64 `json:"recovery"`
			Root     string `json:"root"`
		} `json:"refuse"`
	}
	load(dir, "grants.json", &g)
	type leafState struct {
		guarded       bool
		rootC, adminC uint64
		commanders    map[string][]byte // key hash in hex to point
		grantHash     []byte            // SHA-256 of the kept grant's body
		recovery      uint64            // the recovery seq the kept grant was made under
	}
	rootHash := mustHashOf("root", keys.Keys)
	// rootOr is a row's root key hash, the file's root when it names none.
	rootOr := func(h string) string {
		if h == "" {
			return rootHash
		}
		return h
	}
	// grant reads message grant for a leaf that keeps st (nil before its
	// first grant) and knows recovery as the newest recovery seq, whose
	// root has the key hash rootHash then, and returns what the leaf keeps
	// after taking it. A kept grant of a lower recovery seq counts as
	// none, but a guarded leaf stays guarded.
	group := unhex(g.Group)
	allowed := map[uint64]bool{1: true, 2: true, 3: true, 4: true, 6: true}
	for k := uint64(10); k <= 19; k++ {
		allowed[k] = true
	}
	grant := func(msg []byte, leaf []byte, st *leafState, recovery uint64, rootHash string) (*leafState, error) {
		v, err := strict(msg)
		if err != nil {
			return nil, err
		}
		m := v.(map[any]any)
		ge, ok := m[uint64(2)]
		if !ok {
			return nil, errors.New("grants/shape")
		}
		envb, err := em.Marshal(ge)
		if err != nil {
			return nil, err
		}
		// the body's form before its signature: no unknown critical field,
		// type 1, this group, this leaf
		if ea, ok := ge.([]any); ok && len(ea) >= 2 {
			if bb, ok := ea[0].([]byte); ok {
				if bv, err := strict(bb); err == nil {
					if pre, ok := bv.(map[any]any); ok {
						for k := range pre {
							if n := k.(uint64); n < 256 && !allowed[n] {
								return nil, errors.New("form/critical")
							}
						}
						typ, _ := pre[uint64(1)].(uint64)
						gr, _ := pre[uint64(2)].([]byte)
						lf, _ := pre[uint64(10)].([]byte)
						if typ != 1 || !bytes.Equal(gr, group) || !bytes.Equal(lf, leaf) {
							return nil, errors.New("grants/shape")
						}
						var madeAfter uint64
						if rv, ok := pre[uint64(19)]; ok {
							n, isInt := rv.(uint64)
							switch {
							case !isInt:
								return nil, errors.New("grants/shape")
							case n == 0:
								return nil, errors.New("form/default")
							}
							madeAfter = n
						}
						if madeAfter != recovery || recovery > 16 || st != nil && st.recovery > recovery {
							return nil, errors.New("grants/recovery")
						}
						if gv, ok := pre[uint64(15)]; ok && gv != uint64(1) {
							return nil, errors.New("grants/guarded-value")
						}
					}
				}
			}
		}
		wasGuarded := st != nil && st.guarded
		if st != nil && st.recovery != recovery {
			st = nil
		}
		byRoot := false
		signerKey := func(body map[any]any) ([]byte, error) {
			h, _ := body[uint64(3)].([]byte)
			if hex.EncodeToString(h) == rootHash {
				byRoot = true
				return byHash[rootHash], nil
			}
			if _, g := body[uint64(15)]; g || wasGuarded {
				return nil, errors.New("grants/guarded")
			}
			if st != nil {
				pub, ok := st.commanders[hex.EncodeToString(h)]
				if !ok {
					return nil, errors.New("grants/signer")
				}
				return pub, nil
			}
			rec, ok := m[uint64(3)]
			if !ok {
				return nil, errors.New("grants/admin")
			}
			rb, err := em.Marshal(rec)
			if err != nil {
				return nil, err
			}
			r, _, err := envelope(rb, "cbb record v3", bySignerHash)
			if err != nil || hex.EncodeToString(r[uint64(3)].([]byte)) != rootHash || !adminRecord(r, group) {
				return nil, errors.New("grants/admin")
			}
			kh, pub, err := keyHash(r[uint64(20)])
			if err != nil || !bytes.Equal(kh, h) || !onCurve(pub) {
				return nil, errors.New("grants/admin")
			}
			if p, _ := r[uint64(21)].(uint64); p&1 != 1 {
				return nil, errors.New("grants/admin")
			}
			return pub, nil
		}
		body, gbody, err := envelope(envb, "cbb grant v1", signerKey)
		if err != nil {
			return nil, err
		}
		counter, _ := body[uint64(4)].(uint64)
		madeUnder, named := body[uint64(17)].(uint64)
		_, guarded := body[uint64(15)]
		var rootC uint64
		if st != nil {
			rootC = st.rootC
		}
		if byRoot && named || !byRoot && madeUnder != rootC {
			return nil, errors.New("grants/counter")
		}
		next := &leafState{guarded: guarded || wasGuarded, commanders: map[string][]byte{}, recovery: recovery}
		if wasGuarded && !guarded {
			return nil, errors.New("grants/guarded")
		}
		if st != nil {
			next.rootC, next.adminC = st.rootC, st.adminC
			if byRoot && counter <= st.rootC || !byRoot && counter <= st.adminC {
				return nil, errors.New("grants/counter")
			}
		}
		// an admin grant after the first names the kept grant it replaces
		rep, hasRep := body[uint64(18)].([]byte)
		_, anyRep := body[uint64(18)]
		switch {
		case byRoot || st == nil:
			if anyRep {
				return nil, errors.New("grants/replaces")
			}
		case !hasRep || !bytes.Equal(rep, st.grantHash):
			return nil, errors.New("grants/replaces")
		}
		if life, ok := body[uint64(11)]; ok {
			n, isInt := life.(uint64)
			if !guarded || !isInt || n < 1 || n > 3456000000 {
				return nil, errors.New("grants/life")
			}
		}
		if err := grantSets(body); err != nil {
			return nil, err
		}
		gh := sha256.Sum256(gbody)
		next.grantHash = gh[:]
		if byRoot {
			next.rootC, next.adminC = counter, 0
		} else {
			next.adminC = counter
		}
		cs, _ := body[uint64(12)].([]any)
		for _, k := range cs {
			h, pub, err := keyHash(k)
			if err != nil {
				return nil, err
			}
			next.commanders[hex.EncodeToString(h)] = pub
		}
		return next, nil
	}
	for _, t := range g.Take {
		if _, err := grant(unhex(t.Message), unhex(t.Leaf), nil, 0, rootHash); err != nil {
			fail("grants %s: %v", t.Name, err)
		}
	}
	checkedRefuse := 0
	for _, r := range g.Refuse {
		checkedRefuse++
		_, err := grant(unhex(r.Message), unhex(r.Leaf), nil, r.Recovery, rootOr(r.Root))
		switch {
		case err == nil:
			fail("grants %s: taken", r.Name)
		case strings.HasPrefix(r.Rule, "sig/"):
		case err.Error() != r.Rule:
			fail("grants %s: %v, want %s", r.Name, err, r.Rule)
		}
	}
	var gq struct {
		Sequences []struct {
			Name  string `json:"name"`
			Leaf  string `json:"leaf"`
			Steps []struct {
				Name     string `json:"name"`
				Message  string `json:"message"`
				Verdict  string `json:"verdict"`
				Rule     string `json:"rule"`
				Recovery uint64 `json:"recovery"`
				Root     string `json:"root"`
			} `json:"steps"`
		} `json:"sequences"`
	}
	load(dir, "grants.json", &gq)
	for _, q := range gq.Sequences {
		var st *leafState
		for _, t := range q.Steps {
			next, err := grant(unhex(t.Message), unhex(q.Leaf), st, t.Recovery, rootOr(t.Root))
			switch {
			case err == nil && t.Verdict == "take":
				st = next
			case err != nil && t.Verdict == "refuse" && err.Error() == t.Rule:
			default:
				fail("grants %s, %s: %v", q.Name, t.Name, err)
			}
			checkedRefuse++
		}
	}
	// who may send a leaf copies: an ordinary leaf its readers, a guarded
	// leaf only its commanders
	var gs struct {
		Senders []struct {
			Name    string `json:"name"`
			Grant   string `json:"grant"`
			Origin  string `json:"origin"`
			Verdict string `json:"verdict"`
			Rule    string `json:"rule"`
		} `json:"copy_senders"`
	}
	load(dir, "grants.json", &gs)
	for _, t := range gs.Senders {
		v, err := strict(unhex(t.Grant))
		must(err)
		m := v.(map[any]any)
		origin := unhex(t.Origin)
		named := false
		if _, guarded := m[uint64(15)]; guarded {
			cs, _ := m[uint64(12)].([]any)
			for _, k := range cs {
				if h, _, err := keyHash(k); err == nil && bytes.Equal(h[:16], origin) {
					named = true
				}
			}
		} else {
			rs, _ := m[uint64(13)].([]any)
			for _, r := range rs {
				if a, ok := r.([]any); ok && len(a) == 2 {
					if id, ok := a[0].([]byte); ok && bytes.Equal(id, origin) {
						named = true
					}
				}
			}
		}
		if named != (t.Verdict == "take") || (!named && t.Rule != "copy/leaf-sender") {
			fail("grants copy sender %s: named %v", t.Name, named)
		}
	}
	fmt.Printf("%-18s %d checked\n", "grants.json", len(g.Take)+checkedRefuse+len(gs.Senders))

	// frames
	var fr struct {
		Take   []struct{ Name, Frame string }       `json:"take"`
		Refuse []struct{ Name, Rule, Frame string } `json:"refuse"`
	}
	load(dir, "frames.json", &fr)
	frame := func(b []byte) error {
		if len(b) < 4 {
			return errors.New("short")
		}
		l := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if l != len(b)-4 {
			return errors.New("length")
		}
		onGrid := l == 64 || l == 256 || l == 1024 || l == 4096 || l == 16384 || (l > 16384 && l%16384 == 0)
		if !onGrid {
			return errors.New("frame/grid")
		}
		v, err := strict(b[4:])
		if err != nil {
			return err
		}
		m, ok := v.(map[any]any)
		if !ok {
			return errors.New("not a map")
		}
		if _, ok := m[uint64(0)].(uint64); !ok {
			return errors.New("no t")
		}
		if p, ok := m[uint64(1)]; ok {
			pb, ok := p.([]byte)
			if !ok || bytes.ContainsFunc(pb, func(r rune) bool { return r != 0 }) {
				return errors.New("frame/pad")
			}
		}
		// The one padding: the message without `pad`, padded by trying
		// every length, gives these bytes.
		delete(m, uint64(1))
		again, err := padded(m, onGridSize)
		if err != nil {
			return err
		}
		if !bytes.Equal(again, b[4:]) {
			return errors.New("frame/pad: not the one padding")
		}
		return nil
	}
	for _, t := range fr.Take {
		if err := frame(unhex(t.Frame)); err != nil {
			fail("frames %s: %v", t.Name, err)
		}
	}
	for _, r := range fr.Refuse {
		if frame(unhex(r.Frame)) == nil {
			fail("frames %s: taken", r.Name)
		}
	}
	fmt.Printf("%-18s %d checked\n", "frames.json", len(fr.Take)+len(fr.Refuse))

	// copy
	var cAny map[string]any
	load(dir, "copy.json", &cAny)
	c := map[string]string{}
	for k, v := range cAny {
		if str, ok := v.(string); ok {
			c[k] = str
		}
	}
	hdr := unhex(c["hdr"])
	if _, err := strict(hdr); err != nil {
		fail("copy hdr: %v", err)
	}
	h := sha256.Sum256(append([]byte("cbb copy v2\x00"), hdr...))
	if hex.EncodeToString(h[:]) != c["h"] {
		fail("copy h")
	}
	checkCopy := func(name string, b []byte) {
		v, err := strict(b)
		if err != nil {
			fail("copy %s: %v", name, err)
			return
		}
		m := v.(map[any]any)
		var w []byte
		for _, x := range m[uint64(3)].([]any) {
			xb := x.([]byte)
			switch len(xb) {
			case 1168:
				s := sha256.Sum256(xb)
				w = append(w, s[:]...)
			case 32:
				w = append(w, xb...)
			default:
				fail("copy %s: wrap size %d", name, len(xb))
			}
		}
		W := sha256.Sum256(w)
		var P []byte
		if p, ok := m[uint64(4)].([]byte); ok {
			s := sha256.Sum256(p)
			P = s[:]
		} else {
			P = m[uint64(5)].([]byte)
		}
		msg := append(append(append([]byte{}, h[:]...), W[:]...), P...)
		if err := es256(byHash[mustHashOf("laptop member key", keys.Keys)], "cbb copy sig v2", msg, m[uint64(6)].([]byte)); err != nil {
			fail("copy %s: %v", name, err)
		}
	}
	checkCopy("full", unhex(c["copy"]))
	checkCopy("reduced", unhex(c["reduced_copy_for_board"]))
	if cv, err := strict(unhex(c["content_plaintext"])); err != nil || len(c["content_plaintext"]) != 2048 {
		fail("copy content: %v", err)
	} else {
		cm := cv.(map[any]any)
		delete(cm, uint64(1))
		again, err := padded(cm, contentStep)
		if err != nil || !bytes.Equal(again, unhex(c["content_plaintext"])) {
			fail("copy content: not the one padding (%v)", err)
		}
	}
	// refused: a copy key whose commitment is not the header's, and
	// contents not padded to their one step
	var rc struct {
		Commit []struct {
			Name string `json:"name"`
			Rule string `json:"rule"`
			K    string `json:"K"`
		} `json:"refuse_commit"`
		Contents []struct {
			Name    string `json:"name"`
			Rule    string `json:"rule"`
			Content string `json:"content"`
		} `json:"refuse_contents"`
	}
	load(dir, "copy.json", &rc)
	if len(rc.Commit) == 0 || len(rc.Contents) == 0 {
		fail("copy: no refused commit or content")
	}
	for _, r := range rc.Commit {
		cv, _ := strict(unhex(c["copy"]))
		hv, _ := strict(cv.(map[any]any)[uint64(1)].([]byte))
		have, _ := hv.(map[any]any)[uint64(6)].([]byte)
		ck := hkdfSHA256(unhex(r.K), nil, []byte("cbb copy commit v2"))
		if r.Rule != "copy/commit" || bytes.Equal(ck, have) {
			fail("copy %s: its commit holds", r.Name)
		}
		if !bytes.Equal(hkdfSHA256(unhex(c["K"]), nil, []byte("cbb copy commit v2")), have) {
			fail("copy: the header's commit is not its key's")
		}
	}
	for _, r := range rc.Contents {
		b := unhex(r.Content)
		v, err := strict(b)
		if err != nil {
			fail("copy content %s: %v", r.Name, err)
			continue
		}
		cm := v.(map[any]any)
		delete(cm, uint64(1))
		again, err := padded(cm, contentStep)
		if r.Rule != "copy/content-pad" || (err == nil && bytes.Equal(again, b)) {
			fail("copy content %s: its padding holds", r.Name)
		}
	}
	var edges struct {
		Edges []struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"content_edges"`
	}
	load(dir, "copy.json", &edges)
	for _, e := range edges.Edges {
		b := unhex(e.Content)
		v, err := strict(b)
		if err != nil {
			fail("copy content %s: %v", e.Name, err)
			continue
		}
		m := v.(map[any]any)
		delete(m, uint64(1))
		again, err := padded(m, contentStep)
		if err != nil || !bytes.Equal(again, b) {
			fail("copy content %s: not the one padding (%v)", e.Name, err)
		}
	}
	if err := frame(unhex(c["frame"])); err != nil {
		fail("copy frame: %v", err)
	}
	fmt.Printf("%-18s checked\n", "copy.json")

	// container: the TBS byte for byte with the key and its serial, the point on the curve;
	// the signature in its form (SEQUENCE of two DER INTEGERs of 1 to 33 bytes, at most 72 bytes),
	// its value not read (section 12)
	var ct struct {
		Cert    string `json:"example_cert"`
		KeyHash string `json:"example_key_hash"`
		Take    []struct {
			Name  string `json:"name"`
			Point string `json:"point"`
			Cert  string `json:"cert"`
		} `json:"take"`
		Refuse []struct {
			Name string `json:"name"`
			Cert string `json:"cert"`
		} `json:"refuse"`
	}
	load(dir, "container.json", &ct)
	sigForm := func(v asn1.BitString) error {
		if v.BitLength%8 != 0 || len(v.Bytes) > 72 {
			return errors.New("signature length")
		}
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(v.Bytes, &seq)
		if err != nil || len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
			return errors.New("signature not a SEQUENCE")
		}
		ints, err := elements(seq.Bytes)
		if err != nil || len(ints) != 2 {
			return errors.New("signature not two elements")
		}
		for _, i := range ints {
			if i.Class != asn1.ClassUniversal || i.Tag != asn1.TagInteger || len(i.Bytes) < 1 || len(i.Bytes) > 33 {
				return errors.New("signature integer")
			}
			// DER: not negative, and no zero in front it does not need.
			if i.Bytes[0]&0x80 != 0 || len(i.Bytes) > 1 && i.Bytes[0] == 0 && i.Bytes[1]&0x80 == 0 {
				return errors.New("signature integer not in DER")
			}
		}
		return nil
	}
	container := func(der []byte) ([]byte, error) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(cert.Raw, der) {
			return nil, errors.New("bytes after the certificate")
		}
		var seq asn1.RawValue
		if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) != 0 {
			return nil, errors.New("outer form")
		}
		parts, err := elements(seq.Bytes)
		if err != nil || len(parts) != 3 {
			return nil, errors.New("outer form")
		}
		var sig asn1.BitString
		if rest, err := asn1.Unmarshal(parts[2].FullBytes, &sig); err != nil || len(rest) != 0 {
			return nil, errors.New("signature not a BIT STRING")
		}
		if !bytes.Equal(parts[1].FullBytes, []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}) {
			return nil, errors.New("signature algorithm")
		}
		if err := sigForm(sig); err != nil {
			return nil, err
		}
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not ECDSA")
		}
		pub := elliptic.Marshal(elliptic.P256(), pk.X, pk.Y) //nolint:staticcheck
		h := sha256.Sum256(pub)
		ser := append([]byte{}, h[:16]...)
		ser[0] = 0x40 | ser[0]&0x3f
		want, _ := hex.DecodeString("3081c0a0030201020210" + hex.EncodeToString(ser) +
			"300a06082a8648ce3d040302300e310c300a06035504030c036362623020170d3730303130313030303030305a180f39393939313233313233353935395a300e310c300a06035504030c036362623059301306072a8648ce3d020106082a8648ce3d030107034200" +
			hex.EncodeToString(pub))
		if !bytes.Equal(cert.RawTBSCertificate, want) {
			return nil, errors.New("tbs differs from the template")
		}
		return pub, nil
	}
	if pub, err := container(unhex(ct.Cert)); err != nil {
		fail("container: %v", err)
	} else if !bytes.Equal(pub, byHash[ct.KeyHash]) {
		fail("container key")
	}
	for _, t := range ct.Take {
		if pub, err := container(unhex(t.Cert)); err != nil {
			fail("container %s: %v", t.Name, err)
		} else if !bytes.Equal(pub, unhex(t.Point)) {
			fail("container %s: key", t.Name)
		}
	}
	for _, r := range ct.Refuse {
		if r.Cert == "" {
			continue
		}
		if _, err := container(unhex(r.Cert)); err == nil {
			fail("container %s: taken", r.Name)
		}
	}
	fmt.Printf("%-18s checked\n", "container.json")

	checkSets(dir)
	checkMessages(dir)
	checkWave4(dir)
	if bad > 0 {
		fmt.Printf("%d failures\n", bad)
		os.Exit(1)
	}
	fmt.Println("all good")
}

// elements splits the contents of a SEQUENCE into its elements.
func elements(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}

func mustHashOf(name string, rows []keyRow) string {
	for _, r := range rows {
		if r.Name == name {
			return r.KeyHash
		}
	}
	panic(name)
}

func onGridSize(l int) bool {
	return l == 64 || l == 256 || l == 1024 || l == 4096 || l == 16384 || (l > 16384 && l%16384 == 0)
}

func contentStep(l int) bool {
	for _, s := range []int{1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 2 << 20, 3 << 20, 4 << 20} {
		if l == s {
			return true
		}
	}
	return false
}

// padded encodes m as it is when its size is allowed, else with the
// shortest run of zeros in field 1 that makes it an allowed size, found by
// trying every length (format section 9.1).
func padded(m map[any]any, allowed func(int) bool) ([]byte, error) {
	base, err := em.Marshal(m)
	if err != nil {
		return nil, err
	}
	if allowed(len(base)) {
		return base, nil
	}
	for plen := 0; plen < 8<<20; plen++ {
		m[uint64(1)] = make([]byte, plen)
		b, err := em.Marshal(m)
		if err != nil {
			return nil, err
		}
		if allowed(len(b)) {
			delete(m, uint64(1))
			return b, nil
		}
	}
	return nil, errors.New("no padding reaches an allowed size")
}

// setKey is the order of a set (section 1): an element's encoding, an
// array element by its first element's.
func setKey(x any) []byte {
	if a, ok := x.([]any); ok {
		if len(a) == 0 {
			return nil
		}
		x = a[0]
	}
	b, err := em.Marshal(x)
	must(err)
	return b
}

// sortedSet says whether a is sorted by setKey with each value once.
func sortedSet(a []any) bool {
	for i := 1; i < len(a); i++ {
		if bytes.Compare(setKey(a[i-1]), setKey(a[i])) >= 0 {
			return false
		}
	}
	return true
}

// onceSet says whether a holds each value once, in any order.
func onceSet(a []any) bool {
	seen := map[string]bool{}
	for _, x := range a {
		b, err := em.Marshal(x)
		must(err)
		if seen[string(b)] {
			return false
		}
		seen[string(b)] = true
	}
	return true
}

// grantSets checks a grant body's lists: commanders by key hash, at most 8;
// readers sorted, at most 4; neighbors sorted, at most 8.
func grantSets(body map[any]any) error {
	cs, _ := body[uint64(12)].([]any)
	if len(cs) > 8 {
		return errors.New("grants/commanders")
	}
	for i := 1; i < len(cs); i++ {
		a, _, err1 := keyHash(cs[i-1])
		b, _, err2 := keyHash(cs[i])
		if err1 != nil || err2 != nil || bytes.Compare(a, b) >= 0 {
			return errors.New("grants/commanders")
		}
	}
	var rs, ns []any
	if v, ok := body[uint64(13)]; ok {
		if rs, ok = v.([]any); !ok {
			return errors.New("grants/readers")
		}
	}
	if len(rs) > 4 || !sortedSet(rs) {
		return errors.New("grants/readers")
	}
	for _, r := range rs {
		e, _ := r.([]any)
		if len(e) != 2 {
			return errors.New("grants/readers")
		}
		id, _ := e[0].([]byte)
		k, _ := e[1].([]any)
		var pub []byte
		if len(k) == 2 {
			pub, _ = k[1].([]byte)
		}
		if alg, _ := keyAlg(k); len(id) != 16 || alg != 1 || len(pub) != 65 {
			return errors.New("grants/readers")
		}
		// a reader's ID is its key's: the key hash's first 16 bytes
		if h, _, err := keyHash(k); err != nil || !bytes.Equal(h[:16], id) {
			return errors.New("grants/readers")
		}
	}
	if v, ok := body[uint64(14)]; ok {
		if ns, ok = v.([]any); !ok {
			return errors.New("grants/neighbors")
		}
	}
	if len(ns) > 8 || !sortedSet(ns) {
		return errors.New("grants/neighbors")
	}
	for _, n := range ns {
		if b, _ := n.([]byte); len(b) != 32 {
			return errors.New("grants/neighbors")
		}
	}
	return nil
}

// recordSets checks a record body's sets: the sorted fields of its type,
// and hubs each once in the user's order. It returns how many sets of two
// or more it saw.
func recordSets(m map[any]any) (int, bool) {
	typ, _ := m[uint64(1)].(uint64)
	var sorted, once []uint64
	switch typ {
	case 1:
		sorted = []uint64{26}
	case 2, 3, 4, 9:
		sorted = []uint64{10, 11}
	case 6:
		sorted = []uint64{10}
	case 5, 8:
		sorted = []uint64{11}
	case 10:
		sorted = []uint64{11}
		once = []uint64{10}
	}
	n, ok := 0, true
	for _, f := range sorted {
		a, _ := m[f].([]any)
		if len(a) >= 2 {
			n++
		}
		ok = ok && sortedSet(a)
	}
	// seen: every entry is [key hash, seq >= 1, record ID]; device 26 and
	// revoke, freeze and claim 11 optional, thaw, copies and hubs 11 required
	seenField, required := uint64(0), false
	switch typ {
	case 1:
		seenField = 26
	case 2, 3, 5:
		seenField = 11
	case 4, 8, 10:
		seenField, required = 11, true
	}
	if seenField != 0 {
		v, present := m[seenField]
		a, isArr := v.([]any)
		if (required && !present) || (present && !isArr) {
			ok = false
		}
		for _, e := range a {
			ok = ok && seenEntry(e)
		}
	}
	for _, f := range once {
		a, _ := m[f].([]any)
		if len(a) >= 2 {
			n++
		}
		ok = ok && onceSet(a)
	}
	return n, ok
}

// hidden tells a character a list must not show as it is: C0, DEL, C1,
// U+2028, U+2029 and the bidi controls.
func hidden(r rune) bool {
	return r <= 0x1f || (r >= 0x7f && r <= 0x9f) || (r >= 0x2028 && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// nameOK: a device's name, 1 to 64 bytes, no hidden character.
func nameOK(v any) bool {
	n, ok := v.(string)
	if !ok || len(n) < 1 || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if hidden(r) {
			return false
		}
	}
	return true
}

// adminRecord reads the root's record in a first grant as a record: a
// device record of this group, with the fields of 0.6 only (a reader
// applies it, not holds it), a seq, a name, a role and a member key.
func adminRecord(r map[any]any, group []byte) bool {
	allowed := map[uint64]bool{}
	for _, f := range []uint64{1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26} {
		allowed[f] = true
	}
	for k := range r {
		if n, ok := k.(uint64); ok && n < 256 && !allowed[n] {
			return false
		}
	}
	typ, _ := r[uint64(1)].(uint64)
	g, _ := r[uint64(2)].([]byte)
	seq, _ := r[uint64(4)].(uint64)
	role, _ := r[uint64(12)].(uint64)
	prev, hasPrev := r[uint64(5)]
	prevOK := !hasPrev && seq == 1
	if p, ok := prev.([]byte); hasPrev && ok && len(p) == 32 {
		prevOK = true
	}
	_, pub, err := keyHash(r[uint64(10)])
	k, _ := r[uint64(10)].([]any)
	alg, _ := keyAlg(k)
	return typ == 1 && bytes.Equal(g, group) && seq >= 1 && seq < 1<<31 && prevOK && nameOK(r[uint64(11)]) &&
		role >= 1 && role <= 4 && err == nil && alg == 1 && onCurve(pub)
}

// onCurve reports whether pub is an uncompressed P-256 point, as the Rust
// reader checks a member key and an admin key.
func onCurve(pub []byte) bool {
	if len(pub) != 65 {
		return false
	}
	x, _ := elliptic.Unmarshal(elliptic.P256(), pub) //nolint:staticcheck
	return x != nil
}

func seenEntry(e any) bool {
	t, ok := e.([]any)
	if !ok || len(t) != 3 {
		return false
	}
	h, ok1 := t[0].([]byte)
	seq, ok2 := t[1].(uint64)
	id, ok3 := t[2].([]byte)
	return ok1 && ok2 && ok3 && len(h) == 32 && seq >= 1 && len(id) == 32
}

// copyRule reads a copy's outer map and header and gives the rule they
// break, or "" when they hold.
func copyRule(c []byte) string {
	v, err := strict(c)
	if err != nil {
		return "cbor"
	}
	m, ok := v.(map[any]any)
	if !ok {
		return "copy/shape"
	}
	for k := range m {
		if n, ok := k.(uint64); ok && n < 256 && (n < 1 || n > 6) {
			return "form/critical"
		}
	}
	hb, ok := m[uint64(1)].([]byte)
	if !ok {
		return "copy/shape"
	}
	hv, err := strict(hb)
	if err != nil {
		return "cbor"
	}
	h, ok := hv.(map[any]any)
	if !ok {
		return "copy/shape"
	}
	if _, ok := h[uint64(7)]; ok {
		return "copy/reuse"
	}
	for k := range h {
		if n, ok := k.(uint64); ok && n < 256 && (n < 1 || n > 6) {
			return "form/critical"
		}
	}
	sized := func(f uint64, n int) bool {
		b, ok := h[f].([]byte)
		return ok && len(b) == n
	}
	timeOK := false
	if t, ok := h[uint64(3)].([]any); ok && len(t) == 2 {
		w, ok1 := t[0].(uint64)
		l, ok2 := t[1].(uint64)
		timeOK = ok1 && ok2 && l <= 1<<32-1 && (w != 0 || l != 0)
	}
	blobOK := true
	if b, ok := h[uint64(5)]; ok {
		t, ok := b.([]any)
		blobOK = ok && len(t) == 2
		if blobOK {
			_, ok1 := t[0].(uint64)
			x, ok2 := t[1].([]byte)
			blobOK = ok1 && ok2 && len(x) == 32
		}
	}
	if !sized(1, 16) || !sized(2, 16) || !sized(6, 32) || !timeOK || !blobOK {
		return "copy/shape"
	}
	rs, ok := h[uint64(4)].([]any)
	if !ok || len(rs) == 0 || len(rs) > 256 || !sortedSet(rs) || !onceSet(rs) {
		return "copy/readers"
	}
	for _, r := range rs {
		t, ok := r.([]any)
		if !ok || len(t) != 2 {
			return "copy/readers"
		}
		id, ok1 := t[0].([]byte)
		_, ok2 := t[1].(uint64)
		if !ok1 || !ok2 || len(id) != 16 {
			return "copy/readers"
		}
	}
	ws, ok := m[uint64(3)].([]any)
	if !ok || len(ws) != len(rs) {
		return "copy/shape"
	}
	return ""
}

// checkSets reads every set the vectors hold and checks its order by
// itself, apart from gen.py's own.
func checkSets(dir string) {
	var rs struct {
		Take []struct {
			Name     string `json:"name"`
			Envelope string `json:"envelope"`
		} `json:"take"`
		Refuse []struct {
			Name     string `json:"name"`
			Rule     string `json:"rule"`
			Envelope string `json:"envelope"`
		} `json:"refuse"`
	}
	load(dir, "records.json", &rs)
	body := func(env string) map[any]any {
		v, err := strict(unhex(env))
		if err != nil {
			return nil
		}
		a, _ := v.([]any)
		if len(a) < 2 {
			return nil
		}
		b, _ := a[0].([]byte)
		m, err := strict(b)
		if err != nil {
			return nil
		}
		mm, _ := m.(map[any]any)
		return mm
	}
	twos, refused := 0, 0
	for _, t := range rs.Take {
		n, ok := recordSets(body(t.Envelope))
		twos += n
		if !ok {
			fail("records %s: a set out of order", t.Name)
		}
	}
	if twos < 6 {
		fail("records: only %d sets of two or more", twos)
	}
	setRule := map[string]bool{"records/revoke/keys": true, "records/revoke/seen": true, "records/thaw/records": true,
		"records/checkpoint/heads": true, "records/checkpoint/keep": true, "records/hubs/hubs": true,
		"records/device/seen": true, "records/thaw/seen": true, "records/hubs/seen": true, "records/copies/seen": true}
	for _, t := range rs.Refuse {
		if !setRule[t.Rule] {
			continue
		}
		refused++
		if _, ok := recordSets(body(t.Envelope)); ok {
			fail("records %s: its sets hold", t.Name)
		}
	}
	var fr struct {
		Take []struct {
			Name  string `json:"name"`
			Frame string `json:"frame"`
		} `json:"take"`
		RefuseFields []struct {
			Name    string   `json:"name"`
			Path    []uint64 `json:"path"`
			Message string   `json:"message"`
		} `json:"refuse_fields"`
	}
	load(dir, "frames.json", &fr)
	for _, t := range fr.Take {
		v, err := strict(unhex(t.Frame)[4:])
		must(err)
		m, _ := v.(map[any]any)
		typ, _ := m[uint64(0)].(uint64)
		var set any
		switch typ {
		case 6, 18:
			set = m[uint64(2)]
		}
		if a, ok := set.([]any); ok && (len(a) < 2 || !sortedSet(a)) {
			fail("frames %s: set out of order or short", t.Name)
		}
	}
	for _, t := range fr.RefuseFields {
		v, err := strict(unhex(t.Message))
		must(err)
		for _, k := range t.Path {
			v = v.(map[any]any)[k]
		}
		refused++
		if sortedSet(v.([]any)) {
			fail("frames %s: its set holds", t.Name)
		}
	}
	var cp struct {
		Copy          string `json:"copy"`
		RefuseReaders []struct {
			Name string `json:"name"`
			Copy string `json:"copy"`
		} `json:"refuse_readers"`
		RefuseCopies []struct {
			Name string `json:"name"`
			Rule string `json:"rule"`
			Copy string `json:"copy"`
		} `json:"refuse_copies"`
	}
	load(dir, "copy.json", &cp)
	readers := func(c string) []any {
		v, err := strict(unhex(c))
		must(err)
		h, err := strict(v.(map[any]any)[uint64(1)].([]byte))
		must(err)
		a, _ := h.(map[any]any)[uint64(4)].([]any)
		return a
	}
	if r := readers(cp.Copy); len(r) < 2 || !sortedSet(r) {
		fail("copy: readers out of order")
	}
	if r := copyRule(unhex(cp.Copy)); r != "" {
		fail("copy: refused by its rows (%s)", r)
	}
	for _, t := range cp.RefuseCopies {
		refused++
		if r := copyRule(unhex(t.Copy)); r != t.Rule {
			fail("copy %s: %q, want %s", t.Name, r, t.Rule)
		}
	}
	for _, t := range cp.RefuseReaders {
		refused++
		if r := copyRule(unhex(t.Copy)); r != "copy/readers" {
			fail("copy %s: %q, want copy/readers", t.Name, r)
		}
		if sortedSet(readers(t.Copy)) {
			fail("copy %s: readers hold", t.Name)
		}
	}
	fmt.Printf("%-18s %d sets of two or more taken, %d refused\n", "sets", twos, refused)
}

// keyAlg gives a Key's algorithm number, or 0 when k is not a Key.
func keyAlg(k []any) (uint64, bool) {
	if len(k) != 2 {
		return 0, false
	}
	a, ok := k[0].(uint64)
	return a, ok
}

// hkdfSHA256 gives 32 bytes of HKDF-SHA256 (an empty salt is 32 zero
// bytes, as RFC 5869 says).
func hkdfSHA256(ikm, salt, info []byte) []byte {
	k, err := hkdf.Key(sha256.New, ikm, salt, string(info), 32)
	must(err)
	return k
}

// ownHeadBefore: a checkpoint names its own key's head, if at all, below
// its own seq.
func ownHeadBefore(m map[any]any) bool {
	signer, _ := m[uint64(3)].([]byte)
	seq, _ := m[uint64(4)].(uint64)
	heads, _ := m[uint64(10)].([]any)
	for _, h := range heads {
		e, _ := h.([]any)
		if len(e) != 3 {
			continue
		}
		k, _ := e[0].([]byte)
		n, _ := e[1].(uint64)
		if bytes.Equal(k, signer) && n >= seq {
			return false
		}
	}
	return true
}
