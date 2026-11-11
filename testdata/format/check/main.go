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
	"crypto/sha256"
	"crypto/x509"
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
		_, _, err := envelope(unhex(r.Envelope), f.Label, sk)
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
		if k.Name == "root" && k.ID16 != keys.GroupID {
			fail("group id is not the root key's id")
		}
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
	checkSigned(dir, "statements.json", bySignerHash)
	checkSigned(dir, "commands.json", bySignerHash)
	checkSigned(dir, "credentials.json", bySignerKey)

	// grants: one signed envelope, by the root, or by an admin whose key
	// the root's record in field 3 makes an admin with admit
	var g struct {
		Take []struct {
			Name    string `json:"name"`
			Message string `json:"message"`
		} `json:"take"`
		Refuse []struct {
			Name    string `json:"name"`
			Rule    string `json:"rule"`
			Message string `json:"message"`
		} `json:"refuse"`
	}
	load(dir, "grants.json", &g)
	type leafState struct {
		guarded       bool
		rootC, adminC uint64
		commanders    map[string][]byte // key hash in hex to point
	}
	rootHash := mustHashOf("root", keys.Keys)
	// grant reads message grant for a leaf that keeps st (nil before its
	// first grant) and returns what the leaf keeps after taking it.
	grant := func(msg []byte, st *leafState) (*leafState, error) {
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
		byRoot := false
		signerKey := func(body map[any]any) ([]byte, error) {
			h, _ := body[uint64(3)].([]byte)
			if hex.EncodeToString(h) == rootHash {
				byRoot = true
				return byHash[rootHash], nil
			}
			if _, g := body[uint64(15)]; g || (st != nil && st.guarded) {
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
			if err != nil || hex.EncodeToString(r[uint64(3)].([]byte)) != rootHash {
				return nil, errors.New("grants/admin")
			}
			kh, pub, err := keyHash(r[uint64(20)])
			if err != nil || !bytes.Equal(kh, h) {
				return nil, errors.New("grants/admin")
			}
			if p, _ := r[uint64(21)].(uint64); p&1 != 1 {
				return nil, errors.New("grants/admin")
			}
			return pub, nil
		}
		body, _, err := envelope(envb, "cbb grant v1", signerKey)
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
		next := &leafState{guarded: guarded, commanders: map[string][]byte{}}
		if st != nil {
			next.guarded = next.guarded || st.guarded
			next.rootC, next.adminC = st.rootC, st.adminC
			if st.guarded && !guarded {
				return nil, errors.New("grants/guarded")
			}
			if byRoot && counter <= st.rootC || !byRoot && counter <= st.adminC {
				return nil, errors.New("grants/counter")
			}
		}
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
		if _, err := grant(unhex(t.Message), nil); err != nil {
			fail("grants %s: %v", t.Name, err)
		}
	}
	checkedRefuse := 0
	for _, r := range g.Refuse {
		if !strings.HasPrefix(r.Rule, "sig/") && r.Rule != "grants/shape" && r.Rule != "grants/admin" &&
			r.Rule != "grants/guarded" {
			continue
		}
		checkedRefuse++
		if _, err := grant(unhex(r.Message), nil); err == nil {
			fail("grants %s: taken", r.Name)
		}
	}
	var gq struct {
		Sequences []struct {
			Name  string `json:"name"`
			Steps []struct {
				Name    string `json:"name"`
				Message string `json:"message"`
				Verdict string `json:"verdict"`
				Rule    string `json:"rule"`
			} `json:"steps"`
		} `json:"sequences"`
	}
	load(dir, "grants.json", &gq)
	for _, q := range gq.Sequences {
		var st *leafState
		for _, t := range q.Steps {
			next, err := grant(unhex(t.Message), st)
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
	// the signature's value is not read (section 12)
	var ct struct {
		Cert    string `json:"example_cert"`
		KeyHash string `json:"example_key_hash"`
		Refuse  []struct {
			Name string `json:"name"`
			Cert string `json:"cert"`
		} `json:"refuse"`
	}
	load(dir, "container.json", &ct)
	container := func(der []byte) ([]byte, error) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
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
	for _, r := range ct.Refuse {
		if r.Cert == "" {
			continue
		}
		if _, err := container(unhex(r.Cert)); err == nil {
			fail("container %s: taken", r.Name)
		}
	}
	fmt.Printf("%-18s checked\n", "container.json")

	if bad > 0 {
		fmt.Printf("%d failures\n", bad)
		os.Exit(1)
	}
	fmt.Println("all good")
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
