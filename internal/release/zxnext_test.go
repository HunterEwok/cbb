// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func zxnextBody(version string, at int64) ZXNext {
	z := ZXNext{V: 1, Type: TypeZXNext, Version: version, TimeMS: at}
	for i, n := range ZXNextNames {
		z.Files = append(z.Files, ZXNextFile{Name: n, Size: int64(1000 * (i + 1)), CRC32: strings.Repeat("0a", 4), SHA256: strings.Repeat(string(rune('a'+i)), 64)})
	}
	return z
}

// zxnextVector is one case of testdata/interop/go-zxnext.json.
type zxnextVector struct {
	Name      string `json:"name"`
	Keys      File   `json:"keys"`
	List      File   `json:"list"`
	NowMS     int64  `json:"now_ms"`
	Installed string `json:"installed"`
	OK        bool   `json:"ok"`
}

type zxnextVectors struct {
	Comment string         `json:"comment"`
	Roots   []Key          `json:"roots"`
	Vectors []zxnextVector `json:"vectors"`
}

func makeZXNextVectors(t *testing.T) zxnextVectors {
	root, other := newSigner(t), newSigner(t)
	rel, ch := newSigner(t), newSigner(t)
	day := 24 * time.Hour
	kb := keysBody(3, nowMS-1000, 90*day, rel)
	kb.Keys = append(kb.Keys, ch.keys("channel key", UseChannel)...)
	keys := sign(t, kb, root)
	v := zxnextVectors{
		Comment: "Written by internal/release's TestZXNextVectors -update. The Pi's cbb takes a list with ok before .cbb update takes a newer CBB (docs/protocol.md, section 16, \"The ZX Spectrum Next's files\").",
		Roots:   roots(root),
	}
	add := func(name string, k, l File, now int64, installed string, ok bool) {
		v.Vectors = append(v.Vectors, zxnextVector{Name: name, Keys: k, List: l, NowMS: now, Installed: installed, OK: ok})
	}
	good := sign(t, zxnextBody("0.6.1", nowMS-1000), rel)
	add("valid", keys, good, nowMS, "0.6.0", true)
	add("the same release", keys, good, nowMS, "0.6.1", true)
	add("a release candidate before it", keys, good, nowMS, "0.6.1-rc.2", true)
	add("a clock that is not set", keys, good, 0, "0.6.0", true)
	add("an older release", keys, good, nowMS, "0.6.2", false)
	add("signed by the channel key", keys, sign(t, zxnextBody("0.6.1", nowMS-1000), ch), nowMS, "0.6.0", false)
	add("signed by a root", keys, sign(t, zxnextBody("0.6.1", nowMS-1000), root), nowMS, "0.6.0", false)
	add("signed by another key", keys, sign(t, zxnextBody("0.6.1", nowMS-1000), other), nowMS, "0.6.0", false)
	add("keys.json from another root", sign(t, kb, other), good, nowMS, "0.6.0", false)
	add("keys.json expired", keys, good, nowMS+91*day.Milliseconds(), "0.6.0", false)
	add("signed two days ahead", keys, sign(t, zxnextBody("0.6.1", nowMS+2*day.Milliseconds()), rel), nowMS, "0.6.0", false)
	bad := func(name string, edit func(*ZXNext)) {
		z := zxnextBody("0.6.1", nowMS-1000)
		edit(&z)
		add(name, keys, sign(t, z, rel), nowMS, "0.6.0", false)
	}
	bad("a file twice", func(z *ZXNext) { z.Files[1].Name = "CBB" })
	bad("a file missing", func(z *ZXNext) { z.Files = z.Files[:3] })
	bad("another file", func(z *ZXNext) { z.Files[3].Name = "cbb.sh" })
	bad("a SHA-256 in capitals", func(z *ZXNext) { z.Files[0].SHA256 = strings.ToUpper(z.Files[0].SHA256) })
	bad("a CRC-32 too short", func(z *ZXNext) { z.Files[0].CRC32 = "0a0a0a" })
	bad("an empty file", func(z *ZXNext) { z.Files[2].Size = 0 })
	bad("not a version", func(z *ZXNext) { z.Version = "0.6" })
	return v
}

// TestZXNextVectors writes (with -update) and checks
// testdata/interop/go-zxnext.json: zxnext.json with its keys.json in valid
// and invalid combinations, for the Rust core, which the Pi's cbb runs, to
// agree with.
func TestZXNextVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-zxnext.json")
	if *update {
		data, err := json.MarshalIndent(makeZXNextVectors(t), "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v zxnextVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) != 18 {
		t.Fatalf("the file has %d vectors", len(v.Vectors))
	}
	for _, c := range v.Vectors {
		z, err := CheckZXNext(c.Keys, c.List, v.Roots, time.UnixMilli(c.NowMS), c.Installed)
		if (err == nil) != c.OK {
			t.Errorf("%s: CheckZXNext = %v, the file says ok %v", c.Name, err, c.OK)
			continue
		}
		if err == nil {
			if f, ok := z.File("cbb"); !ok || f.Size != 4000 {
				t.Errorf("%s: the Pi's cbb is %+v", c.Name, f)
			}
		}
	}
}

// Sign takes a valid zxnext.json and refuses one that is not.
func TestSignZXNext(t *testing.T) {
	s := newSigner(t)
	if _, err := Sign(zxnextBody("0.6.1", nowMS), s.key); err != nil {
		t.Fatal(err)
	}
	z := zxnextBody("0.6.1", nowMS)
	z.Files = z.Files[:2]
	if _, err := Sign(z, s.key); err == nil {
		t.Error("Sign took a list without the Pi's cbb")
	}
}
