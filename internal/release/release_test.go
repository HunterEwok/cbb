// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/interop/go-release.json")

const nowMS = int64(1_800_000_000_000)

type signer struct {
	key  *ecdsa.PrivateKey
	spki []byte
}

func newSigner(t *testing.T) signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer{k, spki}
}

func sign(t *testing.T, body any, s signer) File {
	t.Helper()
	// Some vectors are bodies Sign refuses, so this signs without the check.
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	f, err := signData(data, s.key)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func keysBody(seq uint64, at int64, life time.Duration, keys ...signer) Keys {
	k := Keys{V: 1, Type: TypeKeys, Seq: seq, TimeMS: at, ExpiresMS: at + life.Milliseconds()}
	for i, s := range keys {
		k.Keys = append(k.Keys, Key{Key: s.spki, Name: "release key " + string(rune('1'+i))})
	}
	return k
}

func releaseBody(version, channel string) Release {
	sum := strings.Repeat("ab", 32)
	return Release{V: 1, Type: TypeRelease, Version: version, Channel: channel, TimeMS: nowMS - 1000, MinFrom: "0.4.0",
		Files: []Asset{
			{Name: "cbb_" + version + "_linux_amd64.tar.gz", Size: 1234, SHA256: sum,
				Binaries: []Binary{{Name: "cbb", SHA256: strings.Repeat("cd", 32)}}},
			{Name: "SHA256SUMS", Size: 100, SHA256: strings.Repeat("ef", 32)},
		},
		Docker: &Docker{Image: "ghcr.io/example/cbb", Digest: "sha256:" + sum},
	}
}

func channelBody(name string, seq uint64, at int64, life time.Duration, rel File, version string) Channel {
	h := rel.Hash()
	return Channel{V: 1, Type: TypeChannel, Channel: name, Seq: seq, TimeMS: at, ExpiresMS: at + life.Milliseconds(),
		Release: version, ReleaseSHA256: hex.EncodeToString(h[:])}
}

type vector struct {
	Name    string `json:"name"`
	Keys    File   `json:"keys"`
	Channel File   `json:"channel"`
	Release File   `json:"release"`
	Seen    Seen   `json:"seen"`
	OK      bool   `json:"ok"`
	Version string `json:"version,omitempty"`
}

type statusVector struct {
	Name    string   `json:"name"`
	Keys    File     `json:"keys"`
	Status  File     `json:"status"`
	Seen    Seen     `json:"seen"`
	OK      bool     `json:"ok"`
	Revoked []string `json:"revoked,omitempty"`
}

type vectors struct {
	Roots   [][]byte       `json:"roots"`
	NowMS   int64          `json:"now_ms"`
	Name    string         `json:"channel"`
	Vectors []vector       `json:"vectors"`
	Status  []statusVector `json:"status"`
}

func statusBody(seq uint64, at int64, life time.Duration, revoked ...string) Status {
	if revoked == nil {
		revoked = []string{}
	}
	return Status{V: 1, Type: TypeStatus, Seq: seq, TimeMS: at, ExpiresMS: at + life.Milliseconds(), SourceMS: at - 3600_000, AndroidRevoked: revoked}
}

// makeVectors builds the cases every verifier must agree on.
func makeVectors(t *testing.T) vectors {
	root1, root2, other := newSigner(t), newSigner(t), newSigner(t)
	rk1, rk2 := newSigner(t), newSigner(t)
	day := 24 * time.Hour
	keys := sign(t, keysBody(3, nowMS-day.Milliseconds(), 90*day, rk1), root1)
	rotated := sign(t, keysBody(4, nowMS-1000, 90*day, rk2), root2)
	rel := sign(t, releaseBody("0.6.0", "stable"), rk1)
	ch := sign(t, channelBody("stable", 7, nowMS-1000, 30*day, rel, "0.6.0"), rk1)
	rel2 := sign(t, releaseBody("0.6.0", "stable"), rk2)
	ch2 := sign(t, channelBody("stable", 8, nowMS-1000, 30*day, rel2, "0.6.0"), rk2)
	altered := rel
	altered.Body = []byte(strings.Replace(string(rel.Body), `"size":1234`, `"size":1235`, 1))
	other1 := sign(t, releaseBody("0.6.1", "stable"), rk1)
	beta := sign(t, releaseBody("0.6.0", "beta"), rk1)
	expiredKeys := sign(t, keysBody(3, nowMS-91*day.Milliseconds(), 90*day, rk1), root1)
	longKeys := sign(t, keysBody(3, nowMS-1000, 101*day, rk1), root1)
	sk := newSigner(t)
	withStatus := keysBody(5, nowMS-1000, 90*day, rk1)
	withStatus.Keys = append(withStatus.Keys, Key{Key: sk.spki, Name: "status key", Use: UseStatus})
	keysStatus := sign(t, withStatus, root1)
	ck := newSigner(t)
	withChannel := keysBody(6, nowMS-1000, 90*day, rk1)
	withChannel.Keys = append(withChannel.Keys, Key{Key: ck.spki, Name: "channel key", Use: UseChannel})
	keysChannel := sign(t, withChannel, root1)
	unknownUse := keysBody(5, nowMS-1000, 90*day)
	unknownUse.Keys = []Key{{Key: rk1.spki, Name: "a key of a later use", Use: "later"}}
	v := vectors{Roots: [][]byte{root1.spki, root2.spki}, NowMS: nowMS, Name: "stable"}
	add := func(name string, k, c, r File, seen Seen, version string) {
		v.Vectors = append(v.Vectors, vector{Name: name, Keys: k, Channel: c, Release: r, Seen: seen, OK: version != "", Version: version})
	}
	first := Seen{}
	add("valid", keys, ch, rel, first, "0.6.0")
	add("valid after an older one", keys, ch, rel, Seen{KeysSeq: 2, ChannelSeq: 6, Version: "0.5.3"}, "0.6.0")
	add("the same again", keys, ch, rel, Seen{KeysSeq: 3, ChannelSeq: 7, Version: "0.6.0"}, "0.6.0")
	add("a release key rotated by the second root", rotated, ch2, rel2, Seen{KeysSeq: 3, ChannelSeq: 7}, "0.6.0")
	add("signed by a release key the new keys.json dropped", rotated, ch, rel, first, "")
	add("keys.json signed by a key that is not a root", sign(t, keysBody(3, nowMS-1000, 90*day, rk1), other), ch, rel, first, "")
	add("keys.json signed by a release key", sign(t, keysBody(3, nowMS-1000, 90*day, rk1), rk1), ch, rel, first, "")
	add("the channel signed by a root", keys, sign(t, channelBody("stable", 7, nowMS-1000, 30*day, rel, "0.6.0"), root1), rel, first, "")
	add("release.json altered", keys, ch, altered, first, "")
	add("release.json signed by another key", keys, ch, sign(t, releaseBody("0.6.0", "stable"), other), first, "")
	add("keys.json expired", expiredKeys, ch, rel, first, "")
	add("the channel expired", keys, sign(t, channelBody("stable", 7, nowMS-31*day.Milliseconds(), 30*day, rel, "0.6.0"), rk1), rel, first, "")
	add("keys.json lives too long", longKeys, ch, rel, first, "")
	add("the channel lives too long", keys, sign(t, channelBody("stable", 7, nowMS-1000, 101*day, rel, "0.6.0"), rk1), rel, first, "")
	add("a release where the channel file belongs", keys, rel, rel, first, "")
	add("keys.json where the channel file belongs", keys, keys, rel, first, "")
	add("an older keys.json", keys, ch, rel, Seen{KeysSeq: 4}, "")
	add("an older channel file", keys, ch, rel, Seen{KeysSeq: 3, ChannelSeq: 8}, "")
	add("an older channel file under an older keys.json", keys, ch, rel, Seen{KeysSeq: 2, ChannelSeq: 1 << 62, ChannelKeys: 2}, "0.6.0")
	add("a channel file far past the one seen", keys, sign(t, channelBody("stable", 7+MaxSeqStep+1, nowMS-1000, 30*day, rel, "0.6.0"), rk1), rel,
		Seen{KeysSeq: 3, ChannelSeq: 7, ChannelKeys: 3}, "")
	add("a channel file signed two days ahead", keys, sign(t, channelBody("stable", 8, nowMS+2*day.Milliseconds(), 30*day, rel, "0.6.0"), rk1), rel, first, "")
	add("an older version", keys, ch, rel, Seen{Version: "0.6.1"}, "")
	add("another release than the channel names", keys, ch, other1, first, "")
	add("the channel names another version", keys, sign(t, channelBody("stable", 7, nowMS-1000, 30*day, rel, "0.6.1"), rk1), rel, first, "")
	add("the file of another channel", keys, sign(t, channelBody("beta", 7, nowMS-1000, 30*day, beta, "0.6.0"), rk1), beta, first, "")
	add("a release of another channel", keys, sign(t, channelBody("stable", 7, nowMS-1000, 30*day, beta, "0.6.0"), rk1), beta, first, "")
	add("valid beside a status key", keysStatus, ch, rel, first, "0.6.0")
	add("the channel signed by the status key", keysStatus, sign(t, channelBody("stable", 7, nowMS-1000, 30*day, rel, "0.6.0"), sk), rel, first, "")
	add("release.json signed by the status key", keysStatus, ch, sign(t, releaseBody("0.6.0", "stable"), sk), first, "")
	add("signed by a key of a use the reader does not know", sign(t, unknownUse, root1), ch, rel, first, "")
	add("the channel signed by the channel key", keysChannel, sign(t, channelBody("stable", 8, nowMS-1000, 30*day, rel, "0.6.0"), ck), rel, first, "0.6.0")
	add("release.json signed by the channel key", keysChannel, sign(t, channelBody("stable", 8, nowMS-1000, 30*day, rel, "0.6.0"), ck),
		sign(t, releaseBody("0.6.0", "stable"), ck), first, "")
	add("the channel signed by a channel key of another keys.json", keys, sign(t, channelBody("stable", 8, nowMS-1000, 30*day, rel, "0.6.0"), ck), rel, first, "")

	revoked := []string{"0", "1f", "9a", "c35a2e1e3b46b5a1", "15b3d8b2f3a0e3e3cc1d2a4e1f0b7c9d"}
	addStatus := func(name string, k, st File, seen Seen, ok bool) {
		c := statusVector{Name: name, Keys: k, Status: st, Seen: seen, OK: ok}
		if ok {
			c.Revoked = revoked
		}
		v.Status = append(v.Status, c)
	}
	good := sign(t, statusBody(40, nowMS-3600_000, 8*day, revoked...), sk)
	addStatus("valid", keysStatus, good, first, true)
	addStatus("the same again", keysStatus, good, Seen{KeysSeq: 5, StatusSeq: 40}, true)
	addStatus("an older list", keysStatus, good, Seen{KeysSeq: 5, StatusSeq: 41}, false)
	addStatus("an older list under an older keys.json", keysStatus, good, Seen{KeysSeq: 4, StatusSeq: 1 << 62, StatusKeys: 4}, true)
	addStatus("a list far past the one seen", keysStatus, sign(t, statusBody(40+MaxSeqStep+1, nowMS-3600_000, 8*day, revoked...), sk),
		Seen{KeysSeq: 5, StatusSeq: 40, StatusKeys: 5}, false)
	addStatus("a list signed two days ahead", keysStatus, sign(t, statusBody(41, nowMS+2*day.Milliseconds(), 8*day, revoked...), sk), first, false)
	addStatus("an older keys.json", keysStatus, good, Seen{KeysSeq: 6}, false)
	addStatus("signed by a release key", keysStatus, sign(t, statusBody(40, nowMS-3600_000, 8*day, revoked...), rk1), first, false)
	addStatus("signed by a root", keysStatus, sign(t, statusBody(40, nowMS-3600_000, 8*day, revoked...), root1), first, false)
	addStatus("keys.json without a status key", keys, good, first, false)
	addStatus("expired", keysStatus, sign(t, statusBody(40, nowMS-9*day.Milliseconds(), 8*day, revoked...), sk), first, false)
	addStatus("lives too long", keysStatus, sign(t, statusBody(40, nowMS-1000, 9*day, revoked...), sk), first, false)
	addStatus("serials out of order", keysStatus, sign(t, statusBody(40, nowMS-1000, day, "9a", "1f"), sk), first, false)
	addStatus("a serial twice", keysStatus, sign(t, statusBody(40, nowMS-1000, day, "1f", "1f"), sk), first, false)
	addStatus("a serial with a leading zero", keysStatus, sign(t, statusBody(40, nowMS-1000, day, "01f"), sk), first, false)
	addStatus("a serial in capitals", keysStatus, sign(t, statusBody(40, nowMS-1000, day, "1F"), sk), first, false)
	withBoth := withStatus
	withBoth.Keys = append(append([]Key{}, withStatus.Keys...), Key{Key: ck.spki, Name: "channel key", Use: UseChannel})
	addStatus("signed by the channel key", sign(t, withBoth, root1), sign(t, statusBody(40, nowMS-3600_000, 8*day, revoked...), ck), first, false)
	addStatus("a channel file where the list belongs", keysStatus, sign(t, channelBody("stable", 40, nowMS-1000, day, rel, "0.6.0"), sk), first, false)
	return v
}

// TestReleaseVectors writes (with -update) and checks
// testdata/interop/go-release.json: keys.json, a channel file and
// release.json in valid and invalid combinations (docs/protocol.md,
// section 16), for the lite member and the phone kits to agree with.
func TestReleaseVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-release.json")
	if *update {
		data, err := json.MarshalIndent(makeVectors(t), "", "\t")
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
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) != 33 || len(v.Status) != 18 {
		t.Fatalf("the file has %d vectors and %d of the list", len(v.Vectors), len(v.Status))
	}
	for _, c := range v.Status {
		st, seen, err := CheckStatus(c.Keys, c.Status, v.Roots, time.UnixMilli(v.NowMS), c.Seen)
		if (err == nil) != c.OK {
			t.Errorf("%s: CheckStatus = %v, the file says ok %v", c.Name, err, c.OK)
			continue
		}
		if err != nil {
			if seen != c.Seen {
				t.Errorf("%s: a refused check changed seen", c.Name)
			}
			continue
		}
		if strings.Join(st.AndroidRevoked, ",") != strings.Join(c.Revoked, ",") || seen.StatusSeq != st.Seq || seen.KeysSeq != 5 {
			t.Errorf("%s: %v, seen %+v", c.Name, st.AndroidRevoked, seen)
		}
	}
	for _, c := range v.Vectors {
		r, seen, err := Check(c.Keys, c.Channel, c.Release, v.Roots, v.Name, time.UnixMilli(v.NowMS), c.Seen)
		if (err == nil) != c.OK {
			t.Errorf("%s: Check = %v, the file says ok %v", c.Name, err, c.OK)
			continue
		}
		if err != nil {
			if seen != c.Seen {
				t.Errorf("%s: a refused check changed seen", c.Name)
			}
			continue
		}
		if r.Version != c.Version || seen.Version != c.Version {
			t.Errorf("%s: version %s, seen %s, the file has %s", c.Name, r.Version, seen.Version, c.Version)
		}
	}
}

func TestCheckErrors(t *testing.T) {
	v := makeVectors(t)
	now := time.UnixMilli(v.NowMS)
	at := func(name string) vector {
		for _, c := range v.Vectors {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no vector %q", name)
		return vector{}
	}
	for name, want := range map[string]error{
		"keys.json expired":                    ErrExpired,
		"the channel expired":                  ErrExpired,
		"an older version":                     ErrRollback,
		"an older keys.json":                   ErrRollback,
		"a channel file far past the one seen": ErrJump,
		"a channel file signed two days ahead": ErrJump,
		"release.json altered":                 ErrSignature,
		"keys.json signed by a release key":    ErrSignature,
		"the channel signed by a root":         ErrSignature,
	} {
		c := at(name)
		_, _, err := Check(c.Keys, c.Channel, c.Release, v.Roots, v.Name, now, c.Seen)
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	c := at("valid after an older one")
	r, seen, err := Check(c.Keys, c.Channel, c.Release, v.Roots, v.Name, now, c.Seen)
	if err != nil {
		t.Fatal(err)
	}
	if seen != (Seen{KeysSeq: 3, ChannelSeq: 7, Version: "0.6.0", ChannelKeys: 3, StatusKeys: 2}) {
		t.Errorf("seen = %+v", seen)
	}
	if !r.Direct("0.4.0") || !r.Direct("0.5.3") || r.Direct("0.3.9") {
		t.Error("Direct does not follow min_from")
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.6.0", "0.6.0", 0},
		{"0.6.0", "0.5.9", 1},
		{"0.10.0", "0.9.0", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.6.0", "0.6.1", -1},
		{"bad", "0.0.0", -1},
		{"0.0.0", "", 1},
		{"0.6.0-rc.1", "0.6.0", -1},
		{"0.6.0-rc.2", "0.6.0-rc.10", -1},
		{"0.6.0-rc.1", "0.5.9", 1},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"v0.6.0", "0.6", "0.06.0", "0.6.0-rc.0", "0.6.0-beta.1", "0.6.0.1", "1234567.0.0"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("%q passed as a version", bad)
		}
	}
}

func TestCheckFile(t *testing.T) {
	data := []byte("the archive")
	sum := sha256.Sum256(data)
	r := releaseBody("0.6.0", "stable")
	r.Files[0].Size, r.Files[0].SHA256 = int64(len(data)), hex.EncodeToString(sum[:])
	name := r.Files[0].Name
	if err := r.CheckFile(name, data); err != nil {
		t.Fatal(err)
	}
	if r.CheckFile(name, []byte("the archivf")) == nil || r.CheckFile("other.tar.gz", data) == nil {
		t.Error("CheckFile took a file that is not in the release")
	}
}

func TestSignRefusesBadBodies(t *testing.T) {
	s := newSigner(t)
	for name, body := range map[string]any{
		"no type":          map[string]any{"v": 1},
		"unknown version":  Keys{V: 2, Type: TypeKeys, Seq: 1, TimeMS: 1, ExpiresMS: 2, Keys: []Key{{Key: s.spki, Name: "k"}}},
		"no keys":          Keys{V: 1, Type: TypeKeys, Seq: 1, TimeMS: 1, ExpiresMS: 2},
		"a bad version":    func() Release { r := releaseBody("0.6.0", "stable"); r.Version = "v0.6.0"; return r }(),
		"a path as a name": func() Release { r := releaseBody("0.6.0", "stable"); r.Files[0].Name = "../cbb"; return r }(),
		"a name twice":     func() Release { r := releaseBody("0.6.0", "stable"); r.Files[1].Name = r.Files[0].Name; return r }(),
		"a short hash":     func() Release { r := releaseBody("0.6.0", "stable"); r.Files[0].SHA256 = "ab"; return r }(),
		"a binary path out": func() Release {
			r := releaseBody("0.6.0", "stable")
			r.Files[0].Binaries[0].Name = "a/../../cbb"
			return r
		}(),
		"no release hash": Channel{V: 1, Type: TypeChannel, Channel: "stable", Seq: 1, TimeMS: 1, ExpiresMS: 2, Release: "0.6.0"},
	} {
		if _, err := Sign(body, s.key); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestCheckPinned(t *testing.T) {
	root, rk, other := newSigner(t), newSigner(t), newSigner(t)
	roots := [][]byte{root.spki}
	now := time.UnixMilli(nowMS)
	keys := sign(t, keysBody(2, nowMS-1000, 90*24*time.Hour, rk), root)
	rel := sign(t, releaseBody("0.5.2", "stable"), rk)
	r, seen, err := CheckPinned(keys, rel, roots, now, Seen{KeysSeq: 2, ChannelSeq: 9, Version: "0.5.1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "0.5.2" || seen != (Seen{KeysSeq: 2, ChannelSeq: 9, Version: "0.5.2"}) {
		t.Errorf("%s, seen %+v", r.Version, seen)
	}
	if _, _, err := CheckPinned(keys, rel, roots, now, Seen{Version: "0.6.0"}); !errors.Is(err, ErrRollback) {
		t.Errorf("below the highest seen: %v", err)
	}
	if _, _, err := CheckPinned(keys, sign(t, releaseBody("0.5.2", "stable"), other), roots, now, Seen{}); !errors.Is(err, ErrSignature) {
		t.Errorf("signed by another key: %v", err)
	}
	if _, _, err := CheckPinned(keys, rel, roots, now, Seen{KeysSeq: 3}); !errors.Is(err, ErrRollback) {
		t.Errorf("an older keys.json: %v", err)
	}
}

// A seq rises at most MaxSeqStep past the one a device holds, and past
// none on a fresh device, so one file cannot take a device to a seq that
// no later file reaches.
func TestSeqStepFromNothing(t *testing.T) {
	for _, c := range []struct {
		seq, floor uint64
		ok         bool
	}{
		{1, 0, true}, {MaxSeqStep, 0, true}, {MaxSeqStep + 1, 0, false}, {1<<64 - 1, 0, false},
		{10 + MaxSeqStep, 10, true}, {11 + MaxSeqStep, 10, false}, {9, 10, false},
	} {
		if err := checkSeq(c.seq, c.floor); (err == nil) != c.ok {
			t.Errorf("seq %d over %d: %v", c.seq, c.floor, err)
		}
	}
}

// A lifetime from a time before 1970 is refused, so that its length
// cannot leave the range of int64.
func TestLifetimeInRange(t *testing.T) {
	for _, c := range []struct {
		time, expires int64
		ok            bool
	}{
		{1, 2, true},
		{0, MaxLifetime.Milliseconds(), true},
		{0, MaxLifetime.Milliseconds() + 1, false},
		{-1, 1, false},
		{math.MinInt64, math.MaxInt64, false},
		{-(1 << 62), math.MaxInt64, false},
	} {
		if err := lifetime(c.time, c.expires); (err == nil) != c.ok {
			t.Errorf("lifetime from %d to %d: %v", c.time, c.expires, err)
		}
	}
}

// TestStrictFiles reads the release files of
// testdata/interop/strict-files.json, which internal/group's
// TestStrictGeneratedFiles writes from the tables of docs/protocol.md.
func TestStrictFiles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "strict-files.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Releases []struct {
			Name, Rule, Kind string
			Valid            bool
			Body             []byte
			PadAt            int `json:"pad_at"`
			Pad              int
		}
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Releases) == 0 {
		t.Fatal("no release files")
	}
	for _, c := range v.Releases {
		body := c.Body
		if c.Pad > 0 {
			body = append(append(append([]byte{}, body[:c.PadAt]...), strings.Repeat("a", c.Pad)...), body[c.PadAt:]...)
		}
		var err error
		switch {
		case len(body) > MaxBody:
			err = errors.New("too large")
		case c.Kind == TypeKeys:
			_, err = decodeKeys(body)
		case c.Kind == TypeRelease:
			_, err = decodeRelease(body)
		case c.Kind == TypeChannel:
			_, err = decodeChannel(body)
		case c.Kind == TypeStatus:
			_, err = decodeStatus(body)
		default:
			t.Fatalf("%s: unknown kind %q", c.Name, c.Kind)
		}
		if (err == nil) != c.Valid {
			t.Errorf("%q (%s): valid %v, got %v", c.Name, c.Rule, c.Valid, err)
		}
	}
}

// A forwarder's key in keys.json names the project's forwarder for the
// hubs and signs nothing.
func TestForwarderKeys(t *testing.T) {
	root, rel, fwd := newSigner(t), newSigner(t), newSigner(t)
	kb := keysBody(1, nowMS-1000, 90*24*time.Hour, rel)
	kb.Keys = append(kb.Keys, Key{Key: fwd.spki, Name: "cbb.tools:8764", Use: UseForwarder})
	keys := sign(t, kb, root)
	now := time.UnixMilli(nowMS)
	k, err := VerifyKeys(keys, [][]byte{root.spki}, now, Seen{})
	if err != nil {
		t.Fatal(err)
	}
	if got := k.Forwarders("cbb.tools:8764"); len(got) != 1 || !bytes.Equal(got[0], fwd.spki) {
		t.Errorf("Forwarders = %x", got)
	}
	if got := k.Forwarders("example.org:8764"); len(got) != 0 {
		t.Errorf("another forwarder's keys: %x", got)
	}
	r := sign(t, releaseBody("0.6.0", "stable"), fwd)
	ch := sign(t, channelBody("stable", 1, nowMS-1000, 30*24*time.Hour, r, "0.6.0"), rel)
	if _, _, err := Check(keys, ch, r, [][]byte{root.spki}, "stable", now, Seen{}); err == nil {
		t.Error("a forwarder's key signed a release")
	}
}

// A relay's key in keys.json names the project's relay for its members,
// and entries.json may say where it is reached now.
func TestRelayEntries(t *testing.T) {
	root, rel, relayKey := newSigner(t), newSigner(t), newSigner(t)
	kb := keysBody(1, nowMS-1000, 90*24*time.Hour, rel)
	kb.Keys = append(kb.Keys, Key{Key: relayKey.spki, Name: "cbb.tools:8765", Use: UseRelay},
		Key{Key: root.spki, Name: "cbb.tools:8765", Use: UseForwarder})
	keys := sign(t, kb, root)
	now := time.UnixMilli(nowMS)
	k, err := VerifyKeys(keys, [][]byte{root.spki}, now, Seen{})
	if err != nil {
		t.Fatal(err)
	}
	if got := k.Relays("cbb.tools:8765"); len(got) != 1 || !bytes.Equal(got[0], relayKey.spki) {
		t.Errorf("Relays = %x", got)
	}
	b := entriesBody(1, nowMS-1000, 30*24*time.Hour)
	b.Relays = []EntryRelay{{Name: "cbb.tools:8765", Endpoints: []string{"relay.cbb.tools:8765", "cbb.tools:8765"}}}
	e, _, err := CheckEntries(keys, sign(t, b, rel), [][]byte{root.spki}, now, Seen{})
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := e.Relay("cbb.tools:8765"); !ok || len(r.Endpoints) != 2 {
		t.Errorf("Relay = %+v, %v", r, ok)
	}
	if _, ok := e.Relay("example.org:8765"); ok {
		t.Error("another relay's entry")
	}
}

func entriesBody(seq uint64, at int64, life time.Duration) Entries {
	return Entries{V: 1, Type: TypeEntries, Seq: seq, TimeMS: at, ExpiresMS: at + life.Milliseconds(),
		Forwarders: []EntryForwarder{{Name: "cbb.tools:8764",
			VLESS: []EntryVLESS{{Transport: "xhttp", ServerName: "cbb.tools", Port: 443, Path: "/banMEJvnYJJap8S"}}}}}
}

// entries.json passes under a release or channel key, not older than seen
// and not expired, and its bad forms are refused.
func TestCheckEntries(t *testing.T) {
	root, rel, ch, other := newSigner(t), newSigner(t), newSigner(t), newSigner(t)
	kb := keysBody(2, nowMS-1000, 90*24*time.Hour, rel)
	kb.Keys = append(kb.Keys, Key{Key: ch.spki, Name: "channel key", Use: UseChannel})
	keys := sign(t, kb, root)
	roots := [][]byte{root.spki}
	now := time.UnixMilli(nowMS)
	e, seen, err := CheckEntries(keys, sign(t, entriesBody(5, nowMS-1000, 30*24*time.Hour), ch), roots, now, Seen{})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := e.Forwarder("cbb.tools:8764"); !ok || f.VLESS[0].Path != "/banMEJvnYJJap8S" || seen.EntriesSeq != 5 || seen.EntriesKeys != 2 {
		t.Fatalf("took %+v, seen %+v", e, seen)
	}
	if _, _, err := CheckEntries(keys, sign(t, entriesBody(6, nowMS-1000, 30*24*time.Hour), rel), roots, now, seen); err != nil {
		t.Errorf("under the release key: %v", err)
	}
	if _, _, err := CheckEntries(keys, sign(t, entriesBody(4, nowMS-1000, 30*24*time.Hour), ch), roots, now, seen); !errors.Is(err, ErrRollback) {
		t.Errorf("an older one: %v", err)
	}
	if _, _, err := CheckEntries(keys, sign(t, entriesBody(6, nowMS-1000, 30*24*time.Hour), other), roots, now, seen); err == nil {
		t.Error("one under another key was taken")
	}
	if _, _, err := CheckEntries(keys, sign(t, entriesBody(6, nowMS-3000, time.Second), ch), roots, now, seen); !errors.Is(err, ErrExpired) {
		t.Errorf("an expired one: %v", err)
	}
	for _, bad := range []func(*Entries){
		func(e *Entries) { e.Forwarders[0].Name = "cbb.tools" },
		func(e *Entries) { e.Forwarders[0].VLESS[0].Transport = "reality" },
		func(e *Entries) { e.Forwarders[0].VLESS[0].Path = "/short" },
		func(e *Entries) { e.Forwarders[0].VLESS[0].Port = 0 },
		func(e *Entries) { e.Forwarders = append(e.Forwarders, e.Forwarders[0]) },
		func(e *Entries) { e.Forwarders = nil },
		func(e *Entries) { e.Relays = []EntryRelay{{Name: "cbb.tools"}} },
		func(e *Entries) {
			e.Relays = []EntryRelay{{Name: "cbb.tools:8765", Endpoints: []string{"203.0.113.9:8765"}}}
		},
		func(e *Entries) { e.Relays = []EntryRelay{{Name: "cbb.tools:8765"}, {Name: "cbb.tools:8765"}} },
	} {
		b := entriesBody(7, nowMS-1000, 30*24*time.Hour)
		bad(&b)
		if _, _, err := CheckEntries(keys, sign(t, b, ch), roots, now, seen); err == nil {
			t.Errorf("a bad one was taken: %+v", b)
		}
	}
}
