// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
)

var update = flag.Bool("update", false, "rewrite testdata/interop/go-release.json")

const nowMS = int64(1_800_000_000_000)

type signer struct {
	key  Signer
	pubs map[int][]byte
	spki []byte // the ES256 half's
}

func newSigner(t *testing.T) signer {
	t.Helper()
	k, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	pubs, err := k.PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	return signer{k, pubs, pubs[AlgES256]}
}

// keys returns the signer's halves as keys.json lists them.
func (s signer) keys(name, use string) []Key {
	return []Key{{Alg: AlgES256, Key: s.pubs[AlgES256], Name: name, Use: use}, {Alg: AlgSLHDSA, Key: s.pubs[AlgSLHDSA], Name: name, Use: use}}
}

// root returns the signer's halves as a pinned root.
func (s signer) root(name string) []Key { return s.keys(name, UseRoot) }

// roots pins each signer as a root.
func roots(ss ...signer) []Key {
	var out []Key
	for i, s := range ss {
		out = append(out, s.root("root-"+string(rune('1'+i)))...)
	}
	return out
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

// otherAlg is the algorithm of Required that is not alg.
func otherAlg(alg int) int {
	if alg == AlgES256 {
		return AlgSLHDSA
	}
	return AlgES256
}

func keysBody(seq uint64, at int64, life time.Duration, keys ...signer) Keys {
	k := Keys{V: 1, Type: TypeKeys, Seq: seq, TimeMS: at, ExpiresMS: at + life.Milliseconds()}
	for i, s := range keys {
		k.Keys = append(k.Keys, s.keys("release key "+string(rune('1'+i)), "")...)
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

// envelope is a release.json as it comes, its text in a string so that
// no reader of the vectors file changes it, under the vectors' first
// keys.json and channel file: whether the envelope is read, and the file
// taken (docs/protocol.md, section 16, "Two signatures").
type envelope struct {
	Name string `json:"name"`
	// Release is the release.json's bytes as they come, in base64: some
	// are not UTF-8.
	Release []byte `json:"release"`
	OK      bool   `json:"ok"`
}

type vectors struct {
	Roots     []Key          `json:"roots"`
	NowMS     int64          `json:"now_ms"`
	Name      string         `json:"channel"`
	Vectors   []vector       `json:"vectors"`
	Status    []statusVector `json:"status"`
	Envelopes []envelope     `json:"envelopes"`
}

// The file on disk lists each signed file once, in files, and its cases
// name them by their index there: an SLH-DSA signature is 7856 bytes, and
// most cases share their keys.json.
type vectorsFile struct {
	Roots   []Key  `json:"roots"`
	NowMS   int64  `json:"now_ms"`
	Name    string `json:"channel"`
	MaxFile int    `json:"max_file"`
	MaxBody int    `json:"max_body"`
	Files   []File `json:"files"`
	Vectors []struct {
		Name    string `json:"name"`
		Keys    int    `json:"keys"`
		Channel int    `json:"channel"`
		Release int    `json:"release"`
		Seen    Seen   `json:"seen"`
		OK      bool   `json:"ok"`
		Version string `json:"version,omitempty"`
	} `json:"vectors"`
	Status []struct {
		Name    string   `json:"name"`
		Keys    int      `json:"keys"`
		Status  int      `json:"status"`
		Seen    Seen     `json:"seen"`
		OK      bool     `json:"ok"`
		Revoked []string `json:"revoked,omitempty"`
	} `json:"status"`
}

// envelopesFile is testdata/interop/go-release-envelopes.json: the
// envelopes under one keys.json and channel file.
type envelopesFile struct {
	Roots     []Key      `json:"roots"`
	NowMS     int64      `json:"now_ms"`
	Name      string     `json:"channel"`
	Keys      File       `json:"keys"`
	Channel   File       `json:"channel_file"`
	Envelopes []envelope `json:"envelopes"`
}

// fileTable numbers files as vectorsFile lists them, each once.
type fileTable struct {
	files []File
	index map[string]int
}

func (t *fileTable) add(f File) int {
	b, _ := json.Marshal(f)
	if i, ok := t.index[string(b)]; ok {
		return i
	}
	if t.index == nil {
		t.index = map[string]int{}
	}
	t.index[string(b)] = len(t.files)
	t.files = append(t.files, f)
	return len(t.files) - 1
}

func (v vectors) MarshalJSON() ([]byte, error) {
	var t fileTable
	out := vectorsFile{Roots: v.Roots, NowMS: v.NowMS, Name: v.Name, MaxFile: MaxFile, MaxBody: MaxBody}
	for _, c := range v.Vectors {
		out.Vectors = append(out.Vectors, struct {
			Name    string `json:"name"`
			Keys    int    `json:"keys"`
			Channel int    `json:"channel"`
			Release int    `json:"release"`
			Seen    Seen   `json:"seen"`
			OK      bool   `json:"ok"`
			Version string `json:"version,omitempty"`
		}{c.Name, t.add(c.Keys), t.add(c.Channel), t.add(c.Release), c.Seen, c.OK, c.Version})
	}
	for _, c := range v.Status {
		out.Status = append(out.Status, struct {
			Name    string   `json:"name"`
			Keys    int      `json:"keys"`
			Status  int      `json:"status"`
			Seen    Seen     `json:"seen"`
			OK      bool     `json:"ok"`
			Revoked []string `json:"revoked,omitempty"`
		}{c.Name, t.add(c.Keys), t.add(c.Status), c.Seen, c.OK, c.Revoked})
	}
	out.Files = t.files
	return json.Marshal(out)
}

func (v *vectors) UnmarshalJSON(b []byte) error {
	var in vectorsFile
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	file := func(i int) File {
		if i < 0 || i >= len(in.Files) {
			return File{}
		}
		return in.Files[i]
	}
	// Every reader of release files reads up to the same sizes.
	if in.MaxFile != MaxFile || in.MaxBody != MaxBody {
		return fmt.Errorf("the file's limits are %d and %d, the reader's %d and %d", in.MaxFile, in.MaxBody, MaxFile, MaxBody)
	}
	*v = vectors{Roots: in.Roots, NowMS: in.NowMS, Name: in.Name}
	for _, c := range in.Vectors {
		v.Vectors = append(v.Vectors, vector{c.Name, file(c.Keys), file(c.Channel), file(c.Release), c.Seen, c.OK, c.Version})
	}
	for _, c := range in.Status {
		v.Status = append(v.Status, statusVector{c.Name, file(c.Keys), file(c.Status), c.Seen, c.OK, c.Revoked})
	}
	return nil
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
	withStatus.Keys = append(withStatus.Keys, sk.keys("status key", UseStatus)...)
	keysStatus := sign(t, withStatus, root1)
	ck := newSigner(t)
	withChannel := keysBody(6, nowMS-1000, 90*day, rk1)
	withChannel.Keys = append(withChannel.Keys, ck.keys("channel key", UseChannel)...)
	keysChannel := sign(t, withChannel, root1)
	unknownUse := keysBody(5, nowMS-1000, 90*day)
	unknownUse.Keys = rk1.keys("a key of a later use", "later")
	v := vectors{Roots: roots(root1, root2), NowMS: nowMS, Name: "stable"}
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
	// Two signatures (docs/protocol.md, section 16, "Two signatures").
	only := func(f File, alg int) File {
		var sigs []Sig
		for _, sg := range f.Sigs {
			if sg.Alg == alg {
				sigs = append(sigs, sg)
			}
		}
		f.Sigs = sigs
		return f
	}
	mixed := func(a, b File, algB int) File {
		out := only(a, otherAlg(algB))
		out.Sigs = append(out.Sigs, only(b, algB).Sigs...)
		return out
	}
	relBy2 := sign(t, releaseBody("0.6.0", "stable"), rk2)
	twoKeys := sign(t, keysBody(9, nowMS-1000, 90*day, rk1, rk2), root1)
	later := rel
	later.Sigs = append(append([]Sig{}, rel.Sigs...), Sig{Alg: 9, Key: bytes.Repeat([]byte{9}, 32), Sig: bytes.Repeat([]byte{7}, 100)})
	laterFirst := rel
	laterFirst.Sigs = append([]Sig{{Alg: 9, Key: bytes.Repeat([]byte{9}, 32), Sig: []byte{1}}}, rel.Sigs...)
	brokenPQ := rel
	brokenPQ.Sigs = append([]Sig{}, rel.Sigs...)
	brokenPQ.Sigs[1].Sig = append([]byte{}, rel.Sigs[1].Sig...)
	brokenPQ.Sigs[1].Sig[100] ^= 1
	strayPQ := rel
	strayPQ.Sigs = append(append([]Sig{}, rel.Sigs...), only(sign(t, releaseBody("0.6.0", "stable"), other), AlgSLHDSA).Sigs...)
	add("release.json with only its ES256 signature", keys, ch, only(rel, AlgES256), first, "")
	add("release.json with only its SLH-DSA signature", keys, ch, only(rel, AlgSLHDSA), first, "")
	add("keys.json with only the root's ES256 signature", only(keys, AlgES256), ch, rel, first, "")
	add("keys.json with only the root's SLH-DSA signature", only(keys, AlgSLHDSA), ch, rel, first, "")
	add("the channel with only its ES256 signature", keys, only(ch, AlgES256), rel, first, "")
	add("release.json signed by two keys, one half each", twoKeys, ch, mixed(rel, relBy2, AlgSLHDSA), first, "")
	add("keys.json signed by two roots, one half each", mixed(keys, sign(t, keysBody(3, nowMS-day.Milliseconds(), 90*day, rk1), root2), AlgSLHDSA), ch, rel, first, "")
	add("release.json with a third signature of a later algorithm", keys, ch, later, first, "0.6.0")
	add("release.json with a signature of a later algorithm first", keys, ch, laterFirst, first, "0.6.0")
	add("release.json with a broken SLH-DSA signature", keys, ch, brokenPQ, first, "")
	add("release.json with an SLH-DSA signature of a key not in keys.json beside", keys, ch, strayPQ, first, "0.6.0")
	add("release.json without signatures", keys, ch, File{Body: rel.Body, Sigs: []Sig{}}, first, "")
	longLater := rel
	longLater.Sigs = append(append([]Sig{}, rel.Sigs...), Sig{Alg: 9, Key: bytes.Repeat([]byte{9}, 32), Sig: bytes.Repeat([]byte{7}, 40000)})
	add("release.json with a signature of a later algorithm of 40000 bytes", keys, ch, longLater, first, "0.6.0")
	laterKey := keysBody(3, nowMS-day.Milliseconds(), 90*day, rk1)
	laterKey.Keys = append(laterKey.Keys, Key{Alg: 9, Key: bytes.Repeat([]byte{5}, 20000), Name: "release key 1"})
	add("keys.json with a key of a later algorithm of 20000 bytes", sign(t, laterKey, root1), ch, rel, first, "0.6.0")
	add("the channel signed by a channel key of another keys.json", keys, sign(t, channelBody("stable", 8, nowMS-1000, 30*day, rel, "0.6.0"), ck), rel, first, "")
	sameName := keysBody(9, nowMS-1000, 90*day)
	sameName.Keys = append(rk1.keys("release key 1", ""), rk2.keys("release key 1", "")...)
	add("release.json signed by two keys under one name, one half each", sign(t, sameName, root1), ch, mixed(rel, relBy2, AlgSLHDSA), first, "")
	twiceBroken := rel
	twiceBroken.Sigs = append(append([]Sig{}, rel.Sigs...), Sig{Alg: AlgSLHDSA, Key: rel.Sigs[1].Key, Sig: brokenPQ.Sigs[1].Sig})
	add("release.json with its pair and a broken second SLH-DSA signature of the same half", keys, ch, twiceBroken, first, "")
	nine := rel
	nine.Sigs = append([]Sig{}, rel.Sigs...)
	for len(nine.Sigs) < 9 {
		nine.Sigs = append(nine.Sigs, Sig{Alg: 9, Key: bytes.Repeat([]byte{9}, 32), Sig: []byte{byte(len(nine.Sigs))}})
	}
	add("release.json with nine signatures", keys, ch, nine, first, "")
	oneName := keysBody(10, nowMS-1000, 90*day)
	oneName.Keys = append(rk1.keys("k", ""), ck.keys("k", UseChannel)...)
	chBody := channelBody("stable", 8, nowMS-1000, 30*day, rel, "0.6.0")
	chFile := mixed(sign(t, chBody, rk1), sign(t, chBody, ck), AlgSLHDSA)
	add("the channel signed by one half of a release key and one of a channel key of the same name", sign(t, oneName, root1), chFile, rel, first, "")
	highS := rel
	highS.Sigs = append([]Sig{}, rel.Sigs...)
	highS.Sigs[0].Sig = otherS(t, rel.Sigs[0].Sig)
	add("release.json whose ES256 signature has the other S", keys, ch, highS, first, "")
	spelled := keysBody(3, nowMS-day.Milliseconds(), 90*day)
	spelled.Keys = rk1.keys("release key 1", "")
	spelled.Keys[1].Use = UseRelease
	add("release.json under a key whose halves spell the release use apart", sign(t, spelled, root1), ch, rel, first, "0.6.0")

	// The envelope as it comes: rel's, its members spelled otherwise.
	body := base64.StdEncoding.EncodeToString(rel.Body)
	sig := func(i int) string {
		g := rel.Sigs[i]
		return fmt.Sprintf(`{"alg":%d,"key":"%s","sig":"%s"}`, g.Alg, base64.StdEncoding.EncodeToString(g.Key), base64.StdEncoding.EncodeToString(g.Sig))
	}
	both := sig(0) + "," + sig(1)
	env := func(name, raw string, ok bool) {
		v.Envelopes = append(v.Envelopes, envelope{name, []byte(raw), ok})
	}
	env("as signed", `{"body":"`+body+`","sigs":[`+both+`]}`, true)
	env("with a member of a later version", `{"body":"`+body+`","sigs":[`+both+`],"later":{"a":[1]}}`, false)
	env("with a signature of a later algorithm with a member of its own", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw==","later":true}]}`, false)
	env("with its body named in capitals", `{"Body":"`+body+`","sigs":[`+both+`]}`, false)
	env("with its body twice", `{"body":"`+body+`","body":"`+body+`","sigs":[`+both+`]}`, false)
	env("with its body broken across lines", `{"body":"`+body[:4]+`\n`+body[4:]+`","sigs":[`+both+`]}`, false)
	env("with sigs null", `{"body":"`+body+`","sigs":null}`, false)
	env("with a signature of a later algorithm without a key", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"sig":"Bw=="}]}`, false)
	env("with a signature of a negative algorithm", `{"body":"`+body+`","sigs":[`+both+`,{"alg":-9,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature of algorithm 0", `{"body":"`+body+`","sigs":[`+both+`,{"alg":0,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature of algorithm 2147483648", `{"body":"`+body+`","sigs":[`+both+`,{"alg":2147483648,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature of algorithm 2147483647", `{"body":"`+body+`","sigs":[`+both+`,{"alg":2147483647,"key":"CQ==","sig":"Bw=="}]}`, true)
	env("with a signature of algorithm 9.5", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9.5,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature whose algorithm is a string", `{"body":"`+body+`","sigs":[`+both+`,{"alg":"9","key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature whose alg is named in capitals", `{"body":"`+body+`","sigs":[`+both+`,{"Alg":9,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature whose key is null", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":null,"sig":"Bw=="}]}`, false)
	env("with a signature whose alg is given twice", `{"body":"`+body+`","sigs":[{"alg":1,"alg":1,"key":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Key)+`","sig":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Sig)+`"},`+sig(1)+`]}`, false)
	env("with a member of a later version whose name escapes a whole surrogate pair", `{"body":"`+body+`","sigs":[`+both+`],"later\ud83d\ude00":1}`, false)
	env("with a member whose name escapes half a surrogate pair", `{"body":"`+body+`","sigs":[`+both+`],"bod\ud800":1}`, false)
	env("with a signature with a member whose name escapes half a surrogate pair", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw==","\udc00":1}]}`, false)
	env("with a member of a later version given twice", `{"body":"`+body+`","sigs":[`+both+`],"later":1,"later":1}`, false)
	env("with a signature with a member of a later version given twice", `{"body":"`+body+`","sigs":[`+sig(0)[:len(sig(0))-1]+`,"later":1,"later":1},`+sig(1)+`]}`, false)
	env("with a signature of a later algorithm with a member of its own given twice", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw==","later":1,"later":1}]}`, false)
	env("with a member of a later version nested 17 deep, the file's object counted", `{"body":"`+body+`","sigs":[`+both+`],"later":`+strings.Repeat("[", 16)+strings.Repeat("]", 16)+`}`, false)
	env("with a member of a later version nested 18 deep, the file's object counted", `{"body":"`+body+`","sigs":[`+both+`],"later":`+strings.Repeat("[", 17)+strings.Repeat("]", 17)+`}`, false)
	env("with a member of a later version nested 10001 deep", `{"body":"`+body+`","sigs":[`+both+`],"later":`+strings.Repeat("[", 10000)+strings.Repeat("]", 10000)+`}`, false)
	env("with a member of a later version whose name is not UTF-8", `{"body":"`+body+`","sigs":[`+both+`],"lat`+"\xff"+`er":1}`, false)
	env("with a member of a later version whose value is not UTF-8", `{"body":"`+body+`","sigs":[`+both+`],"later":"`+"\xff"+`"}`, false)
	env("with a member of a later version named in capitals", `{"body":"`+body+`","sigs":[`+both+`],"Later":1}`, false)
	env("with a member of a later version that is null", `{"body":"`+body+`","sigs":[`+both+`],"later":null}`, false)
	env("with a member of a later version that is a fraction", `{"body":"`+body+`","sigs":[`+both+`],"later":1.5}`, false)
	env("with its body null", `{"body":null,"sigs":[`+both+`]}`, false)
	env("with spaces between its members", `{ "body" : "`+body+`" , "sigs" : [ `+sig(0)+` , `+sig(1)+` ] }`, false)
	env("with the members of a signature in another order", `{"sigs":[{"sig":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Sig)+`","key":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Key)+`","alg":1},`+sig(1)+`],"body":"`+body+`"}`, false)
	env("with a signature of a later algorithm", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw=="}]}`, true)
	env("with sigs before body", `{"sigs":[`+both+`],"body":"`+body+`"}`, false)
	env("with the body's first character written as an escape", `{"body":"\u00`+fmt.Sprintf("%02x", body[0])+body[1:]+`","sigs":[`+both+`]}`, false)
	env("with a line break after it", `{"body":"`+body+`","sigs":[`+both+`]}`+"\n", true)
	env("with a carriage return and a line break after it", `{"body":"`+body+`","sigs":[`+both+`]}`+"\r\n", true)
	env("with a carriage return between its members", `{"body":"`+body+`",`+"\r"+`"sigs":[`+both+`]}`, false)
	env("with spaces and a line break before it", " \n"+`{"body":"`+body+`","sigs":[`+both+`]}`, true)
	env("with a byte order mark", "\xef\xbb\xbf"+`{"body":"`+body+`","sigs":[`+both+`]}`, false)
	env("with a second object after it", `{"body":"`+body+`","sigs":[`+both+`]}{}`, false)
	env("inside a list", `[{"body":"`+body+`","sigs":[`+both+`]}]`, false)
	env("with a comma before its closing brace", `{"body":"`+body+`","sigs":[`+both+`],}`, false)
	env("with a signature that is not an object", `{"body":"`+body+`","sigs":[`+both+`,[9]]}`, false)

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
	withBoth.Keys = append(append([]Key{}, withStatus.Keys...), ck.keys("channel key", UseChannel)...)
	addStatus("signed by the channel key", sign(t, withBoth, root1), sign(t, statusBody(40, nowMS-3600_000, 8*day, revoked...), ck), first, false)
	addStatus("a channel file where the list belongs", keysStatus, sign(t, channelBody("stable", 40, nowMS-1000, day, rel, "0.6.0"), sk), first, false)
	return v
}

// TestReleaseVectors writes (with -update) and checks
// testdata/interop/go-release.json: keys.json, a channel file and
// release.json in valid and invalid combinations (docs/protocol.md,
// section 16), for the Rust cbb and the phone kits to agree with.
func TestReleaseVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-release.json")
	envPath := filepath.Join("..", "..", "testdata", "interop", "go-release-envelopes.json")
	if *update {
		made := makeVectors(t)
		data, err := json.MarshalIndent(made, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		env := envelopesFile{made.Roots, made.NowMS, made.Name, made.Vectors[0].Keys, made.Vectors[0].Channel, made.Envelopes}
		if data, err = json.MarshalIndent(env, "", "\t"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(envPath, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(compacted(t, data), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) != 53 || len(v.Status) != 18 {
		t.Fatalf("the file has %d vectors and %d of the list", len(v.Vectors), len(v.Status))
	}
	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	var env envelopesFile
	if err := json.Unmarshal(compacted(t, envData), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Envelopes) != 46 {
		t.Fatalf("%d envelopes", len(env.Envelopes))
	}
	for _, c := range env.Envelopes {
		var rel File
		err := json.Unmarshal(c.Release, &rel)
		if err == nil {
			_, _, err = Check(env.Keys, env.Channel, rel, env.Roots, env.Name, time.UnixMilli(env.NowMS), Seen{})
		}
		if (err == nil) != c.OK {
			t.Errorf("envelope %s: %v, the file says ok %v", c.Name, err, c.OK)
		}
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
		"unknown version":  Keys{V: 2, Type: TypeKeys, Seq: 1, TimeMS: 1, ExpiresMS: 2, Keys: s.keys("k", "")},
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
	roots := roots(root)
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
	kb.Keys = append(kb.Keys, Key{Alg: AlgES256, Key: fwd.spki, Name: "cbb.tools:8764", Use: UseForwarder})
	keys := sign(t, kb, root)
	now := time.UnixMilli(nowMS)
	k, err := VerifyKeys(keys, roots(root), now, Seen{})
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
	if _, _, err := Check(keys, ch, r, roots(root), "stable", now, Seen{}); err == nil {
		t.Error("a forwarder's key signed a release")
	}
}

// A relay's key in keys.json names the project's relay for its members,
// and entries.json may say where it is reached now.
func TestRelayEntries(t *testing.T) {
	root, rel, relayKey := newSigner(t), newSigner(t), newSigner(t)
	kb := keysBody(1, nowMS-1000, 90*24*time.Hour, rel)
	kb.Keys = append(kb.Keys, Key{Alg: AlgES256, Key: relayKey.spki, Name: "cbb.tools:8765", Use: UseRelay},
		Key{Alg: AlgES256, Key: root.spki, Name: "cbb.tools:8765", Use: UseForwarder})
	keys := sign(t, kb, root)
	now := time.UnixMilli(nowMS)
	k, err := VerifyKeys(keys, roots(root), now, Seen{})
	if err != nil {
		t.Fatal(err)
	}
	if got := k.Relays("cbb.tools:8765"); len(got) != 1 || !bytes.Equal(got[0], relayKey.spki) {
		t.Errorf("Relays = %x", got)
	}
	b := entriesBody(1, nowMS-1000, 30*24*time.Hour)
	b.Relays = []EntryRelay{{Name: "cbb.tools:8765", Endpoints: []string{"relay.cbb.tools:8765", "cbb.tools:8765"}}}
	e, _, err := CheckEntries(keys, sign(t, b, rel), roots(root), now, Seen{})
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
	kb.Keys = append(kb.Keys, ch.keys("channel key", UseChannel)...)
	keys := sign(t, kb, root)
	roots := roots(root)
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

// entriesVector is one case of testdata/interop/go-entries.json.
type entriesVector struct {
	Name    string `json:"name"`
	Keys    File   `json:"keys"`
	Entries File   `json:"entries"`
	Seen    Seen   `json:"seen"`
	OK      bool   `json:"ok"`
	Seq     uint64 `json:"seq,omitempty"`
}

type entriesVectors struct {
	Roots   []Key           `json:"roots"`
	NowMS   int64           `json:"now_ms"`
	Vectors []entriesVector `json:"vectors"`
}

func makeEntriesVectors(t *testing.T) entriesVectors {
	root, other := newSigner(t), newSigner(t)
	rel, ch, sk := newSigner(t), newSigner(t), newSigner(t)
	day := 24 * time.Hour
	kb := keysBody(3, nowMS-1000, 90*day, rel)
	kb.Keys = append(append(kb.Keys, ch.keys("channel key", UseChannel)...), sk.keys("status key", UseStatus)...)
	keys := sign(t, kb, root)
	v := entriesVectors{Roots: roots(root), NowMS: nowMS}
	add := func(name string, k, e File, seen Seen, seq uint64) {
		v.Vectors = append(v.Vectors, entriesVector{Name: name, Keys: k, Entries: e, Seen: seen, OK: seq != 0, Seq: seq})
	}
	good := sign(t, entriesBody(5, nowMS-1000, 30*day), ch)
	add("valid", keys, good, Seen{}, 5)
	add("signed by the release key", keys, sign(t, entriesBody(5, nowMS-1000, 30*day), rel), Seen{}, 5)
	add("the same again", keys, good, Seen{KeysSeq: 3, EntriesSeq: 5, EntriesKeys: 3}, 5)
	add("an older list", keys, good, Seen{KeysSeq: 3, EntriesSeq: 6, EntriesKeys: 3}, 0)
	add("an older list under an older keys.json", keys, good, Seen{KeysSeq: 2, EntriesSeq: 1 << 40, EntriesKeys: 2}, 5)
	add("a list far past the one seen", keys, sign(t, entriesBody(6+MaxSeqStep, nowMS-1000, 30*day), ch), Seen{KeysSeq: 3, EntriesSeq: 5, EntriesKeys: 3}, 0)
	add("an older keys.json", keys, good, Seen{KeysSeq: 4}, 0)
	add("signed by the status key", keys, sign(t, entriesBody(5, nowMS-1000, 30*day), sk), Seen{}, 0)
	add("signed by a root", keys, sign(t, entriesBody(5, nowMS-1000, 30*day), root), Seen{}, 0)
	add("signed by another key", keys, sign(t, entriesBody(5, nowMS-1000, 30*day), other), Seen{}, 0)
	add("expired", keys, sign(t, entriesBody(5, nowMS-31*day.Milliseconds(), 30*day), ch), Seen{}, 0)
	add("lives too long", keys, sign(t, entriesBody(5, nowMS-1000, 101*day), ch), Seen{}, 0)
	add("signed two days ahead", keys, sign(t, entriesBody(5, nowMS+2*day.Milliseconds(), 30*day), ch), Seen{}, 0)
	bad := entriesBody(5, nowMS-1000, 30*day)
	bad.Forwarders[0].VLESS[0].Path = "/short"
	add("a path too short", keys, sign(t, bad, ch), Seen{}, 0)
	return v
}

// TestEntriesVectors writes (with -update) and checks
// testdata/interop/go-entries.json: entries.json with its keys.json in
// valid and invalid combinations (docs/protocol.md, section 16, "Entry
// points"), for the phone kits to agree with.
func TestEntriesVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "go-entries.json")
	if *update {
		data, err := json.MarshalIndent(makeEntriesVectors(t), "", "\t")
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
	var v entriesVectors
	if err := json.Unmarshal(compacted(t, data), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) != 14 {
		t.Fatalf("the file has %d vectors", len(v.Vectors))
	}
	for _, c := range v.Vectors {
		e, seen, err := CheckEntries(c.Keys, c.Entries, v.Roots, time.UnixMilli(v.NowMS), c.Seen)
		if (err == nil) != c.OK {
			t.Errorf("%s: CheckEntries = %v, the file says ok %v", c.Name, err, c.OK)
			continue
		}
		if err == nil && (e.Seq != c.Seq || seen.EntriesSeq != c.Seq || seen.EntriesKeys != 3 || seen.KeysSeq != 3) {
			t.Errorf("%s: seq %d, seen %+v", c.Name, e.Seq, seen)
		}
	}
}

// ClearSLH leaves an SLH-DSA key without its secret.
func TestClearSLH(t *testing.T) {
	k, err := GenerateSLH(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ClearSLH(k)
	b, err := MarshalSLH(k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:32], make([]byte, 32)) {
		t.Errorf("the secret is still there: %x", b[:32])
	}
	if bytes.Equal(b[32:], make([]byte, 32)) {
		t.Error("the public key went too")
	}
}

// TestNISTSLHDSA checks the SLH-DSA library against NIST's vectors for
// SLH-DSA-SHA2-128s (ACVP, external interface, pure, with a context), as
// the Rust core's nist_slh_dsa does.
func TestNISTSLHDSA(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", "nist-slh-dsa-sha2-128s.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			ID, PK, Msg, Ctx, Sig, Reason string
			Pass                          bool
		}
	}
	if err := json.Unmarshal(data, &v); err != nil || len(v.Cases) != 17 {
		t.Fatalf("%d cases, %v", len(v.Cases), err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, c := range v.Cases {
		spki := append(append([]byte{}, slhSPKIPrefix...), unhex(c.PK)...)
		pk := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
		if err := pk.UnmarshalBinary(spki[len(slhSPKIPrefix):]); err != nil {
			t.Fatal(err)
		}
		got := slhdsa.Verify(&pk, slhdsa.NewMessage(unhex(c.Msg)), unhex(c.Sig), unhex(c.Ctx))
		if got != c.Pass {
			t.Errorf("%s (%s): %v, NIST says %v", c.ID, c.Reason, got, c.Pass)
		}
	}
}

// otherS returns the ES256 signature with S replaced by n - S, which
// verifies as well and no reader takes.
func otherS(t *testing.T, sig []byte) []byte {
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		t.Fatal(err)
	}
	rs.S.Sub(elliptic.P256().Params().N, rs.S)
	out, err := asn1.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Signatures are made with S in the lower half, and the other S is refused.
func TestLowS(t *testing.T) {
	s := newSigner(t)
	for range 20 {
		f, err := Sign(releaseBody("0.6.0", "stable"), s.key)
		if err != nil {
			t.Fatal(err)
		}
		if _, low := lowS(f.Sigs[0].Sig); !low {
			t.Fatal("a signature with the high S")
		}
		if !verifyHalf(AlgES256, s.pubs[AlgES256], f.Body, f.Sigs[0].Sig) || verifyHalf(AlgES256, s.pubs[AlgES256], f.Body, otherS(t, f.Sigs[0].Sig)) {
			t.Fatal("the low S refused or the high S taken")
		}
	}
}

// compacted returns a vectors file without the whitespace it is indented
// with: a release file is read in its canonical form, which an indented
// file inside the vectors is not.
func compacted(t *testing.T, data []byte) []byte {
	var b bytes.Buffer
	if err := json.Compact(&b, data); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestReadAll: a release file of MaxFile bytes is read whole, one byte more
// is refused, never cut.
func TestReadAll(t *testing.T) {
	data := bytes.Repeat([]byte("a"), MaxFile)
	if got, err := ReadAll(bytes.NewReader(data)); err != nil || len(got) != MaxFile {
		t.Errorf("read %d bytes of %d: %v", len(got), MaxFile, err)
	}
	if got, err := ReadAll(bytes.NewReader(append(data, 'a'))); err == nil {
		t.Errorf("read %d bytes of a file of %d", len(got), MaxFile+1)
	}
}
