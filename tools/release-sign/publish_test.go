// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// fakeGitHub plays the gh commands publish and renew run: each release's
// files in a directory named by its tag, the branch channel in one more.
type fakeGitHub struct {
	t        *testing.T
	dir      string
	drafts   map[string]bool
	attested bool
	branch   bool
	commits  int
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{t: t, dir: t.TempDir(), drafts: map[string]bool{}, attested: true}
	prev := gh
	gh = g.run
	t.Cleanup(func() { gh = prev })
	return g
}

// draft makes a draft release of the archives, as the release workflow does.
func (g *fakeGitHub) draft(tag string) {
	archives(g.t, g.release(tag))
	g.drafts[tag] = true
}

func (g *fakeGitHub) release(tag string) string {
	d := filepath.Join(g.dir, tag)
	os.MkdirAll(d, 0o755)
	return d
}

// channel is the branch's directory.
func (g *fakeGitHub) channel() string { return g.release("branch") }

// argAfter returns the value after name in args.
func argAfter(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// fields returns the -f values of args.
func fields(args []string) map[string]string {
	out := map[string]string{}
	for i, a := range args {
		if a == "-f" && i+1 < len(args) {
			k, v, _ := strings.Cut(args[i+1], "=")
			out[k] = v
		}
	}
	return out
}

func copyFile(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, data, 0o644)
}

func (g *fakeGitHub) run(args ...string) ([]byte, error) {
	switch {
	case args[0] == "release" && args[1] == "view":
		draft, ok := g.drafts[args[2]]
		if !ok {
			return nil, errors.New("release not found")
		}
		return json.Marshal(map[string]any{"isDraft": draft,
			"body": "notes\n\n```\nghcr.io/hunterewok/cbb@sha256:" + strings.Repeat("ab", 32) + "\n```\n"})
	case args[0] == "release" && args[1] == "download":
		if _, ok := g.drafts[args[2]]; !ok {
			return nil, errors.New("release not found")
		}
		entries, _ := os.ReadDir(g.release(args[2]))
		for _, e := range entries {
			if p := argAfter(args, "--pattern"); p != "" && p != e.Name() {
				continue
			}
			if err := copyFile(filepath.Join(g.release(args[2]), e.Name()), filepath.Join(argAfter(args, "--dir"), e.Name())); err != nil {
				return nil, err
			}
		}
		return nil, nil
	case args[0] == "attestation":
		if !g.attested {
			return nil, errors.New("verification failed")
		}
		return nil, nil
	case args[0] == "release" && args[1] == "upload":
		if !g.drafts[args[2]] {
			g.t.Errorf("uploaded to %s, which is no draft", args[2])
		}
		for _, a := range args[3:] {
			if strings.HasSuffix(a, ".json") {
				if filepath.Base(a) != "release.json" && filepath.Base(a) != zxnextName {
					g.t.Errorf("uploaded %s to the release", a)
				}
				if err := copyFile(a, filepath.Join(g.release(args[2]), filepath.Base(a))); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	case args[0] == "release" && args[1] == "edit":
		g.drafts[args[2]] = false
		return nil, nil
	case args[0] == "api" && strings.Contains(args[1], "/contents/"):
		name := strings.TrimSuffix(args[1][strings.Index(args[1], "/contents/")+len("/contents/"):], "?ref=channel")
		data, err := os.ReadFile(filepath.Join(g.channel(), name))
		if err != nil {
			return nil, errors.New("HTTP 404")
		}
		return json.Marshal(map[string]string{"content": base64.StdEncoding.EncodeToString(data), "sha": "sha-" + name})
	case args[0] == "api" && args[1] == "-X" && args[2] == "PUT":
		f := fields(args)
		name := args[3][strings.Index(args[3], "/contents/")+len("/contents/"):]
		_, err := os.Stat(filepath.Join(g.channel(), name))
		if f["branch"] != "channel" || !g.branch || (err == nil) != (f["sha"] == "sha-"+name) {
			g.t.Errorf("PUT %s: %v", name, f)
		}
		data, _ := base64.StdEncoding.DecodeString(f["content"])
		g.commits++
		return nil, os.WriteFile(filepath.Join(g.channel(), name), data, 0o644)
	case args[0] == "api" && strings.Contains(args[1], "/git/ref/heads/channel"):
		if !g.branch {
			return nil, errors.New("HTTP 404")
		}
		return []byte(`{}`), nil
	case args[0] == "api" && args[1] == "-X" && args[2] == "POST":
		if strings.HasSuffix(args[3], "/git/refs") {
			g.branch = true
		}
		return []byte(`{"sha":"abc"}`), nil
	}
	g.t.Fatalf("unexpected gh %v", args)
	return nil, nil
}

func (g *fakeGitHub) file(dir, name string, body any) {
	g.t.Helper()
	f, err := readFile(filepath.Join(dir, name))
	if err != nil {
		g.t.Fatal(err)
	}
	if err := json.Unmarshal(f.Body, body); err != nil {
		g.t.Fatal(err)
	}
}

// verifyPublished checks a release as a device fetches it: keys.json and
// stable.json from the branch, release.json and the files from the
// release.
func (g *fakeGitHub) verifyPublished(tag string) {
	g.t.Helper()
	d := g.t.TempDir()
	for _, f := range []string{filepath.Join(g.channel(), "keys.json"), filepath.Join(g.channel(), "stable.json")} {
		if err := copyFile(f, filepath.Join(d, filepath.Base(f))); err != nil {
			g.t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(g.release(tag))
	for _, e := range entries {
		copyFile(filepath.Join(g.release(tag), e.Name()), filepath.Join(d, e.Name()))
	}
	call(g.t, verify, d)
}

type keyFiles struct {
	root1, release, channel, channelPub string
	roots                               [][]byte
}

func testKeys(t *testing.T) keyFiles {
	dir := t.TempDir()
	var k keyFiles
	var root1Pub, root2Pub string
	k.root1, root1Pub = newKey(t, dir, "root-1")
	_, root2Pub = newKey(t, dir, "root-2")
	k.release, _ = newKey(t, dir, "release")
	k.channel, k.channelPub = newKey(t, dir, "channel")
	k.roots = [][]byte{must(readPublic(root1Pub)), must(readPublic(root2Pub))}
	prevRoots, prevAsk, prevNow := pinnedRoots, ask, now
	pinnedRoots = func() [][]byte { return k.roots }
	ask = func(string) bool { return true }
	clock := time.Now()
	now = func() time.Time { return clock }
	t.Cleanup(func() { pinnedRoots, ask, now = prevRoots, prevAsk, prevNow })
	return k
}

// advance moves the tests' clock on.
func advance(d time.Duration) {
	t := now().Add(d)
	now = func() time.Time { return t }
}

// TestPublish publishes releases and renews the channel as the maintainer
// and cbb.tools do, with keys in files and a GitHub in a directory.
func TestPublish(t *testing.T) {
	g := newFakeGitHub(t)
	k := testKeys(t)
	keyFlags := []string{"-root", "file:" + k.root1, "-release-key", "file:" + k.release}
	pub := func(extra ...string) error { return publish(append(append([]string{}, keyFlags...), extra...)) }
	var ks release.Keys
	var c release.Channel
	var r release.Release

	// The first signed release: a root signs keys.json with the channel
	// key, and the branch is made.
	g.draft("v0.6.0")
	if err := pub("-version", "0.6.0", "-min-from", "0.5.0", "-channel", "cbb.tools="+k.channelPub); err != nil {
		t.Fatal(err)
	}
	if g.drafts["v0.6.0"] || !g.branch {
		t.Fatalf("v0.6.0 is not published: %+v", g)
	}
	g.file(g.channel(), "keys.json", &ks)
	g.file(g.channel(), "stable.json", &c)
	g.file(g.release("v0.6.0"), "release.json", &r)
	if ks.Seq != 1 || len(ks.Keys) != 2 || ks.Keys[1].Use != release.UseChannel || c.Seq != 1 || c.Release != "0.6.0" ||
		r.MinFrom != "0.5.0" || r.Docker == nil || len(r.Files) != 4 {
		t.Fatalf("keys %+v, channel %+v, release %+v", ks, c, r)
	}
	g.verifyPublished("v0.6.0")

	// cbb.tools renews the channel; the workflow takes it into the branch.
	served := t.TempDir()
	advance(7 * 24 * time.Hour)
	call(t, extend, "-key", "file:"+k.channel, "-out", served, "-from", g.channel(), "-releases", g.dir)
	if out := string(call(t, take, "-new", filepath.Join(served, "stable.json"), "-releases", g.dir, g.channel())); !strings.Contains(out, "took stable.json 2") {
		t.Errorf("take printed %q", out)
	}
	if out := string(call(t, take, "-new", filepath.Join(served, "stable.json"), "-releases", g.dir, g.channel())); !strings.Contains(out, "is the newest") {
		t.Errorf("take again printed %q", out)
	}
	g.verifyPublished("v0.6.0")
	if out := call(t, due, g.channel()); len(out) != 0 {
		t.Errorf("due printed %q", out)
	}

	// By hand, within keys.json's margin: only stable.json changes.
	advance(13 * 24 * time.Hour)
	if err := renew(keyFlags); err != nil {
		t.Fatal(err)
	}
	g.file(g.channel(), "keys.json", &ks)
	g.file(g.channel(), "stable.json", &c)
	if ks.Seq != 1 || c.Seq != 3 || c.Release != "0.6.0" {
		t.Fatalf("after renew: keys %d, channel %+v", ks.Seq, c)
	}
	// keys.json near its expiry is due, and renew signs it again.
	advance(50 * 24 * time.Hour)
	if out := string(call(t, due, g.channel())); !strings.Contains(out, "keys.json") || !strings.Contains(out, "stable.json") {
		t.Errorf("due printed %q", out)
	}
	if err := renew(keyFlags); err != nil {
		t.Fatal(err)
	}
	g.file(g.channel(), "keys.json", &ks)
	g.file(g.channel(), "stable.json", &c)
	if ks.Seq != 2 || len(ks.Keys) != 2 || c.Seq != 4 {
		t.Fatalf("after the second renew: keys %+v, channel %d", ks, c.Seq)
	}
	g.verifyPublished("v0.6.0")

	// The next release carries keys.json on and raises the channel; a
	// renewal signed for the old release is refused after it.
	stale := t.TempDir()
	call(t, extend, "-key", "file:"+k.channel, "-out", stale, "-from", g.channel(), "-releases", g.dir)
	g.draft("v0.6.1")
	if err := pub("-version", "v0.6.1"); err != nil {
		t.Fatal(err)
	}
	g.file(g.channel(), "keys.json", &ks)
	g.file(g.channel(), "stable.json", &c)
	if ks.Seq != 2 || c.Seq != 5 || c.Release != "0.6.1" {
		t.Fatalf("v0.6.1: keys %d, channel %+v", ks.Seq, c)
	}
	g.verifyPublished("v0.6.1")
	if out := string(call(t, take, "-new", filepath.Join(stale, "stable.json"), "-releases", g.dir, g.channel())); !strings.Contains(out, "is the newest") {
		t.Errorf("took a stale renewal: %q", out)
	}
	// A renewal that names another release is refused.
	other := t.TempDir()
	call(t, extend, "-key", "file:"+k.channel, "-out", other, "-from", g.channel(), "-releases", g.dir)
	var o release.Channel
	g.file(other, "stable.json", &o)
	o.Release, o.Seq = "0.6.0", 9
	write(t, filepath.Join(other, "stable.json"), must(json.Marshal(must(signWith(must(signer("file:"+k.channel)), o)))))
	if take([]string{"-new", filepath.Join(other, "stable.json"), "-releases", g.dir, g.channel()}) == nil {
		t.Error("took a renewal of another release")
	}
	// So is one far past the branch's.
	far := t.TempDir()
	call(t, extend, "-key", "file:"+k.channel, "-out", far, "-from", g.channel(), "-releases", g.dir)
	g.file(far, "stable.json", &o)
	o.Seq = c.Seq + maxTakeStep + 1
	write(t, filepath.Join(far, "stable.json"), must(json.Marshal(must(signWith(must(signer("file:"+k.channel)), o)))))
	if take([]string{"-new", filepath.Join(far, "stable.json"), "-releases", g.dir, g.channel()}) == nil {
		t.Error("took a renewal far past the branch's")
	}

	// A pre-release gets no channel file; answering no leaves a draft.
	g.draft("v0.7.0-rc.1")
	ask = func(string) bool { return false }
	if err := pub("-version", "0.7.0-rc.1", "-docker", "none"); err != nil {
		t.Fatal(err)
	}
	ask = func(string) bool { return true }
	if !g.drafts["v0.7.0-rc.1"] {
		t.Error("published without a yes")
	}
	g.file(g.channel(), "stable.json", &c)
	if c.Release != "0.6.1" {
		t.Errorf("a pre-release changed the channel to %s", c.Release)
	}
	r = release.Release{}
	g.file(g.release("v0.7.0-rc.1"), "release.json", &r)
	if r.Docker != nil {
		t.Errorf("-docker none left %+v", r.Docker)
	}

	// Refused: a published release, a file without the attestation.
	if pub("-version", "0.6.1") == nil {
		t.Error("signed a published release")
	}
	g.draft("v0.6.2")
	g.attested = false
	if pub("-version", "0.6.2") == nil {
		t.Error("signed a file without its attestation")
	}
	if _, err := os.Stat(filepath.Join(g.release("v0.6.2"), "release.json")); err == nil {
		t.Error("uploaded after a failed attestation")
	}
}

// TestPublishKeepsTheSequence: a keys.json that no longer checks out is
// replaced by one numbered above it.
func TestPublishKeepsTheSequence(t *testing.T) {
	g := newFakeGitHub(t)
	k := testKeys(t)
	other, _ := newKey(t, t.TempDir(), "other")
	_, rkPub := newKey(t, t.TempDir(), "release-2")

	// The branch's keys.json is signed by a key that is no root.
	g.branch = true
	kb := write(t, filepath.Join(t.TempDir(), "keys.body"), call(t, keys, "-seq", "7", "release="+rkPub))
	write(t, filepath.Join(g.channel(), "keys.json"), call(t, sign, "-key", "file:"+other, kb))

	g.draft("v0.6.0")
	if err := publish([]string{"-root", "file:" + k.root1, "-release-key", "file:" + k.release, "-version", "0.6.0"}); err != nil {
		t.Fatal(err)
	}
	var ks release.Keys
	g.file(g.channel(), "keys.json", &ks)
	if ks.Seq != 8 || len(ks.Keys) != 1 {
		t.Errorf("keys.json is %+v", ks)
	}
}

// TestExtendRefusesAnUncertifiedKey: the channel key must be in keys.json.
func TestExtendRefusesAnUncertifiedKey(t *testing.T) {
	g := newFakeGitHub(t)
	k := testKeys(t)
	g.draft("v0.6.0")
	if err := publish([]string{"-root", "file:" + k.root1, "-release-key", "file:" + k.release, "-version", "0.6.0"}); err != nil {
		t.Fatal(err)
	}
	if extend([]string{"-key", "file:" + k.channel, "-out", t.TempDir(), "-from", g.channel(), "-releases", g.dir}) == nil {
		t.Error("renewed with a key keys.json does not certify")
	}
}

// TestDropAChannelKey: renew -drop takes a stolen channel key out of
// keys.json, after which it renews nothing.
func TestDropAChannelKey(t *testing.T) {
	g := newFakeGitHub(t)
	k := testKeys(t)
	keyFlags := []string{"-root", "file:" + k.root1, "-release-key", "file:" + k.release}
	g.draft("v0.6.0")
	if err := publish(append(keyFlags, "-version", "0.6.0", "-channel", "cbb.tools="+k.channelPub)); err != nil {
		t.Fatal(err)
	}
	call(t, extend, "-key", "file:"+k.channel, "-out", t.TempDir(), "-from", g.channel(), "-releases", g.dir)
	if err := renew(append(keyFlags, "-drop", "cbb.tools")); err != nil {
		t.Fatal(err)
	}
	var ks release.Keys
	g.file(g.channel(), "keys.json", &ks)
	if ks.Seq != 2 || len(ks.Keys) != 1 || ks.Keys[0].Use != "" {
		t.Errorf("keys.json is %+v", ks)
	}
	if extend([]string{"-key", "file:" + k.channel, "-out", t.TempDir(), "-from", g.channel(), "-releases", g.dir}) == nil {
		t.Error("a dropped channel key renewed the channel")
	}
}

// TestEntries signs the entry points into the branch, renews them on
// cbb.tools with the channel file, takes the renewal into the branch and
// mirrors them; a renewal that names other forwarders is refused.
func TestEntries(t *testing.T) {
	g := newFakeGitHub(t)
	k := testKeys(t)
	g.draft("v0.6.0")
	if err := publish([]string{"-root", "file:" + k.root1, "-release-key", "file:" + k.release,
		"-version", "0.6.0", "-channel", "cbb.tools=" + k.channelPub}); err != nil {
		t.Fatal(err)
	}
	in := write(t, filepath.Join(t.TempDir(), "in.json"), []byte(`{"forwarders":[{"name":"cbb.tools:8764",
		"vless":[{"transport":"xhttp","server_name":"cbb.tools","port":443,"path":"/banMEJvnYJJap8S"}]}],
		"relays":[{"name":"cbb.tools:8765","endpoints":["relay.cbb.tools:8765"]}]}`))
	if out := string(call(t, entries, "-key", "file:"+k.channel, "-in", in, g.channel())); !strings.Contains(out, "entries.json 1") {
		t.Errorf("entries printed %q", out)
	}
	var e release.Entries
	g.file(g.channel(), entriesName, &e)
	if e.Seq != 1 || len(e.Forwarders) != 1 || e.Forwarders[0].VLESS[0].Port != 443 || len(e.Relays) != 1 || e.Relays[0].Endpoints[0] != "relay.cbb.tools:8765" {
		t.Fatalf("signed %+v", e)
	}
	bad := write(t, filepath.Join(t.TempDir(), "bad.json"), []byte(`{"forwarders":[{"name":"cbb.tools"}]}`))
	if entries([]string{"-key", "file:" + k.channel, "-in", bad, g.channel()}) == nil {
		t.Error("signed a forwarder without a port")
	}

	served := t.TempDir()
	advance(7 * 24 * time.Hour)
	if out := string(call(t, extend, "-key", "file:"+k.channel, "-out", served, "-from", g.channel(), "-releases", g.dir)); !strings.Contains(out, "entries.json 2") {
		t.Errorf("extend printed %q", out)
	}
	takeArgs := []string{"-new", filepath.Join(served, "stable.json"), "-new-entries", filepath.Join(served, entriesName), "-releases", g.dir, g.channel()}
	if out := string(call(t, take, takeArgs...)); !strings.Contains(out, "took entries.json 2") {
		t.Errorf("take printed %q", out)
	}
	if out := call(t, due, g.channel()); len(out) != 0 {
		t.Errorf("due printed %q", out)
	}
	advance(25 * 24 * time.Hour)
	if out := string(call(t, due, g.channel())); !strings.Contains(out, entriesName) {
		t.Errorf("due printed %q", out)
	}

	other := t.TempDir()
	g.file(served, entriesName, &e)
	e.Seq++
	e.Forwarders[0].VLESS[0].Path = "/another-path-1"
	write(t, filepath.Join(other, entriesName), must(json.Marshal(must(signWith(must(signer("file:"+k.channel)), e)))))
	if takeEntries(g.channel(), filepath.Join(other, entriesName)) == nil {
		t.Error("took a renewal that names other forwarders")
	}
	e.Forwarders[0].VLESS[0].Path = "/banMEJvnYJJap8S"
	e.Relays[0].Endpoints = []string{"elsewhere.example.org:8765"}
	write(t, filepath.Join(other, entriesName), must(json.Marshal(must(signWith(must(signer("file:"+k.channel)), e)))))
	if takeEntries(g.channel(), filepath.Join(other, entriesName)) == nil {
		t.Error("took a renewal that moves the relay")
	}

	m := t.TempDir()
	call(t, mirror, "-out", m, "-from", g.channel(), "-releases", g.dir)
	var me release.Entries
	g.file(m, entriesName, &me)
	if me.Seq != 2 {
		t.Errorf("the mirror holds entries.json %d", me.Seq)
	}
}
