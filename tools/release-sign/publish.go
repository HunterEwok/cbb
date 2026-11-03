// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/release"
)

// The steps of publish and renew reach GitHub through the gh command, ask
// on the terminal and check under the pinned roots; variables for the
// tests.
var (
	gh  = func(args ...string) ([]byte, error) { return run(append([]string{"gh"}, args...), nil) }
	ask = func(question string) bool {
		fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.EqualFold(strings.TrimSpace(line), "y")
	}
	pinnedRoots = func() [][]byte { return release.Roots }
)

// keysMargin is how long keys.json must still be valid for a release to
// carry it on; a shorter one is signed again by a root.
const keysMargin = 45 * 24 * time.Hour

// channelLife is how long a channel file the release key signs is valid;
// the channel key on cbb.tools renews it every week after.
const channelLife = 30 * 24 * time.Hour

const defaultRepo = "HunterEwok/clipboardbridge"

// channelBranch holds the current keys.json and channel file
// (docs/protocol.md, section 16, "Where the files are").
const channelBranch = "channel"

// stableChannel is the one channel releases go to.
const stableChannel = "stable"

// The image the release workflow's docker job pushes; it adds the digest
// to the draft's notes on a line of its own.
var dockerRE = regexp.MustCompile(`(?m)^ghcr\.io/hunterewok/clipboardbridge@sha256:[0-9a-f]{64}\r?$`)

// signing are the flags publish and renew share.
type signing struct {
	repo, root, releaseKey string
	extra                  []release.Key
	drop                   []string
	newKeys                bool
}

func (s *signing) flags(fs *flag.FlagSet) {
	home, _ := os.UserHomeDir()
	fs.StringVar(&s.repo, "repo", defaultRepo, "the repository")
	fs.StringVar(&s.root, "root", "piv:82", "the root key that signs keys.json when it is signed again")
	fs.StringVar(&s.releaseKey, "release-key", "se:"+filepath.Join(home, ".config", "cbb-release", "release.se"), "the release key")
	fs.BoolVar(&s.newKeys, "new-keys", false, "sign keys.json again even when it is valid for long enough")
	add := func(use string) func(string) error {
		return func(v string) error {
			name, path, ok := strings.Cut(v, "=")
			if !ok {
				return fmt.Errorf("%q is not NAME=KEY.pem", v)
			}
			key, err := readPublic(path)
			if err != nil {
				return err
			}
			s.extra = append(s.extra, release.Key{Key: key, Name: name, Use: use})
			return nil
		}
	}
	fs.Func("release", "NAME=KEY.pem of one more release key, such as one on a YubiKey, added to keys.json (repeatable)", add(release.UseRelease))
	fs.Func("status", "NAME=KEY.pem of a key that signs attest-status.json, added to keys.json (repeatable)", add(release.UseStatus))
	fs.Func("channel", "NAME=KEY.pem of a key that renews the channel file, added to keys.json (repeatable)", add(release.UseChannel))
	fs.Func("forwarder", "ADDRESS=KEY.pem of the project's forwarder (cbb.tools:8764), whose pin hubs then accept, added to keys.json (repeatable: the old and the new key while it changes)", add(release.UseForwarder))
	fs.Func("drop", "the NAME of a key keys.json drops, lost or stolen, or a forwarder key's pin (repeatable)", func(v string) error {
		s.drop = append(s.drop, v)
		return nil
	})
}

// publish signs a release the workflow left as a draft, publishes it and
// makes it the channel's: docs/maintaining.md, "Signed releases".
func publish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	var s signing
	s.flags(fs)
	version := fs.String("version", "", "the release's version, as in its tag without the v")
	minFrom := fs.String("min-from", "", "the lowest version that may update to this one directly")
	docker := fs.String("docker", "", "the image as NAME@sha256:DIGEST; by default from the draft's notes, none for no image")
	dirFlag := fs.String("dir", "", "where the files go; a new directory by default")
	noPublish := fs.Bool("no-publish", false, "check and sign, upload release.json, and leave the release a draft")
	fs.Parse(args)
	v := strings.TrimPrefix(*version, "v")
	if v == "" || fs.NArg() != 0 {
		return errors.New("publish needs -version X.Y.Z and nothing else")
	}
	tag := "v" + v
	pre := strings.Contains(v, "-")

	var view struct {
		IsDraft bool   `json:"isDraft"`
		Body    string `json:"body"`
	}
	out, err := gh("release", "view", tag, "--repo", s.repo, "--json", "isDraft,body")
	if err != nil {
		return fmt.Errorf("the release %s: %w", tag, err)
	}
	if err := json.Unmarshal(out, &view); err != nil {
		return err
	}
	if !view.IsDraft {
		return fmt.Errorf("%s is published already, and a published release takes no more files", tag)
	}
	switch *docker {
	case "":
		*docker = strings.TrimSuffix(dockerRE.FindString(view.Body), "\r")
		if *docker == "" {
			return errors.New("the draft's notes name no Docker image yet: wait for the release workflow's docker job, or pass -docker none")
		}
	case "none":
		*docker = ""
	}

	dir := *dirFlag
	if dir == "" {
		if dir, err = os.MkdirTemp("", "cbb-"+tag+"-"); err != nil {
			return err
		}
	}
	step("downloading %s's files into %s", tag, dir)
	if _, err := gh("release", "download", tag, "--repo", s.repo, "--dir", dir, "--clobber"); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if describes(name) {
			// From an earlier run; signed again below.
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
			continue
		}
		step("checking the build attestation of %s", name)
		if _, err := gh("attestation", "verify", filepath.Join(dir, name), "--repo", s.repo,
			"--source-ref", "refs/tags/"+tag, "--signer-workflow", s.repo+"/.github/workflows/release.yml"); err != nil {
			return fmt.Errorf("%s was not built by the release workflow from %s: %w", name, tag, err)
		}
	}

	cur, err := branchFiles(s.repo)
	if err != nil {
		return err
	}
	rs, err := signer(s.releaseKey)
	if err != nil {
		return err
	}
	keysFile, err := s.keysFor(cur["keys.json"].f, rs)
	if err != nil {
		return err
	}
	r, err := buildManifest(dir, v, stableChannel, *minFrom, *docker)
	if err != nil {
		return err
	}
	step("signing release.json with the release key")
	rel, err := signWith(rs, r)
	if err != nil {
		return err
	}
	files := map[string]release.File{"keys.json": keysFile, "release.json": rel}
	if !pre {
		// A pre-release stays out of the channel, as it stays out of
		// releases/latest.
		ch, err := channelFor(cur[stableChannel+".json"].f, rel, rs)
		if err != nil {
			return err
		}
		files[stableChannel+".json"] = ch
	}
	if err := checkSigned(files, dir); err != nil {
		return fmt.Errorf("the signed files do not check out, nothing was uploaded: %w", err)
	}
	for name, f := range files {
		if err := writeFile(filepath.Join(dir, name), f); err != nil {
			return err
		}
	}
	step("uploading release.json to %s", tag)
	if _, err := gh("release", "upload", tag, "--repo", s.repo, "--clobber", filepath.Join(dir, "release.json")); err != nil {
		return err
	}
	if *noPublish || !ask(fmt.Sprintf("Publish %s now? Once published, its files cannot change.", tag)) {
		step("%s is signed and still a draft; run publish again to publish it, so that the channel names it", tag)
		return nil
	}
	edit := []string{"release", "edit", tag, "--repo", s.repo, "--draft=false"}
	if !pre {
		edit = append(edit, "--latest")
	}
	if _, err := gh(edit...); err != nil {
		return err
	}
	step("%s is published; the published workflow updates the Homebrew tap", tag)
	// The channel names the release only once it is public.
	delete(files, "release.json")
	return putChannel(s.repo, cur, files, "CBB "+tag)
}

// renew signs the channel file again with the release key, and keys.json
// when it is near its expiry, in the branch channel: the way by hand when
// cbb.tools does not renew it.
func renew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	var s signing
	s.flags(fs)
	fs.Parse(args)
	if fs.NArg() != 0 {
		return errors.New("renew takes only flags")
	}
	cur, err := branchFiles(s.repo)
	if err != nil {
		return err
	}
	chFile, ok := cur[stableChannel+".json"]
	if !ok {
		return fmt.Errorf("the branch %s has no %s.json yet; release-sign publish makes it", channelBranch, stableChannel)
	}
	var c release.Channel
	if err := json.Unmarshal(chFile.f.Body, &c); err != nil {
		return err
	}
	rel, err := releaseFile(s.repo, c.Release)
	if err != nil {
		return err
	}
	rs, err := signer(s.releaseKey)
	if err != nil {
		return err
	}
	keysFile, err := s.keysFor(cur["keys.json"].f, rs)
	if err != nil {
		return err
	}
	ch, err := channelFor(chFile.f, rel, rs)
	if err != nil {
		return err
	}
	files := map[string]release.File{"keys.json": keysFile, stableChannel + ".json": ch, "release.json": rel}
	if err := checkSigned(files, ""); err != nil {
		return fmt.Errorf("the signed files do not check out, nothing was uploaded: %w", err)
	}
	delete(files, "release.json")
	if err := putChannel(s.repo, cur, files, "Renew the channel of "+c.Release); err != nil {
		return err
	}
	step("%s.json names %s until %s", stableChannel, c.Release, expiry(ch))
	return nil
}

func step(format string, a ...any) { fmt.Fprintf(os.Stderr, "release-sign: "+format+"\n", a...) }

func writeFile(path string, f release.File) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// branchFile is a file of the branch channel and its blob's hash, which
// replacing it takes.
type branchFile struct {
	f   release.File
	sha string
}

// branchFiles reads keys.json and the channel file from the branch
// channel, leaving out those it lacks: before the first signed release it
// has none.
func branchFiles(repo string) (map[string]branchFile, error) {
	files := map[string]branchFile{}
	for _, name := range []string{"keys.json", stableChannel + ".json"} {
		out, err := gh("api", "repos/"+repo+"/contents/"+name+"?ref="+channelBranch)
		if err != nil {
			step("the branch %s has no %s", channelBranch, name)
			continue
		}
		var c struct {
			Content string `json:"content"`
			SHA     string `json:"sha"`
		}
		if err := json.Unmarshal(out, &c); err != nil {
			return nil, err
		}
		data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(c.Content, "\n", ""))
		if err != nil {
			return nil, fmt.Errorf("%s in the branch %s: %w", name, channelBranch, err)
		}
		var f release.File
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("%s in the branch %s: %w", name, channelBranch, err)
		}
		files[name] = branchFile{f, c.SHA}
	}
	return files, nil
}

// putChannel commits the files that changed to the branch channel, which
// it makes first when there is none.
func putChannel(repo string, cur map[string]branchFile, files map[string]release.File, message string) error {
	if _, err := gh("api", "repos/"+repo+"/git/ref/heads/"+channelBranch); err != nil {
		if err := makeBranch(repo); err != nil {
			return fmt.Errorf("making the branch %s: %w", channelBranch, err)
		}
	}
	for _, name := range []string{"keys.json", stableChannel + ".json"} {
		f, ok := files[name]
		if !ok || bytes.Equal(f.Body, cur[name].f.Body) && bytes.Equal(f.Sig, cur[name].f.Sig) {
			continue
		}
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		args := []string{"api", "-X", "PUT", "repos/" + repo + "/contents/" + name,
			"-f", "message=" + message, "-f", "branch=" + channelBranch,
			"-f", "content=" + base64.StdEncoding.EncodeToString(append(data, '\n'))}
		if c, ok := cur[name]; ok {
			args = append(args, "-f", "sha="+c.sha)
		}
		step("committing %s to the branch %s", name, channelBranch)
		if _, err := gh(args...); err != nil {
			return err
		}
	}
	return nil
}

// makeBranch makes the branch channel: one commit without a parent, with
// its README.
func makeBranch(repo string) error {
	readme := "# The release channel\n\nThe current signed `keys.json` and `stable.json` of CBB's releases\n" +
		"(docs/protocol.md, section 16, on the main branch). `release-sign publish` writes them, and\n" +
		"the channel workflow takes `stable.json` as cbb.tools renews it every week.\n"
	call := func(v, body any, method, path string) error {
		in, err := os.CreateTemp("", "cbb-gh-")
		if err != nil {
			return err
		}
		defer os.Remove(in.Name())
		if err := json.NewEncoder(in).Encode(body); err != nil {
			return err
		}
		in.Close()
		out, err := gh("api", "-X", method, "repos/"+repo+"/"+path, "--input", in.Name())
		if err != nil || v == nil {
			return err
		}
		return json.Unmarshal(out, v)
	}
	var tree, commit struct {
		SHA string `json:"sha"`
	}
	type entry struct {
		Path    string `json:"path"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	if err := call(&tree, map[string]any{"tree": []entry{{"README.md", "100644", "blob", readme}}}, "POST", "git/trees"); err != nil {
		return err
	}
	if err := call(&commit, map[string]any{"message": "The release channel", "tree": tree.SHA, "parents": []string{}}, "POST", "git/commits"); err != nil {
		return err
	}
	step("making the branch %s", channelBranch)
	return call(nil, map[string]string{"ref": "refs/heads/" + channelBranch, "sha": commit.SHA}, "POST", "git/refs")
}

// releaseFile downloads the release.json of a published version.
func releaseFile(repo, version string) (release.File, error) {
	dir, err := os.MkdirTemp("", "cbb-release-")
	if err != nil {
		return release.File{}, err
	}
	defer os.RemoveAll(dir)
	if _, err := gh("release", "download", "v"+version, "--repo", repo, "--dir", dir, "--pattern", "release.json"); err != nil {
		return release.File{}, err
	}
	return readFile(filepath.Join(dir, "release.json"))
}

// keysFor returns the keys.json a release carries: the current one while
// it is valid for long enough, certifies the release key and has the keys
// asked for, otherwise a new one from a root, with the current one's keys
// and a sequence number above its own.
func (s *signing) keysFor(prev release.File, rs crypto.Signer) (release.File, error) {
	spki, err := x509.MarshalPKIXPublicKey(rs.Public())
	if err != nil {
		return release.File{}, err
	}
	var k release.Keys
	have := prev.Body != nil
	if have {
		if k, err = release.VerifyKeys(prev, pinnedRoots(), now(), release.Seen{}); err != nil {
			step("the current keys.json does not check out (%v); a root signs a new one", err)
			have = false
			// Its keys are dropped, but the new one's number stays above
			// its own, which devices may have seen.
			k = release.Keys{}
			json.Unmarshal(prev.Body, &k)
			k.Keys = nil
		}
	}
	kept := k.Keys[:0:0]
	for _, key := range k.Keys {
		pin := sha256.Sum256(key.Key)
		if !slices.Contains(s.drop, key.Name) && !slices.Contains(s.drop, base64.StdEncoding.EncodeToString(pin[:])) {
			kept = append(kept, key)
		}
	}
	dropped := len(kept) != len(k.Keys)
	k.Keys = kept
	holds := func(want release.Key) bool {
		for _, key := range k.Keys {
			use := key.Use
			if use == "" {
				use = release.UseRelease
			}
			if bytes.Equal(key.Key, want.Key) && use == want.Use {
				return true
			}
		}
		return false
	}
	var missing []release.Key
	for _, want := range append([]release.Key{{Key: spki, Use: release.UseRelease}}, s.extra...) {
		if !holds(want) {
			missing = append(missing, want)
		}
	}
	left := time.Duration(k.ExpiresMS-now().UnixMilli()) * time.Millisecond
	if have && len(missing) == 0 && !dropped && left >= keysMargin && !s.newKeys {
		step("keys.json %d is valid until %s; it stays", k.Seq, time.UnixMilli(k.ExpiresMS).UTC().Format(time.DateOnly))
		return prev, nil
	}
	next := release.Keys{V: 1, Type: release.TypeKeys, Seq: k.Seq + 1, TimeMS: now().UnixMilli(), Keys: k.Keys}
	next.ExpiresMS = next.TimeMS + 90*24*time.Hour.Milliseconds()
	for _, m := range missing {
		if m.Use == release.UseRelease {
			m.Use = ""
			if m.Name == "" {
				m.Name = "release " + time.UnixMilli(next.TimeMS).UTC().Format("2006-01")
			}
		}
		next.Keys = append(next.Keys, m)
	}
	root, err := signer(s.root)
	if err != nil {
		return release.File{}, fmt.Errorf("the root key, to sign keys.json %d: %w", next.Seq, err)
	}
	step("signing keys.json %d with the root key: enter the YubiKey's PIN, then touch it", next.Seq)
	return signWith(root, next)
}

// channelFor signs a channel file naming rel, its sequence number above the
// current one's.
func channelFor(prev, rel release.File, s crypto.Signer) (release.File, error) {
	var last release.Channel
	if prev.Body != nil {
		if err := json.Unmarshal(prev.Body, &last); err != nil {
			return release.File{}, fmt.Errorf("the current channel file: %w", err)
		}
	}
	var r release.Release
	if err := json.Unmarshal(rel.Body, &r); err != nil {
		return release.File{}, err
	}
	h := rel.Hash()
	c := release.Channel{V: 1, Type: release.TypeChannel, Channel: r.Channel, Seq: last.Seq + 1, TimeMS: now().UnixMilli(),
		Release: r.Version, ReleaseSHA256: hex.EncodeToString(h[:])}
	c.ExpiresMS = c.TimeMS + channelLife.Milliseconds()
	step("signing %s.json %d", c.Channel, c.Seq)
	return signWith(s, c)
}

// signWith signs body; a hardware key is handed the exact bytes it signs.
func signWith(s crypto.Signer, body any) (release.File, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return release.File{}, err
	}
	if t, ok := s.(*tool); ok {
		t.data = data
	}
	return release.Sign(json.RawMessage(data), s)
}

// checkSigned checks the files as a device would, under the pinned roots,
// and the release's files in dir unless dir is "".
func checkSigned(files map[string]release.File, dir string) error {
	var (
		r   release.Release
		err error
	)
	if ch, ok := files[stableChannel+".json"]; ok {
		r, _, err = release.Check(files["keys.json"], ch, files["release.json"], pinnedRoots(), stableChannel, now(), release.Seen{})
	} else {
		r, _, err = release.CheckPinned(files["keys.json"], files["release.json"], pinnedRoots(), now(), release.Seen{})
	}
	if err != nil || dir == "" {
		return err
	}
	for _, a := range r.Files {
		data, err := os.ReadFile(filepath.Join(dir, a.Name))
		if err != nil {
			return err
		}
		if err := r.CheckFile(a.Name, data); err != nil {
			return err
		}
	}
	step("%s: keys.json, release.json and %d files check out under the pinned roots", r.Version, len(r.Files))
	return nil
}

func expiry(f release.File) string {
	var c release.Channel
	json.Unmarshal(f.Body, &c)
	return time.UnixMilli(c.ExpiresMS).UTC().Format(time.DateOnly)
}
