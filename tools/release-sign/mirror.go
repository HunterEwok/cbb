// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// The ZX Spectrum Next's files: the release's archive of them, and the
// most a file in it may hold (docs/maintaining.md, "The ZX Spectrum
// Next's files").
const (
	zxnextArchive = "cbb-zxnext.tar.gz"
	zxnextMax     = 64 << 20
	// zxnextSeen, in the mirror's directory, names the release the
	// Next's files were last taken from.
	zxnextSeen = ".zxnext-version"
)

// mirror keeps a mirror of the releases, dl.cbb.tools (docs/protocol.md,
// section 16, "Where the files are"): keys.json and the channel file at
// its top, each release's files under vX.Y.Z. It holds no key: it takes
// the newest keys.json and channel file that check out under the pinned
// roots, then the release the channel file names, each -version asked for
// and the min_from of each, checks every file against its release.json as
// a device would, and only then moves a release into place. A release
// once mirrored stays, since a device below its min_from needs an older
// one. With -zxnext it unpacks the Next's files of the newest release
// that has them into that directory: they are served over plain HTTP, and
// the Next checks no signature, so they come only from a checked release.
// On cbb.tools, from an hourly timer (site/deploy/cbb-mirror.service).
func mirror(args []string) error {
	fs := flag.NewFlagSet("mirror", flag.ExitOnError)
	out := fs.String("out", "", "the mirror's directory, served at https://dl.cbb.tools/")
	from := fs.String("from", channelFiles, "where keys.json and the channel file are, comma-separated; the newest that checks out is taken")
	releases := fs.String("releases", releaseFiles, "where each release's files are, under vX.Y.Z")
	zx := fs.String("zxnext", "", "the directory the ZX Spectrum Next's files go to")
	var versions []string
	fs.Func("version", "also mirror this published release, such as a pre-release; repeat for more", func(v string) error {
		v = strings.TrimPrefix(v, "v")
		if !release.IsVersion(v) {
			return fmt.Errorf("%q is not a version", v)
		}
		versions = append(versions, v)
		return nil
	})
	fs.Parse(args)
	if *out == "" || fs.NArg() != 0 {
		return errors.New("mirror needs -out")
	}

	// The mirror itself is a source too, so that it never goes back to
	// older files than it serves.
	best, err := newestChannel(append(strings.Split(*from, ","), *out), *releases)
	if err != nil {
		return err
	}
	var queue []string
	if best.channel {
		queue = append(queue, best.c.Release)
	}
	queue = append(queue, versions...)
	done := map[string]release.Release{}
	for i := 0; i < len(queue); i++ {
		v := queue[i]
		if _, ok := done[v]; ok {
			continue
		}
		r, err := mirrorRelease(*out, *releases, v, best.keys)
		if err != nil {
			return fmt.Errorf("v%s: %w", v, err)
		}
		done[v] = r
		if r.MinFrom != "" {
			queue = append(queue, r.MinFrom)
		}
	}

	if *zx != "" {
		if err := takeZXNext(*out, *zx, done); err != nil {
			return fmt.Errorf("the ZX Spectrum Next's files: %w", err)
		}
	}

	// The top last: the channel file never names a release the mirror
	// does not have yet.
	top := map[string]release.File{"keys.json": best.keys}
	if best.channel {
		top[stableChannel+".json"] = best.ch
	}
	for name, f := range top {
		if err := replaceFile(filepath.Join(*out, name), f); err != nil {
			return err
		}
	}
	if best.channel {
		fmt.Fprintf(stdout, "keys.json %d, %s.json %d names %s until %s\n", best.k.Seq, stableChannel, best.c.Seq, best.c.Release, expiry(best.ch))
	} else {
		fmt.Fprintf(stdout, "keys.json %d, no %s.json yet\n", best.k.Seq, stableChannel)
	}
	return nil
}

// channelSource is keys.json and, when it has one that checks out, the
// channel file of one source.
type channelSource struct {
	keys, ch release.File
	k        release.Keys
	c        release.Channel
	channel  bool
}

// newer reports whether a is newer than b: a higher keys.json first, as a
// device takes it, then a channel file, then a higher one.
func (a channelSource) newer(b channelSource) bool {
	switch {
	case a.k.Seq != b.k.Seq:
		return a.k.Seq > b.k.Seq
	case a.channel != b.channel:
		return a.channel
	}
	return a.channel && a.c.Seq > b.c.Seq
}

// newestChannel reads keys.json and the channel file from each source and
// returns the newest pair that checks out at now. A source that fails is
// skipped and said; none at all is an error.
func newestChannel(sources []string, releases string) (channelSource, error) {
	var best channelSource
	found := false
	for _, src := range sources {
		src = strings.TrimSuffix(strings.TrimSpace(src), "/")
		if src == "" {
			continue
		}
		var s channelSource
		var err error
		if s.keys, err = fetchFile(src + "/keys.json"); err != nil {
			step("%s: %v", src, err)
			continue
		}
		if s.k, err = release.VerifyKeys(s.keys, pinnedRoots(), now(), release.Seen{}); err != nil {
			step("%s/keys.json: %v", src, err)
			continue
		}
		if ch, err := fetchFile(src + "/" + stableChannel + ".json"); err == nil {
			s.channel = checkChannel(&s, ch, src, releases)
		}
		if !found || s.newer(best) {
			best, found = s, true
		}
	}
	if !found {
		return best, errors.New("no source has a keys.json that checks out")
	}
	return best, nil
}

// checkChannel reports whether ch, with the release.json it names, checks
// out under s's keys.json, and keeps it in s.
func checkChannel(s *channelSource, ch release.File, src, releases string) bool {
	var c release.Channel
	if err := json.Unmarshal(ch.Body, &c); err != nil || !release.IsVersion(c.Release) {
		step("%s/%s.json: names no release", src, stableChannel)
		return false
	}
	rel, err := fetchFile(releases + "/v" + c.Release + "/release.json")
	if err != nil {
		step("%s/%s.json: %v", src, stableChannel, err)
		return false
	}
	if _, _, err := release.Check(s.keys, ch, rel, pinnedRoots(), stableChannel, now(), release.Seen{}); err != nil {
		step("%s/%s.json: %v", src, stableChannel, err)
		return false
	}
	s.ch, s.c = ch, c
	return true
}

// mirrorRelease puts a release's files and its release.json into
// out/vX.Y.Z, unless they are there already, and returns the release.
func mirrorRelease(out, releases, v string, keys release.File) (release.Release, error) {
	var r release.Release
	dir := filepath.Join(out, "v"+v)
	if f, err := readFile(filepath.Join(dir, "release.json")); err == nil {
		// Checked when it was mirrored; a release key dropped since
		// does not take it off the mirror.
		return r, json.Unmarshal(f.Body, &r)
	}
	base := releases + "/v" + v
	rel, err := fetchFile(base + "/release.json")
	if err != nil {
		return r, err
	}
	if r, _, err = release.CheckPinned(keys, rel, pinnedRoots(), now(), release.Seen{}); err != nil {
		return r, err
	}
	if r.Version != v {
		return r, fmt.Errorf("release.json is %s", r.Version)
	}
	tmp, err := os.MkdirTemp(out, ".v"+v+"-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(tmp)
	for _, a := range r.Files {
		if a.Name != filepath.Base(a.Name) || strings.HasPrefix(a.Name, ".") {
			return r, fmt.Errorf("release.json names the file %q", a.Name)
		}
		step("downloading %s", base+"/"+a.Name)
		if err := download(base+"/"+a.Name, filepath.Join(tmp, a.Name), a); err != nil {
			return r, err
		}
	}
	if err := checkSums(tmp, r); err != nil {
		return r, err
	}
	if err := writeFile(filepath.Join(tmp, "release.json"), rel); err != nil {
		return r, err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return r, err
	}
	if err := os.Rename(tmp, dir); err != nil {
		return r, err
	}
	step("mirrored v%s", v)
	return r, nil
}

// download writes a release's file to path, and fails unless it has the
// size and SHA-256 release.json gives it.
func download(src, path string, a release.Asset) error {
	var body io.Reader
	if strings.HasPrefix(src, "https://") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "cbb")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", src, resp.Status)
		}
		body = resp.Body
	} else {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		body = f
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, a.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("%s does not match release.json", a.Name)
	}
	return nil
}

// takeZXNext unpacks the Next's files of the newest mirrored release that
// has them into dir, when that release is newer than the one they came
// from last time.
func takeZXNext(out, dir string, done map[string]release.Release) error {
	newest := ""
	for v, r := range done {
		if _, ok := r.Asset(zxnextArchive); ok && (newest == "" || release.Compare(v, newest) > 0) {
			newest = v
		}
	}
	if newest == "" {
		return nil
	}
	seen, _ := os.ReadFile(filepath.Join(out, zxnextSeen))
	if _, err := os.Stat(filepath.Join(dir, "LIST")); err == nil && release.Compare(newest, strings.TrimSpace(string(seen))) <= 0 {
		return nil
	}
	files, err := readZXNext(filepath.Join(out, "v"+newest, zxnextArchive))
	if err != nil {
		return err
	}
	if _, ok := files["LIST"]; !ok {
		return errors.New("the archive has no LIST")
	}
	// Each file is replaced at once; LIST, which .cbb install reads
	// first, last of all.
	for name, data := range files {
		if name != "LIST" {
			if err := replace(filepath.Join(dir, name), data); err != nil {
				return err
			}
		}
	}
	if err := replace(filepath.Join(dir, "LIST"), files["LIST"]); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if _, ok := files[e.Name()]; !ok && !strings.HasPrefix(e.Name(), ".") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	step("took the ZX Spectrum Next's files from v%s", newest)
	return replace(filepath.Join(out, zxnextSeen), []byte(newest+"\n"))
}

// readZXNext reads the files under zxnext/ in the archive: plain files
// only, none in a folder of its own.
func readZXNext(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		name, ok := strings.CutPrefix(strings.TrimPrefix(h.Name, "./"), "zxnext/")
		switch {
		case h.Typeflag == tar.TypeDir && (name == "" || h.Name == "zxnext"):
			continue
		case !ok || h.Typeflag != tar.TypeReg || !filepath.IsLocal(name) || strings.ContainsAny(name, `/\:`) ||
			strings.Contains(name, "..") || strings.HasPrefix(name, ".") || h.Size > zxnextMax:
			return nil, fmt.Errorf("the archive holds %q", h.Name)
		}
		// Only a bare name, the same as its own base, goes on to a path.
		base := filepath.Base(name)
		if base != name || strings.Contains(base, "..") {
			return nil, fmt.Errorf("the archive holds %q", h.Name)
		}
		var b bytes.Buffer
		if _, err := io.Copy(&b, io.LimitReader(tr, zxnextMax)); err != nil {
			return nil, err
		}
		files[base] = b.Bytes()
	}
}

// replaceFile writes a signed file in place of path at once.
func replaceFile(path string, f release.File) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return replace(path, append(data, '\n'))
}

// replace writes data in place of path at once, through a file beside it.
func replace(path string, data []byte) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".new")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
