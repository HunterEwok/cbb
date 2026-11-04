// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/release"
)

// releaseSigner signs releases under a root of its own, as
// tools/release-sign drill does.
type releaseSigner struct {
	root, key *ecdsa.PrivateKey
	keysSeq   uint64 // the seq of the keys.json it signs; 1 when 0
}

func newReleaseSigner(t *testing.T) *releaseSigner {
	t.Helper()
	var s releaseSigner
	var err error
	if s.root, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if s.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	return &s
}

func (s *releaseSigner) roots(t *testing.T) [][]byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&s.root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{der}
}

// sign returns the signed files of version on the stable channel at seq.
func (s *releaseSigner) sign(t *testing.T, version string, seq uint64) *control.Release {
	t.Helper()
	return s.signArchive(t, version, seq, []byte{0})
}

// signArchive is sign with data as the release's archive.
func (s *releaseSigner) signArchive(t *testing.T, version string, seq uint64, data []byte) *control.Release {
	t.Helper()
	key, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute).UnixMilli()
	life := (30 * 24 * time.Hour).Milliseconds()
	keys, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: max(s.keysSeq, 1), TimeMS: at, ExpiresMS: at + life,
		Keys: []release.Key{{Key: key, Name: "test"}}}, s.root)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := release.Sign(release.Release{V: 1, Type: release.TypeRelease, Version: version, Channel: "stable", TimeMS: at,
		Files: []release.Asset{{Name: "cbb-linux-amd64.tar.gz", Size: int64(len(data)), SHA256: hexSum(data)}}}, s.key)
	if err != nil {
		t.Fatal(err)
	}
	h := rel.Hash()
	ch, err := release.Sign(release.Channel{V: 1, Type: release.TypeChannel, Channel: "stable", Seq: seq, TimeMS: at,
		ExpiresMS: at + life, Release: version, ReleaseSHA256: hex.EncodeToString(h[:])}, s.key)
	if err != nil {
		t.Fatal(err)
	}
	return &control.Release{Keys: keys, Channel: ch, Release: rel}
}

// TestReleaseSpreads hands a signed release to one member, as cbb update
// does: a member connected then and one that joins later get it, keep it
// across a restart, and take no older or forged one.
func TestReleaseSpreads(t *testing.T) {
	signer := newReleaseSigner(t)
	roots := signer.roots(t)
	withRoots := func(c *Config) { c.ReleaseRoots = roots }
	var h hub
	pi := startWith(t, &h, "pi", "linux", withRoots)
	pc := startWith(t, &h, "pc", "linux", withRoots)
	pairWith(t, pi, pc)
	waitFor(t, "pc is connected", func() bool { return len(pi.status(t).Peers) == 1 })

	if _, err := pi.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.1", 2))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pc holds 0.6.1", func() bool { return pc.status(t).Release == "0.6.1" })
	if st := pi.status(t); st.Release != "0.6.1" || st.Update != "" {
		// A development build is offered nothing.
		t.Errorf("pi holds %q, offers %q", st.Release, st.Update)
	}

	if _, err := pc.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.0", 1))); err == nil {
		t.Error("pc took an older channel file")
	}
	forged := signer.sign(t, "0.6.2", 3)
	forged.Release.Sig[len(forged.Release.Sig)-1] ^= 1
	if _, err := pc.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, forged)); err == nil {
		t.Error("pc took a forged release")
	}
	other := newReleaseSigner(t)
	if _, err := pc.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, other.sign(t, "0.6.2", 3))); err == nil {
		t.Error("pc took a release under other roots")
	}
	if got := pc.status(t).Release; got != "0.6.1" {
		t.Errorf("pc holds %q after the refused ones", got)
	}

	mac := startWith(t, &h, "mac", "linux", withRoots)
	pairWith(t, pi, mac)
	waitFor(t, "mac, joining later, holds 0.6.1", func() bool { return mac.status(t).Release == "0.6.1" })

	pc.stop()
	pc = restartService(t, &h, pc)
	if got := pc.status(t).Release; got != "0.6.1" {
		t.Errorf("pc holds %q after a restart", got)
	}
}

// A release under a newer keys.json, which only a root signs, is newer
// than the one held whatever its channel file's seq, so a channel file
// signed as far ahead as a device takes holds the group only until the
// root signs keys.json again.
func TestReleaseUnderNewKeys(t *testing.T) {
	signer := newReleaseSigner(t)
	roots := signer.roots(t)
	withRoots := func(c *Config) { c.ReleaseRoots = roots }
	var h hub
	pi := startWith(t, &h, "pi", "linux", withRoots)
	pc := startWith(t, &h, "pc", "linux", withRoots)
	pairWith(t, pi, pc)
	waitFor(t, "pc is connected", func() bool { return len(pi.status(t).Peers) == 1 })

	if _, err := pi.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.1", release.MaxSeqStep))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pc holds 0.6.1", func() bool { return pc.status(t).Release == "0.6.1" })
	signer.keysSeq = 2
	if _, err := pi.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.2", 1))); err != nil {
		t.Fatalf("pi refused a release under a newer keys.json: %v", err)
	}
	waitFor(t, "pc holds 0.6.2", func() bool { return pc.status(t).Release == "0.6.2" })
	signer.keysSeq = 1
	if _, err := pc.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.3", release.MaxSeqStep+1))); err == nil {
		t.Error("pc took a release under an older keys.json")
	}
}

// TestReleaseArchives passes an archive of the held release through the
// group, as cbb update hands it over and asks for it: the member that
// installed it serves it, another fetches it from there, a file the
// release does not list is refused, and a newer release drops it.
func TestReleaseArchives(t *testing.T) {
	signer := newReleaseSigner(t)
	withRoots := func(c *Config) { c.ReleaseRoots = signer.roots(t) }
	var h hub
	pi := startWith(t, &h, "pi", "linux", withRoots)
	pc := startWith(t, &h, "pc", "linux", withRoots)
	pairWith(t, pi, pc)
	waitFor(t, "pc is connected", func() bool { return len(pi.status(t).Peers) == 1 })

	data := bytes.Repeat([]byte("cbb 0.6.1 "), 300_000) // three chunks of the control socket
	sum := hexSum(data)
	if _, err := pi.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.signArchive(t, "0.6.1", 2, data))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pc holds 0.6.1", func() bool { return pc.status(t).Release == "0.6.1" })
	if _, err := getArchive(t, pc, sum); err == nil {
		t.Fatal("pc got an archive no member holds")
	}

	if err := putArchive(t, pi, hexSum([]byte("other")), []byte("other")); err == nil {
		t.Error("pi took a file the release does not list")
	}
	if err := putArchive(t, pi, sum, data[1:]); err == nil {
		t.Error("pi took a short archive")
	}
	if err := putArchive(t, pi, sum, data); err != nil {
		t.Fatal(err)
	}
	got, err := getArchive(t, pc, sum)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("pc got %d bytes, %v", len(got), err)
	}
	if _, err := os.Stat(filepath.Join(pc.dir, releaseFilesDir, sum)); err != nil {
		t.Errorf("pc does not keep the archive it fetched: %v", err)
	}

	if _, err := pi.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.2", 3))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pi and pc drop the archive of 0.6.1", func() bool {
		_, err1 := os.Stat(filepath.Join(pi.dir, releaseFilesDir, sum))
		_, err2 := os.Stat(filepath.Join(pc.dir, releaseFilesDir, sum))
		return os.IsNotExist(err1) && os.IsNotExist(err2)
	})
}

// putArchive hands s an archive as cbb update does after an install.
func putArchive(t *testing.T, s *testService, sum string, data []byte) error {
	t.Helper()
	c := s.dial(t)
	defer c.Close()
	if err := c.Send(&control.Message{Header: control.Header{Op: control.OpReleaseFile, Value: sum, Part: &control.Part{Size: int64(len(data))}}}); err != nil {
		return err
	}
	for len(data) > 0 {
		n := min(len(data), 1<<20)
		if err := c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: data[:n]}); err != nil {
			return err
		}
		data = data[n:]
	}
	_, err := c.Receive()
	return err
}

// getArchive asks s for an archive as cbb update does before downloading.
func getArchive(t *testing.T, s *testService, sum string) ([]byte, error) {
	t.Helper()
	c := s.dial(t)
	defer c.Close()
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpReleaseGet, Value: sum}})
	if err != nil {
		return nil, err
	}
	var out []byte
	for !m.Done {
		if m, err = c.Receive(); err != nil {
			return nil, err
		}
		out = append(out, m.Payload...)
	}
	return out, nil
}

func hexSum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func releaseJSON(t *testing.T, r *control.Release) string {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A hub asks for the archives its members update from that it lacks, and
// only the release lists; a member that is no hub asks for none.
func TestWantedReleaseFiles(t *testing.T) {
	a := release.Asset{Name: "cbb-linux-arm64.tar.gz", SHA256: hexSum([]byte("a"))}
	b := release.Asset{Name: "cbb-windows-amd64.zip", SHA256: hexSum([]byte("b"))}
	c := release.Asset{Name: "cbb-darwin-arm64.tar.gz", SHA256: hexSum([]byte("c"))}
	held := map[string]bool{b.SHA256: true}
	holds := func(sum [sha256.Size]byte) bool { return held[hex.EncodeToString(sum[:])] }
	names := map[string]bool{a.Name: true, b.Name: true, "cbb-plan9-amd64.tar.gz": true}
	if got := wantedFiles([]release.Asset{a, b, c}, names, holds); !slices.Equal(got, []string{a.Name}) {
		t.Errorf("wanted %v", got)
	}

	signer := newReleaseSigner(t)
	var h hub
	pi := startWith(t, &h, "pi", "linux", func(c *Config) { c.ReleaseRoots = signer.roots(t) })
	if _, err := pi.do(t, control.Header{Op: control.OpRelease}, releaseJSON(t, signer.sign(t, "0.6.1", 2))); err != nil {
		t.Fatal(err)
	}
	m, err := pi.do(t, control.Header{Op: control.OpReleaseWant}, "")
	if err != nil || string(m.Payload) != "null" {
		t.Fatalf("a member that is no hub wants %q: %v", m.Payload, err)
	}
}
