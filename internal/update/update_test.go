// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/release"
)

const archive = "clipboardbridge-linux-amd64.tar.gz"

var now = time.UnixMilli(1_800_000_000_000)

type entry struct {
	name string
	data string
	typ  byte
}

func tarGz(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.data)), Typeflag: typ}
		if typ != tar.TypeReg {
			h.Size = 0
			h.Linkname = "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

func sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// fixture is a release signed with throwaway keys, in a folder.
type fixture struct {
	dir        string
	roots      [][]byte
	root, rel  *ecdsa.PrivateKey
	keysSeq    uint64
	channelSeq uint64
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func spki(t *testing.T, k *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{dir: t.TempDir(), root: newKey(t), rel: newKey(t), keysSeq: 1, channelSeq: 1}
	f.roots = [][]byte{spki(t, f.root)}
	return f
}

func (f *fixture) write(t *testing.T, name string, file release.File) {
	t.Helper()
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// publish signs a release of version with the archive data, whose
// programs release.json lists with progs (nil: those in the archive).
func (f *fixture) publish(t *testing.T, version string, data []byte, progs []release.Binary, life time.Duration) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, archive), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if progs == nil {
		progs = []release.Binary{{Name: "clipboardbridge/cbb", SHA256: sum([]byte("cbb " + version))}}
	}
	at := now.UnixMilli() - 1000
	keys, err := release.Sign(release.Keys{V: 1, Type: release.TypeKeys, Seq: f.keysSeq, TimeMS: at,
		ExpiresMS: at + (90 * 24 * time.Hour).Milliseconds(), Keys: []release.Key{{Key: spki(t, f.rel), Name: "test"}}}, f.root)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := release.Sign(release.Release{V: 1, Type: release.TypeRelease, Version: version, Channel: Channel, TimeMS: at,
		Files: []release.Asset{{Name: archive, Size: int64(len(data)), SHA256: sum(data), Binaries: progs}}}, f.rel)
	if err != nil {
		t.Fatal(err)
	}
	h := rel.Hash()
	ch, err := release.Sign(release.Channel{V: 1, Type: release.TypeChannel, Channel: Channel, Seq: f.channelSeq, TimeMS: at,
		ExpiresMS: at + life.Milliseconds(), Release: version, ReleaseSHA256: hex.EncodeToString(h[:])}, f.rel)
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, "keys.json", keys)
	f.write(t, "release.json", rel)
	f.write(t, Channel+".json", ch)
}

func goodArchive(t *testing.T, version string) []byte {
	return tarGz(t,
		entry{name: "clipboardbridge/", typ: tar.TypeDir},
		entry{name: "clipboardbridge/cbb", data: "cbb " + version},
		entry{name: "clipboardbridge/packaging/linux/install.sh", data: "#!/bin/sh\n"})
}

// system is the installed copy as the fakes see it.
type system struct {
	running  string // the version the service reports
	installs []string
	broken   map[string]bool // versions whose service never answers
}

func (f *fixture) updater(t *testing.T, sys *system) *Updater {
	t.Helper()
	work := t.TempDir()
	prog := filepath.Join(work, "installed", "cbb")
	os.MkdirAll(filepath.Dir(prog), 0o755)
	os.WriteFile(prog, []byte("cbb "+sys.running), 0o755)
	return &Updater{
		Dir: work, Work: work, Roots: f.roots, Sources: []Source{Dir(f.dir)},
		Installed: sys.running, Archive: archive, Programs: []string{prog},
		Now: func() time.Time { return now },
		Install: func(_ context.Context, root, bin string) error {
			if _, err := os.Stat(filepath.Join(root, "packaging", "linux", "install.sh")); err != nil {
				return err
			}
			data, err := os.ReadFile(bin)
			if err != nil {
				return err
			}
			v := strings.TrimPrefix(string(data), "cbb ")
			sys.installs = append(sys.installs, v)
			sys.running = v
			return os.WriteFile(prog, data, 0o755)
		},
		Healthy: func(_ context.Context, version string) error {
			if sys.broken[sys.running] || sys.running != version {
				return errors.New("no answer")
			}
			return nil
		},
	}
}

func TestUpdate(t *testing.T) {
	f := newFixture(t)
	f.publish(t, "0.6.1", goodArchive(t, "0.6.1"), nil, 30*24*time.Hour)
	sys := &system{running: "0.6.0"}
	u := f.updater(t, sys)
	found, err := u.Check(context.Background(), State{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !found.Newer || found.Release.Version != "0.6.1" || found.Seen.Version != "0.6.1" {
		t.Fatalf("found %+v", found)
	}
	st, err := u.Apply(context.Background(), found.Source, State{Failed: []string{"0.6.1"}}, found.Release)
	if err != nil {
		t.Fatal(err)
	}
	if sys.running != "0.6.1" || len(st.Failed) != 0 {
		t.Errorf("running %s, failed %v", sys.running, st.Failed)
	}
	// Up to date now.
	u.Installed = "0.6.1"
	if found, err = u.Check(context.Background(), State{Seen: found.Seen}, ""); err != nil || found.Newer {
		t.Errorf("after the update: %+v, %v", found, err)
	}
}

// The archive comes from the group when it has it, the server otherwise,
// and one from the group that does not match release.json is not used.
func TestFromGroup(t *testing.T) {
	data := goodArchive(t, "0.6.1")
	for _, tc := range []struct {
		name  string
		group []byte // nil: the group does not have it
		from  string
	}{
		{"group", data, "the group"},
		{"server", nil, "the server"},
		{"bad copy", append(slices.Clone(data[:len(data)-1]), data[len(data)-1]^1), "the server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.publish(t, "0.6.1", data, nil, 30*24*time.Hour)
			sys := &system{running: "0.6.0"}
			u := f.updater(t, sys)
			var log strings.Builder
			u.Log = &log
			u.Group = func(_ context.Context, a release.Asset) (io.ReadCloser, error) {
				if a.Name != archive || tc.group == nil {
					return nil, errors.New("no member has it")
				}
				return io.NopCloser(bytes.NewReader(tc.group)), nil
			}
			var kept []byte
			u.Keep = func(path string, a release.Asset) {
				kept, _ = os.ReadFile(path)
			}
			found, err := u.Check(context.Background(), State{}, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := u.Apply(context.Background(), found.Source, State{}, found.Release); err != nil {
				t.Fatal(err)
			}
			fromGroup := strings.Contains(log.String(), "from the group.")
			if fromGroup != (tc.from == "the group") {
				t.Errorf("not from %s:\n%s", tc.from, log.String())
			}
			if sys.running != "0.6.1" || !bytes.Equal(kept, data) {
				t.Errorf("running %s, kept %d bytes", sys.running, len(kept))
			}
		})
	}
}

func TestRollback(t *testing.T) {
	f := newFixture(t)
	f.publish(t, "0.6.1", goodArchive(t, "0.6.1"), nil, 30*24*time.Hour)
	sys := &system{running: "0.6.0", broken: map[string]bool{"0.6.1": true}}
	u := f.updater(t, sys)
	found, err := u.Check(context.Background(), State{}, "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := u.Apply(context.Background(), found.Source, State{Available: "0.6.1"}, found.Release)
	if err == nil || !strings.Contains(err.Error(), "0.6.0 is back") {
		t.Fatalf("Apply: %v", err)
	}
	if sys.running != "0.6.0" || !slices.Equal(sys.installs, []string{"0.6.1", "0.6.0"}) {
		t.Errorf("running %s after installs %v", sys.running, sys.installs)
	}
	if !slices.Equal(st.Failed, []string{"0.6.1"}) || st.Available != "" {
		t.Errorf("failed %v, available %q", st.Failed, st.Available)
	}
	if found, _ = u.Check(context.Background(), st, ""); !found.Failed {
		t.Error("the failed version is not marked")
	}
}

func TestRefused(t *testing.T) {
	good := func(t *testing.T) []byte { return goodArchive(t, "0.6.1") }
	for _, c := range []struct {
		name    string
		prepare func(t *testing.T, f *fixture)
		seen    release.Seen
		want    string
	}{
		{"a tampered archive", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", good(t), nil, time.Hour)
			os.WriteFile(filepath.Join(f.dir, archive), append(good(t), 0), 0o644)
		}, release.Seen{}, "does not match the signed release.json"},
		{"a program that release.json does not list", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", good(t), []release.Binary{{Name: "clipboardbridge/cbb", SHA256: sum([]byte("other"))}}, time.Hour)
		}, release.Seen{}, "clipboardbridge/cbb does not match"},
		{"a listed program missing", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", good(t), []release.Binary{{Name: "clipboardbridge/cbb", SHA256: sum([]byte("cbb 0.6.1"))},
				{Name: "clipboardbridge/cbb-helper", SHA256: sum(nil)}}, time.Hour)
		}, release.Seen{}, "is missing"},
		{"a link in the archive", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", tarGz(t, entry{name: "clipboardbridge/cbb", data: "cbb 0.6.1"},
				entry{name: "clipboardbridge/passwd", typ: tar.TypeSymlink}), nil, time.Hour)
		}, release.Seen{}, "not a plain file"},
		{"a path out of the folder", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", tarGz(t, entry{name: "clipboardbridge/cbb", data: "cbb 0.6.1"},
				entry{name: "clipboardbridge/../../evil", data: "x"}), nil, time.Hour)
		}, release.Seen{}, "holds the path"},
		{"a bad signature", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", good(t), nil, time.Hour)
			data, _ := os.ReadFile(filepath.Join(f.dir, "release.json"))
			var rf release.File
			json.Unmarshal(data, &rf)
			rf.Sig[len(rf.Sig)-1] ^= 1
			f.write(t, "release.json", rf)
		}, release.Seen{}, "signature"},
		{"an expired channel", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", good(t), nil, time.Millisecond)
		}, release.Seen{}, "expired"},
		{"an older version", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", good(t), nil, time.Hour)
		}, release.Seen{Version: "0.6.2"}, "older"},
		{"a channel naming no version", func(t *testing.T, f *fixture) {
			// Before the channel file is checked: its name never makes an
			// address.
			f.publish(t, "0.6.1", good(t), nil, time.Hour)
			body, _ := json.Marshal(release.Channel{V: 1, Type: release.TypeChannel, Channel: Channel, Release: "0.6.1/../x"})
			f.write(t, Channel+".json", release.File{Body: body, Sig: []byte{1}, Key: spki(t, f.rel)})
		}, release.Seen{}, "not a version"},
		{"another project's roots", func(t *testing.T, f *fixture) {
			f.publish(t, "0.6.1", good(t), nil, time.Hour)
			f.roots = [][]byte{spki(t, newKey(t))}
		}, release.Seen{}, "signature"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c.prepare(t, f)
			sys := &system{running: "0.6.0"}
			u := f.updater(t, sys)
			found, err := u.Check(context.Background(), State{Seen: c.seen}, "")
			if err == nil {
				_, err = u.Apply(context.Background(), found.Source, State{}, found.Release)
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if len(sys.installs) != 0 {
				t.Errorf("installed %v", sys.installs)
			}
		})
	}
}

func TestNoRoots(t *testing.T) {
	f := newFixture(t)
	f.publish(t, "0.6.1", goodArchive(t, "0.6.1"), nil, time.Hour)
	u := f.updater(t, &system{running: "0.6.0"})
	u.Roots = nil
	if _, err := u.Check(context.Background(), State{}, ""); !errors.Is(err, ErrNoRoots) {
		t.Errorf("%v", err)
	}
}

func TestMinFrom(t *testing.T) {
	f := newFixture(t)
	f.publish(t, "0.6.1", goodArchive(t, "0.6.1"), nil, time.Hour)
	u := f.updater(t, &system{running: "0.4.0"})
	found, err := u.Check(context.Background(), State{}, "")
	if err != nil {
		t.Fatal(err)
	}
	found.Release.MinFrom = "0.5.0"
	if _, err := u.Apply(context.Background(), found.Source, State{}, found.Release); err == nil || !strings.Contains(err.Error(), "cbb update -to 0.5.0") {
		t.Errorf("%v", err)
	}
}

func TestPinned(t *testing.T) {
	f := newFixture(t)
	f.publish(t, "0.5.2", goodArchive(t, "0.5.2"), nil, time.Hour)
	os.Remove(filepath.Join(f.dir, Channel+".json"))
	u := f.updater(t, &system{running: "0.5.0"})
	found, err := u.Check(context.Background(), State{}, "0.5.2")
	if err != nil || !found.Newer {
		t.Fatalf("%+v, %v", found, err)
	}
	if _, err := u.Check(context.Background(), State{}, "0.5.3"); err == nil {
		t.Error("took release.json of 0.5.2 for 0.5.3")
	}
	if _, err := u.Check(context.Background(), State{}, "0.5.2/../0.5.2"); err == nil || !strings.Contains(err.Error(), "not a version") {
		t.Errorf("a version with a path: %v", err)
	}
}

func TestHTTPSources(t *testing.T) {
	var paths []string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("User-Agent") != "cbb" || r.URL.RawQuery != "" {
			t.Errorf("request %s %v", r.URL, r.Header)
		}
		if strings.HasSuffix(r.URL.Path, "/elsewhere") {
			http.Redirect(w, r, "https://example.com/x", http.StatusFound)
			return
		}
		fmt.Fprint(w, "data")
	}))
	defer ts.Close()
	for _, github := range []bool{true, false} {
		s := newHTTP(ts.URL, github)
		s.client.Transport = ts.Client().Transport
		s.channel = ts.URL + "/channel"
		for _, v := range []string{"", "0.6.1"} {
			if data, err := s.Fetch(context.Background(), "keys.json", v, 10); err != nil || string(data) != "data" {
				t.Errorf("%v %q: %q, %v", github, v, data, err)
			}
		}
		if _, err := s.Fetch(context.Background(), "keys.json", "", 2); err == nil {
			t.Error("took a file over the limit")
		}
		if _, err := s.Fetch(context.Background(), "elsewhere", "", 10); err == nil || !strings.Contains(err.Error(), "not an update server") {
			t.Errorf("redirect: %v", err)
		}
	}
	want := []string{"/channel/keys.json", "/download/v0.6.1/keys.json", "/channel/keys.json",
		"/latest/download/elsewhere", "/keys.json", "/v0.6.1/keys.json", "/keys.json", "/elsewhere"}
	if !slices.Equal(paths, want) {
		t.Errorf("paths %v", paths)
	}
	gh := newHTTP(GitHub, true)
	if got := gh.url("stable.json", ""); got != ChannelFiles+"/stable.json" {
		t.Errorf("stable.json from GitHub at %s", got)
	}
	if got := gh.url("release.json", ""); got != GitHub+"/latest/download/release.json" {
		t.Errorf("release.json from GitHub at %s", got)
	}
	if _, err := Sources("http://mirror.example"); err == nil {
		t.Error("took an http mirror")
	}
	if s, err := Sources("https://mirror.example/cbb/"); err != nil || len(s) != 1 || s[0].String() != "https://mirror.example/cbb" {
		t.Errorf("%v, %v", s, err)
	}
}

func TestState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "update")
	st, err := LoadState(dir)
	if err != nil || st.Auto != nil {
		t.Fatalf("%+v, %v", st, err)
	}
	on := true
	st = State{Method: MethodGet, Auto: &on, Seen: release.Seen{KeysSeq: 2, Version: "0.6.0"}, Failed: []string{"0.6.1"}}
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil || got.Auto == nil || !*got.Auto || got.Seen != st.Seen || !slices.Equal(got.Failed, st.Failed) {
		t.Errorf("%+v, %v", got, err)
	}
	if !Due(got, now) {
		t.Error("never checked, and not due")
	}
	got.CheckedMS = now.Add(-time.Hour).UnixMilli()
	if Due(got, now) {
		t.Error("due an hour after a check")
	}
	off := false
	if Due(State{Auto: &off}, now) {
		t.Error("due with automatic updates off")
	}
}

func TestDetectMethod(t *testing.T) {
	t.Setenv("CBB_CONTAINER", "")
	for _, c := range []struct{ recorded, exe, want string }{
		{"", "/usr/local/bin/cbb", MethodGet},
		{MethodPackage, "/usr/bin/cbb", MethodPackage},
		{"", "/opt/homebrew/Cellar/clipboardbridge/0.6.0/bin/cbb", MethodBrew},
		{MethodGet, "/home/linuxbrew/.linuxbrew/bin/cbb", MethodBrew},
		{"", `C:\Users\a\AppData\Local\Microsoft\WinGet\Packages\HunterEwok.clipboardbridge\clipboardbridge\cbb.exe`, MethodWinget},
	} {
		if got := DetectMethod(c.recorded, filepath.FromSlash(c.exe)); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.recorded, c.exe, got, c.want)
		}
	}
	t.Setenv("CBB_CONTAINER", "docker")
	if got := DetectMethod(MethodGet, "/usr/local/bin/cbb"); got != MethodDocker {
		t.Errorf("in a container: %s", got)
	}
}

func TestInstallFailure(t *testing.T) {
	out := "Stopping...\r\ninstall.ps1: starting the service failed: Service 'CBB' cannot be started.\r\nName : x\r\nat <ScriptBlock>, install.ps1: line 388\r\n"
	if got := installFailure(out, "install.ps1"); got != "starting the service failed: Service 'CBB' cannot be started." {
		t.Errorf("got %q", got)
	}
	if got := installFailure("a\nb\nc\nd\ne\nf\n", "install.sh"); got != "b\nc\nd\ne\nf" {
		t.Errorf("without the line: %q", got)
	}
}
