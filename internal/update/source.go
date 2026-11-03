// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// maxManifest is the largest release file fetched: a body of
// release.MaxBody in base64, with the envelope around it.
const maxManifest = 1 << 20

// Source is a server, or a folder, that holds releases. Fetch returns the
// file name of the release version, or of the latest release when version
// is ""; it reads at most max bytes. Open does the same for a large file.
type Source interface {
	Fetch(ctx context.Context, name, version string, max int64) ([]byte, error)
	Open(ctx context.Context, name, version string) (io.ReadCloser, error)
	String() string
}

// The update servers: GitHub's releases, and their mirror on a name of its
// own, apart from the forwarder on cbb.tools.
const (
	GitHub = "https://github.com/HunterEwok/cbb/releases"
	Mirror = "https://dl.cbb.tools"
	// ChannelFiles is where GitHub keeps the current keys.json and channel
	// files: the branch channel, since a published release takes no new
	// files and these are signed again while it is current
	// (docs/protocol.md, section 16, "Where the files are").
	ChannelFiles = "https://raw.githubusercontent.com/HunterEwok/cbb/channel"
)

// channelFile reports whether name is a file signed again while a release
// is current: keys.json and the channel file.
func channelFile(name string) bool { return name == "keys.json" || name == Channel+".json" }

// Sources returns where updates come from: the mirror the user set, or
// GitHub and then dl.cbb.tools.
func Sources(mirror string) ([]Source, error) {
	if mirror == "" {
		return []Source{newHTTP(GitHub, true), newHTTP(Mirror, false)}, nil
	}
	u, err := url.Parse(mirror)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("a mirror is an https:// address, not %q", mirror)
	}
	return []Source{newHTTP(strings.TrimSuffix(mirror, "/"), false)}, nil
}

// Dir is a folder with a release's files side by side, as CI and the
// bench give them (CBB_RELEASE_DIR).
type Dir string

func (d Dir) String() string { return string(d) }

func (d Dir) Open(_ context.Context, name, _ string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(d), name))
}

func (d Dir) Fetch(ctx context.Context, name, version string, max int64) ([]byte, error) {
	f, err := d.Open(ctx, name, version)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readMax(f, max)
}

// httpSource is a server. GitHub keeps each release under download/vX.Y.Z
// and the latest under latest/download; a mirror under vX.Y.Z and its top.
type httpSource struct {
	base   string
	github bool
	// channel is where GitHub keeps the channel files: ChannelFiles.
	channel string
	client  *http.Client
}

// allowedHost reports whether the updater may connect to host: the update
// servers, the hosts GitHub sends its downloads to, and the mirror the
// user named. The service's network limit does not cover this process, so
// it limits itself.
func allowedHost(host, base string) bool {
	if u, err := url.Parse(base); err == nil && strings.EqualFold(u.Hostname(), host) {
		return true
	}
	host = strings.ToLower(host)
	return host == "github.com" || host == "dl.cbb.tools" || strings.HasSuffix(host, ".githubusercontent.com")
}

func newHTTP(base string, github bool) *httpSource {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = 30 * time.Second
	s := &httpSource{base: base, github: github, channel: ChannelFiles}
	s.client = &http.Client{
		Transport: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" || !allowedHost(req.URL.Hostname(), base) {
				return fmt.Errorf("redirected to %s, which is not an update server", req.URL.Host)
			}
			return nil
		},
	}
	return s
}

func (s *httpSource) String() string { return s.base }

func (s *httpSource) url(name, version string) string {
	switch {
	case s.github && version == "" && channelFile(name):
		return s.channel + "/" + name
	case s.github && version == "":
		return s.base + "/latest/download/" + name
	case s.github:
		return s.base + "/download/v" + version + "/" + name
	case version == "":
		return s.base + "/" + name
	}
	return s.base + "/v" + version + "/" + name
}

func (s *httpSource) Open(ctx context.Context, name, version string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url(name, version), nil)
	if err != nil {
		return nil, err
	}
	// The same for every device: no version, system or cookie.
	req.Header.Set("User-Agent", "cbb")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", name, resp.Status)
	}
	return resp.Body, nil
}

func (s *httpSource) Fetch(ctx context.Context, name, version string, max int64) ([]byte, error) {
	body, err := s.Open(ctx, name, version)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return readMax(body, max)
}

func readMax(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return data, nil
}

// download writes the asset of version to path, checking its size and
// SHA-256 against release.json as it arrives.
func download(ctx context.Context, open func(context.Context) (io.ReadCloser, error), a release.Asset, path string) error {
	body, err := open(ctx)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", a.Name, err)
	}
	defer body.Close()
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(body, a.Size+1))
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("downloading %s: %w", a.Name, err)
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		os.Remove(path)
		return fmt.Errorf("%s does not match the signed release.json; not installing it", a.Name)
	}
	return nil
}
