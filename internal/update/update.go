// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package update updates an installed clipboardbridge to the newest signed
// release (docs/design.md, "Secure updates"): it fetches the release files
// of docs/protocol.md, section 16, checks them with internal/release,
// downloads the archive for this system and checks it and the programs in
// it against release.json, and installs it with the archive's own
// installer, which replaces the files safely and keeps the user's earlier
// answers. When the service does not report the new version within a
// minute, the same installer puts the previous programs back, and the
// version goes on a list of failed versions that automatic updates skip.
//
// cbb update runs as its own short-lived process, by hand or from a timer,
// never inside the service, whose network limit allows only the group's
// servers.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/atomicfile"
	"github.com/HunterEwok/clipboardbridge/internal/release"
)

// The install methods the installers record. Only an installation from
// get.sh, get.ps1 or a release archive updates itself; the others update
// through their own tool.
const (
	MethodGet     = "get"
	MethodBrew    = "brew"
	MethodWinget  = "winget"
	MethodDocker  = "docker"
	MethodPackage = "package"
)

// Channel is the channel updates follow.
const Channel = "stable"

// HealthTimeout is how long the new service has to report its version.
const HealthTimeout = time.Minute

// groupTimeout is how long the group has to hand over an archive before
// the server is asked.
const groupTimeout = 10 * time.Minute

// checkEvery is how often a timer checks at most: once a day, with room
// for a timer that fires a little early.
const checkEvery = 20 * time.Hour

// ErrNoRoots is returned by a build that pins no release root keys: it has
// nothing to check a release against, so it takes none.
var ErrNoRoots = errors.New("this build pins no release keys yet, so it cannot check a release and does not update itself; install the next release with get.sh or get.ps1")

// State is what the updater keeps in its directory, update.json, which
// only root or SYSTEM may change.
type State struct {
	// Method is how this copy was installed, as the installer recorded it.
	Method string `json:"method,omitempty"`
	// Auto is the user's answer to "update automatically?"; nil before one.
	Auto *bool `json:"auto,omitempty"`
	// Mirror is the base URL of a mirror to take updates from instead of
	// GitHub and dl.cbb.tools; "" for those.
	Mirror string `json:"mirror,omitempty"`
	// Seen keeps the highest sequence numbers and version taken, so that
	// no server can take this device back.
	Seen release.Seen `json:"seen"`
	// Failed lists the versions that did not become healthy here.
	Failed []string `json:"failed,omitempty"`
	// CheckedMS is when the last check succeeded, Unix milliseconds.
	CheckedMS int64 `json:"checked_ms,omitempty"`
	// Available is the newest version that check found, if newer than
	// the installed one.
	Available string `json:"available,omitempty"`
}

const stateFile = "update.json"

// LoadState reads the state in dir; a missing file is an empty state.
func LoadState(dir string) (State, error) {
	var s State
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("%s: %w", filepath.Join(dir, stateFile), err)
	}
	return s, nil
}

// SaveState writes the state to dir, which it makes for root alone.
func SaveState(dir string, s State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, stateFile), append(data, '\n'), 0o600)
}

// Updater checks for and installs updates. The fields that touch the system
// are functions, so that tests replace them.
type Updater struct {
	// Dir keeps update.json; Work, which may be the same, the downloads,
	// the unpacked archive and the previous programs.
	Dir, Work string
	Roots     [][]byte
	Sources   []Source
	// Installed is the version installed, without the v.
	Installed string
	// Archive is the release's file for this system.
	Archive string
	// Programs are the installed programs a rollback needs, the main
	// one first; their names are those in the archive's top folder.
	Programs []string
	Now      func() time.Time
	// Install runs the installer of the unpacked archive in root on the
	// program bin, which may be the previous one, for a rollback.
	Install func(ctx context.Context, root, bin string) error
	// Healthy waits until the service reports version, without the v.
	Healthy func(ctx context.Context, version string) error
	// Verify, when set, checks the new programs further before they are
	// installed: on Windows, their Authenticode signer.
	Verify func(installed, unpacked []string) error
	// Group, when set, gets the archive from the group's members through
	// the service, before the server is asked (docs/protocol.md, section
	// 16, "In the group"); Keep hands the service the archive once it is
	// installed, for the members after this one.
	Group func(ctx context.Context, a release.Asset) (io.ReadCloser, error)
	Keep  func(path string, a release.Asset)
	Log   io.Writer
}

func (u *Updater) logf(format string, args ...any) {
	if u.Log != nil {
		fmt.Fprintf(u.Log, format+"\n", args...)
	}
}

// Found is the result of a check.
type Found struct {
	Release release.Release
	// Newer says the release is above the installed version.
	Newer bool
	// Failed says the release failed to become healthy here before.
	Failed bool
	// Seen is the state to keep once the release is taken or refused.
	Seen release.Seen
	// Source is the server the files came from, which the archive comes
	// from too.
	Source Source
	// Keys, Chan and Rel are the signed files as fetched, for the group;
	// Chan is empty for a version asked for by name.
	Keys, Chan, Rel release.File
}

// Check fetches and verifies the channel's current release, or the
// release of version when it is not "". It does not change the state.
func (u *Updater) Check(ctx context.Context, st State, version string) (Found, error) {
	if len(u.Roots) == 0 {
		return Found{}, ErrNoRoots
	}
	if version != "" && !release.IsVersion(version) {
		return Found{}, fmt.Errorf("%q is not a version, as 0.6.0 or 0.6.0-rc.1", version)
	}
	var errs []error
	for _, src := range u.Sources {
		f, err := u.checkFrom(ctx, src, st, version)
		if err == nil {
			return f, nil
		}
		// A signature that fails or a rollback is an answer, not a
		// server that is down: another server must not get a say.
		if errors.Is(err, release.ErrSignature) || errors.Is(err, release.ErrRollback) {
			return Found{}, err
		}
		errs = append(errs, fmt.Errorf("%s: %w", src, err))
	}
	if len(errs) == 0 {
		return Found{}, errors.New("no update server is set")
	}
	return Found{}, errors.Join(errs...)
}

func (u *Updater) checkFrom(ctx context.Context, src Source, st State, version string) (Found, error) {
	get := func(name, ver string) (release.File, error) {
		var f release.File
		data, err := src.Fetch(ctx, name, ver, maxManifest)
		if err != nil {
			return f, err
		}
		if err := json.Unmarshal(data, &f); err != nil {
			return f, fmt.Errorf("%s: %w", name, err)
		}
		return f, nil
	}
	keys, err := get("keys.json", "")
	if err != nil {
		return Found{}, err
	}
	var r release.Release
	var seen release.Seen
	var ch, rel release.File
	if version != "" {
		rel, err = get("release.json", version)
		if err != nil {
			return Found{}, err
		}
		if r, seen, err = release.CheckPinned(keys, rel, u.Roots, u.Now(), st.Seen); err != nil {
			return Found{}, err
		}
		if r.Version != version {
			return Found{}, fmt.Errorf("release.json: it is %s, not %s", r.Version, version)
		}
	} else {
		ch, err = get(Channel+".json", "")
		if err != nil {
			return Found{}, err
		}
		var c release.Channel
		if err := json.Unmarshal(ch.Body, &c); err != nil || c.Release == "" {
			return Found{}, fmt.Errorf("%s.json names no release", Channel)
		}
		// The name goes into the release's address before the channel
		// file is checked, so it must be a version and nothing else.
		if !release.IsVersion(c.Release) {
			return Found{}, fmt.Errorf("%s.json names a release that is not a version", Channel)
		}
		rel, err = get("release.json", c.Release)
		if err != nil {
			return Found{}, err
		}
		if r, seen, err = release.Check(keys, ch, rel, u.Roots, Channel, u.Now(), st.Seen); err != nil {
			return Found{}, err
		}
	}
	return Found{
		Release: r,
		Newer:   release.Compare(r.Version, u.Installed) > 0,
		Failed:  slices.Contains(st.Failed, r.Version),
		Seen:    seen,
		Source:  src,
		Keys:    keys,
		Chan:    ch,
		Rel:     rel,
	}, nil
}

// Apply downloads the release's archive, checks it, installs it and waits
// until the service reports the new version; when it does not, it puts the
// previous programs back and adds the version to st.Failed. It returns the
// state to keep, also on an error.
func (u *Updater) Apply(ctx context.Context, src Source, st State, r release.Release) (State, error) {
	if !r.Direct(u.Installed) {
		return st, fmt.Errorf("%s updates only from %s or later; first run: cbb update -to %s", r.Version, r.MinFrom, r.MinFrom)
	}
	asset, ok := r.Asset(u.Archive)
	if !ok {
		return st, fmt.Errorf("release %s has no %s for this system", r.Version, u.Archive)
	}
	if err := os.MkdirAll(u.Work, 0o700); err != nil {
		return st, err
	}
	path := filepath.Join(u.Work, u.Archive)
	fromGroup := false
	if u.Group != nil {
		gctx, cancel := context.WithTimeout(ctx, groupTimeout)
		err := download(gctx, func(ctx context.Context) (io.ReadCloser, error) { return u.Group(ctx, asset) }, asset, path)
		cancel()
		if err == nil {
			fromGroup = true
			u.logf("Took %s (%s) from the group.", u.Archive, r.Version)
		} else {
			// Usual for the first device of a group to take a release.
			u.logf("No device of the group could hand it over (%v).", err)
		}
	}
	if !fromGroup {
		u.logf("Downloading %s (%s)...", u.Archive, r.Version)
		open := func(ctx context.Context) (io.ReadCloser, error) { return src.Open(ctx, asset.Name, r.Version) }
		if err := download(ctx, open, asset, path); err != nil {
			return st, err
		}
	}
	defer os.Remove(path)
	unpacked := filepath.Join(u.Work, "new")
	if err := os.RemoveAll(unpacked); err != nil {
		return st, err
	}
	root, err := unpack(path, unpacked, asset)
	if err != nil {
		return st, fmt.Errorf("%s: %w", u.Archive, err)
	}
	defer os.RemoveAll(unpacked)
	news := make([]string, len(u.Programs))
	for i, p := range u.Programs {
		news[i] = filepath.Join(root, filepath.Base(p))
		if _, err := os.Stat(news[i]); err != nil {
			return st, fmt.Errorf("%s has no %s", u.Archive, filepath.Base(p))
		}
	}
	if u.Verify != nil {
		if err := u.Verify(u.Programs, news); err != nil {
			return st, err
		}
	}
	// The previous programs, for a rollback, in a folder of their own:
	// the installer takes the helper programs from beside the main one.
	prev := filepath.Join(u.Work, "previous")
	if err := os.RemoveAll(prev); err != nil {
		return st, err
	}
	if err := os.MkdirAll(prev, 0o700); err != nil {
		return st, err
	}
	for _, p := range u.Programs {
		if err := copyFile(p, filepath.Join(prev, filepath.Base(p))); err != nil {
			return st, fmt.Errorf("keeping the previous %s: %w", filepath.Base(p), err)
		}
	}
	u.logf("Installing %s...", r.Version)
	err = u.Install(ctx, root, news[0])
	if err == nil {
		hctx, cancel := context.WithTimeout(ctx, HealthTimeout)
		err = u.Healthy(hctx, r.Version)
		cancel()
		if err != nil {
			err = fmt.Errorf("the service did not report %s within %s: %w", r.Version, HealthTimeout, err)
		}
	}
	if err == nil {
		st.Failed = slices.DeleteFunc(st.Failed, func(v string) bool { return v == r.Version })
		st.Available = ""
		u.logf("CBB %s is installed.", r.Version)
		if u.Keep != nil {
			u.Keep(path, asset)
		}
		return st, nil
	}
	if !slices.Contains(st.Failed, r.Version) {
		st.Failed = append(st.Failed, r.Version)
	}
	// Not offered while automatic updates skip it.
	st.Available = ""
	u.logf("Putting %s back: %v", u.Installed, err)
	if rerr := u.Install(ctx, root, filepath.Join(prev, filepath.Base(u.Programs[0]))); rerr != nil {
		return st, fmt.Errorf("%w; and putting %s back failed too: %v", err, u.Installed, rerr)
	}
	hctx, cancel := context.WithTimeout(ctx, HealthTimeout)
	defer cancel()
	if herr := u.Healthy(hctx, u.Installed); herr != nil {
		return st, fmt.Errorf("%w; %s is back, but its service does not answer either: %v", err, u.Installed, herr)
	}
	return st, fmt.Errorf("%w; %s is back, and automatic updates skip %s", err, u.Installed, r.Version)
}

// Due reports whether a timer should check now: automatic updates are on
// and the last check is a day old.
func Due(st State, now time.Time) bool {
	return st.Auto != nil && *st.Auto && now.Sub(time.UnixMilli(st.CheckedMS)) >= checkEvery
}

// TrimVersion takes the v off a tag.
func TrimVersion(v string) string { return strings.TrimPrefix(v, "v") }

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm()|0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
