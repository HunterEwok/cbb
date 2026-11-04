// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/vless"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/control"
	"github.com/HunterEwok/cbb/internal/release"
	"github.com/HunterEwok/cbb/internal/rootless"
	"github.com/HunterEwok/cbb/internal/update"
	"github.com/HunterEwok/cbb/internal/version"
)

const updateUsage = `usage: cbb update [-check | -to VERSION]
       cbb update -auto [on|off]
       cbb update -mirror [URL|default]`

// cmdUpdate checks for and installs the newest signed release
// (internal/update), and sets automatic updates and the mirror.
func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	var check, timer bool
	var to, auto, mirror, method string
	var setAuto, setMirror bool
	for i := 0; i < len(args); i++ {
		// value takes the optional value after a flag.
		value := func() string {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "-check":
			check = true
		case "-timer":
			timer = true
		case "-to":
			if to = update.TrimVersion(value()); to == "" {
				fmt.Fprintln(stderr, "cbb: -to needs a version, such as 0.6.1")
				return 2
			}
		case "-auto":
			setAuto, auto = true, value()
			if auto != "" && auto != "on" && auto != "off" {
				fmt.Fprintln(stderr, "cbb: -auto takes on or off")
				return 2
			}
		case "-mirror":
			setMirror, mirror = true, value()
		case "-installed-by":
			// The installers record how they installed this copy.
			if method = value(); !slices.Contains([]string{update.MethodGet, update.MethodBrew, update.MethodWinget, update.MethodDocker, update.MethodPackage}, method) {
				fmt.Fprintln(stderr, "cbb: -installed-by takes get, brew, winget, docker or package")
				return 2
			}
		default:
			fmt.Fprintln(stderr, updateUsage)
			return 2
		}
	}
	modes := 0
	for _, b := range []bool{check || timer || to != "", setAuto, setMirror, method != ""} {
		if b {
			modes++
		}
	}
	if modes > 1 || (check && timer) {
		fmt.Fprintln(stderr, updateUsage)
		return 2
	}
	dir, work := update.Paths()
	exe := os.Getenv("CBB_UPDATE_FROM")
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return fail(stderr, err)
		}
	}
	// A rootless install updates itself as its own user.
	elevated := isElevated() || rootless.Is()
	needAdmin := func() int {
		if runtime.GOOS == "windows" {
			fmt.Fprintln(stderr, "cbb: run it in a terminal opened as administrator")
		} else {
			fmt.Fprintln(stderr, "cbb: run it with sudo")
		}
		return 1
	}
	st, err := update.LoadState(dir)
	if err != nil && elevated {
		return fail(stderr, err)
	}
	switch {
	case method != "":
		if !elevated {
			return needAdmin()
		}
		st.Method = method
		return saveUpdateState(dir, st, stderr)
	case setAuto && auto == "":
		switch {
		case !elevated:
			return needAdmin()
		case st.Auto == nil:
			fmt.Fprintln(stdout, "unset")
		case *st.Auto:
			fmt.Fprintln(stdout, "on")
		default:
			fmt.Fprintln(stdout, "off")
		}
		return 0
	case setAuto:
		if !elevated {
			return needAdmin()
		}
		on := auto == "on"
		m := update.DetectMethod(st.Method, exe)
		if on && m != update.MethodGet {
			return fail(stderr, fmt.Errorf("this copy came from %s, which updates it: %s", m, strings.Join(update.MethodCommands(m), ", then ")))
		}
		progs, err := update.Programs(exe)
		if err != nil {
			return fail(stderr, err)
		}
		if err := update.SetTimer(on, progs[0]); err != nil {
			return fail(stderr, err)
		}
		st.Auto = &on
		if code := saveUpdateState(dir, st, stderr); code != 0 {
			return code
		}
		if on {
			fmt.Fprintln(stdout, "Automatic updates are on: once a day this device checks for a signed release and installs it.")
		} else {
			fmt.Fprintln(stdout, "Automatic updates are off; cbb update installs a release by hand.")
		}
		return 0
	case setMirror:
		if !elevated {
			return needAdmin()
		}
		if mirror == "" {
			if st.Mirror == "" {
				fmt.Fprintf(stdout, "Updates come from %s, or %s when GitHub does not answer.\n", update.GitHub, update.Mirror)
			} else {
				fmt.Fprintf(stdout, "Updates come from %s.\n", st.Mirror)
			}
			return 0
		}
		if mirror == "default" {
			mirror = ""
		}
		if _, err := update.Sources(mirror); err != nil {
			return fail(stderr, err)
		}
		st.Mirror = mirror
		return saveUpdateState(dir, st, stderr)
	}

	if !check && !elevated {
		return needAdmin()
	}
	// install.ps1 stops every program in Program Files\cbb,
	// this one too: the update runs from a copy in its own folder.
	if runtime.GOOS == "windows" && !check && os.Getenv("CBB_UPDATE_FROM") == "" {
		return updateFromCopy(dir, exe, args, stdout, stderr)
	}
	out := stdout
	if timer {
		log, closeLog := updateLog(dir, stderr)
		defer closeLog()
		out, stderr = log, log
		if !update.Due(st, time.Now()) {
			return 0
		}
	}
	roots, src, err := updateRoots()
	if err != nil {
		return fail(stderr, err)
	}
	m := update.DetectMethod(st.Method, exe)
	sources := src
	if sources == nil {
		if sources, err = update.Sources(st.Mirror); err != nil {
			return fail(stderr, err)
		}
		if st.Mirror == "" {
			var closeWay func()
			sources, closeWay = mirrorOverVLESS(sources, out)
			defer closeWay()
		}
		// The group's members passed the service the newest signed
		// release: the last source, for a device that reaches no server.
		sources = append(sources, update.Group{Held: heldRelease})
	}
	progs, err := update.Programs(exe)
	if err != nil {
		return fail(stderr, err)
	}
	installed := update.TrimVersion(version.Version)
	u := &update.Updater{
		Dir: dir, Work: work, Roots: roots, Sources: sources,
		Installed: installed, Archive: update.ArchiveName(), Programs: progs,
		Now: time.Now, Install: update.Install, Healthy: update.Healthy, Verify: update.VerifySigner,
		Group: groupArchive, Keep: keepArchive,
		Log: out,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	found, err := u.Check(ctx, st, to)
	if err != nil {
		if errors.Is(err, update.ErrNoRoots) && timer {
			return 0
		}
		return fail(stderr, fmt.Errorf("checking for an update: %w", err))
	}
	r := found.Release
	shareRelease(found)
	if elevated {
		st.Seen, st.CheckedMS, st.Available = found.Seen, time.Now().UnixMilli(), ""
		if found.Newer && !found.Failed {
			st.Available = r.Version
		}
		if code := saveUpdateState(dir, st, stderr); code != 0 {
			return code
		}
	}
	switch {
	case !found.Newer && to == "":
		fmt.Fprintf(out, "CBB %s is the newest release; this device runs %s.\n", r.Version, version.Version)
		return 0
	case !found.Newer:
		fmt.Fprintf(out, "This device runs %s, which is not below %s.\n", version.Version, r.Version)
		return 0
	case m != update.MethodGet:
		if !timer {
			fmt.Fprintf(out, "CBB %s is available; this device runs %s. It came from %s, which updates it:\n", r.Version, version.Version, m)
			for _, c := range update.MethodCommands(m) {
				fmt.Fprintln(out, "  "+c)
			}
		}
		return 0
	case check:
		fmt.Fprintf(out, "CBB %s is available; this device runs %s. To install it: %s\n", r.Version, version.Version, updateCommand())
		return 0
	case version.Version == "dev":
		return fail(stderr, fmt.Errorf("this is a development build; cbb update installs %s only over a release", r.Version))
	case found.Failed && timer:
		fmt.Fprintf(out, "Skipping %s, which did not start here before; cbb update tries it again.\n", r.Version)
		return 0
	case found.Failed:
		fmt.Fprintf(out, "%s did not start here before; trying it again.\n", r.Version)
	}
	st, err = u.Apply(ctx, found.Source, st, r)
	if code := saveUpdateState(dir, st, stderr); code != 0 {
		return code
	}
	if err != nil {
		return fail(stderr, err)
	}
	return 0
}

// shareRelease hands the signed release that cbb update fetched from the
// channel to the service, which passes it to the group (docs/protocol.md,
// section 16, "In the group"). A service that does not run misses it.
func shareRelease(found update.Found) {
	if len(found.Chan.Body) == 0 {
		return
	}
	data, err := json.Marshal(control.Release{Keys: found.Keys, Channel: found.Chan, Release: found.Rel})
	if err != nil {
		return
	}
	c, err := control.DialFor(control.OpRelease)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Do(&control.Message{Header: control.Header{Op: control.OpRelease}, Payload: data})
}

// mirrorOverVLESS replaces the mirror on dl.cbb.tools with the way to it
// over VLESS when sync away from home goes over VLESS: the forwarder on
// the mirror's server lets the group's clients reach it, and the mirror is
// then never asked directly (docs/protocol.md, section 16, "Where the
// files are"). GitHub stays asked directly. It returns what stops the way.
func mirrorOverVLESS(sources []update.Source, log io.Writer) ([]update.Source, func()) {
	none := func() {}
	c, err := control.DialFor(control.OpUpdateWay)
	if err != nil {
		return sources, none
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpUpdateWay}})
	c.Close()
	if err != nil || len(m.Payload) == 0 {
		return sources, none
	}
	var v tunnel.VLESS
	if err := json.Unmarshal(m.Payload, &v); err != nil {
		return sources, none
	}
	way, err := vless.DialMirror(v)
	if err != nil {
		fmt.Fprintf(log, "The way to the mirror over VLESS could not start: %v\n", err)
		return sources, none
	}
	addr := way.Addr().String()
	through := update.MirrorThrough(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	})
	out := make([]update.Source, 0, len(sources))
	for _, src := range sources {
		if src.String() == update.Mirror {
			src = through
		}
		out = append(out, src)
	}
	return out, func() { way.Close() }
}

// heldRelease asks the service for the signed release it holds.
func heldRelease(ctx context.Context) (keys, channel, rel release.File, err error) {
	c, err := control.DialFor(control.OpReleaseHeld)
	if err != nil {
		return
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpReleaseHeld}})
	if err != nil {
		return
	}
	var r control.Release
	if err = json.Unmarshal(m.Payload, &r); err != nil {
		return
	}
	return r.Keys, r.Channel, r.Release, nil
}

// groupArchive asks the service for the archive a, which it holds or
// fetches from the group's members (docs/protocol.md, section 16, "In the
// group"); the caller checks what it reads against the release.
func groupArchive(ctx context.Context, a release.Asset) (io.ReadCloser, error) {
	c, err := control.DialFor(control.OpReleaseGet)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	m, err := c.Do(&control.Message{Header: control.Header{Op: control.OpReleaseGet, Value: a.SHA256}})
	if err == nil && (m.Part == nil || m.Part.Size != a.Size) {
		err = errors.New("the service answered with another file")
	}
	if err != nil {
		stop()
		c.Close()
		return nil, err
	}
	return &partReader{c: c, stop: stop}, nil
}

// partReader reads the data answers of a part until Done.
type partReader struct {
	c    *control.Client
	stop func() bool
	buf  []byte
	done bool
}

func (p *partReader) Read(b []byte) (int, error) {
	for len(p.buf) == 0 {
		if p.done {
			return 0, io.EOF
		}
		m, err := p.c.Receive()
		if err != nil {
			return 0, err
		}
		p.buf, p.done = m.Payload, m.Done
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *partReader) Close() error {
	p.stop()
	return p.c.Close()
}

// keepArchive hands the service the archive at path, now installed, so
// that it serves it to the group's members. A service that does not take
// it costs nothing but their downloads.
func keepArchive(path string, a release.Asset) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	c, err := control.DialFor(control.OpReleaseFile)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute))
	if c.Send(&control.Message{Header: control.Header{Op: control.OpReleaseFile, Value: a.SHA256, Part: &control.Part{Size: a.Size}}}) != nil {
		return
	}
	buf := make([]byte, 1<<20)
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 && c.Send(&control.Message{Header: control.Header{Op: control.OpData}, Payload: buf[:n]}) != nil {
			return
		}
		if err != nil {
			break
		}
	}
	c.Receive()
}

func updateCommand() string {
	if runtime.GOOS == "windows" {
		return "cbb update (as administrator)"
	}
	return "sudo cbb update"
}

func saveUpdateState(dir string, st update.State, stderr io.Writer) int {
	if err := update.SaveState(dir, st); err != nil {
		return fail(stderr, err)
	}
	return 0
}

// updateRoots returns the release root keys to check against: the pinned
// ones, or for tests, with the release's files in CBB_RELEASE_DIR, those in
// the PEM file CBB_RELEASE_ROOTS (as get.sh takes them). It also returns
// that folder as the one source, nil without it.
func updateRoots() ([][]byte, []update.Source, error) {
	dir := os.Getenv("CBB_RELEASE_DIR")
	if dir == "" {
		return release.Roots, nil, nil
	}
	src := []update.Source{update.Dir(dir)}
	file := os.Getenv("CBB_RELEASE_ROOTS")
	if file == "" {
		return release.Roots, src, nil
	}
	roots, err := readRoots(file)
	if err != nil {
		return nil, nil, err
	}
	return roots, src, nil
}

// readRoots reads the public keys in a PEM file.
func readRoots(file string) ([][]byte, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var roots [][]byte
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			break
		}
		if b.Type == "PUBLIC KEY" {
			roots = append(roots, b.Bytes)
		}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%s holds no PUBLIC KEY", file)
	}
	return roots, nil
}

// updateLog opens the timer's log in the updater's folder, update.log,
// starting it again past 1 MiB, and returns a writer that stamps each line.
func updateLog(dir string, stderr io.Writer) (io.Writer, func()) {
	path := filepath.Join(dir, "update.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
		os.Rename(path, path+".old")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return stderr, func() {}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return stderr, func() {}
	}
	return &stampWriter{w: io.MultiWriter(f, stderr)}, func() { f.Close() }
}

type stampWriter struct{ w io.Writer }

func (s *stampWriter) Write(p []byte) (int, error) {
	if _, err := fmt.Fprintf(s.w, "%s %s", time.Now().UTC().Format(time.RFC3339), p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// updateFromCopy runs cbb update again from a copy of this program in the
// updater's folder, and returns its exit code.
func updateFromCopy(dir, exe string, args []string, stdout, stderr io.Writer) int {
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return fail(stderr, err)
	}
	cp := filepath.Join(runDir, "cbb-update.exe")
	data, err := os.ReadFile(exe)
	if err != nil {
		return fail(stderr, err)
	}
	if err := os.WriteFile(cp, data, 0o700); err != nil {
		return fail(stderr, fmt.Errorf("copying cbb to %s: %w", runDir, err))
	}
	cmd := exec.Command(cp, append([]string{"update"}, args...)...)
	// install.ps1 leaves this process running and renames its program
	// aside.
	cmd.Env = append(os.Environ(), "CBB_UPDATE_FROM="+exe, "CBB_UPDATE_PARENT="+strconv.Itoa(os.Getpid()))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		return fail(stderr, err)
	}
	return 0
}
