// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command release-sign makes and signs the files that describe a release
// (docs/protocol.md, section 16), on the maintainer's Mac:
//
//	release-sign publish -version 0.6.0 [-min-from 0.5.0] [-docker none] [-channel NAME=KEY.pem] [-forwarder ADDRESS=KEY.pem] [-relay ADDRESS=KEY.pem] [-no-publish]
//	release-sign renew [-new-keys]
//	release-sign extend -key file:channel-key.pem -out DIR      (on cbb.tools)
//	release-sign mirror -out DIR [-from SRC,...] [-zxnext DIR] [-version X.Y.Z]... (on cbb.tools)
//	release-sign take [-new URL] BRANCH-DIR                     (the channel workflow)
//	release-sign due BRANCH-DIR                                 (the channel workflow)
//	release-sign manifest -version 0.6.0 -channel stable [-min-from 0.5.0] [-docker IMAGE@sha256:...] DIR >release.body
//	release-sign keys -seq 2 [-days 90] [-status NAME=status-key.pem] [-forwarder ADDRESS=key.pem] [-relay ADDRESS=key.pem] NAME=release-key.pem... >keys.body
//	release-sign channel -seq 7 [-days 30] release.json >stable.body
//	release-sign sign -key SIGNER BODY >FILE.json
//	release-sign public -key SIGNER >key.pem
//	release-sign pq-new -key CLASSICAL (-to RECIPIENT -identity ID | -out -) [-public PUB.pem] [-name NAME]
//	release-sign pq-check -key SIGNER -public PUB.pem
//	release-sign verify [-roots ROOTS.pem,...] [-channel stable] DIR
//	release-sign drill -version 0.6.0 [-channel-key] DIR ROOTS.pem
//
// A SIGNER is file:KEY.pem (a P-256 key in a file, for tests and drills),
// piv:SLOT (a key on a YubiKey, through yubico-piv-tool; the root keys) or
// se:KEY (a Secure Enclave key through se.swift beside this file, which
// asks for Touch ID; the release key). drill signs DIR as a release with
// throwaway keys in files and writes their roots to ROOTS.pem, for the
// installers' tests and for drills. publish and renew write keys.json and
// stable.json to the branch channel; extend renews stable.json with the
// channel key, and take and due bring it into the branch; entries signs
// the list of the project's entry points, which extend renews and take
// brings in as well; mirror keeps
// dl.cbb.tools and the ZX Spectrum Next's files on cbb.tools.
// docs/maintaining.md, "Signed releases", has the whole flow.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) error{
		"manifest": manifest, "keys": keys, "channel": channel,
		"sign": sign, "public": public, "verify": verify, "drill": drill,
		"publish": publish, "renew": renew, "extend": extend, "take": take, "due": due, "mirror": mirror, "entries": entries,
		"pq-new": pqNew, "pq-check": pqCheck,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "release-sign:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: release-sign publish|renew|extend|entries|mirror|take|due|manifest|keys|channel|sign|public|pq-new|pq-check|verify|drill ... (see the comment in tools/release-sign/main.go)")
	os.Exit(2)
}

var (
	now              = time.Now
	stdout io.Writer = os.Stdout
)

func writeJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(data, '\n'))
	return err
}

// manifest writes the body of release.json for the files in a directory.
func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	version := fs.String("version", "", "the release's version, without the v")
	ch := fs.String("channel", "stable", "the channel")
	minFrom := fs.String("min-from", "", "the lowest version that may update to this one directly")
	docker := fs.String("docker", "", "the image as NAME@sha256:DIGEST")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("manifest needs the directory of the release's files")
	}
	r, err := buildManifest(fs.Arg(0), *version, *ch, *minFrom, *docker)
	if err != nil {
		return err
	}
	return writeJSON(r)
}

func buildManifest(dir, version, ch, minFrom, docker string) (release.Release, error) {
	r := release.Release{V: 1, Type: release.TypeRelease, Version: strings.TrimPrefix(version, "v"), Channel: ch,
		TimeMS: now().UnixMilli(), MinFrom: strings.TrimPrefix(minFrom, "v")}
	if docker != "" {
		image, digest, ok := strings.Cut(docker, "@")
		if !ok {
			return r, errors.New("-docker must be NAME@sha256:DIGEST")
		}
		r.Docker = &release.Docker{Image: image, Digest: digest}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return r, err
	}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || describes(name) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return r, err
		}
		a := release.Asset{Name: name, Size: int64(len(data)), SHA256: hexSum(data)}
		if a.Binaries, err = binaries(name, data); err != nil {
			return r, fmt.Errorf("%s: %w", name, err)
		}
		r.Files = append(r.Files, a)
	}
	// Signing the body checks it as every reader will.
	body, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if err := checkBody(body); err != nil {
		return r, err
	}
	return r, nil
}

// describes tells the files that describe a release (release.json and the
// like, which release-sign signs) from the release's own files; the
// software bills of materials (tools/sbom) are JSON too, and are the
// release's files.
func describes(name string) bool {
	return strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".cdx.json")
}

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// binaries lists the programs inside an archive: the executable files of
// a tar.gz, the .exe files of a zip.
func binaries(name string, data []byte) ([]release.Binary, error) {
	var out []release.Binary
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg || h.Mode&0o111 == 0 || strings.HasSuffix(h.Name, ".sh") {
				continue
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			out = append(out, release.Binary{Name: h.Name, SHA256: hexSum(b)})
		}
	case strings.HasSuffix(name, ".zip") && !strings.HasPrefix(name, "winget"):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
			out = append(out, release.Binary{Name: f.Name, SHA256: hexSum(b)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// checkBody signs body with a throwaway key, which runs the checks Sign
// makes, without a hardware key.
func checkBody(body []byte) error {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	return release.CheckBody(body)
}

// keys writes the body of keys.json, certifying the release keys and,
// with -status, the keys that sign attest-status.json.
func keys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	seq := fs.Uint64("seq", 0, "the sequence number, above the last keys.json's")
	days := fs.Int("days", 90, "days until it expires")
	var status []string
	fs.Func("status", "NAME=KEY.pem of a key that signs attest-status.json (repeatable)", func(v string) error {
		status = append(status, v)
		return nil
	})
	var forwarders []string
	fs.Func("forwarder", "ADDRESS=KEY.pem of the project's forwarder, whose pin hubs accept (repeatable)", func(v string) error {
		forwarders = append(forwarders, v)
		return nil
	})
	var relays []string
	fs.Func("relay", "ADDRESS=KEY.pem of the project's relay, whose pin its members accept (repeatable)", func(v string) error {
		relays = append(relays, v)
		return nil
	})
	fs.Parse(args)
	k := release.Keys{V: 1, Type: release.TypeKeys, Seq: *seq, TimeMS: now().UnixMilli()}
	k.ExpiresMS = k.TimeMS + int64(*days)*24*time.Hour.Milliseconds()
	add := func(arg, use string) error {
		keys, err := keyArg(arg, use)
		k.Keys = append(k.Keys, keys...)
		return err
	}
	for _, arg := range fs.Args() {
		if err := add(arg, ""); err != nil {
			return err
		}
	}
	for _, arg := range status {
		if err := add(arg, release.UseStatus); err != nil {
			return err
		}
	}
	for _, arg := range forwarders {
		if err := add(arg, release.UseForwarder); err != nil {
			return err
		}
	}
	for _, arg := range relays {
		if err := add(arg, release.UseRelay); err != nil {
			return err
		}
	}
	return writeJSON(k)
}

// channel writes the body of a channel file that names a signed
// release.json.
func channel(args []string) error {
	fs := flag.NewFlagSet("channel", flag.ExitOnError)
	seq := fs.Uint64("seq", 0, "the sequence number, above the channel's last")
	days := fs.Int("days", 30, "days until it expires")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("channel needs the signed release.json")
	}
	f, err := readFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var r release.Release
	if err := json.Unmarshal(f.Body, &r); err != nil {
		return err
	}
	h := f.Hash()
	c := release.Channel{V: 1, Type: release.TypeChannel, Channel: r.Channel, Seq: *seq, TimeMS: now().UnixMilli(),
		Release: r.Version, ReleaseSHA256: hex.EncodeToString(h[:])}
	c.ExpiresMS = c.TimeMS + int64(*days)*24*time.Hour.Milliseconds()
	return writeJSON(c)
}

func readFile(path string) (release.File, error) {
	var f release.File
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	return f, json.Unmarshal(data, &f)
}

// keyArg reads NAME=KEY.pem as the entries of keys.json for use: both
// halves of a signer's key, or for a forwarder or a relay its one P-256
// key, the pin its TLS shows.
func keyArg(arg, use string) ([]release.Key, error) {
	name, path, ok := strings.Cut(arg, "=")
	if !ok {
		return nil, fmt.Errorf("%q is not NAME=KEY.pem", arg)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	halves, err := release.ReadHalves(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if use == release.UseForwarder || use == release.UseRelay {
		if len(halves) != 1 || halves[release.AlgES256] == nil {
			return nil, fmt.Errorf("%s: a forwarder's or relay's pin is one P-256 key", path)
		}
		return []release.Key{{Alg: release.AlgES256, Key: halves[release.AlgES256], Name: name, Use: use}}, nil
	}
	var out []release.Key
	for _, alg := range release.Required {
		if halves[alg] == nil {
			return nil, fmt.Errorf("%s holds no key of algorithm %d: a signer's key has both halves (release-sign public)", path, alg)
		}
		out = append(out, release.Key{Alg: alg, Key: halves[alg], Name: name, Use: use})
	}
	return out, nil
}

// readRoots reads root keys from PEM files, the halves of each named by
// its Name header.
func readRoots(paths []string) ([]release.Key, error) {
	var roots []release.Key
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		r, err := release.ParseRoots(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		roots = append(roots, r...)
	}
	return roots, nil
}

// sign signs a body with a signer and writes the file.
func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	key := fs.String("key", "", "the signer: file:KEY.pem, piv:SLOT or se:KEY")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("sign needs the body")
	}
	body, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return err
	}
	body = compact.Bytes()
	s, err := signer(*key)
	if err != nil {
		return err
	}
	f, err := signWith(s, json.RawMessage(body))
	if err != nil {
		return err
	}
	return writeJSON(f)
}

func public(args []string) error {
	fs := flag.NewFlagSet("public", flag.ExitOnError)
	key := fs.String("key", "", "the signer: file:KEY.pem, piv:SLOT or se:KEY")
	name := fs.String("name", "", "the Name header, as roots.pem names a root")
	fs.Parse(args)
	s, err := signer(*key)
	if err != nil {
		return err
	}
	out, err := release.PublicPEM(s, *name)
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}

// verify checks a directory that holds keys.json, the channel file,
// release.json and the files, as a device would.
func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rootsFlag := fs.String("roots", "", "the root keys' PEM files, comma-separated; the pinned roots by default")
	ch := fs.String("channel", "stable", "the channel")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("verify needs the directory")
	}
	dir := fs.Arg(0)
	roots := pinnedRoots()
	if *rootsFlag != "" {
		var err error
		if roots, err = readRoots(strings.Split(*rootsFlag, ",")); err != nil {
			return err
		}
	}
	var files [3]release.File
	for i, name := range []string{"keys.json", *ch + ".json", "release.json"} {
		f, err := readFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		files[i] = f
	}
	r, _, err := release.Check(files[0], files[1], files[2], roots, *ch, now(), release.Seen{})
	if err != nil {
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
	if err := checkSums(dir, r); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s %s: keys.json, %s.json, release.json and %d files check out\n", r.Version, r.Channel, *ch, len(r.Files))
	if r.Docker != nil {
		// The release workflow compares it with the image ghcr.io serves.
		fmt.Fprintf(stdout, "docker %s@%s\n", r.Docker.Image, r.Docker.Digest)
	}
	return nil
}

// checkSums checks the release's SHA256SUMS, when release.json lists one,
// against the files and the manifest: every line names a file there with
// that sum, and every other file of the manifest has a line with its own.
func checkSums(dir string, r release.Release) error {
	if _, ok := r.Asset("SHA256SUMS"); !ok {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return err
	}
	sums := map[string]string{}
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		sum, name, ok := strings.Cut(strings.TrimRight(line, "\r"), " ")
		name = strings.TrimPrefix(strings.TrimPrefix(name, " "), "*")
		if b, err := hex.DecodeString(sum); !ok || err != nil || len(b) != sha256.Size || name == "" {
			return fmt.Errorf("SHA256SUMS line %d is not a sum and a name: %q", i+1, line)
		}
		file, err := os.ReadFile(filepath.Join(dir, filepath.Base(name)))
		if err != nil {
			return fmt.Errorf("SHA256SUMS names %s: %w", name, err)
		}
		if got := sha256.Sum256(file); hex.EncodeToString(got[:]) != strings.ToLower(sum) {
			return fmt.Errorf("SHA256SUMS gives %s another sum than the file has", name)
		}
		sums[name] = strings.ToLower(sum)
	}
	for _, a := range r.Files {
		if a.Name == "SHA256SUMS" {
			continue
		}
		if sums[a.Name] != strings.ToLower(a.SHA256) {
			return fmt.Errorf("SHA256SUMS and release.json disagree on %s", a.Name)
		}
	}
	return nil
}

// signer returns the key a SIGNER names, both halves: CLASSICAL+PQ, or
// file:KEY.pem holding both, or piv:SLOT or se:KEY whose post-quantum half
// pqDir holds.
func signer(spec string) (release.Signer, error) {
	cspec, pspec, _ := strings.Cut(spec, "+")
	if kind, arg, _ := strings.Cut(cspec, ":"); kind == "file" && pspec == "" {
		data, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		defer clear(data)
		s, err := release.ParseSigner(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (a key in a file holds both halves, or names its other half with +slh:FILE)", arg, err)
		}
		return s, nil
	}
	// The passphrase of the sealed halves is asked and checked first,
	// before the hardware is asked for anything.
	if kind, _, _ := strings.Cut(cspec, ":"); pspec == "" && (kind == "piv" || kind == "se") && sealedHalves() {
		if _, err := passphrase(); err != nil {
			return nil, err
		}
	}
	c, err := classicalSigner(cspec)
	if err != nil {
		return nil, err
	}
	pq, err := pqOf(c, pspec)
	if err != nil {
		return nil, err
	}
	return release.Signer{c, pq}, nil
}

// classicalSigner returns the P-256 half a CLASSICAL spec names.
func classicalSigner(spec string) (crypto.Signer, error) {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "file":
		data, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		b, _ := pem.Decode(data)
		if b == nil {
			return nil, fmt.Errorf("%s holds no PEM key", arg)
		}
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			if ec, err2 := x509.ParseECPrivateKey(b.Bytes); err2 == nil {
				return ec, nil
			}
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s is not a signing key", arg)
		}
		return s, nil
	case "piv":
		return newTool([]string{"yubico-piv-tool", "-a", "read-certificate", "-s", arg, "-K", "PEM"},
			[]string{"yubico-piv-tool", "-a", "verify-pin", "--sign", "-s", arg, "-A", "ECCP256", "-H", "SHA256"})
	case "se":
		helper, err := seHelper()
		if err != nil {
			return nil, err
		}
		return newTool([]string{"swift", helper, "public", arg}, []string{"swift", helper, "sign", arg})
	}
	return nil, fmt.Errorf("unknown signer %q: file:KEY.pem, piv:SLOT or se:KEY", spec)
}

//go:embed se.swift
var seSwift []byte

// seHelper returns the path of se.swift: beside the sources when
// CBB_RELEASE_SIGN_DIR names them or the working directory is the
// repository's, otherwise the copy built into this program, written to a
// temporary file, so that release-sign runs from anywhere.
func seHelper() (string, error) {
	dir := os.Getenv("CBB_RELEASE_SIGN_DIR")
	if dir == "" {
		dir = filepath.Join("tools", "release-sign")
	}
	path := filepath.Join(dir, "se.swift")
	if _, err := os.Stat(path); err == nil || os.Getenv("CBB_RELEASE_SIGN_DIR") != "" {
		return path, nil
	}
	path = filepath.Join(os.TempDir(), "cbb-se-"+hexSum(seSwift)[:16]+".swift")
	if err := os.WriteFile(path, seSwift, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// drillFaults are the faults drill -fault puts in keys.json, each a body
// that every reader refuses (docs/protocol.md, section 16).
var drillFaults = []string{"empty-use", "upper-case", "twice", "null", "no-time", "status-brace", "same-name", "broken-pq", "no-pq", "high-s", "broken-twin", "alg-zero", "pin-alg-zero", "pin-not-p256", "path-version"}

// pinFaults are the drill faults that add a forwarder's pin no reader
// takes to keys.json, whatever its use.
var pinFaults = []string{"pin-alg-zero", "pin-not-p256"}

// relFaults are the drill faults put in release.json or stable.json rather
// than keys.json.
var relFaults = []string{"status-brace", "same-name", "broken-pq", "no-pq", "high-s", "broken-twin", "alg-zero", "path-version"}

// otherS returns an ES256 signature with S replaced by n - S: it verifies
// as well, and no reader takes it.
func otherS(sig []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return nil, err
	}
	rs.S.Sub(elliptic.P256().Params().N, rs.S)
	return asn1.Marshal(rs)
}

// faultyKeys signs body, a valid keys.json body, with fault put in.
func faultyKeys(body []byte, fault string, key release.Signer) (release.File, error) {
	s := string(body)
	switch fault {
	case "empty-use":
		s = strings.Replace(s, `"name":"drill"`, `"name":"drill","use":""`, 1)
	case "upper-case":
		s = strings.Replace(s, `"expires_ms":`, `"Expires_ms":1,"expires_ms":`, 1)
	case "twice":
		s = strings.Replace(s, `"seq":1,`, `"seq":1,"seq":2,`, 1)
	case "null":
		s = strings.TrimSuffix(s, "}") + `,"later":null}`
	case "no-time":
		i := strings.Index(s, `"time_ms":`)
		j := strings.Index(s[i:], ",")
		s = s[:i] + s[i+j+1:]
	default:
		return release.File{}, fmt.Errorf("unknown fault %q", fault)
	}
	if s == string(body) {
		return release.File{}, fmt.Errorf("the fault %q changed nothing", fault)
	}
	return signRaw([]byte(s), key)
}

// signRaw signs data as it is, without the checks of release.Sign.
func signRaw(data []byte, key release.Signer) (release.File, error) {
	return release.SignUnchecked(data, key)
}

// drill signs the files in dir as a release with new keys in files: two
// roots, whose public keys go to rootsPath, and a release key.
func drill(args []string) error {
	fs := flag.NewFlagSet("drill", flag.ExitOnError)
	version := fs.String("version", "0.0.1", "the release's version")
	channelKey := fs.Bool("channel-key", false, "sign stable.json with a channel key, as the server renews it")
	relChannel := fs.String("release-channel", "stable", "the channel release.json names, which stable.json names it under anyway, for the installers' tests")
	fault := fs.String("fault", "", "a fault no reader takes, in keys.json or release.json, for the installers' tests: "+strings.Join(drillFaults, ", "))
	fs.Parse(args)
	if fs.NArg() != 2 {
		return errors.New("drill needs the directory and the file for the roots")
	}
	dir, rootsPath := fs.Arg(0), fs.Arg(1)
	var ks [4]release.Signer
	var roots []byte
	for i := range ks {
		k, err := release.GenerateSigner()
		if err != nil {
			return err
		}
		ks[i] = k
		if i < 2 {
			p, err := release.PublicPEM(k, fmt.Sprintf("drill-root-%d", i+1))
			if err != nil {
				return err
			}
			roots = append(roots, p...)
		}
	}
	r, err := buildManifest(dir, *version, *relChannel, "", "")
	if err != nil {
		return err
	}
	rel, err := release.Sign(r, ks[2])
	if err != nil {
		return err
	}
	halves := func(s release.Signer, name, use string) []release.Key {
		k, _ := s.Keys(name, use)
		return k
	}
	t := now().UnixMilli()
	k := release.Keys{V: 1, Type: release.TypeKeys, Seq: 1, TimeMS: t,
		ExpiresMS: t + 90*24*time.Hour.Milliseconds(), Keys: halves(ks[2], "drill", "")}
	chSigner := ks[2]
	if *channelKey {
		k.Keys = append(k.Keys, halves(ks[3], "drill channel", release.UseChannel)...)
		chSigner = ks[3]
	}
	if *fault == "status-brace" {
		// A status key whose name holds a brace signs the release.
		k.Keys = append(k.Keys, halves(ks[3], "a}b", release.UseStatus)...)
		chSigner = ks[3]
		data, _ := json.Marshal(r)
		if rel, err = signRaw(data, ks[3]); err != nil {
			return err
		}
	}
	switch *fault {
	case "same-name":
		// Another key's halves under the release key's name, and
		// release.json signed by one half of each.
		k.Keys = append(k.Keys, halves(ks[3], "drill", "")...)
		other, err := release.Sign(r, ks[3])
		if err != nil {
			return err
		}
		rel.Sigs = []release.Sig{rel.Sigs[0], other.Sigs[1]}
	case "broken-pq":
		rel.Sigs[1].Sig = append([]byte{}, rel.Sigs[1].Sig...)
		rel.Sigs[1].Sig[100] ^= 1
	case "no-pq":
		rel.Sigs = rel.Sigs[:1]
	case "high-s":
		high, err := otherS(rel.Sigs[0].Sig)
		if err != nil {
			return err
		}
		rel.Sigs[0].Sig = high
	case "broken-twin":
		// A second ES256 signature by the same half, broken, after the good one.
		twin := rel.Sigs[0]
		twin.Sig = append([]byte{}, twin.Sig...)
		twin.Sig[len(twin.Sig)-1] ^= 1
		rel.Sigs = append(rel.Sigs, twin)
	case "alg-zero":
		rel.Sigs = append(rel.Sigs, release.Sig{Alg: 0, Key: []byte{9}, Sig: []byte{7}})
	}
	switch *fault {
	case "pin-alg-zero":
		// A forwarder's pin of no algorithm.
		k.Keys = append(k.Keys, release.Key{Alg: 0, Key: halves(ks[3], "pin", "")[0].Key, Name: "forwarder.example", Use: release.UseForwarder})
	case "pin-not-p256":
		// A forwarder's pin of algorithm 1 that is a P-384 key.
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}
		spki, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
		if err != nil {
			return err
		}
		k.Keys = append(k.Keys, release.Key{Alg: release.AlgES256, Key: spki, Name: "forwarder.example", Use: release.UseForwarder})
	}
	var keysFile release.File
	if *fault == "same-name" || slices.Contains(pinFaults, *fault) {
		data, _ := json.Marshal(k)
		keysFile, err = signRaw(data, ks[0])
	} else {
		keysFile, err = release.Sign(k, ks[0])
	}
	if err != nil {
		return err
	}
	if *fault != "" && !slices.Contains(relFaults, *fault) && !slices.Contains(pinFaults, *fault) {
		if keysFile, err = faultyKeys(keysFile.Body, *fault, ks[0]); err != nil {
			return err
		}
	}
	h := rel.Hash()
	c := release.Channel{V: 1, Type: release.TypeChannel, Channel: "stable", Seq: 1, TimeMS: t,
		ExpiresMS: t + 30*24*time.Hour.Milliseconds(), Release: r.Version, ReleaseSHA256: hex.EncodeToString(h[:])}
	var ch release.File
	if *fault == "path-version" {
		// stable.json names a release that is no version but a path.
		c.Release += "/../" + r.Version
		data, _ := json.Marshal(c)
		ch, err = signRaw(data, chSigner)
	} else {
		ch, err = release.Sign(c, chSigner)
	}
	if err != nil {
		return err
	}
	for name, f := range map[string]release.File{"release.json": rel, "keys.json": keysFile, "stable.json": ch} {
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(rootsPath, roots, 0o644)
}
