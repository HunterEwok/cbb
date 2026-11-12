// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package release reads and checks the signed files that describe a
// release (docs/protocol.md, section 16): keys.json, in which a root key
// certifies the release keys; release.json, which lists a release's files
// with their hashes; and a channel file such as stable.json, which names
// the current release of its channel until it expires. The same keys.json
// certifies the status key that signs attest-status.json, the mirror of
// Google's revocation list for Android attestations (section 17).
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/strict"
)

// The body types.
const (
	TypeKeys    = "keys"
	TypeRelease = "release"
	TypeChannel = "channel"
	TypeStatus  = "attest-status"
	TypeEntries = "entries"
)

// The uses keys.json gives its keys. A key of a use the reader does not
// know signs nothing for it. A channel key signs only channel files, so
// that a server renews them without the release key.
const (
	UseRelease = "release"
	UseStatus  = "status"
	UseChannel = "channel"
	// UseForwarder is the key of a forwarder the project runs, named by
	// its address: no signer, but the pin hubs accept from it.
	UseForwarder = "forwarder"
	// UseRelay is the key of a blind relay the project runs, named by its
	// address: no signer, but the pin its members accept from it.
	UseRelay = "relay"
)

const (
	formatVersion = 1
	// MaxBody is the largest body a file may carry.
	MaxBody = 256 << 10
	// MaxFile is the largest a release file may be whole, its body and
	// signatures in base64: room for several post-quantum signatures beside
	// the largest body.
	MaxFile = 1 << 20
	// MaxLifetime is the longest a keys or channel file may stay valid
	// after it was signed.
	MaxLifetime = 100 * 24 * time.Hour
	// MaxStatusLifetime is the longest attest-status.json stays valid: it
	// is signed every day, and lives a week past a day without one.
	MaxStatusLifetime = 8 * 24 * time.Hour
	maxKeys           = 64
	maxFiles          = 256
	maxBinaries       = 64
	maxName           = 64
)

// File is the envelope every release file has: the body's exact bytes and
// its signatures, one for each algorithm of Required by the halves of one
// key, and any of algorithms a later version adds (docs/protocol.md,
// section 16, "Two signatures").
type File struct {
	Body []byte `json:"body"`
	Sigs []Sig  `json:"sigs"`
}

// Hash returns SHA-256 over the body, which names a release.json.
func (f File) Hash() [sha256.Size]byte { return sha256.Sum256(f.Body) }

// Key is one half of a key that keys.json certifies, for its Use:
// UseRelease when empty. The halves of one key share its name and use,
// one for each algorithm; a pinned root is a Key too, of use "root".
type Key struct {
	Alg  int    `json:"alg"`
	Key  []byte `json:"key"` // SubjectPublicKeyInfo, DER
	Name string `json:"name"`
	Use  string `json:"use,omitempty"`
}

// Keys is the body of keys.json, signed by a root key.
type Keys struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	Seq       uint64 `json:"seq"`
	TimeMS    int64  `json:"time_ms"`
	ExpiresMS int64  `json:"expires_ms"`
	Keys      []Key  `json:"keys"`
}

// Binary is a program inside an archive.
type Binary struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Asset is one file of a release.
type Asset struct {
	Name     string   `json:"name"`
	Size     int64    `json:"size"`
	SHA256   string   `json:"sha256"`
	Binaries []Binary `json:"binaries,omitempty"`
}

// Docker names the release's container image.
type Docker struct {
	Image  string `json:"image"`
	Digest string `json:"digest"`
}

// Release is the body of release.json, signed by a release key.
type Release struct {
	V       int     `json:"v"`
	Type    string  `json:"type"`
	Version string  `json:"version"`
	Channel string  `json:"channel"`
	TimeMS  int64   `json:"time_ms"`
	MinFrom string  `json:"min_from,omitempty"`
	Files   []Asset `json:"files"`
	Docker  *Docker `json:"docker,omitempty"`
}

// Channel is the body of a channel file such as stable.json, signed by a
// release key.
type Channel struct {
	V             int    `json:"v"`
	Type          string `json:"type"`
	Channel       string `json:"channel"`
	Seq           uint64 `json:"seq"`
	TimeMS        int64  `json:"time_ms"`
	ExpiresMS     int64  `json:"expires_ms"`
	Release       string `json:"release"`
	ReleaseSHA256 string `json:"release_sha256"`
}

// Status is the body of attest-status.json, signed by a status key: the
// serial numbers Google's list revokes, as attest.Policy takes them.
type Status struct {
	V         int    `json:"v"`
	Type      string `json:"type"`
	Seq       uint64 `json:"seq"`
	TimeMS    int64  `json:"time_ms"`
	ExpiresMS int64  `json:"expires_ms"`
	// SourceMS is when Google last changed its list (Last-Modified), 0
	// when it did not say.
	SourceMS       int64    `json:"source_ms,omitempty"`
	AndroidRevoked []string `json:"android_revoked"`
}

// Entries is the body of entries.json, signed by a release or channel key:
// where the project's forwarders and relays are entered, so that a blocked
// or moved entry is replaced without a release (docs/protocol.md, section
// 16, "Entry points"). The keys of the forwarders and relays stay in
// keys.json.
type Entries struct {
	V          int              `json:"v"`
	Type       string           `json:"type"`
	Seq        uint64           `json:"seq"`
	TimeMS     int64            `json:"time_ms"`
	ExpiresMS  int64            `json:"expires_ms"`
	Forwarders []EntryForwarder `json:"forwarders"`
	Relays     []EntryRelay     `json:"relays,omitempty"`
}

// EntryRelay is one of the project's blind relays.
type EntryRelay struct {
	// Name is its address as keys.json names its key and as devices were
	// set to it, host:port, such as cbb.tools:8765.
	Name string `json:"name"`
	// Endpoints are where it is reached now, host:port, the one to try
	// first first; none for Name itself.
	Endpoints []string `json:"endpoints,omitempty"`
}

// EntryForwarder is one of the project's forwarders.
type EntryForwarder struct {
	// Name is its address as keys.json names its key, host:port, such as
	// cbb.tools:8764.
	Name string `json:"name"`
	// VLESS are the ways in over VLESS for a hub's first registration, the
	// one to try first first.
	VLESS []EntryVLESS `json:"vless,omitempty"`
}

// EntryVLESS is a way in over VLESS: XHTTP behind the web server of a site.
type EntryVLESS struct {
	Transport  string `json:"transport"`   // "xhttp"
	ServerName string `json:"server_name"` // the site's name, which its certificate carries
	Port       uint16 `json:"port"`        // the web server's TCP port
	Path       string `json:"path"`        // the path the registrations are taken on
}

// Forwarder returns the entry of the forwarder named name.
func (e Entries) Forwarder(name string) (EntryForwarder, bool) {
	for _, f := range e.Forwarders {
		if f.Name == name {
			return f, true
		}
	}
	return EntryForwarder{}, false
}

// Relay returns the entry of the relay named name.
func (e Entries) Relay(name string) (EntryRelay, bool) {
	for _, r := range e.Relays {
		if r.Name == name {
			return r, true
		}
	}
	return EntryRelay{}, false
}

// Revoked returns the serial numbers as a set.
func (s Status) Revoked() map[string]bool {
	m := make(map[string]bool, len(s.AndroidRevoked))
	for _, r := range s.AndroidRevoked {
		m[r] = true
	}
	return m
}

// Seen is what a device keeps between checks so that nobody can take it
// back: the highest sequence numbers and the highest version it has taken.
// A channel or status seq holds only under the keys.json that certified
// the key that signed it (ChannelKeys, StatusKeys; KeysSeq when 0, as
// kept before): a newer keys.json, which only a root signs, starts them
// again, so a lost channel or status key cannot hold a device at a seq no
// later file reaches.
type Seen struct {
	KeysSeq     uint64 `json:"keys_seq"`
	ChannelSeq  uint64 `json:"channel_seq"`
	Version     string `json:"version,omitempty"`
	StatusSeq   uint64 `json:"status_seq,omitempty"`
	ChannelKeys uint64 `json:"channel_keys_seq,omitempty"`
	StatusKeys  uint64 `json:"status_keys_seq,omitempty"`
	// EntriesSeq and EntriesKeys are entries.json's, which CheckEntries
	// alone sets: a device keeps them in a Seen of their own.
	EntriesSeq  uint64 `json:"entries_seq,omitempty"`
	EntriesKeys uint64 `json:"entries_keys_seq,omitempty"`
}

// MaxSeqStep is the most a channel or status seq may rise past the one a
// device holds under the same keys.json: far more than the files signed in
// a keys.json's lifetime, far less than the range of seq.
const MaxSeqStep = 1 << 16

// MaxAhead is how far ahead of a device's clock a file may have been
// signed, when that clock reads 2026 or later.
const MaxAhead = 24 * time.Hour

// plausible is a wall time before which a device's clock is not trusted
// to refuse files signed ahead of it (2026-01-01).
const plausible = 1767225600000

// floor returns the seq a file signed under keys.json keysSeq may not go
// below: seq, set under the keys.json at (seen's KeysSeq when 0), or none
// under a newer keys.json.
func floor(seq, at, seenKeys, keysSeq uint64) uint64 {
	if at == 0 {
		at = seenKeys
	}
	if keysSeq > at {
		return 0
	}
	return seq
}

// checkSeq refuses a seq below the floor, or one that rises more than
// MaxSeqStep past it; with no floor, past MaxSeqStep, so that one file
// cannot take a fresh device to a seq no later file reaches.
func checkSeq(seq, floor uint64) error {
	switch {
	case seq < floor:
		return ErrRollback
	case seq-floor > MaxSeqStep:
		return ErrJump
	}
	return nil
}

// signedAhead reports whether a file stamped timeMS was signed more than
// MaxAhead ahead of now.
func signedAhead(timeMS int64, now time.Time) bool {
	ms := now.UnixMilli()
	return ms >= plausible && timeMS > ms+MaxAhead.Milliseconds()
}

var (
	// ErrSignature is returned for a file whose signature does not verify
	// or whose signer is not trusted for it.
	ErrSignature = errors.New("release: the signature is not valid")
	// ErrExpired is returned for a keys or channel file past its expiry.
	ErrExpired = errors.New("release: the file has expired")
	// ErrRollback is returned for a file older than one already taken.
	ErrRollback = errors.New("release: the file is older than one already seen")
	// ErrJump is returned for a file whose seq rises more than MaxSeqStep
	// past the one taken, or that was signed more than MaxAhead ahead of
	// the device's clock.
	ErrJump = errors.New("release: the file is too far ahead of the one already seen")
)

// Sign signs body with each half of key. The body's type and version are
// set by the caller; Sign only checks that the body has a known form.
func Sign(body any, key Signer) (File, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return File{}, err
	}
	if err := checkBody(data); err != nil {
		return File{}, err
	}
	return signData(data, key)
}

// CheckBody reports whether data is a body of a known type and form, as
// Sign checks it before signing.
func CheckBody(data []byte) error { return checkBody(data) }

func checkBody(data []byte) error {
	if len(data) > MaxBody {
		return errors.New("release: the body is too large")
	}
	var b struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	var err error
	switch b.Type {
	case TypeKeys:
		_, err = decodeKeys(data)
	case TypeRelease:
		_, err = decodeRelease(data)
	case TypeChannel:
		_, err = decodeChannel(data)
	case TypeStatus:
		_, err = decodeStatus(data)
	case TypeEntries:
		_, err = decodeEntries(data)
	case TypeZXNext:
		_, err = decodeZXNext(data)
	default:
		err = fmt.Errorf("release: unknown type %q", b.Type)
	}
	return err
}

var (
	assetName  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	channelRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	hexSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE  = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(-rc\.([1-9][0-9]{0,5}))?$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	binaryName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,255}$`)
	serialRE   = regexp.MustCompile(`^(0|[1-9a-f][0-9a-f]{0,63})$`)
)

// decode reads data as a body of type typ into v; the body must have v,
// type and each field of required.
func decode(data []byte, typ string, v any, required ...string) error {
	// The strict form of signed bodies first, so that every program reads a
	// file alike (docs/protocol.md, section 16).
	if err := strict.Check(data, append([]string{"v", "type"}, required...)...); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	var b struct {
		V    int    `json:"v"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	if b.Type != typ {
		return fmt.Errorf("release: the file is a %q, not a %q", b.Type, typ)
	}
	if b.V != formatVersion {
		return fmt.Errorf("release: unknown version %d", b.V)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	return nil
}

func lifetime(timeMS, expiresMS int64) error {
	return lifetimeUpTo(timeMS, expiresMS, MaxLifetime)
}

func lifetimeUpTo(timeMS, expiresMS int64, max time.Duration) error {
	// A time before 1970 is no signing time; from it the difference below
	// cannot leave the range of int64.
	if timeMS < 0 || expiresMS <= timeMS || expiresMS-timeMS > max.Milliseconds() {
		return errors.New("release: the file's lifetime is out of range")
	}
	return nil
}

func decodeKeys(data []byte) (Keys, error) {
	var k Keys
	if err := decode(data, TypeKeys, &k, "seq", "time_ms", "expires_ms", "keys"); err != nil {
		return k, err
	}
	if k.Seq == 0 {
		return k, errors.New("release: keys.json has no sequence number")
	}
	if err := lifetime(k.TimeMS, k.ExpiresMS); err != nil {
		return k, err
	}
	if len(k.Keys) == 0 || len(k.Keys) > maxKeys {
		return k, errors.New("release: keys.json must hold 1 to 64 keys")
	}
	// The keys are the only plain bytes of a body: in base64's one form. A
	// release key's use is left out, never written empty; each key names
	// its algorithm.
	var raw struct {
		Keys []struct {
			Alg *int    `json:"alg"`
			Key string  `json:"key"`
			Use *string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return k, fmt.Errorf("release: %w", err)
	}
	for _, key := range raw.Keys {
		if key.Alg == nil {
			return k, errors.New("release: a key names no algorithm")
		}
		if _, err := strict.DecodeBase64(key.Key); err != nil {
			return k, fmt.Errorf("release: a key: %w", err)
		}
		if key.Use != nil && *key.Use == "" {
			return k, errors.New("release: a key's use is empty")
		}
	}
	for _, key := range k.Keys {
		if key.Name == "" || len(key.Name) > maxName {
			return k, errors.New("release: a key has no valid name")
		}
		if key.Alg < 1 {
			return k, errors.New("release: a key names no algorithm")
		}
		if err := checkPublic(key.Alg, key.Key); err != nil {
			return k, err
		}
	}
	return k, nil
}

func decodeRelease(data []byte) (Release, error) {
	var r Release
	if err := decode(data, TypeRelease, &r, "version", "channel", "time_ms", "files"); err != nil {
		return r, err
	}
	if !versionRE.MatchString(r.Version) {
		return r, fmt.Errorf("release: %q is not a version", r.Version)
	}
	if r.MinFrom != "" && !versionRE.MatchString(r.MinFrom) {
		return r, fmt.Errorf("release: %q is not a version", r.MinFrom)
	}
	if !channelRE.MatchString(r.Channel) {
		return r, fmt.Errorf("release: %q is not a channel", r.Channel)
	}
	if len(r.Files) == 0 || len(r.Files) > maxFiles {
		return r, errors.New("release: release.json must list 1 to 256 files")
	}
	// Each file has its size, which an absent field would read as 0.
	var raw struct {
		Files []struct {
			Size *int64 `json:"size"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return r, fmt.Errorf("release: %w", err)
	}
	for _, a := range raw.Files {
		if a.Size == nil {
			return r, errors.New("release: a file has no size")
		}
	}
	names := map[string]bool{}
	for _, a := range r.Files {
		if !assetName.MatchString(a.Name) || names[a.Name] {
			return r, fmt.Errorf("release: %q is not a valid file name", a.Name)
		}
		names[a.Name] = true
		if a.Size < 0 || !hexSHA256.MatchString(a.SHA256) || len(a.Binaries) > maxBinaries {
			return r, fmt.Errorf("release: the entry for %s is not valid", a.Name)
		}
		for _, b := range a.Binaries {
			if !binaryName.MatchString(b.Name) || strings.Contains(b.Name, "..") || !hexSHA256.MatchString(b.SHA256) {
				return r, fmt.Errorf("release: a binary in %s is not valid", a.Name)
			}
		}
	}
	if r.Docker != nil && (r.Docker.Image == "" || !digestRE.MatchString(r.Docker.Digest)) {
		return r, errors.New("release: the Docker image is not valid")
	}
	return r, nil
}

func decodeChannel(data []byte) (Channel, error) {
	var c Channel
	if err := decode(data, TypeChannel, &c, "channel", "seq", "time_ms", "expires_ms", "release", "release_sha256"); err != nil {
		return c, err
	}
	if !channelRE.MatchString(c.Channel) {
		return c, fmt.Errorf("release: %q is not a channel", c.Channel)
	}
	if c.Seq == 0 {
		return c, errors.New("release: the channel file has no sequence number")
	}
	if err := lifetime(c.TimeMS, c.ExpiresMS); err != nil {
		return c, err
	}
	if !versionRE.MatchString(c.Release) || !hexSHA256.MatchString(c.ReleaseSHA256) {
		return c, errors.New("release: the channel file names no valid release")
	}
	return c, nil
}

func decodeStatus(data []byte) (Status, error) {
	var s Status
	if err := decode(data, TypeStatus, &s, "seq", "time_ms", "expires_ms", "android_revoked"); err != nil {
		return s, err
	}
	if s.Seq == 0 {
		return s, errors.New("release: attest-status.json has no sequence number")
	}
	if err := lifetimeUpTo(s.TimeMS, s.ExpiresMS, MaxStatusLifetime); err != nil {
		return s, err
	}
	if s.AndroidRevoked == nil {
		return s, errors.New("release: attest-status.json has no list")
	}
	for i, r := range s.AndroidRevoked {
		if !serialRE.MatchString(r) || i > 0 && !serialLess(s.AndroidRevoked[i-1], r) {
			return s, fmt.Errorf("release: %q is not a serial number in order", r)
		}
	}
	return s, nil
}

// The bounds of entries.json.
const (
	maxEntryForwarders = 16
	maxEntryVLESS      = 8
	maxEntryRelays     = 16
	maxEntryEndpoints  = 8
)

var (
	entryNameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}:[1-9][0-9]{0,4}$`)
	entrySiteRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	entryPathRE = regexp.MustCompile(`^/[A-Za-z0-9_-]{8,64}$`)
)

func decodeEntries(data []byte) (Entries, error) {
	var e Entries
	if err := decode(data, TypeEntries, &e, "seq", "time_ms", "expires_ms", "forwarders"); err != nil {
		return e, err
	}
	if e.Seq == 0 {
		return e, errors.New("release: entries.json has no sequence number")
	}
	if err := lifetime(e.TimeMS, e.ExpiresMS); err != nil {
		return e, err
	}
	if e.Forwarders == nil || len(e.Forwarders) > maxEntryForwarders {
		return e, errors.New("release: entries.json has no list of forwarders, or too long a one")
	}
	names := map[string]bool{}
	for _, f := range e.Forwarders {
		if !entryNameRE.MatchString(f.Name) || names[f.Name] {
			return e, fmt.Errorf("release: %q is not a forwarder's name, or twice", f.Name)
		}
		names[f.Name] = true
		if len(f.VLESS) > maxEntryVLESS {
			return e, fmt.Errorf("release: %s has too many ways in", f.Name)
		}
		for _, v := range f.VLESS {
			if v.Transport != "xhttp" || !entrySiteRE.MatchString(v.ServerName) || v.Port == 0 || !entryPathRE.MatchString(v.Path) {
				return e, fmt.Errorf("release: a way in to %s is not usable", f.Name)
			}
		}
	}
	if len(e.Relays) > maxEntryRelays {
		return e, errors.New("release: entries.json has too long a list of relays")
	}
	names = map[string]bool{}
	for _, r := range e.Relays {
		if !entryNameRE.MatchString(r.Name) || names[r.Name] {
			return e, fmt.Errorf("release: %q is not a relay's name, or twice", r.Name)
		}
		names[r.Name] = true
		if len(r.Endpoints) > maxEntryEndpoints {
			return e, fmt.Errorf("release: %s has too many addresses", r.Name)
		}
		for _, ep := range r.Endpoints {
			if !entryNameRE.MatchString(ep) {
				return e, fmt.Errorf("release: %q is not an address of %s", ep, r.Name)
			}
		}
	}
	return e, nil
}

// CheckEntries verifies entries.json: keys.json under the roots, entries
// under its release or channel keys, its expiry, and that neither is older
// than seen, which keeps the entries' own floors. It returns the entries
// and the new Seen to keep.
func CheckEntries(keys, entries File, roots []Key, now time.Time, seen Seen) (Entries, Seen, error) {
	k, err := VerifyKeys(keys, roots, now, seen)
	if err != nil {
		return Entries{}, seen, fmt.Errorf("keys.json: %w", err)
	}
	if err := entries.verify(append(k.of(UseRelease), k.of(UseChannel)...)); err != nil {
		return Entries{}, seen, fmt.Errorf("entries.json: %w", err)
	}
	e, err := decodeEntries(entries.Body)
	if err != nil {
		return Entries{}, seen, fmt.Errorf("entries.json: %w", err)
	}
	if now.UnixMilli() >= e.ExpiresMS {
		return Entries{}, seen, fmt.Errorf("entries.json: %w", ErrExpired)
	}
	if signedAhead(e.TimeMS, now) {
		return Entries{}, seen, fmt.Errorf("entries.json: %w", ErrJump)
	}
	if err := checkSeq(e.Seq, floor(seen.EntriesSeq, seen.EntriesKeys, seen.KeysSeq, k.Seq)); err != nil {
		return Entries{}, seen, fmt.Errorf("entries.json: %w", err)
	}
	next := seen
	next.KeysSeq, next.EntriesSeq, next.EntriesKeys = k.Seq, e.Seq, k.Seq
	return e, next, nil
}

// serialLess orders serial numbers as numbers: the shorter first, then
// as strings, which for lowercase hex without leading zeros is the same.
func serialLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// SortSerials puts serial numbers in the order attest-status.json keeps.
func SortSerials(s []string) {
	sort.Slice(s, func(i, j int) bool { return serialLess(s[i], s[j]) })
}

// VerifyKeys checks keys.json against the pinned root keys (the halves of
// each root, of one name) at now, and that it is not older than seen.
func VerifyKeys(f File, roots []Key, now time.Time, seen Seen) (Keys, error) {
	if err := f.verify(roots); err != nil {
		return Keys{}, err
	}
	k, err := decodeKeys(f.Body)
	if err != nil {
		return Keys{}, err
	}
	if now.UnixMilli() >= k.ExpiresMS {
		return Keys{}, ErrExpired
	}
	if signedAhead(k.TimeMS, now) {
		return Keys{}, ErrJump
	}
	if k.Seq < seen.KeysSeq {
		return Keys{}, ErrRollback
	}
	return k, nil
}

// of returns the halves of the keys certified for use.
func (k Keys) of(use string) []Key {
	var out []Key
	for _, key := range k.Keys {
		u := key.Use
		if u == "" {
			u = UseRelease
		}
		if u == use {
			key.Use = u
			out = append(out, key)
		}
	}
	return out
}

// Forwarders returns the keys certified as the forwarder at name: the
// SubjectPublicKeyInfos of its P-256 keys, which its TLS shows.
func (k Keys) Forwarders(name string) [][]byte { return k.named(UseForwarder, name) }

// Relays returns the keys certified as the relay at name.
func (k Keys) Relays(name string) [][]byte { return k.named(UseRelay, name) }

func (k Keys) named(use, name string) [][]byte {
	var out [][]byte
	for _, key := range k.Keys {
		if key.Use == use && key.Name == name && key.Alg == AlgES256 {
			out = append(out, key.Key)
		}
	}
	return out
}

// CheckStatus verifies attest-status.json: keys.json under the roots, the
// status file under a status key of it, its expiry, and that neither is
// older than seen. It returns the list and the new Seen to keep.
func CheckStatus(keys, status File, roots []Key, now time.Time, seen Seen) (Status, Seen, error) {
	k, err := VerifyKeys(keys, roots, now, seen)
	if err != nil {
		return Status{}, seen, fmt.Errorf("keys.json: %w", err)
	}
	if err := status.verify(k.of(UseStatus)); err != nil {
		return Status{}, seen, fmt.Errorf("attest-status.json: %w", err)
	}
	s, err := decodeStatus(status.Body)
	if err != nil {
		return Status{}, seen, fmt.Errorf("attest-status.json: %w", err)
	}
	if now.UnixMilli() >= s.ExpiresMS {
		return Status{}, seen, fmt.Errorf("attest-status.json: %w", ErrExpired)
	}
	if signedAhead(s.TimeMS, now) {
		return Status{}, seen, fmt.Errorf("attest-status.json: %w", ErrJump)
	}
	if err := checkSeq(s.Seq, floor(seen.StatusSeq, seen.StatusKeys, seen.KeysSeq, k.Seq)); err != nil {
		return Status{}, seen, fmt.Errorf("attest-status.json: %w", err)
	}
	next := seen
	next.KeysSeq, next.StatusSeq, next.StatusKeys = k.Seq, s.Seq, k.Seq
	if next.ChannelKeys == 0 {
		next.ChannelKeys = seen.KeysSeq
	}
	return s, next, nil
}

// Check verifies a channel file and the release.json it names: keys.json
// under the roots, the channel file under its release or channel keys and
// release.json under its release keys, the channel's name, both expiries, and that nothing is older than
// seen. It returns the release and the new Seen to keep.
func Check(keys, channel, rel File, roots []Key, name string, now time.Time, seen Seen) (Release, Seen, error) {
	k, err := VerifyKeys(keys, roots, now, seen)
	if err != nil {
		return Release{}, seen, fmt.Errorf("keys.json: %w", err)
	}
	if err := channel.verify(append(k.of(UseRelease), k.of(UseChannel)...)); err != nil {
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, err)
	}
	c, err := decodeChannel(channel.Body)
	if err != nil {
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, err)
	}
	switch {
	case c.Channel != name:
		return Release{}, seen, fmt.Errorf("%s.json: release: the file is for the channel %q", name, c.Channel)
	case now.UnixMilli() >= c.ExpiresMS:
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, ErrExpired)
	case signedAhead(c.TimeMS, now):
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, ErrJump)
	}
	if err := checkSeq(c.Seq, floor(seen.ChannelSeq, seen.ChannelKeys, seen.KeysSeq, k.Seq)); err != nil {
		return Release{}, seen, fmt.Errorf("%s.json: %w", name, err)
	}
	if err := rel.verify(k.of(UseRelease)); err != nil {
		return Release{}, seen, fmt.Errorf("release.json: %w", err)
	}
	if h := rel.Hash(); hex.EncodeToString(h[:]) != c.ReleaseSHA256 {
		return Release{}, seen, fmt.Errorf("release.json: release: it is not the release %s.json names", name)
	}
	r, err := decodeRelease(rel.Body)
	if err != nil {
		return Release{}, seen, fmt.Errorf("release.json: %w", err)
	}
	if r.Version != c.Release || r.Channel != c.Channel {
		return Release{}, seen, fmt.Errorf("release.json: release: it is %s on %s, %s.json names %s", r.Version, r.Channel, name, c.Release)
	}
	if seen.Version != "" && Compare(r.Version, seen.Version) < 0 {
		return Release{}, seen, fmt.Errorf("release.json: %w", ErrRollback)
	}
	next := Seen{KeysSeq: k.Seq, ChannelSeq: c.Seq, Version: r.Version, StatusSeq: seen.StatusSeq, ChannelKeys: k.Seq, StatusKeys: seen.StatusKeys}
	if next.StatusKeys == 0 {
		next.StatusKeys = seen.KeysSeq
	}
	if seen.Version != "" && Compare(seen.Version, r.Version) > 0 {
		next.Version = seen.Version
	}
	return r, next, nil
}

// CheckPinned verifies the release.json of a version asked for by name, as
// an update to the lowest version another release may come from: keys.json
// under the roots and release.json under its release keys, without a
// channel file, and that the version is not below the highest one seen.
func CheckPinned(keys, rel File, roots []Key, now time.Time, seen Seen) (Release, Seen, error) {
	k, err := VerifyKeys(keys, roots, now, seen)
	if err != nil {
		return Release{}, seen, fmt.Errorf("keys.json: %w", err)
	}
	if err := rel.verify(k.of(UseRelease)); err != nil {
		return Release{}, seen, fmt.Errorf("release.json: %w", err)
	}
	r, err := decodeRelease(rel.Body)
	if err != nil {
		return Release{}, seen, fmt.Errorf("release.json: %w", err)
	}
	if seen.Version != "" && Compare(r.Version, seen.Version) < 0 {
		return Release{}, seen, fmt.Errorf("release.json: %w", ErrRollback)
	}
	next := seen
	next.KeysSeq = k.Seq
	if seen.Version == "" || Compare(r.Version, seen.Version) > 0 {
		next.Version = r.Version
	}
	return r, next, nil
}

// Compare compares two versions of the form X.Y.Z or X.Y.Z-rc.N, as -1,
// 0 or 1; a release candidate comes before its release. A string that is
// not a version sorts below every version.
func Compare(a, b string) int {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	switch {
	case !oka || !okb:
		switch {
		case oka:
			return 1
		case okb:
			return -1
		}
		return 0
	}
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// IsVersion reports whether s is a version of the form X.Y.Z or
// X.Y.Z-rc.N, the only names a release has.
func IsVersion(s string) bool {
	_, ok := parseVersion(s)
	return ok
}

// parseVersion returns X, Y, Z and the release candidate's number, or
// finalRelease for a release.
func parseVersion(s string) ([4]int, bool) {
	var out [4]int
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return out, false
	}
	for i, p := range []string{m[1], m[2], m[3]} {
		out[i], _ = strconv.Atoi(p)
	}
	out[3] = finalRelease
	if m[5] != "" {
		out[3], _ = strconv.Atoi(m[5])
	}
	return out, true
}

const finalRelease = 1 << 30

// Direct reports whether a device at installed may update to r in one
// step, or must first take r.MinFrom.
func (r Release) Direct(installed string) bool {
	return r.MinFrom == "" || Compare(installed, r.MinFrom) >= 0
}

// Asset returns the release's entry for the file name.
func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Files {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

// CheckFile reports whether data is the release's file name.
func (r Release) CheckFile(name string, data []byte) error {
	a, ok := r.Asset(name)
	if !ok {
		return fmt.Errorf("release: %s is not in the release", name)
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != a.Size || hex.EncodeToString(sum[:]) != a.SHA256 {
		return fmt.Errorf("release: %s does not match release.json", name)
	}
	return nil
}
