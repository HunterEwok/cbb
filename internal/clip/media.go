// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/core"
	"github.com/HunterEwok/cbb/internal/strict"

	"github.com/HunterEwok/cbb/internal/jsonnum"
)

// Images and files (design.md, "Images and files"; docs/protocol.md,
// section 4, "Media"). A media event carries a manifest instead of the
// bytes: each part's type or path, size and SHA-256. The manifest is small,
// so it travels in events and hellos like a text and the sync model applies
// unchanged; the members that want the content fetch it by its hashes.

const (
	// MaxMedia is the largest copy, all its parts together, that the group
	// carries; each device sets a lower limit of its own.
	MaxMedia = 1 << 30
	// MaxParts bounds the parts of a manifest: a copied folder keeps its
	// tree up to this many entries.
	MaxParts = 10000
	// MaxTypes bounds the parts of clipboard data, one per type.
	MaxTypes = 8
	// MaxPaths bounds the bytes of all the paths of a manifest, so that a
	// media event stays far below the frame limit.
	MaxPaths = 512 << 10
	// MaxPath and MaxName bound one path and each name in it.
	MaxPath = 4096
	MaxName = 255
	// MaxAltText is the largest plain-text alternative of a media event.
	MaxAltText = 256 << 10
)

// The types of clipboard data that media events carry.
const (
	TypePNG  = "image/png"
	TypeJPEG = "image/jpeg"
	TypeHTML = "text/html"
)

// Manifest says what a media event's content is.
type Manifest struct {
	Size  int64  `json:"size"` // all the parts together
	Parts []Part `json:"parts"`
}

// UnmarshalJSON reads a manifest and refuses one with a number that is not
// an integer written as in a signed body, such as "-0": Go takes it for 0,
// the lite member's reader for a float, so the members would not read one
// manifest alike.
func (m *Manifest) UnmarshalJSON(data []byte) error {
	if err := jsonnum.IntegersOnly(data); err != nil {
		return fmt.Errorf("clip: a manifest: %w", err)
	}
	type plain Manifest
	return json.Unmarshal(data, (*plain)(m))
}

// ParseManifest reads a manifest received from another member
// (docs/protocol.md, section 4, "Media"): in the strict form of signed
// bodies and in its canonical form, with no member its table does not
// name, and valid. A build that links the Rust core asks it first, so that
// every program takes the same manifests.
func ParseManifest(b []byte) (*Manifest, error) {
	if checked, err := core.CheckBody(core.KindManifest, b); checked && err != nil {
		return nil, fmt.Errorf("clip: a manifest: %w", err)
	}
	if err := strict.CheckCanonical(b, "parts", "size"); err != nil {
		return nil, fmt.Errorf("clip: a manifest is not in the strict form: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	// plain has no UnmarshalJSON, which would read without the decoder's
	// refusal of unknown members.
	type plain Manifest
	m := new(Manifest)
	if err := d.Decode((*plain)(m)); err != nil {
		return nil, fmt.Errorf("clip: a manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// Part is one item of a manifest: a piece of clipboard data of a Type, or a
// file or folder of a copy of files at its Path.
type Part struct {
	Type   string `json:"type,omitempty"`   // clipboard data: TypePNG, TypeJPEG or TypeHTML
	Path   string `json:"path,omitempty"`   // a file or folder: names joined by "/"
	Dir    bool   `json:"dir,omitempty"`    // with Path: a folder, without size or hash
	Size   int64  `json:"size,omitempty"`   // bytes
	SHA256 []byte `json:"sha256,omitempty"` // of the bytes, 32
}

// Files reports whether m is a copy of files, not clipboard data.
func (m *Manifest) Files() bool { return len(m.Parts) > 0 && m.Parts[0].Path != "" }

// Validate checks a manifest received from another member, or made here.
func (m *Manifest) Validate() error {
	if len(m.Parts) == 0 || len(m.Parts) > MaxParts {
		return fmt.Errorf("clip: a manifest has %d parts, not 1 to %d", len(m.Parts), MaxParts)
	}
	files := m.Files()
	if !files && len(m.Parts) > MaxTypes {
		return fmt.Errorf("clip: a manifest has more than %d types", MaxTypes)
	}
	var size int64
	paths := 0
	seen := make(map[string]bool, len(m.Parts))
	for _, p := range m.Parts {
		key := p.Type
		switch {
		case files && (p.Path == "" || p.Type != ""):
			return errors.New("clip: a manifest mixes files and clipboard data")
		case !files && (p.Type == "" || p.Dir):
			return errors.New("clip: a manifest mixes files and clipboard data")
		case files:
			if err := CheckPath(p.Path); err != nil {
				return err
			}
			paths += len(p.Path)
			// Paths compare as a receiver writes them: two that SavePath
			// makes one would land in one place.
			key = SavePath(p.Path)
		case p.Type != TypePNG && p.Type != TypeJPEG && p.Type != TypeHTML:
			return fmt.Errorf("clip: unknown media type %q", p.Type)
		}
		if seen[key] {
			return fmt.Errorf("clip: %q is twice in a manifest, as a receiver writes it", key)
		}
		seen[key] = true
		if p.Dir {
			if p.Size != 0 || p.SHA256 != nil {
				return errors.New("clip: a folder in a manifest has a size or a hash")
			}
			continue
		}
		if len(p.SHA256) != sha256.Size {
			return errors.New("clip: a part of a manifest has no valid SHA-256")
		}
		if p.Size < 0 || p.Size > MaxMedia {
			return fmt.Errorf("clip: a part of %d bytes", p.Size)
		}
		size += p.Size
	}
	switch {
	case paths > MaxPaths:
		return fmt.Errorf("clip: the paths of a manifest have more than %d bytes", MaxPaths)
	case size != m.Size:
		return fmt.Errorf("clip: a manifest says %d bytes, its parts %d", m.Size, size)
	case size > MaxMedia:
		return fmt.Errorf("clip: a copy of %d bytes is larger than %d", size, MaxMedia)
	}
	if files {
		return checkTree(m.Parts)
	}
	return nil
}

// checkTree checks that no file of a copy is also a folder, or inside a
// file, by the paths as a receiver writes them (SavePath).
func checkTree(parts []Part) error {
	kind := make(map[string]bool, len(parts)) // path: is a folder
	saved := make([]string, len(parts))
	for i, p := range parts {
		saved[i] = SavePath(p.Path)
		kind[saved[i]] = p.Dir
	}
	for _, path := range saved {
		for i := strings.IndexByte(path, '/'); i >= 0; i = nextSlash(path, i) {
			if dir, ok := kind[path[:i]]; ok && !dir {
				return fmt.Errorf("clip: %q is inside the file %q", path, path[:i])
			}
		}
	}
	return nil
}

func nextSlash(s string, i int) int {
	j := strings.IndexByte(s[i+1:], '/')
	if j < 0 {
		return -1
	}
	return i + 1 + j
}

// CheckPath checks a path of a manifest: names joined by "/", each a
// clean name (CheckName), at most MaxPath bytes as a receiver writes it
// (SavePath).
func CheckPath(path string) error {
	if path == "" || len(path) > MaxPath || len(SavePath(path)) > MaxPath {
		return fmt.Errorf("clip: a path of %d bytes as a receiver writes it", len(SavePath(path)))
	}
	for name := range strings.SplitSeq(path, "/") {
		if err := CheckName(name); err != nil {
			return fmt.Errorf("%w in %q", err, path)
		}
	}
	return nil
}

// CheckName checks one name of a path: valid UTF-8 of 1 to MaxName bytes,
// as the receiver writes it too (SaveName), not "." or "..", without control characters, path separators or the
// characters Windows does not allow, and not a name Windows reserves, so
// that a received copy lands where the receiver puts it on every system.
func CheckName(name string) error {
	switch {
	case name == "" || len(name) > MaxName || len(SaveName(name)) > MaxName:
		return fmt.Errorf("clip: a name of %d bytes as a receiver writes it", len(SaveName(name)))
	case name == "." || name == "..":
		return fmt.Errorf("clip: the name %q", name)
	case !utf8.ValidString(name):
		return errors.New("clip: a name is not valid UTF-8")
	case strings.ContainsAny(name, `/\:*?"<>|`):
		return fmt.Errorf("clip: the name %q has a character Windows does not allow", name)
	case strings.HasSuffix(name, ".") || strings.HasSuffix(name, " "):
		return fmt.Errorf("clip: the name %q ends in a dot or a space", name)
	case reserved(name):
		return fmt.Errorf("clip: %q is a name Windows reserves", name)
	}
	for _, r := range name {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return fmt.Errorf("clip: the name %q has a control character", name)
		}
	}
	return nil
}

// reserved reports whether name, before its first dot, is a device name of
// Windows that a manifest may not hold: CON, PRN, AUX, NUL, COM1 to COM9
// and LPT1 to LPT9, in any case of ASCII letters. Windows reserves more
// (device); those a receiver takes and renames, as members of earlier
// versions send them.
func reserved(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	switch base = upperASCII(base); base {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	return len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9'
}

// device reports whether name is a device name of Windows: before its
// first dot, and without the spaces that end that part, one of CON, PRN,
// AUX, NUL, CONIN$, CONOUT$, or COM or LPT followed by one digit 0 to 9 or
// one of the superscripts ¹, ² and ³, in any case of ASCII letters.
func device(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	switch base = upperASCII(strings.TrimRight(base, " ")); base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if !strings.HasPrefix(base, "COM") && !strings.HasPrefix(base, "LPT") {
		return false
	}
	switch base[3:] {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
		return true
	}
	return false
}

// upperASCII returns s with its ASCII letters in upper case and every
// other character as it is, as every implementation compares the names.
func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// SaveName is the name under which a receiver writes a name that
// CheckName took: a device name of Windows (device) gets "_" after its
// base, as CleanName gives it, and any other name stays as it is.
func SaveName(name string) string {
	if !device(name) {
		return name
	}
	return withUnderscore(name)
}

// SavePath is SaveName for each name of a path.
func SavePath(path string) string {
	names := strings.Split(path, "/")
	for i, n := range names {
		names[i] = SaveName(n)
	}
	return strings.Join(names, "/")
}

// CleanName makes a name that CheckName takes out of one a system gave,
// such as a file's: the characters it does not allow become "_", a
// device name of Windows (device) gets "_" after its base and one that ends in a dot or a
// space gets "_" after it.
func CleanName(name string) string {
	name = strings.ToValidUTF8(name, "_")
	var b strings.Builder
	for _, r := range name {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) || strings.ContainsRune(`/\:*?"<>|`, r) {
			r = '_'
		}
		b.WriteRune(r)
	}
	// What the fixes below add can take the name past MaxName, so the
	// name loses characters at its end until the fixed name fits.
	for name = b.String(); ; {
		if name == "" || name == "." || name == ".." {
			return "_"
		}
		if fixed := fixName(name); len(fixed) <= MaxName {
			return fixed
		}
		_, n := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-n]
	}
}

// fixName gives a device name of Windows "_" after its base and one that
// ends in a dot or a space "_" after it.
func fixName(name string) string {
	if device(name) {
		name = withUnderscore(name)
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		name += "_"
	}
	return name
}

// key identifies a manifest's content for the engine's echo checks: the
// parts' types or paths and hashes, so that the same content copied again
// is the same.
func (m *Manifest) key() string {
	var b strings.Builder
	b.WriteString("media\x00")
	for _, p := range m.Parts {
		b.WriteString(p.Type)
		b.WriteString(p.Path)
		b.WriteByte(0)
		b.Write(p.SHA256)
	}
	return b.String()
}

// withUnderscore puts "_" after a name's base, the part before its first
// dot: CON.txt becomes CON_.txt, as Windows reserves the base with any
// extension.
func withUnderscore(name string) string {
	base, ext, dot := strings.Cut(name, ".")
	name = base + "_"
	if dot {
		name += "." + ext
	}
	return name
}
