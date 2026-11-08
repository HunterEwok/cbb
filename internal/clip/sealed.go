// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/HunterEwok/cbb/internal/core"
	"github.com/HunterEwok/cbb/internal/hlc"
	"github.com/HunterEwok/cbb/internal/seal"
	"github.com/HunterEwok/cbb/internal/strict"
)

// A copy sealed end to end (docs/protocol.md, section 4, "Event"): the
// device that copies seals it to the devices of the group that read
// copies and signs it, so the members that pass it on, a hub among them,
// neither read nor change it. The same is in the Rust core
// (cbb_core::copy); both are checked on testdata/interop/copies-go.json
// and copies-rust.json.

const (
	// KeySize is the size of a copy's key.
	KeySize = 32
	// WrapSize is the size of a wrap's key: the encapsulated key, the
	// copy's key and its tag.
	WrapSize = seal.EncSize + KeySize + tagSize
	// MaxReaders is the most readers a copy is sealed to.
	MaxReaders = 256
	// Segment is a blob's segment before sealing; SealedSegment after.
	Segment       = 64 << 10
	SealedSegment = Segment + tagSize
	// MaxSegments is the most segments a blob has: 1 GiB of parts.
	MaxSegments = (MaxMedia + Segment - 1) / Segment

	tagSize = 16
)

// steps are the sizes a Content is padded to.
var steps = []int{1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 2 << 20, 3 << 20, 4 << 20}

var (
	headerContext = []byte("cbb copy v1")
	signContext   = []byte("cbb copy sig v1")
	payloadInfo   = "cbb copy payload v1"
	blobInfo      = "cbb copy blob v1"
	blobAAD       = []byte("cbb blob")
)

// ErrNotReader is returned by Open for a copy that has no wrap for the
// device: it passes the copy on but cannot read it.
var ErrNotReader = errors.New("clip: the copy is not sealed to this device")

// BlobSize is the size of a sealed blob of n bytes of parts.
func BlobSize(n int64) int64 {
	return (n + Segment - 1) / Segment * SealedSegment
}

// Wrap is a reader's sealed copy of the copy's key.
type Wrap struct {
	To  string `json:"to"`
	Key []byte `json:"key"`
}

// Blob names the sealed blob of a copy's images and files.
type Blob struct {
	Size   int64  `json:"size"`
	SHA256 []byte `json:"sha256"`
}

// Sealed is one copy as it travels between members: the event of the
// member protocol.
type Sealed struct {
	ID     string        `json:"id"`
	Origin string        `json:"origin"`
	Time   hlc.Timestamp `json:"time"`
	// Age is outside the signature: it grows on the way.
	Age    int64  `json:"age_ms"`
	Cert   []byte `json:"cert"`
	Issuer []byte `json:"issuer,omitempty"`
	Wraps  []Wrap `json:"wraps"`
	// Payload is the sealed Content; a mark has PayloadSHA256 instead.
	Payload       []byte `json:"payload,omitempty"`
	PayloadSHA256 []byte `json:"payload_sha256,omitempty"`
	Blob          *Blob  `json:"blob,omitempty"`
	Sig           []byte `json:"sig"`

	// The fields of a copy in the open, which no member takes.
	OpenKind  json.RawMessage `json:"kind,omitempty"`
	OpenText  json.RawMessage `json:"text,omitempty"`
	OpenVia   json.RawMessage `json:"via,omitempty"`
	OpenMedia json.RawMessage `json:"media,omitempty"`
}

// Content is what only a copy's readers see.
type Content struct {
	Kind  Kind
	Via   Via
	Text  string
	Media *Manifest // a media copy's, which only it has
}

// Reader is a device a copy is sealed to: its device ID and its public key
// for sealed messages.
type Reader struct {
	ID   string
	Seal []byte
}

func put(b *bytes.Buffer, p []byte) {
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
	b.Write(p)
}

func derive(key []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, key, nil, info, 32)
}

func aeadOf(key []byte, info string) (cipherAEAD, error) {
	k, err := derive(key, info)
	if err != nil {
		return nil, fmt.Errorf("clip: derive a copy's key: %w", err)
	}
	return chacha20poly1305.New(k)
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func segmentNonce(i uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], i)
	return n
}

func segmentAAD(last bool) []byte {
	a := append([]byte(nil), blobAAD...)
	if last {
		return append(a, 1)
	}
	return append(a, 0)
}

// SealSegment seals the segment i of a blob, at most Segment bytes, padded
// with zeros to Segment; last says whether it is the last.
func SealSegment(key []byte, i uint64, last bool, plain []byte) ([]byte, error) {
	if len(key) != KeySize || len(plain) > Segment || i >= MaxSegments {
		return nil, errors.New("clip: a blob's segment is too large or too far, or the key is not 32 bytes")
	}
	a, err := aeadOf(key, blobInfo)
	if err != nil {
		return nil, err
	}
	seg := make([]byte, Segment)
	copy(seg, plain)
	return a.Seal(nil, segmentNonce(i), seg, segmentAAD(last)), nil
}

// OpenSegment opens the segment i of a blob: SealedSegment bytes, the last
// one flagged as such.
func OpenSegment(key []byte, i uint64, last bool, sealed []byte) ([]byte, error) {
	if len(key) != KeySize || len(sealed) != SealedSegment {
		return nil, errors.New("clip: a blob's segment is not 65552 bytes, or the key is not 32 bytes")
	}
	a, err := aeadOf(key, blobInfo)
	if err != nil {
		return nil, err
	}
	p, err := a.Open(nil, segmentNonce(i), sealed, segmentAAD(last))
	if err != nil {
		return nil, errors.New("clip: a blob's segment does not open: it was changed or is from another copy")
	}
	return p, nil
}

// SealBlob seals the n bytes of parts that src gives, one after another,
// into a blob under the copy's key, which it writes to dst, and returns
// the blob's size and SHA-256 (docs/protocol.md, section 4, "The blob").
func SealBlob(key []byte, src io.Reader, n int64, dst io.Writer) (*Blob, error) {
	if n <= 0 || n > MaxMedia {
		return nil, fmt.Errorf("clip: a blob of %d bytes", n)
	}
	h := sha256.New()
	w := io.MultiWriter(dst, h)
	buf := make([]byte, Segment)
	segs := uint64((n + Segment - 1) / Segment)
	for i := range segs {
		m := min(int64(Segment), n-int64(i)*Segment)
		if _, err := io.ReadFull(src, buf[:m]); err != nil {
			return nil, fmt.Errorf("clip: reading the parts of a blob: %w", err)
		}
		seg, err := SealSegment(key, i, i == segs-1, buf[:m])
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(seg); err != nil {
			return nil, err
		}
	}
	return &Blob{Size: int64(segs) * SealedSegment, SHA256: h.Sum(nil)}, nil
}

// OpenBlob opens the sealed blob src under the copy's key and writes the
// n bytes of parts it holds to dst; the zeros after them must be zeros.
// The caller has checked the blob against its SHA-256, and checks each
// part against its own.
func OpenBlob(key []byte, src io.Reader, b *Blob, n int64, dst io.Writer) error {
	if b == nil || n <= 0 || b.Size != BlobSize(n) {
		return errors.New("clip: the blob does not fit its manifest")
	}
	segs := uint64(b.Size / SealedSegment)
	buf := make([]byte, SealedSegment)
	for i := range segs {
		if _, err := io.ReadFull(src, buf); err != nil {
			return fmt.Errorf("clip: reading a blob: %w", err)
		}
		plain, err := OpenSegment(key, i, i == segs-1, buf)
		if err != nil {
			return err
		}
		m := min(int64(Segment), n-int64(i)*Segment)
		if slices.ContainsFunc(plain[m:], func(c byte) bool { return c != 0 }) {
			return errors.New("clip: a blob's padding is not zeros")
		}
		if _, err := dst.Write(plain[:m]); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks the rules a copy's content keeps, whatever its blob.
func (c Content) Validate() error {
	ev := Event{ID: strings.Repeat("0", 32), Origin: strings.Repeat("0", 32), Time: hlc.Timestamp{Wall: 1}, Kind: c.Kind, Via: c.Via, Text: c.Text, Media: c.Media}
	if c.Kind == Secret && c.Text == "" {
		return errors.New("clip: empty text")
	}
	return ev.Validate()
}

func manifestJSON(m *Manifest) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("clip: the manifest does not encode: %w", err)
	}
	return strict.Canonicalize(raw)
}

// Encode gives the Content in binary, padded to its step.
func (c Content) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var manifest []byte
	if c.Media != nil {
		var err error
		if manifest, err = manifestJSON(c.Media); err != nil {
			return nil, err
		}
	}
	var b bytes.Buffer
	b.Write([]byte{1, byte(c.Kind) + 1, byte(c.Via)})
	put(&b, []byte(c.Text))
	put(&b, manifest)
	step, ok := stepFor(b.Len())
	if !ok {
		return nil, errors.New("clip: the copy is larger than 4 MiB with its manifest")
	}
	out := b.Bytes()
	return append(out, make([]byte, step-len(out))...), nil
}

func stepFor(n int) (int, bool) {
	for _, s := range steps {
		if s >= n {
			return s, true
		}
	}
	return 0, false
}

// DecodeContent reads a Content that opened, refusing what breaks its
// rules.
func DecodeContent(b []byte) (Content, error) {
	if !slices.Contains(steps, len(b)) {
		return Content{}, errors.New("clip: the copy's content is not of a size it is padded to")
	}
	short := errors.New("clip: the copy's content is cut short")
	at := 0
	take := func(n int) ([]byte, error) {
		if n < 0 || n > len(b)-at {
			return nil, short
		}
		s := b[at : at+n]
		at += n
		return s, nil
	}
	length := func() (int, error) {
		l, err := take(4)
		if err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(l)
		if n > uint32(len(b)) {
			return 0, short
		}
		return int(n), nil
	}
	head, err := take(3)
	if err != nil {
		return Content{}, err
	}
	if head[0] != 1 {
		return Content{}, fmt.Errorf("clip: the copy's content is of version %d", head[0])
	}
	if head[1] < 1 || head[1] > 3 {
		return Content{}, fmt.Errorf("clip: the copy's content has an unknown kind %d", head[1])
	}
	if head[2] > byte(Universal) {
		return Content{}, fmt.Errorf("clip: the copy's content has an unknown way %d", head[2])
	}
	c := Content{Kind: Kind(head[1] - 1), Via: Via(head[2])}
	n, err := length()
	if err != nil {
		return Content{}, err
	}
	if n > MaxText {
		return Content{}, errors.New("clip: the copy's text is larger than 1 MiB")
	}
	text, err := take(n)
	if err != nil {
		return Content{}, err
	}
	if !utf8.Valid(text) {
		return Content{}, errors.New("clip: the copy's text is not UTF-8")
	}
	c.Text = string(text)
	if n, err = length(); err != nil {
		return Content{}, err
	}
	manifest, err := take(n)
	if err != nil {
		return Content{}, err
	}
	switch {
	case c.Kind == Media:
		if c.Media, err = ParseManifest(manifest); err != nil {
			return Content{}, fmt.Errorf("clip: the copy's manifest: %w", err)
		}
	case n != 0:
		return Content{}, errors.New("clip: a copy that is not media has a manifest")
	}
	for _, x := range b[at:] {
		if x != 0 {
			return Content{}, errors.New("clip: the copy's padding is not zeros")
		}
	}
	if s, _ := stepFor(at); s != len(b) {
		return Content{}, errors.New("clip: the copy's content is padded past its step")
	}
	if err := c.Validate(); err != nil {
		return Content{}, err
	}
	return c, nil
}

func headerHash(id, origin string, t hlc.Timestamp, readers []string, blob *Blob) []byte {
	var h bytes.Buffer
	h.Write(headerContext)
	put(&h, []byte(id))
	put(&h, []byte(origin))
	put(&h, []byte(t.String()))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(readers))))
	for _, r := range readers {
		put(&h, []byte(r))
	}
	if blob != nil {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(blob.Size)))
		h.Write(blob.SHA256)
	} else {
		h.Write(make([]byte, 40))
	}
	s := sha256.Sum256(h.Bytes())
	return s[:]
}

// IsMark reports whether s is a mark: a secret without its payload.
func (s *Sealed) IsMark() bool { return len(s.Payload) == 0 }

// PayloadHash is the SHA-256 of the payload the copy has or stands for.
func (s *Sealed) PayloadHash() []byte {
	if s.IsMark() {
		h := make([]byte, 32)
		copy(h, s.PayloadSHA256)
		return h
	}
	h := sha256.Sum256(s.Payload)
	return h[:]
}

// Mark returns the mark of the copy: the same, without its payload.
func (s *Sealed) Mark() *Sealed {
	m := *s
	m.PayloadSHA256, m.Payload = s.PayloadHash(), nil
	return &m
}

// Validate checks the copy as a receiver must before anything else.
func (s *Sealed) Validate() error {
	switch {
	case s.OpenKind != nil || s.OpenText != nil || s.OpenVia != nil || s.OpenMedia != nil:
		return errors.New("clip: a copy in the open is never taken")
	case !isID(s.ID):
		return errors.New("clip: bad event ID")
	case !isID(s.Origin):
		return errors.New("clip: bad origin device ID")
	case s.Time.IsZero() || !s.Time.Valid():
		return errors.New("clip: bad timestamp")
	case s.Age < 0:
		return fmt.Errorf("clip: negative event age %d ms", s.Age)
	}
	cert, err := x509.ParseCertificate(s.Cert)
	if err != nil {
		return fmt.Errorf("clip: the copy's certificate: %w", err)
	}
	if cert.Subject.CommonName != s.Origin {
		return errors.New("clip: the copy's certificate is not of its origin")
	}
	if len(s.Issuer) > 0 {
		if _, err := x509.ParseCertificate(s.Issuer); err != nil {
			return fmt.Errorf("clip: the copy's issuer: %w", err)
		}
	}
	if len(s.Wraps) == 0 || len(s.Wraps) > MaxReaders {
		return fmt.Errorf("clip: a copy for %d readers, not 1 to %d", len(s.Wraps), MaxReaders)
	}
	for i, w := range s.Wraps {
		if !isID(w.To) || len(w.Key) != WrapSize {
			return errors.New("clip: a copy's wrap is not for a device or not of 1168 bytes")
		}
		if i > 0 && s.Wraps[i-1].To >= w.To {
			return errors.New("clip: a copy's wraps are not sorted, each device once")
		}
	}
	switch {
	case len(s.Payload) > 0 && len(s.PayloadSHA256) == 0:
		if !slices.Contains(steps, len(s.Payload)-tagSize) {
			return errors.New("clip: a copy's payload is not of a size it is padded to")
		}
	case len(s.Payload) == 0 && len(s.PayloadSHA256) == 32:
	default:
		return errors.New("clip: a copy has neither a payload nor its hash, or both")
	}
	if b := s.Blob; b != nil {
		if b.Size <= 0 || b.Size%SealedSegment != 0 || b.Size/SealedSegment > MaxSegments || len(b.SHA256) != 32 {
			return errors.New("clip: a copy's blob is not of whole segments within 1 GiB, or has no SHA-256")
		}
	}
	if len(s.Sig) == 0 {
		return errors.New("clip: a copy is not signed")
	}
	return nil
}

func (s *Sealed) readers() []string {
	out := make([]string, len(s.Wraps))
	for i, w := range s.Wraps {
		out[i] = w.To
	}
	return out
}

// HeaderHash is the hash of the copy's header, which its payload and wraps
// are sealed under.
func (s *Sealed) HeaderHash() []byte {
	return headerHash(s.ID, s.Origin, s.Time, s.readers(), s.Blob)
}

// ToSign is what the origin signs.
func (s *Sealed) ToSign() []byte {
	var b bytes.Buffer
	b.Write(signContext)
	b.Write(s.HeaderHash())
	b.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s.Wraps))))
	for _, w := range s.Wraps {
		put(&b, w.Key)
	}
	b.Write(s.PayloadHash())
	return b.Bytes()
}

// Verifies reports whether the key of cert signed the copy.
func (s *Sealed) Verifies(cert *x509.Certificate) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	h := sha256.Sum256(s.ToSign())
	return ecdsa.VerifyASN1(pub, h[:], s.Sig)
}

// Open opens the copy with the reader me's secret for sealed messages: its
// content, and the copy's key, which opens its blob. A copy without a wrap
// for me gives ErrNotReader.
func (s *Sealed) Open(me string, secret []byte) (Content, []byte, error) {
	if s.IsMark() {
		return Content{}, nil, errors.New("clip: a mark has no content")
	}
	i := slices.IndexFunc(s.Wraps, func(w Wrap) bool { return w.To == me })
	if i < 0 {
		return Content{}, nil, ErrNotReader
	}
	c, k, err := s.open(i, me, secret)
	if err != nil {
		return Content{}, nil, err
	}
	var size int64
	if c.Media != nil {
		size = c.Media.Size
	}
	switch b := s.Blob; {
	case b != nil && size > 0 && b.Size == BlobSize(size):
	case b == nil && size == 0:
	default:
		return Content{}, nil, errors.New("clip: the copy's blob does not fit its manifest")
	}
	return c, k, nil
}

// open opens the copy with the wrap i, which is for me: through the core
// in a build that links it (sealedcore.go), with Go's code otherwise.
func (s *Sealed) open(i int, me string, secret []byte) (Content, []byte, error) {
	if core.Linked() {
		return openInCore(s, me, secret)
	}
	return s.openInGo(i, secret)
}

// openInGo is Go's open of the copy with the wrap i.
func (s *Sealed) openInGo(i int, secret []byte) (Content, []byte, error) {
	h := s.HeaderHash()
	k, err := seal.Open(secret, h, s.Wraps[i].Key)
	if err != nil || len(k) != KeySize {
		return Content{}, nil, errors.New("clip: the copy's key does not open with this device's key")
	}
	a, err := aeadOf(k, payloadInfo)
	if err != nil {
		return Content{}, nil, err
	}
	plain, err := a.Open(nil, make([]byte, 12), s.Payload, h)
	if err != nil {
		return Content{}, nil, errors.New("clip: the copy does not open: it was changed")
	}
	c, err := DecodeContent(plain)
	if err != nil {
		return Content{}, nil, err
	}
	return c, k, nil
}

// NewKey returns a random key for a copy.
func NewKey() []byte {
	k := make([]byte, KeySize)
	rand.Read(k) // never fails, see crypto/rand
	return k
}

// SealCopy seals a copy: its content, under the copy's key, to readers,
// with the blob the caller sealed under the same key, and signs it with
// the key of cert (the member key). issuer is the admin CA that issued
// cert, nil when a root did.
func SealCopy(id, origin string, t hlc.Timestamp, cert, issuer []byte, readers []Reader, c Content, blob *Blob, key []byte, signer crypto.Signer) (*Sealed, error) {
	if len(readers) == 0 || len(readers) > MaxReaders {
		return nil, fmt.Errorf("clip: a copy for %d readers, not 1 to %d", len(readers), MaxReaders)
	}
	if len(key) != KeySize {
		return nil, errors.New("clip: a copy's key is not 32 bytes")
	}
	s, toSign, err := sealDraft(id, origin, t, cert, issuer, readers, c, blob, key)
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(toSign)
	if s.Sig, err = signer.Sign(rand.Reader, d[:], crypto.SHA256); err != nil {
		return nil, fmt.Errorf("clip: sign the copy: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// sealDraft seals a copy without signing it, and gives what its origin
// signs: through the core in a build that links it, with Go's code
// otherwise. The core's copy must give the same bytes to sign as Go reads
// from it, or it is not sent.
func sealDraft(id, origin string, t hlc.Timestamp, cert, issuer []byte, readers []Reader, c Content, blob *Blob, key []byte) (*Sealed, []byte, error) {
	if core.Linked() {
		s, toSign, err := sealInCore(id, origin, t, cert, issuer, readers, c, blob, key)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(toSign, s.ToSign()) {
			return nil, nil, errors.New("clip: the core's sealed copy does not read back as it was signed")
		}
		return s, toSign, nil
	}
	return sealInGo(id, origin, t, cert, issuer, readers, c, blob, key)
}

// sealInGo is Go's seal of a copy, without its signature.
func sealInGo(id, origin string, t hlc.Timestamp, cert, issuer []byte, readers []Reader, c Content, blob *Blob, key []byte) (*Sealed, []byte, error) {
	rs := slices.Clone(readers)
	slices.SortFunc(rs, func(a, b Reader) int { return strings.Compare(a.ID, b.ID) })
	rs = slices.CompactFunc(rs, func(a, b Reader) bool { return a.ID == b.ID })
	ids := make([]string, len(rs))
	for i, r := range rs {
		ids[i] = r.ID
	}
	h := headerHash(id, origin, t, ids, blob)
	plain, err := c.Encode()
	if err != nil {
		return nil, nil, err
	}
	a, err := aeadOf(key, payloadInfo)
	if err != nil {
		return nil, nil, err
	}
	s := &Sealed{ID: id, Origin: origin, Time: t, Cert: cert, Issuer: issuer, Payload: a.Seal(nil, make([]byte, 12), plain, h), Blob: blob}
	for _, r := range rs {
		w, err := seal.Seal(r.Seal, h, key)
		if err != nil {
			return nil, nil, fmt.Errorf("clip: a reader's key for sealed messages: %w", err)
		}
		s.Wraps = append(s.Wraps, Wrap{To: r.ID, Key: w})
	}
	return s, s.ToSign(), nil
}
