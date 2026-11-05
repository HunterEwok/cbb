// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package clip

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/hlc"
	"github.com/HunterEwok/cbb/internal/seal"
)

type testDevice struct {
	id     string
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	secret []byte
	public []byte
}

func newDevice(t *testing.T) testDevice {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := NewID()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: id},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := seal.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	public, err := seal.PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{id, key, cert, secret, public}
}

func readersOf(ds ...testDevice) []Reader {
	var out []Reader
	for _, d := range ds {
		out = append(out, Reader{d.id, d.public})
	}
	return out
}

var copyTime = hlc.Timestamp{Wall: 1761024000000, Logical: 3}

func sealFor(t *testing.T, from testDevice, to []testDevice, c Content, blob *Blob, key []byte) *Sealed {
	t.Helper()
	s, err := SealCopy(NewID(), from.id, copyTime, from.cert.Raw, nil, readersOf(to...), c, blob, key, from.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func textContent(s string) Content { return Content{Kind: Text, Via: Copy, Text: s} }

func TestEveryReaderOpensItsOwn(t *testing.T) {
	a, b, c := newDevice(t), newDevice(t), newDevice(t)
	s := sealFor(t, a, []testDevice{c, a, b}, textContent("hello"), nil, NewKey())
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if !s.Verifies(a.cert) {
		t.Fatal("the origin's signature does not verify")
	}
	ids := []string{a.id, b.id, c.id}
	slices.Sort(ids)
	if got := s.readers(); !slices.Equal(got, ids) {
		t.Fatalf("readers %v, want them sorted %v", got, ids)
	}
	for _, d := range []testDevice{a, b, c} {
		got, _, err := s.Open(d.id, d.secret)
		if err != nil || got != textContent("hello") {
			t.Fatalf("%s opens %+v, %v", d.id, got, err)
		}
	}
	x := newDevice(t)
	if _, _, err := s.Open(x.id, x.secret); !errors.Is(err, ErrNotReader) {
		t.Errorf("a device that is no reader: %v", err)
	}
	if _, _, err := s.Open(b.id, c.secret); err == nil {
		t.Error("a reader opens with another's secret")
	}
}

func TestSealedWireForm(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	s := sealFor(t, a, []testDevice{a, b}, textContent("hello"), nil, NewKey())
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{`"kind"`, `"text"`, `"via"`, `"media"`, "hello"} {
		if bytes.Contains(raw, []byte(f)) {
			t.Errorf("%s is outside the seal: %s", f, raw)
		}
	}
	var back Sealed
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(); err != nil || !back.Verifies(a.cert) {
		t.Fatalf("read back: %v", err)
	}
	// A copy in the open is refused, whatever else it holds.
	for _, f := range []string{"kind", "text", "via", "media"} {
		var v map[string]any
		json.Unmarshal(raw, &v)
		v[f] = "x"
		w, _ := json.Marshal(v)
		var o Sealed
		if err := json.Unmarshal(w, &o); err != nil {
			t.Fatal(err)
		}
		if o.Validate() == nil {
			t.Errorf("a copy with %s is taken", f)
		}
	}
}

func TestNothingInASealedCopyChanges(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	s := sealFor(t, a, []testDevice{a, b}, textContent("hello"), nil, NewKey())
	changes := map[string]func(*Sealed){
		"id":      func(c *Sealed) { c.ID = strings.Repeat("cd", 16) },
		"time":    func(c *Sealed) { c.Time.Logical++ },
		"origin":  func(c *Sealed) { c.Origin = strings.Repeat("ef", 16) },
		"payload": func(c *Sealed) { c.Payload = slices.Clone(c.Payload); c.Payload[5] ^= 1 },
		"wrap": func(c *Sealed) {
			c.Wraps = slices.Clone(c.Wraps)
			c.Wraps[0].Key = slices.Clone(c.Wraps[0].Key)
			c.Wraps[0].Key[2000%WrapSize] ^= 1
		},
		"a reader taken off": func(c *Sealed) { c.Wraps = c.Wraps[1:] },
	}
	for name, change := range changes {
		c := *s
		change(&c)
		if c.Verifies(a.cert) {
			t.Errorf("%s: the signature does not cover it", name)
		}
	}
	// A reader moved to another header no longer opens it.
	c := *s
	c.Time.Logical++
	if _, _, err := c.Open(b.id, b.secret); err == nil {
		t.Error("a copy moved to another time opens")
	}
	// The age is no part of it.
	c = *s
	c.Age = 9000
	if !c.Verifies(a.cert) {
		t.Error("the age is under the signature")
	}
	if _, _, err := c.Open(b.id, b.secret); err != nil {
		t.Error(err)
	}
}

func TestASealedMarkVerifies(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	s := sealFor(t, a, []testDevice{a, b}, Content{Kind: Secret, Text: "hunter2"}, nil, NewKey())
	m := s.Mark()
	if !m.IsMark() || m.Validate() != nil || !m.Verifies(a.cert) {
		t.Fatal("the mark does not verify")
	}
	if _, _, err := m.Open(b.id, b.secret); err == nil {
		t.Error("a mark opens")
	}
	if h := sha256.Sum256(s.Payload); !bytes.Equal(m.PayloadHash(), h[:]) {
		t.Error("the mark's hash is not the payload's")
	}
	if raw, _ := json.Marshal(m); bytes.Contains(raw, []byte(`"payload"`)) {
		t.Error("a mark carries its payload")
	}
}

func TestPaddingHidesTheSize(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	for _, c := range []struct {
		n, want int
	}{{1, 1 << 10}, {900, 1 << 10}, {5000, 16 << 10}, {MaxText, 2 << 20}} {
		s := sealFor(t, a, []testDevice{a, b}, textContent(strings.Repeat("x", c.n)), nil, NewKey())
		if len(s.Payload) != c.want+tagSize {
			t.Errorf("a text of %d bytes: payload of %d", c.n, len(s.Payload))
		}
	}
}

func TestContentIsReadStrictly(t *testing.T) {
	c := Content{Kind: Secret, Via: Phone, Text: "x"}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeContent(b); err != nil || got != c {
		t.Fatalf("%+v, %v", got, err)
	}
	bad := func(name string, change func([]byte) []byte) {
		if _, err := DecodeContent(change(slices.Clone(b))); err == nil {
			t.Errorf("%s is taken", name)
		}
	}
	bad("padding that is not zeros", func(b []byte) []byte { b[1000] = 1; return b })
	bad("another version", func(b []byte) []byte { b[0] = 2; return b })
	bad("an unknown kind", func(b []byte) []byte { b[1] = 9; return b })
	bad("an unknown way", func(b []byte) []byte { b[2] = 9; return b })
	bad("not a step", func(b []byte) []byte { return b[:1000] })
	bad("padded past its step", func(b []byte) []byte { return append(b, make([]byte, 3<<10)...) })
	if _, err := textContent("").Encode(); err == nil {
		t.Error("an empty text encodes")
	}
	if _, err := (Content{Kind: Media, Text: "x"}).Encode(); err == nil {
		t.Error("media without a manifest encodes")
	}
}

func imageContent(size int64) Content {
	return Content{Kind: Media, Via: Copy, Media: &Manifest{Size: size, Parts: []Part{{Type: "image/png", Size: size, SHA256: bytes.Repeat([]byte{7}, 32)}}}}
}

// sealBlob seals parts as a blob of segments under key.
func sealBlob(t *testing.T, key, parts []byte) ([]byte, *Blob) {
	t.Helper()
	n := (len(parts) + Segment - 1) / Segment
	var blob []byte
	for i := range n {
		seg, err := SealSegment(key, uint64(i), i == n-1, parts[i*Segment:min(len(parts), (i+1)*Segment)])
		if err != nil {
			t.Fatal(err)
		}
		blob = append(blob, seg...)
	}
	h := sha256.Sum256(blob)
	return blob, &Blob{Size: int64(len(blob)), SHA256: h[:]}
}

func openBlob(key, blob []byte, size int) ([]byte, error) {
	n := len(blob) / SealedSegment
	var out []byte
	for i := range n {
		p, err := OpenSegment(key, uint64(i), i == n-1, blob[i*SealedSegment:(i+1)*SealedSegment])
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	if size > len(out) || slices.ContainsFunc(out[size:], func(b byte) bool { return b != 0 }) {
		return nil, errors.New("the blob's padding is not zeros")
	}
	return out[:size], nil
}

func TestABlobOpensSegmentBySegment(t *testing.T) {
	a, b := newDevice(t), newDevice(t)
	key := NewKey()
	parts := make([]byte, Segment+100)
	rand.Read(parts)
	blob, meta := sealBlob(t, key, parts)
	if int64(len(blob)) != BlobSize(int64(len(parts))) {
		t.Fatalf("a blob of %d bytes", len(blob))
	}
	s := sealFor(t, a, []testDevice{a, b}, imageContent(int64(len(parts))), meta, key)
	_, k, err := s.Open(b.id, b.secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openBlob(k, blob, len(parts))
	if err != nil || !bytes.Equal(got, parts) {
		t.Fatalf("the blob: %v", err)
	}
	first := blob[:SealedSegment]
	if _, err := OpenSegment(k, 0, true, first); err == nil {
		t.Error("the first segment opens as the last")
	}
	if _, err := OpenSegment(k, 1, true, first); err == nil {
		t.Error("a segment opens at another place")
	}
	if _, err := OpenSegment(NewKey(), 1, true, blob[SealedSegment:]); err == nil {
		t.Error("a segment opens with another copy's key")
	}
	wrong := &Blob{Size: 3 * SealedSegment, SHA256: bytes.Repeat([]byte{1}, 32)}
	if _, _, err := sealFor(t, a, []testDevice{a, b}, imageContent(10), wrong, key).Open(b.id, b.secret); err == nil {
		t.Error("a blob that does not fit its manifest opens")
	}
	if _, _, err := sealFor(t, a, []testDevice{a, b}, imageContent(10), nil, key).Open(b.id, b.secret); err == nil {
		t.Error("bytes without a blob open")
	}
}

// copyVectors is the form of testdata/interop/copies-go.json and
// copies-rust.json: copies each side seals, which the other opens.
type copyVectors struct {
	Comment string       `json:"comment"`
	Cases   []copyCase   `json:"cases"`
	Refused []copyRefuse `json:"refused"`
}

type vectorReader struct {
	ID     string `json:"id"`
	Secret []byte `json:"secret"`
}

type vectorContent struct {
	Kind  Kind      `json:"kind"`
	Via   Via       `json:"via"`
	Text  string    `json:"text"`
	Media *Manifest `json:"media,omitempty"`
}

type copyCase struct {
	Name     string         `json:"name"`
	Event    *Sealed        `json:"event"`
	Readers  []vectorReader `json:"readers"`
	Outsider vectorReader   `json:"outsider"`
	Content  vectorContent  `json:"content"`
	// Blob is the sealed blob and Parts its bytes, for a copy with one.
	Blob  []byte `json:"blob,omitempty"`
	Parts []byte `json:"parts,omitempty"`
}

// copyRefuse is a copy that fails at stage: "validate", "verify" (the
// origin's signature) or "open" (by reader).
type copyRefuse struct {
	Name   string       `json:"name"`
	Stage  string       `json:"stage"`
	Event  *Sealed      `json:"event"`
	Reader vectorReader `json:"reader"`
}

func goCopyVectors(t *testing.T) copyVectors {
	a, b, c, x := newDevice(t), newDevice(t), newDevice(t), newDevice(t)
	v := copyVectors{Comment: "Written by internal/clip's TestCopyVectors -update. Each reader opens each case's event to its content, and the outsider does not; each refused event fails at its stage (docs/protocol.md, section 4, \"Event\")."}
	add := func(name string, ct Content, parts []byte, to ...testDevice) *Sealed {
		key := NewKey()
		var blob []byte
		var meta *Blob
		if parts != nil {
			blob, meta = sealBlob(t, key, parts)
		}
		s := sealFor(t, a, to, ct, meta, key)
		cs := copyCase{Name: name, Event: s, Outsider: vectorReader{x.id, x.secret}, Content: vectorContent(ct), Blob: blob, Parts: parts}
		for _, d := range to {
			cs.Readers = append(cs.Readers, vectorReader{d.id, d.secret})
		}
		v.Cases = append(v.Cases, cs)
		return s
	}
	text := add("a text to three", textContent("Hello, group"), nil, a, b, c)
	add("a secret from a phone", Content{Kind: Secret, Via: Phone, Text: "hunter2"}, nil, a, b)
	add("a long text", Content{Kind: Text, Via: Universal, Text: strings.Repeat("ü", 3000)}, nil, a, c)
	parts := make([]byte, Segment+1234)
	rand.Read(parts)
	img := imageContent(int64(len(parts)))
	img.Text = "an image"
	img.Media.Parts[0].SHA256 = func() []byte { h := sha256.Sum256(parts); return h[:] }()
	add("an image of two segments", img, parts, a, b)
	add("an empty file", Content{Kind: Media, Via: Copy, Media: &Manifest{Size: 0, Parts: []Part{{Path: "empty.txt", Size: 0, SHA256: func() []byte { h := sha256.Sum256(nil); return h[:] }()}}}}, nil, a)

	refuse := func(name, stage string, s *Sealed) {
		v.Refused = append(v.Refused, copyRefuse{name, stage, s, vectorReader{b.id, b.secret}})
	}
	open := *text
	open.OpenText = json.RawMessage(`"Hello, group"`)
	refuse("a copy in the open", "validate", &open)
	unsorted := *text
	unsorted.Wraps = []Wrap{text.Wraps[2], text.Wraps[1], text.Wraps[0]}
	refuse("wraps not sorted", "validate", &unsorted)
	changed := *text
	changed.Payload = slices.Clone(text.Payload)
	changed.Payload[7] ^= 1
	refuse("a changed payload", "verify", &changed)
	moved := *text
	moved.Time.Logical++
	refuse("moved to another time", "verify", &moved)
	off := *text
	off.Wraps = slices.DeleteFunc(slices.Clone(text.Wraps), func(w Wrap) bool { return w.To == c.id })
	refuse("a reader taken off", "verify", &off)
	// Signed again by the origin after the change: the signature verifies
	// but the payload does not open under the other header.
	resigned := *text
	resigned.Time.Logical++
	d := sha256.Sum256(resigned.ToSign())
	resigned.Sig, _ = a.key.Sign(rand.Reader, d[:], nil)
	refuse("moved and signed again", "open", &resigned)
	return v
}

// TestCopyVectors writes (with -update) testdata/interop/copies-go.json and
// checks it and copies-rust.json, which the Rust core writes.
func TestCopyVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "interop")
	if *update {
		data, err := json.MarshalIndent(goCopyVectors(t), "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "copies-go.json"), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"copies-go.json", "copies-rust.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			var v copyVectors
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatal(err)
			}
			if len(v.Cases) < 4 || len(v.Refused) < 4 {
				t.Fatalf("%d cases, %d refused", len(v.Cases), len(v.Refused))
			}
			for _, c := range v.Cases {
				checkCopyCase(t, c)
			}
			for _, r := range v.Refused {
				if got := refusedAt(r); got != r.Stage {
					t.Errorf("%s: refused at %q, not %q", r.Name, got, r.Stage)
				}
			}
		})
	}
}

func checkCopyCase(t *testing.T, c copyCase) {
	t.Helper()
	s := c.Event
	cert, err := x509.ParseCertificate(s.Cert)
	if err != nil || s.Validate() != nil || !s.Verifies(cert) {
		t.Errorf("%s: does not validate or verify (%v, %v)", c.Name, err, s.Validate())
		return
	}
	want := Content{Kind: c.Content.Kind, Via: c.Content.Via, Text: c.Content.Text, Media: c.Content.Media}
	for _, r := range c.Readers {
		got, key, err := s.Open(r.ID, r.Secret)
		if err != nil {
			t.Errorf("%s: %s: %v", c.Name, r.ID, err)
			continue
		}
		gj, _ := json.Marshal(vectorContent(got))
		wj, _ := json.Marshal(vectorContent(want))
		if !bytes.Equal(gj, wj) {
			t.Errorf("%s: opens to %s, not %s", c.Name, gj, wj)
		}
		if c.Blob != nil {
			h := sha256.Sum256(c.Blob)
			if s.Blob == nil || !bytes.Equal(h[:], s.Blob.SHA256) {
				t.Errorf("%s: the blob is not the one the copy names", c.Name)
			}
			if p, err := openBlob(key, c.Blob, len(c.Parts)); err != nil || !bytes.Equal(p, c.Parts) {
				t.Errorf("%s: the blob: %v", c.Name, err)
			}
		}
	}
	if _, _, err := s.Open(c.Outsider.ID, c.Outsider.Secret); err == nil {
		t.Errorf("%s: the outsider opens it", c.Name)
	}
}

func refusedAt(r copyRefuse) string {
	s := r.Event
	if s.Validate() != nil {
		return "validate"
	}
	cert, err := x509.ParseCertificate(s.Cert)
	if err != nil || !s.Verifies(cert) {
		return "verify"
	}
	if _, _, err := s.Open(r.Reader.ID, r.Reader.Secret); err != nil {
		return "open"
	}
	return ""
}
