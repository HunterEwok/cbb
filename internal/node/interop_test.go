// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/clip"
	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/hlc"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

func interopPath(name string) string { return filepath.Join("..", "..", "testdata", "interop", name) }

// memberVectors are what another implementation of the member protocol,
// such as the phone app's CBBKit, must decode and encode the same
// way (docs/protocol.md, sections 4 and 5).
type memberVectors struct {
	Frames     []json.RawMessage `json:"frames"` // message objects as the Go side writes them
	Timestamps []timestampVector `json:"timestamps"`
	Events     []eventVector     `json:"events"`
	Order      []orderVector     `json:"order"`
	// Bodies are frames as text, each a message or not.
	Bodies []bodyVector `json:"bodies"`
}

type bodyVector struct {
	Text string `json:"text"`
	OK   bool   `json:"ok"`
}

type timestampVector struct {
	Text string `json:"text"`
	OK   bool   `json:"ok"`
}

type eventVector struct {
	JSON  json.RawMessage `json:"json"`
	Valid bool            `json:"valid"` // decodes and passes Validate
}

type orderVector struct {
	A     json.RawMessage `json:"a"`
	B     json.RawMessage `json:"b"`
	Later bool            `json:"later"` // A sorts after B
}

const (
	vecDevice = "0123456789abcdef0123456789abcdef"
	vecEvent  = "fedcba9876543210fedcba9876543210"
)

// vecCert is a certificate of vecDevice made the same on every run: an
// ECDSA key from a fixed scalar and its deterministic signature.
func vecCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2025, 10, 21, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: vecDevice},
		NotBefore: at, NotAfter: at.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// vecSealed is a copy of ev as it travels, sealed, with fixed bytes in
// place of its wraps, payload and signature: the frames show the wire's
// shape, and testdata/interop/copies-go.json the sealing itself.
func vecSealed(t *testing.T, ev clip.Event, mark bool, blob *clip.Blob) *clip.Sealed {
	t.Helper()
	s := &clip.Sealed{ID: ev.ID, Origin: ev.Origin, Time: ev.Time, Age: ev.Age, Cert: vecCert(t),
		Wraps: []clip.Wrap{{To: vecDevice, Key: bytes.Repeat([]byte{0x11}, clip.WrapSize)}},
		Blob:  blob, Sig: bytes.Repeat([]byte{0x33}, 70)}
	if mark {
		s.PayloadSHA256 = bytes.Repeat([]byte{0x22}, 32)
	} else {
		s.Payload = bytes.Repeat([]byte{0x22}, 1024+16)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func vecTime(t *testing.T, s string) hlc.Timestamp {
	t.Helper()
	var ts hlc.Timestamp
	if err := ts.UnmarshalText([]byte(s)); err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestMemberInteropVectors(t *testing.T) {
	text := clip.Event{ID: vecEvent, Origin: vecDevice, Time: vecTime(t, "1761024000000.3"), Age: 1500, Kind: clip.Text, Text: "hello <world> & \"you\" / ✓"}
	mark := clip.Event{ID: vecEvent, Origin: vecDevice, Via: clip.Phone, Time: vecTime(t, "1761024000001.0"), Age: 20, Kind: clip.Secret}
	secret := mark
	secret.Text = "hunter2"
	universal := text
	universal.Via = clip.Universal
	sum := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	files := clip.Event{ID: vecEvent, Origin: vecDevice, Time: vecTime(t, "1761024000002.0"), Age: 5, Kind: clip.Media, Text: "trip",
		Media: &clip.Manifest{Size: 1234, Parts: []clip.Part{{Path: "trip", Dir: true}, {Path: "trip/a.jpg", Size: 1234, SHA256: sum(1)}, {Path: "trip/empty.txt", SHA256: sum(2)}}}}
	image := clip.Event{ID: vecEvent, Origin: vecDevice, Time: vecTime(t, "1761024000003.0"), Kind: clip.Media,
		Media: &clip.Manifest{Size: 70000, Parts: []clip.Part{{Type: clip.TypePNG, Size: 60000, SHA256: sum(3)}, {Type: clip.TypeHTML, Size: 10000, SHA256: sum(4)}}}}
	hello := func(role Role, h helloOut) json.RawMessage {
		data, err := encode(h)
		if err != nil {
			t.Fatal(err)
		}
		return msg(t, &message{Type: typeHello, Role: role, Hello: data})
	}
	blob := &clip.Blob{SHA256: sum(5)}
	sealed := func(e clip.Event) *clip.Sealed {
		var b *clip.Blob
		if e.Media != nil && e.Media.Size > 0 {
			b = &clip.Blob{Size: clip.BlobSize(e.Media.Size), SHA256: blob.SHA256}
		}
		return vecSealed(t, e, e.IsMark(), b)
	}
	event := func(e clip.Event) json.RawMessage {
		data, err := encode(sealed(e))
		if err != nil {
			t.Fatal(err)
		}
		return msg(t, &message{Type: typeEvent, Event: data})
	}
	v := memberVectors{Frames: []json.RawMessage{
		hello(Full, helloOut{Hello: clip.Hello{Wall: 1761024000500}, Current: sealed(text), Records: "q83vEjRWeJA=", Name: "pi", OS: group.OSLinux}),
		hello(Full, helloOut{Hello: clip.Hello{Wall: 1761024000500}, Current: sealed(mark), OS: group.OSMacOS}),
		hello(Phone, helloOut{Hello: clip.Hello{Wall: 0}, OS: group.OSiOS}),
		event(text),
		event(secret),
		event(universal),
		msg(t, &message{Type: typePing}),
		msg(t, &message{Type: typeBye}),
		msg(t, &message{Type: typeCert, Cert: []byte("member certificate DER")}),
		msg(t, &message{Type: typeRecs, Records: []group.Record{
			{Body: []byte(`{"v":1,"type":"revoke"}`), Sig: []byte("sig")},
			{Body: []byte(`{"v":1}`), Sig: []byte("sig2"), Chain: [][]byte{[]byte("admin CA")}},
		}}),
		hello(Phone, helloOut{Hello: clip.Hello{Wall: 0}, TunnelKey: vecBytes(1)}),
		msg(t, &message{Type: typeTun, Tunnel: &TunnelOffer{HubKey: vecBytes(2), PSK: vecBytes(3),
			Endpoints: []string{"203.0.113.7:8764", "[2001:db8::7]:8764"}}}),
		msg(t, &message{Type: typeTun, Tunnel: &TunnelOffer{HubKey: vecBytes(4), PSK: vecBytes(5)}}),
		msg(t, &message{Type: typeTun, Tunnel: &TunnelOffer{HubKey: vecBytes(6), PSK: vecBytes(7), Endpoints: []string{"203.0.113.7:8764"},
			Obfuscation: json.RawMessage(`{"jc":4,"jmin":50,"jmax":300,"s1":20,"s2":40,"s3":16,"s4":24,` +
				`"h1":"1073741840-1073807375","h2":"16-65551","h3":"3221225488-3221291023","h4":"2147483664-2147549199",` +
				`"header_protection_key":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="}`)}}),
		msg(t, &message{Type: typeTun, Tunnel: &TunnelOffer{HubKey: vecBytes(8), PSK: vecBytes(9), Endpoints: []string{"203.0.113.9:8764"},
			VLESS: json.RawMessage(`{"endpoint":"203.0.113.9:443","public_key":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",` +
				`"short_id":"0123456789abcdef","server_name":"www.example.com","id":"5f0c1e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f"}`)}}),
		hello(Full, helloOut{Hello: clip.Hello{Wall: 1761024000500}, OS: group.OSMacOS,
			Device: &group.DeviceInfo{Form: "laptop", OSVersion: "15.1", Version: "0.5.0", MAC: "a4:83:e7:01:02:0f"}}),
		// Images and files (frames 16 to 18).
		event(files),
		event(image),
		hello(Full, helloOut{Hello: clip.Hello{Wall: 1761024000500}, Current: sealed(image), OS: group.OSLinux, Features: []string{FeatureMedia}}),
		// The members a computer reaches (frame 19).
		msg(t, &message{Type: typeReach, Reach: []group.DeviceID{vecDevice, "fedcba9876543210fedcba9876543210"}}),
	}}

	for _, s := range []string{"1761024000000.3", "1.0", "0.0", "253402300799999.4294967295", "253402300800000.0",
		"1.4294967296", "", "1", "1.", ".1", "-1.0", "+1.0", "1 .0", "1.0 ", "0x1.0", "1.0.0", "01.0", "1.00"} {
		var ts hlc.Timestamp
		v.Timestamps = append(v.Timestamps, timestampVector{Text: s, OK: ts.UnmarshalText([]byte(s)) == nil})
	}

	for _, raw := range []string{
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"text","text":"x"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","via":"phone","time":"1.0","age_ms":0,"kind":"secret","text":""}`,
		// An old name of via phone, refused.
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","via":"iphone","time":"1.0","age_ms":0,"kind":"text","text":"x"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","kind":"text","text":"no age"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"text","text":""}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"0.0","age_ms":0,"kind":"text","text":"x"}`,
		`{"id":"FEDCBA9876543210FEDCBA9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"text","text":"x"}`,
		`{"id":"fedcba98","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"text","text":"x"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":-1,"kind":"text","text":"x"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"image","text":"x"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","via":"fax","time":"1.0","age_ms":0,"kind":"text","text":"x"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1","age_ms":0,"kind":"text","text":"x"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"text","text":"x","extra":true}`,
		// Images and files.
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","text":"","media":{"size":3,"parts":[{"type":"image/png","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","text":"alt","media":{"size":3,"parts":[{"type":"image/png","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":1,"parts":[{"path":"d","dir":true},{"path":"d/f.txt","size":1,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		// Media without a manifest, a text with one, and manifests that break a rule.
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","text":"alt"}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"text","text":"x","media":{"size":3,"parts":[{"type":"image/png","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":4,"parts":[{"type":"image/png","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":0,"parts":[]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":3,"parts":[{"type":"image/gif","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":3,"parts":[{"type":"image/png","size":3,"sha256":"AQID"}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":6,"parts":[{"type":"image/png","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},{"type":"image/png","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":3,"parts":[{"path":"a","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},{"type":"image/png","size":3,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":1,"parts":[{"path":"../f","size":1,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":1,"parts":[{"path":"d/con.txt","size":1,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":1,"parts":[{"path":"d/f.","size":1,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":1,"parts":[{"path":"a","size":1,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},{"path":"a/b","size":0,"sha256":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]}}`,
		`{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"media","media":{"size":0,"parts":[{"path":"d","dir":true,"size":1}]}}`,
	} {
		var e clip.Event
		ok := json.Unmarshal([]byte(raw), &e) == nil && e.Validate() == nil
		v.Events = append(v.Events, eventVector{JSON: json.RawMessage(raw), Valid: ok})
	}

	ev := func(id, ts string) clip.Event {
		return clip.Event{ID: id, Origin: vecDevice, Time: vecTime(t, ts), Kind: clip.Text, Text: "x"}
	}
	for _, p := range [][2]clip.Event{
		{ev(vecEvent, "2.0"), ev(vecEvent, "1.0")},
		{ev(vecEvent, "1.1"), ev(vecEvent, "1.0")},
		{ev(vecEvent, "1.0"), ev(vecEvent, "1.1")},
		{ev("ff000000000000000000000000000000", "1.0"), ev("0f000000000000000000000000000000", "1.0")},
		{ev("0f000000000000000000000000000000", "1.0"), ev("ff000000000000000000000000000000", "1.0")},
		{ev(vecEvent, "1.0"), ev(vecEvent, "1.0")},
	} {
		a, _ := encode(p[0])
		b, _ := encode(p[1])
		v.Order = append(v.Order, orderVector{A: a, B: b, Later: later(p[0], p[1])})
	}

	// Numbers: only integers as in signed bodies, anywhere in a frame.
	for _, s := range []string{
		`{"t":"hello","role":"full","hello":{"wall_ms":0}}`,
		`{"t":"hello","role":"full","hello":{"wall_ms":-0}}`,
		`{"t":"hello","role":"full","hello":{"wall_ms":1761024000500.0}}`,
		`{"t":"event","event":{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":-0,"kind":"text","text":"x"}}`,
		`{"t":"event","event":{"id":"fedcba9876543210fedcba9876543210","origin":"0123456789abcdef0123456789abcdef","time":"1.0","age_ms":0,"kind":"text","text":"x","extra":-0}}`,
		`{"t":"ping","extra":-1}`,
		`{"t":"ping","extra":-0}`,
		`{"t":"ping","extra":[1,2.5]}`,
		`{"t":"ping","extra":1e3}`,
		`{"t":"ping","extra":9223372036854775807}`,
		`{"t":"ping","extra":9223372036854775808}`,
		`{"t":"ping","extra":"-0 1.5 1e3"}`,
		`{"t":"ping","extra":"\"-0"}`,
		`{"t":"ping","extra":{"-0":0}}`,
	} {
		_, err := decodeMessage([]byte(s))
		v.Bodies = append(v.Bodies, bodyVector{Text: s, OK: err == nil})
	}

	checkVectors(t, "member.json", v)
}

// vecBytes is a 32-byte key of the vectors: b, b+1, ...
func vecBytes(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

// later is the order of docs/protocol.md, section 5: by time, then by ID.
func later(a, b clip.Event) bool {
	if c := a.Time.Compare(b.Time); c != 0 {
		return c > 0
	}
	return a.ID > b.ID
}

func msg(t *testing.T, m *message) json.RawMessage {
	t.Helper()
	f, err := frame(m)
	if err != nil {
		t.Fatal(err)
	}
	return json.RawMessage(f[4:])
}

// checkVectors compares v, as JSON, with the file, or rewrites it with
// -update.
func checkVectors(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := interopPath(name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is out of date; run go test ./internal/node -run TestMemberInteropVectors -update", path)
	}
}

// certVectors are member certificates and whether the member protocol
// accepts each at a time, for another implementation's peer check. The
// certificates are random, so the file is written only with -update; a
// normal run checks that the Go side still decides as it says.
type certVectors struct {
	GroupCA []byte       `json:"group_ca"`
	Cases   []certVector `json:"cases"`
}

type certVector struct {
	Name   string `json:"name"`
	Cert   []byte `json:"cert"`
	NowMS  int64  `json:"now_ms"`
	Device string `json:"device"` // "" when refused
}

// acceptedDevice checks a peer's certificate as the member TLS
// configuration does: the chain to the group CA at max(now, its start),
// then the device name.
func acceptedDevice(ca, cert *x509.Certificate, now time.Time) string {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	at := now
	if at.Before(ca.NotBefore) {
		at = ca.NotBefore
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return ""
	}
	id, err := group.DeviceOf(cert)
	if err != nil {
		return ""
	}
	return string(id)
}

func TestMemberCertVectors(t *testing.T) {
	path := interopPath("member-certs.json")
	if *update {
		t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
		g, err := group.Create(t0)
		if err != nil {
			t.Fatal(err)
		}
		other, err := group.Create(t0)
		if err != nil {
			t.Fatal(err)
		}
		at := func(d time.Duration) int64 { return t0.Add(d).UnixMilli() }
		v := certVectors{GroupCA: g.GroupCA.Cert.Raw, Cases: []certVector{
			{Name: "a member", Cert: g.Cert.Raw, NowMS: at(24 * time.Hour)},
			{Name: "a clock years behind", Cert: g.Cert.Raw, NowMS: 0},
			{Name: "expired", Cert: g.Cert.Raw, NowMS: at(3 * 365 * 24 * time.Hour)},
			{Name: "another group", Cert: other.Cert.Raw, NowMS: at(24 * time.Hour)},
			{Name: "the group CA itself", Cert: g.GroupCA.Cert.Raw, NowMS: at(24 * time.Hour)},
		}}
		for i := range v.Cases {
			c, _ := x509.ParseCertificate(v.Cases[i].Cert)
			v.Cases[i].Device = acceptedDevice(g.GroupCA.Cert, c, time.UnixMilli(v.Cases[i].NowMS))
		}
		data, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v certVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(v.GroupCA)
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, c := range v.Cases {
		cert, err := x509.ParseCertificate(c.Cert)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if got := acceptedDevice(ca, cert, time.UnixMilli(c.NowMS)); got != c.Device {
			t.Errorf("%s: accepted as %q, the file says %q", c.Name, got, c.Device)
		}
		if c.Device != "" {
			accepted++
		}
	}
	if accepted != 2 {
		t.Errorf("%d cases accepted, want the member at two times", accepted)
	}
}

// TestSwiftMemberFrames decodes the frames the phone app's CBBKit
// writes (testdata/interop/swift-member.json, from its tests) as a member
// does.
func TestSwiftMemberFrames(t *testing.T) {
	data, err := os.ReadFile(interopPath("swift-member.json"))
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	if err := json.Unmarshal(data, &frames); err != nil {
		t.Fatal(err)
	}
	if len(frames) < 3 {
		t.Fatalf("%d frames, want a hello, an event and a ping at least", len(frames))
	}
	for i, f := range frames {
		m, err := readMessage(nopDeadline{bytes.NewReader(f)}, time.Second)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		switch {
		case i == 0:
			if m.Type != typeHello || m.Role != Phone {
				t.Fatalf("frame 0 is %s from %q, want the phone's hello", m.Type, m.Role)
			}
			_, extra, err := decodeHello(m.Hello)
			if err != nil || extra.current == nil || extra.current.Validate() != nil || extra.Name != "iPhone" {
				t.Errorf("the hello: %+v, %v", extra, err)
			}
			// The phone's current copy is a secret, which a hello carries only as its mark.
			if extra.current != nil && !extra.current.IsMark() {
				t.Error("the hello carries a secret's payload")
			}
		case m.Type == typeEvent:
			var s clip.Sealed
			if err := json.Unmarshal(m.Event, &s); err != nil || s.Validate() != nil || s.IsMark() {
				t.Errorf("frame %d: a copy that Go refuses: %s, %v", i, m.Event, err)
			}
		case m.Type != typePing && m.Type != typeBye:
			t.Errorf("frame %d: unexpected type %q", i, m.Type)
		}
	}
}

type nopDeadline struct{ *bytes.Reader }

func (nopDeadline) SetReadDeadline(time.Time) error { return nil }

// contentVectors are the messages and binary frames of content
// (docs/protocol.md, section 4, "Content"), for the kits.
type contentVectors struct {
	Frames []json.RawMessage `json:"frames"` // get, missing and a cancel, as Go writes them
	Chunks []chunkVector     `json:"chunks"`
}

type chunkVector struct {
	SHA256 []byte `json:"sha256"`
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
	// Frame is the frame, length included, without the zeros at its end;
	// FrameLen is its length with them.
	Frame    []byte `json:"frame"`
	FrameLen int    `json:"frame_len"`
}

func TestContentInteropVectors(t *testing.T) {
	sum := bytes.Repeat([]byte{7}, 32)
	v := contentVectors{Frames: []json.RawMessage{
		msg(t, &message{Type: typeGet, Get: &Get{SHA256: sum, Offset: 0, Length: getWindow}}),
		msg(t, &message{Type: typeGet, Get: &Get{SHA256: sum, Offset: 3 << 20, Length: 12345}}),
		msg(t, &message{Type: typeMissing, Get: &Get{SHA256: sum, Offset: 0, Length: getWindow}}),
		msg(t, &message{Type: typeGet, Get: &Get{SHA256: sum}}), // a cancel
	}}
	for _, ch := range []chunk{
		{sum: [32]byte(sum), offset: 0, data: []byte("hello")},
		{sum: [32]byte(sum), offset: 1 << 40, data: bytes.Repeat([]byte{0xab}, 100)},
		{sum: [32]byte(sum), offset: 5, data: nil},
	} {
		f := encodeChunk(ch)
		v.Chunks = append(v.Chunks, chunkVector{SHA256: ch.sum[:], Offset: ch.offset, Data: ch.data, Frame: bytes.TrimRight(f, "\x00"), FrameLen: len(f)})
	}
	checkVectors(t, "content.json", v)
}
