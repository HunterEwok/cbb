// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/authority"
)

// A strictVector is a body and whether every member takes it: the
// vectors of testdata/interop/strict.json, which the Rust core and both
// phone kits read too.
type strictVector struct {
	Name  string `json:"name"`
	Body  []byte `json:"body"`
	Valid bool   `json:"valid"`
}

type strictVectors struct {
	Records   []strictVector `json:"records"`
	Commands  []strictVector `json:"commands"`
	Manifests []strictVector `json:"manifests"`
}

const (
	vecGroup  = "0011223344556677"
	vecDevice = "00112233445566778899aabbccddeeff"
	vecOther  = "ffeeddccbbaa99887766554433221100"
)

var (
	vecHash  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	vecHash2 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
)

// padded returns the device body dev(good), with an unknown member that
// makes it n bytes long.
func padded(dev func(string) []byte, good string, n int) []byte {
	b := dev(good + `,"later":""`)
	return dev(good + `,"later":"` + strings.Repeat("a", n-len(b)) + `"`)
}

// makeStrictVectors returns the vectors; each body is written out as it
// is, so that it can break the rules of JSON.
func makeStrictVectors() strictVectors {
	dev := func(fields string) []byte {
		return []byte(`{"v":1,"type":"device","group":"` + vecGroup + `","time_ms":1700000000000` + fields + `}`)
	}
	good := `,"device":"` + vecDevice + `","name":"Laptop","role":"full","os":"linux","key":"` + vecHash + `"`
	with := func(old, repl string) []byte { return dev(strings.Replace(good, old, repl, 1)) }
	r := func(name string, valid bool, body []byte) strictVector {
		return strictVector{Name: name, Body: body, Valid: valid}
	}
	var v strictVectors
	v.Records = []strictVector{
		r("device", true, dev(good)),
		r("device with spaces and newlines", true, []byte(" {\n\t\"v\": 1, \"type\": \"device\", \"group\": \""+vecGroup+"\", \"time_ms\": 1700000000000"+good+"}\r\n")),
		r("revoke", true, []byte(`{"v":1,"type":"revoke","group":"`+vecGroup+`","time_ms":5,"keys":["`+vecHash+`"],"keep":["`+vecHash2+`"]}`)),
		r("thaw", true, []byte(`{"v":1,"type":"thaw","group":"`+vecGroup+`","time_ms":5,"records":["`+vecHash+`"]}`)),
		r("an unknown member", true, dev(good+`,"later":"x","more":{"a":[1,-2,true,false,"s"]}`)),
		r("an earlier role", true, with(`"role":"full"`, `"role":"linux"`)),
		r("a surrogate pair escaped", true, with(`"Laptop"`, `"Lap\ud83d\ude00"`)),
		r("other escapes", true, with(`"Laptop"`, `"\u00e9\"\\\/"`)),
		r("a kind and a proof", true, dev(good+`,"store":"proven","kind":"android-tee","proof":"x"`)),
		r("a body of 8 KiB", true, padded(dev, good, 8<<10)),
		r("negative time", true, []byte(`{"v":1,"type":"revoke","group":"`+vecGroup+`","time_ms":-1,"keys":["`+vecHash+`"]}`)),

		r("a kind as a number", false, dev(good+`,"kind":1`)),
		r("a kind as a list", false, dev(good+`,"kind":[1,2]`)),
		r("a proof as an object", false, dev(good+`,"proof":{}`)),
		r("a proof as a boolean", false, dev(good+`,"proof":true`)),
		r("a body over 8 KiB", false, padded(dev, good, 8<<10+1)),
		r("a member name in upper case", false, with(`"name"`, `"NAME"`)),
		r("a member name in mixed case", false, []byte(`{"v":1,"Type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("a member name escaped", false, with(`"name"`, `"n\u0061me"`)),
		r("a member name with a Kelvin sign", false, with(`"key"`, "\"\u212aey\"")),
		r("a member twice", false, dev(good+`,"type":"revoke"`)),
		r("a member twice with the same value", false, dev(good+`,"name":"Laptop"`)),
		r("a member twice in a nested object", false, dev(good+`,"later":{"a":1,"a":2}`)),
		r("invalid UTF-8", false, with(`"Laptop"`, "\"Lap\xfftop\"")),
		r("overlong UTF-8", false, with(`"Laptop"`, "\"Lap\xc0\xaftop\"")),
		r("a surrogate in UTF-8", false, with(`"Laptop"`, "\"Lap\xed\xa0\x80top\"")),
		r("a lone high surrogate escaped", false, with(`"Laptop"`, `"Lap\ud800top"`)),
		r("a lone low surrogate escaped", false, with(`"Laptop"`, `"Lap\udc00top"`)),
		r("a high surrogate before an escape past the low ones", false, with(`"Laptop"`, `"Lap\ud800\ue000"`)),
		r("a high surrogate before an escape below the low ones", false, with(`"Laptop"`, `"Lap\ud800\udbff"`)),
		r("a high surrogate before another escape", false, with(`"Laptop"`, `"Lap\ud800\n"`)),
		r("a high surrogate at the end of a string", false, with(`"Laptop"`, `"Lap\ud800"`)),
		r("the last surrogate pair escaped", true, with(`"Laptop"`, `"Lap\udbff\udfff"`)),
		r("a byte order mark", false, append([]byte("\xef\xbb\xbf"), dev(good)...)),
		r("a raw control character", false, with(`"Laptop"`, "\"Lap\ttop\"")),
		r("an unknown escape", false, with(`"Laptop"`, `"Lap\xtop"`)),
		r("no time", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`"`+good+`}`)),
		r("no version", false, []byte(`{"type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("no group", false, []byte(`{"v":1,"type":"device","time_ms":1`+good+`}`)),
		r("a null", false, with(`"os":"linux"`, `"os":null`)),
		r("a null among unknown members", false, dev(good+`,"later":[null]`)),
		r("a time with a fraction", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":1.0`+good+`}`)),
		r("a time with an exponent", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":1e3`+good+`}`)),
		r("a time with a leading zero", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":01`+good+`}`)),
		r("a time out of range", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":9223372036854775808`+good+`}`)),
		r("a version as a string", false, []byte(`{"v":"1","type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("another version", false, []byte(`{"v":2,"type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("a version that wraps in 32 bits", false, []byte(`{"v":4294967297,"type":"device","group":"`+vecGroup+`","time_ms":1`+good+`}`)),
		r("more after the object", false, append(dev(good), []byte(`{}`)...)),
		r("an array", false, []byte(`[`+string(dev(good))+`]`)),
		r("nested too deeply", false, dev(good+`,"later":`+strings.Repeat("[", 17)+strings.Repeat("]", 17))),
		r("a key hash with stray bits", false, with(vecHash, vecHash[:42]+"x=")),
		r("a key hash without padding", false, with(vecHash, strings.TrimRight(vecHash, "="))),
		r("a key hash with a newline", false, with(vecHash, vecHash[:20]+`\n`+vecHash[20:])),
		r("a key hash of 31 bytes", false, with(vecHash, base64.StdEncoding.EncodeToString(make([]byte, 31)))),
		r("an admin hash of 33 bytes", false, dev(good+`,"admin":"`+base64.StdEncoding.EncodeToString(make([]byte, 33))+`"`)),
		r("no key", false, with(`,"key":"`+vecHash+`"`, ``)),
		r("a device ID in upper case", false, with(vecDevice, strings.ToUpper(vecDevice))),
		r("a name of 65 bytes", false, with(`"Laptop"`, `"`+strings.Repeat("a", 65)+`"`)),
		r("a name with a control character", false, with(`"Laptop"`, `"Lap\u0007top"`)),
		r("a name with a C1 control character", false, with(`"Laptop"`, `"Lap\u0085top"`)),
		r("an empty name", false, with(`"Laptop"`, `""`)),
		r("an unknown role", false, with(`"role":"full"`, `"role":"server"`)),
		r("an unknown system", false, with(`"os":"linux"`, `"os":"beos"`)),
		r("an unknown type", false, []byte(`{"v":1,"type":"other","group":"`+vecGroup+`","time_ms":1}`)),
		r("a revoke of nothing", false, []byte(`{"v":1,"type":"revoke","group":"`+vecGroup+`","time_ms":1,"keys":[]}`)),
		r("a root without a certificate", false, []byte(`{"v":1,"type":"root","group":"`+vecGroup+`","time_ms":1,"root":""}`)),
		r("a time of zero", true, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":0`+good+`}`)),
		r("a time of negative zero", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":-0`+good+`}`)),
		r("a time of negative zeros", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":-00`+good+`}`)),
		r("a time of zeros", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":00`+good+`}`)),
		r("a time of zero with an exponent", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":0e0`+good+`}`)),
		r("a time of negative zero with a fraction", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":-0.0`+good+`}`)),
		r("a time of negative zero with an exponent", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":-0e0`+good+`}`)),
		r("a time of a minus sign", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":-`+good+`}`)),
		r("a time of a plus sign", false, []byte(`{"v":1,"type":"device","group":"`+vecGroup+`","time_ms":+1`+good+`}`)),
		r("a negative zero in an unknown nested object", false, dev(good+`,"later":{"a":{"b":-0}}`)),
		r("a negative zero in an unknown array", false, dev(good+`,"later":[1,-0]`)),
		r("a zero in an unknown nested object", true, dev(good+`,"later":{"a":{"b":0}}`)),
		r("a negative number in an unknown nested object", true, dev(good+`,"later":{"a":{"b":-10}}`)),
	}
	cmd := func(fields string) []byte {
		return []byte(`{"v":1,"type":"paste-off","group":"` + vecGroup + `","by":"` + vecOther + `","to":"` + vecDevice +
			`","id":"0123456789abcdef0123456789abcdef","time_ms":1000,"expires_ms":20000` + fields + `}`)
	}
	v.Commands = []strictVector{
		r("paste-off", true, cmd("")),
		r("an empty kind and no enter", true, cmd(`,"kind":"","enter":false,"text":"","action":""`)),
		r("mode", true, []byte(`{"v":1,"type":"mode","group":"`+vecGroup+`","by":"`+vecOther+`","to":"`+vecDevice+
			`","id":"0123456789abcdef0123456789abcdef","time_ms":1000,"expires_ms":20000,"mode":"own"}`)),
		r("paste", true, []byte(`{"v":1,"type":"paste","group":"`+vecGroup+`","by":"`+vecOther+`","to":"`+vecDevice+
			`","id":"0123456789abcdef0123456789abcdef","time_ms":1000,"expires_ms":20000,"mode":"paste","kind":"secret","text":"line\none"}`)),
		r("a member name in upper case", false, bytes.Replace(cmd(""), []byte(`"to"`), []byte(`"TO"`), 1)),
		r("a member twice", false, cmd(`,"type":"mode"`)),
		r("no signer", false, bytes.Replace(cmd(""), []byte(`"by":"`+vecOther+`",`), nil, 1)),
		r("no time", false, bytes.Replace(cmd(""), []byte(`"time_ms":1000,`), nil, 1)),
		r("a null mode", false, cmd(`,"mode":null`)),
		r("invalid UTF-8", false, cmd(",\"later\":\"\xff\"")),
		r("an ID in upper case", false, bytes.Replace(cmd(""), []byte("abcdef0123456789abcdef"), []byte("ABCDEF0123456789abcdef"), 1)),
		r("a kind on paste-off", false, cmd(`,"kind":"text"`)),
		r("enter on paste-off", false, cmd(`,"enter":true`)),
		r("an expiry of negative zero", false, bytes.Replace(cmd(""), []byte(`"expires_ms":20000`), []byte(`"expires_ms":-0`), 1)),
		r("an expiry of negative zeros", false, bytes.Replace(cmd(""), []byte(`"expires_ms":20000`), []byte(`"expires_ms":-00`), 1)),
		r("an expiry of zero with an exponent", false, bytes.Replace(cmd(""), []byte(`"expires_ms":20000`), []byte(`"expires_ms":0e0`), 1)),
		r("an expiry of negative zero with a fraction", false, bytes.Replace(cmd(""), []byte(`"expires_ms":20000`), []byte(`"expires_ms":-0.0`), 1)),
		r("a time of negative zero", false, bytes.Replace(cmd(""), []byte(`"time_ms":1000`), []byte(`"time_ms":-0`), 1)),
		r("a negative zero in an unknown nested object", false, cmd(`,"later":{"a":[{"b":-0}]}`)),
		r("a time before 1970", false, bytes.Replace(cmd(""), []byte(`"time_ms":1000`), []byte(`"time_ms":-1`), 1)),
		r("the earliest time and the latest expiry", false, bytes.Replace(cmd(""), []byte(`"time_ms":1000,"expires_ms":20000`),
			[]byte(`"time_ms":-9223372036854775808,"expires_ms":9223372036854775807`), 1)),
		r("the earliest time", false, bytes.Replace(cmd(""), []byte(`"time_ms":1000`), []byte(`"time_ms":-9223372036854775808`), 1)),
	}
	part := func(p string) []byte {
		return []byte(`{"size":3,"parts":[{"path":"d","dir":true` + p + `},{"path":"d/f","size":3,"sha256":"` + vecHash + `"}]}`)
	}
	// file is a manifest of one file, whose size is written as size and
	// all of whose parts together are total bytes.
	file := func(total int, size string) []byte {
		return []byte(fmt.Sprintf(`{"size":%d,"parts":[{"path":"f","size":%s,"sha256":"%s"}]}`, total, size, vecHash))
	}
	// two is a manifest of two empty files at the paths a and b.
	two := func(a, b string) []byte {
		return []byte(`{"size":0,"parts":[{"path":"` + a + `","size":0,"sha256":"` + vecHash + `"},{"path":"` + b + `","size":0,"sha256":"` + vecHash + `"}]}`)
	}
	v.Manifests = []strictVector{
		r("a folder", true, part("")),
		r("a folder with a null hash", true, part(`,"sha256":null`)),
		r("a folder with an empty hash", false, part(`,"sha256":""`)),
		r("a folder with a hash", false, part(`,"sha256":"`+vecHash+`"`)),
		r("a folder with a size", false, part(`,"size":1`)),
		r("a file of no bytes", true, file(0, "0")),
		r("a file of negative zero bytes", false, file(0, "-0")),
		r("a file of negative zeros", false, file(0, "-00")),
		r("a file of zeros", false, file(0, "00")),
		r("a file of zero with an exponent", false, file(0, "0e0")),
		r("a file of negative zero with a fraction", false, file(0, "-0.0")),
		r("a file of zero with a fraction", false, file(0, "0.0")),
		r("a file of one with a fraction", false, file(1, "1.0")),
		r("a manifest of negative zero bytes", false, []byte(`{"size":-0,"parts":[{"path":"f","size":0,"sha256":"`+vecHash+`"}]}`)),
		r("a manifest of negative zero bytes with a folder", false, []byte(`{"size":-0,"parts":[{"path":"d","dir":true}]}`)),
		r("a manifest of zero bytes with a folder", true, []byte(`{"size":0,"parts":[{"path":"d","dir":true}]}`)),
		// Paths compare byte for byte: names in NFC and NFD, or the Kelvin
		// sign and K, are two paths, and a "/" that a combining mark follows
		// still separates names.
		r("two names in NFC and NFD", true, two("\u00e9", "e\u0301")),
		r("the Kelvin sign and K", true, two("\u212a", "K")),
		// A receiver writes a name Windows reserves with "_" after its base
		// (clip.SaveName): two paths that become one, a file that a path
		// goes through once written, and names or paths that grow past the
		// bounds are refused.
		r("two names that are one once written", false, two("COM0.txt", "COM0_.txt")),
		r("two names in other cases once written", true, two("COM0.txt", "com0_.txt")),
		r("a file that another goes through once written", false, two("COM0", "COM0_/f")),
		r("a name of 764 bytes that grows to 765", true, two(`COM0.`+strings.Repeat("a", 759), "f")),
		r("a name of 765 bytes that grows to 766", false, two(`COM0.`+strings.Repeat("a", 760), "f")),
		r("a path of 16384 bytes that grows past it", false, two(strings.Repeat("COM0/", 3275)+strings.Repeat("f", 9), "g")),
		r("a path of 16384 bytes that stays", true, two(strings.Repeat("COMX/", 3275)+strings.Repeat("f", 9), "g")),
		r("a slash before a combining mark", true, []byte(`{"size":0,"parts":[{"path":"a","dir":true},{"path":"a/\u0301b","dir":true}]}`)),
	}
	return v
}

// TestStrictVectors checks Go's verdict on testdata/interop/strict.json,
// which go test -update writes.
func TestStrictVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "strict.json")
	if *update {
		b, err := json.MarshalIndent(makeStrictVectors(), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v strictVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Records) == 0 || len(v.Commands) == 0 || len(v.Manifests) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Records {
		// Records of version 1, valid or not, are refused: version 2
		// reads only its own canonical bodies (docs/records-v2.md).
		if _, err := authority.ParseBody(c.Body); err == nil {
			t.Errorf("record %q of version 1 taken", c.Name)
		}
	}
	for _, c := range v.Commands {
		_, err := parseCommandBody(c.Body)
		if (err == nil) != c.Valid {
			t.Errorf("command %q: valid %v, got %v", c.Name, c.Valid, err)
		}
	}
	// The manifests are in internal/clip, whose test reads them.
}

// A record whose body is not in the canonical form is refused though its
// signature is good: the members that read JSON more loosely would count
// it, the others would not (docs/protocol.md, Conventions, "Signed bodies").
func TestRecordsStrictBody(t *testing.T) {
	ca, err := NewGroupCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tag := Tag(ca.Cert)
	good, err := signRecord(RecordBody{Type: RecordRevoke, Group: tag, TimeMS: 1, Keys: []KeyHash{{1}}}, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	body := string(good.Body)
	sign := func(body string) Record {
		sum := sha256.Sum256([]byte(body))
		sig, err := ca.Key.Sign(rand.Reader, sum[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		return Record{Body: []byte(body), Sig: sig, Chain: [][]byte{}}
	}
	for _, bad := range []string{
		strings.Replace(body, `"type":"revoke"`, `"type":"device","type":"revoke"`, 1),
		strings.Replace(body, `"type":`, `"TYPE":`, 1),
		strings.Replace(body, `"time_ms":1`, `"time_ms":-0`, 1),
		strings.Replace(body, `"time_ms":1`, `"time_ms":1.0`, 1),
		strings.Replace(body, `"group":"`+tag+`"`, `"group":"\u0041`+tag[1:]+`"`, 1),
		strings.Replace(body, `{`, `{ `, 1),
		strings.Replace(body, `}`, `,"unknown":1}`, 1),
		strings.Replace(body, `"time_ms":1,`, ``, 1),
	} {
		if bad == body {
			t.Fatalf("a mutation of %s changed nothing", body)
		}
		s := NewRecords(ca.Cert)
		if ok, err := s.Add(sign(bad)); err == nil || ok {
			t.Errorf("%q taken", bad)
		}
	}
	s := NewRecords(ca.Cert)
	if ok, err := s.Add(sign(body)); err != nil || !ok {
		t.Fatalf("a canonical record refused: %v", err)
	}
}
