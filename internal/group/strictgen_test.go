// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/HunterEwok/clipboardbridge/internal/authority"
)

// The generator of testdata/interop/strict-generated.json: from the tables
// of docs/protocol.md ("Signed bodies" in Conventions, the record fields of
// section 10, the command fields of section 15 and the manifest of section
// 4), a valid body of every kind and, for each of its fields, the changes a
// member must refuse or take. Each vector names its rule, the row of a
// table, so that a member that disagrees says which row it reads otherwise.
// The verdicts come from the tables, never from what one implementation
// does; strict.json keeps the vectors written by hand.

// A genVector is one body of strict-generated.json. A body of more than a
// few kilobytes is written short: pad bytes "a" go in at pad_at.
type genVector struct {
	Name  string `json:"name"`
	Rule  string `json:"rule"`
	Valid bool   `json:"valid"`
	Body  []byte `json:"body"`
	PadAt int    `json:"pad_at,omitempty"`
	Pad   int    `json:"pad,omitempty"`
	// Kind names the body's kind where the reader needs it.
	Kind string `json:"kind,omitempty"`
}

// Full returns the body with its padding.
func (v genVector) Full() []byte {
	if v.Pad == 0 {
		return v.Body
	}
	b := append([]byte{}, v.Body[:v.PadAt]...)
	b = append(b, bytes.Repeat([]byte("a"), v.Pad)...)
	return append(b, v.Body[v.PadAt:]...)
}

type genVectors struct {
	Records   []genVector `json:"records"`
	Commands  []genVector `json:"commands"`
	Manifests []genVector `json:"manifests"`
}

// A genMember is one member of a body as written: its name and its value,
// raw JSON.
type genMember struct{ name, value string }

// A genBody is a body as its members, in order.
type genBody []genMember

func (b genBody) bytes() []byte {
	var s strings.Builder
	s.WriteByte('{')
	for i, m := range b {
		if i > 0 {
			s.WriteByte(',')
		}
		s.WriteString(`"` + m.name + `":` + m.value)
	}
	s.WriteByte('}')
	return []byte(s.String())
}

func (b genBody) get(name string) (string, bool) {
	for _, m := range b {
		if m.name == name {
			return m.value, true
		}
	}
	return "", false
}

// set returns b with name's value replaced, or with name added last.
func (b genBody) set(name, value string) genBody {
	out := append(genBody{}, b...)
	for i, m := range out {
		if m.name == name {
			out[i].value = value
			return out
		}
	}
	return append(out, genMember{name, value})
}

// sorted returns b with its members in bytewise order of their names.
func (b genBody) sorted() genBody {
	out := append(genBody{}, b...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (b genBody) del(name string) genBody {
	var out genBody
	for _, m := range b {
		if m.name != name {
			out = append(out, m)
		}
	}
	return out
}

func (b genBody) rename(name, to string) genBody {
	out := append(genBody{}, b...)
	for i, m := range out {
		if m.name == name {
			out[i].name = to
		}
	}
	return out
}

// A genValue is a value of a field and whether a member takes the body
// with it.
type genValue struct {
	what  string
	value string
	valid bool
}

func ok(what, value string) genValue  { return genValue{what, value, true} }
func bad(what, value string) genValue { return genValue{what, value, false} }

// JSON types, for the values of the wrong type.
const (
	jString = "string"
	jInt    = "integer"
	jBool   = "boolean"
	jArray  = "array"
	jObject = "object"
)

var genWrongType = map[string]string{
	jString: `"x"`,
	jInt:    `1`,
	jBool:   `true`,
	jArray:  `["x"]`,
	jObject: `{"x":1}`,
}

// A genField is a row of a table: a field of a body kind, its JSON type,
// whether the body must have it, and the values that test its range.
type genField struct {
	name     string
	typ      string
	required bool
	values   []genValue
}

// A genKind is one kind of body: its valid body, its fields and its size
// limit.
type genKind struct {
	section string // records, commands or manifests
	name    string // device, revoke, ...: the vectors' prefix
	base    genBody
	fields  []genField
	others  []genField // the other types' fields, whose JSON type alone is tested here
	max     int        // the longest body; 0: no limit of its own
	strict  bool
	whole   bool // the rules of the body as a whole are tested on this kind
	// canonical bodies are taken only in their canonical form, with no
	// member their kind does not know (records, section 10): members in
	// bytewise order of their names, no whitespace, no escape but \", \\
	// and \u00XX below U+0020.
	canonical bool
}

// put returns b's bytes as k writes its bodies: a canonical kind's members
// in order.
func (k genKind) put(b genBody) []byte {
	if k.canonical {
		b = b.sorted()
	}
	return b.bytes()
}

const (
	two53 = "9007199254740992"
	two63 = "9223372036854775808"
	two64 = "18446744073709551616"
)

func genB64(n int, b byte) string {
	return `"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, n)) + `"`
}

// genHashValues are the values of a 32-byte hash in standard base64.
func genHashValues() []genValue {
	h := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	return []genValue{
		ok("of other bytes", genB64(32, 0xfe)),
		bad("of 31 bytes", genB64(31, 7)),
		bad("of 33 bytes", genB64(33, 7)),
		bad("empty", `""`),
		bad("without padding", `"`+strings.TrimRight(h, "=")+`"`),
		bad("with stray bits", `"`+h[:42]+`x="`),
		bad("with a newline escaped", `"`+h[:20]+`\n`+h[20:]+`"`),
		bad("in base64url", `"`+base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))+`"`),
		bad("not base64", `"`+strings.Repeat("!", 43)+`="`),
	}
}

// genHashListValues are the values of an array of 32-byte hashes, of which
// the body needs one at least when nonEmpty.
func genHashListValues(nonEmpty bool) []genValue {
	h := genB64(32, 7)
	v := []genValue{
		{"empty", `[]`, !nonEmpty},
		ok("of two", `[`+h+`,`+genB64(32, 9)+`]`),
		ok("of the same hash twice", `[`+h+`,`+h+`]`),
		bad("with a hash of 31 bytes", `[`+h+`,`+genB64(31, 7)+`]`),
		bad("with a hash with stray bits", `["`+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))[:42]+`x="]`),
		bad("with a number", `[`+h+`,1]`),
		bad("with a list", `[[`+h+`]]`),
	}
	return v
}

// genIntForm are the numbers written in a form signed bodies refuse.
func genIntForm() []genValue {
	return []genValue{
		bad("of negative zero", `-0`),
		bad("of negative zeros", `-00`),
		bad("with an exponent", `1e3`),
		bad("with a capital exponent", `1E3`),
		bad("with a fraction", `1.0`),
		bad("of zero with a fraction", `0.0`),
		bad("with a leading zero", `01`),
		bad("with a plus sign", `+1`),
		bad("of a minus sign", `-`),
		bad("of 2^63", two63),
		bad("of 2^64", two64),
		bad("of -2^63-1", `-9223372036854775809`),
	}
}

// genStringForm are the strings written in a form signed bodies refuse.
func genStringForm() []genValue {
	return []genValue{
		bad("with a raw control character", "\"a\tb\""),
		bad("with a lone high surrogate", `"a\ud800b"`),
		bad("with a lone low surrogate", `"a\udc00b"`),
		bad("with an unknown escape", `"a\xb"`),
		bad("with a short escape", `"a\u00e"`),
		bad("of invalid UTF-8", "\"a\xffb\""),
		bad("of overlong UTF-8", "\"a\xc0\xafb\""),
		bad("with a surrogate in UTF-8", "\"a\xed\xa0\x80b\""),
	}
}

// genDeviceIDValues are the values of a device ID.
func genDeviceIDValues() []genValue {
	return []genValue{
		ok("of other digits", `"ffffffffffffffffffffffffffffffff"`),
		bad("in upper case", `"00112233445566778899AABBCCDDEEFF"`),
		bad("of 31 characters", `"00112233445566778899aabbccddeef"`),
		bad("of 33 characters", `"00112233445566778899aabbccddeeff0"`),
		bad("not hex", `"00112233445566778899aabbccddeefg"`),
		bad("empty", `""`),
		ok("escaped", `"\u0030\u0030112233445566778899aabbccddeeff"`),
	}
}

func genEnum(taken []string, refused ...string) []genValue {
	var v []genValue
	for _, s := range taken {
		v = append(v, ok(fmt.Sprintf("%q", s), `"`+s+`"`))
	}
	for _, s := range refused {
		v = append(v, bad(fmt.Sprintf("%q", s), `"`+s+`"`))
	}
	return v
}

const (
	genGroup = `"0011223344556677"`
	genDev   = `"00112233445566778899aabbccddeeff"`
	genOther = `"ffeeddccbbaa99887766554433221100"`
	genID    = `"0123456789abcdef0123456789abcdef"`
)

// commandKinds returns the command bodies of section 15.
func commandKinds() []genKind {
	common := genBody{{"v", "1"}, {"type", ""}, {"group", genGroup}, {"by", genOther}, {"to", genDev},
		{"id", genID}, {"time_ms", "1000"}, {"expires_ms", "20000"}}
	with := func(t string, m ...genMember) genBody {
		b := common.set("type", `"`+t+`"`)
		for _, x := range m {
			b = b.set(x.name, x.value)
		}
		return b
	}
	id := []genValue{
		ok("of other digits", `"ffffffffffffffffffffffffffffffff"`),
		bad("in upper case", `"0123456789ABCDEF0123456789abcdef"`),
		bad("of 31 characters", `"0123456789abcdef0123456789abcde"`),
		bad("of 33 characters", `"0123456789abcdef0123456789abcdef0"`),
		bad("not hex", `"0123456789abcdef0123456789abcdeg"`),
		bad("empty", `""`),
	}
	commonFields := []genField{
		{"v", jInt, true, []genValue{bad("of 0", "0"), bad("of 2", "2"), bad("that wraps in 32 bits", "4294967297")}},
		{"type", jString, true, genEnum(nil, "other", "", "Mode", "paste_off")},
		{"group", jString, true, nil},
		{"by", jString, true, genDeviceIDValues()},
		{"to", jString, true, genDeviceIDValues()},
		{"id", jString, true, id},
		// expires_ms is 20000: time_ms from -10000 to 19999 would do, but
		// a time before 1970 is refused.
		{"time_ms", jInt, true, []genValue{
			ok("of 0", "0"), ok("of 19999", "19999"), bad("of 20000, the expiry", "20000"), bad("of -1", "-1"),
			bad("of -2^63", "-9223372036854775808"), bad("of 2^53", two53),
		}},
		{"expires_ms", jInt, true, []genValue{
			ok("30 s after the time", "31000"), ok("1 ms after the time", "1001"), bad("30 s and 1 ms after the time", "31001"),
			bad("at the time", "1000"), bad("before the time", "999"), bad("of 2^63-1", "9223372036854775807"),
			bad("of -1", "-1"),
		}},
	}
	// The fields of the other types, empty or absent unless the type's
	// own rows say otherwise.
	mode := genField{"mode", jString, false, []genValue{ok("empty", `""`), bad("of own", `"own"`)}}
	hub := genField{"hub", jObject, false, []genValue{bad("empty", `{}`), bad("of a forwarder", `{"endpoints":["192.0.2.1:8764"]}`)}}
	enter := genField{"enter", jBool, false, []genValue{ok("false", `false`), bad("true", `true`)}}
	kind := genField{"kind", jString, false, []genValue{ok("empty", `""`), bad("of text", `"text"`)}}
	text := genField{"text", jString, false, []genValue{ok("empty", `""`), bad("of a", `"a"`)}}
	action := genField{"action", jString, false, []genValue{ok("empty", `""`), bad("of lock", `"lock"`)}}
	fields := func(own ...genField) []genField {
		f := append([]genField{}, commonFields...)
		f = append(f, own...)
	next:
		for _, o := range []genField{mode, hub, enter, kind, text, action} {
			for _, x := range own {
				if x.name == o.name {
					continue next
				}
			}
			f = append(f, o)
		}
		return f
	}
	key := genB64(32, 5)
	client := func(dev string) string {
		return `{"device":"` + dev + `","key":` + key + `,"psk":` + genB64(32, 6) + `}`
	}
	clients := func(n int) string {
		var c []string
		for i := range n {
			c = append(c, client(fmt.Sprintf("%032x", i)))
		}
		return `[` + strings.Join(c, ",") + `]`
	}
	endpoints := func(n int) string {
		var e []string
		for i := range n {
			e = append(e, fmt.Sprintf(`"192.0.2.%d:8764"`, i+1))
		}
		return `[` + strings.Join(e, ",") + `]`
	}
	fwd := `"forwarder":{"endpoint":"cbb.example:8764","key":"AAAA"}`
	hubValues := []genValue{
		ok("of a forwarder", `{`+fwd+`}`),
		ok("of one address", `{"endpoints":["192.0.2.1:8764"]}`),
		ok("of 8 addresses", `{"endpoints":`+endpoints(8)+`}`),
		ok("of a forwarder and 8 addresses", `{`+fwd+`,"endpoints":`+endpoints(8)+`}`),
		ok("of a forwarder and no clients", `{`+fwd+`,"clients":[]}`),
		ok("of 256 clients", `{`+fwd+`,"clients":`+clients(256)+`}`),
		ok("with an unknown member", `{`+fwd+`,"later":{"a":1}}`),
		ok("with an unknown member of a client", `{`+fwd+`,"clients":[{"device":"`+fmt.Sprintf("%032x", 1)+`","key":`+key+`,"psk":`+key+`,"later":1}]}`),
		bad("empty", `{}`),
		bad("of no address", `{"endpoints":[]}`),
		bad("of 9 addresses", `{"endpoints":`+endpoints(9)+`}`),
		bad("of a forwarder and 9 addresses", `{`+fwd+`,"endpoints":`+endpoints(9)+`}`),
		bad("of 257 clients", `{`+fwd+`,"clients":`+clients(257)+`}`),
		bad("of a forwarder without an address", `{"forwarder":{"endpoint":"","key":"AAAA"}}`),
		bad("of a forwarder without a key", `{"forwarder":{"endpoint":"cbb.example:8764","key":""}}`),
		bad("of a forwarder as a string", `{"forwarder":"cbb.example:8764"}`),
		bad("of an address as a number", `{"endpoints":[1]}`),
		bad("of a client twice", `{`+fwd+`,"clients":[`+client(fmt.Sprintf("%032x", 1))+`,`+client(fmt.Sprintf("%032x", 1))+`]}`),
		bad("of a client without a device ID", `{`+fwd+`,"clients":[`+client("x")+`]}`),
		bad("of a client in upper case", `{`+fwd+`,"clients":[`+client(strings.Repeat("A", 32))+`]}`),
		bad("of a client's key of 31 bytes", `{`+fwd+`,"clients":[{"device":"`+fmt.Sprintf("%032x", 1)+`","key":`+genB64(31, 5)+`,"psk":`+key+`}]}`),
		bad("of a client's preshared key of 33 bytes", `{`+fwd+`,"clients":[{"device":"`+fmt.Sprintf("%032x", 1)+`","key":`+key+`,"psk":`+genB64(33, 5)+`}]}`),
		bad("of a client's key with stray bits", `{`+fwd+`,"clients":[{"device":"`+fmt.Sprintf("%032x", 1)+`","key":"`+strings.TrimSuffix(strings.Trim(key, `"`), "=")[:42]+`x=","psk":`+key+`}]}`),
		bad("of a client without a key", `{`+fwd+`,"clients":[{"device":"`+fmt.Sprintf("%032x", 1)+`","psk":`+key+`}]}`),
		bad("of a client as a list", `{`+fwd+`,"clients":[[1]]}`),
	}
	pasteText := []genValue{
		ok("of a line break", `"a\nb"`),
		ok("of a surrogate pair", `"\ud83d\ude00"`),
		ok("escaped", `"\u0061\u00e9"`),
		bad("empty", `""`),
	}
	actionName := []genValue{
		ok("of 32 characters", `"`+"a"+strings.Repeat("-", 30)+"9"+`"`),
		ok("of one letter", `"a"`),
		ok("with digits and dashes", `"lock-2"`),
		bad("empty", `""`),
		bad("of 33 characters", `"`+strings.Repeat("a", 33)+`"`),
		bad("starting with a digit", `"2lock"`),
		bad("starting with a dash", `"-lock"`),
		bad("in upper case", `"Lock"`),
		bad("with an underscore", `"lock_screen"`),
		bad("with a space", `"lock screen"`),
		bad("of a letter with an accent", `"\u00e9"`),
	}
	return []genKind{
		{section: "commands", name: "mode", max: 64 << 10, strict: true, base: with("mode", genMember{"mode", `"own"`}),
			fields: fields(genField{"mode", jString, true, []genValue{
				ok("of shared", `"shared"`), ok("of receive", `"receive"`), ok("of send", `"send"`), bad("empty", `""`),
			}})},
		{section: "commands", name: "hub", max: 64 << 10, strict: true, base: with("hub", genMember{"hub", `{` + fwd + `}`}),
			fields: fields(genField{"hub", jObject, true, hubValues})},
		{section: "commands", name: "paste", max: 2 << 20, strict: true,
			base: with("paste", genMember{"mode", `"paste"`}, genMember{"kind", `"text"`}, genMember{"text", `"hello"`}),
			fields: fields(
				genField{"mode", jString, true, []genValue{ok("of type", `"type"`), bad("empty", `""`), bad("of own", `"own"`), bad("in upper case", `"Paste"`)}},
				genField{"kind", jString, true, []genValue{ok("of secret", `"secret"`), bad("empty", `""`), bad("of image", `"image"`)}},
				genField{"text", jString, true, pasteText},
				genField{"enter", jBool, false, []genValue{ok("true", `true`), ok("false", `false`)}},
			)},
		{section: "commands", name: "paste-off", max: 64 << 10, strict: true, whole: true, base: with("paste-off"), fields: fields()},
		{section: "commands", name: "actions-off", max: 64 << 10, strict: true, base: with("actions-off"), fields: fields()},
		{section: "commands", name: "away-off", max: 64 << 10, strict: true, base: with("away-off"), fields: fields()},
		{section: "commands", name: "action", max: 64 << 10, strict: true, base: with("action", genMember{"action", `"lock"`}),
			fields: fields(genField{"action", jString, true, actionName})},
	}
}

// manifestKinds returns the manifests of section 4, "Media": they are not
// signed bodies, so only their numbers have the strict form.
func manifestKinds() []genKind {
	h := genB64(32, 7)
	png := `{"type":"image/png","size":3,"sha256":` + h + `}`
	part := func(m string) string { return `[` + m + `]` }
	data := genBody{{"size", "3"}, {"parts", part(png)}}
	files := genBody{{"size", "3"}, {"parts", `[{"path":"d","dir":true},{"path":"d/f","size":3,"sha256":` + h + `}]`}}
	file := func(path string) string {
		return `[{"path":` + path + `,"size":3,"sha256":` + h + `}]`
	}
	size := append([]genValue{bad("of 2, less than its parts", "2"), bad("of 4, more than its parts", "4"), bad("of -3", "-3")}, genIntForm()...)
	partOf := func(fields string) string { return part(`{"type":"image/png"` + fields + `}`) }
	dataParts := []genValue{
		ok("of the three types", `[`+png+`,{"type":"image/jpeg","size":0,"sha256":`+h+`},{"type":"text/html","size":0,"sha256":`+h+`}]`),
		ok("with an unknown member", partOf(`,"size":3,"sha256":`+h+`,"later":{"a":1}`)),
		bad("empty", `[]`),
		bad("of an unknown type", part(`{"type":"image/gif","size":3,"sha256":`+h+`}`)),
		bad("of a type twice", `[`+png+`,{"type":"image/png","size":0,"sha256":`+h+`}]`),
		bad("of a part without a hash", partOf(`,"size":3`)),
		bad("of a hash of 31 bytes", partOf(`,"size":3,"sha256":`+genB64(31, 7))),
		bad("of an empty hash", partOf(`,"size":3,"sha256":""`)),
		bad("of a type as a number", part(`{"type":1,"size":3,"sha256":`+h+`}`)),
		bad("of a size as a string", partOf(`,"size":"3","sha256":`+h)),
		bad("of a negative size", partOf(`,"size":-1,"sha256":`+h)),
		bad("of a size of negative zero", partOf(`,"size":-0,"sha256":`+h)),
		bad("of a size with a fraction", partOf(`,"size":3.0,"sha256":`+h)),
		bad("of a size with an exponent", partOf(`,"size":3e0,"sha256":`+h)),
		bad("of a type and a path", partOf(`,"path":"f","size":3,"sha256":`+h)),
		bad("of a type and a folder", partOf(`,"dir":true,"size":3,"sha256":`+h)),
		bad("of a part as a list", `[[1]]`),
	}
	fileParts := []genValue{
		ok("of one file", file(`"f"`)),
		ok("of a name of 255 bytes", file(`"`+strings.Repeat("a", 255)+`"`)),
		ok("of a name with a dot inside", file(`"a.b"`)),
		ok("of a name in another script", file("\"\u0444\u0430\u0439\u043b\"")),
		ok("of a name like a reserved one", file(`"CONSOLE"`)),
		ok("of a folder with a null hash", `[{"path":"d","dir":true,"sha256":null},{"path":"d/f","size":3,"sha256":`+h+`}]`),
		ok("of a file that is not a folder", `[{"path":"f","dir":false,"size":3,"sha256":`+h+`}]`),
		bad("of a name of 256 bytes", file(`"`+strings.Repeat("a", 256)+`"`)),
		bad("of an empty path", file(`""`)),
		bad("of an empty name", file(`"d//f"`)),
		bad("of a path starting with a slash", file(`"/f"`)),
		bad("of a name of a dot", file(`"."`)),
		bad("of a name of two dots", file(`"d/../f"`)),
		bad("of a name ending in a dot", file(`"f."`)),
		bad("of a name ending in a space", file(`"f "`)),
		bad("of a backslash", file(`"d\\f"`)),
		bad("of a colon", file(`"d:f"`)),
		bad("of an asterisk", file(`"f*"`)),
		bad("of a question mark", file(`"f?"`)),
		bad("of a quotation mark", file(`"f\""`)),
		bad("of a less-than sign", file(`"f<"`)),
		bad("of a pipe", file(`"f|"`)),
		bad("of a control character", file(`"f\u0001"`)),
		bad("of DEL", file(`"f\u007f"`)),
		bad("of a C1 control character", file(`"f\u0085"`)),
		bad("of CON", file(`"CON"`)),
		bad("of con.txt", file(`"con.txt"`)),
		bad("of COM1", file(`"COM1"`)),
		bad("of LPT9", file(`"d/lpt9.log"`)),
		bad("of NUL", file(`"NUL"`)),
		bad("of a path twice", `[{"path":"f","size":3,"sha256":`+h+`},{"path":"f","size":0,"sha256":`+h+`}]`),
		bad("of a file inside a file", `[{"path":"f","size":3,"sha256":`+h+`},{"path":"f/g","size":0,"sha256":`+h+`}]`),
		bad("of a folder with a size", `[{"path":"d","dir":true,"size":1},{"path":"d/f","size":2,"sha256":`+h+`}]`),
		bad("of a folder with a hash", `[{"path":"d","dir":true,"sha256":`+h+`},{"path":"d/f","size":3,"sha256":`+h+`}]`),
		bad("of a folder with an empty hash", `[{"path":"d","dir":true,"sha256":""},{"path":"d/f","size":3,"sha256":`+h+`}]`),
		bad("of a file and clipboard data", `[{"path":"f","size":3,"sha256":`+h+`},{"type":"image/png","size":0,"sha256":`+h+`}]`),
		bad("of a folder as a string", `[{"path":"d","dir":"true"},{"path":"d/f","size":3,"sha256":`+h+`}]`),
		bad("of a path as a number", `[{"path":1,"size":3,"sha256":`+h+`}]`),
		bad("of a path of 4097 bytes", file(`"`+strings.Repeat(strings.Repeat("a", 255)+"/", 16)+"a"+`"`)),
	}
	return []genKind{
		{section: "manifests", name: "clipboard data", base: data, fields: []genField{
			{"size", jInt, true, size},
			{"parts", jArray, true, dataParts},
		}},
		{section: "manifests", name: "files", base: files, fields: []genField{
			{"size", jInt, true, nil},
			{"parts", jArray, true, fileParts},
		}},
	}
}

// genCommon names the fields every body of a section has.
var genCommon = map[string]map[string]bool{
	"records":  {"v": true, "alg": true, "type": true, "group": true, "signer": true, "seq": true, "prev": true, "time_ms": true},
	"commands": {"v": true, "type": true, "group": true, "by": true, "to": true, "id": true, "time_ms": true, "expires_ms": true},
}

// genKindVectors returns the vectors of one kind of body.
func genKindVectors(k genKind) []genVector {
	var out []genVector
	// whole is set for the rules of the body as a whole: each body they
	// take has whitespace or a member no kind knows, which a canonical
	// kind refuses.
	whole := false
	add := func(rule, what string, valid bool, body []byte) {
		if whole && k.canonical {
			valid = false
		}
		out = append(out, genVector{Name: k.name + ": " + what, Rule: rule, Valid: valid, Body: body})
	}
	base := k.put(k.base)
	row := func(f string) string {
		if k.section == "manifests" {
			return "manifests/" + f
		}
		return k.section + "/" + k.name + "/" + f
	}
	form := func(f string) string { return "form/" + f }
	add(row("body"), "valid", true, base)
	for _, f := range k.others {
		wrong := jInt
		if f.typ != jString {
			wrong = jString
		}
		add(row(f.name), f.name+" as a "+wrong, false, k.put(k.base.set(f.name, genWrongType[wrong])))
	}
	for _, f := range k.fields {
		cur, present := k.base.get(f.name)
		if present {
			add(row(f.name), f.name+" missing", !f.required, k.put(k.base.del(f.name)))
		}
		for _, t := range []string{jString, jInt, jBool, jArray, jObject} {
			if t != f.typ {
				add(row(f.name), f.name+" as a "+t, false, k.put(k.base.set(f.name, genWrongType[t])))
			}
		}
		if !k.strict {
			for _, v := range f.values {
				add(row(f.name), f.name+" "+v.what, v.valid, k.put(k.base.set(f.name, v.value)))
			}
			continue
		}
		if !k.whole && genCommon[k.section][f.name] {
			// The form of the fields every body of the section has is
			// tested on one kind; their rows on every kind.
			for _, v := range f.values {
				add(row(f.name), f.name+" "+v.what, v.valid, k.put(k.base.set(f.name, v.value)))
			}
			continue
		}
		if !present {
			// An absent field is written with a value of its type.
			cur = map[string]string{jString: `""`, jInt: "0", jBool: "false", jArray: "[]", jObject: "{}"}[f.typ]
		}
		add(form("null"), f.name+" null", false, k.put(k.base.set(f.name, "null")))
		add(form("names"), f.name+" written twice", false, append(k.base.set(f.name, cur), genMember{f.name, cur}).bytes())
		add(form("names"), f.name+" with its name in upper case", false, k.put(k.base.set(f.name, cur).rename(f.name, strings.ToUpper(f.name))))
		add(form("names"), f.name+" with its name escaped", false, k.put(k.base.set(f.name, cur).rename(f.name, `\u00`+fmt.Sprintf("%x", f.name[0])+f.name[1:])))
		switch f.typ {
		case jInt:
			for _, v := range genIntForm() {
				add(form("numbers"), f.name+" "+v.what, false, k.put(k.base.set(f.name, v.value)))
			}
		case jString:
			if f.required || present {
				for _, v := range genStringForm() {
					add(form("strings"), f.name+" "+v.what, false, k.put(k.base.set(f.name, v.value)))
				}
			}
		}
		for _, v := range f.values {
			add(row(f.name), f.name+" "+v.what, v.valid, k.put(k.base.set(f.name, v.value)))
		}
	}
	if !k.strict {
		return out
	}
	if k.max > 0 {
		// A body of exactly max bytes, padded in an unknown member, and one
		// byte more.
		for _, n := range []int{k.max, k.max + 1} {
			b := k.put(k.base.set("later", `""`))
			v := genVector{Name: fmt.Sprintf("%s: a body of %d bytes", k.name, n), Rule: "size/" + k.section,
				Valid: n == k.max, Body: b, PadAt: len(b) - 2, Pad: n - len(b)}
			out = append(out, v)
		}
	}
	if !k.whole {
		return out
	}
	whole = true
	// The rules of the body as a whole, the same for every kind of a
	// section.
	add(form("object"), "with spaces and line breaks", true, []byte(" \t\r\n"+strings.ReplaceAll(string(base), `,"`, ", \n\t\"")+"\r\n "))
	add(form("object"), "with a byte order mark", false, append([]byte("\xef\xbb\xbf"), base...))
	add(form("object"), "with more after the object", false, append(append([]byte{}, base...), []byte(`{}`)...))
	add(form("object"), "with a comma after the object", false, append(append([]byte{}, base...), ','))
	add(form("object"), "with a NUL after the object", false, append(append([]byte{}, base...), 0))
	add(form("object"), "with a form feed around the object", false, append([]byte("\f"), base...))
	add(form("object"), "in an array", false, []byte("["+string(base)+"]"))
	add(form("object"), "with a trailing comma", false, append(base[:len(base)-1:len(base)-1], []byte(",}")...))
	add(form("object"), "cut short", false, base[:len(base)-1])
	add(form("unknown"), "with an unknown member", true, k.put(k.base.set("later", `"x"`)))
	add(form("unknown"), "with an unknown nested object", true, k.put(k.base.set("later", `{"a":{"b":[1,-2,true,false,"s",{}]}}`)))
	add(form("unknown"), "with an unknown member of every type", true, k.put(k.base.set("later", `[0,-9223372036854775808,9223372036854775807,"",[],{}]`)))
	add(form("null"), "with a null in an unknown member", false, k.put(k.base.set("later", `[null]`)))
	add(form("numbers"), "with a negative zero in an unknown member", false, k.put(k.base.set("later", `{"a":[-0]}`)))
	add(form("numbers"), "with a fraction in an unknown member", false, k.put(k.base.set("later", `[1.5]`)))
	add(form("numbers"), "with 2^63 in an unknown member", false, k.put(k.base.set("later", `[`+two63+`]`)))
	add(form("names"), "with a member twice in an unknown member", false, k.put(k.base.set("later", `{"a":1,"a":1}`)))
	add(form("names"), "with an upper case name in an unknown member", false, k.put(k.base.set("later", `{"A":1}`)))
	add(form("names"), "with an empty name", false, k.put(k.base.set("later", `{"":1}`)))
	add(form("names"), "with a name of 64 characters", true, k.put(k.base.set(strings.Repeat("a", 64), `1`)))
	add(form("names"), "with a name of 65 characters", false, k.put(k.base.set(strings.Repeat("a", 65), `1`)))
	add(form("names"), "with a name with a dash", false, k.put(k.base.set("la-ter", `1`)))
	add(form("names"), "with a name with a Kelvin sign", false, k.put(k.base.set("\u212aey", `1`)))
	add(form("depth"), "nested 16 deep", true, k.put(k.base.set("later", strings.Repeat("[", 16)+strings.Repeat("]", 16))))
	add(form("depth"), "nested 17 deep", false, k.put(k.base.set("later", strings.Repeat("[", 17)+strings.Repeat("]", 17))))
	add(form("depth"), "nested 17 deep in objects", false, k.put(k.base.set("later", strings.Repeat(`{"a":`, 17)+"1"+strings.Repeat("}", 17))))
	for _, s := range genStringForm() {
		add(form("strings"), "with an unknown member "+s.what, false, k.put(k.base.set("later", s.value)))
	}
	add(form("strings"), "with an unknown member of a surrogate pair", true, k.put(k.base.set("later", `"\ud83d\ude00"`)))
	add(form("strings"), "with an unknown member of C0 controls escaped", true, k.put(k.base.set("later", `"\u0000\u001f\b\f\n\r\t\"\\\/"`)))
	add(form("strings"), "with an unknown member of upper case escapes", true, k.put(k.base.set("later", `"\u00E9\uD83D\uDE00"`)))
	add(form("utf8"), "with an unknown member of four-byte UTF-8", true, k.put(k.base.set("later", "\"\xf0\x9f\x98\x80\"")))
	add(form("utf8"), "with an unknown member of UTF-8 above U+10FFFF", false, k.put(k.base.set("later", "\"\xf4\x90\x80\x80\"")))
	add(form("utf8"), "with an unknown member of a cut UTF-8 sequence", false, k.put(k.base.set("later", "\"\xe2\x82\"")))
	add(form("utf8"), "with an unknown member of a lone continuation byte", false, k.put(k.base.set("later", "\"\x80\"")))
	return out
}

// makeGenVectors returns the vectors of strict-generated.json.
func makeGenVectors() genVectors {
	var v genVectors
	for _, k := range recordKinds() {
		v.Records = append(v.Records, genKindVectors(k)...)
	}
	v.Records = append(v.Records, recordVectors()...)
	for _, k := range commandKinds() {
		v.Commands = append(v.Commands, genKindVectors(k)...)
	}
	// The texts of paste commands at their limits, padded in the text.
	paste := func(mode string, n int, valid bool) genVector {
		b := []byte(`{"v":1,"type":"paste","group":` + genGroup + `,"by":` + genOther + `,"to":` + genDev + `,"id":` + genID +
			`,"time_ms":1000,"expires_ms":20000,"mode":"` + mode + `","kind":"text","text":""}`)
		return genVector{Name: fmt.Sprintf("paste: a text of %d bytes to %s", n, mode), Rule: "commands/paste/text",
			Valid: valid, Body: b, PadAt: len(b) - 2, Pad: n}
	}
	v.Commands = append(v.Commands,
		paste("paste", 1<<20, true), paste("paste", 1<<20+1, false),
		paste("type", 4<<10, true), paste("type", 4<<10+1, false))
	for _, k := range manifestKinds() {
		v.Manifests = append(v.Manifests, genKindVectors(k)...)
	}
	// The limits of a manifest's size.
	big := func(n string, valid bool) genVector {
		return genVector{Name: "clipboard data: a part of " + n + " bytes", Rule: "manifests/size", Valid: valid,
			Body: []byte(`{"size":` + n + `,"parts":[{"type":"image/png","size":` + n + `,"sha256":` + genB64(32, 7) + `}]}`)}
	}
	v.Manifests = append(v.Manifests, big("0", true), big("1073741824", true), big("1073741825", false), big(two53, false))
	seen := map[string]bool{}
	for _, l := range [][]genVector{v.Records, v.Commands, v.Manifests} {
		for _, c := range l {
			if seen[c.Name] {
				panic("two vectors named " + c.Name)
			}
			seen[c.Name] = true
		}
	}
	return v
}

// A genSection is a named list of vectors.
type genSection struct {
	name string
	l    []genVector
}

// encodeSections writes the vectors one to a line, so that a change to the
// tables shows as a change of those lines.
func encodeSections(sections []genSection) []byte {
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, s := range sections {
		fmt.Fprintf(&b, "  %q: [\n", s.name)
		for j, c := range s.l {
			line, err := json.Marshal(c)
			if err != nil {
				panic(err)
			}
			b.WriteString("    ")
			b.Write(line)
			if j < len(s.l)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString("  ]")
		if i < len(sections)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.Bytes()
}

func encodeGenVectors(v genVectors) []byte {
	return encodeSections([]genSection{{"records", v.Records}, {"commands", v.Commands}, {"manifests", v.Manifests}})
}

// TestStrictGenerated checks that testdata/interop/strict-generated.json is
// what the tables give (go test -update writes it), and Go's verdict on
// every record and command of it; internal/clip checks the manifests.
func TestStrictGenerated(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "strict-generated.json")
	want := encodeGenVectors(makeGenVectors())
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatal("strict-generated.json is not what the tables give: run go test ./internal/group -run TestStrictGenerated -update")
	}
	var v genVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Records {
		_, err := authority.ParseBody(c.Full())
		if (err == nil) != c.Valid {
			t.Errorf("record %q (%s): valid %v, got %v", c.Name, c.Rule, c.Valid, err)
		}
	}
	for _, c := range v.Commands {
		_, err := parseCommandBody(c.Full())
		if (err == nil) != c.Valid {
			t.Errorf("command %q (%s): valid %v, got %v", c.Name, c.Rule, c.Valid, err)
		}
	}
}

// TestStrictMutants checks Go's verdict on the mutant vectors
// (testdata/interop/strict-mutants-*.json): valid bodies changed byte by
// byte, each with the verdict of the tables of docs/protocol.md.
func TestStrictMutants(t *testing.T) {
	n := 0
	for i := 1; ; i++ {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", fmt.Sprintf("strict-mutants-%d.json", i)))
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var v genVectors
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
		for _, c := range v.Records {
			// Records of version 1 are refused, whatever the mutation.
			if _, err := authority.ParseBody(c.Full()); err == nil {
				t.Errorf("record %q of version 1 taken", c.Name)
			}
			n++
		}
		for _, c := range v.Commands {
			_, err := parseCommandBody(c.Full())
			if (err == nil) != c.Valid {
				t.Errorf("command %q (%s): valid %v, got %v", c.Name, c.Rule, c.Valid, err)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no mutant vectors")
	}
}
