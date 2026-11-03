// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package invite

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the interop test vectors")

// vectorFile is testdata/interop/invites.json: texts that parse, with what
// they hold, and texts that must not, with the reason. The Rust core
// (cbb_core::invite) reads the same file.
type vectorFile struct {
	Valid   []validVector   `json:"valid"`
	Refused []refusedVector `json:"refused"`
}

type validVector struct {
	Name        string          `json:"name"`
	Text        string          `json:"text"`
	Group       string          `json:"group"`
	Hub         string          `json:"hub"`
	HubKey      string          `json:"hub_key"`
	Endpoints   []string        `json:"endpoints"`
	GuestKey    string          `json:"guest_key"`
	GuestPSK    string          `json:"guest_psk"`
	Secret      string          `json:"secret"`
	Expires     int64           `json:"expires"`
	Obfuscation json.RawMessage `json:"obfuscation"`
}

type refusedVector struct {
	Name   string `json:"name"`
	Text   string `json:"text"`
	Reason Reason `json:"reason"`
}

func key(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32)))
}

const obf = `{"jc":4,"jmin":40,"jmax":300,"s1":20,"s2":30,"s3":16,"s4":24,"h1":"100-200","h2":"1073741840-1073807375","h3":"2147483664-2147483664","h4":"3221225488-4294967295","header_protection_key":"` + "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=" + `"}`

// fields is the JSON of the base invitation, field by field, in the order
// Go writes them; a vector replaces or drops fields.
func fields() [][2]string {
	return [][2]string{
		{"v", `1`},
		{"g", `"0f1e2d3c4b5a6978"`},
		{"h", `"0123456789abcdef0123456789abcdef"`},
		{"hk", `"` + key(1) + `"`},
		{"ep", `["203.0.113.7:8764","[2001:db8::7]:8764"]`},
		{"k", `"` + key(2) + `"`},
		{"psk", `"` + key(3) + `"`},
		{"s", `"BwcHBwcHBwcHBwcHBwcHBw=="`},
		{"exp", `1800000000`},
	}
}

func build(set map[string]string, drop ...string) string {
	var b strings.Builder
	b.WriteString("{")
	first := true
	seen := map[string]bool{}
	add := func(k, v string) {
		if !first {
			b.WriteString(",")
		}
		first = false
		b.WriteString(`"` + k + `":` + v)
	}
	for _, f := range fields() {
		seen[f[0]] = true
		if contains(drop, f[0]) {
			continue
		}
		if v, ok := set[f[0]]; ok {
			add(f[0], v)
		} else {
			add(f[0], f[1])
		}
	}
	for _, k := range []string{"o", "x", "dup"} {
		if v, ok := set[k]; ok && !seen[k] {
			if k == "dup" {
				b.WriteString(v)
				continue
			}
			add(k, v)
		}
	}
	b.WriteString("}")
	return wrap(b.String())
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func wrap(js string) string { return prefix + base64.StdEncoding.EncodeToString([]byte(js)) }

func makeVectors() vectorFile {
	var v vectorFile
	base := validVector{Group: "0f1e2d3c4b5a6978", Hub: "0123456789abcdef0123456789abcdef",
		HubKey: key(1), Endpoints: []string{"203.0.113.7:8764", "[2001:db8::7]:8764"},
		GuestKey: key(2), GuestPSK: key(3), Secret: "BwcHBwcHBwcHBwcHBwcHBw==", Expires: 1_800_000_000,
		Obfuscation: json.RawMessage("null")}
	add := func(name, text string, change func(*validVector)) {
		c := base
		c.Name, c.Text = name, text
		if change != nil {
			change(&c)
		}
		v.Valid = append(v.Valid, c)
	}
	add("plain", build(nil), nil)
	add("white space around", " \t\n"+build(nil)+"\r\n", nil)
	add("obfuscated", build(map[string]string{"o": obf}), func(c *validVector) { c.Obfuscation = json.RawMessage(obf) })
	add("one IPv4 address", build(map[string]string{"ep": `["192.0.2.1:1"]`}), func(c *validVector) { c.Endpoints = []string{"192.0.2.1:1"} })
	eight := `["192.0.2.1:1","192.0.2.2:2","192.0.2.3:3","192.0.2.4:4","192.0.2.5:5","192.0.2.6:6","192.0.2.7:7","[::ffff:192.0.2.8]:65535"]`
	add("eight addresses", build(map[string]string{"ep": eight}), func(c *validVector) {
		c.Endpoints = []string{"192.0.2.1:1", "192.0.2.2:2", "192.0.2.3:3", "192.0.2.4:4", "192.0.2.5:5", "192.0.2.6:6", "192.0.2.7:7", "[::ffff:192.0.2.8]:65535"}
	})
	long := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 64)))
	add("a secret of 64 bytes", build(map[string]string{"s": `"` + long + `"`}), func(c *validVector) { c.Secret = long })
	add("fields in another order", wrap(`{"exp":1800000000,"s":"BwcHBwcHBwcHBwcHBwcHBw==","psk":"`+key(3)+`","k":"`+key(2)+`","ep":["203.0.113.7:8764","[2001:db8::7]:8764"],"hk":"`+key(1)+`","h":"0123456789abcdef0123456789abcdef","g":"0f1e2d3c4b5a6978","v":1}`), nil)

	refuse := func(name, text string, r Reason) {
		v.Refused = append(v.Refused, refusedVector{Name: name, Text: text, Reason: r})
	}
	good := build(nil)
	refuse("another scheme", "cbb://join?code=123456", NotInvitation)
	refuse("empty", "", NotInvitation)
	refuse("prefix in capitals", "CBB://invite#"+strings.TrimPrefix(good, prefix), NotInvitation)
	refuse("no-break space around", "\u00a0"+good, NotInvitation)
	refuse("cut", good[:len(good)-5], Damaged)
	refuse("padding after the padding", good+"==", Damaged)
	refuse("without padding", prefix+base64.RawStdEncoding.EncodeToString([]byte(`{"v":1,"g":"??","h":">>>"}`)), Damaged)
	refuse("base64url", prefix+base64.URLEncoding.EncodeToString([]byte(`{"v":1,"g":"???","h":">>>"}`)), Damaged)
	refuse("white space inside", good[:40]+" "+good[40:], Damaged)
	refuse("line break inside", good[:40]+"\n"+good[40:], Damaged)
	refuse("not JSON", wrap(`v=1`), Damaged)
	refuse("an array", wrap(`[1]`), Damaged)
	refuse("version 2", build(map[string]string{"v": `2`}), Version)
	refuse("version as a string", build(map[string]string{"v": `"1"`}), Damaged)
	refuse("version 1.0", build(map[string]string{"v": `1.0`}), Damaged)
	refuse("no version", build(nil, "v"), Damaged)
	refuse("unknown field", build(map[string]string{"x": `1`}), Damaged)
	refuse("field twice", build(map[string]string{"dup": `,"g":"0f1e2d3c4b5a6978"`}), Damaged)
	refuse("field name in capitals", wrap(strings.Replace(mustJSON(good), `"hk"`, `"HK"`, 1)), Damaged)
	refuse("null", build(map[string]string{"o": `null`}), Damaged)
	refuse("no expiry", build(nil, "exp"), Damaged)
	refuse("no secret", build(nil, "s"), Damaged)
	refuse("number as a string", build(map[string]string{"exp": `"1800000000"`}), Damaged)
	refuse("expiry 1e9", build(map[string]string{"exp": `1e9`}), Damaged)
	refuse("expiry 0", build(map[string]string{"exp": `0`}), BadExpiry)
	refuse("expiry negative", build(map[string]string{"exp": `-1`}), BadExpiry)
	refuse("group short", build(map[string]string{"g": `"0f1e2d3c4b5a697"`}), BadGroup)
	refuse("group in capitals", build(map[string]string{"g": `"0F1E2D3C4B5A6978"`}), BadGroup)
	refuse("group empty", build(map[string]string{"g": `""`}), BadGroup)
	refuse("hub not hex", build(map[string]string{"h": `"0123456789abcdef0123456789abcdeg"`}), BadHub)
	refuse("hub long", build(map[string]string{"h": `"0123456789abcdef0123456789abcdef0"`}), BadHub)
	refuse("hub key short", build(map[string]string{"hk": `"` + base64.StdEncoding.EncodeToString(make([]byte, 31)) + `"`}), BadKey)
	refuse("guest key zero", build(map[string]string{"k": `"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"`}), BadKey)
	refuse("key without padding", build(map[string]string{"psk": `"` + strings.TrimRight(key(3), "=") + `"`}), BadKey)
	refuse("key in base64url", build(map[string]string{"hk": `"` + base64.URLEncoding.EncodeToString([]byte(strings.Repeat("\xfb", 32))) + `"`}), BadKey)
	refuse("key with stray bits", build(map[string]string{"hk": `"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF="`}), BadKey)
	refuse("no address", build(map[string]string{"ep": `[]`}), BadEndpoints)
	refuse("nine addresses", build(map[string]string{"ep": strings.TrimSuffix(eight, `]`) + `,"192.0.2.9:9"]`}), BadEndpoints)
	refuse("address without port", build(map[string]string{"ep": `["192.0.2.1"]`}), BadEndpoints)
	refuse("port 0", build(map[string]string{"ep": `["192.0.2.1:0"]`}), BadEndpoints)
	refuse("port too large", build(map[string]string{"ep": `["192.0.2.1:65536"]`}), BadEndpoints)
	refuse("host name", build(map[string]string{"ep": `["cbb.example:8764"]`}), BadEndpoints)
	refuse("IPv6 without brackets", build(map[string]string{"ep": `["2001:db8::7:8764"]`}), BadEndpoints)
	refuse("IPv6 with a zone", build(map[string]string{"ep": `["[fe80::1%eth0]:8764"]`}), BadEndpoints)
	refuse("IPv6 not compressed", build(map[string]string{"ep": `["[2001:db8:0:0:0:0:0:7]:8764"]`}), BadEndpoints)
	refuse("IPv6 in capitals", build(map[string]string{"ep": `["[2001:DB8::7]:8764"]`}), BadEndpoints)
	refuse("IPv4 with a leading zero", build(map[string]string{"ep": `["192.0.2.01:8764"]`}), BadEndpoints)
	refuse("port with a leading zero", build(map[string]string{"ep": `["192.0.2.1:08764"]`}), BadEndpoints)
	refuse("address not a string", build(map[string]string{"ep": `[1]`}), Damaged)
	refuse("secret of 15 bytes", build(map[string]string{"s": `"` + base64.StdEncoding.EncodeToString(make([]byte, 15)) + `"`}), BadSecret)
	refuse("secret of 65 bytes", build(map[string]string{"s": `"` + base64.StdEncoding.EncodeToString(make([]byte, 65)) + `"`}), BadSecret)
	obfWith := func(from, to string) string { return build(map[string]string{"o": strings.Replace(obf, from, to, 1)}) }
	refuse("obfuscation empty", build(map[string]string{"o": `{}`}), BadObfuscation)
	refuse("obfuscation unknown field", build(map[string]string{"o": strings.Replace(obf, `{`, `{"i1":"x",`, 1)}), Damaged)
	refuse("obfuscation without s4", obfWith(`"s4":24,`, ``), BadObfuscation)
	refuse("too many junk packets", obfWith(`"jc":4`, `"jc":17`), BadObfuscation)
	refuse("junk sizes reversed", obfWith(`"jmin":40`, `"jmin":301`), BadObfuscation)
	refuse("padding too small", obfWith(`"s1":20`, `"s1":15`), BadObfuscation)
	refuse("handshake sizes alike", obfWith(`"s2":30`, `"s2":76`), BadObfuscation)
	refuse("ranges overlap", obfWith(`"h1":"100-200"`, `"h1":"100-1073741840"`), BadObfuscation)
	refuse("range at WireGuard's types", obfWith(`"h1":"100-200"`, `"h1":"4-200"`), BadObfuscation)
	refuse("range reversed", obfWith(`"h1":"100-200"`, `"h1":"200-100"`), BadObfuscation)
	refuse("range with a sign", obfWith(`"h1":"100-200"`, `"h1":"+100-200"`), BadObfuscation)
	refuse("range with a leading zero", obfWith(`"h1":"100-200"`, `"h1":"0100-200"`), BadObfuscation)
	refuse("range with more after it", obfWith(`"h1":"100-200"`, `"h1":"100-200x"`), BadObfuscation)
	refuse("range with spaces", obfWith(`"h1":"100-200"`, `"h1":"100 - 200"`), BadObfuscation)
	refuse("range above 32 bits", obfWith(`"h4":"3221225488-4294967295"`, `"h4":"3221225488-4294967296"`), BadObfuscation)
	refuse("header key zero", obfWith(`BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=`, base64.StdEncoding.EncodeToString(make([]byte, 32))), BadObfuscation)
	return v
}

func mustJSON(text string) string {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, prefix))
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestVectors writes (with -update) and checks testdata/interop/invites.json.
func TestVectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "invites.json")
	if *update {
		data, err := json.MarshalIndent(makeVectors(), "", "\t")
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
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	for i := range v.Valid {
		var b bytes.Buffer
		if err := json.Compact(&b, v.Valid[i].Obfuscation); err != nil {
			t.Fatal(err)
		}
		v.Valid[i].Obfuscation = b.Bytes()
	}
	if !reflect.DeepEqual(v, makeVectors()) {
		t.Fatal("invites.json is out of date: go test ./internal/invite -run TestVectors -update")
	}
	for _, c := range v.Valid {
		in, err := Parse(c.Text)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		var eps []string
		for _, e := range in.Endpoints {
			eps = append(eps, e.String())
		}
		b64 := base64.StdEncoding.EncodeToString
		got := validVector{Name: c.Name, Text: c.Text, Group: in.Group, Hub: in.Hub, HubKey: b64(in.HubKey[:]),
			Endpoints: eps, GuestKey: b64(in.GuestKey[:]), GuestPSK: b64(in.GuestPSK[:]), Secret: b64(in.Secret),
			Expires: in.Expires.Unix(), Obfuscation: json.RawMessage("null")}
		if in.Obfuscation != nil {
			o, err := json.Marshal(in.Obfuscation)
			if err != nil {
				t.Fatal(err)
			}
			got.Obfuscation = o
		}
		if !reflect.DeepEqual(got, c) {
			t.Errorf("%s: got %+v, want %+v", c.Name, got, c)
		}
		// What Go writes, it reads back the same.
		again, err := Parse(in.String())
		if err != nil || !reflect.DeepEqual(again, in) {
			t.Errorf("%s: written again: %v", c.Name, err)
		}
	}
	for _, c := range v.Refused {
		_, err := Parse(c.Text)
		var e *Error
		if !errors.As(err, &e) || e.Reason != c.Reason {
			t.Errorf("%s: %v, want %s", c.Name, err, c.Reason)
		}
	}
}
