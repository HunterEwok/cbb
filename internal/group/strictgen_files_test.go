// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The generator of testdata/interop/strict-files.json: the server
// credentials of docs/protocol.md section 18 and the release files of
// section 16, signed bodies in the strict form like records and commands,
// from the tables of those sections. internal/release checks the release
// files.

const (
	// A P-256 key, a P-384 key and the P-256 key with bits after its last
	// byte, as SubjectPublicKeyInfo in base64.
	genP256      = `"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEisTU0kiulUla1IJnCzjqGjJXTjaRtYjaMBcnJkhyA7t34yvhwHB6o8QmvZ+ZzjvjhygF8oLcfmRq6a/qgoX/FA=="`
	genP384      = `"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEMoRALl99rpVZVnqLkr8SIICF/ccy5tmAUUHR6wxVHlxre5pgqiBXi3PKfarow3t4RiDbZ170VvCSVVN5cponfbHOvzaIZwSrttxum3Y4QCPEt6PHgXNwOF49EjfNopH3"`
	genP256Stray = `"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEisTU0kiulUla1IJnCzjqGjJXTjaRtYjaMBcnJkhyA7t34yvhwHB6o8QmvZ+ZzjvjhygF8oLcfmRq6a/qgoX/FB=="`
	genTag       = `"8899aabbccddeeff"`
	// The P-256 key above with its point compressed, which Go's x509
	// refuses.
	genP256Compressed = `"MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACisTU0kiulUla1IJnCzjqGjJXTjaRtYjaMBcnJkhyA7s="`
	genSHA            = `"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"`
	// The P-256 key above with one byte of its point changed, so that the
	// point is not on the curve.
	// genSLH is an SLH-DSA-SHA2-128s key.
	genSLH          = `"MDAwCwYJYIZIAWUDBAMUAyEAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="`
	genP256OffCurve = `"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEisTU0kiulUla1IJnCzjqGjJXTjaRtYjaMBcnJkhyA7t34yvhwHB6/8QmvZ+ZzjvjhygF8oLcfmRq6a/qgoX/FA=="`
)

// genFileVectors are the vectors of strict-files.json.
type genFileVectors struct {
	Credentials []genVector `json:"credentials"`
	Releases    []genVector `json:"releases"`
}

// genTagValues are the values of a tag: 16 of 0-9 and a-f.
func genTagValues() []genValue {
	return []genValue{
		ok("of other digits", `"ffffffffffffffff"`),
		bad("in upper case", `"00112233445566AA"`),
		bad("of 15 characters", `"001122334455667"`),
		bad("of 17 characters", `"00112233445566778"`),
		bad("not hex", `"001122334455667g"`),
		bad("with a line break after it", `"0011223344556677\n"`),
		bad("empty", `""`),
	}
}

// genKeyValues are the values of a P-256 key in SubjectPublicKeyInfo.
func genKeyValues() []genValue {
	return []genValue{
		bad("of a P-384 key", genP384),
		bad("of a compressed point", genP256Compressed),
		bad("of a point not on the curve", genP256OffCurve),
		bad("with stray bits", genP256Stray),
		bad("without padding", strings.TrimRight(genP256, `="`)+`"`),
		bad("not a key", genB64(32, 7)),
		bad("empty", `""`),
	}
}

// genHashes returns a list of n hashes.
func genHashes(n int) string {
	var s []string
	for i := range n {
		s = append(s, genB64(32, byte(i)))
	}
	return "[" + strings.Join(s, ",") + "]"
}

// genListValues are the values of a list of key hashes of at most max.
func genListValues(max int) []genValue {
	return append(genHashListValues(false),
		ok(fmt.Sprintf("of %d", max), genHashes(max)),
		bad(fmt.Sprintf("of %d", max+1), genHashes(max+1)))
}

// credentialKinds returns the credential bodies of section 18.
func credentialKinds() []genKind {
	common := func(typ string) []genField {
		return []genField{
			{"v", jInt, true, []genValue{bad("of 0", "0"), bad("of 2", "2")}},
			{"type", jString, true, genEnum(nil, "later", strings.ToUpper(typ))},
			{"group", jString, true, genTagValues()},
			{"version", jInt, true, []genValue{ok("of 2^63-1", "9223372036854775807"), bad("of 0", "0"), bad("of -1", "-1")}},
			{"expires_ms", jInt, true, []genValue{ok("of 1", "1"), bad("of 0", "0"), bad("of -1", "-1")}},
		}
	}
	base := func(typ string, own ...genMember) genBody {
		return append(genBody{{"v", "1"}, {"type", `"` + typ + `"`}, {"group", genGroup}, {"version", "1"}, {"expires_ms", "1800000000000"}}, own...)
	}
	h := genHashes(1)
	none := func(name, what, value string) genField {
		return genField{name, jArray, false, []genValue{ok("empty", `[]`), bad(what, value)}}
	}
	noTag := genField{"tag", jString, false, []genValue{ok("empty", `""`), bad("of a tag", genTag)}}
	noKey := genField{"key", jString, false, []genValue{ok("empty", `""`), bad("of a key", genP256)}}
	keyed := func(typ string, whole bool) genKind {
		return genKind{section: "credentials", name: typ, max: 16 << 10, strict: true, whole: whole,
			base: base(typ, genMember{"tag", genTag}, genMember{"key", genP256}),
			fields: append(common(typ),
				genField{"tag", jString, true, genTagValues()},
				genField{"key", jString, true, genKeyValues()},
				none("hubs", "of one", h), none("admins", "of one", h), none("members", "of one", h))}
	}
	return []genKind{
		keyed("period", true),
		keyed("server", false),
		{section: "credentials", name: "hubs", max: 16 << 10, strict: true,
			base: base("hubs", genMember{"hubs", genHashes(2)}, genMember{"admins", genHashes(1)}),
			fields: append(common("hubs"), noTag, noKey,
				genField{"hubs", jArray, false, genListValues(MaxCredentialHubs)},
				genField{"admins", jArray, false, genListValues(maxCredentialList)},
				none("members", "of one", h))},
		{section: "credentials", name: "members", max: 16 << 10, strict: true,
			base: base("members", genMember{"members", genHashes(2)}),
			fields: append(common("members"), noTag, noKey,
				none("hubs", "of one", h), none("admins", "of one", h),
				genField{"members", jArray, false, genListValues(MaxCredentialMembers)})},
	}
}

// genVersionValues are the values of a version.
func genVersionValues() []genValue {
	return []genValue{
		ok("of a release candidate", `"1.2.3-rc.4"`),
		ok("of six digits", `"999999.999999.999999-rc.999999"`),
		ok("of zeros", `"0.0.0"`),
		bad("with a v", `"v0.6.0"`),
		bad("of two numbers", `"0.6"`),
		bad("of four numbers", `"0.6.0.1"`),
		bad("with a leading zero", `"0.06.0"`),
		bad("of seven digits", `"1000000.0.0"`),
		bad("of a candidate 0", `"0.6.0-rc.0"`),
		bad("with a line break after it", `"0.6.0\n"`),
		bad("of a beta", `"0.6.0-beta.1"`),
		bad("empty", `""`),
	}
}

func genChannelValues() []genValue {
	return []genValue{
		ok("of one letter", `"a"`),
		ok("of 32 characters", `"a`+strings.Repeat("-", 30)+`9"`),
		bad("of 33 characters", `"a`+strings.Repeat("b", 32)+`"`),
		bad("in upper case", `"Stable"`),
		bad("starting with a digit", `"1a"`),
		bad("with an underscore", `"a_b"`),
		bad("with a line break after it", `"stable\n"`),
		bad("empty", `""`),
	}
}

func genSHAValues() []genValue {
	return []genValue{
		bad("in upper case", strings.ToUpper(genSHA)),
		bad("of 63 characters", genSHA[:64]+`"`),
		bad("of 65 characters", genSHA[:65]+`0"`),
		bad("with a line break after it", genSHA[:65]+`\n"`),
		bad("empty", `""`),
	}
}

func genSeqValues() []genValue {
	return []genValue{ok("of 2^63-1", "9223372036854775807"), bad("of 0", "0"), bad("of -1", "-1")}
}

// genLifetime are the fields time_ms and expires_ms of a file signed at
// 1000 that lives at most max milliseconds.
func genLifetime(max int64) []genField {
	at := func(n int64) string { return strconv.FormatInt(n, 10) }
	return []genField{
		{"time_ms", jInt, true, []genValue{ok("of 0", "0"), bad("of -1", "-1"), bad("of expires_ms", "2000")}},
		{"expires_ms", jInt, true, []genValue{
			ok("at the longest lifetime", at(1000+max)), bad("past the longest lifetime", at(1001+max)),
			bad("of time_ms", "1000"), bad("before time_ms", "999")}},
	}
}

// releaseKinds returns the release files of section 16.
func releaseKinds() []genKind {
	day := int64(24 * 3600 * 1000)
	common := func(typ string) []genField {
		return []genField{
			{"v", jInt, true, []genValue{bad("of 0", "0"), bad("of 2", "2")}},
			{"type", jString, true, genEnum(nil, "later", strings.ToUpper(typ))},
		}
	}
	base := func(typ string, own ...genMember) genBody {
		return append(genBody{{"v", "1"}, {"type", `"` + typ + `"`}}, own...)
	}
	key := func(fields string) string {
		return `{"alg":1,"key":` + genP256 + `,"name":"release key"` + fields + `}`
	}
	keyList := func(n int) string {
		var s []string
		for i := range n {
			s = append(s, `{"alg":1,"key":`+genP256+`,"name":"release key `+strconv.Itoa(i)+`"}`)
		}
		return "[" + strings.Join(s, ",") + "]"
	}
	keys := []genValue{
		ok("of 64", keyList(64)),
		ok("of a status key", `[`+key(`,"use":"status"`)+`]`),
		ok("of a key of a later use", `[`+key(`,"use":"later"`)+`]`),
		ok("of a name of 64 bytes", `[{"alg":1,"key":`+genP256+`,"name":"`+strings.Repeat("k", 64)+`"}]`),
		ok("of an SLH-DSA half", `[`+key("")+`,{"alg":4,"key":`+genSLH+`,"name":"release key"}]`),
		ok("of a key of a later algorithm", `[{"alg":9,"key":`+genB64(32, 7)+`,"name":"k"}]`),
		bad("of 65", keyList(65)),
		bad("of two halves of one algorithm under one name", `[`+key("")+`,`+key("")+`]`),
		bad("of two halves of one algorithm under one name, one use left out", `[`+key("")+`,`+key(`,"use":"release"`)+`]`),
		bad("of two status halves of one algorithm under one name", `[`+key(`,"use":"status"`)+`,`+key(`,"use":"status"`)+`]`),
		ok("of one name under two uses", `[`+key("")+`,`+key(`,"use":"status"`)+`]`),
		ok("of two forwarder pins under one name", `[`+key(`,"use":"forwarder"`)+`,`+key(`,"use":"forwarder"`)+`]`),
		bad("of a negative algorithm", `[{"alg":-1,"key":`+genP256+`,"name":"k"}]`),
		ok("of algorithm 2147483647", `[{"alg":2147483647,"key":"","name":"k"}]`),
		bad("of algorithm 2147483648", `[{"alg":2147483648,"key":"","name":"k"}]`),
		ok("of a key of a later algorithm of 8192 bytes", `[{"alg":9,"key":`+genB64(8192, 7)+`,"name":"k"}]`),
		ok("of an empty key of a later algorithm", `[{"alg":9,"key":"","name":"k"}]`),
		bad("of an empty use", `[`+key(`,"use":""`)+`]`),
		bad("of a key without an algorithm", `[{"key":`+genP256+`,"name":"k"}]`),
		bad("of algorithm 0", `[{"alg":0,"key":`+genP256+`,"name":"k"}]`),
		bad("of a P-256 key as algorithm 4", `[{"alg":4,"key":`+genP256+`,"name":"k"}]`),
		bad("of an SLH-DSA key as algorithm 1", `[{"alg":1,"key":`+genSLH+`,"name":"k"}]`),
		bad("of an algorithm as a string", `[{"alg":"1","key":`+genP256+`,"name":"k"}]`),
		bad("of a compressed key", `[{"alg":1,"key":`+genP256Compressed+`,"name":"k"}]`),
		bad("of a key not on the curve", `[{"alg":1,"key":`+genP256OffCurve+`,"name":"k"}]`),
		bad("empty", `[]`),
		bad("of a P-384 key", `[{"alg":1,"key":`+genP384+`,"name":"k"}]`),
		bad("of a key with stray bits", `[{"alg":1,"key":`+genP256Stray+`,"name":"k"}]`),
		bad("of a key that is not one", `[{"alg":1,"key":`+genB64(32, 7)+`,"name":"k"}]`),
		bad("of a key without a name", `[{"alg":1,"key":`+genP256+`}]`),
		bad("of an empty name", `[{"alg":1,"key":`+genP256+`,"name":""}]`),
		bad("of a name of 65 bytes", `[{"alg":1,"key":`+genP256+`,"name":"`+strings.Repeat("k", 65)+`"}]`),
		bad("of an entry without a key", `[{"alg":1,"name":"k"}]`),
		bad("of a key as a number", `[{"alg":1,"key":1,"name":"k"}]`),
		bad("of an entry as a string", `["k"]`),
	}
	file := func(fields string) string { return `{"name":"cbb.tar.gz","size":3,"sha256":` + genSHA + fields + `}` }
	fileList := func(n int) string {
		var s []string
		for i := range n {
			s = append(s, `{"name":"f`+strconv.Itoa(i)+`","size":3,"sha256":`+genSHA+`}`)
		}
		return "[" + strings.Join(s, ",") + "]"
	}
	bin := func(name string) string { return file(`,"binaries":[{"name":` + name + `,"sha256":` + genSHA + `}]`) }
	files := []genValue{
		ok("of 256", fileList(256)),
		ok("of a file of size 0", `[{"name":"f","size":0,"sha256":`+genSHA+`}]`),
		ok("of a binary", `[`+bin(`"bin/cbb"`)+`]`),
		bad("of 257", fileList(257)),
		bad("of a file without a size", `[{"name":"f","sha256":`+genSHA+`}]`),
		bad("of a name with a line break after it", `[{"name":"f\n","size":3,"sha256":`+genSHA+`}]`),
		bad("of a binary with a line break after it", `[`+bin(`"bin/cbb\n"`)+`]`),
		bad("empty", `[]`),
		bad("of a name twice", `[`+file("")+`,`+file("")+`]`),
		bad("of a path as a name", `[{"name":"../cbb","size":3,"sha256":`+genSHA+`}]`),
		bad("of a name starting with a dot", `[{"name":".cbb","size":3,"sha256":`+genSHA+`}]`),
		bad("of a name of 129 bytes", `[{"name":"`+strings.Repeat("f", 129)+`","size":3,"sha256":`+genSHA+`}]`),
		bad("of a negative size", `[{"name":"f","size":-1,"sha256":`+genSHA+`}]`),
		bad("of a hash in upper case", `[{"name":"f","size":3,"sha256":`+strings.ToUpper(genSHA)+`}]`),
		bad("of a binary out of its folder", `[`+bin(`"a/../../cbb"`)+`]`),
		bad("of a binary with an empty name", `[`+bin(`""`)+`]`),
		bad("of a size as a string", `[{"name":"f","size":"3","sha256":`+genSHA+`}]`),
	}
	docker := []genValue{
		ok("of an image", `{"image":"ghcr.io/x/cbb","digest":"sha256:`+strings.Trim(genSHA, `"`)+`"}`),
		bad("without an image", `{"digest":"sha256:`+strings.Trim(genSHA, `"`)+`"}`),
		bad("of a digest without sha256", `{"image":"x","digest":`+genSHA+`}`),
		bad("of a digest with a line break after it", `{"image":"x","digest":"sha256:`+strings.Trim(genSHA, `"`)+`\n"}`),
		bad("empty", `{}`),
	}
	return []genKind{
		{section: "releases", name: "keys", max: 256 << 10, strict: true, whole: true,
			base: base("keys", genMember{"seq", "1"}, genMember{"time_ms", "1000"}, genMember{"expires_ms", "2000"}, genMember{"keys", keyList(1)}),
			fields: append(append(common("keys"), genField{"seq", jInt, true, genSeqValues()}),
				append(genLifetime(100*day), genField{"keys", jArray, true, keys})...)},
		{section: "releases", name: "release", max: 256 << 10, strict: true,
			base: base("release", genMember{"version", `"0.6.0"`}, genMember{"channel", `"stable"`}, genMember{"time_ms", "1000"},
				genMember{"files", `[` + file("") + `]`}),
			fields: append(common("release"),
				genField{"version", jString, true, genVersionValues()},
				genField{"channel", jString, true, genChannelValues()},
				genField{"time_ms", jInt, true, []genValue{ok("of 0", "0"), ok("of -1", "-1")}},
				genField{"min_from", jString, false, append(genVersionValues()[:3], bad("with a v", `"v0.5.0"`))},
				genField{"files", jArray, true, files},
				genField{"docker", jObject, false, docker})},
		{section: "releases", name: "channel", max: 256 << 10, strict: true,
			base: base("channel", genMember{"channel", `"stable"`}, genMember{"seq", "7"}, genMember{"time_ms", "1000"}, genMember{"expires_ms", "2000"},
				genMember{"release", `"0.6.0"`}, genMember{"release_sha256", genSHA}),
			fields: append(append(common("channel"),
				genField{"channel", jString, true, genChannelValues()},
				genField{"seq", jInt, true, genSeqValues()}),
				append(genLifetime(100*day),
					genField{"release", jString, true, genVersionValues()},
					genField{"release_sha256", jString, true, genSHAValues()})...)},
		{section: "releases", name: "attest-status", max: 256 << 10, strict: true,
			base: base("attest-status", genMember{"seq", "40"}, genMember{"time_ms", "1000"}, genMember{"expires_ms", "2000"},
				genMember{"android_revoked", `["0","1f","9a","c35a2e1e3b46b5a1"]`}),
			fields: append(append(common("attest-status"), genField{"seq", jInt, true, genSeqValues()}),
				append(genLifetime(8*day),
					genField{"source_ms", jInt, false, []genValue{ok("of 1", "1")}},
					genField{"android_revoked", jArray, true, []genValue{
						ok("empty", `[]`),
						ok("of 64 digits", `["`+strings.Repeat("f", 64)+`"]`),
						bad("of 65 digits", `["`+strings.Repeat("f", 65)+`"]`),
						bad("out of order", `["9a","1f"]`),
						bad("of a serial twice", `["1f","1f"]`),
						bad("of a leading zero", `["01f"]`),
						bad("in capitals", `["1F"]`),
						bad("of a line break after a serial", `["1f\n"]`),
						bad("of an empty serial", `[""]`),
						bad("of a number", `[31]`),
					}})...)},
	}
}

// makeGenFileVectors returns the vectors of strict-files.json; each names
// its kind, which tells a reader how to read it.
func makeGenFileVectors() genFileVectors {
	var v genFileVectors
	kinds := func(ks []genKind) []genVector {
		var out []genVector
		for _, k := range ks {
			for _, c := range genKindVectors(k) {
				c.Kind = k.name
				out = append(out, c)
			}
		}
		return out
	}
	v.Credentials, v.Releases = kinds(credentialKinds()), kinds(releaseKinds())
	seen := map[string]bool{}
	for _, l := range [][]genVector{v.Credentials, v.Releases} {
		for _, c := range l {
			if seen[c.Name] {
				panic("two vectors named " + c.Name)
			}
			seen[c.Name] = true
		}
	}
	return v
}

// TestStrictGeneratedFiles checks that testdata/interop/strict-files.json
// is what the tables give (go test -update writes it), and Go's verdict on
// every credential of it.
func TestStrictGeneratedFiles(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "interop", "strict-files.json")
	v := makeGenFileVectors()
	want := encodeSections([]genSection{{"credentials", v.Credentials}, {"releases", v.Releases}})
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
		t.Fatal("strict-files.json is not what the tables give: run go test ./internal/group -run TestStrictGeneratedFiles -update")
	}
	var got genFileVectors
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Credentials {
		_, err := parseCredentialBody(c.Full())
		if (err == nil) != c.Valid {
			t.Errorf("credential %q (%s): valid %v, got %v", c.Name, c.Rule, c.Valid, err)
		}
	}
}
