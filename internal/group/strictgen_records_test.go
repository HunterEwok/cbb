// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package group

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// genAdminCA is a CA certificate, DER in base64, for the recovery record's
// cert: the rows ask that it parse and that admin be its key hash.
const genAdminCA = "MIIBizCCATGgAwIBAgIQIU4ugU5TGPXO8wLdaCqsWTAKBggqhkjOPQQDAjAkMSIwIAYDVQQDExljYmIgZ3JvdXAgcm9vdCAyMDI2LTA5LTIxMB4XDTI2MDkyMDE0MTMyMFoXDTQ2MDkyMTE0MTMyMFowJDEiMCAGA1UEAxMZY2JiIGdyb3VwIHJvb3QgMjAyNi0wOS0yMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHzlZSoWQN5jcrsuJSafFKFo5mEF/aFpfLHCjbR0LJzjk2SAPlK/v79zskO1WcdWJfmp1jCcFPXDnnz/3cxA4jOjRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSSG/WhtadYshu4uDXqfUlAzHEqRDAKBggqhkjOPQQDAgNIADBFAiA5/QdnvYZOGuJAnHBYAwDNT1nIdVZhmyD7bhAJDZvOHAIhAMGwoinRdSd8I2UIY1SgsacNYOVAuhNzgyp2kWviBeXS"

// genAdminHash is the key hash of genAdminCA, in quotes.
func genAdminHash() string {
	der, err := base64.StdEncoding.DecodeString(genAdminCA)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return `"` + base64.StdEncoding.EncodeToString(h[:]) + `"`
}

// genSortedHashes returns n distinct hashes, in quotes, sorted by their
// base64 as the rows want.
func genSortedHashes(n int) []string {
	var out []string
	for i := range n {
		h := sha256.Sum256([]byte(strconv.Itoa(i)))
		out = append(out, `"`+base64.StdEncoding.EncodeToString(h[:])+`"`)
	}
	sort.Strings(out)
	return out
}

// recordKinds returns the record bodies of section 10, "Records", in their
// canonical form.
func recordKinds() []genKind {
	hash := genB64(32, 7)
	nine := genB64(32, 9)
	common := genBody{{"v", "2"}, {"alg", `"es256"`}, {"type", ""}, {"group", genGroup}, {"signer", genB64(32, 5)},
		{"seq", "2"}, {"prev", genB64(32, 6)}, {"time_ms", "1700000000000"}}
	with := func(t string, m ...genMember) genBody {
		b := common.set("type", `"`+t+`"`)
		for _, x := range m {
			b = b.set(x.name, x.value)
		}
		return b
	}
	// Every record has these; the base records have seq 2, so prev is
	// needed.
	commonFields := []genField{
		{"v", jInt, true, []genValue{bad("of 1", "1"), bad("of 3, a later version", "3"), bad("of 0", "0"), bad("of -1", "-1"),
			bad("that wraps to 2 in 32 bits", "4294967298")}},
		{"alg", jString, true, genEnum(nil, "ES256", "es384", "", "es256 ")},
		{"type", jString, true, genEnum(nil, "other", "", "Device", "device ")},
		{"group", jString, true, []genValue{bad("empty", `""`)}},
		{"signer", jString, true, genHashValues()},
		{"seq", jInt, true, []genValue{
			ok("of 2^31-1", "2147483647"), bad("of 2^31", "2147483648"), bad("of 0", "0"), bad("of -1", "-1"),
			bad("of 1 with prev", "1"),
		}},
		{"prev", jString, true, genHashValues()},
		{"time_ms", jInt, true, []genValue{
			ok("of 0", "0"), ok("of -1", "-1"), ok("of 2^53", two53),
			ok("of 2^63-1", "9223372036854775807"), ok("of -2^63", "-9223372036854775808"),
		}},
	}
	seenOne := `[{"key":` + hash + `,"seq":0}]`
	seen := genField{"seen", jArray, true, []genValue{
		bad("empty", `[]`),
		ok("of two", `[{"key":`+hash+`,"seq":3},{"key":`+nine+`,"seq":2147483647}]`),
		bad("not sorted", `[{"key":`+nine+`,"seq":1},{"key":`+hash+`,"seq":1}]`),
		bad("with a key twice", `[{"key":`+hash+`,"seq":1},{"key":`+hash+`,"seq":2}]`),
		bad("with a seq of 2^31", `[{"key":`+hash+`,"seq":2147483648}]`),
		bad("with a seq of -1", `[{"key":`+hash+`,"seq":-1}]`),
		bad("without seq", `[{"key":`+hash+`}]`),
		bad("without key", `[{"seq":1}]`),
		bad("with its members out of order", `[{"seq":1,"key":`+hash+`}]`),
		bad("with an unknown member", `[{"key":`+hash+`,"later":1,"seq":1}]`),
		bad("with a key of 31 bytes", `[{"key":`+genB64(31, 7)+`,"seq":1}]`),
		bad("with a string", `["x"]`),
	}}
	sortedList := func(name string, needed bool) genField {
		return genField{name, jArray, needed, []genValue{
			bad("empty", `[]`),
			ok("of two", `[`+hash+`,`+nine+`]`),
			bad("not sorted", `[`+nine+`,`+hash+`]`),
			bad("with a hash twice", `[`+hash+`,`+hash+`]`),
			bad("with a hash of 31 bytes", `[`+genB64(31, 7)+`]`),
			bad("with a hash without padding", `["`+strings.TrimRight(genB64(32, 7)[1:45], "=")+`"]`),
			bad("with a number", `[1]`),
			bad("with a list", `[[`+hash+`]]`),
		}}
	}
	// The fields of every type: in a type that does not have one, its JSON
	// type is checked.
	all := map[string]genField{
		"device": {"device", jString, false, nil}, "name": {"name", jString, false, nil},
		"role": {"role", jString, false, nil}, "os": {"os", jString, false, nil},
		"key": {"key", jString, false, nil}, "admin": {"admin", jString, false, nil},
		"powers": {"powers", jArray, false, nil}, "commands": {"commands", jArray, false, nil},
		"store": {"store", jString, false, nil}, "kind": {"kind", jString, false, nil},
		"proof": {"proof", jString, false, nil}, "holds_root": {"holds_root", jBool, false, nil},
		"seal": {"seal", jString, false, nil}, "keys": {"keys", jArray, false, nil},
		"seen": {"seen", jArray, false, nil}, "records": {"records", jArray, false, nil},
		"root": {"root", jString, false, nil}, "cert": {"cert", jString, false, nil},
		"takeover_delay_ms": {"takeover_delay_ms", jInt, false, nil}, "key_level": {"key_level", jString, false, nil},
		"heads": {"heads", jArray, false, nil}, "keep": {"keep", jArray, false, nil},
		"hubs": {"hubs", jArray, false, nil},
	}
	var names []string
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	kind := func(name string, base genBody, own ...genField) genKind {
		var others []genField
	next:
		for _, n := range names {
			for _, o := range own {
				if o.name == n {
					continue next
				}
			}
			others = append(others, all[n])
		}
		return genKind{section: "records", name: name, base: base, fields: append(append([]genField{}, commonFields...), own...),
			others: others, strict: true, canonical: true, whole: name == "device"}
	}

	devID := []genValue{
		ok("of other digits", `"ffffffffffffffffffffffffffffffff"`),
		bad("in upper case", `"00112233445566778899AABBCCDDEEFF"`),
		bad("of 31 characters", `"00112233445566778899aabbccddeef"`),
		bad("of 33 characters", `"00112233445566778899aabbccddeeff0"`),
		bad("not hex", `"00112233445566778899aabbccddeefg"`),
		bad("empty", `""`),
		bad("escaped", `"\u0030\u0030112233445566778899aabbccddeeff"`),
	}
	name := []genValue{
		ok("of 64 bytes", `"`+strings.Repeat("a", 64)+`"`),
		ok("of 64 bytes in 32 characters", `"`+strings.Repeat("\u00e9", 32)+`"`),
		ok("of one character", `"a"`),
		ok("with a no-break space", "\"a\u00a0b\""),
		ok("with a line separator", "\"a\u2028b\""),
		ok("with a four-byte character", "\"a\U0001f600b\""),
		ok("with a zero-width space", "\"a\u200bb\""),
		ok("with a solidus", `"a/b"`),
		bad("empty", `""`),
		bad("of 65 bytes", `"`+strings.Repeat("a", 65)+`"`),
		bad("of 65 bytes in 33 characters", `"`+strings.Repeat("\u00e9", 32)+`a"`),
		bad("with a tab", `"a\u0009b"`),
		bad("with a NUL", `"a\u0000b"`),
		bad("with DEL", "\"a\x7fb\""),
		bad("with a C1 control character", "\"a\u0085b\""),
		bad("with the last C1 control character", "\"a\u009fb\""),
		bad("with a letter escaped", `"\u0061"`),
		bad("with a no-break space escaped", `"a\u00a0b"`),
		bad("with a solidus escaped", `"a\/b"`),
		bad("with a tab escaped short", `"a\tb"`),
		bad("with a control character in upper-case hex", `"a\u001Fb"`),
	}
	powers := []genValue{
		ok("of one", `["admit"]`),
		ok("of all eight", `["admit","freeze","hub","remove","remove-admins","renew","takeover","thaw"]`),
		bad("empty", `[]`),
		bad("not sorted", `["renew","admit"]`),
		bad("with a power twice", `["admit","admit"]`),
		bad("with an unknown power", `["admit","fly"]`),
		bad("in upper case", `["Admit"]`),
		bad("with a number", `[1]`),
	}
	commands := []genValue{
		ok("of one", `["paste"]`),
		ok("of all nine", `["action","actions-off","away-off","hub","mode","mute","paste","paste-off","unmute"]`),
		bad("empty", `[]`),
		bad("not sorted", `["paste","mode"]`),
		bad("with a command twice", `["paste","paste"]`),
		bad("with an unknown command", `["reboot"]`),
	}
	free := func(taken ...string) []genValue {
		v := genEnum(taken)
		return append(v, bad("empty", `""`))
	}
	seal := []genValue{
		ok("of 1216 bytes", genB64(1216, 4)),
		bad("of 1215 bytes", genB64(1215, 4)),
		bad("of 1217 bytes", genB64(1217, 4)),
		bad("empty", `""`),
		bad("in base64url", `"`+base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 1216))+`"`),
	}
	device := kind("device",
		with("device", genMember{"device", genDev}, genMember{"name", `"Laptop"`}, genMember{"role", `"full"`},
			genMember{"os", `"linux"`}, genMember{"key", hash}, genMember{"admin", nine}),
		genField{"device", jString, true, devID},
		genField{"name", jString, true, name},
		genField{"role", jString, true, genEnum([]string{"full", "phone", "lite", "watch"}, "linux", "mac", "iphone", "server", "", "Full")},
		genField{"os", jString, false, genEnum([]string{"linux", "windows", "macos", "ios", "android", "watchos", "wearos", "none"}, "", "beos", "Linux", "mac", "iphone")},
		genField{"key", jString, true, genHashValues()},
		genField{"admin", jString, false, genHashValues()},
		genField{"powers", jArray, false, powers},
		genField{"commands", jArray, false, commands},
		// A value the reader does not know counts as the role's default
		// (section 17), so any is taken.
		genField{"store", jString, false, free("file", "hardware", "proven", "rootless", "later")},
		genField{"kind", jString, false, free("android-tee", "android-strongbox", "tpm", "later")},
		genField{"proof", jString, false, free("00ff", "x")},
		genField{"holds_root", jBool, false, []genValue{ok("true", "true"), bad("false", "false")}},
		genField{"seal", jString, false, seal},
	)
	root := genField{"root", jString, true, []genValue{
		ok("of one byte", genB64(1, 1)), ok("of 1024 bytes", genB64(1024, 1)),
		bad("empty", `""`), bad("with stray bits", `"AB=="`), bad("without padding", `"AQ"`),
		bad("in base64url", `"-_-_"`),
	}}
	delay := genField{"takeover_delay_ms", jInt, false, []genValue{
		ok("of 0", "0"), ok("of 7 days", "604800000"), bad("of 7 days and 1 ms", "604800001"), bad("of -1", "-1"),
	}}
	level := genField{"key_level", jString, false, genEnum([]string{"proven", "hardware", "files"}, "", "Files", "file")}
	heads := genField{"heads", jArray, true, []genValue{
		bad("empty", `[]`),
		ok("of two", `[{"id":`+hash+`,"key":`+hash+`,"seq":1},{"id":`+nine+`,"key":`+nine+`,"seq":2147483647}]`),
		bad("not sorted", `[{"id":`+hash+`,"key":`+nine+`,"seq":1},{"id":`+hash+`,"key":`+hash+`,"seq":1}]`),
		bad("with a key twice", `[{"id":`+hash+`,"key":`+hash+`,"seq":1},{"id":`+nine+`,"key":`+hash+`,"seq":2}]`),
		bad("with a seq of 0", `[{"id":`+hash+`,"key":`+hash+`,"seq":0}]`),
		bad("with a seq of 2^31", `[{"id":`+hash+`,"key":`+hash+`,"seq":2147483648}]`),
		bad("without id", `[{"key":`+hash+`,"seq":1}]`),
		bad("with an unknown member", `[{"id":`+hash+`,"key":`+hash+`,"later":1,"seq":1}]`),
	}}
	hubs := genField{"hubs", jArray, true, []genValue{
		ok("of two in the user's order", `["ffffffffffffffffffffffffffffffff","00112233445566778899aabbccddeeff"]`),
		ok("of 16", `[`+strings.Join(genDeviceIDs(16), ",")+`]`),
		bad("of 17", `[`+strings.Join(genDeviceIDs(17), ",")+`]`),
		bad("empty", `[]`),
		bad("with a device twice", `[`+genDev+`,`+genDev+`]`),
		bad("with a device in upper case", `["00112233445566778899AABBCCDDEEFF"]`),
		bad("with a number", `[1]`),
	}}
	admin := genField{"admin", jString, true, genHashValues()}
	return []genKind{
		device,
		kind("revoke", with("revoke", genMember{"keys", `[` + hash + `]`}, genMember{"seen", seenOne}), sortedList("keys", true), seen),
		kind("freeze", with("freeze", genMember{"keys", `[` + hash + `]`}, genMember{"seen", seenOne}), sortedList("keys", true), seen),
		kind("thaw", with("thaw", genMember{"records", `[` + hash + `]`}), sortedList("records", true)),
		kind("claim", with("claim", genMember{"root", genB64(32, 3)}, genMember{"seen", seenOne}), root, seen),
		kind("resolve", with("resolve", genMember{"records", `[` + hash + `]`}), sortedList("records", true)),
		kind("settings", with("settings", genMember{"takeover_delay_ms", "0"}, genMember{"key_level", `"files"`}), delay, level),
		kind("checkpoint", with("checkpoint", genMember{"heads", `[{"id":` + nine + `,"key":` + hash + `,"seq":1}]`}, genMember{"keep", `[` + hash + `]`}),
			heads, sortedList("keep", false)),
		kind("hubs", with("hubs", genMember{"hubs", `[` + genDev + `]`}), hubs),
		kind("recovery", with("recovery", genMember{"admin", genAdminHash()}, genMember{"cert", `"` + genAdminCA + `"`}),
			genField{"admin", jString, true, []genValue{bad("of another key", hash)}},
			genField{"cert", jString, true, []genValue{bad("of another certificate", genB64(32, 1)), bad("empty", `""`)}}),
		kind("handover", with("handover", genMember{"admin", hash}), admin),
	}
}

// genDeviceIDs returns n distinct device IDs, in quotes.
func genDeviceIDs(n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf(`"%032x"`, i+1))
	}
	return out
}

// recordVectors returns the vectors of section 10 beyond each field's row:
// the canonical form, and the sizes of a body.
func recordVectors() []genVector {
	base := recordKinds()[0].base.sorted()
	b := base.bytes()
	var out []genVector
	add := func(rule, what string, valid bool, body []byte) {
		out = append(out, genVector{Name: "device: " + what, Rule: rule, Valid: valid, Body: body})
	}
	reversed := append(genBody{}, base...)
	sort.SliceStable(reversed, func(i, j int) bool { return reversed[i].name > reversed[j].name })
	add("form/canonical", "with its members in reverse order", false, reversed.bytes())
	swapped := append(genBody{}, base...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	add("form/canonical", "with two members swapped", false, swapped.bytes())
	add("form/canonical", "with a space after a colon", false, []byte(strings.Replace(string(b), `":`, `": `, 1)))
	add("form/canonical", "with a newline at the end", false, append(append([]byte{}, b...), '\n'))
	add("form/canonical", "with a name escaped", false, []byte(strings.Replace(string(b), `"alg"`, `"\u0061lg"`, 1)))

	// The sizes: 8 KiB for every type but a checkpoint, padded in a
	// claim's root; 64 KiB for a checkpoint, of hashes in keep.
	claim := recordKinds()[4]
	for _, n := range []int{8 << 10, 8<<10 + 1} {
		v := genSized(claim, n, "root")
		out = append(out, genVector{Name: fmt.Sprintf("claim: a body of %d bytes", n), Rule: "size/records", Valid: n == 8<<10,
			Body: v.Body, PadAt: v.PadAt, Pad: v.Pad})
	}
	checkpoint := recordKinds()[7]
	for _, n := range []int{8<<10 + 1, 64 << 10, 64<<10 + 1} {
		out = append(out, genVector{Name: fmt.Sprintf("checkpoint: a body of %d bytes", n), Rule: "size/records",
			Valid: n <= 64<<10, Body: genCheckpointOf(checkpoint, n)})
	}
	return out
}

// genSized returns k's base with the string field padded in base64 to
// exactly n bytes: the pad, in fours of "a", goes at pad_at, and time_ms
// takes the bytes left over.
func genSized(k genKind, n int, field string) genVector {
	for digits := 1; digits <= 19; digits++ {
		b := k.base.set(field, `""`).set("time_ms", strings.Repeat("1", digits)).sorted().bytes()
		if pad := n - len(b); pad > 0 && pad%4 == 0 {
			at := strings.Index(string(b), `"`+field+`":""`) + len(field) + 4
			return genVector{Body: b, PadAt: at, Pad: pad}
		}
	}
	panic("genSized: no time_ms fits")
}

// genCheckpointOf returns a checkpoint of exactly n bytes: its keep holds
// as many hashes as fit, and the seqs of its four heads (1 to 10 digits
// each) and its time_ms (1 to 19) take the bytes left over.
func genCheckpointOf(k genKind, n int) []byte {
	heads := genSortedHashes(4)
	body := func(keep []string, seqs [4]int, timeDigits int) []byte {
		var hs []string
		for i, h := range heads {
			hs = append(hs, `{"id":`+h+`,"key":`+h+`,"seq":`+strings.Repeat("1", seqs[i])+`}`)
		}
		b := k.base.set("keep", "["+strings.Join(keep, ",")+"]").set("heads", "["+strings.Join(hs, ",")+"]")
		return b.set("time_ms", strings.Repeat("1", timeDigits)).sorted().bytes()
	}
	keep := genSortedHashes(n / 47)
	ones := [4]int{1, 1, 1, 1}
	for len(body(keep, ones, 1)) > n {
		keep = keep[:len(keep)-1]
	}
	left := n - len(body(keep, ones, 1))
	// Each hash in keep takes 47 bytes, and the digits take up to 54.
	seqs := ones
	for i := range seqs {
		more := min(left, 9)
		seqs[i] += more
		left -= more
	}
	b := body(keep, seqs, 1+left)
	if len(b) != n {
		panic(fmt.Sprintf("genCheckpointOf: %d bytes, want %d", len(b), n))
	}
	return b
}
