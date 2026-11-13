// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package release

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// p256N is the order of P-256.
var p256N = elliptic.P256().Params().N

// strayBits returns s, base64 with padding, with stray bits set in its
// last character before the padding: the same bytes in another form.
func strayBits(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	t := strings.TrimRight(s, "=")
	if len(t) == len(s) {
		return s + "!" // no room: not base64 at all
	}
	last := strings.IndexByte(alphabet, t[len(t)-1])
	return t[:len(t)-1] + string(alphabet[last|1]) + s[len(t):]
}

// Envelope is a release.json written one way, and whether every reader
// takes it (docs/protocol.md, section 16, "Two signatures").
type Envelope struct {
	Name string `json:"name"`
	// Raw is the file's bytes as they come, in base64 in JSON: some are
	// not UTF-8.
	Raw []byte `json:"release"`
	OK  bool   `json:"ok"`
}

// Envelopes returns one signed release.json written in the ways every
// reader must agree on, for the interop vectors and the installers'
// tests. sign signs the same release.json, ES256 and SLH-DSA, anew each
// time it is called. large adds files of about 1 MiB, too large for the
// vectors.
func Envelopes(sign func() (File, error), large bool) ([]Envelope, error) {
	rel, err := sign()
	if err != nil {
		return nil, err
	}
	body := base64.StdEncoding.EncodeToString(rel.Body)
	sig := func(i int) string {
		g := rel.Sigs[i]
		return fmt.Sprintf(`{"alg":%d,"key":"%s","sig":"%s"}`, g.Alg, base64.StdEncoding.EncodeToString(g.Key), base64.StdEncoding.EncodeToString(g.Sig))
	}
	both := sig(0) + "," + sig(1)
	var out []Envelope
	env := func(name, raw string, ok bool) { out = append(out, Envelope{name, []byte(raw), ok}) }
	env("as signed", `{"body":"`+body+`","sigs":[`+both+`]}`, true)
	env("with a member of a later version", `{"body":"`+body+`","sigs":[`+both+`],"later":{"a":[1]}}`, false)
	env("with a signature of a later algorithm with a member of its own", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw==","later":true}]}`, false)
	env("with its body named in capitals", `{"Body":"`+body+`","sigs":[`+both+`]}`, false)
	env("with its body twice", `{"body":"`+body+`","body":"`+body+`","sigs":[`+both+`]}`, false)
	env("with its body broken across lines", `{"body":"`+body[:4]+`\n`+body[4:]+`","sigs":[`+both+`]}`, false)
	env("with sigs null", `{"body":"`+body+`","sigs":null}`, false)
	env("with a signature of a later algorithm without a key", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"sig":"Bw=="}]}`, false)
	env("with a signature of a negative algorithm", `{"body":"`+body+`","sigs":[`+both+`,{"alg":-9,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature of algorithm 0", `{"body":"`+body+`","sigs":[`+both+`,{"alg":0,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature of algorithm 2147483648", `{"body":"`+body+`","sigs":[`+both+`,{"alg":2147483648,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature of algorithm 2147483647", `{"body":"`+body+`","sigs":[`+both+`,{"alg":2147483647,"key":"CQ==","sig":"Bw=="}]}`, true)
	env("with a signature of algorithm 9.5", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9.5,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature whose algorithm is a string", `{"body":"`+body+`","sigs":[`+both+`,{"alg":"9","key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature whose alg is named in capitals", `{"body":"`+body+`","sigs":[`+both+`,{"Alg":9,"key":"CQ==","sig":"Bw=="}]}`, false)
	env("with a signature whose key is null", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":null,"sig":"Bw=="}]}`, false)
	env("with a signature whose alg is given twice", `{"body":"`+body+`","sigs":[{"alg":1,"alg":1,"key":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Key)+`","sig":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Sig)+`"},`+sig(1)+`]}`, false)
	env("with a member of a later version whose name escapes a whole surrogate pair", `{"body":"`+body+`","sigs":[`+both+`],"later\ud83d\ude00":1}`, false)
	env("with a member whose name escapes half a surrogate pair", `{"body":"`+body+`","sigs":[`+both+`],"bod\ud800":1}`, false)
	env("with a signature with a member whose name escapes half a surrogate pair", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw==","\udc00":1}]}`, false)
	env("with a member of a later version given twice", `{"body":"`+body+`","sigs":[`+both+`],"later":1,"later":1}`, false)
	env("with a signature with a member of a later version given twice", `{"body":"`+body+`","sigs":[`+sig(0)[:len(sig(0))-1]+`,"later":1,"later":1},`+sig(1)+`]}`, false)
	env("with a signature of a later algorithm with a member of its own given twice", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw==","later":1,"later":1}]}`, false)
	env("with a member of a later version nested 17 deep, the file's object counted", `{"body":"`+body+`","sigs":[`+both+`],"later":`+strings.Repeat("[", 16)+strings.Repeat("]", 16)+`}`, false)
	env("with a member of a later version nested 18 deep, the file's object counted", `{"body":"`+body+`","sigs":[`+both+`],"later":`+strings.Repeat("[", 17)+strings.Repeat("]", 17)+`}`, false)
	env("with a member of a later version nested 10001 deep", `{"body":"`+body+`","sigs":[`+both+`],"later":`+strings.Repeat("[", 10000)+strings.Repeat("]", 10000)+`}`, false)
	env("with a member of a later version whose name is not UTF-8", `{"body":"`+body+`","sigs":[`+both+`],"lat`+"\xff"+`er":1}`, false)
	env("with a member of a later version whose value is not UTF-8", `{"body":"`+body+`","sigs":[`+both+`],"later":"`+"\xff"+`"}`, false)
	env("with a member of a later version named in capitals", `{"body":"`+body+`","sigs":[`+both+`],"Later":1}`, false)
	env("with a member of a later version that is null", `{"body":"`+body+`","sigs":[`+both+`],"later":null}`, false)
	env("with a member of a later version that is a fraction", `{"body":"`+body+`","sigs":[`+both+`],"later":1.5}`, false)
	env("with its body null", `{"body":null,"sigs":[`+both+`]}`, false)
	env("with spaces between its members", `{ "body" : "`+body+`" , "sigs" : [ `+sig(0)+` , `+sig(1)+` ] }`, false)
	env("with the members of a signature in another order", `{"sigs":[{"sig":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Sig)+`","key":"`+base64.StdEncoding.EncodeToString(rel.Sigs[0].Key)+`","alg":1},`+sig(1)+`],"body":"`+body+`"}`, false)
	env("with a signature of a later algorithm", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CQ==","sig":"Bw=="}]}`, true)
	env("with sigs before body", `{"sigs":[`+both+`],"body":"`+body+`"}`, false)
	env("with the body's first character written as an escape", `{"body":"\u00`+fmt.Sprintf("%02x", body[0])+body[1:]+`","sigs":[`+both+`]}`, false)
	env("with a line break after it", `{"body":"`+body+`","sigs":[`+both+`]}`+"\n", true)
	env("with a carriage return and a line break after it", `{"body":"`+body+`","sigs":[`+both+`]}`+"\r\n", true)
	env("with a carriage return between its members", `{"body":"`+body+`",`+"\r"+`"sigs":[`+both+`]}`, false)
	env("with spaces and a line break before it", " \n"+`{"body":"`+body+`","sigs":[`+both+`]}`, true)
	env("with a byte order mark", "\xef\xbb\xbf"+`{"body":"`+body+`","sigs":[`+both+`]}`, false)
	env("with a second object after it", `{"body":"`+body+`","sigs":[`+both+`]}{}`, false)
	env("inside a list", `[{"body":"`+body+`","sigs":[`+both+`]}]`, false)
	env("with a comma before its closing brace", `{"body":"`+body+`","sigs":[`+both+`],}`, false)
	env("with a signature that is not an object", `{"body":"`+body+`","sigs":[`+both+`,[9]]}`, false)
	env("with a third member that sorts between body and sigs", `{"body":"`+body+`","c":1,"sigs":[`+both+`]}`, false)
	env("with a signature with a fourth member that sorts first", `{"body":"`+body+`","sigs":[{"aaa":1,`+sig(0)[1:]+`,`+sig(1)+`]}`, false)
	env("with a form feed after it", `{"body":"`+body+`","sigs":[`+both+`]}`+"\f", false)
	env("with a no-break space after it", `{"body":"`+body+`","sigs":[`+both+`]}`+"\u00a0", false)
	// A signature over 16 KiB is passed over, one of 16 KiB is checked.
	long := func(n int) string {
		return fmt.Sprintf(`{"alg":1,"key":"%s","sig":"%s"}`, base64.StdEncoding.EncodeToString(rel.Sigs[0].Key), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, n)))
	}
	env("with an ES256 signature of 16385 bytes by the listed half after the pair", `{"body":"`+body+`","sigs":[`+both+`,`+long(16385)+`]}`, true)
	env("with an ES256 signature of 16384 bytes by the listed half after the pair", `{"body":"`+body+`","sigs":[`+both+`,`+long(16384)+`]}`, false)
	// The ES256 signature's DER in other forms of the same numbers.
	der := func(r, s []byte) []byte {
		out := []byte{0x30, byte(4 + len(r) + len(s)), 0x02, byte(len(r))}
		out = append(append(out, r...), 0x02, byte(len(s)))
		return append(out, s...)
	}
	// The count of signatures, base64 in its one form, the one S.
	later := func(n int) string {
		out := ""
		for i := range n {
			out += fmt.Sprintf(`,{"alg":9,"key":"CQ==","sig":"%s"}`, base64.StdEncoding.EncodeToString([]byte{byte(i)}))
		}
		return out
	}
	env("with eight signatures", `{"body":"`+body+`","sigs":[`+both+later(6)+`]}`, true)
	env("with nine signatures", `{"body":"`+body+`","sigs":[`+both+later(7)+`]}`, false)
	env("with a signature's key in base64 with stray bits", `{"body":"`+body+`","sigs":[`+both+`,{"alg":9,"key":"CR==","sig":"Bw=="}]}`, false)
	env("with its body in base64 with stray bits", `{"body":"`+strayBits(body)+`","sigs":[`+both+`]}`, false)
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(rel.Sigs[0].Sig, &rs); err != nil {
		return nil, err
	}
	rs.S.Sub(p256N, rs.S)
	otherS, err := asn1.Marshal(rs)
	if err != nil {
		return nil, err
	}
	env("with its ES256 signature's other S", fmt.Sprintf(`{"body":"%s","sigs":[{"alg":1,"key":"%s","sig":"%s"},%s]}`, body,
		base64.StdEncoding.EncodeToString(rel.Sigs[0].Key), base64.StdEncoding.EncodeToString(otherS), sig(1)), false)
	if large {
		// The whole file at MaxFile and one byte more, a signature of a
		// later algorithm making it up: its number's digits take up what
		// base64 cannot.
		sized := func(n int) string {
			head := `{"body":"` + body + `","sigs":[` + both + `,{"alg":`
			tail := `","sig":"Bw=="}]}`
			room := n - len(head) - len(`,"key":"`) - len(tail)
			digits := 1 + (room-1)%4
			key := base64.StdEncoding.EncodeToString(make([]byte, (room-digits)/4*3))
			return head + strings.Repeat("9", digits) + `,"key":"` + key + tail
		}
		env("of 1 MiB, a signature of a later algorithm making it up", sized(MaxFile), true)
		env("of 1 MiB and one byte, a signature of a later algorithm making it up", sized(MaxFile+1), false)
	}
	// rel signed again until the ES256 signature's R needs a zero byte
	// before it, so that it can also be written without.
	var high File
	var r, sv []byte
	for r == nil {
		var err error
		if high, err = sign(); err != nil {
			return nil, err
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(high.Sigs[0].Sig, &rs); err != nil {
			return nil, err
		}
		if rs.R.BitLen() == 256 {
			r, sv = rs.R.Bytes(), rs.S.Bytes()
			if sv[0] >= 0x80 {
				sv = append([]byte{0}, sv...)
			}
		}
	}
	withDER := func(d []byte) string {
		b64 := base64.StdEncoding.EncodeToString
		return fmt.Sprintf(`{"body":"%s","sigs":[{"alg":1,"key":"%s","sig":"%s"},{"alg":4,"key":"%s","sig":"%s"}]}`,
			b64(high.Body), b64(high.Sigs[0].Key), b64(d), b64(high.Sigs[1].Key), b64(high.Sigs[1].Sig))
	}
	env("signed again, its ES256 signature's R with the zero byte it needs", withDER(der(append([]byte{0}, r...), sv)), true)
	env("signed again, its ES256 signature's R with a zero byte more", withDER(der(append([]byte{0, 0}, r...), sv)), false)
	env("signed again, its ES256 signature's S with a zero byte more", withDER(der(append([]byte{0}, r...), append([]byte{0}, sv...))), false)
	env("signed again, its ES256 signature's R without the zero byte it needs", withDER(der(r, sv)), false)
	return out, nil
}
