// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package phone holds the join QR code that cbb pair shows and the phone
// apps scan.
package phone

import (
	"net"
	"net/url"
	"strings"
)

// A JoinCode is what the QR code of cbb pair carries: the code, the
// addresses where the joining computer listens, and the fingerprint of its
// certificate (pair.CertFingerprint).
type JoinCode struct {
	Code        string
	Addrs       []string // host:port, best first
	Fingerprint string
}

// maxJoinAddrs bounds the addresses a member dials for one QR code.
const maxJoinAddrs = 4

// JoinQR returns the text of the QR code that cbb pair shows: a URL,
// cbb://join?code=123456&addr=192.168.1.20:40123&fp=…, which the
// phone apps read; later fields can be added without breaking them.
func JoinQR(jc JoinCode) string {
	q := url.Values{}
	if len(jc.Addrs) > 0 {
		q["addr"] = jc.Addrs
	}
	if jc.Fingerprint != "" {
		q.Set("fp", jc.Fingerprint)
	}
	// The code goes first, so a person reading the text sees it at once.
	text := "cbb://join?code=" + url.QueryEscape(jc.Code)
	if len(q) > 0 {
		text += "&" + q.Encode()
	}
	return text
}

// ParseJoinQR returns what the text of a join QR code carries, and whether
// the text is one. Unknown query fields are ignored, and at most four
// addresses are kept.
func ParseJoinQR(s string) (JoinCode, bool) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || !strings.EqualFold(u.Scheme, "cbb") || !strings.EqualFold(u.Host, "join") {
		return JoinCode{}, false
	}
	// Only percent escapes are decoded, never a + as a space, as the phone
	// kits read the text: a fingerprint's base64 may hold a +.
	q := url.Values{}
	for item := range strings.SplitSeq(u.RawQuery, "&") {
		k, v, _ := strings.Cut(item, "=")
		k, err1 := url.PathUnescape(k)
		v, err2 := url.PathUnescape(v)
		if err1 == nil && err2 == nil && k != "" {
			q[k] = append(q[k], v)
		}
	}
	jc := JoinCode{Code: q.Get("code"), Fingerprint: q.Get("fp")}
	for _, a := range q["addr"] {
		if _, _, err := net.SplitHostPort(a); err == nil && len(jc.Addrs) < maxJoinAddrs {
			jc.Addrs = append(jc.Addrs, a)
		}
	}
	return jc, jc.Code != ""
}
