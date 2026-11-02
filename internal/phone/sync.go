// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
	"github.com/HunterEwok/clipboardbridge/internal/group"
)

// recentCopy is how recent a computer's copy must be for the button to
// fetch it: the user most likely copied and then picked up the phone.
const recentCopy = 45 * time.Second

// maxBody bounds a request: a text of up to 1 MiB, escaped in JSON.
const maxBody = 7 << 20

// Group is what the iPhone endpoint needs from the member.
type Group interface {
	// Current returns the group's current event, with its age as of now.
	Current() (clip.Event, bool)
	// Local returns the member's own clipboard text and its age.
	Local() (string, clip.Kind, time.Duration, bool)
	// Send makes an event from the iPhone button and writes it to the
	// member's own clipboard.
	Send(text string, kind clip.Kind, via clip.Via) error
	Tokens
}

// Tokens checks the shortcut's tokens.
type Tokens interface {
	// PhoneCA returns the iPhone CA, whose key checks the tokens.
	PhoneCA() *group.CA
	// PhoneRevoked reports whether the phone with this ID was removed
	// from the group (cbb remove).
	PhoneRevoked(phoneID string) bool
}

// checkToken checks a token: the group issued it, and its phone was not
// removed.
func checkToken(t Tokens, token string) error {
	id, err := CheckToken(t.PhoneCA(), token)
	if err != nil {
		return err
	}
	if t.PhoneRevoked(id) {
		return ErrBadToken
	}
	return nil
}

// syncRequest is what the shortcut sends. V may come as a number or, from
// a shortcut built by hand with a text field, as a string.
type syncRequest struct {
	V      json.Number `json:"v"`
	Text   string      `json:"text"`
	Secret bool        `json:"secret,omitempty"`
}

// syncReply is what the shortcut gets: always with HTTP status 200, since
// a shortcut cannot read status codes.
type syncReply struct {
	V         int    `json:"v"`
	Direction string `json:"direction"` // to_iphone, from_iphone, none, unpaired or error
	Copy      string `json:"copy,omitempty"`
	ExpiresIn int    `json:"expires_in"` // seconds a secret copy may stay, 0 for normal text
	Message   string `json:"message"`
}

// SyncHandler serves POST /sync.
func SyncHandler(g Group) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := func(rep syncReply) {
			rep.V = 1
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(rep)
		}
		fail := func(msg string) { reply(syncReply{Direction: "error", Message: msg}) }
		// unpaired tells the shortcut to forget its token and pair again.
		unpaired := func(msg string) { reply(syncReply{Direction: "unpaired", Message: msg}) }
		if r.Method != http.MethodPost {
			fail("the shortcut must POST to /sync")
			return
		}
		token := bearer(r.Header.Get("Authorization"))
		if token == "" {
			unpaired("the shortcut has no token; run cbb pair -phone and the shortcut again")
			return
		}
		if err := checkToken(g, token); err != nil {
			unpaired(ErrBadToken.Error())
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			fail("the text is too large; clipboardbridge carries up to 1 MiB")
			return
		}
		var req syncRequest
		if err := json.Unmarshal(body, &req); err != nil || req.V.String() != "1" {
			fail("the shortcut is from another version of clipboardbridge; install it again")
			return
		}
		rep, err := decide(g, req)
		if err != nil {
			fail(err.Error())
			return
		}
		reply(rep)
	})
}

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
// clipboardbridge://join?code=123456&addr=192.168.1.20:40123&fp=…, which the
// shortcut and the phone apps read alike; later fields can be added without
// breaking either.
func JoinQR(jc JoinCode) string {
	q := url.Values{}
	if len(jc.Addrs) > 0 {
		q["addr"] = jc.Addrs
	}
	if jc.Fingerprint != "" {
		q.Set("fp", jc.Fingerprint)
	}
	// The code goes first, so a person reading the text sees it at once.
	text := "clipboardbridge://join?code=" + url.QueryEscape(jc.Code)
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
	if err != nil || !strings.EqualFold(u.Scheme, "clipboardbridge") || !strings.EqualFold(u.Host, "join") {
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

// bearer returns the token of an Authorization header: "Bearer cb1.…" in
// any case, or the bare token, as a shortcut built by hand may send it.
func bearer(h string) string {
	h = strings.TrimSpace(h)
	if scheme, rest, ok := strings.Cut(h, " "); ok && strings.EqualFold(scheme, "Bearer") {
		h = strings.TrimSpace(rest)
	}
	return h
}

// decide picks the direction, as the design's iPhone button section says.
func decide(g Group, req syncRequest) (syncReply, error) {
	cur, hasCur := g.Current()
	local, localKind, localAge, hasLocal := g.Local()

	// 1. A computer copied something a moment ago: the iPhone gets it.
	// Copies from the iPhone itself, directly or through Universal
	// Clipboard, do not count.
	if hasCur && cur.Via == clip.Copy && !cur.IsMark() && cur.Text != "" &&
		time.Duration(cur.Age)*time.Millisecond < recentCopy && cur.Text != req.Text {
		return toPhone(cur.Text, cur.Kind, time.Duration(cur.Age)*time.Millisecond), nil
	}
	// 2. The iPhone has a new text: it goes to the group and to the
	// member's own clipboard.
	if req.Text != "" && (!hasCur || cur.Text != req.Text) && (!hasLocal || local != req.Text) {
		kind := clip.Text
		if req.Secret {
			kind = clip.Secret
		}
		if err := g.Send(req.Text, kind, clip.Phone); err != nil {
			if errors.Is(err, errTooLarge) {
				return syncReply{}, err
			}
			return syncReply{}, errors.New("the text could not be sent: " + err.Error())
		}
		return syncReply{Direction: "from_iphone", Message: "Sent to the computers"}, nil
	}
	// 3. The member's own clipboard holds another text: the iPhone gets it.
	if hasLocal && local != req.Text {
		return toPhone(local, localKind, localAge), nil
	}
	return syncReply{Direction: "none", Message: "Nothing new to transfer"}, nil
}

var errTooLarge = errors.New("the text is too large")

func toPhone(text string, kind clip.Kind, age time.Duration) syncReply {
	rep := syncReply{Direction: "to_iphone", Copy: text, Message: "Copied to the iPhone"}
	if kind == clip.Secret {
		rep.ExpiresIn = max(1, int((clip.DefaultSecretTTL-age)/time.Second))
		rep.Message = "Copied a password to the iPhone"
	}
	return rep
}
