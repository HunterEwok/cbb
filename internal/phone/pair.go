// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/group"
	"github.com/HunterEwok/cbb/internal/pair"
	"github.com/HunterEwok/cbb/internal/uptime"
)

// Window is an open pairing window for an iPhone: a six-digit code that the
// user types on the pairing page, after trusting the iPhone CA. Like a
// computer's window it is open for five minutes, closes after a success or
// the third wrong code, and its time counts sleep.
type Window struct {
	code []byte
	ca   *group.CA

	mu       sync.Mutex
	expires  time.Duration
	failures int
	err      error // why it closed
	phoneID  string
	done     chan struct{}
	uptime   func() time.Duration
}

// OpenWindow opens a pairing window for the code.
func OpenWindow(ca *group.CA, code string) (*Window, error) {
	code, err := pair.NormalizeCode(code)
	if err != nil {
		return nil, err
	}
	if ca == nil || ca.Key == nil {
		return nil, errors.New("phone: only a Linux member that holds the iPhone CA can pair an iPhone")
	}
	return &Window{code: []byte(code), ca: ca, expires: uptime.Now() + pair.Lifetime, done: make(chan struct{}), uptime: uptime.Now}, nil
}

// Done is closed when the window closes.
func (w *Window) Done() <-chan struct{} { return w.done }

// Result returns the paired phone's ID, or why the window closed.
func (w *Window) Result() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.phoneID != "" {
		return w.phoneID, nil
	}
	return "", w.err
}

// Close closes the window.
func (w *Window) Close() { w.closeWith(pair.ErrClosed) }

func (w *Window) closeWith(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeLocked(err)
}

func (w *Window) closeLocked(err error) {
	if w.err == nil && w.phoneID == "" {
		w.err = err
		close(w.done)
	}
}

// try checks a code and returns a new token for a right one.
func (w *Window) try(code string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err == nil && w.phoneID == "" && w.uptime() >= w.expires {
		w.closeLocked(pair.ErrExpired)
	}
	if w.phoneID != "" {
		return "", pair.ErrClosed
	}
	if w.err != nil {
		return "", w.err
	}
	c, err := pair.NormalizeCode(code)
	if err != nil || subtle.ConstantTimeCompare([]byte(c), w.code) != 1 {
		w.failures++
		if w.failures >= pair.MaxFailures {
			w.closeLocked(pair.ErrTooMany)
		}
		return "", pair.ErrWrongCode
	}
	token, id, err := NewToken(w.ca)
	if err != nil {
		return "", err
	}
	w.phoneID = id
	close(w.done)
	return token, nil
}

// Fingerprint returns what the user compares under the profile's details:
// the SHA-256 fingerprint of the iPhone CA, in the groups iOS shows.
func Fingerprint(ca *group.CA) string { return group.Fingerprint(ca.Cert) }

// ShortFingerprint returns the first eight groups of the fingerprint, which
// the user compares: a fake profile would need a CA whose fingerprint starts
// with the same 64 bits.
func ShortFingerprint(ca *group.CA) string { return Fingerprint(ca)[:8*3-1] }

// Profile returns the configuration profile that installs the iPhone CA.
// Its identifier is fixed, so a new profile replaces the old one.
func Profile(ca *group.CA) []byte {
	sum := sha256.Sum256(ca.Cert.Raw)
	uuid := func(salt byte) string {
		h := sha256.Sum256(append(sum[:], salt))
		h[6] = h[6]&0x0f | 0x50 // a name-based UUID
		h[8] = h[8]&0x3f | 0x80
		return fmt.Sprintf("%X-%X-%X-%X-%X", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
	}
	der := base64.StdEncoding.EncodeToString(ca.Cert.Raw)
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>cbb-iphone-ca.cer</string>
			<key>PayloadContent</key>
			<data>` + der + `</data>
			<key>PayloadDescription</key>
			<string>Lets the CBB shortcut reach cbb.local. The certificate is limited to that name.</string>
			<key>PayloadDisplayName</key>
			<string>` + template.HTMLEscapeString(ca.Cert.Subject.CommonName) + `</string>
			<key>PayloadIdentifier</key>
			<string>tools.cbb.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>` + uuid(1) + `</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trust for CBB on this home network.</string>
	<key>PayloadDisplayName</key>
	<string>CBB</string>
	<key>PayloadIdentifier</key>
	<string>tools.cbb</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>` + uuid(2) + `</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`)
}

// ProfileHandler serves the profile port while a window is open: a page
// that walks the user through the steps, the profile, and the shortcut.
func ProfileHandler(ca *group.CA) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /cbb.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="cbb.mobileconfig"`)
		w.Write(Profile(ca))
	})
	for _, name := range []string{SyncShortcut} {
		mux.HandleFunc("GET /"+name+".shortcut", func(w http.ResponseWriter, r *http.Request) {
			sc := Shortcut(name)
			if sc == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.shortcut"`)
			w.Write(sc)
		})
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data := map[string]string{}
		if Shortcut(SyncShortcut) != nil {
			data["Shortcut"] = "yes"
		}
		page(w, profilePage, data)
	})
	return mux
}

// pairRequest is what the shortcut sends to /pair on its first run. The
// code may come as a number or as text.
type pairRequest struct {
	V    json.Number     `json:"v"`
	Code json.RawMessage `json:"code"`
}

// pairReply is what the shortcut gets from /pair, always with status 200.
type pairReply struct {
	V       int    `json:"v"`
	OK      bool   `json:"ok"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message"`
}

// PairHandler serves the pairing page on the iPhone port, and the same
// pairing as JSON for the shortcut's first run. win returns the open
// window, or nil.
func PairHandler(win func() *Window) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pair", func(w http.ResponseWriter, r *http.Request) {
		page(w, codePage, map[string]string{})
	})
	mux.HandleFunc("POST /pair", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if strings.Contains(r.Header.Get("Content-Type"), "json") {
			pairJSON(w, r, win())
			return
		}
		code := r.PostFormValue("code")
		wd := win()
		if wd == nil {
			page(w, codePage, map[string]string{"Error": "No pairing window is open. Run cbb pair -phone on a Linux member."})
			return
		}
		token, err := wd.try(code)
		if err != nil {
			page(w, codePage, map[string]string{"Error": pairError(err)})
			return
		}
		page(w, tokenPage, map[string]string{"Token": token})
	})
	return mux
}

func pairJSON(w http.ResponseWriter, r *http.Request, wd *Window) {
	reply := func(rep pairReply) {
		rep.V = 1
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(rep)
	}
	var req pairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.V.String() != "1" {
		reply(pairReply{Message: "The shortcut is from another version of cbb; install it again."})
		return
	}
	if wd == nil {
		reply(pairReply{Message: "No pairing window is open. Run cbb pair -phone on a Linux member, then the shortcut again."})
		return
	}
	var code string
	if json.Unmarshal(req.Code, &code) != nil {
		// A number: typed into a number field, it lost its leading zeros.
		var n json.Number
		json.Unmarshal(req.Code, &n)
		code = n.String()
		for len(code) > 0 && len(code) < 6 && strings.Trim(code, "0123456789") == "" {
			code = "0" + code
		}
	}
	token, err := wd.try(code)
	if err != nil {
		reply(pairReply{Message: pairError(err)})
		return
	}
	reply(pairReply{OK: true, Token: token, Message: "This iPhone is paired. Press the shortcut to sync."})
}

// pairError is the message for a failed code.
func pairError(err error) string {
	if errors.Is(err, pair.ErrWrongCode) {
		return "Wrong code. Check it and try again."
	}
	return strings.TrimPrefix(err.Error(), "pair: ") + ". Run cbb pair -phone again."
}

func page(w http.ResponseWriter, t *template.Template, data map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	t.Execute(w, data)
}

const pageHead = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cbb</title>
<style>body{font:17px -apple-system,system-ui,sans-serif;margin:24px;max-width:36em;line-height:1.45}
input,button{font:inherit;padding:10px 12px;border-radius:10px;border:1px solid #888}
code{word-break:break-all;font-size:15px}.err{color:#b00020}.fp{font:20px ui-monospace,monospace}
.small{font-size:13px;color:#666;word-break:break-all}li{margin-bottom:18px}
.btn{display:inline-block;background:#0a7aff;color:#fff;text-decoration:none;padding:12px 18px;border-radius:12px}</style>
</head><body>`

var profilePage = template.Must(template.New("profile").Parse(pageHead + `
<h1>cbb on this iPhone</h1>
<ol>
<li><p><a class="btn" href="/cbb.mobileconfig">Install the profile</a></p>
<p>Allow the download, then open Settings: the profile waits at the top, under <b>Profile Downloaded</b>. Tap <b>Install</b>.</p></li>
<li><p>In Settings &rsaquo; General &rsaquo; VPN &amp; Device Management &rsaquo; cbb &rsaquo; More Details, compare the SHA-256 fingerprint with the one in the <b>computer's terminal</b>, where <code>cbb pair -phone</code> runs. This page cannot show it: it comes over plain HTTP, and anyone on the network could change it.</p>
<p>If the fingerprint does not start with what the terminal shows, remove the profile and stop: someone else is answering. Do not turn on full trust for it.</p></li>
<li><p>Settings &rsaquo; General &rsaquo; About &rsaquo; Certificate Trust Settings: turn on <b>cbb</b>. Without it, the shortcut reports that it cannot make a secure connection.</p></li>
{{if .Shortcut}}<li><p><a class="btn" href="/cbb.shortcut">Add the shortcut</a></p>
<p>Then run it once: it asks for the six-digit code that the computer shows, and remembers this iPhone.</p></li>
{{else}}<li><p>Add the cbb shortcut from the release page, run it once, and type the six-digit code that the computer shows.</p></li>
{{end}}<li><p>Put the shortcut on Back Tap: Settings &rsaquo; Accessibility &rsaquo; Touch &rsaquo; Back Tap &rsaquo; Double Tap &rsaquo; cbb. On an iPhone with an Action button, use that instead.</p></li>
</ol>
</body></html>`))

var codePage = template.Must(template.New("code").Parse(pageHead + `
<h1>Pair this iPhone</h1>
{{with .Error}}<p class="err">{{.}}</p>{{end}}
<form method="post" action="/pair">
<p><label>The code from cbb pair -phone:<br>
<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="7" required autofocus></label></p>
<p><button type="submit">Pair</button></p>
</form>
</body></html>`))

var tokenPage = template.Must(template.New("token").Parse(pageHead + `
<h1>Paired</h1>
<p>Install the cbb shortcut and paste this token when it asks for it:</p>
<p><code>{{.Token}}</code></p>
<p>Keep it private: it lets the shortcut use the group's clipboard. Then assign the shortcut to the Action button or to Back Tap.</p>
</body></html>`))
