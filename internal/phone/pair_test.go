// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/pair"
)

func postCode(t *testing.T, h http.Handler, code string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/pair", strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Body.String()
}

var tokenRE = regexp.MustCompile(`<code>(cb1\.[A-Za-z0-9_-]+)</code>`)

func TestPairPage(t *testing.T) {
	ca := newCA(t)
	code := pair.NewCode()
	w, err := OpenWindow(ca, code)
	if err != nil {
		t.Fatal(err)
	}
	h := PairHandler(func() *Window { return w })
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	if out := postCode(t, h, wrong); !strings.Contains(out, "Wrong code") {
		t.Errorf("a wrong code got:\n%s", out)
	}
	out := postCode(t, h, code[:3]+" "+code[3:])
	m := tokenRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the right code got:\n%s", out)
	}
	id, err := CheckToken(ca, m[1])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.Result(); err != nil || got != id {
		t.Errorf("Result = %q, %v; want %q", got, err, id)
	}
	// The window paired one phone; it takes no more codes.
	if out := postCode(t, h, code); tokenRE.MatchString(out) {
		t.Error("a second phone paired through the same window")
	}
	// No window: a clear message, and no token.
	if out := postCode(t, PairHandler(func() *Window { return nil }), code); !strings.Contains(out, "No pairing window") {
		t.Errorf("without a window:\n%s", out)
	}
}

func TestPairWindowLimits(t *testing.T) {
	ca := newCA(t)
	w, _ := OpenWindow(ca, "123456")
	for range pair.MaxFailures {
		if _, err := w.try("654321"); !errors.Is(err, pair.ErrWrongCode) {
			t.Fatalf("try = %v", err)
		}
	}
	if _, err := w.try("123456"); !errors.Is(err, pair.ErrTooMany) {
		t.Errorf("the right code after three wrong ones: %v", err)
	}
	// Expiry, on the clock that counts sleep.
	w2, _ := OpenWindow(ca, "123456")
	now := time.Duration(0)
	w2.uptime = func() time.Duration { return now }
	w2.expires = pair.Lifetime
	now = pair.Lifetime
	if _, err := w2.try("123456"); !errors.Is(err, pair.ErrExpired) {
		t.Errorf("after five minutes: %v", err)
	}
	w3, _ := OpenWindow(ca, "123456")
	w3.Close()
	if _, err := w3.try("123456"); !errors.Is(err, pair.ErrClosed) {
		t.Errorf("after Close: %v", err)
	}
	if _, err := OpenWindow(ca, "12345"); err == nil {
		t.Error("opened a window with a five-digit code")
	}
}

func TestPagesAreSafe(t *testing.T) {
	ca := newCA(t)
	w, _ := OpenWindow(ca, "123456")
	h := PairHandler(func() *Window { return w })
	req := httptest.NewRequest(http.MethodGet, "/pair", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP %q", csp)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the page may be cached")
	}
	// A code that looks like markup is not echoed as markup.
	if out := postCode(t, h, "<script>"); strings.Contains(out, "<script>") {
		t.Error("the input was echoed unescaped")
	}
}

func TestProfile(t *testing.T) {
	ca := newCA(t)
	p := string(Profile(ca))
	for _, want := range []string{"com.apple.security.root", "tools.cbb", "<key>PayloadRemovalDisallowed</key>"} {
		if !strings.Contains(p, want) {
			t.Errorf("the profile lacks %q", want)
		}
	}
	m := regexp.MustCompile(`<data>([A-Za-z0-9+/=]+)</data>`).FindStringSubmatch(p)
	if m == nil {
		t.Fatal("no certificate data")
	}
	der, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || !cert.Equal(ca.Cert) {
		t.Error("the profile does not carry the iPhone CA")
	}
	// The same CA gives the same profile, so installing it again replaces
	// it instead of adding a second one.
	if string(Profile(ca)) != p {
		t.Error("the profile is not stable")
	}
	if runtime.GOOS == "darwin" {
		path := filepath.Join(t.TempDir(), "p.mobileconfig")
		os.WriteFile(path, []byte(p), 0o600)
		if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
			t.Errorf("plutil: %v\n%s", err, out)
		}
	}
	// The profile port serves it with the type iOS installs.
	rec := httptest.NewRecorder()
	ProfileHandler(ca).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cbb.mobileconfig", nil))
	if rec.Header().Get("Content-Type") != "application/x-apple-aspen-config" || rec.Body.String() != p {
		t.Errorf("profile response %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	ProfileHandler(ca).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	// The page comes over plain HTTP, so it sends the user to the terminal
	// for the fingerprint instead of showing one.
	if strings.Contains(rec.Body.String(), ShortFingerprint(ca)) || !strings.Contains(rec.Body.String(), "terminal") {
		t.Error("the profile page shows the fingerprint, or does not send the user to the terminal for it")
	}
	if len(ShortFingerprint(ca)) != 23 || !strings.HasPrefix(Fingerprint(ca), ShortFingerprint(ca)) {
		t.Errorf("short fingerprint %q", ShortFingerprint(ca))
	}
	// Without a signed shortcut in this build, the page sends the user to
	// the release, and the file is not served.
	if Shortcut(SyncShortcut) == nil {
		if !strings.Contains(rec.Body.String(), "release page") {
			t.Error("the page does not say where the shortcut is")
		}
		rec = httptest.NewRecorder()
		ProfileHandler(ca).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cbb.shortcut", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("a missing shortcut: %d", rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	ProfileHandler(ca).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sync", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("the profile port serves /sync: %d", rec.Code)
	}
}

func TestPairJSON(t *testing.T) {
	// The shortcut's first run: the code as a number, which loses leading
	// zeros, and a JSON answer with the token.
	ca := newCA(t)
	w, err := OpenWindow(ca, "012345")
	if err != nil {
		t.Fatal(err)
	}
	h := PairHandler(func() *Window { return w })
	post := func(body string) pairReply {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/pair", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var rep pairReply
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &rep) != nil {
			t.Fatalf("reply %d %s", rec.Code, rec.Body)
		}
		return rep
	}
	if rep := post(`{"v":1,"code":"999999"}`); rep.OK || rep.Token != "" || !strings.Contains(rep.Message, "Wrong code") {
		t.Errorf("a wrong code got %+v", rep)
	}
	rep := post(`{"v":1,"code":12345}`)
	if !rep.OK {
		t.Fatalf("the right code got %+v", rep)
	}
	if _, err := CheckToken(ca, rep.Token); err != nil {
		t.Errorf("the token: %v", err)
	}
	if rep := post(`{"v":2,"code":"012345"}`); rep.OK {
		t.Errorf("another version got %+v", rep)
	}
	none := PairHandler(func() *Window { return nil })
	req := httptest.NewRequest(http.MethodPost, "/pair", strings.NewReader(`{"v":1,"code":"012345"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	none.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "No pairing window") {
		t.Errorf("without a window: %s", rec.Body)
	}
}

func TestShortcutFile(t *testing.T) {
	// The committed property list is what the generator makes; run
	// go run ./tools/shortcut after changing it, and sign it again.
	for name, want := range UnsignedShortcuts() {
		got, err := os.ReadFile("shortcut/" + name + ".plist")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("shortcut/%s.plist is stale; run go run ./tools/shortcut", name)
		}
	}
	got := UnsignedShortcut()
	d := xml.NewDecoder(bytes.NewReader(got))
	for {
		if _, err := d.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("not well-formed XML: %v", err)
		}
	}
	for _, want := range []string{"https://cbb.local:8764/pair", "https://cbb.local:8764/sync", tokenPath, "unpaired", "to_iphone"} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("the shortcut lacks %q", want)
		}
	}
	if runtime.GOOS == "darwin" {
		for name := range UnsignedShortcuts() {
			if out, err := exec.Command("plutil", "-lint", "shortcut/"+name+".plist").CombinedOutput(); err != nil {
				t.Errorf("plutil: %v\n%s", err, out)
			}
		}
	}
}
