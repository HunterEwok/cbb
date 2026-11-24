// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package vlesstest helps tests of VLESS over XHTTP.
package vlesstest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// WebServer runs the web server of a forwarder's site for XHTTP: TLS with
// a certificate for example.com, the path passed as plain HTTP to the
// address back returns, which may change while it runs, and the site
// everywhere else. It returns its address and its certificate in PEM, for
// vless.TrustForTests.
func WebServer(t testing.TB, path string, back func() string) (netip.AddrPort, []byte) {
	t.Helper()
	return WebServerNaming(t, path, back, netip.Addr{})
}

// WebServerNaming is WebServer naming client as every client's address in
// X-Real-IP, as nginx's proxy_set_header X-Real-IP $remote_addr does with
// the address the client connects from; that address if client is not
// valid.
func WebServerNaming(t testing.TB, path string, back func() string, client netip.Addr) (netip.AddrPort, []byte) {
	t.Helper()
	addr, cert, _ := WebServerWatched(t, path, back, client)
	return addr, cert
}

// WebServerWatched is WebServerNaming with a Watch of what the web server
// does with the clients' requests, for a test to tell when the
// forwarder's side refused a client without waiting for time to pass.
func WebServerWatched(t testing.TB, path string, back func() string, client netip.Addr) (netip.AddrPort, []byte, *Watch) {
	t.Helper()
	w := newWatch(t)
	web := webServer(t, path, back, nil, client, w)
	return netip.MustParseAddrPort(web.Listener.Addr().String()), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: web.Certificate().Raw}), w
}

// Watch records what refuses a client at a web server of WebServerWatched:
// the site answered a path that is not passed on ("site"), the TLS
// handshake failed, as with a client that does not take the certificate
// ("handshake"), or an XHTTP session's download ended while its client
// still ran ("ended"): the forwarder's side closes a session it does not
// let in, and the download of a session it carries stays open until its
// client closes.
type Watch struct {
	mu     sync.Mutex
	cond   *sync.Cond
	seq    int // requests and handshakes so far
	events []watched
	done   bool
}

type watched struct {
	kind string
	seq  int // of the request it is about
}

func newWatch(t testing.TB) *Watch {
	w := &Watch{}
	w.cond = sync.NewCond(&w.mu)
	t.Cleanup(func() {
		w.mu.Lock()
		w.done = true
		w.mu.Unlock()
		w.cond.Broadcast()
	})
	return w
}

// begin counts a request or a handshake and returns its number.
func (w *Watch) begin() int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seq++
	return w.seq
}

func (w *Watch) note(kind string, seq int) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.events = append(w.events, watched{kind, seq})
	w.mu.Unlock()
	w.cond.Broadcast()
}

// Mark returns the point after which Refused looks: requests that began
// before it, such as the downloads of clients closed before, do not count.
func (w *Watch) Mark() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

// Refused returns a channel that gets the first refusal of a request that
// began after mark.
func (w *Watch) Refused(mark int) <-chan string {
	ch := make(chan string, 1)
	go func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		for !w.done {
			for _, e := range w.events {
				if e.seq > mark {
					ch <- e.kind
					return
				}
			}
			w.cond.Wait()
		}
	}()
	return ch
}

// handshakes counts the failed TLS handshakes the server logs.
type handshakes struct{ w *Watch }

func (h handshakes) Write(b []byte) (int, error) {
	if strings.Contains(string(b), "TLS handshake error") {
		h.w.note("handshake", h.w.begin())
	}
	return len(b), nil
}

// WebServerCA is WebServer with a certificate as a public site has one: an
// RSA certificate for WebName from a CA of its own, whose certificate in
// PEM it returns, for clients that check the chain to a root, such as the
// Rust cbb with SSL_CERT_FILE.
func WebServerCA(t testing.TB, path string, back func() string) (netip.AddrPort, []byte) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cbb test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: WebName}, DNSNames: []string{WebName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	web := webServer(t, path, back, &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, netip.Addr{}, nil)
	return netip.MustParseAddrPort(web.Listener.Addr().String()), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// webServer runs WebServerNaming's site with the certificate, or httptest's
// own, telling w, if not nil, what it does.
func webServer(t testing.TB, path string, back func() string, cert *tls.Certificate, client netip.Addr, w *Watch) *httptest.Server {
	t.Helper()
	proxy := &httputil.ReverseProxy{FlushInterval: -1, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(&url.URL{Scheme: "http", Host: back()})
		r.Out.Host = r.In.Host
		from := client
		if !from.IsValid() {
			if ap, err := netip.ParseAddrPort(r.In.RemoteAddr); err == nil {
				from = ap.Addr()
			}
		}
		r.Out.Header.Set("X-Real-IP", from.String())
	}}
	site := http.NewServeMux()
	site.HandleFunc(path+"/", func(rw http.ResponseWriter, r *http.Request) {
		seq := w.begin()
		proxy.ServeHTTP(rw, r)
		// XHTTP's packet-up downloads with GET and uploads with POST.
		if r.Method == http.MethodGet {
			w.note("ended", seq)
		}
	})
	site.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		w.note("site", w.begin())
		io.WriteString(rw, "the site")
	})
	web := httptest.NewUnstartedServer(site)
	web.EnableHTTP2 = true
	web.Config.ErrorLog = log.New(io.Discard, "", 0)
	if w != nil {
		web.Config.ErrorLog = log.New(handshakes{w}, "", 0)
	}
	if cert != nil {
		web.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	web.StartTLS()
	// The clients' downloads are long requests that a closed client
	// leaves open for a while.
	t.Cleanup(func() { web.CloseClientConnections(); web.Close() })
	return web
}

// WebName is the name WebServer's certificate carries.
const WebName = "example.com"
