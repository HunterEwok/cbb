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
	web := webServer(t, path, back, nil, client)
	return netip.MustParseAddrPort(web.Listener.Addr().String()), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: web.Certificate().Raw})
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
	web := webServer(t, path, back, &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, netip.Addr{})
	return netip.MustParseAddrPort(web.Listener.Addr().String()), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// webServer runs WebServerNaming's site with the certificate, or httptest's
// own.
func webServer(t testing.TB, path string, back func() string, cert *tls.Certificate, client netip.Addr) *httptest.Server {
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
	site.Handle(path+"/", proxy)
	site.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "the site") })
	web := httptest.NewUnstartedServer(site)
	web.EnableHTTP2 = true
	web.Config.ErrorLog = log.New(io.Discard, "", 0)
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
