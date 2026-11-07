// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

func webCase(c string) bool { return strings.HasPrefix(c, "web:") }

// runWeb plays the web server of a forwarder's site, in front of its
// VLESS over XHTTP (W46), or the mirror of the releases on its server
// (W47): HTTPS on addr with a certificate for NAME from a CA of its own,
// whose PEM it writes to CAFILE for the devices to trust; requests under
// PATH go to BACKEND as they are, or with "-" for BACKEND get a 404, and it
// counts them in HITS; any other gets the site. It keeps its CA across a
// restart of the forwarder, in CAFILE and CAFILE.key, and a second web
// server with the same CAFILE takes the same CA.
//
//	forge -addr :443 web:NAME,PATH,BACKEND,CAFILE,HITS
func runWeb(addr, c string) error {
	f := strings.Split(strings.TrimPrefix(c, "web:"), ",")
	if len(f) != 5 || !strings.HasPrefix(f[1], "/") {
		return errors.New("web: want NAME,PATH,BACKEND,CAFILE,HITS")
	}
	name, path, backend, caFile, hitsFile := f[0], f[1], f[2], f[3], f[4]
	caKey, caDER, err := webCA(caFile)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	var proxy http.Handler = http.NotFoundHandler()
	if backend != "-" {
		to, err := url.Parse("http://" + backend)
		if err != nil {
			return err
		}
		rp := httputil.NewSingleHostReverseProxy(to)
		rp.FlushInterval = -1
		proxy = rp
	}
	var hits atomic.Int64
	srv := &http.Server{Addr: addr, ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if path != "/" && r.URL.Path != path && !strings.HasPrefix(r.URL.Path, path+"/") {
				fmt.Fprintln(w, siteBody)
				return
			}
			os.WriteFile(hitsFile, fmt.Appendf(nil, "%d %s\n", hits.Add(1), r.URL.Path), 0o644)
			proxy.ServeHTTP(w, r)
		}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}}}}
	return srv.ListenAndServeTLS("", "")
}

// webCA reads the CA kept in caFile, or makes one and keeps it there.
func webCA(caFile string) (*ecdsa.PrivateKey, []byte, error) {
	if c, err := os.ReadFile(caFile); err == nil {
		k, err := os.ReadFile(caFile + ".key")
		if err != nil {
			return nil, nil, err
		}
		cb, _ := pem.Decode(c)
		kb, _ := pem.Decode(k)
		if cb == nil || kb == nil {
			return nil, nil, errors.New("web: the CA kept is not PEM")
		}
		key, err := x509.ParseECPrivateKey(kb.Bytes)
		return key, cb.Bytes, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cbb-bench web CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(caFile+".key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return nil, nil, err
	}
	return key, der, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
