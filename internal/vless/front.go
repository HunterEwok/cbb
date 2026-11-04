// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package vless

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// front is the plain HTTP the web server passes the XHTTP path to: a
// request under the path of a group that is let in (path/group/...) goes
// to the groups' inbound as path/..., every other one under the path to
// the registrations' inbound, which lets in RegistrationID alone. Both
// inbounds listen on the loopback and take the path itself.
type front struct {
	path   string
	groups netip.AddrPort
	regs   netip.AddrPort

	mu    sync.Mutex
	paths map[string]int // the groups' paths that are let in, each counted

	srv *http.Server
}

func (f *front) start(listen netip.AddrPort) error {
	l, err := net.Listen("tcp", listen.String())
	if err != nil {
		return err
	}
	proxy := func(to netip.AddrPort) *httputil.ReverseProxy {
		u := &url.URL{Scheme: "http", Host: to.String()}
		return &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(u)
				r.Out.Host = r.In.Host
			},
			// XHTTP streams its download: pass each write at once.
			FlushInterval: -1,
			ErrorLog:      log.New(io.Discard, "", 0),
			ErrorHandler:  func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusBadGateway) },
		}
	}
	groups, regs := proxy(f.groups), proxy(f.regs)
	f.srv = &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rest, ok := strings.CutPrefix(r.URL.Path, f.path+"/")
			if !ok {
				http.NotFound(w, r)
				return
			}
			if seg, tail, ok := strings.Cut(rest, "/"); ok && f.has(seg) {
				r.URL.Path, r.URL.RawPath = f.path+"/"+tail, ""
				groups.ServeHTTP(w, r)
				return
			}
			regs.ServeHTTP(w, r)
		}),
	}
	go func() {
		if err := f.srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.Close()
		}
	}()
	return nil
}

func (f *front) has(seg string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.paths[seg] > 0
}

func (f *front) close() {
	if f.srv != nil {
		f.srv.Close()
	}
}
