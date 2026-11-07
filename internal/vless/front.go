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

	"github.com/HunterEwok/cbb/internal/budget"
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
	// down counts the sessions whose download (GET) is open, by inbound
	// and session ID; an upload to any other session is held by Xray for
	// up to 30 seconds before anyone reads it, so it pays from uploads.
	down    map[string]int
	uploads *budget.Rates // by source
	all     *budget.Rates // all sources together

	srv *http.Server
}

// What uploads to a session that no download has opened may come, a
// second, from a source at each level and from all sources together
// (docs/relay-budget.md, "XHTTP"): each holds at most MaxPostBytes for 30
// seconds, so all of them together hold at most about 256 MiB.
var (
	uploadRates = [4]budget.Rate{{PerSecond: 32, Burst: 64}, {PerSecond: 32, Burst: 64}, {PerSecond: 64, Burst: 128}, {PerSecond: 128, Burst: 256}}
	uploadsAll  = budget.Rate{PerSecond: 256, Burst: 512}
)

// opened counts a session's download opening (n 1) or closing (n -1).
func (f *front) opened(key string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down == nil {
		f.down = map[string]int{}
	}
	if f.down[key] += n; f.down[key] <= 0 {
		delete(f.down, key)
	}
}

// mayUpload reports whether an upload to the session may pass: always when
// its download is open, which reads it, else when its source and all
// sources together have uploads left.
func (f *front) mayUpload(key string, from netip.Addr, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down[key] > 0 {
		return true
	}
	if f.uploads == nil {
		f.uploads = budget.NewRates(uploadRates[0], uploadRates[1], uploadRates[2], uploadRates[3])
		// All sources pay as one: an address that is not valid has one
		// payer at every level.
		f.all = budget.NewRates(uploadsAll, uploadsAll, uploadsAll, uploadsAll)
	}
	// The source first, so that one over its own share spends nothing
	// of all sources'.
	return f.uploads.Take(from, 1, now) && f.all.Take(netip.Addr{}, 1, now)
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
				// Xray takes the client's address from these, and only
				// with frontHeader (the inbounds' trustedXForwardedFor);
				// the Rewrite has removed any the client sent.
				r.Out.Header.Del(frontHeader)
				if a := clientOf(r.In); a.IsValid() {
					r.Out.Header.Set("X-Forwarded-For", a.String())
					r.Out.Header.Set(frontHeader, "1")
				}
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
			to, in := regs, "r"
			if seg, tail, ok := strings.Cut(rest, "/"); ok && f.has(seg) {
				r.URL.Path, r.URL.RawPath = f.path+"/"+tail, ""
				to, in, rest = groups, "g/"+seg, tail
			}
			session, _, _ := strings.Cut(rest, "/")
			key := in + "/" + session
			switch r.Method {
			case http.MethodGet:
				f.opened(key, 1)
				defer f.opened(key, -1)
			case http.MethodPost:
				if !f.mayUpload(key, clientOf(r), time.Now()) {
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
			}
			to.ServeHTTP(w, r)
		}),
	}
	go func() {
		if err := f.srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.Close()
		}
	}()
	return nil
}

// FromHeader is the header in which the web server in front of XHTTP names
// the client's address, which pays for the client's registrations
// (docs/relay-budget.md, "XHTTP"); nginx: proxy_set_header X-Real-IP
// $remote_addr.
const FromHeader = "X-Real-IP"

// frontHeader marks the front's requests to Xray's inbounds, which take
// X-Forwarded-For only from a request that has it.
const frontHeader = "X-Cbb-Front"

// clientOf returns the client's address of a request to the front: the one
// FromHeader names when the request comes from the loopback, as from a web
// server on the same host, else the address it comes from.
func clientOf(r *http.Request) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	a := peer.Addr().Unmap()
	if a.IsLoopback() {
		if h, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(FromHeader))); err == nil {
			return h.Unmap().WithZone("")
		}
	}
	return a
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
