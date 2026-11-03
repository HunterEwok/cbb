// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

func signedFile(t *testing.T, expires time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"v": 1, "expires_ms": expires.UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(release.File{Body: body, Sig: []byte{1}, Key: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChecks(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fresh.json":
			w.Write(signedFile(t, now.Add(60*24*time.Hour)))
		case "/stale.json":
			w.Write(signedFile(t, now.Add(3*24*time.Hour)))
		case "/broken.json":
			w.Write([]byte("<html>"))
		case "/down":
			w.WriteHeader(http.StatusBadGateway)
		case "/private":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	end := srv.Certificate().NotAfter

	run := func(c *checker, f func(*checker)) (string, int) {
		var out bytes.Buffer
		c.client, c.out = srv.Client(), &out
		f(c)
		return out.String(), c.failed
	}
	for _, tc := range []struct {
		name   string
		c      checker
		f      func(*checker)
		failed int
		want   string
	}{
		{"a private site answers", checker{now: now}, func(c *checker) { c.site(site{srv.URL + "/private", 14 * 24 * time.Hour}) }, 0, "certificate expires in"},
		{"a site that fails", checker{now: now}, func(c *checker) { c.site(site{srv.URL + "/down", time.Hour}) }, 1, "502"},
		{"a certificate about to expire", checker{now: end.Add(-48 * time.Hour)}, func(c *checker) { c.site(site{srv.URL + "/private", 14 * 24 * time.Hour}) }, 1, "in 2 days"},
		{"a fresh file", checker{now: now}, func(c *checker) { c.file(signed{srv.URL + "/fresh.json", 10 * 24 * time.Hour, "x"}) }, 0, "expires in 60 days"},
		{"a stale file", checker{now: now}, func(c *checker) { c.file(signed{srv.URL + "/stale.json", 10 * 24 * time.Hour, "renew it"}) }, 1, "in 3 days: renew it"},
		{"a broken file", checker{now: now}, func(c *checker) { c.file(signed{srv.URL + "/broken.json", time.Hour, "x"}) }, 1, "not a signed file"},
		{"no file before the first release", checker{now: now}, func(c *checker) { c.file(signed{srv.URL + "/keys.json", time.Hour, "x"}) }, 0, "not served yet"},
		{"no file when one is required", checker{now: now, requireFiles: true}, func(c *checker) { c.file(signed{srv.URL + "/keys.json", time.Hour, "x"}) }, 1, "404"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, failed := run(&tc.c, tc.f)
			if failed != tc.failed || !strings.Contains(out, tc.want) {
				t.Errorf("failed %d, want %d; output %q, want %q in it", failed, tc.failed, out, tc.want)
			}
		})
	}

	t.Run("ports", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		c := checker{now: now}
		out, failed := run(&c, func(c *checker) { c.port(addr) })
		if failed != 1 {
			t.Errorf("a closed port passed: %q", out)
		}
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		c = checker{now: now}
		out, failed = run(&c, func(c *checker) { c.port(ln.Addr().String()) })
		if failed != 0 || !strings.Contains(out, "takes connections") {
			t.Errorf("an open port failed: %q", out)
		}
	})
}
