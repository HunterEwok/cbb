// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Command monitor checks the project's servers from outside, as the
// monitor workflow runs it every few hours (docs/maintaining.md, "Watching
// cbb.tools"): the websites answer over HTTPS with certificates that are
// not about to expire, the forwarder's and the relay's ports take a
// connection, and the signed files that devices fetch (keys.json,
// stable.json, attest-status.json) are not close to their expiry, which
// would mean a timer on cbb.tools stopped; and, with -traffic, that the
// server's traffic of the last 24 hours stays inside its budget
// (docs/relay-budget.md, "Money and traffic"). It prints one line per check
// and exits 1 when any fails, so that the failed run mails the maintainer.
//
// Usage:
//
//	go run ./tools/monitor [-require-files] [-ports cbb.tools:8764,cbb.tools:8765]
//	    [-traffic https://cbb.tools/status/traffic.json -traffic-budget 1TB]
//
// Before the first signed release the files are not served yet (404); a
// missing file counts as a failure only with -require-files.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/release"
)

// site is a website whose certificate is watched.
type site struct {
	url    string
	within time.Duration // warn when the certificate expires sooner
}

// signed is a signed file devices fetch, and how long before its expiry
// to warn: long enough to act, short enough not to warn every day.
type signed struct {
	url    string
	within time.Duration
	todo   string
}

var sites = []site{
	{"https://cbb.tools/", 14 * 24 * time.Hour},
	{"https://dl.cbb.tools/", 14 * 24 * time.Hour},
}

var files = []signed{
	{"https://cbb.tools/channel/keys.json", 21 * 24 * time.Hour, "sign it again with a YubiKey: release-sign renew -new-keys"},
	{"https://cbb.tools/channel/stable.json", 10 * 24 * time.Hour, "the cbb-channel timer on cbb.tools stopped: check it, or release-sign renew"},
	{"https://dl.cbb.tools/keys.json", 21 * 24 * time.Hour, "the mirror on cbb.tools stopped copying keys.json"},
	{"https://dl.cbb.tools/stable.json", 10 * 24 * time.Hour, "the mirror on cbb.tools stopped copying stable.json"},
	{"https://cbb.tools/attest/attest-status.json", 5 * 24 * time.Hour, "the attest-status timer on cbb.tools stopped: check it"},
}

const timeout = 20 * time.Second

func main() {
	requireFiles := flag.Bool("require-files", false, "count a signed file that is not served (404) as a failure")
	ports := flag.String("ports", "cbb.tools:8764", "the forwarder's and the relay's addresses, comma-separated, that must take a TCP connection")
	trafficURL := flag.String("traffic", "", "the URL of the server's traffic.json (site/deploy/cbb-traffic.sh), checked against -traffic-budget")
	trafficBudget := flag.String("traffic-budget", "1TB", "the bytes the server may move in 24 hours before the check fails, such as 800GB or 1.5TB")
	flag.Parse()
	budget, err := parseBytes(*trafficBudget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "monitor: -traffic-budget: %v\n", err)
		os.Exit(2)
	}
	c := checker{client: &http.Client{Timeout: timeout}, now: time.Now(), requireFiles: *requireFiles, out: os.Stdout}
	for _, s := range sites {
		c.site(s)
	}
	for _, p := range strings.Split(*ports, ",") {
		if p = strings.TrimSpace(p); p != "" {
			c.port(p)
		}
	}
	for _, f := range files {
		c.file(f)
	}
	if *trafficURL != "" {
		c.traffic(*trafficURL, budget)
	}
	if c.failed > 0 {
		fmt.Fprintf(c.out, "%d of the checks failed\n", c.failed)
		os.Exit(1)
	}
}

type checker struct {
	client       *http.Client
	now          time.Time
	requireFiles bool
	out          io.Writer
	dial         func(ctx context.Context, network, addr string) (net.Conn, error) // nil: net.Dialer
	failed       int
}

func (c *checker) ok(format string, args ...any) {
	fmt.Fprintf(c.out, "ok    "+format+"\n", args...)
}

func (c *checker) fail(format string, args ...any) {
	c.failed++
	fmt.Fprintf(c.out, "FAIL  "+format+"\n", args...)
}

// site checks that url answers over HTTPS, with any status (a private site
// may refuse the page), and that its certificate lives longer than within.
func (c *checker) site(s site) {
	resp, err := c.client.Get(s.url)
	if err != nil {
		c.fail("%s: %v", s.url, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		c.fail("%s: %s", s.url, resp.Status)
		return
	}
	c.certificate(s.url, resp.TLS, s.within)
}

func (c *checker) certificate(url string, st *tls.ConnectionState, within time.Duration) {
	if st == nil || len(st.PeerCertificates) == 0 {
		c.fail("%s: no TLS certificate", url)
		return
	}
	end := st.PeerCertificates[0].NotAfter
	left := end.Sub(c.now)
	if left < within {
		c.fail("%s: its certificate expires on %s, in %s: renew it on cbb.tools (certbot)", url, end.UTC().Format(time.DateOnly), days(left))
		return
	}
	c.ok("%s: its certificate expires in %s", url, days(left))
}

// port checks that addr takes a TCP connection: the forwarder and the
// relay listen on TCP as well as UDP, and UDP cannot be checked without
// the group's keys.
func (c *checker) port(addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dial := c.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		c.fail("%s: %v", addr, err)
		return
	}
	conn.Close()
	c.ok("%s takes connections", addr)
}

// file checks that a signed file is served and not close to its expiry.
// It reads the expiry only: the devices check the signatures themselves.
func (c *checker) file(f signed) {
	resp, err := c.client.Get(f.url)
	if err != nil {
		c.fail("%s: %v", f.url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && !c.requireFiles {
		c.ok("%s: not served yet (before the first signed release)", f.url)
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.fail("%s: %s", f.url, resp.Status)
		return
	}
	expires, err := expiry(io.LimitReader(resp.Body, 2*release.MaxBody))
	if err != nil {
		c.fail("%s: %v", f.url, err)
		return
	}
	left := expires.Sub(c.now)
	if left < f.within {
		c.fail("%s expires on %s, in %s: %s", f.url, expires.UTC().Format(time.DateOnly), days(left), f.todo)
		return
	}
	c.ok("%s expires in %s", f.url, days(left))
}

// trafficStale is how old traffic.json may be: cbb-traffic.timer writes it
// every 15 minutes.
const trafficStale = 2 * time.Hour

// traffic checks the server's traffic of the last 24 hours, which
// cbb-traffic.sh writes, against budget. Before the file is served, as with
// the signed files, a 404 passes unless -require-files.
func (c *checker) traffic(url string, budget float64) {
	resp, err := c.client.Get(url)
	if err != nil {
		c.fail("%s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && !c.requireFiles {
		c.ok("%s: not served yet (cbb-traffic.timer not set up)", url)
		return
	}
	if resp.StatusCode != http.StatusOK {
		c.fail("%s: %s", url, resp.Status)
		return
	}
	var t struct {
		UpdatedMS int64   `json:"updated_ms"`
		Hours     float64 `json:"hours"`
		DayBytes  float64 `json:"day_bytes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&t); err != nil || t.UpdatedMS <= 0 {
		c.fail("%s: not a traffic file", url)
		return
	}
	if age := c.now.Sub(time.UnixMilli(t.UpdatedMS)); age > trafficStale {
		c.fail("%s was written %s ago: cbb-traffic.timer on cbb.tools stopped", url, age.Round(time.Minute))
		return
	}
	if t.DayBytes > budget {
		c.fail("%s: the server moved %s in the last %.0f hours, over the budget of %s: see docs/relay-budget.md, \"Money and traffic\"", url, formatBytes(t.DayBytes), t.Hours, formatBytes(budget))
		return
	}
	c.ok("%s: %s in the last %.0f hours, %.0f%% of the budget of %s", url, formatBytes(t.DayBytes), t.Hours, 100*t.DayBytes/budget, formatBytes(budget))
}

// parseBytes reads a size such as 800GB or 1.5TB, in powers of 1000.
func parseBytes(s string) (float64, error) {
	units := []struct {
		suffix string
		mult   float64
	}{{"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"B", 1}}
	for _, u := range units {
		if n, ok := strings.CutSuffix(s, u.suffix); ok {
			v, err := strconv.ParseFloat(n, 64)
			if err != nil || v <= 0 {
				return 0, fmt.Errorf("%q is not a size such as 800GB or 1.5TB", s)
			}
			return v * u.mult, nil
		}
	}
	return 0, fmt.Errorf("%q is not a size such as 800GB or 1.5TB", s)
}

func formatBytes(b float64) string {
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.2f TB", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1f GB", b/1e9)
	default:
		return fmt.Sprintf("%.0f MB", b/1e6)
	}
}

// expiry reads expires_ms from the body of a signed file.
func expiry(r io.Reader) (time.Time, error) {
	var f release.File
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return time.Time{}, fmt.Errorf("not a signed file: %w", err)
	}
	var b struct {
		ExpiresMS int64 `json:"expires_ms"`
	}
	if err := json.Unmarshal(f.Body, &b); err != nil {
		return time.Time{}, fmt.Errorf("its body: %w", err)
	}
	if b.ExpiresMS <= 0 {
		return time.Time{}, errors.New("its body has no expires_ms")
	}
	return time.UnixMilli(b.ExpiresMS), nil
}

func days(d time.Duration) string {
	if d < 0 {
		return "the past"
	}
	n := int(d.Hours() / 24)
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
