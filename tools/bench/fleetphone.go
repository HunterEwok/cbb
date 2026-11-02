// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	profileDataRE = regexp.MustCompile(`<data>([A-Za-z0-9+/=\s]+)</data>`)
	phoneURLRE    = regexp.MustCompile(`open http://([0-9.]+):(\d+)/`)
	phoneFPRE     = regexp.MustCompile(`fingerprint must start with:\s+([0-9A-F ]{23})`)
	phoneCodeRE   = regexp.MustCompile(`code the shortcut asks for:\s+(\d{3}) (\d{3})`)
)

// syncReply is what POST /sync answers the shortcut.
type syncReply struct {
	Direction string `json:"direction"`
	Copy      string `json:"copy"`
	Message   string `json:"message"`
}

// shortcut plays the iPhone's shortcut from a fleet container: curl with
// the iPhone CA that the profile carries, to clipboardbridge.local at the
// member's address.
type shortcut struct {
	phone *Device
	addr  string // the member's IP address
	port  string
	token string
}

// post sends JSON to path over HTTPS and decodes the reply into v.
func (s *shortcut) post(ctx context.Context, path, token, body string, v any) error {
	cmd := fmt.Sprintf("curl -sS --max-time 10 --cacert /tmp/cbb-ca.pem --resolve clipboardbridge.local:%s:%s -H 'Content-Type: application/json' --data-binary @- https://clipboardbridge.local:%s%s",
		s.port, s.addr, s.port, path)
	if token != "" {
		cmd += " -H " + shellQuote("Authorization: Bearer "+token)
	}
	out, err := Run(ctx, s.phone, cmd, body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		return fmt.Errorf("%s answered %q", path, firstLine(out))
	}
	return nil
}

// sync runs the shortcut once with the iPhone's clipboard text.
func (s *shortcut) sync(ctx context.Context, text, token string) (syncReply, error) {
	body, _ := json.Marshal(map[string]any{"v": 1, "text": text})
	var rep syncReply
	err := s.post(ctx, "/sync", token, string(body), &rep)
	return rep, err
}

// phoneWindow opens cbb pair -phone on hub until stop and returns what it
// shows: the address, the fingerprint's start and the code.
func phoneWindow(ctx context.Context, hub *Device) (addr, port, fp, code string, stop func(), err error) {
	ctx, cancel := context.WithCancel(ctx)
	got := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- Stream(ctx, hub, "cbb pair -phone", func(line string) {
			if m := phoneURLRE.FindStringSubmatch(line); m != nil {
				addr, port = m[1], m[2]
			}
			if m := phoneFPRE.FindStringSubmatch(line); m != nil {
				fp = m[1]
			}
			if m := phoneCodeRE.FindStringSubmatch(line); m != nil {
				code = m[1] + m[2]
			}
			if strings.HasPrefix(line, "Waiting up to") {
				select {
				case got <- struct{}{}:
				default:
				}
			}
		})
	}()
	stop = func() {
		cancel()
		Run(context.WithoutCancel(ctx), hub, "pkill -f 'cbb pair' || true", "")
	}
	select {
	case <-got:
		if addr == "" || fp == "" || code == "" {
			stop()
			return "", "", "", "", nil, fmt.Errorf("cbb pair -phone showed address %q, fingerprint %q, code %q", addr, fp, code)
		}
		return addr, port, fp, code, stop, nil
	case err = <-done:
		stop()
		if err == nil {
			err = errors.New("cbb pair -phone ended")
		}
		return "", "", "", "", nil, err
	case <-time.After(30 * time.Second):
		stop()
		return "", "", "", "", nil, errors.New("cbb pair -phone showed nothing in 30 s")
	}
}

// phoneShortcut (X1 to X4, K12, G24): an iPhone with the shortcut, played
// by curl: the profile over plain HTTP only while the window is open, its
// fingerprint and the CA's name constraints, pairing by code over the
// iPhone CA, POST /sync each way, the tokens refused once revoked, and a
// new iPhone CA once an admin is removed.
func phoneShortcut(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/X2-shortcut/"
	g := fleetGroup(ctx, r, f, "fleet/X2-shortcut", 2)
	if g == nil || len(g.members) < 2 {
		return
	}
	hub, other := g.members[0], g.members[1]
	var s *shortcut
	if r.Do(p+"phone", func() error {
		d, err := f.Add(ctx)
		s = &shortcut{phone: d}
		return err
	}) != nil {
		return
	}
	var code, fp0 string
	var ca []byte
	if r.Do("fleet/X1-profile", func() error {
		addr, port, fp, c, stop, err := phoneWindow(ctx, hub)
		if err != nil {
			return err
		}
		defer stop()
		s.addr, s.port, code = addr, port, c
		out, err := Run(ctx, s.phone, "curl -sS --max-time 10 http://"+addr+":"+port+"/clipboardbridge.mobileconfig", "")
		if err != nil {
			return err
		}
		m := profileDataRE.FindStringSubmatch(out)
		if m == nil {
			return fmt.Errorf("the profile carries no certificate: %q", firstLine(out))
		}
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(m[1]), ""))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(der)
		var hex []string
		for _, b := range sum[:8] {
			hex = append(hex, fmt.Sprintf("%02X", b))
		}
		if got := strings.Join(hex, " "); got != fp {
			return fmt.Errorf("the profile's fingerprint starts %s, the terminal shows %s", got, fp)
		}
		ca, fp0 = der, fp
		if _, err := Run(ctx, s.phone, "cat >/tmp/cbb-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))); err != nil {
			return err
		}
		// The code goes only over the trusted CA, never plain HTTP.
		if out, err := Run(ctx, s.phone, "curl -s -o /dev/null -w '%{http_code}' -X POST http://"+addr+":"+port+"/pair -d code="+code, ""); err != nil || strings.TrimSpace(out) == "200" {
			return fmt.Errorf("POST /pair over plain HTTP answered %q: %v", out, err)
		}
		var rep struct {
			OK      bool   `json:"ok"`
			Token   string `json:"token"`
			Message string `json:"message"`
		}
		if err := s.post(ctx, "/pair", "", `{"v":1,"code":"`+code+`"}`, &rep); err != nil {
			return err
		}
		if !rep.OK || rep.Token == "" {
			return fmt.Errorf("pairing the shortcut: %s", rep.Message)
		}
		s.token = rep.Token
		return nil
	}) != nil {
		return
	}
	r.Do("fleet/X4-name-constraints", func() error {
		// The iPhone CA vouches for clipboardbridge.local alone, and for
		// no IP address.
		c, err := x509.ParseCertificate(ca)
		switch {
		case err != nil:
			return err
		case !c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains) != 1 || c.PermittedDNSDomains[0] != "clipboardbridge.local":
			return fmt.Errorf("the iPhone CA permits the names %q (critical %v)", c.PermittedDNSDomains, c.PermittedDNSDomainsCritical)
		}
		for _, ip := range []string{"192.168.1.1", "10.0.0.1", "fd00::1", "2001:db8::1"} {
			excluded := false
			for _, n := range c.ExcludedIPRanges {
				excluded = excluded || n.Contains(net.ParseIP(ip))
			}
			if !excluded {
				return fmt.Errorf("the iPhone CA does not exclude %s", ip)
			}
		}
		return nil
	})
	r.Do("fleet/X1-closed", func() error {
		return eventually(ctx, timeout, func() error {
			out, _ := Run(ctx, s.phone, "curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://"+s.addr+":"+s.port+"/clipboardbridge.mobileconfig", "")
			if strings.TrimSpace(out) == "200" {
				return errors.New("the profile is served with no pairing window open")
			}
			return nil
		})
	})
	want := func(rep syncReply, err error, direction, copy string) error {
		switch {
		case err != nil:
			return err
		case rep.Direction != direction || rep.Copy != copy:
			return fmt.Errorf("the shortcut got %s %q (%s), not %s %q", rep.Direction, rep.Copy, rep.Message, direction, copy)
		}
		return nil
	}
	text := "cbb-bench " + g.run
	r.Do(p+"phone-text-to-group", func() error {
		rep, err := s.sync(ctx, text+" from the phone", s.token)
		if err := want(rep, err, "from_iphone", ""); err != nil {
			return err
		}
		return arrives(ctx, other, text+" from the phone", timeout)
	})
	// The phone's own text is no computer's copy: nothing comes back.
	r.Do(p+"nothing-new", func() error {
		rep, err := s.sync(ctx, text+" from the phone", s.token)
		return want(rep, err, "none", "")
	})
	r.Do(p+"computer-copy-to-phone", func() error {
		if err := Copy(ctx, other, text+" from a computer"); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			rep, err := s.sync(ctx, "", s.token)
			return want(rep, err, "to_iphone", text+" from a computer")
		})
	})
	r.Do("fleet/X3-unknown-token", func() error {
		bad := "cb1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		rep, err := s.sync(ctx, "", bad)
		if err := want(rep, err, "unpaired", ""); err != nil {
			return err
		}
		if strings.Contains(rep.Message, bad) {
			return fmt.Errorf("the message repeats the token: %q", rep.Message)
		}
		return nil
	})
	// K12: -new-token revokes every token given so far.
	r.Do("fleet/K12-kept-hashed", func() error {
		out, err := Run(ctx, hub, "grep -rlF "+shellQuote(strings.TrimPrefix(s.token, "cb1."))+" /var/lib/clipboardbridge || true", "")
		if err == nil && strings.TrimSpace(out) != "" {
			err = fmt.Errorf("the token is kept as it is in %s", out)
		}
		return err
	})
	r.Do("fleet/K12-new-token", func() error {
		out, err := Run(ctx, hub, "timeout 5 cbb pair -phone -new-token </dev/null >/dev/null 2>&1; true", "")
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return eventually(ctx, timeout, func() error {
			rep, err := s.sync(ctx, "", s.token)
			return want(rep, err, "unpaired", "")
		})
	})
	// G24: removing an admin replaces the iPhone CA, whose key admins
	// hold: the old profile's CA no longer trusts the member, and a new
	// window shows another fingerprint.
	r.Do("fleet/G24-admin-removed", func() error {
		if err := succeeds(ctx, hub, "cbb admin -allow-file-key "+other.Name, "", "is an admin now"); err != nil {
			return err
		}
		if err := listsAs(ctx, g.members, other.Name, "admin", false, timeout); err != nil {
			return err
		}
		if _, err := Run(ctx, hub, "cbb remove "+other.Name, ""); err != nil {
			return err
		}
		return eventually(ctx, timeout, func() error {
			if _, err := s.sync(ctx, "", s.token); err == nil {
				return errors.New("the shortcut still trusts the member through the old iPhone CA")
			}
			return nil
		})
	})
	r.Do("fleet/G24-new-fingerprint", func() error {
		_, _, fp, _, stop, err := phoneWindow(ctx, hub)
		if err != nil {
			return err
		}
		stop()
		if fp == fp0 {
			return fmt.Errorf("the iPhone CA's fingerprint is still %s after an admin's removal", fp)
		}
		return nil
	})
}
