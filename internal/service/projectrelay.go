// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/HunterEwok/cbb/internal/netguard"
	"github.com/HunterEwok/cbb/internal/node"
	"github.com/HunterEwok/cbb/internal/relay"
	"github.com/HunterEwok/cbb/internal/release"
	"github.com/HunterEwok/cbb/internal/tunnel"
	"github.com/HunterEwok/cbb/internal/update"
)

// The project's relay (cbb global relay default) is known by the signed
// lists, not by what the device was set with (docs/protocol.md, section
// 16, "Entry points"): its keys by keys.json, where the old and the new key
// stand side by side while it changes, and its address by entries.json.
// The device takes the pins at each start; when a registration fails, it
// fetches the newest lists from the mirror, which is on the relay's
// server, looks up the relay's address again and tries at once, without
// asking the user. cbb update and the group bring the lists as well.

// relayRefetch is how often a failing link to the project's relay fetches
// the signed lists again.
const relayRefetch = 10 * time.Minute

// newestKeys returns the newest keys.json this device holds that checks
// out, from its release or from its entry points; false for none.
func (s *Service) newestKeys() (release.Keys, bool) {
	var files []release.File
	if h := s.heldRelease(); h != nil {
		files = append(files, h.set.Keys)
	}
	if h := s.heldEntries(); h != nil {
		files = append(files, h.set.Keys)
	}
	var best release.Keys
	ok := false
	for _, f := range files {
		k, err := release.VerifyKeys(f, s.releaseRoots(), s.cfg.now(), release.Seen{})
		if err == nil && (!ok || k.Seq > best.Seq) {
			best, ok = k, true
		}
	}
	return best, ok
}

// projectRelayPins returns the pins this device accepts from the project's
// relay: those of the newest keys.json, when it names any, else the
// built-in ones.
func (s *Service) projectRelayPins() []string {
	var listed [][]byte
	if k, ok := s.newestKeys(); ok {
		listed = k.Relays(relay.ProjectHost)
	}
	return relay.ProjectPins(listed)
}

// projectRelayLink is the link to the project's relay at ep with the pins
// of the newest keys.json.
func (s *Service) projectRelayLink(ep netip.AddrPort) relay.Link {
	pins := s.projectRelayPins()
	return relay.Link{Endpoint: ep, Pin: pins[0], Also: pins[1:]}
}

// projectRelayAddrs looks up where the project's relay is reached now: the
// addresses its newest entry points give, else its own name.
func (s *Service) projectRelayAddrs(ctx context.Context) []netip.AddrPort {
	names := []string{relay.ProjectHost}
	if h := s.heldEntries(); h != nil {
		if r, ok := h.entries.Relay(relay.ProjectHost); ok && len(r.Endpoints) > 0 {
			names = r.Endpoints
		}
	}
	var out []netip.AddrPort
	for _, name := range names {
		host, port, err := net.SplitHostPort(name)
		if err != nil {
			continue
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			continue
		}
		p := uint16(n)
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := s.cfg.lookupIP(lctx, host)
		cancel()
		if err != nil {
			s.logf("cbb: sync away from home: looking up the relay at %s: %v", name, err)
			continue
		}
		for _, ip := range ips {
			if ep := netip.AddrPortFrom(ip.Unmap(), p); !slices.Contains(out, ep) {
				out = append(out, ep)
			}
		}
	}
	return out
}

// fetchProjectLists fetches keys.json and entries.json from the mirror,
// reached at the relay's address, since the service's network reaches no
// other server; the service checks them, keeps them when they are newer
// and passes them to the group.
func (s *Service) fetchProjectLists(ctx context.Context, at netip.Addr) error {
	src := update.MirrorThrough(func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: 15 * time.Second, Control: netguard.Control}
		return d.DialContext(ctx, "tcp", netip.AddrPortFrom(at, 443).String())
	})
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	keys, err := update.FetchKeys(ctx, src)
	if err != nil {
		return err
	}
	entries, err := update.FetchEntries(ctx, src)
	if err != nil {
		return err
	}
	return s.putEntries(node.EntriesSet{Keys: keys, Entries: entries})
}

// relayKeyRefused reports whether err says the relay's key is none of the
// pins.
func relayKeyRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not the one given")
}

// projectRelayRetry returns the Retry of a link to the project's relay
// for run: after a failure it fetches the signed lists, at most every
// relayRefetch, then gives the link with their pins and, when the relay
// does not answer where it was, the next address it is reached at, kept in
// the state and allowed by the network limit.
func (s *Service) projectRelayRetry(run *tunRun) func(ctx context.Context, err error) (relay.Link, bool) {
	var fetched time.Time
	return func(ctx context.Context, err error) (relay.Link, bool) {
		s.tunMu.Lock()
		st := s.tunnel
		if s.tunRun != run || st == nil || st.Relay == nil || !st.Relay.Project {
			s.tunMu.Unlock()
			return relay.Link{}, false
		}
		cur := st.Relay.Endpoint
		s.tunMu.Unlock()
		if fetched.IsZero() || time.Since(fetched) >= relayRefetch {
			fetched = time.Now()
			if ferr := s.fetchProjectLists(ctx, cur.Addr()); ferr != nil {
				s.logf("cbb: sync away from home: fetching the signed lists for the relay: %v", ferr)
			}
		}
		next := cur
		if !relayKeyRefused(err) {
			// It did not answer there: the next address it has, or the
			// first when that one is none of them any more.
			addrs := s.projectRelayAddrs(ctx)
			if i := slices.Index(addrs, cur); i >= 0 && len(addrs) > 1 {
				next = addrs[(i+1)%len(addrs)]
			} else if i < 0 && len(addrs) > 0 {
				next = addrs[0]
			}
		}
		if next != cur {
			if serr := s.moveProjectRelay(run, next); serr != nil {
				s.logf("cbb: sync away from home: %v", serr)
				next = cur
			}
		}
		return s.projectRelayLink(next), ctx.Err() == nil
	}
}

// moveProjectRelay keeps ep as the project's relay's address in the state
// and lets the service reach it.
func (s *Service) moveProjectRelay(run *tunRun, ep netip.AddrPort) error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	st := s.tunnel
	if s.tunRun != run || st == nil || st.Relay == nil {
		return errors.New("the link to the relay ended")
	}
	old := *st.Relay
	st.Relay.Endpoint = ep
	if err := st.Save(s.cfg.StateDir); err != nil {
		*st.Relay = old
		return fmt.Errorf("saving the relay's new address: %w", err)
	}
	s.guardLocked()
	s.logf("cbb: sync away from home: the relay is reached at %v now; where the system limits this service's network, run cbb global allow", ep)
	return nil
}

// relayLink is the link a device starts with to its relay: the one it was
// set with, or for the project's relay its last address with the pins of
// the newest keys.json.
func (s *Service) relayLink(l tunnel.RelayLink) relay.Link {
	if l.Project {
		return s.projectRelayLink(l.Endpoint)
	}
	return relay.Link{Endpoint: l.Endpoint, Pin: l.Pin}
}
