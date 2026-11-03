// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/HunterEwok/cbb/internal/atomicfile"
	"github.com/HunterEwok/cbb/internal/budget"
	"github.com/HunterEwok/cbb/internal/group"
)

// stateLabel names the key that hashes what the state table keeps.
const stateLabel = "cbb forwarder state"

// writeDelay is how long a change waits for others before the table is
// written: the file lags the table by at most this.
const writeDelay = 2 * time.Second

// networkTags bounds the entries one network (an IPv4 /24 or an IPv6 /64)
// may add to the table while they last, wideTags those of one wide network
// (an IPv4 /16 or an IPv6 /48) and providerTags those of one IPv6 provider
// (a /32), so that filling the table takes rememberedGroups/wideTags wide
// networks, and for IPv6 rememberedGroups/providerTags providers
// (docs/relay-budget.md).
const (
	networkTags  = 256
	wideTags     = 1024
	providerTags = 4096
)

// tagCaps are the caps of the entries by the source that added them; the
// table's own bound is rememberedGroups.
var tagCaps = budget.Caps{Network: networkTags, Wide: wideTags, Provider: providerTags}

// errTableFull is what a registration with a new tag is refused with when
// the table, or its network's share of it, is full.
var errTableFull = errors.New("this forwarder cannot remember another group now; try again later")

// versions is all the forwarder keeps about the groups that registered with
// a credential (docs/protocol.md, section 13): under a hash of each
// period's tag, the version of its newest hubs' credential and a hash of
// the period key that signed it, so that an older credential, or one of
// another key, is refused. Both hashes are keyed with a secret from the
// forwarder's own key, so the table names no group by itself; and a period
// lasts about a month, so it cannot link one month of a group to the next.
//
// An entry stays until the newest credential it recorded has expired, since
// before that an older credential of the period would be accepted if it were
// forgotten. The table holds at most rememberedGroups entries, each network
// at most networkTags of the entries it added, each wide network at most
// wideTags and each IPv6 provider at most providerTags; a tag new to the table is refused when any of these is reached
// and nothing has expired, and no entry is dropped to make room. With a file the table outlives a restart;
// it is written a moment after a change, and when the forwarder closes.
type versions struct {
	file   string // "" keeps it in memory only
	secret []byte
	now    func() time.Time
	delay  time.Duration                    // writeDelay
	logf   func(format string, args ...any) // nil logs nothing

	mu      sync.Mutex
	entries map[string]versionEntry // by hashed tag
	nets    *budget.Count           // entries added from each network since the start
	seq     uint64
	pruneAt time.Time   // no entry expires before this
	dirty   bool        // changes not yet written
	timer   *time.Timer // the pending write
	write   sync.Mutex  // one write at a time
}

// A versionEntry is one period's newest credential: its version, the
// hashed period key, when it was kept, as a counter, and when the last
// credential it saw expires, in Unix milliseconds.
type versionEntry struct {
	Version uint64 `json:"version"`
	Key     string `json:"key"`
	Seq     uint64 `json:"seq"`
	Expires int64  `json:"expires,omitempty"`

	net netip.Prefix // where it came from; not written
}

// newVersions returns the table, read from file if there is one; its
// hashes are keyed with a secret from the forwarder's key.
func newVersions(file string, key any) (*versions, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, der)
	m.Write([]byte(stateLabel))
	v := &versions{file: file, secret: m.Sum(nil), now: time.Now, delay: writeDelay, entries: map[string]versionEntry{}, nets: budget.NewCount(tagCaps)}
	if file == "" {
		return v, nil
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &v.entries); err != nil {
		return nil, err
	}
	for _, e := range v.entries {
		v.seq = max(v.seq, e.Seq)
	}
	return v, nil
}

func (v *versions) hash(parts ...[]byte) string {
	m := hmac.New(sha256.New, v.secret)
	for _, p := range parts {
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// check reports whether the period's credential, presented from the network
// of from, may register its group: with nothing kept for its tag, any (the
// first period key the forwarder sees for a tag is the group's) while the
// table has room for it; else the same period key must have signed it, at the
// version kept or later.
func (v *versions) check(p *group.Presented, from netip.Addr) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.entries[v.hash([]byte(p.Tag))]
	switch {
	case !ok:
		return v.roomLocked(from)
	case v.hash([]byte(p.Tag), p.Signer[:]) != e.Key:
		return errors.New("another key registered this group's period first")
	case p.Hubs.Version < e.Version:
		return errors.New("the group's hubs' credential is older than one this forwarder saw")
	}
	return nil
}

// roomLocked reports whether a tag new to the table, from the network of
// from, may be added; the entries that have expired go first if it is full.
func (v *versions) roomLocked(from netip.Addr) error {
	full := func() bool {
		_, full := v.nets.Full(from, 1)
		return full || len(v.entries) >= rememberedGroups
	}
	if full() {
		v.pruneLocked()
		if full() {
			return errTableFull
		}
	}
	return nil
}

// pruneLocked forgets the entries whose last credential has expired. It
// scans the table only when one may have.
func (v *versions) pruneLocked() {
	now := v.now()
	if now.Before(v.pruneAt) {
		return
	}
	next := int64(math.MaxInt64)
	changed := false
	for t, e := range v.entries {
		if e.Expires > now.UnixMilli() {
			next = min(next, e.Expires)
			continue
		}
		delete(v.entries, t)
		if e.net.IsValid() {
			v.nets.Remove(e.net.Addr(), 1)
		}
		changed = true
	}
	v.pruneAt = time.UnixMilli(next)
	if changed {
		v.changedLocked()
	}
}

// keep remembers the period's credential, presented from the network of from,
// as the group's newest, and has the table written when it changed. It
// returns errTableFull, keeping nothing, when the tag is new and there is no
// room for it.
func (v *versions) keep(p *group.Presented, from netip.Addr) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	t := v.hash([]byte(p.Tag))
	key := v.hash([]byte(p.Tag), p.Signer[:])
	// A period lasts PeriodLifetime: a credential that claims to last
	// longer, which no group makes, holds its entry no longer than that.
	expires := min(p.Hubs.ExpiresMS, v.now().Add(group.PeriodLifetime).UnixMilli())
	e, ok := v.entries[t]
	if ok && e.Version == p.Hubs.Version && e.Key == key && e.Expires >= expires {
		return nil
	}
	if !ok {
		if err := v.roomLocked(from); err != nil {
			return err
		}
		// The entry is charged to its network and wide network by the
		// network alone, which is all it keeps of where it came from.
		e.net = network(from)
		v.nets.Add(e.net.Addr(), 1)
		if at := time.UnixMilli(expires); v.pruneAt.IsZero() || at.Before(v.pruneAt) {
			v.pruneAt = at
		}
	}
	v.seq++
	e.Version, e.Key, e.Seq = p.Hubs.Version, key, v.seq
	// An older credential may outlast the newest; the entry stays until the
	// last one the group could still present has expired.
	e.Expires = max(e.Expires, expires)
	v.entries[t] = e
	v.changedLocked()
	return nil
}

// changedLocked notes that the table changed and, with a file, has it written
// writeDelay from now unless a write is already waiting.
func (v *versions) changedLocked() {
	if v.file == "" {
		return
	}
	v.dirty = true
	if v.timer == nil {
		v.timer = time.AfterFunc(v.delay, func() {
			if err := v.flush(); err != nil && v.logf != nil {
				v.logf("forward: keeping the state: %v", err)
			}
		})
	}
}

// flush writes the table if it changed since it was last written. The table
// is copied under the lock; it is encoded and written outside it.
func (v *versions) flush() error {
	v.write.Lock()
	defer v.write.Unlock()
	v.mu.Lock()
	if !v.dirty {
		v.mu.Unlock()
		return nil
	}
	v.dirty = false
	if v.timer != nil {
		v.timer.Stop()
		v.timer = nil
	}
	snapshot := maps.Clone(v.entries)
	v.mu.Unlock()
	data, err := json.Marshal(snapshot)
	if err == nil {
		err = atomicfile.Write(v.file, data, 0o600)
	}
	if err != nil {
		v.mu.Lock()
		v.dirty = true
		v.mu.Unlock()
	}
	return err
}
