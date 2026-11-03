// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package relay

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/netip"
	"sync"

	"github.com/HunterEwok/cbb/internal/group"
)

// A recordSet is a group's authority records as the relay keeps them: the
// set that has verified them, the bytes they take, which an open relay
// bounds for each group, and what each source that brought them paid, which
// it bounds for each source and in all (Limits).
type recordSet struct {
	set   *group.Records
	bytes int
	paid  map[netip.Addr]int
}

// recordSize is what a record takes in memory, as far as the limits count.
func recordSize(r group.Record) int {
	n := len(r.Body) + len(r.Sig)
	for _, c := range r.Chain {
		n += len(c)
	}
	return n
}

// A tagLock keeps the registrations of one group one at a time while they
// check its records, which the set does not allow at once; it exists only
// while some registration holds or waits for it.
type tagLock struct {
	mu sync.Mutex
	n  int
}

// lockTag waits for its turn among the registrations of the group tag, and
// returns the function that ends it.
func (r *Relay) lockTag(tag string) (unlock func()) {
	r.mu.Lock()
	l := r.tagLocks[tag]
	if l == nil {
		l = &tagLock{}
		r.tagLocks[tag] = l
	}
	l.n++
	r.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		r.mu.Lock()
		if l.n--; l.n == 0 {
			delete(r.tagLocks, tag)
		}
		r.mu.Unlock()
	}
}

// checkRecords adds the records of a claim to what the relay keeps for the
// group tag, whose first root is root, and returns the group's set (nil when
// the relay keeps none and the claim has none), and whether the claim
// brought records that were new. The caller holds the group's tagLock. Each
// record is verified once, when first sent: the records the relay already
// keeps cost nothing, and the new ones are charged to the address they come
// from. On an open relay, what it keeps for a group, and in all, is bounded.
func (r *Relay) checkRecords(tag string, root *x509.Certificate, from netip.Addr, recs []group.Record) (*recordSet, bool, error) {
	r.mu.Lock()
	rs := r.records[tag]
	if rs == nil && len(recs) == 0 {
		r.mu.Unlock()
		return nil, false, nil
	}
	created := rs == nil
	if created {
		rs = &recordSet{set: group.NewRecords(root), paid: map[netip.Addr]int{}}
	}
	var missing []group.Record
	size := 0
	// A body may come under several signers, each a record of its own.
	type held struct {
		id  [sha256.Size]byte
		sig string
	}
	seen := map[held]bool{}
	for _, rec := range recs {
		k := held{rec.ID(), string(rec.Sig)}
		if seen[k] || rs.set.Has(rec) {
			continue
		}
		seen[k] = true
		missing = append(missing, rec)
		size += recordSize(rec)
	}
	var err error
	switch {
	case len(missing) == 0:
	case !r.allow.Take(from, float64(len(missing)), r.now()):
		err = errors.New("too many records from this network; try again later")
	case r.cfg.Open && rs.bytes+size > r.limits.GroupRecordBytes:
		err = errors.New("the relay keeps as many records of this group as it can")
	case r.cfg.Open && r.fullLocked(from, size):
		err = errors.New("the relay keeps as many records from this network as it can; try again later")
	}
	if err != nil {
		r.mu.Unlock()
		return rs, false, err
	}
	if created {
		r.records[tag] = rs
	}
	rs.bytes += size
	rs.paid[from] += size
	r.recordBytes.Add(from, size)
	r.mu.Unlock()
	// The signatures take time, so they are checked outside the lock, with
	// the group's other registrations waiting.
	fresh, _ := rs.set.AddAll(missing)
	if len(fresh) < len(missing) {
		// What did not verify is not kept.
		kept := 0
		for _, rec := range fresh {
			kept += recordSize(rec)
		}
		r.mu.Lock()
		rs.bytes -= size - kept
		if rs.paid[from] -= size - kept; rs.paid[from] <= 0 {
			delete(rs.paid, from)
		}
		r.recordBytes.Remove(from, size-kept)
		r.mu.Unlock()
	}
	return rs, len(fresh) > 0, nil
}

// fullLocked reports whether size more bytes of records from the address
// from would take the source past its share, or all sources past the open
// relay's limit.
func (r *Relay) fullLocked(from netip.Addr, size int) bool {
	_, full := r.recordBytes.Full(from, size)
	return full
}

// forgetRecords ends a registration that failed: a group that the relay
// holds no device of, and whose records its own registration brought, does
// not keep them. The caller holds the group's tagLock.
func (r *Relay) forgetRecords(tag string) {
	r.mu.Lock()
	if r.cfg.Open && len(r.groups[tag]) == 0 {
		r.dropRecordsLocked(tag)
	}
	r.mu.Unlock()
}

// dropRecordsLocked forgets the records of the group tag.
func (r *Relay) dropRecordsLocked(tag string) {
	if rs := r.records[tag]; rs != nil {
		for a, n := range rs.paid {
			r.recordBytes.Remove(a, n)
		}
		delete(r.records, tag)
	}
}
