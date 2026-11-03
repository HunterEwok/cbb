// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package forward

import (
	"container/heap"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/HunterEwok/cbb/internal/budget"
	"github.com/HunterEwok/cbb/internal/group"
)

// What the forwarder keeps of the groups that are not registered now. A
// group's authority records are a few kilobytes (a handful of roots, admins
// and removals); the bounds leave a genuine group room to spare and stop a
// group nobody knows from filling the forwarder's memory.
const (
	// rememberedGroups bounds the groups whose records, or credential
	// versions, the forwarder keeps after their registration ends; past it
	// the memory forgets as rememberedBytes says, versions the group kept
	// least recently.
	rememberedGroups = 100_000
	// rememberedGroupBytes bounds the records kept for one group: a
	// registration whose authority records come to more is refused, so
	// that none of them is left out.
	rememberedGroupBytes = 256 << 10
	// rememberedBytes bounds the records kept for all groups that are not
	// registered now; past it the provider (an IPv6 /32, an IPv4 /16) that
	// holds the most of them gives up its group kept least recently.
	rememberedBytes = 32 << 20
	// networkRecordBytes, wideRecordBytes and providerRecordBytes bound the
	// records that the registrations from one network (an IPv4 /24 or an
	// IPv6 /64), from one wide network (an IPv4 /16 or an IPv6 /48) and from
	// one IPv6 provider (a /32) bring, registered or not: a registration
	// whose new records would take its source past them is refused
	// (docs/relay-budget.md).
	networkRecordBytes  = 4 * rememberedGroupBytes
	wideRecordBytes     = 16 * rememberedGroupBytes
	providerRecordBytes = 64 * rememberedGroupBytes
)

// memory keeps in memory, for each group that registered with records (a
// hub from before the credentials, docs/protocol.md, section 13), its
// authority records (group.Records.AuthorityRecords: revocations, freezes,
// thaws, roots and the root's own device records, which make phones admins
// or not). A hub that the group removed, or an admin it demoted, could
// otherwise register again while the group's own hub is away, with the
// records from before. Nothing of them is written to disk: a group that
// registers with a credential needs none of them (versions).
//
// The records of a group that is registered now are never forgotten, and
// they are no part of what the memory keeps of the others: those, the
// groups that are away, are bounded in count and in bytes, per group and in
// all. Every group's bytes are charged to the network that brought them, by
// its first address, which is all the memory keeps of where they came
// from; a group that is away is held for the provider (an IPv6 /32, an
// IPv4 /16) that brought most of its records. Past the bounds the memory
// forgets from the provider that holds the most, its group kept least
// recently first, so a genuine group is forgotten only once every other
// provider holds no more than its own (docs/relay-budget.md).
type memory struct {
	mu     sync.Mutex
	live   func(tag string) bool // whether the group is registered now; nil: none is
	groups map[string]*kept
	bytes  int // the size of every group's records
	payers *budget.Count
	// The groups that are away, by the provider that holds them.
	away      map[netip.Prefix]*holder
	heaviest  holders // the holders, the one that holds the most first
	awayBytes int
	awayCount int
}

// kept is one group's records.
type kept struct {
	tag   string
	recs  []group.Record
	ids   map[[sha256.Size]byte]struct{} // by envelopeKey
	bytes int
	paid  map[netip.Addr]int // by the network that brought them
	from  netip.Addr         // the network of the registration that kept it first
	// While the group is away: the provider that holds it, and its place
	// in that one's groups.
	holder *holder
	elem   *list.Element
}

// holder is a provider (an IPv6 /32, an IPv4 /16) and the groups that are
// away that it holds.
type holder struct {
	provider netip.Prefix
	groups   *list.List // of *kept, the group kept least recently first
	bytes    int
	index    int // in memory.heaviest
}

// groupWeight is what a group that is away costs besides its records: the
// count of groups is bounded too, and a holder of many small groups weighs
// as much as their memory.
const groupWeight = 512

func (h *holder) weight() int { return h.bytes + groupWeight*h.groups.Len() }

// holders is a heap of holders, the heaviest first.
type holders []*holder

func (h holders) Len() int           { return len(h) }
func (h holders) Less(i, j int) bool { return h[i].weight() > h[j].weight() }
func (h holders) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *holders) Push(x any) {
	x.(*holder).index = len(*h)
	*h = append(*h, x.(*holder))
}
func (h *holders) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

func newMemory(live func(tag string) bool) *memory {
	return &memory{live: live, groups: map[string]*kept{}, away: map[netip.Prefix]*holder{},
		payers: budget.NewCount(budget.Caps{Network: networkRecordBytes, Wide: wideRecordBytes, Provider: providerRecordBytes})}
}

// envelopeKey names a record as the memory keeps it: one body may come
// under several signers, each an envelope of its own that the group's
// records keep (docs/protocol.md, section 10), so the key is the record's
// ID and its signature.
func envelopeKey(r group.Record) [sha256.Size]byte {
	id := r.ID()
	h := sha256.New()
	h.Write(id[:])
	h.Write(r.Sig)
	return [sha256.Size]byte(h.Sum(nil))
}

// recordBytes is what a record costs in memory, about.
func recordBytes(r group.Record) int {
	n := len(r.Body) + len(r.Sig) + 64
	for _, c := range r.Chain {
		n += len(c)
	}
	return n
}

// fits reports whether the forwarder can keep records for one group.
func fits(records []group.Record) bool {
	n := 0
	for _, r := range records {
		n += recordBytes(r)
	}
	return n <= rememberedGroupBytes
}

// records returns what the forwarder knows of the group's authority.
func (m *memory) records(tag string) []group.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g := m.groups[tag]; g != nil {
		return slices.Clone(g.recs)
	}
	return nil
}

// keys returns the envelope keys of records, each hashed once, outside the
// memory's lock.
func keys(records []group.Record) [][sha256.Size]byte {
	ks := make([][sha256.Size]byte, len(records))
	for i, r := range records {
		ks[i] = envelopeKey(r)
	}
	return ks
}

// room reports whether the records that a registration from the address
// from would add to what the memory keeps for the group fit within what
// its network, wide network and provider may bring. It changes nothing.
func (m *memory) room(tag string, from netip.Addr, records []group.Record) error {
	ks := keys(records)
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[tag]
	n := 0
	for i, r := range records {
		if g != nil {
			if _, ok := g.ids[ks[i]]; ok {
				continue
			}
		}
		n += recordBytes(r)
	}
	if _, full := m.payers.Full(network(from).Addr(), n); n > 0 && full {
		return errors.New("the forwarder keeps as many records from this network as it can; try again later")
	}
	return nil
}

// keep remembers the group's authority records, checked ones only: what
// authority returned, which fits, from a registration from the address
// from, which room let through. Records the group already has are not
// looked at again; a record that would take the group past its bound,
// which only a registration of the group at the same time can bring, is
// left out.
func (m *memory) keep(tag string, from netip.Addr, records []group.Record) {
	ks := keys(records)
	payer := network(from).Addr()
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[tag]
	if g == nil {
		g = &kept{tag: tag, ids: map[[sha256.Size]byte]struct{}{}, paid: map[netip.Addr]int{}, from: payer}
		m.groups[tag] = g
	}
	m.returnedLocked(g)
	for i, r := range records {
		// Another registration of the group may have kept records meanwhile.
		if _, ok := g.ids[ks[i]]; ok {
			continue
		}
		n := recordBytes(r)
		if g.bytes+n > rememberedGroupBytes {
			continue
		}
		g.ids[ks[i]] = struct{}{}
		g.recs = append(g.recs, r)
		g.bytes += n
		g.paid[payer] += n
		m.payers.Add(payer, n)
		m.bytes += n
	}
	if m.live == nil || !m.live(tag) {
		// Its registration ended meanwhile, or the tests keep groups that
		// none is registered for.
		m.leftLocked(g)
	}
}

// left tells the memory that a registration of the group ended: unless
// another one holds the group now, the group is away from now on.
func (m *memory) left(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g := m.groups[tag]; g != nil && g.holder == nil && (m.live == nil || !m.live(tag)) {
		m.leftLocked(g)
	}
}

// leftLocked counts the group among those that are away, as the one kept
// last, after forgetting what the bounds leave no room for beside it.
func (m *memory) leftLocked(g *kept) {
	for (m.awayBytes+g.bytes > rememberedBytes || m.awayCount+1 > rememberedGroups) && len(m.heaviest) > 0 {
		o := m.heaviest[0].groups.Front().Value.(*kept)
		m.returnedLocked(o)
		if m.live != nil && m.live(o.tag) {
			// It registered again without records to keep.
			continue
		}
		delete(m.groups, o.tag)
		m.bytes -= o.bytes
		for a, n := range o.paid {
			m.payers.Remove(a, n)
		}
	}
	// The provider that brought most of its records holds it.
	prov, most := budget.Of(g.from, budget.Provider), 0
	for a, n := range g.paid {
		if p := budget.Of(a, budget.Provider); n > most || n == most && p.Addr().Less(prov.Addr()) {
			prov, most = p, n
		}
	}
	h := m.away[prov]
	if h == nil {
		h = &holder{provider: prov, groups: list.New()}
		m.away[prov] = h
		heap.Push(&m.heaviest, h)
	}
	g.holder, g.elem = h, h.groups.PushBack(g)
	h.bytes += g.bytes
	m.awayBytes += g.bytes
	m.awayCount++
	heap.Fix(&m.heaviest, h.index)
}

// returnedLocked takes the group out of those that are away, if it is.
func (m *memory) returnedLocked(g *kept) {
	h := g.holder
	if h == nil {
		return
	}
	h.groups.Remove(g.elem)
	g.holder, g.elem = nil, nil
	h.bytes -= g.bytes
	m.awayBytes -= g.bytes
	m.awayCount--
	if h.groups.Len() == 0 {
		heap.Remove(&m.heaviest, h.index)
		delete(m.away, h.provider)
	} else {
		heap.Fix(&m.heaviest, h.index)
	}
}

// RemoveGroupFiles deletes the files that earlier versions kept in dir, one
// for each group that registered, with its roots and removals, and then dir
// itself when nothing else is left in it. It returns how many it deleted.
func RemoveGroupFiles(dir string) (int, error) {
	es, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range es {
		name := e.Name()
		tag, ok := strings.CutSuffix(strings.TrimSuffix(name, ".tmp"), ".json")
		if !ok || !validTag(tag) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return n, err
		}
		n++
	}
	os.Remove(dir) // only when it is empty
	return n, nil
}

// validTag reports whether tag is a group tag, 16 lowercase hex digits.
func validTag(tag string) bool {
	if len(tag) != 16 {
		return false
	}
	_, err := hex.DecodeString(tag)
	return err == nil && tag == strings.ToLower(tag)
}
