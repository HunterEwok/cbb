// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package authority

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"sort"
	"strconv"

	"github.com/HunterEwok/clipboardbridge/internal/strict"
)

// Input is what the evaluation takes (docs/protocol.md, section 10, "The state").
type Input struct {
	// GroupCA is the group's first root; its tag is Group.
	GroupCA *x509.Certificate
	Group   string
	Records []Record
	// NowMS is the member's clock, which counts sleep and does not jump,
	// and FirstSeen the time on that clock when the member first held
	// each claim, by record ID; a claim missing from it was first held
	// now.
	NowMS     int64
	FirstSeen map[Hash]int64
	// TimeUnknown says the member does not know how long it has held its
	// claims: its clock started again and it kept no time. No claim then
	// takes effect by waiting (docs/protocol.md, section 10, "Handing the group
	// over").
	TimeUnknown bool
}

// rec is a verified record with what the evaluation finds about it.
type rec struct {
	*Signed
	issuer Hash // the root that issued the admin CA; zero for a root's own record
	key    limitKey
	label  label
	why    string // why the labelling put it out
}

type label int

const (
	unlabelled label = iota
	in
	out
	undecided
)

// Evaluate turns a record set into the group's state. It drops records
// that do not verify, and depends only on the set, never on its order.
func Evaluate(input Input) (*State, error) {
	if input.GroupCA == nil {
		return nil, errors.New("authority: no group CA")
	}
	// The set a root's checkpoint prunes is evaluated as if the member had
	// dropped what it leaves out; the checkpoint that counts is the newest
	// that still counts there (docs/protocol.md, section 10, "Checkpoints").
	full := newEvaluation(input, nil)
	var best *State
	var bestKey [2]int64
	var bestID Hash
	for _, c := range full.checkpoints(KeyHashOf(input.GroupCA)) {
		in := input
		in.Records = prune(input.Records, input.Group, c)
		e := newEvaluation(in, anchorsOf(&c.Body))
		ep := e.run(in)
		r := e.byID(c.ID)
		if r == nil || !ep.rootRecord(r) {
			continue
		}
		key := [2]int64{int64(ep.onPath[c.Body.Signer]), c.Body.Seq}
		if best == nil || key[0] > bestKey[0] || key[0] == bestKey[0] && (key[1] > bestKey[1] || key[1] == bestKey[1] && c.ID.String() < bestID.String()) {
			best, bestKey, bestID = ep.finish(in), key, c.ID
			best.Checkpoint = &c.ID
		}
	}
	if best != nil {
		return best, nil
	}
	return full.run(input).finish(input), nil
}

// MaxCheckpoints is how many of a set's checkpoints the evaluation tries:
// those of the highest seq, then the smallest ID.
const MaxCheckpoints = 8

// run turns the evaluation into its last epoch, with the claims of the
// roots before the current one.
func (e *evaluation) run(input Input) *epoch {
	path, cuts := []Hash{KeyHashOf(input.GroupCA)}, map[Hash]int64{}
	var ep *epoch
	var earlier []Claim // the claims of the roots before the current one
	for {
		ep = e.epoch(path, cuts)
		next, cut := ep.decideClaims(input.NowMS, input.FirstSeen, input.TimeUnknown)
		if next == nil {
			break
		}
		earlier = append(earlier, ep.claims...)
		cuts[path[len(path)-1]] = cut
		path = append(path, *next)
	}
	ep.claims = append(earlier, ep.claims...)
	return ep
}

// finish builds the state of the last epoch.
func (ep *epoch) finish(input Input) *State {
	s := ep.state()
	s.Newer = newer(input, s, ep.e.roots)
	s.Ignored = ep.ignored(s.Newer)
	return s
}

// checkpoints returns the checkpoints the evaluation tries: a root's own,
// of a root of the group (the group CA, or the root of a claim that an
// admin under such a root signed), at most MaxCheckpoints. They come from
// every verified record, past the limits too, so that a root's checkpoint
// can bring a set back under them.
func (e *evaluation) checkpoints(groupCA Hash) []*rec {
	roots := map[Hash]bool{groupCA: true}
	for grew := true; grew; {
		grew = false
		for _, rs := range e.allBy {
			for _, r := range rs {
				if r.Body.Type != TypeClaim || r.AdminCA == nil || !roots[r.issuer] {
					continue
				}
				if c, err := x509.ParseCertificate(r.Body.Root); err == nil && !roots[KeyHashOf(c)] {
					roots[KeyHashOf(c)], grew = true, true
				}
			}
		}
	}
	var cs []*rec
	for signer := range roots {
		for _, r := range e.allBy[signer] {
			if r.AdminCA == nil && r.Body.Type == TypeCheckpoint {
				cs = append(cs, r)
			}
		}
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Body.Seq != cs[j].Body.Seq {
			return cs[i].Body.Seq > cs[j].Body.Seq
		}
		return cs[i].ID.String() < cs[j].ID.String()
	})
	if len(cs) > MaxCheckpoints {
		cs = cs[:MaxCheckpoints]
	}
	return cs
}

// prune leaves out of a set what checkpoint c drops: each record of this
// group whose body reads, at or below its signer's head, that is neither a
// head nor kept, whether or not its signature checks.
func prune(recs []Record, group string, c *rec) []Record {
	heads := map[Hash]Head{}
	for _, h := range c.Body.Heads {
		heads[h.Key] = h
	}
	anchors := anchorsOf(&c.Body)
	var out []Record
	for _, r := range recs {
		if b, err := ParseBody(r.Body); err == nil && b.Group == group {
			if h, ok := heads[b.Signer]; ok && b.Seq <= h.Seq && !anchors[r.ID()] {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// byID finds a verified record.
func (e *evaluation) byID(id Hash) *rec {
	for _, rs := range e.bySig {
		for _, r := range rs {
			if r.ID == id {
				return r
			}
		}
	}
	return nil
}

// newer returns the IDs of the records of a later version for this group
// that a current root or admin of s signed, sorted, at most MaxNewer: a
// member keeps them and passes them on, never applies them, and tells its
// user to update (docs/protocol.md, section 10, "Records of a later version").
func newer(input Input, s *State, roots map[Hash]*x509.Certificate) []Hash {
	admins := map[Hash]bool{}
	for _, d := range s.Devices {
		if d.Admin != nil {
			admins[*d.Admin] = true
		}
	}
	var ids []Hash
	for _, r := range input.Records {
		if len(r.Body) > MaxBody || strict.CheckCanonical(r.Body, "v", "group", "signer") != nil {
			continue
		}
		var b struct {
			V      json.RawMessage `json:"v"`
			Group  any             `json:"group"`
			Signer Hash            `json:"signer"`
		}
		if json.Unmarshal(r.Body, &b) != nil || b.Group != input.Group {
			continue
		}
		// The raw token: an integer, never a quoted one.
		v, err := strconv.ParseInt(string(b.V), 10, 64)
		if err != nil || v <= 2 || v > MaxSeq {
			continue
		}
		var pub crypto.PublicKey
		switch {
		case len(r.Chain) == 0 && contains(s.Roots, b.Signer) && roots[b.Signer] != nil:
			pub = roots[b.Signer].PublicKey
		case len(r.Chain) == 1 && admins[b.Signer]:
			if ca, err := x509.ParseCertificate(r.Chain[0]); err == nil && KeyHashOf(ca) == b.Signer {
				pub = ca.PublicKey
			}
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		digest := sha256.Sum256(r.Body)
		if !ok || !ecdsa.VerifyASN1(ec, digest[:], r.Sig) {
			continue
		}
		if id := r.ID(); !contains(ids, id) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	if len(ids) > MaxNewer {
		ids = ids[:MaxNewer]
	}
	return ids
}

// evaluation holds the verified records of a set.
type evaluation struct {
	anchors map[Hash]bool              // the heads and keep of the checkpoint it prunes by, where a prev chain may end
	failed  map[Hash]string            // why records left out before the epochs were, by ID
	roots   map[Hash]*x509.Certificate // every root the group may have
	bySig   map[Hash][]*rec            // records by signer
	allBy   map[Hash][]*rec            // bySig with the records past the limits too, for checkpoints
	devices map[string][]*rec          // device records by device ID
	capped  map[Hash]bool              // device records over MaxDevices or MaxAdmins, which count for nothing
}

func newEvaluation(input Input, anchors map[Hash]bool) *evaluation {
	e := &evaluation{anchors: anchors, failed: map[Hash]string{}, roots: map[Hash]*x509.Certificate{KeyHashOf(input.GroupCA): input.GroupCA}, bySig: map[Hash][]*rec{}, allBy: map[Hash][]*rec{}, devices: map[string][]*rec{}, capped: map[Hash]bool{}}
	// The new roots of claims are the only other roots a record may be
	// signed under; a claim itself is signed by an admin CA.
	for _, r := range input.Records {
		if len(r.Chain) != 1 {
			continue
		}
		if b, err := ParseBody(r.Body); err == nil && b.Type == TypeClaim {
			if c, err := x509.ParseCertificate(b.Root); err == nil && checkRoot(c) == nil {
				e.roots[KeyHashOf(c)] = c
			}
		}
	}
	rootKey := func(h Hash) crypto.PublicKey {
		if c := e.roots[h]; c != nil {
			return c.PublicKey
		}
		return nil
	}
	// One body may come with more than one valid admin CA (an admin key
	// certified again); the smallest DER is kept, whatever the order.
	byID := map[Hash]*rec{}
	for _, r := range input.Records {
		s, err := Verify(r, rootKey)
		switch {
		case err != nil:
			if _, perr := ParseBody(r.Body); perr != nil {
				e.fail(r.ID(), WhyUnreadable)
			} else {
				e.fail(r.ID(), WhySignature)
			}
			continue
		case s.Body.Group != input.Group:
			e.fail(s.ID, WhyGroup)
			continue
		}
		x := &rec{Signed: s}
		if s.AdminCA != nil {
			issuer, ok := e.issuerOf(s.AdminCA)
			if !ok {
				e.fail(s.ID, WhyIssuer)
				continue
			}
			x.issuer = issuer
		}
		if old := byID[s.ID]; old == nil || old.AdminCA != nil && bytes.Compare(s.AdminCA.Raw, old.AdminCA.Raw) < 0 {
			byID[s.ID] = x
		}
	}
	for _, x := range byID {
		e.allBy[x.Body.Signer] = append(e.allBy[x.Body.Signer], x)
	}
	for _, x := range e.limit(KeyHashOf(input.GroupCA), byID) {
		e.bySig[x.Body.Signer] = append(e.bySig[x.Body.Signer], x)
		if x.Body.Type == TypeDevice {
			e.devices[x.Body.Device] = append(e.devices[x.Body.Device], x)
		}
	}
	e.capDevices()
	return e
}

// The limits on a record set (docs/protocol.md, section 10, "Limits"). Records over
// them count for nothing, with the reason WhyLimit; the set is never
// refused, so that no admin can stop the group by filling it.
const (
	MaxRecords  = 1024    // records in the set, as the checkpoint prunes it
	MaxSetBytes = 1 << 20 // their bodies, signatures and chains together
	MaxDevices  = 256     // devices with a device record
	MaxAdmins   = 64      // admin keys a root names
	MaxPath     = 16      // roots on the path: the group CA and 15 handovers
)

// limitKey is a record's place in the order the limits take records in:
// the group CA's own records first, then those of the other roots of the
// group, then those under an admin CA of the group, then the rest; within
// each, by depth (how many of its signer's records have a lower seq), then
// signer and ID. Each signer's records stay in seq order, so what a limit
// leaves out is the end of its chains, never a record in the middle.
type limitKey struct {
	rank, depth int
	signer, id  Hash
}

func (a limitKey) less(b limitKey) bool {
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	if a.depth != b.depth {
		return a.depth < b.depth
	}
	if c := bytes.Compare(a.signer[:], b.signer[:]); c != 0 {
		return c < 0
	}
	return bytes.Compare(a.id[:], b.id[:]) < 0
}

// limit returns the records that fit in MaxRecords and MaxSetBytes, taken
// in limitKey order up to the first that does not fit; that one and every
// record after it fail with WhyLimit. It notes each record's key for
// capDevices.
func (e *evaluation) limit(groupCA Hash, byID map[Hash]*rec) []*rec {
	// The roots of the group: the group CA and the root of each claim an
	// admin CA of one of them signed.
	roots := map[Hash]bool{groupCA: true}
	for grew := true; grew; {
		grew = false
		for _, x := range byID {
			if x.Body.Type == TypeClaim && x.AdminCA != nil && roots[x.issuer] {
				if r := claimRoot(x); !roots[r] {
					roots[r], grew = true, true
				}
			}
		}
	}
	rank := map[Hash]int{}
	seqs := map[Hash][]int64{}
	for _, x := range byID {
		k := x.Body.Signer
		r := 3
		switch {
		case k == groupCA:
			r = 0
		case roots[k]:
			r = 1
		case x.AdminCA != nil && roots[x.issuer]:
			r = 2
		}
		if old, ok := rank[k]; !ok || r < old {
			rank[k] = r
		}
		seqs[k] = append(seqs[k], x.Body.Seq)
	}
	for _, q := range seqs {
		slices.Sort(q)
	}
	all := make([]*rec, 0, len(byID))
	for _, x := range byID {
		q := seqs[x.Body.Signer]
		lower := sort.Search(len(q), func(i int) bool { return q[i] >= x.Body.Seq })
		x.key = limitKey{rank: rank[x.Body.Signer], depth: lower, signer: x.Body.Signer, id: x.ID}
		all = append(all, x)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].key.less(all[j].key) })
	size := 0
	for i, x := range all {
		n := len(x.Record.Body) + len(x.Record.Sig)
		for _, c := range x.Record.Chain {
			n += len(c)
		}
		if i >= MaxRecords || size+n > MaxSetBytes {
			for _, y := range all[i:] {
				e.fail(y.ID, WhyLimit)
			}
			return all[:i]
		}
		size += n
	}
	return all
}

// capDevices marks the device records over MaxDevices and MaxAdmins: the
// devices, and the admin keys of a root's own records, are taken in the
// limitKey order of their first such record, and a record naming one
// past the limit counts for nothing.
func (e *evaluation) capDevices() {
	isAdmin := func(x *rec) bool { return x.AdminCA == nil && x.Body.Admin != nil }
	devices := e.over(MaxDevices, func(x *rec) (string, bool) { return x.Body.Device, true })
	admins := e.over(MaxAdmins, func(x *rec) (string, bool) {
		if !isAdmin(x) {
			return "", false
		}
		return x.Body.Admin.String(), true
	})
	for _, rs := range e.devices {
		for _, x := range rs {
			if devices[x.Body.Device] || isAdmin(x) && admins[x.Body.Admin.String()] {
				e.capped[x.ID] = true
			}
		}
	}
}

// over takes the names the device records give (name returns false for a
// record that gives none) in the limitKey order of each name's first record
// and returns those past the first max.
func (e *evaluation) over(max int, name func(*rec) (string, bool)) map[string]bool {
	best := map[string]limitKey{}
	for _, rs := range e.devices {
		for _, x := range rs {
			n, ok := name(x)
			if !ok {
				continue
			}
			if k, seen := best[n]; !seen || x.key.less(k) {
				best[n] = x.key
			}
		}
	}
	names := make([]string, 0, len(best))
	for n := range best {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return best[names[i]].less(best[names[j]]) })
	over := map[string]bool{}
	for _, n := range names[min(len(names), max):] {
		over[n] = true
	}
	return over
}

// fail notes why a record was left out; of two copies of one body left out
// for different reasons, the reason first in byte order is kept, whatever
// the order of the set.
func (e *evaluation) fail(id Hash, why string) {
	if old, ok := e.failed[id]; !ok || why < old {
		e.failed[id] = why
	}
}

// issuerOf finds the root that issued an admin CA.
func (e *evaluation) issuerOf(c *x509.Certificate) (Hash, bool) {
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return Hash{}, false
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return Hash{}, false
	}
	for h, root := range e.roots {
		if c.CheckSignatureFrom(root) == nil {
			return h, true
		}
	}
	return Hash{}, false
}

// certifiedBy reports whether der is an admin CA that the root signer
// signed: a recovery record's cert counts only from the root that names it.
func (e *evaluation) certifiedBy(der []byte, signer Hash) bool {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	issuer, ok := e.issuerOf(c)
	return ok && issuer == signer
}

// checkRoot checks a claim's new root: self-signed, a CA with path
// length 1 and a P-256 key.
func checkRoot(c *x509.Certificate) error {
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 1 || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("authority: a new root is not a CA with path length 1")
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return errors.New("authority: a new root's key is not a P-256 key")
	}
	if c.CheckSignatureFrom(c) != nil {
		return errors.New("authority: a new root is not self-signed")
	}
	return nil
}

// epoch is the evaluation under one path of roots.
type epoch struct {
	e      *evaluation
	path   []Hash
	onPath map[Hash]int // position on the path
	cuts   map[Hash]int64
	cur    Hash

	voided  map[Hash]bool
	counted map[Hash]bool // records whose chain is whole, before any fork, not voided
	forked  map[Hash]int64

	admins    map[Hash]*rec // each admin key's newest root record naming it
	recovery  *rec          // the recovery record that counts, if any
	revoked   map[Hash]bool
	frozen    map[Hash]bool
	conflicts []Conflict
	claims    []Claim
	stopFull  bool
	pending   *Hash // the claimant of a pending claim
}

func (e *evaluation) epoch(path []Hash, cuts map[Hash]int64) *epoch {
	ep := &epoch{e: e, path: path, onPath: map[Hash]int{}, cuts: cuts, cur: path[len(path)-1], forked: map[Hash]int64{}}
	for i, h := range path {
		ep.onPath[h] = i
	}
	ep.voided = ep.voids()
	ep.counted = map[Hash]bool{}
	for signer, rs := range e.bySig {
		ep.chain(signer, rs)
	}
	ep.findAdmins()
	ep.label()
	ep.collect()
	return ep
}

// rootRecord reports whether r is a root's own record that counts in this
// epoch: its root is on the path and it is within that root's cut.
func (ep *epoch) rootRecord(r *rec) bool {
	if r.AdminCA != nil || !ep.counted[r.ID] || ep.e.capped[r.ID] {
		return false
	}
	if _, ok := ep.onPath[r.Body.Signer]; !ok {
		return false
	}
	if cut, ok := ep.cuts[r.Body.Signer]; ok && r.Body.Seq > cut {
		return false
	}
	return true
}

// anchorsOf returns the IDs a checkpoint names: its heads and keep.
func anchorsOf(b *Body) map[Hash]bool {
	a := map[Hash]bool{}
	for _, h := range b.Heads {
		a[h.ID] = true
	}
	for _, id := range b.Keep {
		a[id] = true
	}
	return a
}

// voids returns the records the current root's resolve records name. A
// resolve counts here when its own chain is whole, whatever forks it has,
// so the root can end two histories of its own.
func (ep *epoch) voids() map[Hash]bool {
	v := map[Hash]bool{}
	byID := map[Hash]*rec{}
	for _, r := range ep.e.bySig[ep.cur] {
		byID[r.ID] = r
	}
	for _, r := range ep.e.bySig[ep.cur] {
		if r.AdminCA != nil || r.Body.Type != TypeResolve || !wholeTo(r, byID, ep.e.anchors) {
			continue
		}
		for _, id := range r.Body.Records {
			v[id] = true
		}
	}
	return v
}

// wholeTo reports whether r's prev chain down to seq 1, or to a record
// whose ID is one of anchors, is held, each step one seq lower.
func wholeTo(r *rec, byID map[Hash]*rec, anchors map[Hash]bool) bool {
	for steps := 0; r.Body.Seq > 1 && !anchors[r.ID]; steps++ {
		p := byID[*r.Body.Prev]
		if p == nil || p.Body.Seq != r.Body.Seq-1 || steps > MaxSeq {
			return false
		}
		r = p
	}
	return true
}

// chain finds which of one signer's records count: whole chains, not on a
// branch that a resolve voided, below the lowest seq with two records.
func (ep *epoch) chain(signer Hash, rs []*rec) {
	byID, bySeq := map[Hash]*rec{}, map[int64][]*rec{}
	for _, r := range rs {
		byID[r.ID] = r
		bySeq[r.Body.Seq] = append(bySeq[r.Body.Seq], r)
	}
	// A voided record with a sibling ends its branch; the walk is only
	// over whole chains, which end at seq 1 or at an anchor.
	dead := func(r *rec) bool {
		for {
			if ep.voided[r.ID] && len(bySeq[r.Body.Seq]) > 1 {
				return true
			}
			if r.Body.Seq == 1 || ep.e.anchors[r.ID] {
				return false
			}
			r = byID[*r.Body.Prev]
		}
	}
	live := map[int64][]*rec{}
	for _, r := range rs {
		if wholeTo(r, byID, ep.e.anchors) && !dead(r) {
			live[r.Body.Seq] = append(live[r.Body.Seq], r)
		}
	}
	fork := int64(MaxSeq + 1)
	for seq, l := range live {
		if len(l) > 1 && seq < fork {
			fork = seq
		}
	}
	if fork <= MaxSeq {
		ep.forked[signer] = fork
	}
	for seq, l := range live {
		for _, r := range l {
			if seq < fork && !ep.voided[r.ID] {
				ep.counted[r.ID] = true
			}
		}
	}
}

// newer reports whether root record a is newer than b: a later root on the
// path, then a higher seq.
func (ep *epoch) newer(a, b *rec) bool {
	if pa, pb := ep.onPath[a.Body.Signer], ep.onPath[b.Body.Signer]; pa != pb {
		return pa > pb
	}
	return a.Body.Seq > b.Body.Seq
}

// findAdmins finds the admin keys: the admin of a device record a root on
// the path signed, with the powers of the newest such record.
func (ep *epoch) findAdmins() {
	ep.admins = map[Hash]*rec{}
	for _, rs := range ep.e.devices {
		for _, r := range rs {
			if r.Body.Admin == nil || !ep.rootRecord(r) {
				continue
			}
			if old := ep.admins[*r.Body.Admin]; old == nil || ep.newer(r, old) {
				ep.admins[*r.Body.Admin] = r
			}
		}
	}
	// The recovery key: the admin of the newest recovery record a root on
	// the path signed, with takeover only, unless a device record makes
	// that key an admin too.
	ep.recovery = nil
	for signer := range ep.onPath {
		for _, r := range ep.e.bySig[signer] {
			if r.Body.Type == TypeRecovery && ep.rootRecord(r) && ep.e.certifiedBy(r.Body.Cert, r.Body.Signer) && (ep.recovery == nil || ep.newer(r, ep.recovery)) {
				ep.recovery = r
			}
		}
	}
	if r := ep.recovery; r != nil && ep.admins[*r.Body.Admin] == nil {
		ep.admins[*r.Body.Admin] = r
	}
}

func (ep *epoch) has(admin Hash, power string) bool {
	r := ep.admins[admin]
	if r == nil {
		return false
	}
	if r.Body.Type == TypeRecovery {
		return power == PowerTakeover
	}
	i := sort.SearchStrings(r.Body.Powers, power)
	return i < len(r.Body.Powers) && r.Body.Powers[i] == power
}

// isAdmin reports whether k is an admin key or the member key of a device
// whose newest root record names one: what only remove-admins removes.
func (ep *epoch) isAdmin(k Hash) bool {
	if ep.admins[k] != nil {
		return true
	}
	for _, r := range ep.admins {
		if r.Body.Key != nil && *r.Body.Key == k {
			return true
		}
	}
	return false
}

// isRoot reports whether k is a root key or the member key of the root's
// own device, which nobody removes.
func (ep *epoch) isRoot(k Hash) bool {
	if ep.e.roots[k] != nil {
		return true
	}
	if d := ep.rootDevice(); d != nil && *d.Body.Key == k {
		return true
	}
	return false
}

// rootDevice returns the current root's newest device record with
// holds_root.
func (ep *epoch) rootDevice() *rec {
	var best *rec
	for _, r := range ep.e.bySig[ep.cur] {
		if r.Body.Type == TypeDevice && r.Body.HoldsRoot && ep.rootRecord(r) && (best == nil || r.Body.Seq > best.Body.Seq) {
			best = r
		}
	}
	return best
}

// permitted reports whether an admin may sign r (docs/protocol.md, section 10, "Who
// signs what").
func (ep *epoch) permitted(r *rec) bool {
	a := r.Body.Signer
	if _, ok := ep.onPath[r.issuer]; !ok || ep.admins[a] == nil || ep.e.capped[r.ID] {
		return false
	}
	b := &r.Body
	switch b.Type {
	case TypeDevice:
		return ep.has(a, PowerAdmit) && b.Admin == nil && !b.HoldsRoot && b.Role != "phone" && b.Role != "watch"
	case TypeRevoke:
		for _, k := range b.Keys {
			switch {
			case ep.isRoot(k):
				return false
			case ep.isAdmin(k) && !ep.has(a, PowerRemoveAdmins):
				return false
			case !ep.isAdmin(k) && !ep.has(a, PowerRemove):
				return false
			}
		}
		return true
	case TypeFreeze:
		if !ep.has(a, PowerFreeze) {
			return false
		}
		for _, k := range b.Keys {
			if ep.admins[k] == nil || ep.has(k, PowerRemoveAdmins) {
				return false
			}
		}
		return true
	case TypeThaw:
		return ep.has(a, PowerThaw) && ep.has(a, PowerRemoveAdmins)
	case TypeClaim:
		return ep.has(a, PowerTakeover) && r.issuer == ep.cur
	case TypeHubs:
		return ep.has(a, PowerHub)
	}
	return false
}

// seenOf returns a record's seen entry for k, 0 when it names none.
func seenOf(b *Body, k Hash) int64 {
	for _, s := range b.Seen {
		if s.Key == k {
			return s.Seq
		}
	}
	return 0
}

// cuts reports whether a, a revoke or freeze, cuts off b: it names b's
// signer and saw fewer of its records than b's seq.
func cutsOff(a, b *rec) bool {
	if a.Body.Signer == b.Body.Signer || a.Body.Type != TypeRevoke && a.Body.Type != TypeFreeze {
		return false
	}
	i := sort.Search(len(a.Body.Keys), func(i int) bool { return a.Body.Keys[i].String() >= b.Body.Signer.String() })
	return i < len(a.Body.Keys) && a.Body.Keys[i] == b.Body.Signer && seenOf(&a.Body, b.Body.Signer) < b.Body.Seq
}

// label gives every admin record its label: the grounded labelling of the
// attacks of removals, freezes and thaws (docs/protocol.md, section 10, "Which admin
// records count").
func (ep *epoch) label() {
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			r.label, r.why = unlabelled, ""
		}
	}
	var adminRecs, rootActs []*rec
	thawedByRoot := map[Hash]bool{}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			switch {
			case ep.rootRecord(r):
				if r.Body.Type == TypeThaw {
					for _, id := range r.Body.Records {
						thawedByRoot[id] = true
					}
				}
			case r.AdminCA != nil && ep.counted[r.ID]:
				if !ep.permitted(r) {
					r.label, r.why = out, WhyPower
				}
				adminRecs = append(adminRecs, r)
			}
		}
	}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if ep.rootRecord(r) && (r.Body.Type == TypeRevoke || r.Body.Type == TypeFreeze && !thawedByRoot[r.ID]) {
				rootActs = append(rootActs, r)
			}
		}
	}
	// A root's removal or freeze puts what it cuts off out for good, and
	// a root's thaw puts out the admin freezes it names.
	for _, b := range adminRecs {
		if b.label == out {
			continue
		}
		if b.Body.Type == TypeFreeze && thawedByRoot[b.ID] {
			b.label, b.why = out, WhyCut
		}
		for _, a := range rootActs {
			if cutsOff(a, b) {
				b.label, b.why = out, WhyCut
			}
		}
	}
	attackers := map[*rec][]*rec{}
	for _, b := range adminRecs {
		for _, a := range adminRecs {
			if a.label == out {
				continue
			}
			// An admin's removal of a claimant does not cut its claim:
			// decideClaims sees it as a dispute.
			if cutsOff(a, b) && b.Body.Type != TypeClaim || a.Body.Type == TypeThaw && b.Body.Type == TypeFreeze && contains(a.Body.Records, b.ID) {
				attackers[b] = append(attackers[b], a)
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, b := range adminRecs {
			if b.label != unlabelled {
				continue
			}
			all := true
			for _, a := range attackers[b] {
				if a.label == in {
					b.label, b.why, changed = out, WhyRemoved, true
					break
				}
				if a.label != out {
					all = false
				}
			}
			if b.label == unlabelled && all {
				b.label, changed = in, true
			}
		}
	}
	var undec []*rec
	for _, b := range adminRecs {
		if b.label == unlabelled {
			b.label = undecided
			if b.Body.Type == TypeRevoke || b.Body.Type == TypeFreeze || b.Body.Type == TypeThaw {
				undec = append(undec, b)
			}
		}
	}
	ep.conflictsOf(undec, attackers)
}

func contains(hs []Hash, h Hash) bool {
	for _, x := range hs {
		if x == h {
			return true
		}
	}
	return false
}

// conflictsOf groups undecided records that attack each other into
// conflicts.
func (ep *epoch) conflictsOf(undec []*rec, attackers map[*rec][]*rec) {
	parent := map[*rec]*rec{}
	find := func(r *rec) *rec {
		for parent[r] != nil && parent[r] != r {
			r = parent[r]
		}
		return r
	}
	for _, r := range undec {
		parent[r] = r
	}
	for _, b := range undec {
		for _, a := range attackers[b] {
			if parent[a] != nil {
				parent[find(a)] = find(b)
			}
		}
	}
	byRoot := map[*rec][]*rec{}
	for _, r := range undec {
		byRoot[find(r)] = append(byRoot[find(r)], r)
	}
	for _, rs := range byRoot {
		c := Conflict{Kind: ConflictAdmins}
		signers := map[Hash]bool{}
		for _, r := range rs {
			c.Records = append(c.Records, r.ID)
			signers[r.Body.Signer] = true
		}
		for s := range signers {
			c.Signers = append(c.Signers, s)
		}
		ep.conflicts = append(ep.conflicts, c)
		ep.stopFull = true
	}
}

// counts reports whether r counts: a root's record in this epoch, or an
// admin record that is in.
func (ep *epoch) counts(r *rec) bool {
	return ep.rootRecord(r) || r.AdminCA != nil && r.label == in
}

// collect finds the revoked and frozen keys and the two histories.
func (ep *epoch) collect() {
	ep.revoked, ep.frozen = map[Hash]bool{}, map[Hash]bool{}
	// A root's thaw ends any freeze; an admin's only an admin's, which
	// the labelling already put out.
	thawed := map[Hash]bool{}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.Body.Type == TypeThaw && ep.rootRecord(r) {
				for _, id := range r.Body.Records {
					thawed[id] = true
				}
			}
		}
	}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if !ep.counts(r) {
				continue
			}
			switch r.Body.Type {
			case TypeRevoke:
				for _, k := range r.Body.Keys {
					ep.revoked[k] = true
				}
			case TypeFreeze:
				if !thawed[r.ID] {
					for _, k := range r.Body.Keys {
						ep.frozen[k] = true
					}
				}
			}
		}
	}
	for signer := range ep.forked {
		c := Conflict{Kind: ConflictTwoHistories, Signers: []Hash{signer}}
		for _, r := range ep.e.bySig[signer] {
			if r.Body.Seq == ep.forked[signer] {
				c.Records = append(c.Records, r.ID)
			}
		}
		ep.conflicts = append(ep.conflicts, c)
		if _, root := ep.onPath[signer]; root {
			ep.stopFull = true
		}
	}
}

// settings returns the current root's newest settings record that counts.
func (ep *epoch) settings() *rec {
	var settings *rec
	for _, r := range ep.e.bySig[ep.cur] {
		if r.Body.Type == TypeSettings && ep.rootRecord(r) && (settings == nil || r.Body.Seq > settings.Body.Seq) {
			settings = r
		}
	}
	return settings
}

// handover returns the current root's newest handover record that counts.
func (ep *epoch) handover() *rec {
	var h *rec
	for _, r := range ep.e.bySig[ep.cur] {
		if r.Body.Type == TypeHandover && ep.rootRecord(r) && (h == nil || r.Body.Seq > h.Body.Seq) {
			h = r
		}
	}
	return h
}

// decideClaims looks at the claims under the current root and returns the
// next root and the current root's cut when one takes effect.
func (ep *epoch) decideClaims(now int64, firstSeen map[Hash]int64, unknown bool) (*Hash, int64) {
	delay := int64(DefaultDelay)
	settings := ep.settings()
	if settings != nil && settings.Body.TakeoverDelayMS != nil {
		delay = *settings.Body.TakeoverDelayMS
	}
	cancelled := func(c *rec) bool {
		for _, r := range ep.e.bySig[ep.cur] {
			if !ep.rootRecord(r) {
				continue
			}
			if r.Body.Type == TypeResolve && contains(r.Body.Records, c.ID) || r.Body.Type == TypeRevoke && contains(r.Body.Keys, c.Body.Signer) {
				return true
			}
		}
		return false
	}
	var live []*rec
	for _, rs := range ep.e.bySig {
		for _, c := range rs {
			if c.Body.Type != TypeClaim || c.AdminCA == nil || c.issuer != ep.cur || !ep.counted[c.ID] && !ep.voided[c.ID] {
				continue
			}
			root, _ := x509.ParseCertificate(c.Body.Root)
			cl := Claim{Record: c.ID, Claimant: c.Body.Signer}
			if root != nil {
				cl.Root = KeyHashOf(root)
			}
			switch {
			case root == nil || ep.e.roots[cl.Root] == nil || cl.Root == ep.path[0]:
				cl.State = "void"
			case cancelled(c):
				cl.State = "cancelled"
			case c.label == out:
				cl.State = "void"
			default:
				if _, again := ep.onPath[cl.Root]; again {
					cl.State = "void"
				} else {
					live = append(live, c)
				}
			}
			if cl.State != "" {
				ep.claims = append(ep.claims, cl)
			}
		}
	}
	// An admin's removal or freeze of a claimant that the claimant had
	// seen voids its claim; one the claimant had not seen disputes it,
	// whatever else its author had seen: a claimed root can sign before
	// its claim takes effect, so nothing in seen tells a removal written
	// after the handover. Such a removal is signed under an admin CA of
	// the new root, which counts only in the new root's epoch.
	disputes := map[*rec][]*rec{}
	var kept []*rec
	for _, c := range live {
		void := false
		for _, r := range ep.removals(c.Body.Signer) {
			if seenOf(&c.Body, r.Body.Signer) >= r.Body.Seq {
				void = true
			} else {
				disputes[c] = append(disputes[c], r)
			}
		}
		if void {
			ep.claims = append(ep.claims, Claim{Record: c.ID, Claimant: c.Body.Signer, Root: claimRoot(c), State: "void"})
		} else {
			kept = append(kept, c)
		}
	}
	live = kept
	// One claim at a time: a claim whose author held another live claim
	// counts for nothing.
	var first []*rec
	for _, c := range live {
		later := false
		for _, o := range live {
			if o != c && seenOf(&c.Body, o.Body.Signer) >= o.Body.Seq {
				later = true
			}
		}
		if later {
			ep.claims = append(ep.claims, Claim{Record: c.ID, Claimant: c.Body.Signer, Root: claimRoot(c), State: "void"})
		} else {
			first = append(first, c)
		}
	}
	live = first
	if len(live) > 1 {
		c := Conflict{Kind: ConflictClaims}
		for _, r := range live {
			ep.claims = append(ep.claims, Claim{Record: r.ID, Claimant: r.Body.Signer, Root: claimRoot(r), State: "competing"})
			c.Records = append(c.Records, r.ID)
			c.Signers = append(c.Signers, r.Body.Signer)
		}
		ep.conflicts = append(ep.conflicts, c)
		ep.stopFull = true
		return nil, 0
	}
	if len(live) == 0 {
		return nil, 0
	}
	c := live[0]
	cl := Claim{Record: c.ID, Claimant: c.Body.Signer, Root: claimRoot(c)}
	if ds := disputes[c]; len(ds) > 0 {
		cl.State = "disputed"
		ep.claims = append(ep.claims, cl)
		conflict := Conflict{Kind: ConflictClaims, Records: []Hash{c.ID}, Signers: []Hash{c.Body.Signer}}
		for _, r := range ds {
			conflict.Records = append(conflict.Records, r.ID)
			if !contains(conflict.Signers, r.Body.Signer) {
				conflict.Signers = append(conflict.Signers, r.Body.Signer)
			}
		}
		ep.conflicts = append(ep.conflicts, conflict)
		ep.stopFull = true
		return nil, 0
	}
	if h := ep.handover(); h != nil && *h.Body.Admin == c.Body.Signer && seenOf(&c.Body, ep.cur) >= h.Body.Seq {
		// The root handed the group to this admin: its claim, made after
		// it held the handover, takes effect without the delay.
		delay = 0
	}
	seen, ok := firstSeen[c.ID]
	if !ok || seen > now {
		seen = now
	}
	waits := unknown && delay > 0
	elapsed := subSat(now, seen)
	if c.label != in || ep.rootFrozen(c.Body.Signer) || waits || elapsed < delay {
		cl.State = "pending"
		if left := subSat(delay, elapsed); left > 0 && !unknown {
			cl.LeftMS = left
		}
		ep.claims = append(ep.claims, cl)
		ep.pending = &c.Body.Signer
		return nil, 0
	}
	if len(ep.path) >= MaxPath {
		// A handover past the limit on the path counts for nothing.
		cl.State = "void"
		ep.claims = append(ep.claims, cl)
		return nil, 0
	}
	cl.State = "effective"
	ep.claims = append(ep.claims, cl)
	next := cl.Root
	return &next, seenOf(&c.Body, ep.cur)
}

// removals returns the admin removals and freezes that count and name
// the admin key k or the member key of its device.
func (ep *epoch) removals(k Hash) []*rec {
	keys := []Hash{k}
	if d := ep.admins[k]; d != nil && d.Body.Key != nil {
		keys = append(keys, *d.Body.Key)
	}
	var out []*rec
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.AdminCA == nil || r.label != in || r.Body.Type != TypeRevoke && r.Body.Type != TypeFreeze {
				continue
			}
			for _, key := range keys {
				if contains(r.Body.Keys, key) {
					out = append(out, r)
					break
				}
			}
		}
	}
	return out
}

// rootFrozen reports whether a root's freeze, not thawed by a root, names
// k: the root holding a claim back.
func (ep *epoch) rootFrozen(k Hash) bool {
	if !ep.frozen[k] {
		return false
	}
	thawed := map[Hash]bool{}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.Body.Type == TypeThaw && ep.rootRecord(r) {
				for _, id := range r.Body.Records {
					thawed[id] = true
				}
			}
		}
	}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.Body.Type == TypeFreeze && ep.rootRecord(r) && !thawed[r.ID] && contains(r.Body.Keys, k) {
				return true
			}
		}
	}
	return false
}

func claimRoot(r *rec) Hash {
	c, err := x509.ParseCertificate(r.Body.Root)
	if err != nil {
		return Hash{}
	}
	return KeyHashOf(c)
}

// State is the group's state (docs/protocol.md, section 10, "The state").
type State struct {
	Roots       []Hash     `json:"roots"`
	RootDevice  string     `json:"root_device,omitempty"`
	Devices     []Device   `json:"devices,omitempty"`
	Revoked     []Hash     `json:"revoked,omitempty"`
	Claims      []Claim    `json:"claims,omitempty"`
	Conflicts   []Conflict `json:"conflicts,omitempty"`
	Stop        string     `json:"stop"`
	NoSecretsTo []string   `json:"no_secrets_to,omitempty"`
	NothingTo   []string   `json:"nothing_to,omitempty"`
	// Newer lists records of a later version: the member keeps them and
	// tells its user to update.
	Newer []Hash `json:"newer,omitempty"`
	// Ignored lists the records that do not count and why, so that the
	// apps and the log can say what happened to a record.
	Ignored []Ignored `json:"ignored,omitempty"`
	// Checkpoint is the root's checkpoint that counts: a member may drop
	// the records it leaves out (docs/protocol.md, section 10, "Checkpoints").
	Checkpoint *Hash `json:"checkpoint,omitempty"`
	// Hubs is the user's main hubs from the hubs record that counts, the
	// devices of the state with the role full or phone, in its order
	// (docs/protocol.md, section 10, "The hubs table").
	Hubs []string `json:"hubs,omitempty"`
	// KeyLevel is the key level of the current root's newest settings
	// record that counts; "" when it sets none, which means "hardware".
	KeyLevel string `json:"key_level,omitempty"`
	// Recovery is the admin key of the group's recovery key, from the
	// newest recovery record of a root on the path, while it is neither
	// revoked nor frozen (docs/records-v2.md, "The recovery key").
	Recovery *Hash `json:"recovery,omitempty"`
}

// The values of State.Stop (docs/protocol.md, section 10, "Stopping the
// exchange"): nothing stops, no member sends a secret, or every member
// exchanges records only.
const (
	StopNone    = "none"
	StopSecrets = "secrets"
	StopFull    = "full"
)

// Device is one device of the state.
type Device struct {
	Device   string   `json:"device"`
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	OS       string   `json:"os,omitempty"`
	Keys     []Hash   `json:"keys"`
	Store    string   `json:"store,omitempty"`
	Kind     string   `json:"kind,omitempty"`
	Proof    string   `json:"proof,omitempty"`
	Seal     []byte   `json:"seal,omitempty"`
	Admin    *Hash    `json:"admin,omitempty"`
	Powers   []string `json:"powers,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Frozen   bool     `json:"frozen,omitempty"`
}

// Claim is a claim of the state.
type Claim struct {
	Record   Hash   `json:"record"`
	Claimant Hash   `json:"claimant"`
	Root     Hash   `json:"root"`
	State    string `json:"state"`
	LeftMS   int64  `json:"left_ms,omitempty"`
}

// Ignored is a record of the set that does not count, with why.
type Ignored struct {
	Record Hash   `json:"record"`
	Why    string `json:"why"`
}

// The kinds of a Conflict (docs/protocol.md, section 10, "The state").
const (
	ConflictAdmins       = "admins"
	ConflictClaims       = "claims"
	ConflictTwoHistories = "two_histories"
)

// Conflict is a conflict of the state.
type Conflict struct {
	Kind    string `json:"kind"`
	Records []Hash `json:"records"`
	Signers []Hash `json:"signers"`
}

// state builds the State of the last epoch.
func (ep *epoch) state() *State {
	s := &State{Roots: ep.path, Stop: StopNone}
	if d := ep.rootDevice(); d != nil && !ep.revoked[*d.Body.Key] {
		s.RootDevice = d.Body.Device
	}
	forkedAdmin := false
	for signer := range ep.forked {
		if _, root := ep.onPath[signer]; !root {
			forkedAdmin = true
		}
	}
	for id, rs := range ep.e.devices {
		if d, ok := ep.device(id, rs); ok {
			s.Devices = append(s.Devices, d)
		}
		// The devices that an admin with two histories alone admitted
		// get nothing.
		alone := len(rs) > 0
		for _, r := range rs {
			if _, f := ep.forked[r.Body.Signer]; !f || r.AdminCA == nil {
				alone = false
			}
		}
		if alone {
			s.NothingTo = append(s.NothingTo, id)
		}
		if ep.pending != nil {
			for _, r := range rs {
				if r.Body.Admin != nil && *r.Body.Admin == *ep.pending && ep.rootRecord(r) {
					s.NoSecretsTo = append(s.NoSecretsTo, id)
					break
				}
			}
		}
	}
	sort.Slice(s.Devices, func(i, j int) bool { return s.Devices[i].Device < s.Devices[j].Device })
	sort.Strings(s.NothingTo)
	sort.Strings(s.NoSecretsTo)
	for k := range ep.revoked {
		s.Revoked = append(s.Revoked, k)
	}
	sortHashes(s.Revoked)
	s.Claims = ep.claims
	sort.Slice(s.Claims, func(i, j int) bool { return s.Claims[i].Record.String() < s.Claims[j].Record.String() })
	s.Conflicts = ep.conflicts
	for i := range s.Conflicts {
		sortHashes(s.Conflicts[i].Records)
		sortHashes(s.Conflicts[i].Signers)
	}
	sort.Slice(s.Conflicts, func(i, j int) bool {
		return s.Conflicts[i].Records[0].String() < s.Conflicts[j].Records[0].String()
	})
	s.Hubs = ep.hubs(s.Devices)
	if r := ep.settings(); r != nil {
		s.KeyLevel = r.Body.KeyLevel
	}
	if r := ep.recovery; r != nil && ep.admins[*r.Body.Admin] == r && !ep.revoked[*r.Body.Admin] && !ep.frozen[*r.Body.Admin] {
		k := *r.Body.Admin
		s.Recovery = &k
	}
	switch {
	case ep.stopFull:
		s.Stop = StopFull
	case forkedAdmin:
		s.Stop = StopSecrets
	}
	return s
}

// hubs returns the main hubs of the hubs record that counts: a root's
// beats an admin's, a later root's an earlier one's, then the higher seq;
// among admins the later time_ms, then the smaller signer, then the
// higher seq. Only the devices it names that are among devices with the
// role full or phone are kept.
func (ep *epoch) hubs(devices []Device) []string {
	var best *rec
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			if r.Body.Type == TypeHubs && ep.counts(r) && (best == nil || ep.newerHubs(r, best)) {
				best = r
			}
		}
	}
	if best == nil {
		return nil
	}
	may := map[string]bool{}
	for _, d := range devices {
		may[d.Device] = d.Role == "full" || d.Role == "phone"
	}
	var out []string
	for _, h := range best.Body.Hubs {
		if may[h] {
			out = append(out, h)
		}
	}
	return out
}

// newerHubs reports whether hubs record a beats b.
func (ep *epoch) newerHubs(a, b *rec) bool {
	ra, rb := a.AdminCA == nil, b.AdminCA == nil
	switch {
	case ra != rb:
		return ra
	case ra:
		return ep.newer(a, b)
	case a.Body.TimeMS != b.Body.TimeMS:
		return a.Body.TimeMS > b.Body.TimeMS
	case a.Body.Signer != b.Body.Signer:
		return a.Body.Signer.String() < b.Body.Signer.String()
	}
	return a.Body.Seq > b.Body.Seq
}

// The reasons a record does not count (docs/protocol.md, section 10, "The state").
const (
	WhyUnreadable = "unreadable" // its body is not a record of version 2
	WhySignature  = "signature"  // its signature or chain does not check
	WhyGroup      = "group"      // it is of another group
	WhyIssuer     = "issuer"     // its admin CA is from no root of the group
	WhyNotRoot    = "not_root"   // its signer is no root on the path
	WhyHistory    = "history"    // its prev chain is broken, on a voided branch or at a second history
	WhyCut        = "cut"        // a root's removal, freeze or thaw cut it off, or it is past its root's cut
	WhyPower      = "power"      // its signer was no admin with the power it needs
	WhyRemoved    = "removed"    // an admin's removal or freeze that counts cut it off
	WhyUndecided  = "undecided"  // it is in a conflict between admins
	WhyLimit      = "limit"      // it is past a limit on the set (MaxRecords, MaxSetBytes, MaxDevices, MaxAdmins)
)

// MaxIgnored is how many records a state lists in ignored.
const MaxIgnored = 64

// ignored lists the records of the set that do not count, with why,
// sorted by ID, at most MaxIgnored; the records of a later version are
// in newer instead.
func (ep *epoch) ignored(newer []Hash) []Ignored {
	why := map[Hash]string{}
	for id, w := range ep.e.failed {
		why[id] = w
	}
	for _, rs := range ep.e.bySig {
		for _, r := range rs {
			delete(why, r.ID)
			if w := ep.whyNot(r); w != "" {
				why[r.ID] = w
			}
		}
	}
	for _, id := range newer {
		delete(why, id)
	}
	var out []Ignored
	for id, w := range why {
		out = append(out, Ignored{Record: id, Why: w})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Record.String() < out[j].Record.String() })
	if len(out) > MaxIgnored {
		out = out[:MaxIgnored]
	}
	return out
}

// whyNot says why a verified record does not count in this epoch, "" when
// it counts.
func (ep *epoch) whyNot(r *rec) string {
	switch {
	case ep.counts(r):
		return ""
	case r.Body.Type == TypeClaim && ep.tookEffect(r.ID):
		// A claim that took effect counted under the root before.
		return ""
	case ep.e.capped[r.ID]:
		return WhyLimit
	case !ep.counted[r.ID]:
		return WhyHistory
	case r.AdminCA == nil:
		if _, ok := ep.onPath[r.Body.Signer]; !ok {
			return WhyNotRoot
		}
		return WhyCut
	case r.label == undecided:
		return WhyUndecided
	case r.why != "":
		return r.why
	}
	return WhyPower
}

// tookEffect reports whether claim id took effect on the path.
func (ep *epoch) tookEffect(id Hash) bool {
	for _, c := range ep.claims {
		if c.Record == id && c.State == "effective" {
			return true
		}
	}
	return false
}

func sortHashes(hs []Hash) {
	sort.Slice(hs, func(i, j int) bool { return hs[i].String() < hs[j].String() })
}

// device builds one device of the state from its counting records.
func (ep *epoch) device(id string, rs []*rec) (Device, bool) {
	var counting []*rec
	keys := map[Hash]bool{}
	for _, r := range rs {
		if ep.counts(r) && !ep.revoked[*r.Body.Key] {
			counting = append(counting, r)
			keys[*r.Body.Key] = true
		}
	}
	if len(counting) == 0 {
		return Device{}, false
	}
	// The newest record: a root's beats an admin's, a later root's an
	// earlier one's, then the higher seq; among admins the larger signer.
	sort.Slice(counting, func(i, j int) bool {
		a, b := counting[i], counting[j]
		ra, rb := a.AdminCA == nil, b.AdminCA == nil
		switch {
		case ra != rb:
			return ra
		case ra:
			return ep.newer(a, b)
		case a.Body.Signer != b.Body.Signer:
			return a.Body.Signer.String() > b.Body.Signer.String()
		}
		return a.Body.Seq > b.Body.Seq
	})
	n := counting[0].Body
	d := Device{Device: id, Name: n.Name, Role: n.Role, OS: n.OS, Store: n.Store, Kind: n.Kind, Proof: n.Proof, Seal: n.Seal}
	for k := range keys {
		d.Keys = append(d.Keys, k)
	}
	sortHashes(d.Keys)
	if n.Admin != nil && counting[0].AdminCA == nil && !ep.revoked[*n.Admin] && ep.admins[*n.Admin] == counting[0] {
		a := *n.Admin
		d.Admin, d.Powers, d.Commands, d.Frozen = &a, n.Powers, n.Commands, ep.frozen[a]
	}
	return d, true
}

// Encode returns the state as canonical JSON, the bytes the vectors
// compare.
func (s *State) Encode() ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return strict.Canonicalize(raw)
}

// Equal reports whether two states are the same bytes.
func (s *State) Equal(o *State) bool {
	a, err1 := s.Encode()
	b, err2 := o.Encode()
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}

// subSat is a - b, held at the ends of int64 instead of wrapping: a
// caller's times are any int64.
func subSat(a, b int64) int64 {
	d := a - b
	if (b > 0 && d > a) || (b < 0 && d < a) {
		if b > 0 {
			return math.MinInt64
		}
		return math.MaxInt64
	}
	return d
}
