// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
//
// A model of the record rules of 0.6 (records v3), in Quint (https://quint-lang.org). It is
// written from the rules as the owner settled them (the design of records v3, its section 7,
// with rule 33: the root changes only by the recovery key, at once), not from the code's
// structure, so that it can disagree with the code. It lets the simulator try many ways a few
// devices can sign, sync, compact and drop records, checking these promises:
//
//  1. One set, one state: a member that has been offered a set of records, in whatever order
//     and with whatever it dropped on the way, keeps what a member given the whole set at once
//     keeps, and evaluates it to the same state.
//  2. A device or admin a root removed never returns: once a root's removal of a key counts on
//     a member, the key (and the other key of its device) stays removed there, whatever comes,
//     unless a change of root left the removal off its list (rule 33, point 6). A removal by an
//     admin is not final: a root may void it.
//  3. One chain, one state: two members that hold the same recovery chain and keep the same
//     records are in one state.
//  5. During a stop of the admins only the current root's commands run, and its records still
//     count; during a full stop (two recovery records at one seq) nothing runs.
//  6. No key takes another key's room: every key with room keeps at least its fair share (or
//     all it made, or its ceiling); only the roots on the path and the admin keys they name
//     have room; the set never holds more than its room. Recovery records live outside it.
//  7. A member follows its recovery chain: its path is the first root and the new roots of the
//     longest chain of recovery records it holds and has verified, whatever the old roots, the
//     admins or anyone else signed, and in whatever order it got them (with promise 1).
//  8. The path of roots never grows shorter on a member, unless it came to a full stop.
//  9. A newcomer takes the recovery chain from its admitter: the admitter's path at the
//     Welcome is the start of the newcomer's.
// 10. After a change of root, of each replaced root only the records the recovery record lists
//     count, whatever that key signs later (a thief holding it included).
// 11. Two recovery records at one seq of the chain stop every member that holds both, and once
//     every member holds every recovery record, all of them or none are stopped.
// 12. A removed key gains nothing: of a removed key, only records that every counted removal
//     of it saw count (a removed phone admin turned thief included).
// 13. After a change of root, two members that hold the same recovery chain, were offered the
//     same records and hold the new root's first checkpoint are in one state, whether or not
//     either compacted on a checkpoint of the replaced root or of the new root. (Not yet true
//     of the core, nor of this model, when one compacted on the new root's own checkpoint and
//     the room is full; compactedAgreeOldRootOnly is the weaker form checked meanwhile.)
//
// (Promise 4, a claim's delay, is gone with the delay.)
//
// Who is in it: the group's first root R; a phone admin A, a computer admin C, a watch admin W;
// each admin's device has a member key too (dA, dC, dW), and a removal or freeze of either
// key of a device names both. C2 is another admin key for C's device: a root's newer record
// of a device that names another key, or none, takes the old key's powers, and of what the old
// key signed only what that record saw counts. A thaw revives only what it saw of the frozen
// key's records. D is a device the admins and roots admit and remove; NA and NK are new roots
// (NA may first be an admin key a root names, of the device dN);
// X is an admin key a root may name. K is the group's recovery key, fixed when the group was
// made and never replaced. Any key may stay silent,
// act as a thief (pretend it held none of the other admins' records), or sign a second record
// at a seq it already used. Five members keep a set each: r (R's device), a (A's, with NA and
// X), c (C's and W's), k (the member the recovery key is entered on, with NK) and m, a member
// that only syncs. A record's place among others of one key at one seq comes from a hash of
// its ID, so a fork may land before or after the record it forks.
//
// A record names its chain: its line is the IDs of its key's records from seq 1 up to itself,
// as the prev hash commits to them. What a removal or freeze saw of a key is the line of the
// head it held, so "a saw t" means t is on that line. A checkpoint names its heads the same way
// and a list of records it keeps; records at or below a head that are neither a head nor kept
// are pruned by it.
//
// The recovery records (rule 33, brief v2 of 12:20) are a chain of their own: seq 1, 2, 3,
// each signed by K, its line the chain's IDs (so it names the record before it). A record
// names a new root, one that was never a root, and lists the records of the earlier roots that
// stay; it counts as soon as a member holds it (with its list, which the model carries in the
// record) and the chain below it, whatever any root or admin signed to that member before. Any
// two records K signed at one seq, at any depth, valid or not, are a fork: the member stops for
// good. The newest record's list is the whole truth about every earlier root: lists do not add
// up. The device that becomes the root writes the list: every record of the roots so far that
// it counts, every root's removal it holds, and the heads the current root's counting
// checkpoint named. A record also carries from: the seq at which the new root's records
// start (1 for a fresh key); of a key that signed before, as an admin, a record below from
// counts only if listed. With the head, before it is released, the writer signs the new
// root's first checkpoint: the heads the list anchors, keeping what the writer counts under
// the new root. The owner's "who stays" is removals the new root signs. The recovery
// records are outside the rooms; no checkpoint prunes them; no root's or admin's record
// touches the recovery key. Guarded leaves are not in the model.
//
// The scale: a record takes one or two units of room, a checkpoint two. The set holds 14
// units, a root key 8, an admin key 5. The format's numbers are 4096, 1024 and 256; the rules
// do not depend on the numbers.
//
// Left out, since other tests cover them: signatures and the byte form (one record, one ID,
// its units from its body), settings, leaves and watches, two keys with one device ID, admin
// records' later narrowing of a device.
//
// Run it:
//
//	quint test --backend=typescript docs/model/records-v3.qnt
//	quint run --backend=typescript --invariant=promises --max-steps=25 --max-samples=500 docs/model/records-v3.qnt
//
// with --invariant set to oneState, removedStayOut, oneChainOneState, stopRootOnly, fairRoom,
// followsRecovery, pathGrows, newcomerTakes, oldRootListed, twinStops, removedGainsNothing or
// compactedAgree for one promise. The typescript backend takes a few traces a second here, so a long run takes
// many samples and several seeds. --step=guided weights the steps towards changes of root one
// after another, thieves and compaction, and --witnesses secondTakeover compactedGap counts the
// traces that reach them.
module records_v3 {
  type Key = str
  type Id = int
  type Record = {
    id: Id,
    signer: Key,
    seq: int,
    // The IDs of its key's records from seq 1 up to itself; for a recovery record, the IDs of
    // the recovery chain up to itself.
    line: List[Id],
    // "admin" (a root names target an admin key with the set kit; its device's member key is
    // DEV's), "device" (admits or changes the device target), "revoke" (removes target),
    // "freeze" (freezes the admin target), "thaw" (voids the freeze targetRec), "resolve"
    // (voids record targetRec), "checkpoint" (heads and keep), "copies" (a record that only
    // takes room); the recovery chain's "recover" (target is the new root, keep the list).
    kind: str,
    target: Key,
    kit: str,
    targetRec: Id,
    // The line of the head of each key the author held (or says): what a revoke, freeze, thaw
    // or a root's record of an admin's device saw.
    seen: Key -> List[Id],
    // checkpoint: the line of each key's head, and the records it keeps below them.
    heads: Key -> List[Id],
    keep: Set[Id],
    units: int,
  }

  // What a member that drops records remembers of them (core keep::Cut): the level, which only
  // falls, and for each key the place of the first record it dropped and the units dropped
  // from there.
  type Cut = { level: int, marks: Key -> (int, int) }

  type Store = {
    recs: Set[Id], // the records it keeps in its rooms
    got: Set[Id], // every record it was offered
    chain: Set[Id], // the recovery records it holds, outside the rooms, never dropped
    cut: Cut,
    path: List[Key], // the path its rooms were last cut by
    cuts: Key -> List[Id], // and the list of each replaced root on it
    checkpoint: Id, // the checkpoint it compacted on, or 0
  }

  type View = {
    path: List[Key],
    counting: Set[Id],
    revoked: Set[Key],
    frozen: Set[Key],
    admins: Key -> str,
    stop: bool,
    devices: Set[Key],
    commanders: Set[Key],
    rootsCount: bool, // every whole record of the current root counts
    cuts: Key -> List[Id], // what the recovery record listed of each replaced root
    checkpoint: Id, // the checkpoint the state comes from, or 0
  }

  // The recovery chain a member follows: its records in seq order, the recovery key of the
  // next place, and whether two records at one seq stop it in full.
  type Chain = { ids: List[Id], recs: List[Record], key: Key, stop: bool, open: bool }

  pure val ROOT = "R"
  pure val PHONE = "A"
  pure val COMPUTER = "C"
  pure val WATCH = "W"
  pure val RECOVERY = "K"
  pure val DEVICE = "D"
  pure val MINTED = "X"
  // The keys whose records live in the rooms.
  pure val SIGNERS = Set("R", "A", "C", "C2", "W", "NA", "NK", "X")
  pure val ROOT_KEYS = Set("R", "NA", "NK")
  pure val RKEYS = Set("K")
  pure val THIEVES = Set("A", "C", "C2", "W", "X")
  pure val HOLDER = Map("R" -> "r", "A" -> "a", "NA" -> "a", "X" -> "a", "C" -> "c", "C2" -> "c", "W" -> "c",
    "K" -> "k", "NK" -> "k")
  pure val MEMBERS = Set("r", "a", "c", "k", "m")
  // The device (its member key) of each admin key: C2 is a second admin key the root may name
  // for C's device in place of C.
  pure val DEV = Map("A" -> "dA", "C" -> "dC", "C2" -> "dC", "W" -> "dW", "X" -> "dX", "NA" -> "dN")
  pure val DEVS = Set("dA", "dC", "dW", "dX", "dN")

  pure val ROOM = 14
  pure val ROOTC = 8
  pure val ADMINC = 5
  pure val MAXU = 2
  pure val TOP = ROOTC
  pure val MAXREC = 16
  pure val MAXCHAIN = 3

  pure val NOCUT: Cut = { level: TOP, marks: Map() }

  // A root's removal stands when its key signs a second record at the same seq.
  pure val ROOT_REMOVAL_SURVIVES_FORK = true
  // In a full root's order, its removals, freezes and resolves before its checkpoints.
  pure val EARLY_BEFORE_CHECKPOINTS = true

  pure val NONE = 10000000
  // A record's ID as the hash orders it: not the order it was signed in.
  pure def hid(i: Id): int = (i * 7) % 23

  // The powers of the three sets the apps write; no set takes the group over (rule 33).
  pure def powersOf(kit: str): Set[str] =
    if (kit == "phone") Set("admit", "manage", "remove", "freeze", "hub", "removeAdmins", "thaw")
    else if (kit == "computer") Set("admit", "manage", "remove", "freeze", "hub")
    else if (kit == "watch") Set("remove", "freeze")
    else Set()

  // --- Helpers ---------------------------------------------------------------------------

  pure def min2(a: int, b: int): int = if (a < b) a else b
  pure def max2(a: int, b: int): int = if (a > b) a else b
  pure def getOr(m: Key -> int, k: Key, d: int): int = if (m.keys().contains(k)) m.get(k) else d
  pure def sumUnits(rs: Set[Record]): int = rs.fold(0, (t, r) => t + r.units)
  pure def ofKey(rs: Set[Record], k: Key): Set[Record] = rs.filter(r => r.signer == k)
  pure def recsOf(xs: Set[Id], db: Id -> Record): Set[Record] = xs.map(i => db.get(i))
  pure def idsOf(rs: Set[Record]): Set[Id] = rs.map(r => r.id)
  pure def onList(l: List[Key], k: Key): bool = l.indices().exists(i => l[i] == k)
  pure def inLine(l: List[Id], x: Id): bool = l.indices().exists(i => l[i] == x)
  pure def indexOf(l: List[Key], k: Key): int = l.indices().fold(-1, (f, i) => if (l[i] == k) i else f)
  pure def last(l: List[Key]): Key = l[l.length() - 1]
  pure def lastId(l: List[Id]): Id = l[l.length() - 1]
  pure def isPrefix(a: List[Key], b: List[Key]): bool =
    a.length() <= b.length() and a.indices().forall(i => a[i] == b[i])
  pure def isChain(r: Record): bool = r.kind == "recover"
  // The keys of the device a key belongs to: its member key and every admin key named for it.
  // A removal or freeze of one names them all.
  pure def keysOfDev(d: Key): Set[Key] = Set(d).union(DEV.keys().filter(a => DEV.get(a) == d))
  pure def withPair(k: Key): Set[Key] =
    if (DEV.keys().contains(k)) keysOfDev(DEV.get(k)) else if (DEVS.contains(k)) keysOfDev(k) else Set(k)
  pure def devOf(r: Record): Key =
    if (r.kind == "admin" and DEV.keys().contains(r.target)) DEV.get(r.target) else if (r.kind == "device") r.target else ""
  pure def lineOf(m: Key -> List[Id], k: Key): List[Id] = if (m.keys().contains(k)) m.get(k) else []
  // x is on the chain that ends at the head of line, as far as a set can tell: on the line,
  // and every record above it up to the head is held (ids) or vouched for by a checkpoint
  // (anchors). A listed head the set lacks hides everything below it.
  pure def onChain(l: List[Id], x: Id, ids: Set[Id], anchors: Set[Id]): bool = {
    val at = l.indices().fold(-1, (f, i) => if (l[i] == x) i else f)
    at >= 0 and (anchors.contains(x) or l.indices().forall(j => j <= at or ids.contains(l[j]) or anchors.contains(l[j])))
  }
  // a (a revoke, freeze, thaw or a root's device record) saw t: t is on the chain of the head
  // a held of t's key.
  pure def sawIn(a: Record, t: Record, ids: Set[Id], anchors: Set[Id]): bool = onChain(lineOf(a.seen, t.signer), t.id, ids, anchors)
  // The current root's entry in cuts, when the newest recovery record names a key that signed
  // before as an admin: its `from` as a negative first item, then the list. Of that key, a
  // record below `from` counts only when listed.
  pure def floored(l: List[Id]): bool = l.length() > 0 and l[0] < 0
  pure def floorOf(l: List[Id]): int = if (floored(l)) 0 - l[0] else 0
  // k is a replaced root: it keeps only what the newest list names.
  pure def replaced(cuts: Key -> List[Id], k: Key): bool = cuts.keys().contains(k) and not(floored(cuts.get(k)))
  // r's key is not replaced, or r is on the list the recovery record kept of r's key; of the
  // current root, r is at or above `from`, or listed.
  pure def within(cuts: Key -> List[Id], r: Record): bool =
    not(cuts.keys().contains(r.signer)) or inLine(cuts.get(r.signer), r.id)
      or (floored(cuts.get(r.signer)) and r.seq >= floorOf(cuts.get(r.signer)))
  // A set of IDs as a list, in ID order.
  pure def toList(s: Set[Id]): List[Id] = range(1, MAXREC + 6).select(i => s.contains(i))

  // What a checkpoint keeps as anchors, and which records it prunes.
  pure def anchorsOf(c: Record): Set[Id] =
    c.heads.keys().filter(k => c.heads.get(k).length() > 0).map(k => lastId(c.heads.get(k))).union(c.keep)
  // A checkpoint never prunes a root's removal (a root's removal is final).
  pure def rootRemoval(r: Record): bool = r.kind == "revoke" and ROOT_KEYS.contains(r.signer)
  pure def prunedBy(c: Record, r: Record): bool =
    not(rootRemoval(r)) and c.heads.keys().contains(r.signer) and r.seq <= c.heads.get(r.signer).length() and not(anchorsOf(c).contains(r.id))

  pure val NONEREC: Record = {
    id: 0, signer: "", seq: 0, line: [], kind: "", target: "", kit: "", targetRec: 0, seen: Map(), heads: Map(), keep: Set(), units: 0,
  }

  // --- The recovery chain (rule 33) -------------------------------------------------------

  // A recovery record is valid by itself and the chain below it : the recovery
  // key signed it, and its new root differs from every root before it.
  pure def validAt(r: Record, path: List[Key]): bool =
    r.kind == "recover" and r.signer == RECOVERY and ROOT_KEYS.contains(r.target) and not(onList(path, r.target))
  // The chain a member follows among the recovery records rs: from seq 1, a valid record
  // whose previous ID is the member's tip extends it; a gap ends the chain. Any two records the
  // recovery key signed at one seq, at any depth, valid or not, are a fork: the member stops
  // for good.
  pure def chainOf(rs: Set[Record]): Chain =
    range(1, MAXCHAIN + 1).foldl({ ids: [], recs: [], key: RECOVERY, stop: false, open: true }, (acc, i) =>
      if (not(acc.open)) acc
      else {
        val path = pathCutsOf(acc.recs)._1
        val cands = rs.filter(r => isChain(r) and r.seq == i and validAt(r, path) and r.line.slice(0, i - 1) == acc.ids)
        if (cands.size() != 1) { ...acc, open: false }
        else {
          val c = cands.fold(NONEREC, (a, r) => r)
          { ...acc, ids: acc.ids.append(c.id), recs: acc.recs.append(c) }
        }
      })
  pure def forked(rs: Set[Record]): bool =
    rs.exists(a => rs.exists(b => isChain(a) and isChain(b) and a != b and a.signer == RECOVERY and b.signer == RECOVERY
      and a.seq == b.seq))
  pure def chainOfAll(rs: Set[Record]): Chain = { ...chainOf(rs), stop: forked(rs) }
  // The path and the replaced roots' lists the chain gives: each record makes its key the
  // root; the newest record's list is the whole truth about every earlier root (lists do not
  // add up).
  pure def pathCutsOf(l: List[Record]): (List[Key], Key -> List[Id]) = {
    val path = l.foldl([ROOT], (p, c) => p.append(c.target))
    val list = if (l.length() == 0) [] else toList(l[l.length() - 1].keep)
    val from = if (l.length() == 0) 0 else l[l.length() - 1].targetRec
    val olds = path.indices().filter(i => i + 1 < path.length()).map(i => path[i]).mapBy(k => list)
    // The newest record's from: the seq at which the new root's records start; a key that
    // signed before (as an admin) keeps below it only what the list names.
    (path, if (from > 1) olds.put(last(path), [0 - from].concat(list)) else olds)
  }
  pure def pathCuts(ch: Chain): (List[Key], Key -> List[Id]) = pathCutsOf(ch.recs)

  // --- Keeping (rule 6) ------------------------------------------------------------------

  // A record's place in its key's order: by seq, then ID; first the current root's
  // checkpoints, so that a full root can still checkpoint, and any root's removals, freezes
  // and resolves, so that a full set never drops one while it keeps a record of that root.
  // A replaced root keeps what its recovery record lists, before anything else of it.
  type Order = { roots: Set[Key], cuts: Key -> List[Id] }
  pure def pos(r: Record, cur: Key, ord: Order): int = {
    val cp = r.signer == cur and r.kind == "checkpoint"
    val early = ord.roots.contains(r.signer) and (r.kind == "revoke" or r.kind == "freeze" or r.kind == "resolve")
    if (rootRemoval(r)) r.seq * 100 + hid(r.id)
    else if (r.signer != cur and ord.cuts.keys().contains(r.signer)) {
      if (inLine(ord.cuts.get(r.signer), r.id)) 10000 + r.seq * 100 + hid(r.id)
      else 200000 + r.seq * 100 + hid(r.id)
    }
    else if (cp) (if (EARLY_BEFORE_CHECKPOINTS) 10000 else 0) + (MAXREC + 4 - r.seq) * 100 + hid(r.id)
    else if (early) (if (EARLY_BEFORE_CHECKPOINTS) 0 else 10000) + r.seq * 100 + hid(r.id)
    else 100000 + r.seq * 100 + hid(r.id)
  }
  pure def minPos(rs: Set[Record], cur: Key, ord: Order): int = rs.fold(NONE, (m, r) => min2(m, pos(r, cur, ord)))
  // The units of a key's records up to r, r included.
  pure def prefix(rs: Set[Record], r: Record, cur: Key, ord: Order): int =
    sumUnits(rs.filter(x => pos(x, cur, ord) <= pos(r, cur, ord)))

  pure def past(cut: Cut, r: Record, cur: Key, ord: Order): bool =
    cut.marks.keys().contains(r.signer) and pos(r, cur, ord) >= cut.marks.get(r.signer)._1

  pure def dropped(cut: Cut, k: Key): int = if (cut.marks.keys().contains(k)) cut.marks.get(k)._2 else 0
  pure def demand(owned: Set[Record], ceil: Key -> int, cut: Cut, s: int): int =
    owned.map(r => r.signer).fold(0, (d, k) =>
      d + min2(s, min2(ceil.get(k), dropped(cut, k) + sumUnits(ofKey(owned, k)))))

  // What a set keeps of items, having dropped before what cut remembers: water-filling to one
  // level for every key with room (ceil), each key's records in its order.
  pure def keepAfter(items: Set[Record], ceil: Key -> int, cut: Cut, cur: Key, ord: Order): (Set[Id], Cut) = {
    val live = items.filter(r => not(past(cut, r, cur, ord)))
    val owned = live.filter(r => ceil.keys().contains(r.signer))
    val top = min2(cut.level, TOP)
    val level =
      if (demand(owned, ceil, cut, top) <= ROOM) top
      else 0.to(top).filter(s => demand(owned, ceil, cut, s) <= ROOM).fold(0, (m, s) => max2(m, s))
    val keptOwned = owned.filter(r => prefix(ofKey(owned, r.signer), r, cur, ord) <= min2(level, ceil.get(r.signer)))
    val out = owned.exclude(keptOwned)
    val markKeys = cut.marks.keys().union(out.map(r => r.signer))
    val marks = markKeys.mapBy(k => {
      val o = ofKey(out, k)
      if (o == Set()) cut.marks.get(k)
      else if (cut.marks.keys().contains(k))
        (min2(minPos(o, cur, ord), cut.marks.get(k)._1), sumUnits(o) + cut.marks.get(k)._2)
      else (minPos(o, cur, ord), sumUnits(o))
    })
    (idsOf(keptOwned), { level: level, marks: marks })
  }

  // --- A member's set (the keys it knows, what it stores) --------------------------------

  // The admin keys a member knows: those the roots on its path name, each replaced root's
  // within its list.
  pure def learned(rs: Set[Record], path: List[Key], cuts: Key -> List[Id]): Set[Key] =
    rs.filter(r => onList(path, r.signer) and within(cuts, r) and r.kind == "admin").map(r => r.target)

  // The ceilings: a root's on the path, an admin key's.
  pure def ceilings(path: List[Key], admins: Set[Key]): Key -> int =
    SIGNERS.filter(k => onList(path, k) or admins.contains(k)).mapBy(k => if (onList(path, k)) ROOTC else ADMINC)

  pure def rootsOf(path: List[Key]): Set[Key] = path.indices().map(i => path[i])

  // The chain, the path and the lists a set keeps by: those of the recovery records it holds.
  pure def chainState(s: Store, db: Id -> Record): Chain = chainOfAll(recsOf(s.chain, db))
  pure def keptPath(s: Store, db: Id -> Record): List[Key] = pathCuts(chainState(s, db))._1
  pure def keptCuts(s: Store, db: Id -> Record): Key -> List[Id] = pathCuts(chainState(s, db))._2
  pure def orderOf(s: Store, db: Id -> Record): Order = { roots: rootsOf(keptPath(s, db)), cuts: keptCuts(s, db) }

  // Whether a set stores r at all: its signer is known, it is within its root's list (a
  // replaced root keeps nothing else), and the checkpoint the set compacted on does not prune
  // it (unless a replaced root signed that checkpoint).
  pure def storable(s: Store, r: Record, db: Id -> Record): bool = {
    val got = recsOf(s.got, db)
    val path = keptPath(s, db)
    val cuts = keptCuts(s, db)
    val admins = learned(got, path, cuts)
    not(isChain(r))
      and (admins.contains(r.signer) or onList(path, r.signer))
      and within(cuts, r)
      and (s.checkpoint == 0 or replaced(cuts, db.get(s.checkpoint).signer) or not(prunedBy(db.get(s.checkpoint), r)))
  }

  // What a set keeps of items: of those within the lists, what the rooms keep.
  pure def settle(s: Store, items: Set[Record], cut: Cut, db: Id -> Record): (Set[Id], Cut) = {
    val path = keptPath(s, db)
    val cuts = keptCuts(s, db)
    val admins = learned(recsOf(s.got, db), path, cuts)
    val shown = items.filter(r => within(cuts, r))
    keepAfter(shown, ceilings(path, admins), cut, last(path), orderOf(s, db))
  }

  // Drops what the set does not keep.
  pure def recut(s: Store, db: Id -> Record): Store = {
    val res = settle(s, recsOf(s.recs, db), s.cut, db)
    { ...s, recs: res._1, cut: res._2 }
  }

  // A record offered to the set: a recovery record is held always, whatever any root or admin
  // signed before, a removal of the member itself included (brief v2, section 4);
  // another is stored when the set may store it and its key dropped nothing before it, then
  // the set cuts back.
  pure def insertInto(s0: Store, r: Record, db: Id -> Record): Store = {
    val s = { ...s0, got: s0.got.union(Set(r.id)) }
    // The set cuts its rooms by the new path at once, so that a record offered next is judged by
    // the path the set holds now, not the one it last cut by.
    if (isChain(r)) pathed({ ...s, chain: s.chain.union(Set(r.id)) }, db)
    else if (s.recs.contains(r.id) or past(s.cut, r, last(keptPath(s, db)), orderOf(s, db)) or not(storable(s, r, db))) s
    else recut({ ...s, recs: s.recs.union(Set(r.id)) }, db)
  }

  // When the chain changes the path, the set cuts its rooms again by the new path: the new
  // root gets a root's room, the replaced root keeps its list, and the set forgets the cut it
  // kept by the old path.
  pure def pathed(s: Store, db: Id -> Record): Store = {
    val pc = pathCuts(chainState(s, db))
    if (pc._1 == s.path and pc._2 == s.cuts) s
    else {
      val s2 = { ...s, path: pc._1, cuts: pc._2, cut: NOCUT }
      recut({ ...s2, recs: s2.recs.filter(i => storable(s2, db.get(i), db)) }, db)
    }
  }

  // Compaction: the set takes its state's checkpoint and drops what that prunes.
  pure def compactStore(s: Store, v: View, db: Id -> Record): Store =
    if (v.checkpoint == s.checkpoint) s
    else {
      val s2 = { ...s, checkpoint: v.checkpoint, cut: NOCUT }
      recut({ ...s2, recs: s2.recs.filter(i => storable(s2, db.get(i), db)) }, db)
    }

  // --- Evaluation --------------------------------------------------------------------------

  // The evaluation of the room records under the path of roots, with the anchors of the
  // checkpoint it prunes by.
  pure def epoch(rs: Set[Record], path: List[Key], cuts: Key -> List[Id], anchors: Set[Id]): View = {
    val cur = last(path)
    val adminKeys = learned(rs, path, cuts)
    val ids = idsOf(rs)
    pure def saw(a: Record, t: Record): bool = sawIn(a, t, ids, anchors)
    pure def isAdmin(r: Record): bool = adminKeys.contains(r.signer) and not(onList(path, r.signer))
    pure def onPath(r: Record): bool = not(isAdmin(r)) and onList(path, r.signer) and within(cuts, r)
    // A root's removal, freeze or resolve counts by itself, without the records below it; it
    // makes nothing above it whole.
    pure def early(r: Record): bool = onPath(r) and (r.kind == "revoke" or r.kind == "freeze" or r.kind == "resolve")
    // A whole chain: every record of its line is here, or down to an anchor; a replaced root's
    // listed record counts by the list; of a current root with a from, its line from there.
    pure def whole(r: Record): bool = {
      val top = r.line.indices().fold(-1, (m, j) => if (anchors.contains(r.line[j])) j else m)
      val low = if (cuts.keys().contains(r.signer)) floorOf(cuts.get(r.signer)) - 2 else -1
      early(r) or replaced(cuts, r.signer) or r.line.indices().forall(i => i <= max2(top, low) or ids.contains(r.line[i]))
    }
    // The resolves of every root on the path; a root's removal is final.
    val voids = rs.filter(r => onPath(r) and r.kind == "resolve" and whole(r)).map(r => r.targetRec)
      .filter(i => not(rs.exists(x => x.id == i and x.kind == "revoke" and onList(path, x.signer) and not(isAdmin(x)))))
    // Two histories: a key with two live whole records at one seq counts nothing from that seq
    // on. A record is dead when its line holds a voided record that has a twin: a root's
    // resolve picks a branch.
    val wholes = rs.filter(r => whole(r) and within(cuts, r))
    val deadIds = voids.filter(i => rs.exists(x => x.id == i and rs.exists(o => o != x and o.signer == x.signer and o.seq == x.seq)))
    val lives = wholes.filter(r => not(r.line.indices().exists(j => deadIds.contains(r.line[j]))))
    val forkSeq = SIGNERS.mapBy(k => lives.filter(r => r.signer == k
      and lives.exists(o => o != r and o.signer == k and o.seq == r.seq)).fold(NONE, (m, r) => min2(m, r.seq)))
    pure def forkAt(k: Key): int = getOr(forkSeq, k, NONE)
    val forks = SIGNERS.filter(k => forkAt(k) < NONE)
    pure def belowFork(r: Record): bool = r.seq < forkAt(r.signer) or (ROOT_REMOVAL_SURVIVES_FORK and early(r))
    pure def counted(r: Record): bool =
      lives.contains(r) and not(voids.contains(r.id)) and belowFork(r)
    pure def rootRec(r: Record): bool = onPath(r) and counted(r)
    pure def newer(a: Record, b: Record): bool = {
      val pa = indexOf(path, a.signer)
      val pb = indexOf(path, b.signer)
      pa > pb or (pa == pb and a.seq > b.seq)
    }
    // The admin keys, each with the set of the newest root record that names it.
    val adminRecs = rs.filter(r => r.kind == "admin" and rootRec(r))
    val named = adminRecs.map(r => r.target)
    val adm = named.mapBy(a => {
      val mine = adminRecs.filter(r => r.target == a)
      mine.filter(r => mine.forall(o => o == r or newer(r, o))).fold("", (s, r) => r.kit)
    })
    pure def has(a: Key, p: str): bool = adm.keys().contains(a) and powersOf(adm.get(a)).contains(p)
    pure def isAdminKey(k: Key): bool = withPair(k).exists(x => adm.keys().contains(x))
    pure def isRootKey(k: Key): bool = onList(path, k)
    pure def rootHas(d: Key): bool = rs.exists(r => devOf(r) == d and rootRec(r))
    // An admin key acts only by its device's newest root record: a newer root record of the
    // device that names no admin key, or another one, replaces it, and works as a removal of
    // the old key: what it signed and the replacing record saw counts, the rest not.
    pure def about(d: Key): Set[Record] = rs.filter(r => devOf(r) == d and rootRec(r))
    pure def replacers(k: Key): Set[Record] =
      if (not(DEV.keys().contains(k))) Set()
      else {
        val naming = adminRecs.filter(r => r.target == k)
        about(DEV.get(k)).filter(r => not(r.kind == "admin" and r.target == k) and naming.forall(n => newer(r, n)))
      }
    pure def current(k: Key): bool = adm.keys().contains(k) and replacers(k) == Set()
    // The admin record that admits a device no root recorded: each admin's first, the
    // smallest ID.
    pure def admittedBy(d: Key): Id = {
      val ok = rs.filter(r => r.kind == "device" and r.target == d and isAdmin(r) and counted(r) and has(r.signer, "admit"))
      val firsts = ok.filter(r => not(ok.exists(o => o.signer == r.signer and o.seq < r.seq)))
      if (rootHas(d)) -1 else firsts.fold(NONE, (m, r) => min2(m, r.id))
    }
    // What an admin's record may do.
    pure def permitted(r: Record): bool =
      if (not(adm.keys().contains(r.signer))) false
      else if (r.kind == "device") {
        val first = admittedBy(r.target)
        not(rootHas(r.target)) and (first == r.id or (first != NONE and first != -1 and has(r.signer, "manage")))
      }
      else if (r.kind == "revoke")
        if (withPair(r.target).exists(t => isRootKey(t))) false
        else if (isAdminKey(r.target)) has(r.signer, "removeAdmins")
        else has(r.signer, "remove")
      else if (r.kind == "freeze")
        has(r.signer, "freeze") and withPair(r.target).exists(t => adm.keys().contains(t))
          and withPair(r.target).forall(t => not(has(t, "removeAdmins")))
      else if (r.kind == "thaw") has(r.signer, "thaw") and has(r.signer, "removeAdmins")
      else if (r.kind == "copies") true
      else false
    // a, a removal or freeze, cuts off b: it names a key of b's signer's device and did not
    // see b; of its own signer's key, it cuts off only what that key signs after it. A thaw of
    // a freeze leaves cut off what the freeze cut off and the thaw did not see. A record a
    // thawed key signs counts when its seen lists the thaw (rule 31).
    pure def thawedFor(f: Record, b: Record): bool = rs.exists(t => t.kind == "thaw" and t.targetRec == f.id
      and (onPath(t) or (isAdmin(t) and has(t.signer, "thaw") and has(t.signer, "removeAdmins"))) and saw(b, t))
    pure def cutsOffRm(a: Record, b: Record): bool =
      (a.kind == "revoke" or a.kind == "freeze") and a != b and withPair(a.target).contains(b.signer)
        and (if (a.signer == b.signer) b.seq > a.seq else not(saw(a, b)))
        and not(a.kind == "freeze" and thawedFor(a, b))
    pure def cutsOff(a: Record, b: Record): bool =
      if (a.kind == "thaw") rs.exists(f => f.id == a.targetRec and f.kind == "freeze" and cutsOffRm(f, b)) and not(saw(a, b))
      else cutsOffRm(a, b)
    val rootThawed = rs.filter(r => r.kind == "thaw" and rootRec(r)).map(r => r.targetRec)
    val rootActs = rs.filter(r => rootRec(r)
      and (r.kind == "revoke" or r.kind == "thaw" or (r.kind == "freeze" and not(rootThawed.contains(r.id)))))
    val toLabel = rs.filter(r => isAdmin(r) and counted(r))
    val outFirst = toLabel.filter(b => not(permitted(b)) or (b.kind == "freeze" and rootThawed.contains(b.id))
      or rootActs.exists(a => cutsOff(a, b)) or replacers(b.signer).exists(a => not(saw(a, b))))
    pure def attackers(b: Record): Set[Record] =
      toLabel.filter(a => not(outFirst.contains(a))
        and (cutsOff(a, b) or (b.kind == "freeze" and a.kind == "thaw" and a.targetRec == b.id)))
    // The grounded labelling of the admins' removals, freezes and thaws.
    val labels = 0.to(MAXREC).fold((Set(), outFirst), (io, i) => {
      val open = toLabel.exclude(io._1).exclude(io._2)
      val newOut = open.filter(b => attackers(b).exists(a => io._1.contains(a)))
      val newIn = open.filter(b => attackers(b).forall(a => io._2.contains(a)))
      (io._1.union(newIn), io._2.union(newOut))
    })
    val ins = labels._1
    val undecided = toLabel.exclude(ins).exclude(labels._2)
    val adminConflict = undecided.exists(r => r.kind == "revoke" or r.kind == "freeze" or r.kind == "thaw")
    pure def counts(r: Record): bool = rootRec(r) or (isAdmin(r) and ins.contains(r))
    val revoked = rs.filter(r => r.kind == "revoke" and counts(r)).fold(Set(), (s, r) => s.union(withPair(r.target)))
    val frozen = rs.filter(r => r.kind == "freeze" and counts(r) and not(rootThawed.contains(r.id)))
      .fold(Set(), (s, r) => s.union(withPair(r.target)))
    val currentAdmins = adm.keys().filter(a => current(a) and not(revoked.contains(a)))
    val stop = adminConflict
    val devices = rs.filter(r => counts(r) and devOf(r) != "").map(r => devOf(r)).exclude(revoked)
    {
      path: path,
      counting: idsOf(rs.filter(r => counts(r))),
      revoked: revoked,
      frozen: frozen,
      admins: currentAdmins.mapBy(a => adm.get(a)),
      stop: stop,
      devices: devices,
      commanders: currentAdmins.union(Set(cur)).filter(k => not(revoked.contains(k)) and not(frozen.contains(k))
        and not(forks.contains(k)) and (k == cur or not(stop))),
      rootsCount: rs.filter(r => onPath(r) and r.signer == cur and counted(r)).forall(r => counts(r)),
      cuts: cuts,
      checkpoint: 0,
    }
  }

  // The newest checkpoint of a root, within its list: the highest seq, then the smallest ID;
  // 0 when it has none.
  pure def newestCheckpoint(rs: Set[Record], v: View, k: Key): Id = {
    val cs = rs.filter(r => r.signer == k and r.kind == "checkpoint" and within(v.cuts, r))
    cs.filter(c => cs.forall(o => o == c or c.seq > o.seq or (c.seq == o.seq and c.id < o.id))).fold(0, (m, c) => c.id)
  }

  // The state with the checkpoint c tried, or fallback when c is 0 or does not count in the
  // set it prunes.
  pure def applyCheckpoint(path: List[Key], cuts: Key -> List[Id], c: Id,
      acc: (Set[Record], Set[Id], View)): (Set[Record], Set[Id], View) =
    if (c == 0) acc
    else {
      val cp = acc._1.filter(r => r.id == c).fold(NONEREC, (a, r) => r)
      val pruned = acc._1.filter(r => not(prunedBy(cp, r)))
      val anchors = acc._2.union(anchorsOf(cp))
      val v = epoch(pruned, path, cuts, anchors)
      // It counts only on a set that holds every record its keep names, each on its key's
      // chain up to the checkpoint's head of that key: no ID in keep stands for a record
      // nobody saw, and two named twins are a fork before anything is pruned.
      val ids = idsOf(acc._1)
      val whole = cp.keep.forall(i => ids.contains(i) and {
        val r = acc._1.filter(x => x.id == i).fold(NONEREC, (a, x) => x)
        not(cp.heads.keys().contains(r.signer)) or r.seq > cp.heads.get(r.signer).length()
          or inLine(cp.heads.get(r.signer), i)
      })
      if (cp != NONEREC and whole and v.counting.contains(c)) (pruned, anchors, { ...v, checkpoint: c }) else acc
    }

  // The state: the path from the recovery chain; the current root's newest checkpoint
  // applies, a replaced root's never; two recovery records at one seq stop everything.
  pure def fullEvaluate(rs: Set[Record], ch: Chain): View = {
    val pc = pathCuts(ch)
    val plain = epoch(rs, pc._1, pc._2, Set())
    val a0 = (rs, Set(), plain)
    val v = applyCheckpoint(pc._1, pc._2, newestCheckpoint(rs, plain, last(pc._1)), a0)._3
    if (ch.stop) { ...v, stop: true, commanders: Set() } else v
  }

  // A member's state: its set evaluated (the evaluation keeps again what the set holds).
  pure def storeView(s: Store, db: Id -> Record): View =
    fullEvaluate(recsOf(settle(s, recsOf(s.recs, db), NOCUT, db)._1, db), chainState(s, db))

  // What a member given every record of got at once keeps, and its state.
  pure def pureKept(s: Store, db: Id -> Record): Set[Id] =
    settle(s, recsOf(s.got, db).filter(r => storable(s, r, db)), NOCUT, db)._1
  pure def pureView(s: Store, db: Id -> Record): View = fullEvaluate(recsOf(pureKept(s, db), db), chainState(s, db))

  // --- The system ------------------------------------------------------------------------

  var db: Id -> Record
  var nextId: int
  var st: str -> Store
  // Each member's state, kept with its set.
  var views: str -> View
  // The keys a root's removal took, as each member saw it: history for promise 2.
  var gone: str -> Set[Key]
  // Each member's path before its last change: history for promise 8.
  var before: str -> List[Key]
  // The admitter's path when the newcomer m took its Welcome: history for promise 9.
  var welcomed: List[Key]

  pure val EMPTY: Store = {
    recs: Set(), got: Set(), chain: Set(), cut: NOCUT, path: [ROOT], cuts: Map(), checkpoint: 0,
  }

  pure def rootRemoved(v: View, db: Id -> Record): Set[Key] =
    recsOf(v.counting, db).filter(r => r.kind == "revoke" and onList(v.path, r.signer))
      .fold(Set(), (s, r) => s.union(withPair(r.target)))

  // A set cut by its chain's path, and its state.
  pure def finish(s2: Store, db2: Id -> Record): (Store, View) = {
    val s3 = pathed(s2, db2)
    (s3, storeView(s3, db2))
  }

  // Member m's set becomes s2.
  action commit(db2: Id -> Record, n2: int, m: str, s2: Store): bool = {
    val sv = finish(s2, db2)
    all {
      db' = db2,
      nextId' = n2,
      st' = st.put(m, sv._1),
      views' = views.put(m, sv._2),
      gone' = gone.put(m, gone.get(m).union(rootRemoved(sv._2, db2))),
      before' = before.put(m, views.get(m).path),
      welcomed' = welcomed,
    }
  }

  // Every member's set becomes nx's at once.
  action commitAll(nx: str -> (Store, View)): bool = all {
    db' = db,
    nextId' = nextId,
    st' = MEMBERS.mapBy(m => nx.get(m)._1),
    views' = MEMBERS.mapBy(m => nx.get(m)._2),
    gone' = MEMBERS.mapBy(m => gone.get(m).union(rootRemoved(nx.get(m)._2, db))),
    before' = MEMBERS.mapBy(m => views.get(m).path),
    welcomed' = welcomed,
  }

  pure def rec(id: Id, signer: Key, line: List[Id], kind: str, target: Key, kit: str, targetRec: Id,
      seen: Key -> List[Id], heads: Key -> List[Id], keep: Set[Id], units: int): Record =
    { id: id, signer: signer, seq: line.length(), line: line, kind: kind, target: target, kit: kit, targetRec: targetRec,
      seen: seen, heads: heads, keep: keep, units: units }

  // The group as the root made it: A a phone admin, C a computer admin, W a watch admin; the
  // recovery key K is the group's own, known to every member from its admission.
  pure val START: Id -> Record = Map(
    1 -> rec(1, ROOT, [1], "admin", PHONE, "phone", 0, Map(), Map(), Set(), 1),
    2 -> rec(2, ROOT, [1, 2], "admin", COMPUTER, "computer", 0, Map(), Map(), Set(), 1),
    3 -> rec(3, ROOT, [1, 2, 3], "admin", WATCH, "watch", 0, Map(), Map(), Set(), 1),
  )
  pure def offerAll(s: Store, l: List[Id], db: Id -> Record): Store = l.foldl(s, (x, i) => insertInto(x, db.get(i), db))
  pure val STARTSTORE: Store = offerAll(EMPTY, [1, 2, 3], START)
  pure val FIRST = 4

  action init = all {
    db' = START,
    nextId' = FIRST,
    st' = MEMBERS.mapBy(m => STARTSTORE),
    views' = MEMBERS.mapBy(m => storeView(STARTSTORE, START)),
    gone' = MEMBERS.mapBy(m => Set()),
    before' = MEMBERS.mapBy(m => [ROOT]),
    welcomed' = [],
  }

  // The line of a key's newest record among rs (the highest seq, then the smallest ID).
  pure def headLine(rs: Set[Record], k: Key): List[Id] =
    ofKey(rs, k).fold((0, NONE, []), (b, r) => if (r.seq > b._1 or (r.seq == b._1 and r.id < b._2)) (r.seq, r.id, r.line) else b)._3

  // k signs a record; its own device stores it at once. What it saw is what that device holds,
  // or, for a thief, that with the other admins' records hidden. A fork signs at the seq of the
  // key's newest record again.
  action sign(k: Key, kind: str, target: Key, kit: str, targetRec: Id, pretend: bool, fork: bool, units: int): bool =
    signFull(k, kind, target, kit, targetRec, pretend, fork, units, false, Set())
  // The same, and a hidden record stays off its own device too (a root key used for a minute
  // by someone who keeps the record back); a checkpoint may name more records in its keep.
  action signFull(k: Key, kind: str, target: Key, kit: str, targetRec: Id, pretend: bool, fork: bool, units: int,
      hidden: bool, extraKeep: Set[Id]): bool = {
    val h = HOLDER.get(k)
    val s = st.get(h)
    val mine = recsOf(s.recs, db)
    val own = headLine(db.keys().map(i => db.get(i)), k)
    val base = if (fork and own.length() > 0) own.slice(0, own.length() - 1) else own
    val seen0 = SIGNERS.mapBy(x => if (x == k) base else headLine(mine, x))
    val seen = if (pretend) seen0.keys().mapBy(x => if (x != k and THIEVES.contains(x)) [] else seen0.get(x)) else seen0
    val isCp = kind == "checkpoint"
    val r = rec(nextId, k, base.append(nextId), kind, target, kit, targetRec,
      seen,
      if (isCp) seen else Map(),
      // A checkpoint keeps what its signer counts.
      if (isCp) views.get(h).counting.filter(i => db.get(i).kind != "checkpoint").union(extraKeep) else Set(),
      units)
    val db2 = db.put(nextId, r)
    all {
      SIGNERS.contains(k),
      nextId <= FIRST + MAXREC,
      not(fork) or own.length() > 0,
      commit(db2, nextId + 1, h, if (hidden) s else insertInto(s, r, db2)),
    }
  }

  // The recovery key k (or a thief holding it) signs a recovery record at seq `at` of the
  // chain its member follows (at its end, or at a seq that chain already has: a twin). The
  // list: "honest" is what the core writes on the device that becomes the root (every record
  // of the roots so far that it counts, the new root key's own records that count when it was
  // an admin, every root's removal it holds, and the heads the current root's counting
  // checkpoint named, not that checkpoint itself); "literal" is the same with only the current
  // root's counted records (the first wording of brief v2); "none" lists nothing; "all" lists
  // every record those roots ever signed. The owner's "who stays" is removals the new root
  // signs after. The record's from (targetRec) is the seq at which the new root's records
  // start: 1 for a fresh key, after its last record for a key that signed as an admin.
  // "honest" also signs the new root's first checkpoint, before the head is released: the
  // heads the list anchors (the replaced root's counting checkpoint's), keeping what the
  // writer counts under the new root. "nocp" is "honest" without that checkpoint; "from1" is
  // "honest" with from 1 (the key's admin records taken as a root's).
  action signChain(k: Key, kind: str, target: Key, at: int, mode: str): bool = {
    val h = HOLDER.get(k)
    val s = st.get(h)
    val v = views.get(h)
    val ch = chainState(s, db)
    val base = ch.ids.slice(0, at - 1)
    val before = pathCutsOf(ch.recs.slice(0, at - 1))._1
    val cur = last(before)
    val held = recsOf(s.recs, db).filter(r => onList(before, r.signer) or r.signer == target)
    val oldCp = if (v.checkpoint != 0 and db.get(v.checkpoint).signer == cur) db.get(v.checkpoint) else NONEREC
    val cp = oldCp.heads.keys().filter(k => oldCp.heads.get(k).length() > 0)
      .map(k => lastId(oldCp.heads.get(k))).filter(i => onList(before, db.get(i).signer))
    val honest = idsOf(held.filter(r => (v.counting.contains(r.id) and r.kind != "checkpoint") or rootRemoval(r))).union(cp)
    val keep = if (mode == "honest" or mode == "nocp" or mode == "from1") honest
      else if (mode == "literal") honest.filter(i => db.get(i).signer == cur or rootRemoval(db.get(i)) or cp.contains(i))
      else if (mode == "none") Set()
      else db.keys().filter(i => onList(before, db.get(i).signer))
    val own = headLine(db.keys().map(i => db.get(i)), target)
    val from = if (mode == "from1") 1 else own.length() + 1
    val r = rec(nextId, k, base.append(nextId), kind, target, "", from, Map(), Map(), keep, 0)
    val db2 = db.put(nextId, r)
    val s1 = insertInto(s, r, db2)
    val withCp = mode == "honest" or mode == "from1"
    // The new root's first checkpoint: what the writer counts once the head applies.
    val v1 = finish(s1, db2)._2
    val c = rec(nextId + 1, target, own.append(nextId + 1), "checkpoint", "", "", 0, oldCp.heads, oldCp.heads,
      v1.counting.filter(i => db2.get(i).kind != "checkpoint"), 2)
    val db3 = if (withCp) db2.put(nextId + 1, c) else db2
    all {
      RKEYS.contains(k),
      at >= 1,
      at <= ch.ids.length() + 1,
      nextId + 1 <= FIRST + MAXREC,
      commit(db3, if (withCp) nextId + 2 else nextId + 1, h, if (withCp) insertInto(pathed(s1, db3), c, db3) else s1),
    }
  }

  action signDevice = nondet k = Set(ROOT, PHONE, COMPUTER, "NA", "NK", MINTED).oneOf() nondet f = Set(true, false).oneOf()
    sign(k, "device", DEVICE, "", 0, false, f, 1)
  // A root (or a thief) names an admin; a root may name again one it removed.
  action signAdmin = nondet k = Set(ROOT, PHONE, "NA", "NK").oneOf() nondet a = Set(PHONE, COMPUTER, "C2", WATCH, MINTED, "NA").oneOf()
    nondet kit = Set("phone", "computer", "watch").oneOf() sign(k, "admin", a, kit, 0, false, false, 1)
  // A root takes the admin key off a device: a device record about it, with no admin key.
  action signDemote = nondet k = ROOT_KEYS.oneOf() nondet d = Set("dA", "dC", "dW").oneOf()
    sign(k, "device", d, "", 0, false, false, 1)
  // Anyone removes or freezes anyone, the recovery key too (which no such record touches).
  action signRevoke = nondet k = SIGNERS.oneOf() nondet t = Set(PHONE, "dA", COMPUTER, WATCH, RECOVERY, DEVICE, MINTED).oneOf()
    nondet p = Set(true, false).oneOf() sign(k, "revoke", t, "", 0, p, false, 1)
  action signFreeze = nondet k = Set(ROOT, PHONE, COMPUTER, WATCH, "NA").oneOf() nondet t = Set(COMPUTER, WATCH, RECOVERY, "dW", PHONE).oneOf()
    nondet p = Set(true, false).oneOf() sign(k, "freeze", t, "", 0, p, false, 1)
  // A key whose freeze its member holds a thaw of signs again, listing the thaw (rule 31).
  action signAfterThaw = nondet i = db.keys().oneOf() all {
    db.get(i).kind == "thaw",
    db.keys().contains(db.get(i).targetRec),
    val k = db.get(db.get(i).targetRec).target
    all {
      Set(COMPUTER, WATCH, PHONE).contains(k),
      st.get(HOLDER.get(k)).recs.contains(i),
      sign(k, "device", DEVICE, "", 0, false, false, 1),
    },
  }
  action signThaw = nondet k = Set(ROOT, PHONE, "NA").oneOf() nondet i = db.keys().oneOf() all {
    db.get(i).kind == "freeze",
    sign(k, "thaw", "", "", i, false, false, 1),
  }
  // A root voids a record.
  action signResolve = nondet k = Set(ROOT, "NA", "NK").oneOf() nondet i = db.keys().oneOf() nondet f = Set(true, false).oneOf()
    sign(k, "resolve", "", "", i, false, f, 1)
  action signCheckpoint = nondet k = Set(ROOT, "NA", "NK").oneOf() sign(k, "checkpoint", "", "", 0, false, false, 2)
  // A root's record kept back from every member (a twin of its newest record, or the next
  // one), and a root's checkpoint whose keep names any record of its key, held or not.
  action signHidden = nondet k = ROOT_KEYS.oneOf() nondet f = Set(true, false).oneOf()
    nondet kind = Set("admin", "revoke").oneOf() nondet t = Set(MINTED, PHONE, COMPUTER).oneOf()
    signFull(k, kind, t, "phone", 0, false, f, 1, true, Set())
  action signCheckpointNaming = nondet k = ROOT_KEYS.oneOf() nondet i = db.keys().oneOf() all {
    db.get(i).signer == k,
    signFull(k, "checkpoint", "", "", 0, false, false, 2, false, Set(i)),
  }
  // An admin key uses a later root's key as a device's member key.
  action signUseKey = nondet k = Set(PHONE, COMPUTER, WATCH, MINTED).oneOf() nondet t = Set("NA", "NK", MINTED).oneOf()
    sign(k, "device", t, "", 0, false, false, 1)
  action signCopies = nondet k = SIGNERS.oneOf() nondet u = Set(1, 2).oneOf() sign(k, "copies", "", "", 0, false, false, u)
  // Any recovery record at any place: a new root (or a key that was one, which is not
  // valid), any list.
  action signRecover = nondet t = Set("NA", "NK", ROOT).oneOf()
    nondet mode = Set("honest", "literal", "none", "all", "nocp", "from1").oneOf() nondet at = Set(1, 2, 3).oneOf()
    signChain(RECOVERY, "recover", t, at, mode)

  // A newcomer: m starts again from what admitter x hands it, the recovery chain and its
  // records (rule 33, point 9).
  pure def welcomeStore(sx: Store, db: Id -> Record): Store = {
    val withChain = sx.chain.fold(EMPTY, (s, i) => insertInto(s, db.get(i), db))
    sx.recs.fold(pathed(withChain, db), (s, i) => insertInto(s, db.get(i), db))
  }
  action welcomeNewcomer = nondet x = MEMBERS.exclude(Set("m")).oneOf() welcomeFrom(x)
  action welcomeFrom(x: str): bool = {
    val sv = finish(welcomeStore(st.get(x), db), db)
    all {
      db' = db,
      nextId' = nextId,
      st' = st.put("m", sv._1),
      views' = views.put("m", sv._2),
      gone' = gone.put("m", rootRemoved(sv._2, db)),
      before' = before.put("m", sv._2.path),
      welcomed' = views.get(x).path,
    }
  }

  // Member m is offered record i.
  action give(m: str, i: Id): bool = commit(db, nextId, m, insertInto(st.get(m), db.get(i), db))

  // Sync: a member is offered a record it does not keep (again, perhaps).
  action deliver = nondet m = MEMBERS.oneOf() nondet i = db.keys().oneOf() all {
    not(st.get(m).recs.contains(i)),
    not(st.get(m).chain.contains(i)),
    give(m, i),
  }

  // A member compacts: it takes its state's checkpoint.
  action compact = nondet m = MEMBERS.oneOf() compactAt(m)
  action compactAt(m: str): bool = commit(db, nextId, m, compactStore(st.get(m), views.get(m), db))

  action step = any {
    signDevice, signDemote, signAdmin, signRevoke, signFreeze, signThaw, signResolve, signCheckpoint, signCopies,
    signUseKey, signAfterThaw, signHidden, signCheckpointNaming, signRecover, welcomeNewcomer,
    deliver, deliver, deliver, deliver, compact,
  }

  // --- Guided steps ------------------------------------------------------------------------

  // The recovery key, on its member, changes the root to a key its state does not know, at the
  // end of the chain it follows: the honest writer refuses a key that signed or was named
  // (brief v2, section 4). A head naming a known key comes only from signRecover (the
  // recovery key used by hand).
  pure def knownTo(s: Store, t: Key, db: Id -> Record): bool =
    recsOf(s.got, db).exists(r => r.signer == t or (r.kind == "admin" and r.target == t) or r.target == t)
  action signChange = nondet t = Set("NA", "NK").oneOf() {
    val ch = chainState(st.get("k"), db)
    all {
      not(ch.stop),
      not(onList(views.get("k").path, t)),
      not(knownTo(st.get("k"), t, db)),
      signChain(RECOVERY, "recover", t, ch.ids.length() + 1, "honest"),
    }
  }
  // A new root signs, for the next change to list or to fill the room.
  action signNewRoot = nondet k = Set("NA", "NK").oneOf() nondet u = Set(1, 2).oneOf() all {
    onList(views.get(HOLDER.get(k)).path, k),
    sign(k, "copies", "", "", 0, false, false, u),
  }
  // A thief holds the old root key after a change of root: it signs removals, new admins,
  // devices, resolves and checkpoints as the old root.
  action oldRootThief = nondet i = db.keys().oneOf() all {
    MEMBERS.exists(m => views.get(m).path.length() > 1),
    any {
      sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1),
      sign(ROOT, "revoke", PHONE, "", 0, false, false, 1),
      sign(ROOT, "revoke", RECOVERY, "", 0, false, false, 1),
      sign(ROOT, "admin", MINTED, "phone", 0, false, false, 1),
      sign(ROOT, "device", DEVICE, "", 0, false, false, 1),
      sign(ROOT, "resolve", "", "", i, false, false, 1),
      sign(ROOT, "checkpoint", "", "", 0, false, false, 2),
      signFull(ROOT, "admin", MINTED, "phone", 0, false, true, 1, false, Set()),
    },
  }
  // A root removes the phone admin; then a thief holding the removed phone admin's key signs
  // removals, freezes, devices and thaws, pretending it saw nothing.
  action rootRemovesPhone = nondet k = ROOT_KEYS.oneOf() all {
    onList(views.get(HOLDER.get(k)).path, k),
    sign(k, "revoke", PHONE, "", 0, false, false, 1),
  }
  action removedAdminThief = nondet i = db.keys().oneOf() nondet p = Set(true, false).oneOf() all {
    MEMBERS.exists(m => views.get(m).revoked.contains(PHONE)),
    any {
      sign(PHONE, "revoke", COMPUTER, "", 0, p, false, 1),
      sign(PHONE, "revoke", DEVICE, "", 0, p, false, 1),
      sign(PHONE, "revoke", "dA", "", 0, p, false, 1),
      sign(PHONE, "freeze", WATCH, "", 0, p, false, 1),
      sign(PHONE, "device", DEVICE, "", 0, p, false, 1),
      sign(PHONE, "copies", "", "", 0, p, false, 2),
      sign(PHONE, "thaw", "", "", i, p, false, 1),
      sign(PHONE, "device", DEVICE, "", 0, p, true, 1),
    },
  }
  // The recovery key (or a thief holding it) signs a second record at a seq the chain
  // already has, at any depth.
  action recoveryTwin = nondet t = Set("NA", "NK").oneOf() nondet at = Set(1, 2, 3).oneOf() {
    val ch = chainState(st.get("k"), db)
    all {
      at <= ch.ids.length(),
      signChain(RECOVERY, "recover", t, at, "honest"),
    }
  }
  // Every member is offered one record at once: any record, or the newest.
  action offerEveryone(i: Id): bool = commitAll(MEMBERS.mapBy(m => finish(insertInto(st.get(m), db.get(i), db), db)))
  action broadcast = nondet i = db.keys().oneOf() offerEveryone(i)
  action broadcastNewest = offerEveryone(nextId - 1)
  // Sync with fairness: every member is offered, in ID order, every record some member holds.
  action syncAll = {
    val held = MEMBERS.fold(Set(), (u, n) => u.union(st.get(n).recs).union(st.get(n).chain))
    val order = range(1, nextId).select(i => held.contains(i))
    commitAll(MEMBERS.mapBy(m => finish(order.foldl(st.get(m), (s, i) => insertInto(s, db.get(i), db)), db)))
  }
  action guided = any {
    step, signChange, signChange, signChange, signNewRoot, signNewRoot, signNewRoot, signCopies, signCheckpoint,
    broadcast, broadcastNewest, broadcastNewest, broadcastNewest, broadcastNewest, deliver,
    compact, compact, syncAll, syncAll, oldRootThief, oldRootThief, oldRootThief, rootRemovesPhone,
    removedAdminThief, removedAdminThief, removedAdminThief, recoveryTwin, signRecover,
    signThaw, signAfterThaw, welcomeNewcomer, signHidden, signCheckpointNaming,
  }

  // Witnesses of a run (quint run --witnesses): how many traces reach these.
  val firstTakeover = MEMBERS.exists(m => views.get(m).path.length() >= 2)
  val secondTakeover = MEMBERS.exists(m => views.get(m).path.length() >= 3)
  val fullStop = MEMBERS.exists(m => chainState(st.get(m), db).stop)
  // A member that compacted on a checkpoint dropped a record below one it kept of the same key.
  val compactedGap = MEMBERS.exists(m => {
    val s = st.get(m)
    s.checkpoint != 0 and recsOf(s.got.exclude(s.recs).exclude(s.chain), db).exists(r =>
      recsOf(s.recs, db).exists(k => k.signer == r.signer and k.seq > r.seq))
  })

  // --- Promises --------------------------------------------------------------------------

  // A member that every record it was offered would leave as it is.
  def saturated(m: str): bool = {
    val s = st.get(m)
    s.got.forall(i => insertInto(s, db.get(i), db).recs == s.recs)
  }

  // 1. One set, one state.
  val oneState = MEMBERS.forall(m => {
    val s = st.get(m)
    saturated(m) implies (s.recs == pureKept(s, db) and views.get(m) == pureView(s, db))
  })

  // 2. A key a root removed stays removed, unless a change of root left the removal off its
  // list.
  pure def cutOff(v: View, r: Record): bool = not(within(v.cuts, r))
  // A gap is liveness, not a rule: an honest peer that holds a line serves it, so a member is
  // checked once it was offered, to no change, every record some member holds.
  def synced(m: str): bool = MEMBERS.forall(n => st.get(n).recs.union(st.get(n).chain).forall(i => {
    val s2 = insertInto(st.get(m), db.get(i), db)
    s2.recs == st.get(m).recs and s2.chain == st.get(m).chain
  }))
  // A removal some earlier change of the member's chain cut off: the sets dropped it then, and
  // a later list that names it again (a recovery key may list what nobody holds) cannot bring
  // it back while no member holds it. Once a member holds it and the newest list names it, it
  // counts.
  def heldByNone(r: Record): bool = MEMBERS.forall(n => not(st.get(n).recs.contains(r.id)))
  def cutEarlier(m: str, r: Record): bool = {
    val ch = chainState(st.get(m), db).recs
    ch.indices().exists(j => not(within(pathCutsOf(ch.slice(0, j + 1))._2, r)))
  }
  val removedStayOut = MEMBERS.forall(m => synced(m) implies {
    val v = views.get(m)
    // Removals by the roots on the member's path (a key that is a root elsewhere, not here,
    // removes nothing).
    val removals = recsOf(st.get(m).got, db).filter(r => r.kind == "revoke" and onList(v.path, r.signer))
    v.stop or gone.get(m).forall(k =>
      removals.filter(r => withPair(r.target).contains(k)).forall(r => cutOff(v, r) or (cutEarlier(m, r) and heldByNone(r)))
        or (v.revoked.contains(k) and not(v.admins.keys().contains(k)) and not(v.devices.contains(k))))
  })

  // 3. Two members that hold the same recovery chain and keep the same records are in one
  // state.
  val oneChainOneState = MEMBERS.forall(m1 => MEMBERS.forall(m2 => {
    val s1 = st.get(m1)
    val s2 = st.get(m2)
    (s1.chain == s2.chain and s1.recs == s2.recs and s1.got == s2.got and saturated(m1) and saturated(m2))
      implies views.get(m1) == views.get(m2)
  }))

  // 5. During a stop only the current root's commands run, and the root's records still
  // count; during a full stop nothing runs.
  val stopRootOnly = MEMBERS.forall(m => {
    val v = views.get(m)
    v.rootsCount and (v.stop implies v.commanders.forall(k => k == last(v.path)))
      and (chainState(st.get(m), db).stop implies v.commanders == Set())
  })

  // 6. No key takes another key's room.
  val fairRoom = MEMBERS.forall(m => {
    val s = st.get(m)
    val rs = recsOf(s.recs, db)
    val got = recsOf(s.got, db)
    val path = keptPath(s, db)
    val cuts = keptCuts(s, db)
    val admins = learned(got, path, cuts)
    val ceil = ceilings(path, admins)
    // Only the roots on the path and the admin keys their records name.
    val legit = rootsOf(path).union(got.filter(r => onList(path, r.signer) and r.kind == "admin").map(r => r.target))
    val owners = got.filter(r => not(isChain(r))).map(r => r.signer).filter(k => ceil.keys().contains(k))
    val fair = if (owners.size() == 0) ROOM else ROOM / owners.size()
    and {
      ceil.keys().forall(k => legit.contains(k)),
      sumUnits(rs) <= ROOM,
      rs.map(r => r.signer).forall(k => ceil.keys().contains(k) and sumUnits(ofKey(rs, k)) <= ceil.get(k)),
      saturated(m) implies owners.forall(k =>
        sumUnits(ofKey(rs, k)) + MAXU - 1 >= min2(fair, min2(ceil.get(k), sumUnits(ofKey(got.filter(r => storable(s, r, db)), k))))),
    }
  })

  // 7. A member follows the recovery chain it holds: its path is the first root and the new
  // roots of that chain, and its replaced roots keep what the chain's records list.
  val followsRecovery = MEMBERS.forall(m => {
    val v = views.get(m)
    val pc = pathCutsOf(chainOf(recsOf(st.get(m).got, db).filter(r => isChain(r))).recs)
    v.path == pc._1 and v.cuts == pc._2
  })

  // 8. A member's path never grows shorter, unless it came to a full stop.
  val pathGrows = MEMBERS.forall(m => isPrefix(before.get(m), views.get(m).path) or chainState(st.get(m), db).stop)

  // 9. A newcomer takes its admitter's chain: the admitter's path is the start of its own.
  val newcomerTakes = isPrefix(welcomed, views.get("m").path) or chainState(st.get("m"), db).stop

  // 10. After a change of root, of each replaced root only what its recovery record listed
  // counts.
  val oldRootListed = MEMBERS.forall(m => {
    val v = views.get(m)
    v.path.indices().forall(i => i + 1 >= v.path.length() or
      recsOf(v.counting, db).filter(r => r.signer == v.path[i]).forall(r => inLine(v.cuts.get(v.path[i]), r.id)))
  })

  // 11. Two recovery records at one seq stop a member that holds both, and once every member
  // holds every recovery record, they all stop or none does.
  val twinStops = and {
    MEMBERS.forall(m => chainState(st.get(m), db).stop implies (views.get(m).stop and views.get(m).commanders == Set())),
    MEMBERS.forall(m => MEMBERS.forall(n => st.get(n).chain.subseteq(st.get(m).chain)))
      implies (MEMBERS.forall(m => views.get(m).stop) or MEMBERS.forall(m => not(chainState(st.get(m), db).stop))),
  }

  // 12. A removed key gains nothing: of a key a counted removal took, a record counts only if
  // every counted removal of it saw the record (or it came before the key's own removal).
  val removedGainsNothing = MEMBERS.forall(m => {
    val v = views.get(m)
    val cnt = recsOf(v.counting, db)
    val removals = cnt.filter(r => r.kind == "revoke")
    cnt.forall(r => removals.filter(rm => withPair(rm.target).contains(r.signer) and rm != r).forall(rm =>
      if (rm.signer == r.signer) r.seq < rm.seq else inLine(lineOf(rm.seen, r.signer), r.id)))
  })

  // 13. After a change of root, two members that hold the same recovery chain, were offered
  // the same records and hold the new root's first checkpoint are in one state, whether or not
  // either compacted on a checkpoint of the replaced root.
  def firstCheckpointHeld(m: str): bool = {
    val s = st.get(m)
    val ch = chainState(s, db)
    ch.recs.length() > 0 and {
      val tip = ch.recs[ch.recs.length() - 1]
      recsOf(s.got, db).exists(r => r.signer == tip.target and r.kind == "checkpoint" and r.seq == max2(tip.targetRec, 1))
    }
  }
  // Compacted on nothing, or on a replaced root's checkpoint (not on the current root's own).
  def notOnCurrent(m: str): bool = {
    val s = st.get(m)
    s.checkpoint == 0 or db.get(s.checkpoint).signer != last(keptPath(s, db))
  }
  val compactedAgree = MEMBERS.forall(m1 => MEMBERS.forall(m2 => {
    val s1 = st.get(m1)
    val s2 = st.get(m2)
    (s1.chain == s2.chain and s1.got == s2.got and not(chainState(s1, db).stop) and firstCheckpointHeld(m1)
      and saturated(m1) and saturated(m2)) implies views.get(m1) == views.get(m2)
  }))
  // 13w, weaker, while the core keeps more after compacting on the current root's checkpoint
  // than before (core/tests/records_model.rs, compacting_on_the_roots_checkpoint_changes_nothing):
  // promise 13 only for members that compacted on a replaced root's checkpoint or not at all.
  val compactedAgreeOldRootOnly = MEMBERS.forall(m1 => MEMBERS.forall(m2 => {
    val s1 = st.get(m1)
    val s2 = st.get(m2)
    (s1.chain == s2.chain and s1.got == s2.got and not(chainState(s1, db).stop) and firstCheckpointHeld(m1)
      and notOnCurrent(m1) and notOnCurrent(m2) and saturated(m1) and saturated(m2)) implies views.get(m1) == views.get(m2)
  }))

  // Promise 13 was tried: two members that agree in what it asks for, one compacted on a
  // replaced root's checkpoint and the other not.
  val agreeTried = MEMBERS.exists(m1 => MEMBERS.exists(m2 => {
    val s1 = st.get(m1)
    val s2 = st.get(m2)
    s1.chain == s2.chain and s1.got == s2.got and firstCheckpointHeld(m1) and s1.checkpoint != 0 and notOnCurrent(m1)
      and s2.checkpoint == 0 and saturated(m1) and saturated(m2)
  }))

  val promises = and {
    oneState, removedStayOut, oneChainOneState, stopRootOnly, fairRoom, followsRecovery, pathGrows, newcomerTakes,
    oldRootListed, twinStops, removedGainsNothing, compactedAgreeOldRootOnly,
  }
  // compactedAgree (promise 13 in full) is checked on its own until the core keeps the same
  // records whether or not a member compacted on the current root's checkpoint.

  // --- Scenarios ---------------------------------------------------------------------------

  action signAs(k: Key, kind: str, target: Key, targetRec: Id): bool =
    sign(k, kind, target, "", targetRec, false, false, if (kind == "checkpoint") 2 else 1)
  // The recovery key's member changes the root to t at the end of its chain.
  action recoverAs(k: Key, t: Key): bool = signChain(k, "recover", t, chainState(st.get("k"), db).ids.length() + 1, "honest")

  // The recovery key changes the root: a member that holds the record follows it at once.
  run recoveryChangesRootTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .expect(views.get("k").path == [ROOT, "NK"])
      .then(give("m", 4))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").cuts == Map(ROOT -> [1, 2, 3])
        and views.get("m").admins.keys() == Set(PHONE, COMPUTER, WATCH) and promises)

  // No root's or admin's record touches the recovery key: removed by the root and frozen by
  // the phone admin, it still changes the root.
  run recoveryUntouchableTest =
    init
      .then(signAs(ROOT, "revoke", RECOVERY, 0))
      .then(signAs(PHONE, "freeze", RECOVERY, 0))
      .then(give("k", 4))
      .then(give("k", 5))
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(views.get("m").path == [ROOT, "NK"] and promises)

  // A recovery record that names a key that was a root before is not valid and changes
  // nothing.
  run oldKeyNotValidTest =
    init
      .then(signChain(RECOVERY, "recover", ROOT, 1, "honest"))
      .then(give("m", 4))
      .expect(views.get("m").path == [ROOT] and not(views.get("m").stop) and promises)

  // A device the root removed does not come back by a new record for its key.
  run removedDeviceStaysOutTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE)
        and gone.get("m").contains(DEVICE) and promises)

  // A removal by an admin is not final: the root's resolve voids it, and the device counts
  // again under its old key. A removal by the root is final: its resolve changes nothing.
  run removalsByAdminAndRootTest =
    init
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(signAs(COMPUTER, "revoke", DEVICE, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE))
      .then(signAs(ROOT, "resolve", "", 5))
      .then(give("m", 6))
      .expect(views.get("m").devices.contains(DEVICE) and not(views.get("m").revoked.contains(DEVICE)))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(give("m", 7))
      .then(signAs(ROOT, "resolve", "", 7))
      .then(give("m", 8))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE) and promises)

  // Two freezes a watch admin signs of its own key do not stop the group.
  run ownKeyFreezesTest =
    init
      .then(sign(WATCH, "freeze", WATCH, "", 0, true, false, 1))
      .then(sign(WATCH, "freeze", WATCH, "", 0, true, false, 1))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(views.get("m").stop) and views.get("m").commanders.contains(PHONE) and promises)

  // A removal of an admin's member key removes its admin key: its later removal, which the
  // root's removal did not see, does not count.
  run bothKeysRemovedTest =
    init
      .then(signAs(ROOT, "revoke", "dA", 0))
      .then(signAs(PHONE, "revoke", COMPUTER, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(views.get("m").revoked.contains(PHONE) and not(views.get("m").admins.keys().contains(PHONE))
        and not(views.get("m").revoked.contains(COMPUTER)) and promises)

  // A thief holding the removed phone admin's key gains nothing: its removals, freezes and
  // devices count nowhere, before or after a change of root.
  run removedAdminThiefTest =
    init
      .then(signAs(ROOT, "revoke", PHONE, 0))
      .then(sign(PHONE, "revoke", COMPUTER, "", 0, true, false, 1))
      .then(sign(PHONE, "freeze", WATCH, "", 0, true, false, 1))
      .then(sign(PHONE, "device", DEVICE, "", 0, true, false, 1))
      .then(give("m", 4)).then(give("m", 5)).then(give("m", 6)).then(give("m", 7))
      .expect(views.get("m").admins.keys() == Set(COMPUTER, WATCH) and not(views.get("m").devices.contains(DEVICE))
        and not(views.get("m").frozen.contains(WATCH)) and promises)
      .then(give("k", 4)).then(give("k", 5)).then(give("k", 6)).then(give("k", 7))
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("m", 8))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").revoked.contains(PHONE)
        and not(views.get("m").devices.contains(DEVICE)) and promises)

  // What the old root resolved stays resolved after a change of root, when the member the
  // recovery key is entered on held it.
  run oldRootResolveStaysTest =
    init
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(signAs(COMPUTER, "revoke", DEVICE, 0))
      .then(give("r", 4))
      .then(give("r", 5))
      .then(signAs(ROOT, "resolve", "", 5))
      .then(give("k", 4))
      .then(give("k", 5))
      .then(give("k", 6))
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").devices.contains(DEVICE) and promises)

  // A thief with the old root key after the change removes a device, names an admin and forks
  // a record: none is on the list, so none counts, and a member keeps none.
  run oldRootThiefTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(give("k", 4))
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").devices.contains(DEVICE))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(sign(ROOT, "admin", MINTED, "phone", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, true, 1))
      .then(give("m", 7))
      .then(give("m", 8))
      .then(give("m", 9))
      .expect(views.get("m").devices.contains(DEVICE) and not(views.get("m").admins.keys().contains(MINTED))
        and st.get("m").recs.intersect(Set(7, 8, 9)) == Set() and promises)

  // A removal by the old root that the recovery key's member did not hold is not on the list:
  // after the change it counts no more, and the device returns (rule 33, point 6, against
  // decision 14: what the list leaves off is gone).
  run unlistedRootRemovalTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(give("k", 4))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(give("c", 4))
      .then(give("c", 5))
      .expect(not(views.get("c").devices.contains(DEVICE)))
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("c", 6))
      .expect(views.get("c").path == [ROOT, "NK"] and views.get("c").devices.contains(DEVICE) and promises)

  // A key a root not yet on the path names teaches nothing: its records are not kept until
  // the recovery record makes that root the root, and what that root signed before the
  // record's from stays out unless listed; what it signs from there counts.
  run mintedKeyTest =
    init
      .then(sign("NA", "admin", MINTED, "computer", 0, false, false, 1))
      .then(signAs(MINTED, "device", DEVICE, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(st.get("m").recs.contains(5)) and not(views.get("m").devices.contains(DEVICE)))
      .then(signChain(RECOVERY, "recover", "NA", 1, "honest"))
      .expect(db.get(6).targetRec == 2)
      .then(give("m", 6))
      .then(give("m", 7))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(views.get("m").path == [ROOT, "NA"] and not(views.get("m").admins.keys().contains(MINTED))
        and not(views.get("m").devices.contains(DEVICE)) and promises)
      .then(give("a", 6))
      .then(give("a", 7))
      .then(sign("NA", "admin", MINTED, "computer", 0, false, false, 1))
      .then(give("m", 8))
      .then(give("m", 5))
      .expect(views.get("m").admins.keys().contains(MINTED) and views.get("m").devices.contains(DEVICE) and promises)

  // The root's checkpoint gives the state on a member that compacted on it.
  run checkpointTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(views.get("m").checkpoint == 5 and views.get("m").devices.contains(DEVICE))
      .then(compactAt("m"))
      .expect(views.get("m").checkpoint == 5 and views.get("m").devices.contains(DEVICE) and promises)

  // The root takes the admin key off A's device: what A signs after, unseen by that record,
  // does not count, and A is no longer an admin.
  run demotedAdminTest =
    init
      .then(signAs(ROOT, "device", "dA", 0))
      .then(signAs(PHONE, "revoke", COMPUTER, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(views.get("m").revoked.contains(COMPUTER))
        and not(views.get("m").admins.keys().contains(PHONE)) and promises)

  // The root names another admin key for C's device: C's later record does not count, C2's does.
  run replacedAdminKeyTest =
    init
      .then(sign(ROOT, "admin", "C2", "computer", 0, false, false, 1))
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").admins.keys().contains("C2")
        and not(views.get("m").admins.keys().contains(COMPUTER)))
      .then(give("c", 4))
      .then(signAs("C2", "device", DEVICE, 0))
      .then(give("m", 6))
      .expect(views.get("m").devices.contains(DEVICE) and promises)

  // A second change of root: the chain's seq 2 names NA under NK, listing what NK signed. A
  // member that holds seq 2 alone follows nothing yet; with seq 1 it follows both.
  run secondChangeTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signAs("NK", "device", DEVICE, 0))
      .then(recoverAs(RECOVERY, "NA"))
      .then(give("m", 6))
      .then(give("m", 7))
      .then(give("m", 8))
      .expect(views.get("m").path == [ROOT] and not(views.get("m").devices.contains(DEVICE)))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 8))
      .expect(views.get("m").path == [ROOT, "NK", "NA"] and views.get("m").cuts == Map(ROOT -> [1, 2, 3, 6], "NK" -> [1, 2, 3, 6])
        and views.get("m").devices.contains(DEVICE) and promises)

  // Two recovery records at one seq: every member that holds both comes to a full stop, and
  // after sync every member does; nothing runs, the root's commands included.
  run recoveryTwinStopsTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "NA", 1, "honest"))
      .then(give("m", 4))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(give("m", 6))
      .expect(views.get("m").stop and views.get("m").commanders == Set())
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).stop and views.get(x).commanders == Set()) and promises)

  // A second record at a seq deep below the tip stops every member for good:
  // after two changes of root, a record at seq 1 names another root.
  run deepTwinStopsTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(recoverAs(RECOVERY, "NA"))
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).path == [ROOT, "NK", "NA"]))
      .then(signChain(RECOVERY, "recover", "NA", 1, "honest"))
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).stop and views.get(x).commanders == Set()) and promises)

  // A thief with the old root key after the change removes the device D; m gets that
  // removal before the recovery record. It still takes the record (brief v2, section 4) and
  // follows the new root, and D counts again there, as no listed removal names it.
  run removedDeviceFollowsTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(syncAll)
      .then(recoverAs(RECOVERY, "NK"))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(give("m", 7))
      .expect(not(views.get("m").devices.contains(DEVICE)))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").devices.contains(DEVICE) and promises)

  // The owner unticks the computer admin: the new root signs its removal in the same act. The
  // root's earlier removal of the watch admin is on the list and stays.
  run untickTest =
    init
      .then(signAs(ROOT, "revoke", WATCH, 0))
      .then(give("k", 4))
      .then(recoverAs(RECOVERY, "NK"))
      .then(signAs("NK", "revoke", COMPUTER, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").admins.keys() == Set(PHONE)
        and views.get("m").revoked.contains(WATCH) and promises)

  // The old root removes the phone admin on its own device, which has not yet got the change
  // to NK; that change does not list the removal. A second head, to NA, lists it again. The
  // old root's device takes both heads at once, keeps the removal (the newest list names it)
  // and has A out; once sync has offered it again, every member has A out.
  run relistedRemovalTest =
    init
      .then(signAs(ROOT, "revoke", PHONE, 0))
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "NA", 2, "all"))
      .expect(not(db.get(5).keep.contains(4)) and db.get(7).keep.contains(4))
      .then(give("r", 7))
      .then(give("r", 5))
      .then(give("r", 6))
      .expect(views.get("r").path == [ROOT, "NK", "NA"] and views.get("r").revoked.contains(PHONE)
        and not(views.get("r").admins.keys().contains(PHONE)) and promises)
      .expect(views.get("m").admins.keys().contains(PHONE))
      // One round of sync in ID order: a member that takes the removal before the first head
      // drops it at that head and takes it again only in the next round.
      .then(syncAll)
      .expect(views.get("k").revoked.contains(PHONE) and promises)
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).path == [ROOT, "NK", "NA"] and views.get(x).revoked.contains(PHONE)
        and not(views.get(x).admins.keys().contains(PHONE))) and promises)

  // Why the list holds what the writer counts of every earlier root: a list of the replaced
  // root's records alone, at the second change, leaves the first root's records off the newest
  // list, which is the whole truth, so the admins the first root named are gone.
  run literalListTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "NA", 2, "literal"))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(views.get("m").path == [ROOT, "NK", "NA"] and views.get("m").admins.keys() == Set() and promises)

  // A fork may be two records of which one is not valid (it names an earlier root): any two
  // records the recovery key signed at one seq stop the member for good.
  run invalidForkStopsTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", ROOT, 1, "honest"))
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).stop and views.get(x).commanders == Set()) and promises)

  // A thaw revives only what it saw of the frozen key; the rest stays cut off.
  run thawTest =
    init
      .then(signAs(PHONE, "freeze", COMPUTER, 0))
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(signAs(ROOT, "thaw", "", 4))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").frozen.contains(COMPUTER)) and not(views.get("m").devices.contains(DEVICE)) and promises)

  // Rule 31: what the thawed key signs after the thaw, listing it in seen, counts.
  run thawedAdminWorksTest =
    init
      .then(signAs(PHONE, "freeze", COMPUTER, 0))
      .then(give("r", 4))
      .then(signAs(ROOT, "thaw", "", 4))
      .then(give("c", 4))
      .then(give("c", 5))
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").frozen.contains(COMPUTER)) and views.get("m").devices.contains(DEVICE) and promises)

  run thawSeenTest =
    init
      .then(signAs(PHONE, "freeze", COMPUTER, 0))
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(give("r", 4))
      .then(give("r", 5))
      .then(signAs(ROOT, "thaw", "", 4))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").frozen.contains(COMPUTER)) and views.get("m").devices.contains(DEVICE) and promises)

  // After a change of root, other keys fill the room and push out some of what the list kept
  // of the old root; the change stays, since the recovery record is outside the rooms.
  run fullRoomAfterChangeTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("m", 4))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(give("m", 5)).then(give("m", 6)).then(give("m", 7)).then(give("m", 8))
      .then(give("m", 9)).then(give("m", 10)).then(give("m", 11)).then(give("m", 12))
      .expect(st.get("m").chain == Set(4) and views.get("m").path == [ROOT, "NK"] and promises)

  // The root keeps back a twin of its newest record and checkpoints naming it. The checkpoint
  // never counts (a named record off its chain), and the twin, handed in after a change of
  // root, counts nothing.
  run hiddenKeepTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signFull(ROOT, "admin", MINTED, "phone", 0, false, true, 1, true, Set()))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set(5)))
      .then(give("m", 4))
      .then(give("m", 6))
      .then(compactAt("m"))
      .expect(views.get("m").checkpoint == 0 and st.get("m").recs.contains(4) and views.get("m").devices.contains(DEVICE))
      .then(give("k", 4))
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("m", 7))
      .then(compactAt("m"))
      .then(give("m", 5))
      .expect(views.get("m").path == [ROOT, "NK"] and not(views.get("m").admins.keys().contains(MINTED))
        and views.get("m").checkpoint == 0 and promises)

  // A newcomer takes the chain from its admitter's Welcome and has its path.
  run newcomerTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signAs("NK", "copies", "", 0))
      .then(recoverAs(RECOVERY, "NA"))
      .then(welcomeFrom("k"))
      .expect(views.get("m").path == [ROOT, "NK", "NA"] and welcomed == [ROOT, "NK", "NA"] and promises)

  // A member that compacted on the replaced root's checkpoint and one that did not end in one
  // state after the change: the new root's first checkpoint, signed with the head, prunes again
  // what the old one pruned (A's removal the root resolved).
  run compactedChangeTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(give("a", 4))
      .then(signAs(PHONE, "revoke", DEVICE, 0))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1))
      .then(give("r", 5))
      .then(give("r", 6))
      .then(signAs(ROOT, "resolve", "", 5))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(give("m", 4)).then(give("m", 5)).then(give("m", 6)).then(give("m", 7)).then(give("m", 8))
      .then(give("c", 4)).then(give("c", 5)).then(give("c", 6)).then(give("c", 7)).then(give("c", 8))
      .then(give("k", 4)).then(give("k", 5)).then(give("k", 6)).then(give("k", 7)).then(give("k", 8))
      .then(compactAt("m"))
      .expect(views.get("m").checkpoint == 8 and not(st.get("m").recs.contains(5)) and st.get("c").recs.contains(5))
      .then(recoverAs(RECOVERY, "NK"))
      .expect(db.get(10).signer == "NK" and db.get(10).kind == "checkpoint" and db.get(10).seq == 1)
      .then(give("m", 9)).then(give("m", 10)).then(give("m", 5))
      .then(give("c", 9)).then(give("c", 10))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m") == views.get("c") and views.get("m").checkpoint == 10
        and views.get("m").devices.contains(DEVICE) and promises)
      .then(compactAt("m"))
      .then(compactAt("c"))
      .expect(st.get("m").recs == st.get("c").recs and views.get("m") == views.get("c") and promises)

  // An admin key named as the root: what it signed as an admin below the head's from counts
  // only if listed; what it signs from there counts as the root's.
  run adminNamedRootTest =
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1))
      .then(give("a", 4))
      .then(signAs("NA", "device", DEVICE, 0))
      .then(give("k", 4))
      .then(give("k", 5))
      .expect(views.get("k").devices.contains(DEVICE) and views.get("k").admins.keys().contains("NA"))
      .then(signChain(RECOVERY, "recover", "NA", 1, "literal"))
      .expect(db.get(6).targetRec == 2)
      .then(give("m", 4)).then(give("m", 5)).then(give("m", 6))
      .expect(views.get("m").path == [ROOT, "NA"] and views.get("m").cuts.get("NA")[0] == -2
        and not(views.get("m").devices.contains(DEVICE)) and promises)
      .then(give("a", 6))
      .then(signAs("NA", "device", DEVICE, 0))
      .then(give("m", 7))
      .expect(views.get("m").devices.contains(DEVICE) and promises)

  // The same with the writer's full list, by hand (the honest writer refuses a known key): the
  // admin record is listed, and counts.
  run adminNamedRootListedTest =
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1))
      .then(give("a", 4))
      .then(signAs("NA", "device", DEVICE, 0))
      .then(give("k", 4))
      .then(give("k", 5))
      .then(recoverAs(RECOVERY, "NA"))
      .then(give("m", 4)).then(give("m", 5)).then(give("m", 6)).then(give("m", 7))
      .expect(views.get("m").path == [ROOT, "NA"] and views.get("m").devices.contains(DEVICE)
        and views.get("m").checkpoint == 7 and promises)

  // The honest writer cannot name a key its state knows: with NA named as an admin, the only
  // change it can make is to NK.
  run honestRefusesKnownKeyTest =
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1))
      .then(give("k", 4))
      .then(signChange)
      .expect(views.get("k").path == [ROOT, "NK"] and promises)
}
