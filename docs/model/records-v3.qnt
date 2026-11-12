// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
//
// A model of the record rules of 0.6 (records v3), in Quint (https://quint-lang.org). It is
// written from the rules as the owner settled them (the design of records v3, its section 7,
// decisions 1 to 22), not from the code's structure, so that it can disagree with the code. It
// lets the simulator try many ways a few devices can sign, sync, wait, compact and drop
// records, checking eight promises:
//
//  1. One set, one state: a member that has been offered a set of records, in whatever order
//     and with whatever it dropped on the way, keeps what a member given the whole set at once
//     keeps (with the same roots promoted, the same checkpoint compacted on, the same claims
//     counted), and evaluates it to the same state.
//  2. A device or admin a root removed never returns: once a root's removal of a key counts on
//     a member, the key (and the other key of its device) stays removed there, whatever comes,
//     unless a takeover cut the removal off (decision 16). A removal by an admin is not final:
//     a root may void it (decision 14).
//  3. One root: two members that keep the same records and counted the same claims have the
//     same root, or one of them is still waiting out a claim the other already counts.
//  4. A claim never counts before the member itself has held it for the takeover delay.
//  5. During a full stop only the current root's commands run, and its records still count.
//  6. No key takes another key's room: every key with room keeps at least its fair share (or
//     all it made, or its ceiling); only the first root, the roots a member promoted and the
//     admin keys those roots name have room; a claimed root keeps at most what its claim paid
//     ahead; the set never holds more than its room.
//  7. A takeover a member counted is never undone, whatever any key signs later: the claims
//     it counted are a list in the order counted, kept apart from the set and never dropped,
//     and the i-th one's new root stays the path's root after the i-th (decisions 17 and 20).
//     A later claim is taken only under the last root, by a key fit for it. A counted claim
//     is checked once, when counted, and what proves it is pinned with it (decision 22); a set
//     keeps by the roots and cuts its counted claims name.
//  8. The path of roots never grows shorter on a member.
//  9. A newcomer takes its admitter's counted claims (decision 21): it checks each in the one
//     epoch of the claim's root, on the path of the counted claims before it, and keeps them.
//
// Who is in it: the group's first root R; a phone admin A (it may take the group over and
// remove admins), a computer admin C (no takeover), a watch admin W (it removes devices and
// freezes admins) and the recovery key K, which only claims; each admin's device has a member
// key too (dA, dC, dW), and a removal or freeze of either key of a device names both
// (decision 2, rule 2). C2 is another admin key for C's device: a root's newer record of a
// device that names another key, or none, takes the old key's powers, and of what the old key
// signed only what that record saw counts (decision 20). A thaw revives only what it saw of
// the frozen key's records; the rest stays cut off. D is a device the admins and roots admit and remove; NA and NK are the
// new roots A and K would name; X is an admin key a claimed root names, a key that anyone with
// an admin key can mint. Any of them may stay silent (a lost root), act as a thief (pretend it
// held none of the other admins' records), or sign a second record at a seq it already used.
// Five members keep a set each: r (R's device), a (A's, with NA and X), c (C's and W's),
// k (K's, with NK) and m, a member that only syncs. A record's place among others of one key
// at one seq comes from a hash of its ID, so a fork may land before or after the record it
// forks, and a member that drops records may leave gaps below a checkpoint.
//
// A record names its chain: its line is the IDs of its key's records from seq 1 up to itself,
// as the prev hash commits to them. What a removal, freeze or claim saw of a key is the line
// of the head it held (decision 19), so "a saw t" means t is on that line. A checkpoint names
// its heads the same way and a list of records it keeps; records at or below a head that are
// neither a head nor kept are pruned by it.
//
// The scale: a record takes one or two units of room, a checkpoint two; a claim takes three
// (one for itself, one for its new key, one paid ahead for its root's records). The set holds
// 14 units, a root key 8, an admin key 5, a claimed root 1 while only its claim names it; the
// takeover delay is two ticks of a member's own count. The format's numbers are 4096, 1024,
// 256 and 16, and a claim 80 units; the rules do not depend on the numbers.
//
// A root may hand the group to an admin key (its claim then needs no delay), keep a record back from every member, and name
// in a checkpoint's keep any record of its own key (audit 2c, Q-1 and Q-6); an admin key may
// use a claimed root's key as a device's key (Q-3); m may start again as a newcomer from any
// member's Welcome.
//
// Left out, since other tests cover them: signatures and the byte form (one record, one ID,
// its units from its body), settings, leaves and watches, two keys with one
// device ID, admin records' later narrowing of a device.
//
// Run it:
//
//	quint test --backend=typescript docs/model/records-v3.qnt
//	quint run --backend=typescript --invariant=promises --max-steps=25 --max-samples=500 docs/model/records-v3.qnt
//
// with --invariant set to oneState, removedStayOut, oneRoot, claimWaits, stopRootOnly,
// fairRoom, countedFinal, pathGrows or newcomerTakes for one promise. The typescript backend takes a few
// traces a second here, so a long run takes many samples and several seeds. Random steps seldom
// reach a second takeover; --step=guided weights the steps towards takeovers one after
// another and compaction, and --witnesses secondTakeover compactedGap counts the traces that
// reach them (with --max-steps=40, about a quarter and a sixth).
module records_v3 {
  type Key = str
  type Id = int
  type Record = {
    id: Id,
    signer: Key,
    seq: int,
    // The IDs of its key's records from seq 1 up to itself.
    line: List[Id],
    // "admin" (a root names target an admin key with the set kit; its device's member key is
    // DEV's), "recovery" (target is the recovery key), "device" (admits or changes the device
    // target), "revoke" (removes target), "freeze" (freezes the admin target), "thaw" (voids
    // the freeze targetRec), "resolve" (voids record targetRec), "claim" (target is the new
    // root), "checkpoint" (heads and keep), "copies" (a record that only takes room).
    kind: str,
    target: Key,
    kit: str,
    targetRec: Id,
    // The line of the head of each key the author held (or says): what a revoke, freeze, thaw,
    // claim or a root's record of an admin's device saw.
    seen: Key -> List[Id],
    // checkpoint: the line of each key's head, and the records it keeps below them.
    heads: Key -> List[Id],
    keep: Set[Id],
    units: int,
  }

  // What a member that drops records remembers of them (core keep::Cut): the level, which only
  // falls, for each key the place of the first record it dropped and the units dropped from
  // there, and for each claimed root the place past its paid-ahead room.
  type Cut = { level: int, marks: Key -> (int, int), future: Key -> int }

  type Store = {
    recs: Set[Id], // the records it keeps
    got: Set[Id], // every record it was offered
    cut: Cut,
    path: List[Key], // the roots its own evaluation put on the path, when it compacted
    cuts: Key -> List[Id], // and how far each earlier root on it counts
    checkpoint: Id, // the checkpoint it compacted on, or 0
    held: Id -> int, // how long it has held each claim, in its own ticks
    // The claims it has counted, in the order it counted them, each kept apart from the set
    // with its signer, its new root and its cut (decisions 17 and 20): never dropped.
    counted: List[Counted],
  }

  type Counted = { id: Id, signer: Key, target: Key, cut: List[Id] }

  type View = {
    path: List[Key],
    counting: Set[Id],
    revoked: Set[Key],
    frozen: Set[Key],
    admins: Key -> str,
    stop: bool,
    claims: Id -> str,
    devices: Set[Key],
    commanders: Set[Key],
    rootsCount: bool, // every whole record of the current root counts
    cuts: Key -> List[Id], // the line up to which each earlier root's records count
    checkpoint: Id, // the checkpoint the state comes from, or 0
  }

  pure val ROOT = "R"
  pure val PHONE = "A"
  pure val COMPUTER = "C"
  pure val WATCH = "W"
  pure val RECOVERY = "K"
  pure val DEVICE = "D"
  pure val MINTED = "X"
  pure val SIGNERS = Set("R", "A", "C", "C2", "W", "K", "NA", "NK", "X")
  pure val ROOT_KEYS = Set("R", "NA", "NK")
  pure val THIEVES = Set("A", "C", "C2", "W", "K", "X")
  pure val HOLDER = Map("R" -> "r", "A" -> "a", "NA" -> "a", "X" -> "a", "C" -> "c", "C2" -> "c", "W" -> "c", "K" -> "k", "NK" -> "k")
  pure val MEMBERS = Set("r", "a", "c", "k", "m")
  // The device (its member key) of each admin key: C2 is a second admin key the root may name
  // for C's device in place of C.
  pure val DEV = Map("A" -> "dA", "C" -> "dC", "C2" -> "dC", "W" -> "dW", "X" -> "dX")
  pure val DEVS = Set("dA", "dC", "dW", "dX")

  pure val ROOM = 14
  pure val ROOTC = 8
  pure val ADMINC = 5
  pure val FUTURE = 1
  pure val CLAIMU = 1 + 1 + FUTURE
  pure val MAXU = CLAIMU
  pure val TOP = ROOTC
  pure val DELAY = 2
  pure val MAXREC = 16
  pure val MAXPATH = 3

  pure val NOCUT: Cut = { level: TOP, marks: Map(), future: Map() }

  // Decided for the design (12.11): a root's removal stands when its key signs a second record
  // at the same seq (true); false is the code at 6386e41, kept to compare until it changes.
  pure val ROOT_REMOVAL_SURVIVES_FORK = true

  // Decided for the design (12.11): in a full root's order, its removals, freezes and resolves
  // before its checkpoints (true); false is the code at 6386e41, where checkpoints push its
  // removals out.
  pure val EARLY_BEFORE_CHECKPOINTS = true

  pure val NONE = 10000000
  // A record's ID as the hash orders it: not the order it was signed in.
  pure def hid(i: Id): int = (i * 7) % 23

  // The powers of the three sets the apps write (decision 13), and the recovery key's.
  pure def powersOf(kit: str): Set[str] =
    if (kit == "phone") Set("admit", "manage", "remove", "freeze", "hub", "removeAdmins", "thaw", "takeover")
    else if (kit == "computer") Set("admit", "manage", "remove", "freeze", "hub")
    else if (kit == "watch") Set("remove", "freeze")
    else if (kit == "recovery") Set("takeover")
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
  // The keys of the device a key belongs to: its member key and every admin key named for it.
  // A removal or freeze of one names them all (decision 2, rule 2).
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
  // a (a revoke, freeze, thaw, claim or a root's device record) saw t: t is on the chain of
  // the head a held of t's key.
  pure def sawIn(a: Record, t: Record, ids: Set[Id], anchors: Set[Id]): bool = onChain(lineOf(a.seen, t.signer), t.id, ids, anchors)
  pure def sawAny(a: Record, k: Key): bool = lineOf(a.seen, k).length() > 0
  // r is on the line the claim saw of r's key, or r's key is not cut (what the line names; a
  // set also needs the chain, onChain).
  pure def within(cuts: Key -> List[Id], r: Record): bool =
    not(cuts.keys().contains(r.signer)) or inLine(cuts.get(r.signer), r.id)
  pure def withinIn(cuts: Key -> List[Id], r: Record, ids: Set[Id], anchors: Set[Id]): bool =
    not(cuts.keys().contains(r.signer)) or onChain(cuts.get(r.signer), r.id, ids, anchors)

  // What a checkpoint keeps as anchors, and which records it prunes.
  pure def anchorsOf(c: Record): Set[Id] =
    c.heads.keys().filter(k => c.heads.get(k).length() > 0).map(k => lastId(c.heads.get(k))).union(c.keep)
  // A checkpoint never prunes a root's removal (a root's removal is final).
  pure def rootRemoval(r: Record): bool = r.kind == "revoke" and ROOT_KEYS.contains(r.signer)
  pure def prunedBy(c: Record, r: Record): bool =
    not(rootRemoval(r)) and c.heads.keys().contains(r.signer) and r.seq <= c.heads.get(r.signer).length() and not(anchorsOf(c).contains(r.id))

  // --- Keeping (rule 6) ------------------------------------------------------------------

  // A record's place in its key's order: by seq, then ID; first the current root's
  // checkpoints, so that a full root can still checkpoint, and any root's removals, freezes
  // and resolves, so that a full set never drops one while it keeps a record of that root
  // (decision 15). Which of the two comes first is open (EARLY_BEFORE_CHECKPOINTS).
  // A key's order of keeping. A root a takeover cut keeps, within the cut, its line from the
  // head the claim saw down to the checkpoint that vouches for the rest, then what that
  // checkpoint names, then the rest of its line downward, never a part in the middle
  // (decision 22); other keys as before.
  type Order = { roots: Set[Key], cuts: Key -> List[Id], anchors: Set[Id] }
  pure def pos(r: Record, cur: Key, ord: Order): int = {
    val cp = r.signer == cur and r.kind == "checkpoint"
    val early = ord.roots.contains(r.signer) and (r.kind == "revoke" or r.kind == "freeze" or r.kind == "resolve")
    // A root's or a claimed root's removal comes first on every set, its own included.
    if (rootRemoval(r)) r.seq * 100 + hid(r.id)
    else if (r.signer != cur and ord.cuts.keys().contains(r.signer)) {
      val l = ord.cuts.get(r.signer)
      // The line from the head the claim saw down to the checkpoint that vouches for the rest
      // comes first: without it nothing below shows; then what that checkpoint names; then
      // the rest of the line, head-down.
      val vouched = l.indices().fold(0, (m, i) => if (ord.anchors.contains(l[i])) max2(m, i + 1) else m)
      val onLine = l.indices().exists(i => l[i] == r.id)
      if (onLine and r.seq > vouched) (l.length() - r.seq) * 100 + hid(r.id)
      else if (ord.anchors.contains(r.id)) 5000 + r.seq * 100 + hid(r.id)
      else if (onLine) 10000 + (l.length() - r.seq) * 100 + hid(r.id)
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
    (cut.marks.keys().contains(r.signer) and pos(r, cur, ord) >= cut.marks.get(r.signer)._1)
      or (cut.future.keys().contains(r.signer) and pos(r, cur, ord) >= cut.future.get(r.signer))

  pure def dropped(cut: Cut, k: Key): int = if (cut.marks.keys().contains(k)) cut.marks.get(k)._2 else 0
  pure def demand(owned: Set[Record], ceil: Key -> int, cut: Cut, s: int): int =
    owned.map(r => r.signer).fold(0, (d, k) =>
      d + min2(s, min2(ceil.get(k), dropped(cut, k) + sumUnits(ofKey(owned, k)))))

  // What a set keeps of items, having dropped before what cut remembers: water-filling to one
  // level for every key with room (ceil), each key's records in its order; a root that only
  // kept claims name keeps what they paid ahead.
  pure def keepAfter(items: Set[Record], ceil: Key -> int, cut: Cut, cur: Key, ord: Order, pins: Set[Key]): (Set[Id], Cut) = {
    val live = items.filter(r => not(past(cut, r, cur, ord)))
    val owned = live.filter(r => ceil.keys().contains(r.signer))
    val claimed = live.filter(r => not(ceil.keys().contains(r.signer)))
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
    val named = keptOwned.filter(r => r.kind == "claim").map(r => r.target).union(pins)
    val inFuture = claimed.filter(r => named.contains(r.signer))
    val keptFuture = inFuture.filter(r => prefix(ofKey(inFuture, r.signer), r, cur, ord) <= FUTURE)
    val over = inFuture.exclude(keptFuture)
    val futureKeys = cut.future.keys().union(over.map(r => r.signer))
    val future = futureKeys.mapBy(h => {
      val o = ofKey(over, h)
      if (o == Set()) cut.future.get(h)
      else if (cut.future.keys().contains(h)) min2(minPos(o, cur, ord), cut.future.get(h))
      else minPos(o, cur, ord)
    })
    (idsOf(keptOwned).union(idsOf(keptFuture)), { level: level, marks: marks, future: future })
  }

  // --- A member's set (the keys it knows, what it stores) --------------------------------

  // The admin keys a member knows: those the first root's and its promoted roots' records name,
  // each root's within its cut. A root that only a claim names teaches no key (rule 6).
  pure def learned(rs: Set[Record], path: List[Key], cuts: Key -> List[Id]): Set[Key] =
    rs.filter(r => onList(path, r.signer) and within(cuts, r) and (r.kind == "admin" or r.kind == "recovery"))
      .map(r => r.target)
  // The roots it knows: those on its path and those the claims of known admin keys name.
  pure def knownRoots(rs: Set[Record], path: List[Key], admins: Set[Key]): Set[Key] =
    path.indices().map(i => path[i]).union(rs.filter(r => r.kind == "claim" and admins.contains(r.signer)).map(r => r.target))

  // The ceilings: the first root's and a promoted root's, an admin key's; a claimed root has
  // none of its own (decision 10).
  pure def ceilings(path: List[Key], admins: Set[Key]): Key -> int =
    SIGNERS.filter(k => onList(path, k) or admins.contains(k)).mapBy(k => if (onList(path, k)) ROOTC else ADMINC)

  pure def rootsOf(path: List[Key]): Set[Key] = path.indices().map(i => path[i])

  // Whether a set stores r at all: its signer is known, it is within its root's cut (an old
  // root keeps nothing above it), and the checkpoint the set compacted on does not prune it.
  pure def storable(s: Store, r: Record, db: Id -> Record): bool = {
    val got = recsOf(s.got, db)
    val admins = learned(got, keptPath(s), keptCuts(s))
    (admins.contains(r.signer) or knownRoots(got, keptPath(s), admins).contains(r.signer))
      and within(keptCuts(s), r)
      and (s.checkpoint == 0 or not(prunedBy(db.get(s.checkpoint), r)))
  }

  // The path and cuts a set keeps by: those it compacted on, carried on by the claims it counted
  // since (each counted claim names its new root and how far the root before it counts).
  pure def keptPath(s: Store): List[Key] =
    if (s.counted.length() + 1 <= s.path.length()) s.path
    else s.counted.foldl([ROOT], (l, c) => l.append(c.target))
  pure def keptCuts(s: Store): Key -> List[Id] =
    s.counted.indices().fold(s.cuts, (m, i) => {
      val k = if (i == 0) ROOT else s.counted[i - 1].target
      if (m.keys().contains(k)) m else m.put(k, s.counted[i].cut)
    })
  pure def orderOf(s: Store, db: Id -> Record): Order =
    { roots: rootsOf(keptPath(s)), cuts: keptCuts(s), anchors: storeAnchors(s, db) }
  pure def countedIds(s: Store): Set[Id] = s.counted.indices().map(i => s.counted[i].id)
  pure def countedRoots(s: Store): Set[Key] = s.counted.indices().map(i => s.counted[i].target)
  pure def storeAnchors(s: Store, db: Id -> Record): Set[Id] = if (s.checkpoint == 0) Set() else anchorsOf(db.get(s.checkpoint))
  // A root a takeover cut has its line fixed by hashes, from the head the claim saw down. The
  // newest checkpoint on that line that the set holds vouches by ID for what its keep names,
  // compacted on or not; a twin off the line is no part of it.
  pure def lineAnchors(s: Store, items: Set[Record]): Set[Id] = {
    val cuts = keptCuts(s)
    cuts.keys().fold(Set(), (acc, k) => {
      val cs = items.filter(r => r.signer == k and r.kind == "checkpoint" and inLine(cuts.get(k), r.id))
      val newest = cs.filter(c => cs.forall(o => o == c or c.seq > o.seq))
      newest.fold(acc, (a, c) => a.union(anchorsOf(c)))
    })
  }

  // What a set keeps of items: the counted claims apart from any room; of the rest what the
  // rooms keep; then, of a root a takeover cut, only what its chain shows (down from the head
  // the claim saw, through records held or named by the checkpoint).
  pure def settle(s: Store, items: Set[Record], cut: Cut, db: Id -> Record): (Set[Id], Cut) = {
    val path = keptPath(s)
    val cuts = keptCuts(s)
    val admins = learned(recsOf(s.got, db), path, cuts)
    val pinned = items.filter(r => countedIds(s).contains(r.id))
    val anchors = storeAnchors(s, db).union(lineAnchors(s, items))
    // A cut root's record below a record of its chain the set lacks takes no room (decision 22:
    // head-down, never past a gap).
    val shown = items.filter(r => withinIn(cuts, r, idsOf(items), anchors))
    val res = keepAfter(shown.exclude(pinned), ceilings(path, admins), cut, last(path), { ...orderOf(s, db), anchors: anchors }, countedRoots(s))
    val k0 = res._1.union(idsOf(pinned))
    val k1 = k0.filter(i => withinIn(cuts, db.get(i), k0, anchors))
    val k2 = k1.filter(i => withinIn(cuts, db.get(i), k1, anchors))
    (k2, res._2)
  }

  // Drops what the set does not keep.
  pure def recut(s: Store, db: Id -> Record): Store = {
    val res = settle(s, recsOf(s.recs, db), s.cut, db)
    { ...s, recs: res._1, cut: res._2 }
  }

  // A record offered to the set: stored when the set may store it and its key dropped nothing
  // before it, then the set cuts back.
  pure def insertInto(s0: Store, r: Record, db: Id -> Record): Store = {
    val s = { ...s0, got: s0.got.union(Set(r.id)) }
    val pinned = countedIds(s).contains(r.id)
    if (s.recs.contains(r.id) or (past(s.cut, r, last(keptPath(s)), orderOf(s, db)) and not(pinned)) or not(storable(s, r, db))) s
    else recut({ ...s, recs: s.recs.union(Set(r.id)) }, db)
  }

  // Compaction: the set takes the path its state found (giving its roots a root's room) and
  // drops what the state's checkpoint prunes.
  pure def compactStore(s: Store, v: View, db: Id -> Record): Store =
    if (v.path == s.path and v.cuts == s.cuts and v.checkpoint == s.checkpoint) s
    else {
      val s2 = { ...s, path: v.path, cuts: v.cuts, checkpoint: v.checkpoint, cut: NOCUT }
      val keep = s2.recs.filter(i => storable(s2, db.get(i), db))
      recut({ ...s2, recs: keep }, db)
    }

  // --- Evaluation --------------------------------------------------------------------------

  type Epoch = { view: View, next: Key, cut: List[Id] }

  pure val NOVIEW: View = {
    path: [], counting: Set(), revoked: Set(), frozen: Set(), admins: Map(), stop: false, claims: Map(),
    devices: Set(), commanders: Set(), rootsCount: true, cuts: Map(), checkpoint: 0,
  }

  // The evaluation under one path of roots, with the anchors of the checkpoint it prunes by.
  pure def epoch(rs: Set[Record], held: Id -> int, path: List[Key], cuts: Key -> List[Id], anchors: Set[Id]): Epoch = {
    val cur = last(path)
    val adminKeys = learned(rs, path, cuts)
    val ids = idsOf(rs)
    pure def saw(a: Record, t: Record): bool = sawIn(a, t, ids, anchors)
    pure def isAdmin(r: Record): bool = adminKeys.contains(r.signer) and not(onList(path, r.signer))
    pure def onPath(r: Record): bool = not(isAdmin(r)) and onList(path, r.signer) and withinIn(cuts, r, ids, anchors)
    // A root's removal, freeze or resolve counts by itself, without the records below it
    // (decision 15); it makes nothing above it whole.
    pure def early(r: Record): bool = onPath(r) and (r.kind == "revoke" or r.kind == "freeze" or r.kind == "resolve")
    // A whole chain: every record of its line is here, or down to an anchor.
    pure def whole(r: Record): bool = {
      val top = r.line.indices().fold(-1, (m, j) => if (anchors.contains(r.line[j])) j else m)
      early(r) or r.line.indices().forall(i => i <= top or ids.contains(r.line[i]))
    }
    // The resolves of every root on the path, each up to its cut; a root's removal is final.
    val voids = rs.filter(r => onPath(r) and r.kind == "resolve" and whole(r)).map(r => r.targetRec)
      .filter(i => not(rs.exists(x => x.id == i and x.kind == "revoke" and onList(path, x.signer) and not(isAdmin(x)))))
    // Two histories: a key with two live whole records at one seq counts nothing from that seq
    // on. A record is dead when its line holds a voided record that has a twin: a root's
    // resolve picks a branch.
    val wholes = rs.filter(r => whole(r) and withinIn(cuts, r, ids, anchors))
    val deadIds = voids.filter(i => rs.exists(x => x.id == i and rs.exists(o => o != x and o.signer == x.signer and o.seq == x.seq)))
    val lives = wholes.filter(r => not(r.line.indices().exists(j => deadIds.contains(r.line[j]))))
    val forkSeq = SIGNERS.mapBy(k => lives.filter(r => r.signer == k
      and lives.exists(o => o != r and o.signer == k and o.seq == r.seq)).fold(NONE, (m, r) => min2(m, r.seq)))
    pure def forkAt(k: Key): int = getOr(forkSeq, k, NONE)
    val forks = SIGNERS.filter(k => forkAt(k) < NONE)
    // With ROOT_REMOVAL_SURVIVES_FORK, a root's removal, freeze or resolve counts even at or
    // above a seq where its key has two histories (decision 14: a root's removal is final).
    pure def belowFork(r: Record): bool = r.seq < forkAt(r.signer) or (ROOT_REMOVAL_SURVIVES_FORK and early(r))
    pure def counted(r: Record): bool =
      lives.contains(r) and not(voids.contains(r.id)) and belowFork(r)
    pure def rootRec(r: Record): bool = onPath(r) and counted(r)
    pure def newer(a: Record, b: Record): bool = {
      val pa = indexOf(path, a.signer)
      val pb = indexOf(path, b.signer)
      pa > pb or (pa == pb and a.seq > b.seq)
    }
    // The admin keys, each with the set of the newest root record that names it; the recovery
    // key with takeover only. These are the powers its records were signed with; whether a key
    // is its device's admin key now is current().
    val adminRecs = rs.filter(r => r.kind == "admin" and rootRec(r))
    val named = adminRecs.map(r => r.target)
    val setOf = named.mapBy(a => {
      val mine = adminRecs.filter(r => r.target == a)
      mine.filter(r => mine.forall(o => o == r or newer(r, o))).fold("", (s, r) => r.kit)
    })
    val recoveries = rs.filter(r => r.kind == "recovery" and rootRec(r))
    val recovery = recoveries.filter(r => recoveries.forall(o => o == r or newer(r, o))).map(r => r.target)
    val adm = named.union(recovery).mapBy(a => if (named.contains(a)) setOf.get(a) else "recovery")
    pure def has(a: Key, p: str): bool = adm.keys().contains(a) and powersOf(adm.get(a)).contains(p)
    pure def isAdminKey(k: Key): bool = withPair(k).exists(x => adm.keys().contains(x))
    val claimRoots = rs.filter(r => r.kind == "claim" and isAdmin(r)).map(r => r.target)
    pure def isRootKey(k: Key): bool = onList(path, k) or claimRoots.contains(k)
    pure def rootHas(d: Key): bool = rs.exists(r => devOf(r) == d and rootRec(r))
    // An admin key acts only by its device's newest root record (decision 20): a newer root
    // record of the device that names no admin key, or another one, replaces it, and works as a
    // removal of the old key: what it signed and the replacing record saw counts, the rest not.
    pure def about(d: Key): Set[Record] = rs.filter(r => devOf(r) == d and rootRec(r))
    pure def replacers(k: Key): Set[Record] =
      if (not(DEV.keys().contains(k))) Set()
      else {
        val naming = adminRecs.filter(r => r.target == k)
        about(DEV.get(k)).filter(r => not(r.kind == "admin" and r.target == k) and naming.forall(n => newer(r, n)))
      }
    pure def current(k: Key): bool = adm.keys().contains(k) and replacers(k) == Set()
    // The admin record that admits a device no root recorded: each admin's first, the
    // smallest ID (the records of the model for one device are alike).
    pure def admittedBy(d: Key): Id = {
      val ok = rs.filter(r => r.kind == "device" and r.target == d and isAdmin(r) and counted(r) and has(r.signer, "admit"))
      val firsts = ok.filter(r => not(ok.exists(o => o.signer == r.signer and o.seq < r.seq)))
      if (rootHas(d)) -1 else firsts.fold(NONE, (m, r) => min2(m, r.id))
    }
    // What an admin's record may do (rules 3, decisions 13 and 18).
    pure def permitted(r: Record): bool =
      if (not(adm.keys().contains(r.signer))) false
      else if (adm.get(r.signer) == "recovery" and r.kind != "claim") false
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
          and (withPair(r.target).exists(t => recovery.contains(t)) implies has(r.signer, "removeAdmins"))
      else if (r.kind == "thaw") has(r.signer, "thaw") and has(r.signer, "removeAdmins")
      else if (r.kind == "claim") has(r.signer, "takeover") and sawAny(r, cur)
      else if (r.kind == "copies") true
      else false
    // a, a removal or freeze, cuts off b: it names a key of b's signer's device and did not
    // see b; of its own signer's key, it cuts off only what that key signs after it. A thaw of
    // a freeze leaves cut off what the freeze cut off and the thaw did not see (decision 20 (c)).
    pure def cutsOffRm(a: Record, b: Record): bool =
      (a.kind == "revoke" or a.kind == "freeze") and a != b and withPair(a.target).contains(b.signer)
        and (if (a.signer == b.signer) b.seq > a.seq else not(saw(a, b)))
    pure def cutsOff(a: Record, b: Record): bool =
      if (a.kind == "thaw") rs.exists(f => f.id == a.targetRec and f.kind == "freeze" and cutsOffRm(f, b)) and not(saw(a, b))
      else cutsOffRm(a, b)
    val rootThawed = rs.filter(r => r.kind == "thaw" and rootRec(r)).map(r => r.targetRec)
    val rootActs = rs.filter(r => rootRec(r)
      and (r.kind == "revoke" or r.kind == "thaw" or (r.kind == "freeze" and not(rootThawed.contains(r.id)))))
    val toLabel = rs.filter(r => isAdmin(r) and counted(r))
    val outFirst = toLabel.filter(b => not(permitted(b)) or (b.kind == "freeze" and rootThawed.contains(b.id))
      or rootActs.exists(a => cutsOff(a, b)) or replacers(b.signer).exists(a => not(saw(a, b)))
      // An admin's record that uses a claimed root's key, which the claim did not see, does not
      // count itself.
      or ((b.kind == "device" or b.kind == "admin") and rs.exists(c => c.kind == "claim" and c != b
        and withPair(b.target).contains(c.target) and not(saw(c, b)))))
    pure def attackers(b: Record): Set[Record] =
      if (b.kind == "claim") Set()
      else toLabel.filter(a => not(outFirst.contains(a))
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
    pure def rootFrozen(k: Key): bool = rootActs.exists(a => a.kind == "freeze" and withPair(a.target).contains(k))
    val currentAdmins = adm.keys().filter(a => current(a) and not(revoked.contains(a)))
    // The claims under this root.
    // A removal that saw the new root's records disputes nothing (decision 20).
    pure def sawNewRoot(r: Record, c: Record): bool = lineOf(r.seen, c.target).length() > 0
    // A root's removal of the claimant, or its record of the claimant's device that takes the
    // claimant's admin key (a demotion, or another key), cancels a claim it saw (decision 20).
    pure def cancelled(c: Record): bool = rs.exists(r => r.signer == cur and rootRec(r)
      and ((r.kind == "resolve" and r.targetRec == c.id)
        or (r.kind == "revoke" and withPair(r.target).contains(c.signer) and saw(r, c) and not(sawNewRoot(r, c)))
        or (replacers(c.signer).contains(r) and saw(r, c))))
    // A claim is void by its new key's use only for a use the claim saw or a root on the path
    // signed: a record signed by that key, or one that names it as a device's key.
    pure def usesKey(r: Record, k: Key): bool =
      r.signer == k or ((r.kind == "device" or r.kind == "admin") and withPair(r.target).contains(k))
    pure def voidRoot(c: Record): bool =
      c.target == c.signer or onList(path, c.target)
        or rs.exists(r => r != c and usesKey(r, c.target) and (saw(c, r) or rootRec(r)))
    val here = rs.filter(c => c.kind == "claim" and isAdmin(c) and sawAny(c, cur) and (counted(c) or voids.contains(c.id)))
    val voided = here.filter(c => voidRoot(c) or (not(cancelled(c)) and labels._2.contains(c)))
    val cancels = here.filter(c => not(voidRoot(c)) and cancelled(c))
    val live = here.exclude(voided).exclude(cancels)
    val again = live.filter(c => live.exists(o => o.signer == c.signer and (o.seq < c.seq or (o.seq == c.seq and o.id < c.id))))
    val one = live.exclude(again)
    // An admin's removal or freeze of the claimant: seen by the claim, it voids it; unseen, it
    // disputes it.
    pure def removalsOf(k: Key): Set[Record] =
      rs.filter(r => (r.kind == "revoke" or r.kind == "freeze") and isAdmin(r) and ins.contains(r) and withPair(r.target).contains(k))
    val seenRemoved = one.filter(c => removalsOf(c.signer).exists(rm => saw(c, rm)))
    val kept = one.exclude(seenRemoved)
    val later = kept.filter(c => kept.exists(o => o != c and saw(c, o)))
    val first = kept.exclude(later)
    pure def disputed(c: Record): bool = removalsOf(c.signer).exists(rm => not(saw(c, rm)) and not(sawNewRoot(rm, c)))
    pure def heldOf(c: Record): int = if (held.keys().contains(c.id)) held.get(c.id) else 0
    val voidIds = idsOf(voided.union(again).union(seenRemoved).union(later))
    val competing = first.size() > 1
    val alone = if (first.size() == 1) first else Set()
    val disputes = alone.filter(c => disputed(c))
    // A handover: the current root's newest one names an admin key whose claim, made after it
    // held the handover, takes effect without the delay.
    val handovers = rs.filter(r => r.kind == "handover" and r.signer == cur and rootRec(r))
    val hand = handovers.filter(h => handovers.forall(o => o == h or h.seq > o.seq or (h.seq == o.seq and h.id < o.id)))
    pure def delayOf(c: Record): int = if (hand.exists(h => h.target == c.signer and saw(c, h))) 0 else DELAY
    // A claim is taken only when the root's line walks from the head its seen names down to an
    // anchor (the first record, a checkpoint's anchor, or a held checkpoint whose keep is all
    // held) through records held; else it waits.
    pure def walkable(c: Record): bool = {
      val l = lineOf(c.seen, cur)
      l.indices().exists(j => (j == 0 or anchors.contains(l[j]) or rs.exists(x => x.id == l[j] and x.kind == "checkpoint" and x.keep.forall(i => ids.contains(i))))
        and l.indices().forall(i => i < j or ids.contains(l[i]) or anchors.contains(l[i])))
    }
    val ready = alone.filter(c => not(disputed(c)) and ins.contains(c) and not(rootFrozen(c.signer)) and heldOf(c) >= delayOf(c)
      and walkable(c))
    val full = path.length() >= MAXPATH
    val effective = if (full) Set() else ready
    val claims = idsOf(here).mapBy(i =>
      if (voidIds.contains(i) or (full and idsOf(ready).contains(i))) "void"
      else if (idsOf(cancels).contains(i)) "cancelled"
      else if (competing) "competing"
      else if (idsOf(disputes).contains(i)) "disputed"
      else if (idsOf(effective).contains(i)) "effective"
      else "pending")
    val stop = adminConflict or competing or disputes != Set()
    val devices = rs.filter(r => counts(r) and devOf(r) != "").map(r => devOf(r)).exclude(revoked)
    {
      view: {
        path: path,
        counting: idsOf(rs.filter(r => counts(r))).union(idsOf(effective)),
        revoked: revoked,
        frozen: frozen,
        admins: currentAdmins.mapBy(a => adm.get(a)),
        stop: stop,
        claims: claims,
        devices: devices,
        commanders: currentAdmins.union(Set(cur)).filter(k => not(revoked.contains(k)) and not(frozen.contains(k))
          and not(forks.contains(k)) and (k == cur or not(stop))),
        rootsCount: rs.filter(r => onPath(r) and r.signer == cur and counted(r)).forall(r => counts(r)),
        cuts: cuts,
        checkpoint: 0,
      },
      next: effective.fold("", (k, c) => c.target),
      cut: effective.fold([], (n, c) => lineOf(c.seen, cur)),
    }
  }

  // One step along the path. The member's counted claims are a list in the order it counted
  // them (decision 20): the next one on the list is final under the current root (decision
  // 17), checked still (its signer had the power to take over, its new key is fit), taken
  // from what the member kept of it (its signer, new root and cut) without its record: the cut
  // applies from the start of the epoch and the epoch's other claims are left out. Past the
  // list, the epoch decides, and a new claim is taken only under the last root.
  pure def advance(rs: Set[Record], held: Id -> int, counted: List[Counted], path: List[Key], cuts: Key -> List[Id], anchors: Set[Id]): Epoch = {
    val d = path.length() - 1
    val cur = last(path)
    val ids = idsOf(rs)
    if (d < counted.length() and path.length() < MAXPATH) {
      // Checked once, when counted (decision 22): what proves it is pinned with it.
      val e = counted[d]
      { view: { ...NOVIEW, path: path, claims: Map(e.id -> "effective"), counting: Set(e.id) }, next: e.target, cut: e.cut }
    } else epoch(rs, held, path, cuts, anchors)
  }

  pure val NONEREC: Record = {
    id: 0, signer: "", seq: 0, line: [], kind: "", target: "", kit: "", targetRec: 0, seen: Map(), heads: Map(), keep: Set(), units: 0,
  }

  pure def merge(a: Id -> str, b: Id -> str): Id -> str =
    a.keys().union(b.keys()).mapBy(i => if (b.keys().contains(i)) b.get(i) else a.get(i))

  // Turns records into the group's state: an epoch for each root on the path, the claims of
  // the earlier roots kept.
  pure def evaluate(rs: Set[Record], held: Id -> int, counted: List[Counted], anchors: Set[Id]): View = {
    val e1 = advance(rs, held, counted, [ROOT], Map(), anchors)
    if (e1.next == "") e1.view
    else {
      val p2 = [ROOT, e1.next]
      val c2 = Map(ROOT -> e1.cut)
      val e2 = advance(rs, held, counted, p2, c2, anchors)
      val v2 = { ...e2.view, claims: merge(e1.view.claims, e2.view.claims), counting: e1.view.counting.union(e2.view.counting) }
      if (e2.next == "") v2
      else {
        val e3 = advance(rs, held, counted, p2.append(e2.next), c2.put(e1.next, e2.cut), anchors)
        { ...e3.view, claims: merge(v2.claims, e3.view.claims), counting: v2.counting.union(e3.view.counting) }
      }
    }
  }

  // The newest checkpoint of a root on the path, within its cut: the highest seq, then the
  // smallest ID; 0 when it has none.
  pure def newestCheckpoint(rs: Set[Record], v: View, k: Key): Id = {
    val cs = rs.filter(r => r.signer == k and r.kind == "checkpoint" and within(v.cuts, r))
    cs.filter(c => cs.forall(o => o == c or c.seq > o.seq or (c.seq == o.seq and c.id < o.id))).fold(0, (m, c) => c.id)
  }

  // The state with the checkpoint c tried, or fallback when c is 0 or does not count in the
  // set it prunes.
  // One root's checkpoint applied on what the ones before it left: it counts when it still
  // counts in the set it prunes; then that pruned set goes on.
  pure def applyCheckpoint(held: Id -> int, counted: List[Counted], c: Id,
      acc: (Set[Record], Set[Id], View)): (Set[Record], Set[Id], View) =
    if (c == 0) acc
    else {
      val cp = acc._1.filter(r => r.id == c).fold(NONEREC, (a, r) => r)
      val pruned = acc._1.filter(r => not(prunedBy(cp, r)))
      val anchors = acc._2.union(anchorsOf(cp))
      val v = evaluate(pruned, held, counted, anchors)
      // It counts only on a set that holds every record its keep names, each on its key's
      // chain up to the checkpoint's head of that key (audit 2c, Q-1): no ID in keep stands for
      // a record nobody saw, and two named twins are a fork before anything is pruned.
      val ids = idsOf(acc._1)
      val whole = cp.keep.forall(i => ids.contains(i) and {
        val r = acc._1.filter(x => x.id == i).fold(NONEREC, (a, x) => x)
        not(cp.heads.keys().contains(r.signer)) or r.seq > cp.heads.get(r.signer).length()
          or inLine(cp.heads.get(r.signer), i)
      })
      if (cp != NONEREC and whole and v.counting.contains(c)) (pruned, anchors, { ...v, checkpoint: c }) else acc
    }

  // The state: the path roots' newest checkpoints within their cuts apply in the path's
  // order, each on what the ones before it pruned (decision 22, rule 12).
  pure def fullEvaluate(rs: Set[Record], held: Id -> int, counted: List[Counted]): View = {
    val plain = evaluate(rs, held, counted, Set())
    val p = plain.path
    val a0 = (rs, Set(), { ...plain, checkpoint: 0 })
    val a1 = applyCheckpoint(held, counted, newestCheckpoint(rs, plain, p[0]), a0)
    val a2 = if (p.length() > 1) applyCheckpoint(held, counted, newestCheckpoint(a1._1, plain, p[1]), a1) else a1
    val a3 = if (p.length() > 2) applyCheckpoint(held, counted, newestCheckpoint(a2._1, plain, p[2]), a2) else a2
    a3._3
  }

  // A member's state: its set evaluated (the evaluation keeps again what the set holds).
  pure def storeView(s: Store, db: Id -> Record): View =
    fullEvaluate(recsOf(settle(s, recsOf(s.recs, db), NOCUT, db)._1, db), s.held, s.counted)

  // What a member given every record of got at once keeps, and its state.
  pure def pureKept(s: Store, db: Id -> Record): Set[Id] =
    settle(s, recsOf(s.got, db).filter(r => storable(s, r, db)), NOCUT, db)._1
  pure def pureView(s: Store, db: Id -> Record): View = fullEvaluate(recsOf(pureKept(s, db), db), s.held, s.counted)

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
  // The new roots of the counted claims the newcomer m took from its admitter's Welcome:
  // history for promise 9.
  var welcomed: List[Key]

  pure val NOCOUNTED: List[Counted] = []
  pure val EMPTY: Store = {
    recs: Set(), got: Set(), cut: NOCUT, path: [ROOT], cuts: Map(), checkpoint: 0, held: Map(), counted: [],
  }

  pure def rootRemoved(v: View, db: Id -> Record): Set[Key] =
    recsOf(v.counting, db).filter(r => r.kind == "revoke" and onList(v.path, r.signer))
      .fold(Set(), (s, r) => s.union(withPair(r.target)))

  // A set and the claims its state counts: those that put the path's roots past the counted
  // ones there, appended in the path's order.
  pure def withCounted(s2: Store, db2: Id -> Record): (Store, View) = {
    val v2 = storeView(s2, db2)
    val add = range(0, v2.path.length()).foldl(NOCOUNTED, (l, i) =>
      if (i == 0 or i <= s2.counted.length()) l
      else {
        val cs = v2.claims.keys().filter(c => v2.claims.get(c) == "effective" and db2.get(c).target == v2.path[i])
        cs.fold(l, (l2, c) => l2.append({ id: c, signer: db2.get(c).signer, target: v2.path[i], cut: lineOf(db2.get(c).seen, v2.path[i - 1]) }))
      })
    if (add.length() == 0) (s2, v2)
    else {
      // Its new roots get a root's room: like compaction, the set forgets the cut it kept by
      // the old path and asks again for what it dropped.
      val s3 = recut({ ...s2, counted: s2.counted.concat(add), cut: NOCUT }, db2)
      (s3, storeView(s3, db2))
    }
  }

  // Member m's set becomes s2; the claims its state counts it remembers as counted.
  action commit(db2: Id -> Record, n2: int, m: str, s2: Store): bool = {
    val sv = withCounted(s2, db2)
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

  pure def rec(id: Id, signer: Key, line: List[Id], kind: str, target: Key, kit: str, targetRec: Id,
      seen: Key -> List[Id], heads: Key -> List[Id], keep: Set[Id], units: int): Record =
    { id: id, signer: signer, seq: line.length(), line: line, kind: kind, target: target, kit: kit, targetRec: targetRec,
      seen: seen, heads: heads, keep: keep, units: units }

  // The group as the root made it: A a phone admin, C a computer admin, W a watch admin, K the
  // recovery key.
  pure val START: Id -> Record = Map(
    1 -> rec(1, ROOT, [1], "admin", PHONE, "phone", 0, Map(), Map(), Set(), 1),
    2 -> rec(2, ROOT, [1, 2], "admin", COMPUTER, "computer", 0, Map(), Map(), Set(), 1),
    3 -> rec(3, ROOT, [1, 2, 3], "admin", WATCH, "watch", 0, Map(), Map(), Set(), 1),
    4 -> rec(4, ROOT, [1, 2, 3, 4], "recovery", RECOVERY, "", 0, Map(), Map(), Set(), 1),
  )
  pure def offerAll(s: Store, l: List[Id], db: Id -> Record): Store = l.foldl(s, (x, i) => insertInto(x, db.get(i), db))
  pure val STARTSTORE: Store = offerAll(EMPTY, [1, 2, 3, 4], START)

  action init = all {
    db' = START,
    nextId' = 5,
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
      if (isCp) seen else Map(), if (isCp) views.get(h).counting.filter(i => db.get(i).kind != "checkpoint").union(extraKeep) else Set(), units)
    val db2 = db.put(nextId, r)
    all {
      nextId <= 4 + MAXREC,
      not(fork) or own.length() > 0,
      commit(db2, nextId + 1, h, if (hidden) s else insertInto(s, r, db2)),
    }
  }

  action signDevice = nondet k = Set(ROOT, PHONE, COMPUTER, "NA", "NK", MINTED).oneOf() nondet f = Set(true, false).oneOf()
    sign(k, "device", DEVICE, "", 0, false, f, 1)
  // A root (or a thief, or a claimed root) names an admin; a root may name again one it removed.
  action signAdmin = nondet k = Set(ROOT, PHONE, "NA", "NK").oneOf() nondet a = Set(PHONE, COMPUTER, "C2", WATCH, MINTED).oneOf()
    nondet kit = Set("phone", "computer", "watch").oneOf() sign(k, "admin", a, kit, 0, false, false, 1)
  // A root takes the admin key off a device: a device record about it, with no admin key.
  action signDemote = nondet k = ROOT_KEYS.oneOf() nondet d = Set("dA", "dC", "dW").oneOf()
    sign(k, "device", d, "", 0, false, false, 1)
  action signRevoke = nondet k = SIGNERS.oneOf() nondet t = Set(PHONE, "dA", COMPUTER, WATCH, RECOVERY, DEVICE, MINTED).oneOf()
    nondet p = Set(true, false).oneOf() sign(k, "revoke", t, "", 0, p, false, 1)
  action signFreeze = nondet k = Set(ROOT, PHONE, COMPUTER, WATCH, "NA").oneOf() nondet t = Set(COMPUTER, WATCH, RECOVERY, "dW", PHONE).oneOf()
    nondet p = Set(true, false).oneOf() sign(k, "freeze", t, "", 0, p, false, 1)
  action signThaw = nondet k = Set(ROOT, PHONE, "NA").oneOf() nondet i = db.keys().oneOf() all {
    db.get(i).kind == "freeze",
    sign(k, "thaw", "", "", i, false, false, 1),
  }
  // A root voids a record: a claim, an admin's removal, or any other.
  action signResolve = nondet k = Set(ROOT, "NA", "NK").oneOf() nondet i = db.keys().oneOf() nondet f = Set(true, false).oneOf()
    sign(k, "resolve", "", "", i, false, f, 1)
  action signClaim = nondet k = Set(PHONE, COMPUTER, WATCH, RECOVERY, MINTED).oneOf() nondet t = Set("NA", "NK", MINTED, COMPUTER).oneOf()
    nondet p = Set(true, false).oneOf() sign(k, "claim", t, "", 0, p, false, CLAIMU)
  action signCheckpoint = nondet k = Set(ROOT, "NA", "NK").oneOf() sign(k, "checkpoint", "", "", 0, false, false, 2)
  // Q-1's way: a root's record kept back from every member (a twin of its newest record, or
  // the next one), and a root's checkpoint whose keep names any record of its key, held or not.
  action signHidden = nondet k = ROOT_KEYS.oneOf() nondet f = Set(true, false).oneOf()
    nondet kind = Set("admin", "revoke").oneOf() nondet t = Set(MINTED, PHONE, COMPUTER).oneOf()
    signFull(k, kind, t, "phone", 0, false, f, 1, true, Set())
  action signCheckpointNaming = nondet k = ROOT_KEYS.oneOf() nondet i = db.keys().oneOf() all {
    db.get(i).signer == k,
    signFull(k, "checkpoint", "", "", 0, false, false, 2, false, Set(i)),
  }
  // An admin key uses a claimed root's key as a device's member key (Q-3's way).
  action signUseKey = nondet k = Set(PHONE, COMPUTER, WATCH, MINTED).oneOf() nondet t = Set("NA", "NK", MINTED).oneOf()
    sign(k, "device", t, "", 0, false, false, 1)
  // A root hands the group over to an admin key: that key's claim, made after it held the
  // handover, needs no time (Q-6's way).
  action signHandover = nondet k = ROOT_KEYS.oneOf() nondet t = Set(PHONE, RECOVERY, COMPUTER).oneOf()
    sign(k, "handover", t, "", 0, false, false, 1)
  // A newcomer (decision 21): m starts again from what admitter x hands it, x's records and
  // counted claims. It takes each counted claim, in order, that its proof shows: the one
  // epoch of the claim's root, the path of the counted claims before it, with that claim
  // alone decided there and held for the delay (audit 2c, Q-6); a Welcome with one that does
  // not prove is refused.
  pure def proves(given: Set[Record], prefix: List[Counted], c: Counted, anchors: Set[Id]): bool = {
    val path = prefix.foldl([ROOT], (l, x) => l.append(x.target))
    val cuts = prefix.indices().fold(Map(), (m, j) => m.put(path[j], prefix[j].cut))
    val earlier = prefix.foldl(Set(), (s, x) => s.union(Set(x.id)))
    val alone = given.filter(r => r.kind != "claim" or r.id == c.id or earlier.contains(r.id))
    val allHeld = idsOf(alone).mapBy(i => DELAY)
    val e = epoch(alone, allHeld, path, cuts, anchors)
    e.view.claims.keys().contains(c.id) and e.view.claims.get(c.id) == "effective" and e.next == c.target
  }
  pure def welcomeStore(sx: Store, db: Id -> Record): Store = {
    val given = recsOf(sx.recs, db)
    val anchors = storeAnchors(sx, db).union(lineAnchors(sx, given))
    val proved = range(0, sx.counted.length()).foldl((NOCOUNTED, true), (acc, i) =>
      if (acc._2 and proves(given, acc._1, sx.counted[i], anchors)) (acc._1.append(sx.counted[i]), true) else (acc._1, false))
    sx.recs.fold({ ...EMPTY, counted: proved._1 }, (s, i) => insertInto(s, db.get(i), db))
  }
  action welcomeNewcomer = nondet x = MEMBERS.exclude(Set("m")).oneOf() welcomeFrom(x)
  action welcomeFrom(x: str): bool = {
    val ws = welcomeStore(st.get(x), db)
    val sv = withCounted(ws, db)
    all {
      // The joiner refuses a Welcome whose counted claims its records do not prove (format
      // section 19); the joiner then has not joined.
      ws.counted.length() == st.get(x).counted.length(),
      db' = db,
      nextId' = nextId,
      st' = st.put("m", sv._1),
      views' = views.put("m", sv._2),
      gone' = gone.put("m", rootRemoved(sv._2, db)),
      before' = before.put("m", sv._2.path),
      welcomed' = st.get(x).counted.foldl([], (l, c) => l.append(c.target)),
    }
  }
  action signCopies = nondet k = SIGNERS.oneOf() nondet u = Set(1, 2).oneOf() sign(k, "copies", "", "", 0, false, false, u)

  // Member m is offered record i.
  action give(m: str, i: Id): bool = commit(db, nextId, m, insertInto(st.get(m), db.get(i), db))

  // Sync: a member is offered a record it does not keep (again, perhaps).
  action deliver = nondet m = MEMBERS.oneOf() nondet i = db.keys().oneOf() all {
    not(st.get(m).recs.contains(i)),
    give(m, i),
  }

  // A member's own count goes on for the claims it holds (it caps at DELAY + 1).
  action tick = nondet m = MEMBERS.oneOf() tickAt(m)
  action tickAt(m: str): bool = {
    val s = st.get(m)
    val cs = s.recs.filter(i => db.get(i).kind == "claim")
    val held = s.held.keys().union(cs).mapBy(i =>
      if (cs.contains(i)) min2(DELAY + 1, (if (s.held.keys().contains(i)) s.held.get(i) else 0) + 1) else s.held.get(i))
    commit(db, nextId, m, { ...s, held: held })
  }

  // Every member's own count goes on at once (a guided run's shortcut through the delay).
  pure def ticked(s: Store, db: Id -> Record): Store = {
    val cs = s.recs.filter(i => db.get(i).kind == "claim")
    val held = s.held.keys().union(cs).mapBy(i =>
      if (cs.contains(i)) min2(DELAY + 1, (if (s.held.keys().contains(i)) s.held.get(i) else 0) + 1) else s.held.get(i))
    { ...s, held: held }
  }
  action tickAll = {
    val nx = MEMBERS.mapBy(m => withCounted(ticked(st.get(m), db), db))
    all {
      db' = db,
      nextId' = nextId,
      st' = MEMBERS.mapBy(m => nx.get(m)._1),
      views' = MEMBERS.mapBy(m => nx.get(m)._2),
      gone' = MEMBERS.mapBy(m => gone.get(m).union(rootRemoved(nx.get(m)._2, db))),
      before' = MEMBERS.mapBy(m => views.get(m).path),
      welcomed' = welcomed,
    }
  }

  // A member compacts: it takes its state's path and checkpoint.
  action compact = nondet m = MEMBERS.oneOf() compactAt(m)
  action compactAt(m: str): bool = commit(db, nextId, m, compactStore(st.get(m), views.get(m), db))

  action step = any {
    signDevice, signDemote, signAdmin, signRevoke, signFreeze, signThaw, signResolve, signClaim, signCheckpoint, signCopies,
    signUseKey, signHidden, signCheckpointNaming, signHandover, welcomeNewcomer,
    deliver, deliver, deliver, deliver, tick, compact,
  }

  // A guided run: the same steps, weighted towards takeovers one after another, records of
  // the new roots for the next claimant to see, filling the room and compacting, so that many
  // traces reach a second takeover and a compaction that leaves a gap.
  action signNewRoot = nondet k = Set("NA", "NK").oneOf() nondet u = Set(1, 2).oneOf() all {
    views.get(HOLDER.get(k)).path.length() > 1,
    sign(k, "copies", "", "", 0, false, false, u),
  }
  // K takes over while its own member has only R as root; A takes over once its member counts
  // NK and holds a record of NK's, so its claim is one under the last root.
  action signTakeover = any {
    all {
      views.get("k").path == [ROOT],
      not(db.keys().exists(i => db.get(i).signer == RECOVERY and db.get(i).kind == "claim")),
      sign(RECOVERY, "claim", "NK", "", 0, false, false, CLAIMU),
    },
    all {
      views.get("a").path == [ROOT, "NK"],
      not(db.keys().exists(i => db.get(i).signer == PHONE and db.get(i).kind == "claim" and lineOf(db.get(i).seen, "NK") != [])),
      recsOf(st.get("a").recs, db).exists(r => r.signer == "NK"),
      sign(PHONE, "claim", "NA", "", 0, false, false, CLAIMU),
    },
  }
  // Every member is offered one record at once: any record, or the newest.
  action offerEveryone(i: Id): bool = {
    val nx = MEMBERS.mapBy(m => withCounted(insertInto(st.get(m), db.get(i), db), db))
    all {
      db' = db,
      nextId' = nextId,
      st' = MEMBERS.mapBy(m => nx.get(m)._1),
      views' = MEMBERS.mapBy(m => nx.get(m)._2),
      gone' = MEMBERS.mapBy(m => gone.get(m).union(rootRemoved(nx.get(m)._2, db))),
      before' = MEMBERS.mapBy(m => views.get(m).path),
      welcomed' = welcomed,
    }
  }
  action broadcast = nondet i = db.keys().oneOf() offerEveryone(i)
  // Sync with fairness: every member is offered, in ID order, every record some member holds.
  action syncAll = {
    val held = MEMBERS.fold(Set(), (u, n) => u.union(st.get(n).recs))
    val order = range(1, nextId).select(i => held.contains(i))
    val nx = MEMBERS.mapBy(m => withCounted(order.foldl(st.get(m), (s, i) => insertInto(s, db.get(i), db)), db))
    all {
      db' = db,
      nextId' = nextId,
      st' = MEMBERS.mapBy(m => nx.get(m)._1),
      views' = MEMBERS.mapBy(m => nx.get(m)._2),
      gone' = MEMBERS.mapBy(m => gone.get(m).union(rootRemoved(nx.get(m)._2, db))),
      before' = MEMBERS.mapBy(m => views.get(m).path),
      welcomed' = welcomed,
    }
  }
  action broadcastNewest = offerEveryone(nextId - 1)
  action guided = any {
    step, signTakeover, signTakeover, signTakeover, signNewRoot, signNewRoot, signNewRoot, signCopies, signCheckpoint,
    broadcast, broadcastNewest, broadcastNewest, broadcastNewest, broadcastNewest, deliver,
    tickAll, tickAll, tickAll, tickAll, compact, compact, syncAll, syncAll, welcomeNewcomer, signHandover, signHidden, signCheckpointNaming,
  }

  // Witnesses of a run (quint run --witnesses): how many traces reach these.
  val firstTakeover = MEMBERS.exists(m => st.get(m).counted.length() >= 1)
  val secondTakeover = MEMBERS.exists(m => st.get(m).counted.length() >= 2)
  // A member that compacted on a checkpoint and dropped a record it was offered.
  val compactedDrop = MEMBERS.exists(m => st.get(m).checkpoint != 0 and st.get(m).got.exclude(st.get(m).recs) != Set())
  // A member that compacted on a checkpoint dropped a record below one it kept of the same key.
  val compactedGap = MEMBERS.exists(m => {
    val s = st.get(m)
    s.checkpoint != 0 and recsOf(s.got.exclude(s.recs), db).exists(r =>
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

  // 2. A key a root removed stays removed, unless a takeover cut the removal off: the new root
  // takes the old root's records up to the line the claim saw, and no further.
  pure def cutOff(v: View, r: Record): bool = not(within(v.cuts, r))
  // A gap is liveness, not a rule: an honest peer that holds a line serves it, so a member is
  // checked once it was offered, to no change, every record some member holds.
  def synced(m: str): bool = MEMBERS.forall(n => st.get(n).recs.forall(i => insertInto(st.get(m), db.get(i), db).recs == st.get(m).recs))
  val removedStayOut = MEMBERS.forall(m => synced(m) implies {
    val v = views.get(m)
    val removals = recsOf(st.get(m).got, db).filter(r => r.kind == "revoke" and ROOT_KEYS.contains(r.signer))
    gone.get(m).forall(k =>
      removals.filter(r => withPair(r.target).contains(k)).forall(r => cutOff(v, r))
        or (v.revoked.contains(k) and not(v.admins.keys().contains(k)) and not(v.devices.contains(k))))
  })

  // 3. Members that keep the same records and counted the same claims have one root, or one
  // waits out a claim.
  val oneRoot = MEMBERS.forall(m1 => MEMBERS.forall(m2 => {
    val p1 = views.get(m1).path
    val p2 = views.get(m2).path
    val same = st.get(m1).recs == st.get(m2).recs and st.get(m1).counted == st.get(m2).counted
    same implies (isPrefix(p1, p2) or isPrefix(p2, p1))
  }))

  // 4. A claim counts only after the member held it for the delay.
  val claimWaits = MEMBERS.forall(m => {
    val v = views.get(m)
    val held = st.get(m).held
    // A newcomer's counted claims from its Welcome were held by its admitter (decision 21).
    val fromWelcome = if (m != "m") Set() else st.get(m).counted.indices().filter(i => i < welcomed.length()).map(i => st.get(m).counted[i].id)
    // A claim the root handed the group to (it saw a handover naming its signer) needs no time.
    def handed(i: Id): bool = db.keys().exists(h => db.get(h).kind == "handover" and db.get(h).target == db.get(i).signer
      and inLine(lineOf(db.get(i).seen, db.get(h).signer), h))
    v.claims.keys().forall(i => (v.claims.get(i) == "effective" and not(fromWelcome.contains(i)) and not(handed(i)))
      implies (held.keys().contains(i) and held.get(i) >= DELAY))
  })

  // 5. During a full stop only the current root's commands run, and the root's records still
  // count.
  val stopRootOnly = MEMBERS.forall(m => {
    val v = views.get(m)
    v.rootsCount and (v.stop implies v.commanders.forall(k => k == last(v.path)))
  })

  // 6. No key takes another key's room.
  val fairRoom = MEMBERS.forall(m => {
    val s = st.get(m)
    val rs0 = recsOf(s.recs, db)
    val got = recsOf(s.got, db)
    val admins = learned(got, keptPath(s), keptCuts(s))
    val ceil = ceilings(keptPath(s), admins)
    // Only the first root, the promoted roots and the admin keys their records name.
    val legit = rootsOf(keptPath(s)).union(got.filter(r => onList(keptPath(s), r.signer) and (r.kind == "admin" or r.kind == "recovery")).map(r => r.target))
    val owners = got.map(r => r.signer).filter(k => ceil.keys().contains(k))
    val fair = if (owners.size() == 0) ROOM else ROOM / owners.size()
    // Counted claims are kept outside the rooms.
    val pins = countedIds(s)
    val rs = rs0.filter(r => not(pins.contains(r.id)))
    val named = rs0.filter(r => r.kind == "claim").map(r => r.target).union(countedRoots(s))
    // A cut root's records below a gap in what it was offered are not its to keep (decision 22).
    and {
      ceil.keys().forall(k => legit.contains(k)),
      // A claimed root's records are paid ahead by its claim's units.
      sumUnits(rs.filter(r => ceil.keys().contains(r.signer))) <= ROOM,
      rs.map(r => r.signer).forall(k =>
        if (ceil.keys().contains(k)) sumUnits(ofKey(rs, k)) <= ceil.get(k)
        else named.contains(k) and sumUnits(ofKey(rs, k)) <= FUTURE),
      saturated(m) implies owners.forall(k =>
        sumUnits(ofKey(rs, k)) + MAXU - 1 >= min2(fair, min2(ceil.get(k), sumUnits(ofKey(got.filter(r => storable(s, r, db) and not(pins.contains(r.id))
          and withinIn(keptCuts(s), r, s.got, storeAnchors(s, db).union(lineAnchors(s, got)))), k))))),
    }
  })

  // 7. A takeover a member counted is never undone, whatever any key signs later: the i-th
  // counted claim's new root stays the path's root after the i-th.
  val countedFinal = MEMBERS.forall(m => {
    val p = views.get(m).path
    val c = st.get(m).counted
    c.indices().forall(i => i + 1 < p.length() and p[i + 1] == c[i].target)
  })

  // 8. A member's path never grows shorter: its path before is a start of its path now.
  val pathGrows = MEMBERS.forall(m => isPrefix(before.get(m), views.get(m).path))

  // 9. A newcomer takes its admitter's counted claims: their new roots are the start of its
  // own counted claims' (decision 21).
  val newcomerTakes = {
    val mine = st.get("m").counted.foldl([], (l, c) => l.append(c.target))
    welcomed.length() <= mine.length() and welcomed.indices().forall(i => welcomed[i] == mine[i])
  }

  val promises = and { oneState, removedStayOut, oneRoot, claimWaits, stopRootOnly, fairRoom, countedFinal, pathGrows, newcomerTakes }

  // --- Scenarios (core tests run the same: core/tests/records_model.rs) ------------------

  def claimState(m: str, i: Id): str = if (views.get(m).claims.keys().contains(i)) views.get(m).claims.get(i) else "none"
  action signAs(k: Key, kind: str, target: Key, targetRec: Id): bool =
    sign(k, kind, target, "", targetRec, false, false, if (kind == "claim") CLAIMU else if (kind == "checkpoint") 2 else 1)

  // The recovery key claims a group whose root is lost: the claim waits until the member has
  // held it for the delay, then its new root takes over and the member counts the claim.
  run recoveryKeyTakesOverTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .expect(claimState("m", 5) == "pending" and views.get("m").path == [ROOT])
      .then(tickAt("m"))
      .expect(claimState("m", 5) == "effective" and views.get("m").path == [ROOT, "NK"]
        and countedIds(st.get("m")) == Set(5) and promises)

  // A computer admin has no takeover: its claim is void however long it is held.
  run computerCannotTakeOverTest =
    init
      .then(signAs(COMPUTER, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(claimState("m", 5) == "void" and views.get("m").path == [ROOT] and not(views.get("m").stop))

  // Two claims stop the group; the root's records still count, and its resolve ends the stop.
  run competingClaimsStopTest =
    init
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").stop and claimState("m", 5) == "competing" and claimState("m", 6) == "competing")
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(give("m", 7))
      .then(give("m", 8))
      .expect(views.get("m").stop and views.get("m").revoked.contains(DEVICE)
        and views.get("m").commanders == Set(ROOT))
      .then(signAs(ROOT, "resolve", "", 5))
      .then(give("m", 9))
      .expect(not(views.get("m").stop) and claimState("m", 6) == "effective" and views.get("m").path == [ROOT, "NK"]
        and countedIds(st.get("m")) == Set(6))

  // A phone admin that had not seen a claim removes the claimant: the claim is disputed and
  // the group stops.
  run objectionDisputesTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(signAs(PHONE, "revoke", RECOVERY, 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(claimState("m", 5) == "disputed" and views.get("m").stop and views.get("m").path == [ROOT])

  // A device the root removed does not come back by a new record for its key.
  run removedDeviceStaysOutTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE)
        and gone.get("m").contains(DEVICE) and promises)

  // A claimed root keeps only what its claim paid ahead until the claim counts and the member
  // gives it a root's room.
  run claimedRootRoomTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(signAs("NK", "device", DEVICE, 0))
      .then(signAs("NK", "copies", "", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(st.get("m").recs.contains(6) and not(st.get("m").recs.contains(7)))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(compactAt("m"))
      .then(give("m", 7))
      .expect(views.get("m").path == [ROOT, "NK"] and st.get("m").recs.contains(7) and views.get("m").devices.contains(DEVICE))

  // A removal by an admin is not final: the root's resolve voids it, and the device counts
  // again under its old key. A removal by the root is final: its resolve changes nothing.
  run removalsByAdminAndRootTest =
    init
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(signAs(COMPUTER, "revoke", DEVICE, 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE))
      .then(signAs(ROOT, "resolve", "", 6))
      .then(give("m", 7))
      .expect(views.get("m").devices.contains(DEVICE) and not(views.get("m").revoked.contains(DEVICE)))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(give("m", 8))
      .then(signAs(ROOT, "resolve", "", 8))
      .then(give("m", 9))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE) and promises)

  // A takeover the member counted stays: neither the old root's late resolve of the claim nor
  // a later claim of another admin undoes it.
  run countedTakeoverStaysTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(give("r", 5))
      .then(signAs(ROOT, "resolve", "", 5))
      .then(give("m", 6))
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(give("m", 7))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK"] and claimState("m", 5) == "effective" and promises)

  // A watch admin may not freeze the recovery key; a phone admin may, and the frozen key's
  // claim waits.
  run recoveryFreezeTest =
    init
      .then(signAs(WATCH, "freeze", RECOVERY, 0))
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(not(views.get("m").frozen.contains(RECOVERY)) and views.get("m").path == [ROOT, "NK"])

  // Two freezes a watch admin signs of its own key do not stop the group.
  run ownKeyFreezesTest =
    init
      .then(sign(WATCH, "freeze", WATCH, "", 0, true, false, 1))
      .then(sign(WATCH, "freeze", WATCH, "", 0, true, false, 1))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").stop) and views.get("m").commanders.contains(PHONE) and promises)

  // A removal of an admin's member key removes its admin key: its later claim, which the
  // removal did not see, is void.
  run bothKeysRemovedTest =
    init
      .then(signAs(ROOT, "revoke", "dA", 0))
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").revoked.contains(PHONE) and not(views.get("m").admins.keys().contains(PHONE))
        and claimState("m", 6) == "void" and views.get("m").path == [ROOT] and promises)

  // What the old root resolved stays resolved after a takeover.
  run oldRootResolveStaysTest =
    init
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(signAs(COMPUTER, "revoke", DEVICE, 0))
      .then(give("r", 5))
      .then(give("r", 6))
      .then(signAs(ROOT, "resolve", "", 6))
      .then(give("k", 5))
      .then(give("k", 6))
      .then(give("k", 7))
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .then(give("m", 8))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").devices.contains(DEVICE) and promises)

  // After a takeover the old root's key counts only on the line the claim saw: neither a new
  // removal nor a second record at the seq of its newest counts, and a member that compacted
  // keeps none.
  run oldRootAboveCutTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(give("k", 5))
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(compactAt("m"))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, true, 1))
      .then(give("m", 7))
      .then(give("m", 8))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").devices.contains(DEVICE)
        and not(st.get("m").recs.contains(7)) and not(st.get("m").recs.contains(8)) and promises)

  // A key a claimed root names teaches nothing until the claim counts: its records are not kept.
  run mintedKeyTest =
    init
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(sign("NA", "admin", MINTED, "computer", 0, false, false, 1))
      .then(signAs(MINTED, "device", DEVICE, 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(not(st.get("m").recs.contains(7)) and not(views.get("m").admins.keys().contains(MINTED))
        and not(views.get("m").devices.contains(DEVICE)) and promises)

  // The root's checkpoint gives the state on a member that compacted on it; a claimed root's
  // checkpoint is not tried.
  run checkpointTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(views.get("m").checkpoint == 6 and views.get("m").devices.contains(DEVICE))
      .then(compactAt("m"))
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(signAs("NA", "checkpoint", "", 0))
      .then(give("m", 7))
      .then(give("m", 8))
      .expect(views.get("m").checkpoint == 6 and views.get("m").devices.contains(DEVICE)
        and views.get("m").admins.keys().contains(PHONE) and promises)
  // The root takes the admin key off A's device: what A signs after, unseen by that record,
  // does not count, and A is no longer an admin.
  run demotedAdminTest =
    init
      .then(signAs(ROOT, "device", "dA", 0))
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT] and claimState("m", 6) != "effective"
        and not(views.get("m").admins.keys().contains(PHONE)) and promises)

  // The root names another admin key for C's device: C's later record does not count, C2's does.
  run replacedAdminKeyTest =
    init
      .then(sign(ROOT, "admin", "C2", "computer", 0, false, false, 1))
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").admins.keys().contains("C2")
        and not(views.get("m").admins.keys().contains(COMPUTER)))
      .then(give("c", 5))
      .then(signAs("C2", "device", DEVICE, 0))
      .then(give("m", 7))
      .expect(views.get("m").devices.contains(DEVICE) and promises)

  // After a counted takeover, a second claim that did not see the new root is not taken.
  run secondClaimShortSeenTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK"] and claimState("m", 6) != "effective" and promises)

  // A second claim that saw the new root is taken under it; the counted claims are a list in
  // the order counted.
  run secondTakeoverTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(signAs("NK", "device", DEVICE, 0))
      .then(give("a", 5))
      .then(give("a", 6))
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(give("m", 6))
      .then(give("m", 7))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK", "NA"]
        and st.get("m").counted.foldl([], (l, c) => l.append(c.id)) == [5, 7] and promises)

  // A counted claim is kept outside the rooms: records the claimant forks beside it, at its
  // seq, never push it out, before or after compaction.
  run countedClaimKeptTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(sign(RECOVERY, "copies", "", "", 0, false, true, 2))
      .then(sign(RECOVERY, "copies", "", "", 0, false, true, 2))
      .then(sign(RECOVERY, "copies", "", "", 0, false, true, 2))
      .then(sign(RECOVERY, "copies", "", "", 0, false, true, 2))
      .then(give("m", 6))
      .then(give("m", 7))
      .then(give("m", 8))
      .then(give("m", 9))
      .then(compactAt("m"))
      .expect(st.get("m").recs.contains(5) and views.get("m").path == [ROOT, "NK"] and promises)

  // A thaw revives only what it saw of the frozen key; the rest stays cut off.
  run thawTest =
    init
      .then(signAs(PHONE, "freeze", COMPUTER, 0))
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(signAs(ROOT, "thaw", "", 5))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(not(views.get("m").frozen.contains(COMPUTER)) and not(views.get("m").devices.contains(DEVICE)) and promises)

  run thawSeenTest =
    init
      .then(signAs(PHONE, "freeze", COMPUTER, 0))
      .then(signAs(COMPUTER, "device", DEVICE, 0))
      .then(give("r", 5))
      .then(give("r", 6))
      .then(signAs(ROOT, "thaw", "", 5))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(not(views.get("m").frozen.contains(COMPUTER)) and views.get("m").devices.contains(DEVICE) and promises)
  // The live old root honestly removes the claimant after seeing its claim. A member that
  // counted the claim first keeps the takeover; a member that was off during the delay and
  // gets the claim and the removal together sees the claim cancelled.
  run claimantRemovedTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(give("r", 5))
      .then(signAs(ROOT, "revoke", RECOVERY, 0))
      .then(give("m", 6))
      .then(give("c", 5))
      .then(give("c", 6))
      .then(tickAt("c"))
      .then(tickAt("c"))
      .then(tickAt("c"))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("c").path == [ROOT]
        and claimState("c", 5) == "cancelled" and promises)

  // A removal of the claimant that saw the new root's records disputes nothing: a member off
  // during the delay counts the claim all the same.
  run claimantRemovedAfterNewRootTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(signAs("NK", "device", DEVICE, 0))
      .then(give("r", 5))
      .then(give("r", 6))
      .then(signAs(ROOT, "revoke", RECOVERY, 0))
      .then(give("c", 5))
      .then(give("c", 6))
      .then(give("c", 7))
      .then(tickAt("c"))
      .then(tickAt("c"))
      .expect(views.get("c").path == [ROOT, "NK"] and claimState("c", 5) == "effective" and promises)
  // After a takeover counts, other keys fill the room and push out the old root's records: it
  // keeps them from the head the claim saw downward, and the takeover stays, since a counted
  // claim is checked once, when counted (decision 22).
  run fullRoomAfterTakeoverTest =
    init
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(give("m", 6)).then(give("m", 7)).then(give("m", 8)).then(give("m", 9))
      .then(give("m", 10)).then(give("m", 11)).then(give("m", 12)).then(give("m", 13))
      .expect(st.get("m").recs.contains(4) and not(st.get("m").recs.contains(1))
        and views.get("m").path == [ROOT, "NK"] and promises)

  // Audit 2c, Q-3: an admin's device record that uses a claimed root's key, which the claim
  // did not see, voids nothing and does not count; the root's record that uses it voids it.
  run claimKeyUseTest =
    init
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(signAs(COMPUTER, "device", "NA", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(claimState("m", 5) == "effective" and views.get("m").path == [ROOT, "NA"]
        and not(views.get("m").counting.contains(6)) and promises)
      .then(signAs(ROOT, "device", "NK", 0))
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("k", 7))
      .then(give("c", 8))
      .then(give("c", 7))
      .then(give("c", 8))
      .expect(claimState("c", 8) == "void")

  // Audit 2c, Q-4: the root takes the admin key off the claimant's device having seen its
  // claim: the claim is cancelled, as by a removal.
  run demotionCancelsTest =
    init
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(give("r", 5))
      .then(signAs(ROOT, "device", "dA", 0))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(claimState("m", 5) == "cancelled" and views.get("m").path == [ROOT]
        and not(views.get("m").admins.keys().contains(PHONE)) and promises)

  // Audit 2c, Q-1: the root keeps back a twin of its newest record and checkpoints naming it.
  // The checkpoint never counts (a named record off its chain), and the twin, handed in after
  // a takeover, counts nothing.
  run hiddenKeepTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signFull(ROOT, "admin", MINTED, "phone", 0, false, true, 1, true, Set()))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set(6)))
      .then(give("m", 5))
      .then(give("m", 7))
      .then(compactAt("m"))
      .expect(views.get("m").checkpoint == 0 and st.get("m").recs.contains(5) and views.get("m").devices.contains(DEVICE))
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("m", 8))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(compactAt("m"))
      .then(give("m", 6))
      .expect(views.get("m").path == [ROOT, "NK"] and not(views.get("m").admins.keys().contains(MINTED))
        and views.get("m").checkpoint == 0 and promises)

  // Audit 2c, Q-6: after a handover (no delay) and a later takeover under the new root, a
  // newcomer takes both counted claims from its admitter's Welcome and has its path.
  run handoverNewcomerTest =
    init
      .then(sign(ROOT, "handover", RECOVERY, "", 0, false, false, 1))
      .then(give("k", 5))
      .then(signAs(RECOVERY, "claim", "NK", 0))
      .then(give("a", 5))
      .then(give("a", 6))
      .expect(views.get("a").path == [ROOT, "NK"] and countedIds(st.get("a")) == Set(6))
      .then(signAs("NK", "copies", "", 0))
      .then(give("a", 7))
      .then(signAs(PHONE, "claim", "NA", 0))
      .then(tickAt("a"))
      .then(tickAt("a"))
      .expect(views.get("a").path == [ROOT, "NK", "NA"])
      .then(welcomeFrom("a"))
      .expect(views.get("m").path == [ROOT, "NK", "NA"] and countedIds(st.get("m")) == Set(6, 8)
        and welcomed == ["NK", "NA"] and promises)
}
