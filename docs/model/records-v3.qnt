// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
//
// A model of the record rules of 0.6 (records v3), in Quint (https://quint-lang.org). It is not
// the code: it states the rules the core's `records` module implements, at a small scale, and
// lets the simulator try many ways a few devices can sign, sync, wait and drop records, checking
// six promises:
//
//  1. One set, one state: a member that has been offered a set of records, in whatever order
//     and with whatever it dropped on the way, keeps what a member given the whole set at once
//     keeps, and evaluates it to the same state.
//  2. A device or admin a root removed never returns: once a root's removal of a key counts on
//     a member, the key stays removed there, whatever else comes (a resolve, a full set, a new
//     record for it). A removal by an admin is not final: the root may void it.
//  3. One root: two members that keep the same records have the same root, or one of them is
//     still waiting out a claim the other already counts (its path of roots is a start of the
//     other's).
//  4. A claim never counts before the member itself has held it for the takeover delay.
//  5. During a full stop only the current root's commands run, and its records still count
//     (members exchange records only; admins' records still count in the state).
//  6. No key takes another key's room: every key keeps at least its fair share of the set (or
//     all it made, or its ceiling), a claimed root keeps at most what its claim paid ahead, and
//     the set never holds more than its room.
//
// Who is in it: the group's first root R; a phone admin A (the phone set of powers: it may take
// the group over); a computer admin C (the computer set: no takeover, no removing admins); the
// recovery key K, which only claims; the device D that admins and the root admit and remove;
// and the new roots NA and NK, whose keys A and K hold. Any of them may stay silent (a lost
// root) or act as a thief (a claim may pretend it held none of the other admins' records).
// Five members keep a set each: r (R's device), a (A's, with NA), c (C's), k (K's, with NK) and
// m, a member that only syncs.
//
// The scale: a record takes one or two units of room; a claim takes three (one for itself,
// one for its new key, one paid ahead for its root's records). The set holds 12 units, a root
// key 8, an admin key 6, a claimed root 1 while only its claim names it; the takeover delay is
// two ticks of a member's own count. The format's numbers are 4096, 1024, 256 and 16, and a
// claim 80 units; the rules do not depend on the numbers.
//
// Left out, since other tests cover them: signatures and the byte form (one record, one ID),
// two histories of one key, freezes and thaws, checkpoints, handovers, settings, leaves and
// watches, two keys with one device ID.
//
// The rules here are those the owner settled on 11.11; #513 builds the last of them. Two
// switches keep its code before that one step away, and break promise 1 or 2 when flipped:
// ROOT_REMOVALS_FIRST (a root's removals and resolves first in its order when a set is cut,
// standing for their chain) and SKIP_RECUT_WITHIN_ROOM (the set cuts back only past a ceiling
// or the room). A takeover cuts off the old root's records past the claim's seen, its
// removals with them (owner, 11.11): a live root cancels the claim within the delay.
//
// Run it:
//
//	quint test --backend=typescript docs/model/records-v3.qnt
//	quint run --backend=typescript --invariant=promises --max-steps=25 --max-samples=500 docs/model/records-v3.qnt
//
// with --invariant set to oneState, removedStayOut, oneRoot, claimWaits, stopRootOnly or
// fairRoom for one promise. The typescript backend takes a few traces a second here, so a
// long run takes many samples and several seeds.
module records_v3 {
  type Key = str
  type Id = int
  type Record = {
    id: Id,
    signer: Key,
    seq: int,
    // "admin" (a root's device record that makes target an admin with the set kit), "recovery"
    // (target is the recovery key), "device" (admits or changes the device target),
    // "revoke" (removes target), "resolve" (voids record targetRec), "claim" (target is the
    // new root), "copies" (a record that only takes room).
    kind: str,
    target: Key,
    kit: str,
    targetRec: Id,
    // The highest seq of each signer the author held (or says it held): revoke and claim.
    seen: Key -> int,
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
    promoted: Set[Key], // the roots after the first its own evaluation put on the path
    admins: Set[Key], // the admin keys it learned
    roots: Set[Key], // the root keys it knows: the first, the promoted, those of kept claims
    held: Id -> int, // how long it has held each claim, in its own ticks
  }

  type View = {
    path: List[Key],
    counting: Set[Id],
    revoked: Set[Key],
    admins: Key -> str,
    stop: bool,
    claims: Id -> str,
    devices: Set[Key],
    commanders: Set[Key],
    rootsCount: bool, // every record of the current root with a whole chain counts
    cuts: Key -> int, // the seq up to which each earlier root's records count
  }

  pure val ROOT = "R"
  pure val PHONE = "A"
  pure val COMPUTER = "C"
  pure val RECOVERY = "K"
  pure val DEVICE = "D"
  pure val SIGNERS = Set("R", "A", "C", "K", "NA", "NK")
  pure val HOLDER = Map("R" -> "r", "A" -> "a", "NA" -> "a", "C" -> "c", "K" -> "k", "NK" -> "k")
  pure val MEMBERS = Set("r", "a", "c", "k", "m")

  pure val ROOM = 12
  pure val ROOTC = 8
  pure val ADMINC = 6
  pure val FUTURE = 1
  pure val CLAIMU = 1 + 1 + FUTURE
  pure val MAXU = CLAIMU
  pure val TOP = ROOTC
  pure val DELAY = 2
  pure val MAXREC = 16
  pure val MAXPATH = 3

  pure val NOCUT: Cut = { level: TOP, marks: Map(), future: Map() }
  pure val NONE = 10000000

  // The powers of the three sets the apps write (core AdminKind::grants), and the recovery
  // key's.
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
  pure def seenOf(r: Record, k: Key): int = getOr(r.seen, k, 0)
  pure def sumUnits(rs: Set[Record]): int = rs.fold(0, (t, r) => t + r.units)
  pure def ofKey(rs: Set[Record], k: Key): Set[Record] = rs.filter(r => r.signer == k)
  pure def recsOf(xs: Set[Id], db: Id -> Record): Set[Record] = xs.map(i => db.get(i))
  pure def idsOf(rs: Set[Record]): Set[Id] = rs.map(r => r.id)
  pure def onList(l: List[Key], k: Key): bool = l.indices().exists(i => l[i] == k)
  pure def indexOf(l: List[Key], k: Key): int = l.indices().fold(-1, (f, i) => if (l[i] == k) i else f)
  pure def last(l: List[Key]): Key = l[l.length() - 1]
  pure def isPrefix(a: List[Key], b: List[Key]): bool =
    a.length() <= b.length() and a.indices().forall(i => a[i] == b[i])

  // --- Keeping (core records::keep) ------------------------------------------------------

  // A record's place in its key's order: by seq, then ID; a root's removals and resolves come
  // before its other records (as its checkpoints do in the core), so that a full set never
  // drops one while it keeps any of the root's records (owner, 11.11). With
  // ROOT_REMOVALS_FIRST false, the order of #513 before that.
  pure val ROOT_REMOVALS_FIRST = true
  pure val ROOT_KEYS = Set(ROOT, "NA", "NK")
  pure def pos(r: Record): int =
    if (ROOT_REMOVALS_FIRST and ROOT_KEYS.contains(r.signer) and (r.kind == "revoke" or r.kind == "resolve")) r.seq * 100 + r.id
    else 100000 + r.seq * 100 + r.id
  pure def minPos(rs: Set[Record]): int = rs.fold(NONE, (m, r) => min2(m, pos(r)))
  // The units of a key's records up to r, r included.
  pure def prefix(rs: Set[Record], r: Record): int = sumUnits(rs.filter(x => pos(x) <= pos(r)))

  pure def past(cut: Cut, r: Record): bool =
    (cut.marks.keys().contains(r.signer) and pos(r) >= cut.marks.get(r.signer)._1)
      or (cut.future.keys().contains(r.signer) and pos(r) >= cut.future.get(r.signer))

  pure def dropped(cut: Cut, k: Key): int = if (cut.marks.keys().contains(k)) cut.marks.get(k)._2 else 0
  pure def demand(owned: Set[Record], ceil: Key -> int, cut: Cut, s: int): int =
    owned.map(r => r.signer).fold(0, (d, k) =>
      d + min2(s, min2(ceil.get(k), dropped(cut, k) + sumUnits(ofKey(owned, k)))))

  // What a set keeps of items, having dropped before what cut remembers. ceil gives the ceiling
  // of each key with room of its own; a key it does not name is a root only claims name.
  pure def keepAfter(items: Set[Record], ceil: Key -> int, cut: Cut): (Set[Id], Cut) = {
    val live = items.filter(r => not(past(cut, r)))
    val owned = live.filter(r => ceil.keys().contains(r.signer))
    val claimed = live.filter(r => not(ceil.keys().contains(r.signer)))
    val top = min2(cut.level, TOP)
    val level =
      if (demand(owned, ceil, cut, top) <= ROOM) top
      else 0.to(top).filter(s => demand(owned, ceil, cut, s) <= ROOM).fold(0, (m, s) => max2(m, s))
    val keptOwned = owned.filter(r => prefix(ofKey(owned, r.signer), r) <= min2(level, ceil.get(r.signer)))
    val out = owned.exclude(keptOwned)
    val markKeys = cut.marks.keys().union(out.map(r => r.signer))
    val marks = markKeys.mapBy(k => {
      val o = ofKey(out, k)
      if (o == Set()) cut.marks.get(k)
      else if (cut.marks.keys().contains(k))
        (min2(minPos(o), cut.marks.get(k)._1), sumUnits(o) + cut.marks.get(k)._2)
      else (minPos(o), sumUnits(o))
    })
    val named = keptOwned.filter(r => r.kind == "claim").map(r => r.target)
    val inFuture = claimed.filter(r => named.contains(r.signer))
    val keptFuture = inFuture.filter(r => prefix(ofKey(inFuture, r.signer), r) <= FUTURE)
    val over = inFuture.exclude(keptFuture)
    val futureKeys = cut.future.keys().union(over.map(r => r.signer))
    val future = futureKeys.mapBy(h => {
      val o = ofKey(over, h)
      if (o == Set()) cut.future.get(h)
      else if (cut.future.keys().contains(h)) min2(minPos(o), cut.future.get(h))
      else minPos(o)
    })
    (idsOf(keptOwned).union(idsOf(keptFuture)), { level: level, marks: marks, future: future })
  }

  // The ceilings: the first root's and a promoted root's, an admin key's; a claimed root has
  // none of its own.
  pure def ceilings(promoted: Set[Key], admins: Set[Key]): Key -> int =
    SIGNERS.filter(k => k == ROOT or promoted.contains(k) or admins.contains(k))
      .mapBy(k => if (k == ROOT or promoted.contains(k)) ROOTC else ADMINC)

  // --- A member's set (core records::set::RecordSet) -------------------------------------

  pure def roleOf(admins: Set[Key], roots: Set[Key], k: Key): str =
    if (admins.contains(k)) "admin" else if (roots.contains(k)) "root" else ""

  // Drops what the set does not keep and forgets the roots of claims it dropped.
  pure def recut(s: Store, db: Id -> Record): Store = {
    val res = keepAfter(recsOf(s.recs, db), ceilings(s.promoted, s.admins), s.cut)
    val kept = recsOf(res._1, db)
    val named = kept.filter(r => r.kind == "claim" and s.admins.contains(r.signer)).map(r => r.target)
    val roots = s.roots.filter(h => h == ROOT or named.contains(h) or s.promoted.contains(h))
    { ...s, recs: res._1, cut: res._2, roots: roots }
  }

  // The set cuts back after every record it takes. With true, as #513 does today: only when
  // the stored units pass a ceiling or the room, which forgets the units the cut remembers.
  pure val SKIP_RECUT_WITHIN_ROOM = false

  // A record offered to the set: refused when its signer is unknown, not kept when its key
  // dropped a record before it; else stored, its keys learned, and the set cut back when a
  // ceiling is passed.
  pure def insertInto(s0: Store, r: Record, db: Id -> Record): Store = {
    val s = { ...s0, got: s0.got.union(Set(r.id)) }
    val role = roleOf(s.admins, s.roots, r.signer)
    if (s.recs.contains(r.id) or role == "" or past(s.cut, r)) s
    else {
      val admins = if (role == "root" and (r.kind == "admin" or r.kind == "recovery")) s.admins.union(Set(r.target)) else s.admins
      val roots = if (role == "admin" and r.kind == "claim") s.roots.union(Set(r.target)) else s.roots
      val s2 = { ...s, recs: s.recs.union(Set(r.id)), admins: admins, roots: roots }
      val rs = recsOf(s2.recs, db)
      val ceil = ceilings(s2.promoted, s2.admins)
      val mine = sumUnits(ofKey(rs, r.signer))
      val over = mine > (if (ceil.keys().contains(r.signer)) ceil.get(r.signer) else FUTURE)
      if (over or sumUnits(rs) > ROOM or not(SKIP_RECUT_WITHIN_ROOM)) recut(s2, db) else s2
    }
  }

  // Gives the roots the member's evaluation put on the path a root's room.
  pure def compactStore(s: Store, v: View, db: Id -> Record): Store = {
    val promoted = v.path.indices().filter(i => i > 0).map(i => v.path[i])
    if (promoted == s.promoted) s
    else recut({ ...s, promoted: promoted, cut: NOCUT }, db)
  }

  // --- Evaluation (core records::eval) ---------------------------------------------------

  // The keys a set of records names, learned until none is added (check_all).
  pure def learnAll(rs: Set[Record]): (Set[Key], Set[Key]) =
    0.to(4).fold((Set(), Set(ROOT)), (ar, i) => {
      val admins = ar._1.union(rs.filter(r => roleOf(ar._1, ar._2, r.signer) == "root"
        and (r.kind == "admin" or r.kind == "recovery")).map(r => r.target))
      val roots = ar._2.union(rs.filter(r => roleOf(ar._1, ar._2, r.signer) == "admin" and r.kind == "claim").map(r => r.target))
      (admins, roots)
    })

  type Epoch = { view: View, next: Key, cut: int }

  // The evaluation under one path of roots.
  pure def epoch(rs: Set[Record], adminKeys: Set[Key], held: Id -> int, path: List[Key], cuts: Key -> int): Epoch = {
    val cur = last(path)
    pure def isAdmin(r: Record): bool = adminKeys.contains(r.signer)
    // A whole chain: the signer's records from seq 1 up to it are all here.
    // With ROOT_REMOVALS_FIRST, a root's removal or resolve stands for its chain, as a
    // checkpoint's anchors do in the core: the set may have dropped records below it.
    pure def whole(r: Record): bool =
      (ROOT_REMOVALS_FIRST and not(isAdmin(r)) and (r.kind == "revoke" or r.kind == "resolve"))
        or 1.to(r.seq).forall(q => rs.exists(x => x.signer == r.signer and x.seq == q))
    // A root's removal is final: no resolve voids it (owner, 11.11).
    val voids = rs.filter(r => r.signer == cur and not(isAdmin(r)) and r.kind == "resolve" and whole(r)).map(r => r.targetRec)
      .filter(i => not(rs.exists(x => x.id == i and x.kind == "revoke" and not(isAdmin(x)))))
    pure def counted(r: Record): bool = whole(r) and not(voids.contains(r.id))
    pure def rootRec(r: Record): bool =
      not(isAdmin(r)) and counted(r) and onList(path, r.signer)
        and (r.signer != cur implies r.seq <= getOr(cuts, r.signer, 0))
    pure def newer(a: Record, b: Record): bool = {
      val pa = indexOf(path, a.signer)
      val pb = indexOf(path, b.signer)
      pa > pb or (pa == pb and a.seq > b.seq)
    }
    // The admin keys, each with the set of the newest root record that names it; the recovery
    // key with takeover only.
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
    val claimRoots = rs.filter(r => r.kind == "claim" and isAdmin(r)).map(r => r.target)
    pure def isRootKey(k: Key): bool = k == ROOT or claimRoots.contains(k)
    pure def rootHas(d: Key): bool = rs.exists(r => (r.kind == "device" or r.kind == "admin") and r.target == d and rootRec(r))
    // The admin record that admits a device no root recorded: each admin's first, the
    // smallest ID (the records of the model for one device are alike).
    pure def admittedBy(d: Key): Id = {
      val ok = rs.filter(r => r.kind == "device" and r.target == d and isAdmin(r) and counted(r) and has(r.signer, "admit"))
      val firsts = ok.filter(r => not(ok.exists(o => o.signer == r.signer and o.seq < r.seq)))
      if (rootHas(d)) -1 else firsts.fold(NONE, (m, r) => min2(m, r.id))
    }
    pure def permitted(r: Record): bool =
      if (not(adm.keys().contains(r.signer))) false
      else if (adm.get(r.signer) == "recovery" and r.kind != "claim") false
      else if (r.kind == "device") {
        val first = admittedBy(r.target)
        not(rootHas(r.target)) and (first == r.id or (first != NONE and first != -1 and has(r.signer, "manage")))
      }
      else if (r.kind == "revoke")
        if (isRootKey(r.target)) false
        else if (adm.keys().contains(r.target)) has(r.signer, "removeAdmins")
        else has(r.signer, "remove")
      else if (r.kind == "claim") has(r.signer, "takeover") and seenOf(r, cur) >= 1
      else if (r.kind == "copies") true
      else false
    // a, a removal, cuts off b: it names b's signer and saw fewer of its records.
    pure def cutsOff(a: Record, b: Record): bool =
      a.kind == "revoke" and a.signer != b.signer and a.target == b.signer and seenOf(a, b.signer) < b.seq
    val rootActs = rs.filter(r => rootRec(r) and r.kind == "revoke")
    val toLabel = rs.filter(r => isAdmin(r) and counted(r))
    val outFirst = toLabel.filter(b => not(permitted(b)) or rootActs.exists(a => cutsOff(a, b)))
    pure def attackers(b: Record): Set[Record] =
      if (b.kind == "claim") Set()
      else toLabel.filter(a => not(outFirst.contains(a)) and cutsOff(a, b))
    // The grounded labelling of the admins' removals.
    val labels = 0.to(MAXREC).fold((Set(), outFirst), (io, i) => {
      val open = toLabel.exclude(io._1).exclude(io._2)
      val newOut = open.filter(b => attackers(b).exists(a => io._1.contains(a)))
      val newIn = open.filter(b => attackers(b).forall(a => io._2.contains(a)))
      (io._1.union(newIn), io._2.union(newOut))
    })
    val ins = labels._1
    val undecided = toLabel.exclude(ins).exclude(labels._2)
    val adminConflict = undecided.exists(r => r.kind == "revoke")
    pure def counts(r: Record): bool = rootRec(r) or (isAdmin(r) and ins.contains(r))
    val revoked = rs.filter(r => r.kind == "revoke" and counts(r)).map(r => r.target)
    // The claims under this root.
    pure def cancelled(c: Record): bool = rs.exists(r => r.signer == cur and rootRec(r)
      and ((r.kind == "resolve" and r.targetRec == c.id) or (r.kind == "revoke" and r.target == c.signer)))
    pure def voidRoot(c: Record): bool =
      c.target == c.signer or onList(path, c.target)
        or rs.exists(r => r.signer == c.target and isAdmin(r))
        or rs.exists(r => (r.kind == "device" or r.kind == "admin") and r.target == c.target)
    val here = rs.filter(c => c.kind == "claim" and isAdmin(c) and seenOf(c, cur) >= 1 and (counted(c) or voids.contains(c.id)))
    val voided = here.filter(c => voidRoot(c) or (not(cancelled(c)) and labels._2.contains(c)))
    val cancels = here.filter(c => not(voidRoot(c)) and cancelled(c))
    val live = here.exclude(voided).exclude(cancels)
    val again = live.filter(c => live.exists(o => o.signer == c.signer and (o.seq < c.seq or (o.seq == c.seq and o.id < c.id))))
    val one = live.exclude(again)
    pure def removalsOf(k: Key): Set[Record] = rs.filter(r => r.kind == "revoke" and isAdmin(r) and ins.contains(r) and r.target == k)
    val seenRemoved = one.filter(c => removalsOf(c.signer).exists(rm => seenOf(c, rm.signer) >= rm.seq))
    val kept = one.exclude(seenRemoved)
    val later = kept.filter(c => kept.exists(o => o != c and seenOf(c, o.signer) >= o.seq))
    val first = kept.exclude(later)
    pure def disputed(c: Record): bool = removalsOf(c.signer).exists(rm => seenOf(c, rm.signer) < rm.seq)
    pure def heldOf(c: Record): int = if (held.keys().contains(c.id)) held.get(c.id) else 0
    val voidIds = idsOf(voided.union(again).union(seenRemoved).union(later))
    val competing = first.size() > 1
    val alone = if (first.size() == 1) first else Set()
    val disputes = alone.filter(c => disputed(c))
    val ready = alone.filter(c => not(disputed(c)) and ins.contains(c) and heldOf(c) >= DELAY)
    val full = path.length() >= MAXPATH
    val effective = if (full) Set() else ready
    val claims = idsOf(here).mapBy(i =>
      if (voidIds.contains(i) or (full and idsOf(ready).contains(i))) "void"
      else if (idsOf(cancels).contains(i)) "cancelled"
      else if (competing) "competing"
      else if (idsOf(disputes).contains(i)) "disputed"
      else if (idsOf(effective).contains(i)) "effective"
      else "pending")
    val devices = rs.filter(r => r.kind == "device" and counts(r) and not(revoked.contains(r.target))).map(r => r.target)
    {
      view: {
        path: path,
        counting: idsOf(rs.filter(r => counts(r))).union(idsOf(effective)),
        revoked: revoked,
        admins: adm.keys().filter(a => not(revoked.contains(a))).mapBy(a => adm.get(a)),
        stop: adminConflict or competing or disputes != Set(),
        claims: claims,
        devices: devices,
        commanders: adm.keys().union(Set(cur)).filter(k => not(revoked.contains(k))
          and (k == cur or not(adminConflict or competing or disputes != Set()))),
        rootsCount: rs.filter(r => rootRec(r) and r.signer == cur).forall(r => counts(r)),
        cuts: cuts,
      },
      next: effective.fold("", (k, c) => c.target),
      cut: effective.fold(0, (n, c) => seenOf(c, cur)),
    }
  }

  pure def merge(a: Id -> str, b: Id -> str): Id -> str =
    a.keys().union(b.keys()).mapBy(i => if (b.keys().contains(i)) b.get(i) else a.get(i))

  // Turns records into the group's state: an epoch for each root on the path, the claims of
  // the earlier roots kept.
  pure def evaluate(rs: Set[Record], adminKeys: Set[Key], held: Id -> int): View = {
    val e1 = epoch(rs, adminKeys, held, [ROOT], Map())
    if (e1.next == "") e1.view
    else {
      val p2 = [ROOT, e1.next]
      val c2 = Map(ROOT -> e1.cut)
      val e2 = epoch(rs, adminKeys, held, p2, c2)
      if (e2.next == "") { ...e2.view, claims: merge(e1.view.claims, e2.view.claims) }
      else {
        val e3 = epoch(rs, adminKeys, held, p2.append(e2.next), c2.put(e1.next, e2.cut))
        { ...e3.view, claims: merge(merge(e1.view.claims, e2.view.claims), e3.view.claims) }
      }
    }
  }

  // A member's state: its set evaluated with the keys it learned (the evaluation keeps again
  // what the set holds, as the core's does).
  pure def storeView(s: Store, db: Id -> Record): View = {
    val kept = keepAfter(recsOf(s.recs, db), ceilings(s.promoted, s.admins), NOCUT)._1
    evaluate(recsOf(kept, db), s.admins, s.held)
  }

  // What a member given every record of got at once keeps, and its state (core evaluate).
  pure def pureKept(got: Set[Id], promoted: Set[Key], db: Id -> Record): Set[Id] = {
    val rs = recsOf(got, db)
    val ar = learnAll(rs)
    val checked = rs.filter(r => roleOf(ar._1, ar._2, r.signer) != "")
    keepAfter(checked, ceilings(promoted, ar._1), NOCUT)._1
  }
  pure def pureView(got: Set[Id], promoted: Set[Key], held: Id -> int, db: Id -> Record): View = {
    val ar = learnAll(recsOf(got, db))
    evaluate(recsOf(pureKept(got, promoted, db), db), ar._1, held)
  }

  // --- The system ------------------------------------------------------------------------

  var db: Id -> Record
  var nextId: int
  var st: str -> Store
  // Each member's state, kept with its set.
  var views: str -> View
  // The keys a root's removal took, as each member saw it: history for promise 2.
  var gone: str -> Set[Key]

  pure val EMPTY: Store = {
    recs: Set(), got: Set(), cut: NOCUT, promoted: Set(), admins: Set(), roots: Set(ROOT), held: Map(),
  }

  pure def rootRemoved(v: View, db: Id -> Record): Set[Key] =
    recsOf(v.counting, db).filter(r => r.kind == "revoke" and onList(v.path, r.signer)).map(r => r.target)

  // Member m's set becomes s2 (by record r, or by none when r is 0).
  action commit(db2: Id -> Record, n2: int, m: str, s2: Store, r: Id): bool = {
    val v2 = storeView(s2, db2)
    all {
      db' = db2,
      nextId' = n2,
      st' = st.put(m, s2),
      views' = views.put(m, v2),
      gone' = gone.put(m, gone.get(m).union(rootRemoved(v2, db2))),
    }
  }

  pure def rec(id: Id, signer: Key, seq: int, kind: str, target: Key, kit: str, targetRec: Id, seen: Key -> int, units: int): Record =
    { id: id, signer: signer, seq: seq, kind: kind, target: target, kit: kit, targetRec: targetRec, seen: seen, units: units }

  // The group as the root made it: A a phone admin, C a computer admin, K the recovery key.
  pure val START: Id -> Record = Map(
    1 -> rec(1, ROOT, 1, "admin", PHONE, "phone", 0, Map(), 1),
    2 -> rec(2, ROOT, 2, "admin", COMPUTER, "computer", 0, Map(), 1),
    3 -> rec(3, ROOT, 3, "recovery", RECOVERY, "", 0, Map(), 1),
  )
  pure def offerAll(s: Store, l: List[Id], db: Id -> Record): Store = l.foldl(s, (x, i) => insertInto(x, db.get(i), db))
  pure val STARTSTORE: Store = offerAll(EMPTY, [1, 2, 3], START)

  action init = all {
    db' = START,
    nextId' = 4,
    st' = MEMBERS.mapBy(m => STARTSTORE),
    views' = MEMBERS.mapBy(m => storeView(STARTSTORE, START)),
    gone' = MEMBERS.mapBy(m => Set()),
  }

  // k signs a record; its own device stores it at once. seen is what that device holds, or,
  // for a thief, what it holds with the other admins' records hidden.
  action sign(k: Key, kind: str, target: Key, kit: str, targetRec: Id, pretend: bool, units: int): bool = {
    val h = HOLDER.get(k)
    val s = st.get(h)
    val mine = recsOf(s.recs, db)
    val seen0 = SIGNERS.mapBy(x => ofKey(mine, x).fold(0, (m, r) => max2(m, r.seq)))
    val seen = if (pretend) seen0.keys().mapBy(x =>
        if (x != k and (x == PHONE or x == COMPUTER or x == RECOVERY)) 0 else seen0.get(x))
      else seen0
    val seq = db.keys().filter(i => db.get(i).signer == k).size() + 1
    val r = rec(nextId, k, seq, kind, target, kit, targetRec, seen.put(k, seq - 1), units)
    val db2 = db.put(nextId, r)
    all {
      nextId <= MAXREC,
      commit(db2, nextId + 1, h, insertInto(s, r, db2), nextId),
    }
  }

  action signDevice = nondet k = Set(ROOT, PHONE, COMPUTER, "NA", "NK").oneOf() sign(k, "device", DEVICE, "", 0, false, 1)
  // A root (or a thief) names an admin; a root may name again an admin it removed.
  action signAdmin = nondet k = Set(ROOT, PHONE, "NA").oneOf() nondet a = Set(PHONE, COMPUTER).oneOf()
    nondet kit = Set("phone", "computer").oneOf() sign(k, "admin", a, kit, 0, false, 1)
  action signRevoke = nondet k = SIGNERS.oneOf() nondet t = Set(PHONE, COMPUTER, RECOVERY, DEVICE).oneOf()
    nondet p = Set(true, false).oneOf() sign(k, "revoke", t, "", 0, p, 1)
  // A root voids a record: a claim, an admin's removal, or any other.
  action signResolve = nondet k = Set(ROOT, "NA", "NK").oneOf() nondet i = db.keys().oneOf()
    sign(k, "resolve", "", "", i, false, 1)
  action signClaim = nondet k = Set(PHONE, COMPUTER, RECOVERY).oneOf() nondet t = Set("NA", "NK", COMPUTER).oneOf()
    nondet p = Set(true, false).oneOf() sign(k, "claim", t, "", 0, p, CLAIMU)
  action signCopies = nondet k = SIGNERS.oneOf() nondet u = Set(1, 2).oneOf() sign(k, "copies", "", "", 0, false, u)

  // Member m is offered record i.
  action give(m: str, i: Id): bool = commit(db, nextId, m, insertInto(st.get(m), db.get(i), db), i)

  // Sync: a member is offered a record it does not keep (again, perhaps).
  action deliver = nondet m = MEMBERS.oneOf() nondet i = db.keys().oneOf() all {
    not(st.get(m).recs.contains(i)),
    commit(db, nextId, m, insertInto(st.get(m), db.get(i), db), i),
  }

  // A member's own count goes on for the claims it holds (it caps at DELAY + 1).
  action tick = nondet m = MEMBERS.oneOf() tickAt(m)
  action tickAt(m: str): bool = {
    val s = st.get(m)
    val cs = s.recs.filter(i => db.get(i).kind == "claim")
    val held = s.held.keys().union(cs).mapBy(i =>
      if (cs.contains(i)) min2(DELAY + 1, (if (s.held.keys().contains(i)) s.held.get(i) else 0) + 1) else s.held.get(i))
    commit(db, nextId, m, { ...s, held: held }, 0)
  }

  // A member gives the roots its state puts on the path a root's room.
  action compact = nondet m = MEMBERS.oneOf() compactAt(m)
  action compactAt(m: str): bool = commit(db, nextId, m, compactStore(st.get(m), views.get(m), db), 0)

  action step = any {
    signDevice, signAdmin, signRevoke, signResolve, signClaim, signCopies,
    deliver, deliver, deliver, tick, compact,
  }

  // --- Promises --------------------------------------------------------------------------

  // A member that every record it was offered would leave as it is.
  def saturated(m: str): bool = {
    val s = st.get(m)
    s.got.forall(i => insertInto(s, db.get(i), db).recs == s.recs)
  }

  // 1. One set, one state.
  val oneState = MEMBERS.forall(m => {
    val s = st.get(m)
    saturated(m) implies (s.recs == pureKept(s.got, s.promoted, db) and views.get(m) == pureView(s.got, s.promoted, s.held, db))
  })

  // 2. A key a root removed stays removed, unless a takeover cut the removal off: the new root
  // takes the old root's records up to what the claim had seen, and no further.
  pure def cutOff(v: View, r: Record): bool = v.cuts.keys().contains(r.signer) and r.seq > v.cuts.get(r.signer)
  val removedStayOut = MEMBERS.forall(m => {
    val v = views.get(m)
    val removals = recsOf(st.get(m).got, db).filter(r => r.kind == "revoke" and ROOT_KEYS.contains(r.signer))
    gone.get(m).forall(k =>
      removals.filter(r => r.target == k).forall(r => cutOff(v, r))
        or (v.revoked.contains(k) and not(v.admins.keys().contains(k)) and not(v.devices.contains(k))))
  })

  // 3. Members that keep the same records have one root, or one waits out a claim.
  val oneRoot = MEMBERS.forall(m1 => MEMBERS.forall(m2 => {
    val p1 = views.get(m1).path
    val p2 = views.get(m2).path
    st.get(m1).recs == st.get(m2).recs implies (isPrefix(p1, p2) or isPrefix(p2, p1))
  }))

  // 4. A claim counts only after the member held it for the delay.
  val claimWaits = MEMBERS.forall(m => {
    val v = views.get(m)
    val held = st.get(m).held
    v.claims.keys().forall(i => v.claims.get(i) == "effective" implies (held.keys().contains(i) and held.get(i) >= DELAY))
  })

  // 5. During a full stop only the current root's commands run (members exchange records
  // only; copies, commands of admins and admissions stop), and the root's records still count.
  // Admins' records still count in the state (owner, 11.11: the stop stays as it is).
  val stopRootOnly = MEMBERS.forall(m => {
    val v = views.get(m)
    v.rootsCount and (v.stop implies v.commanders.forall(k => k == last(v.path)))
  })

  // 6. No key takes another key's room.
  val fairRoom = MEMBERS.forall(m => {
    val s = st.get(m)
    val rs = recsOf(s.recs, db)
    val ceil = ceilings(s.promoted, s.admins)
    val got = recsOf(s.got, db)
    val owners = got.map(r => r.signer).filter(k => ceil.keys().contains(k))
    val fair = if (owners.size() == 0) ROOM else ROOM / owners.size()
    val named = rs.filter(r => r.kind == "claim").map(r => r.target)
    and {
      // A claimed root's records are paid ahead by its claim's units.
      sumUnits(rs.filter(r => ceil.keys().contains(r.signer))) <= ROOM,
      rs.map(r => r.signer).forall(k =>
        if (ceil.keys().contains(k)) sumUnits(ofKey(rs, k)) <= ceil.get(k)
        else named.contains(k) and sumUnits(ofKey(rs, k)) <= FUTURE),
      saturated(m) implies owners.forall(k =>
        sumUnits(ofKey(rs, k)) + MAXU - 1 >= min2(fair, min2(ceil.get(k), sumUnits(ofKey(got, k))))),
    }
  })

  val promises = and { oneState, removedStayOut, oneRoot, claimWaits, stopRootOnly, fairRoom }

  // --- Scenarios (core tests run the same: core/tests/records_model.rs) ------------------

  def claimState(m: str, i: Id): str = if (views.get(m).claims.keys().contains(i)) views.get(m).claims.get(i) else "none"

  // The recovery key claims a group whose root is lost: the claim waits until the member has
  // held it for the delay, then its new root takes over.
  run recoveryKeyTakesOverTest =
    init
      .then(sign(RECOVERY, "claim", "NK", "", 0, false, CLAIMU))
      .then(give("m", 4))
      .then(tickAt("m"))
      .expect(claimState("m", 4) == "pending" and views.get("m").path == [ROOT])
      .then(tickAt("m"))
      .expect(claimState("m", 4) == "effective" and views.get("m").path == [ROOT, "NK"] and promises)

  // A computer admin has no takeover: its claim is void however long it is held.
  run computerCannotTakeOverTest =
    init
      .then(sign(COMPUTER, "claim", "NK", "", 0, false, CLAIMU))
      .then(give("m", 4))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(claimState("m", 4) == "void" and views.get("m").path == [ROOT] and not(views.get("m").stop))

  // Two claims stop the group; the root's records still count, and its resolve ends the stop.
  run competingClaimsStopTest =
    init
      .then(sign(PHONE, "claim", "NA", "", 0, false, CLAIMU))
      .then(sign(RECOVERY, "claim", "NK", "", 0, false, CLAIMU))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(views.get("m").stop and claimState("m", 4) == "competing" and claimState("m", 5) == "competing")
      .then(sign(ROOT, "device", DEVICE, "", 0, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, 1))
      .then(give("m", 6))
      .then(give("m", 7))
      .expect(views.get("m").stop and views.get("m").revoked.contains(DEVICE))
      .then(sign(ROOT, "resolve", "", "", 4, false, 1))
      .then(give("m", 8))
      .expect(not(views.get("m").stop) and claimState("m", 4) == "cancelled" and claimState("m", 5) == "effective"
        and views.get("m").path == [ROOT, "NK"])

  // A phone admin that had not seen a claim removes the claimant: the claim is disputed and
  // the group stops.
  run objectionDisputesTest =
    init
      .then(sign(RECOVERY, "claim", "NK", "", 0, false, CLAIMU))
      .then(sign(PHONE, "revoke", RECOVERY, "", 0, false, 1))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .expect(claimState("m", 4) == "disputed" and views.get("m").stop and views.get("m").path == [ROOT])

  // A device the root removed does not come back by a new record for its key.
  run removedDeviceStaysOutTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, 1))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, 1))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE)
        and gone.get("m").contains(DEVICE) and promises)

  // A claimed root keeps only what its claim paid ahead until the claim counts and the member
  // gives it a root's room.
  run claimedRootRoomTest =
    init
      .then(sign(RECOVERY, "claim", "NK", "", 0, false, CLAIMU))
      .then(give("k", 4))
      .then(sign("NK", "device", DEVICE, "", 0, false, 1))
      .then(sign("NK", "copies", "", "", 0, false, 1))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .expect(st.get("m").recs.contains(5) and not(st.get("m").recs.contains(6)))
      .then(tickAt("m"))
      .then(tickAt("m"))
      .then(compactAt("m"))
      .then(give("m", 6))
      .expect(views.get("m").path == [ROOT, "NK"] and st.get("m").recs.contains(6) and views.get("m").devices.contains(DEVICE))

  // A removal by an admin is not final: the root's resolve voids it, and the device counts
  // again under its old key. A removal by the root is final: its resolve changes nothing.
  run removalsByAdminAndRootTest =
    init
      .then(sign(COMPUTER, "device", DEVICE, "", 0, false, 1))
      .then(sign(COMPUTER, "revoke", DEVICE, "", 0, false, 1))
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE))
      .then(sign(ROOT, "resolve", "", "", 5, false, 1))
      .then(give("m", 6))
      .expect(views.get("m").devices.contains(DEVICE) and not(views.get("m").revoked.contains(DEVICE)))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, 1))
      .then(give("m", 7))
      .then(sign(ROOT, "resolve", "", "", 7, false, 1))
      .then(give("m", 8))
      .expect(not(views.get("m").devices.contains(DEVICE)) and views.get("m").revoked.contains(DEVICE) and promises)
}
