// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok
//
// A model of handing the group over in records v:2 (docs/protocol.md, section 10, "Handing the group
// over"), in Quint (https://quint-lang.org). It is not the code: it states the rules for
// claims as the specification words them and lets the simulator try every way a few devices
// can sign, sync and wait, checking the promises the specification makes about them.
//
// Who is in it: the root R, which may act or stay silent (lost); two admins, A and B, each
// with `takeover` and `remove-admins`, so each may claim the group and each may remove the
// other; and the new roots their claims name, NA and NB, whose keys the claimants hold, so
// a claimed root can sign before its claim takes effect. Any admin may be a thief: a
// claimant may pretend in `seen` not to have held the other admin's records. The rest of the
// rules (admin attacks, freezes, two histories) are left out: a removal here counts.
//
// Run it (CI's `model` job does):
//
//	quint test --backend=typescript docs/model/claims.qnt
//	quint run --backend=typescript --invariant=promises --max-steps=12 --max-samples=20000 docs/model/claims.qnt
module claims {
  type Key = str
  type Record = {
    id: int,
    signer: Key,
    seq: int,
    kind: str, // "claim", "revoke", "resolve", "device"
    target: Key, // revoke: the removed key
    targetRec: int, // resolve: the voided record
    seen: Key -> int, // the highest seq of each signer the author held (or says it held)
    newRoot: Key, // claim: the claimed root
  }

  pure val ROOT = "R"
  pure val ADMINS = Set("A", "B")
  pure val NEWROOT = Map("A" -> "NA", "B" -> "NB")
  pure val KEYS = Set("R", "A", "B", "NA", "NB")
  pure val MAXRECORDS = 7

  // Every record signed so far, what each key's device holds, the next record ID, and
  // whether the delay has passed on the member that evaluates.
  var recs: Set[Record]
  var held: Key -> Set[int]
  var nextId: int
  var elapsed: bool

  // --- Evaluation, on a member that holds every record -----------------------------------

  def ofSigner(k: Key): Set[Record] = recs.filter(r => r.signer == k)
  def maxSeq(ids: Set[int], k: Key): int =
    recs.filter(r => r.signer == k and ids.contains(r.id)).fold(0, (m, r) => if (r.seq > m) r.seq else m)
  def heldSeen(k: Key): Key -> int = KEYS.mapBy(s => maxSeq(held.get(k), s))
  // "A record r happened before s when s's seen names r's signer with a seq of r's seq or more."
  def sawRec(s: Record, r: Record): bool = s.seen.get(r.signer) >= r.seq

  def claims: Set[Record] = recs.filter(r => r.kind == "claim")
  def resolvedByRoot(x: Record): bool =
    recs.exists(r => r.signer == ROOT and r.kind == "resolve" and r.targetRec == x.id)
  // "cancelled for good when the current root's own key signs a resolve that names it, or a
  // revoke of the claimant's admin key"
  def cancelled(c: Record): bool =
    resolvedByRoot(c) or recs.exists(r => r.signer == ROOT and r.kind == "revoke" and r.target == c.signer)
  // The counting admin removals of a claimant: another admin's revoke that the root did not void.
  def adminRemovals(c: Record): Set[Record] =
    recs.filter(r => r.kind == "revoke" and ADMINS.contains(r.signer) and r.target == c.signer and not(resolvedByRoot(r)))
  // "void ... when its author had seen a counting admin revoke or freeze of its own admin key
  // ..., or when its author had seen another claim under the same root that is not void or
  // cancelled". Two admins hold two claims at most here, so one level of the recursion does.
  def voidBase(c: Record): bool = adminRemovals(c).exists(rm => sawRec(c, rm))
  def void(c: Record): bool =
    voidBase(c) or claims.exists(o => o.id != c.id and sawRec(c, o) and not(cancelled(o)) and not(voidBase(o)))
  def live(c: Record): bool = not(cancelled(c)) and not(void(c))
  // "disputed when a counting admin revoke or freeze names the claimant's admin key or member
  // key and the claimant had not seen it, whatever else its author had seen"
  def disputed(c: Record): bool = adminRemovals(c).exists(rm => not(sawRec(c, rm)))
  def liveClaims: Set[Record] = claims.filter(c => live(c))
  // "takes effect when the delay has passed on that member and it is none of the above, it is
  // the only such claim under the current root"
  def effective(c: Record): bool = elapsed and live(c) and not(disputed(c)) and liveClaims.size() == 1
  // "Two claims under one root that are neither void nor cancelled stop the group fully ...
  // A disputed claim stops the group the same way."
  def stopFull: bool = liveClaims.size() >= 2 or liveClaims.exists(c => disputed(c))

  // --- Promises --------------------------------------------------------------------------

  // "the root always wins"
  val rootWins = claims.forall(c => cancelled(c) implies not(effective(c)))
  // "An admin who objects to a claim removes the claimant, and the group stops fully until the
  // current root decides" (for a claim that is not void anyway: a void claim counts for nothing)
  val objectionStops = claims.forall(c =>
    adminRemovals(c).exists(rm => not(sawRec(c, rm))) and live(c)
      implies (not(effective(c)) and stopFull))
  // "a claim made after its author's removal counts for nothing"
  val removedCannotClaim = claims.forall(c => adminRemovals(c).exists(rm => sawRec(c, rm)) implies not(effective(c)))
  // "a second claim ... stops the group instead of choosing"
  val twoClaimsStop = liveClaims.size() >= 2 implies (stopFull and claims.forall(c => not(effective(c))))
  val atMostOneEffective = claims.filter(c => effective(c)).size() <= 1
  val promises = rootWins and objectionStops and removedCannotClaim and twoClaimsStop and atMostOneEffective

  // --- Actions ---------------------------------------------------------------------------

  // k signs a record that the devices in holders hold at once, with seen as given and its
  // own entry its previous seq.
  action signAs(k: Key, holders: Set[Key], kind: str, target: Key, targetRec: int, newRoot: Key, seen: Key -> int): bool = {
    val n = ofSigner(k).size()
    val r = { id: nextId, signer: k, seq: n + 1, kind: kind, target: target, targetRec: targetRec,
              seen: seen.put(k, n), newRoot: newRoot }
    all {
      nextId < MAXRECORDS,
      recs' = recs.union(Set(r)),
      held' = KEYS.mapBy(h => if (holders.contains(h)) held.get(h).union(Set(nextId)) else held.get(h)),
      nextId' = nextId + 1,
      elapsed' = elapsed,
    }
  }

  // An admin claims the group, honestly or pretending it held none of the other admin's records.
  action claim = nondet a = ADMINS.oneOf() nondet pretend = Set(true, false).oneOf() {
    val seen = heldSeen(a)
    val told = if (pretend) KEYS.mapBy(k => if (ADMINS.contains(k) and k != a) 0 else seen.get(k)) else seen
    all {
      not(claims.exists(c => c.signer == a)),
      signAs(a, Set(a, NEWROOT.get(a)), "claim", "", 0, NEWROOT.get(a), told),
    }
  }

  // A claimed root's key signs a record while its claim is still pending.
  action claimedRootSigns = nondet c = claims.oneOf() {
    val k = c.newRoot
    all { ofSigner(k).size() < 1, signAs(k, Set(k, c.signer), "device", "", 0, "", heldSeen(k)) }
  }

  // An admin objects to the other's claim: it removes the claimant, with seen as it holds it
  // (it synced first, as the apps do).
  action object = nondet c = claims.oneOf() nondet a = ADMINS.exclude(Set(c.signer)).oneOf() all {
    not(recs.exists(r => r.kind == "revoke" and r.signer == a)),
    signAs(a, Set(a), "revoke", c.signer, 0, "", heldSeen(a)),
  }

  // The root, when it is not lost, cancels a claim, removes a claimant or voids a removal.
  action rootCancels = nondet c = claims.oneOf() signAs(ROOT, Set(ROOT), "resolve", "", c.id, "", heldSeen(ROOT))
  action rootRemoves = nondet c = claims.oneOf() signAs(ROOT, Set(ROOT), "revoke", c.signer, 0, "", heldSeen(ROOT))
  action rootVoidsRemoval = nondet r = recs.filter(x => x.kind == "revoke" and ADMINS.contains(x.signer)).oneOf()
    signAs(ROOT, Set(ROOT), "resolve", "", r.id, "", heldSeen(ROOT))

  // Sync: a device receives a record it lacks.
  action deliver = nondet k = KEYS.oneOf() nondet r = recs.oneOf() all {
    not(held.get(k).contains(r.id)),
    held' = held.put(k, held.get(k).union(Set(r.id))),
    recs' = recs, nextId' = nextId, elapsed' = elapsed,
  }

  // The claims' delay passes on the member that evaluates.
  action delayPasses = all { not(elapsed), elapsed' = true, recs' = recs, held' = held, nextId' = nextId }

  action init = all {
    recs' = Set(), held' = KEYS.mapBy(k => Set()), nextId' = 1, elapsed' = false,
  }

  action step = any {
    claim, claimedRootSigns, object, rootCancels, rootRemoves, rootVoidsRemoval, deliver, delayPasses,
  }

  // --- Scenarios -------------------------------------------------------------------------

  // The claimed root signs at once; the objecting admin syncs before it removes the claimant,
  // so its seen names the claimed root. The removal still disputes the claim.
  run objectionAfterClaimedRootSignedTest =
    init
      .then(signAs("A", Set("A", "NA"), "claim", "", 0, "NA", KEYS.mapBy(k => 0)))
      .then(signAs("NA", Set("NA", "A"), "device", "", 0, "", KEYS.mapBy(k => 0)))
      .then(all { held' = held.put("B", Set(1, 2)), recs' = recs, nextId' = nextId, elapsed' = elapsed })
      .then(signAs("B", Set("B"), "revoke", "A", 0, "", heldSeen("B")))
      .then(delayPasses)
      .expect(claims.forall(c => disputed(c) and not(effective(c))) and stopFull and promises)

  // Nobody objects and the root is lost: the claim takes effect once the delay has passed.
  run unopposedClaimTakesEffectTest =
    init
      .then(signAs("A", Set("A", "NA"), "claim", "", 0, "NA", KEYS.mapBy(k => 0)))
      .then(delayPasses)
      .expect(claims.forall(c => effective(c)) and not(stopFull))

  // The root voids the objection: the claim goes on.
  run rootVoidsObjectionTest =
    init
      .then(signAs("A", Set("A", "NA"), "claim", "", 0, "NA", KEYS.mapBy(k => 0)))
      .then(signAs("B", Set("B"), "revoke", "A", 0, "", KEYS.mapBy(k => 0)))
      .then(signAs(ROOT, Set(ROOT), "resolve", "", 2, "", KEYS.mapBy(k => 0)))
      .then(delayPasses)
      .expect(claims.forall(c => effective(c)) and not(stopFull))

  // Two claims stop the group, whatever their delay.
  run twoClaimsTest =
    init
      .then(signAs("A", Set("A", "NA"), "claim", "", 0, "NA", KEYS.mapBy(k => 0)))
      .then(signAs("B", Set("B", "NB"), "claim", "", 0, "NB", KEYS.mapBy(k => 0)))
      .then(delayPasses)
      .expect(stopFull and claims.forall(c => not(effective(c))))

  // A claim whose author had seen its own removal counts for nothing.
  run claimAfterRemovalTest =
    init
      .then(signAs("B", Set("B", "A"), "revoke", "A", 0, "", KEYS.mapBy(k => 0)))
      .then(signAs("A", Set("A", "NA"), "claim", "", 0, "NA", heldSeen("A")))
      .then(delayPasses)
      .expect(claims.forall(c => void(c) and not(effective(c))) and not(stopFull))
}
