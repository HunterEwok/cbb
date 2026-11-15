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
//  2. A device or admin a root removed never returns through an old record: once a root's
//     removal of a key counts on a member, the key (and the other key of its device) counts
//     there again only by an admission newer than that removal, whatever comes, unless a change
//     of root left the removal off its list (rule 33, point 6), or the current root's counting
//     checkpoint keeps an old admission of the key and leaves out every root removal naming it
//     (the root brought it back itself). A counting checkpoint may prune the removal with the
//     key's records; a replay of them is refused unless the waiting checkpoint names it. A
//     removal by an admin is not final: a root may void it.
//  1b. Sync converges: a member that fetched, to no change, what its peers list and what its
//     missing() names keeps what a member given at once every record some member holds keeps.
//     With the honest writer (it never keeps what it pruned, never lowers a head, keeps what
//     counts) this holds with no assumption. Otherwise it holds when, from the newest checkpoint
//     of the current root that can become whole on, what the waiting checkpoints name outside
//     the rooms fits one ROOM.
//  1c. A newer checkpoint that is not whole takes nothing from the counting one.
//  3. One chain, one state: two members that hold the same recovery chain and keep the same
//     records are in one state.
//  5. During a stop of the admins only the current root's commands run, and its records still
//     count; during a full stop (two recovery records at one seq) nothing runs.
//  6. No key takes another key's room: every key with room keeps at least its fair share (or
//     all it made, or its ceiling); only the roots on the path and the admin keys they name
//     have room; the set never holds more than its room. Recovery records live outside it.
//     A halted set keeps what it had (promise 11), so the fair share is asked of the others.
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
//     same records and hold the new root's first checkpoint are in one state. A counting
//     checkpoint compacts as it comes, so neither keeps what it left out.
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
// Stated limits (what the promises do not claim):
//
//  - A deviant recovery key may bring a removed key back. The recovery key is above the root in
//    the trust order: a change whose list drops a cut root's counting removal and re-signs
//    nothing (signChain mode "from1", kit "deviant") makes the removed key's records count
//    again, and removedGainsNothing fails (k.11115 on 1612ae59, five steps: the root removes A;
//    A signs device D; sync; the honest change to NK re-signs the removal; the deviant change
//    to NA lists neither). The honest change is clean on the same trace, and so is the deviant
//    one under FIXED_CAPS, where A's room is 0 once removed (deviantRecoveryBringsBackTest).
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
    // recover: the ID of the new root's first checkpoint, which its writer signs before the
    // head (format 20.3, field 13). Every head the model signs names one; 0 only in the
    // writer's own look ahead at what it will count.
    first: Id,
    // (I): the ID of its key's record it follows (its key's last record its writer's set
    // kept), -1 for none (it follows the head); 0 when the model does not use it.
    follows: Id,
    // Signed off its key's device (a second writer on the key: signHidden); the model's mark.
    off: bool,
    // A removal's further keys beside target (REISSUE_REMOVALS packs several removals into one).
    also: Set[Key],
    // (DROPS_EPOCH, candidate E: a checkpoint's count of the removals left out along its root's
    // checkpoints; a device record's epoch, the highest count its writer held.)
    drops: int,
    epoch: int,
    // (FLAG: an admin or device record says 0, an admission, or 1, an update of a key that
    // already counted at its writer.)
    flag: int,
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
    wait: Set[Id], // the newest checkpoint of the current root that does not count yet, and the records it names that the rooms turned away
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
  pure val SIGNERS = Set("R", "A", "C", "C2", "W", "NA", "NK", "X").union(if (SPARE) Set("A1", "A2", "C3") else Set())
  // NB: a fourth root key, only for a third change in the scenarios (it signs nothing else and
  // is not among SIGNERS; the random steps never name it).
  pure val ROOT_KEYS = Set("R", "NA", "NK", "NB")
  pure val RKEYS = Set("K")
  pure val THIEVES = Set("A", "C", "C2", "W", "X")
  pure val HOLDER = Map("R" -> "r", "A" -> "a", "NA" -> "a", "X" -> "a", "C" -> "c", "C2" -> "c", "W" -> "c",
    "A1" -> "a", "A2" -> "a", "C3" -> "c",
    "K" -> "k", "NK" -> "k", "NB" -> "k")
  pure val MEMBERS = Set("r", "a", "c", "k", "m")
  // The device (its member key) of each admin key: C2 is a second admin key the root may name
  // for C's device in place of C.
  pure val DEV = Map("A" -> "dA", "C" -> "dC", "C2" -> "dC", "W" -> "dW", "X" -> "dX", "NA" -> "dN",
    "A1" -> "dA", "A2" -> "dA", "C3" -> "dC")
  pure val DEVS = Set("dA", "dC", "dW", "dX", "dN")

  // Under CEIL_FIT: ROOM 20 = the current root's 6 + the cut roots' reserve 6 + 4 admins at 2
  // (the records' 4096 = 1024 + 1024 + 8 x 256, scaled; architecture 16:50Z).
  // WIDE_ROOT: the root's room and the room 6 units wider, for the writer floor's promises: at
  // ROOTC 8 the floor (checkpoint 2 + margin 1, three admissions held) leaves 2 free units, so a
  // scenario that stops there says nothing about the core's 1536.
  pure val WIDE_ROOT = false
  // WIDE_ADMIN: sizes only, for scenarios whose admin records do not fit ADMINC 2 under
  // CEIL_FIT: each admin cap grows by 3 and the room by 3 for each live admin.
  pure val WIDE_ADMIN = false
  // ROOT_RATIO: sizes only, for REISSUE_STATE: the real root room against the state a change
  // re-issues is 1536 : (about 256 devices + 16 admin keys + the folded removals), about 5 : 1;
  // the model re-issues up to about 4-5 units (three admissions, a device, a freeze), so the
  // root's room (and with it the cut roots' reserve) is 24 at that ratio, the room 36 wider.
  pure val ROOT_RATIO = false
  pure val ROOM = (if (CEIL_FIT) 20 else 14) + (if (WIDE_ROOT) 6 else 0) + (if (WIDE_ADMIN) 12 else 0) + (if (ROOT_RATIO) 36 else 0)
  pure val ROOTC = (if (CEIL_FIT) 6 else 8) + (if (WIDE_ROOT) 6 else 0) + (if (ROOT_RATIO) 18 else 0)
  pure val ADMINC = (if (CEIL_FIT) 2 else 5) + (if (WIDE_ADMIN) 3 else 0)
  pure val MAXU = 2
  pure val TOP = ROOTC
  // (REISSUE_REMOVALS: the new roots' re-signed removals take IDs too.)
  pure val MAXREC = if (REISSUE_STATE) 28 else if (REISSUE_REMOVALS) 20 else 16
  pure val MAXCHAIN = 3

  // An ID no record ever has: a first checkpoint named and never released.
  pure val NEVER = 99
  pure val NOCUT: Cut = { level: TOP, marks: Map() }

  // In a full root's order, its removals, freezes and resolves before its checkpoints.
  pure val EARLY_BEFORE_CHECKPOINTS = true
  // A set takes a record its counting checkpoint settled when the waiting checkpoint names it
  // (review C, 11:33Z).
  pure val WAIT_TAKES_SETTLED = true
  // The bound of the place aside, in units (the core: one ROOM in all).
  pure val ASIDE_ROOM = ROOM
  // The place aside holds what a waiting checkpoint names: its keep and the record just below it
  // that it waits for (architecture 14:02Z; off: its keep only).
  pure val ASIDE_TAKES_WAITED = true
  // F-12: a held checkpoint above the counting one holds out the devices whose admissions it
  // prunes (architecture 13:09Z; proposed, off is the text as it stands).
  pure val F12 = false
  // The rule as it stood at 1e9c92a1, for the record: only the newest waiting checkpoint waits
  // (ONE_SLOT), and missing() names only what the newest waiting checkpoint keeps (N-7).
  pure val ONE_SLOT = false
  // Nothing that waits is put ahead of the rooms: waiting checkpoints enter them as ordinary
  // records after the counting checkpoint and what it names, and one the rooms turn away
  // waits aside, counted in the bound before what it names (architecture 14:31Z). Off: the
  // root's newest checkpoint is kept first beside the counting one, and when both do not fit
  // the rooms fall back to the plain rule and the members count no checkpoint
  // (everyWaitingTest).
  pure val NEWEST_ASIDE = true
  // A current root's checkpoint takes room only once it is whole for this purpose: every record
  // it keeps is held, and every record of its line is held or pruned by a held checkpoint of
  // its signer. Until then it waits aside (seed j.8004: a checkpoint that can never be whole
  // evicted whole records of its key from the rooms of a fresh member).
  pure val CP_ROOM_WHEN_WHOLE = false
  // A checkpoint names its key's record just below it (its prev) for the rooms only when it
  // keeps it: a prev it prunes takes no part of the rooms beside it and does not decide whether
  // it fits (seed j.8004: a fresh member holding a prev the checkpoint prunes found the counting
  // checkpoint over its signer's ceiling and counted none; one that had dropped it counted it).
  pure val PREV_ROOM_WHEN_KEPT = false
  // The chain applies its newest head whose first checkpoint is held; the heads below it need
  // none (the core, #530 c805311e). Off: every head needs its own.
  pure val FIRST_NEWEST_ONLY = false
  // Records of the roots that held heads name, got before the path reaches them, wait in one
  // root's room (ROOTC units), the root of the lowest recovery seq first, each root's records
  // in its own order; the rest are turned away until offered again. The first checkpoints the
  // heads wait for stay beside the chain, outside that room (#530 c805311e, seed 47). Off:
  // they wait in got without bound.
  pure val EARLY_ROOM = false
  // A waiting checkpoint the rooms turn away is skipped, not a stop: the records after it in its
  // key's order are judged without it (seed j.8001: a bent checkpoint that never becomes whole,
  // ahead of the root's newer records, took them out with it at the root's own device).
  pure val WAIT_SKIP = false
  // A set's memory of what its rooms dropped: "mark" (a key that dropped records turns away
  // its later ones and keeps claiming the dropped units), "none" (no memory: a record is judged
  // against the rooms as they are, as a member given everything at once would judge it), or
  // "lapse" (a key's mark is forgotten once the set holds no record of the key at or past it),
  // or "heads" (the part of a key's mark at or below the head the counting checkpoint names
  // for it lapses; architecture 14:42Z, (D)), or "gapless" (no marks; above the head of the
  // set's checkpoint a key counts only its gap-free run; architecture 14:55Z, (G)), or
  // "follows" (no marks; a record counts when what it follows is the head or counts, the
  // higher seq of two that follow the same record wins; architecture 15:07Z, (I)).
  pure val CUT_MODE = "mark"
  // (E): an honest writer never signs a record its own set would not keep (architecture
  // 14:46Z).
  pure val WRITER_KEEPS = false
  // (H): a writer signs only while its key's units above the counting checkpoint's head stay
  // within FLOOR, and the root admits at most MAX_ADMINS admin keys (architecture 15:00Z).
  pure val WRITER_FLOOR = false
  pure val FLOOR = 2
  pure val ROOT_FLOOR = 6
  pure val MAX_ADMINS = 4
  // (J): the ceilings of every key with room fit ROOM together, so the level never falls:
  // the writer of an admission refuses one that would break it (room for the current root
  // and RESERVE for the cut roots), the writer of a change of root lists the cut roots' records
  // within RESERVE (signChain), and no writer signs past its own ceiling
  // (the units its own set holds of the key with the new record, after what a new checkpoint
  // prunes; with WRITER_KEEPS, nor what its own set would not keep). Sizes: ROOM above.
  pure val CEIL_FIT = false
  // The core's change list today (architecture 11-13 20:42Z, break 1): a removal of keys no
  // record the writer holds names is left off the list. Off: every held root removal is
  // listed (the proposed rule, part a). On, a late admission makes a removed key count again.
  pure val CORE_LIST_FILTER = false
  // NEW_ROOT_ONLY (architecture 11-13 23:20Z, k.9521): no change names as new root a key already
  // on the path before it; the core's write_change refuses one ("the new root key must be a new
  // key") and eval::chain holds it void. Without it the model let the recovery key's holder
  // write a change back to the current root and sign that root's first checkpoint on a device
  // that does not hold the root key (two writers on one root key).
  pure val NEW_ROOT_ONLY = false
  // CUT_RESET_ON_DROP (k.9521, the part the core cannot take): the model's compaction forgot
  // the set's marks whenever its counting checkpoint changed; the core's RecordSet::compact
  // resets the cut only when the checkpoint drops a record.
  pure val CUT_RESET_ON_DROP = false
  // WHOLE_BY_SETTLER (records 11-13 23:35Z; the exhaustive-check thread's restart probe): a
  // head's first records (first checkpoint, Zs) a later checkpoint of the new root settled
  // count as held, so a member restarted from what it saves (which drops pruned first records)
  // rebuilds the same chain. `firstPrunedTest`, promise-like check `savedStable`.
  pure val WHOLE_BY_SETTLER = false
  // Core 066addaf: (a) a key whose admission the rooms turned away is no key of the set (the
  // store learns admin keys from what it holds, not from all it got); (b) the records of a key
  // that a waiting head names as root sit aside whatever order they came in, and are saved
  // (the model keeps them in got; a restart from what the set saves now keeps them too).
  pure val HELD_ADMISSIONS = false
  // Core #530 5eb8ab55 (architecture 11-14 08:43Z), all four decided:
  // EARLY_ASIDE: a record of a root that a held head names and the path does not list yet is held
  // aside (Waiting), not refused, and saved (`earlyAside`); this was HELD_ADMISSIONS' (b).
  pure val EARLY_ASIDE = false
  // SAVE_FIRSTS: the set always saves the first checkpoint of every change it holds, outside the
  // rooms; the new root's records below it (the Zs) a later counting checkpoint may prune, and a
  // settler covers that gap on restore (eval.rs first_gap).
  pure val SAVE_FIRSTS = false
  // FIRST_REQUIRED (eval.rs first_gap): the change's first checkpoint itself must be held; a
  // settler stands in only for the head's first records below it (the Zs).
  pure val FIRST_REQUIRED = false
  // SETTLER_HELD: a head's first records and their settlers count only among held records (rooms,
  // place aside, early records held aside), never among all the set got.
  pure val SETTLER_HELD = false
  // Architecture 11-14 03:00Z (records to word it): a root's room keeps removals and resolves
  // first, then the key's NEWEST checkpoint (and one newer being judged), then everything else
  // by seq; today every checkpoint of the current root goes first, so checkpoints that never
  // count could push out the root's device records. The marks compare positions, so a key's
  // marks reset when a newer checkpoint of it arrives. Promise `ownCpsNoCrowd`.
  pure val NEWEST_CP_FIRST = false
  // Records 066addaf: the core's write_checkpoint signs only as the set's last root. The model's
  // honest writer of a checkpoint first takes its own key's records and the recovery records
  // that made its key a root (the model hands a key's records to one member, its holder to
  // another), then signs only if its key is the set's last root.
  pure val WRITER_LAST_ROOT = false
  // Architecture 11-14 06:08Z (records to word it): a floor in the writer: a root's record (not a
  // removal) is refused when, after it, the root's records other than checkpoints plus its next
  // checkpoint would pass the root's ceiling, so the root can always checkpoint.
  // DECIDED 11-14 08:28Z (records aeeb8a85): a margin of the root's ceiling stays for removals
  // (1/24 of 1536 in the core, at least two exempt records; two units here).
  pure val WRITER_CP_FLOOR = false
  pure val CP_UNITS = 2
  pure val REMOVAL_MARGIN = 2
  // The model's honest keep without switches is the code's at aeeb8a85 (records 11-14 09:17Z):
  // every counting record below its key's head, minus the folded root removals (droppedAt), the
  // older removals a kept one covers and the admissions they removed; device versions, settings
  // history, admins' removals, resolves and freezes all stay.
  // CP_KEEP_LIVE (records' proposal, not decided): the honest root checkpoint also keeps only the
  // newest record of each device and of each writer's settings, and folds admins' removals with
  // the device records they removed.
  // Floor: the core's ordinary-record floor keeps 64 units (1/24 of the root's ceiling) beyond the
  // next checkpoint, at least two exempt records; the model's REMOVAL_MARGIN is two units.
  pure val CP_KEEP_LIVE = false
  // FIXED_CAPS (records b37218ee, architecture D2 11-14 12:50Z, DECIDED): the rooms are a pure
  // function of the records held, nothing remembered (no level, no marks). Outside the rooms: the
  // recovery chain, the fork proof, the firsts, and each root's checkpoint that may count with
  // what it names (pre per key). Roots first: the current root within ROOTC, the cut roots in one
  // room within RESERVE. The roster comes from the root records those rooms keep: the first
  // LIVE_MAX admin keys named, not removed and not taken back, by their newest admission's place
  // on the path and seq, at ADMINC each; every other key 0, what it signed staying only as far as
  // a root's checkpoint keeps it. Each key keeps its longest prefix of whole records, in its
  // order, within its cap less what it holds outside the rooms.
  // SHARE_REST (b37218ee's first wording, not default): the keys no longer admins share what the
  // live keys leave, min(ADMINC, (ROOM - ROOTC - RESERVE - ADMINC * live) / n2) each.
  pure val FIXED_CAPS = false
  pure val SHARE_REST = false
  // CP_KEEP (records b37218ee, keep v2): the current root's honest checkpoint keeps below the
  // heads what counts, except its own older checkpoints; a removal (a root's or an admin's)
  // strictly under its signer's head whose keys are all settled plain device keys, with their
  // admissions; a root removal a newer kept one covers; the root's copies but the newest; the
  // root's records of one device but the oldest and the newest; a resolve whose target goes.
  pure val CP_KEEP = false
  // CP_FIRST (architecture D2 11-14 12:50Z, DECIDED): before a root's removal or take-back of an
  // admin key, the honest writer checkpoints first, so that what that key signed stays as far as
  // the checkpoint keeps it once its cap is 0; a removal is never blocked: when the checkpoint
  // cannot be written, the removal goes and the caller is warned (kit "warned"). A bent root
  // skips the checkpoint (kit "nocp"). Promise cpFirstKeepsDevices.
  pure val CP_FIRST = false
  // OWN_HEAD (architecture rule C, 11-14 13:15Z, DECIDED TRUE): a checkpoint's head for its own
  // signer's key is present iff its seq is above 1, and is the line up to its prev; a checkpoint
  // that breaks it is malformed and every set refuses it. The bent root (signBent, lower = its own
  // key or "none") writes such checkpoints.
  pure val OWN_HEAD = false
  pure val LIVE_MAX = 4
  // Records 11-13 21:12Z: the change re-signs the cut roots' counting removals as the new
  // root's first records (signChainG). REISSUE_DROP_ONLY: the mutation that leaves the old
  // removals off the list without the new ones; it must fail.
  pure val REISSUE_REMOVALS = false
  // REISSUE_STATE (architecture 11-14 16:50Z, question B; needs REISSUE_REMOVALS): a new root
  // re-issues among its first records, beside the Zs, the whole state of the cut roots that
  // counts: their live admissions (admin and device records of keys not removed, the newest of
  // each key), their freezes and the newest copies record of each cut root, as records Y of
  // the new root (same kind, target, kit and units; targetRec names the head, as a Z's does).
  // The list carries only what is not state plus the removals and state that did not fit.
  pure val REISSUE_STATE = false
  // DROPS_EPOCH (candidate E, architecture 11-14 16:50Z): a checkpoint carries drops, the
  // highest drops its writer holds, plus one when it leaves a removal out; every device record
  // carries epoch, the highest drops its writer holds. A member's drops is the highest of the
  // checkpoints it holds; a device record with epoch below it counts only if a held checkpoint
  // or the chain's list keeps it. (Against an admin's device record the root never held that
  // arrives after the checkpoint that dropped the removal of its device.)
  pure val DROPS_EPOCH = false
  // FLAG (candidate, architecture 11-14 20:39Z): every admin and device record carries a flag,
  // 0 an admission, 1 an update. An update never admits, whoever signs it: the first-admission
  // search, rootHas and the checkpoint's settled keys read admissions only; an update counts
  // only while some admission of its key counts, and an admin's update only narrows (units no
  // higher than the admission's). The honest writer writes 1 for a key that already counts at
  // it; a new root's re-issue (REISSUE_STATE's Ys) is an admission. No drops, no epoch.
  pure val FLAG = false
  // FRESH_KEY (environment, architecture 11-14 20:46Z): an honest device offers its key to one
  // admitter once (computers and boards make a fresh member key at every join), so an honest
  // writer admits a key that does not count at it only if no record anywhere names that key
  // yet. Off, a device may offer one key twice (a phone retrying through another admitter).
  pure val FRESH_KEY = false
  // ROOT_WAITS (candidate W, architecture 11-14 20:54Z; FLAG and DROPS_EPOCH off): an admin key
  // may sign an acknowledgement ("ack", a record that only says what its writer saw). The
  // root's honest checkpoint settles a removal (leaves it out with its keys' admissions) only
  // when every live admin key has a counting record whose seen holds the removal's signer at
  // the removal's seq or later. The ack sits on the admin's own line, so a root that counts it
  // holds everything that admin signed before it. No change to evaluation.
  pure val ROOT_WAITS = false
  // The admin keys live in a writer's counted records: named by a root's admin record, not
  // removed, not taken back by a newer root device record of their device.
  pure def liveAdmins(counted: Set[Record]): Set[Key] = {
    val named = counted.filter(x => x.kind == "admin" and ROOT_KEYS.contains(x.signer))
    named.map(x => x.target).filter(a =>
      not(counted.exists(v => v.kind == "revoke" and tgt(v).contains(a)))
      and not(DEV.keys().contains(a) and counted.exists(x => x.kind == "device" and ROOT_KEYS.contains(x.signer)
        and x.target == DEV.get(a) and named.forall(n => n.target != a or n.id < x.id)))
      and not(TAKEN_FOR_GOOD and named.exists(n => n.target == a and counted.exists(x => ROOT_KEYS.contains(x.signer)
        and devOf(x) == devOf(n) and x.id > n.id and not(x.kind == "admin" and x.target == a)))))
  }
  // An admin record for key a would grant it again: a was removed, or a root device record of
  // its device came after a record naming it (a take-back).
  // LAST_ROOT_ONLY (candidate L, owner 11-14 21:17Z via architecture; on top of ROOT_WAITS and
  // REISSUE_STATE): after a change of root evaluation counts only the last root's records and
  // those of admin keys it named; nothing an earlier root or its admins signed counts. State
  // carries over only as the new root's re-issue (Ys), admins wiped (their devices re-issued as
  // plain devices); the writer never grants a key that was an admin key under another root.
  pure val LAST_ROOT_ONLY = false
  // KEPT_ADMINS (owner's idea, architecture 11-14 21:37Z; under LAST_ROOT_ONLY): at a change
  // the writer may name some devices as admins again, each under a new key, among the new
  // root's first records. In the model C's device is kept, as C2.
  pure val KEPT_ADMINS = false
  pure val NEWKEY = Map("C" -> "C2")
  // SPARE (candidate S, architecture 11-14 21:43Z; under LAST_ROOT_ONLY): an admin's ack
  // carries (as its target) a spare admin key its device made and never signed with. At a
  // change the writer names an old admin's device with that spare, taken only from an ack that
  // counts under the root being replaced and never named before (S1), and keeps no admins
  // while it holds an earlier change not yet applied (S2). Spares: A, A1, A2 and C, C2, C3.
  pure val SPARE = false
  pure val SPARE_OF = Map("A" -> "A1", "A1" -> "A2", "C" -> "C2", "C2" -> "C3")
  pure def spareOf(k: Key): Key = if (SPARE and SPARE_OF.keys().contains(k)) SPARE_OF.get(k) else ""
  // SEEN_HOLDS_ROOT (with SPARE): an admin's record other than a removal, freeze or thaw counts
  // only if its seen holds a record of the last root that names its key.
  pure val SEEN_HOLDS_ROOT = false
  // SEEN_POS (the core's wording, architecture 11-14 21:53Z; beside SEEN_HOLDS_ROOT): an admin
  // key's records count only at or above a record of that key, on its line, whose seen holds
  // the last root's record naming it. No kind is exempt; the honest writer signs a removal,
  // freeze or thaw only above such a record (its ack).
  pure val SEEN_POS = false
  // POS_HEADS_COUNTING (a fix to try for branch (b), off): the honest checkpoint names for an
  // admin key only a head that counts at its writer, never a void record.
  pure val POS_HEADS_COUNTING = false
  // (Void records still link their line; the model's rooms charge them like any held record
  // until a checkpoint leaves them out: the core does not charge them.)
  // GRANT_ABOVE (records' refinement of ROOT_WAITS, 11-14 21:37Z): a removal's settle does not
  // wait for an admin key named only by records of the removal's root above its seq (who holds
  // the grant holds the removal, the claim checked by grantHoldsRemoval).
  pure val GRANT_ABOVE = false
  // CANCELLED (architecture 11-14 23:24Z): within one root a checkpoint never drops a root
  // record naming an admin key, so the honest writer never forgets a taken-back key; the two
  // switches below stay off, and the tfg tests keep the calibration: a deviant root's re-grant
  // revives the key (out of scope).
  // CP_DEV_ANY (a wrong reading of the core's keep, kept for the calibration): of a device's
  // root records the honest checkpoint keeps only the oldest and the newest, admin namings
  // included (off: only its plain device records are thinned).
  pure val CP_DEV_ANY = false
  // TAKEN_FOR_GOOD (architecture 11-14 23:06Z, W's third patch): (a) the root's checkpoint keeps,
  // for each taken-back admin key, the root record that named it and the one that took it
  // back; (b) an admin key that a newer root record of its device took back never counts
  // again, on any device, whatever later record names it.
  pure val TAKEN_FOR_GOOD = false
  // A kit that names its admin key for another device than DEV's (the phones reuse their key).
  pure val KIT_DEV = Map("phone@dZ" -> "dZ", "phone@dZ!" -> "dZ")
  // A root's deviant naming with the powers of a kit ("!": no writer check applies).
  pure val KIT_BASE = Map("phone@dZ" -> "phone", "computer!" -> "computer", "phone@dZ!" -> "phone", "phone!" -> "phone")
  pure val BENT_KITS = Set("computer!", "phone@dZ!", "phone!")
  pure def posAnchored(mine: Set[Record], v: View, k: Key, kind: str): bool = {
    val cur = last(v.path)
    val gs = mine.filter(g => g.kind == "admin" and g.target == k and g.signer == cur)
    (gs != Set() and not(Set("revoke", "freeze", "thaw").contains(kind)))
      or mine.exists(b => b.signer == k and gs.exists(g => inLine(lineOf(b.seen, cur), g.id)))
  }
  pure def regrant(rs: Set[Record], a: Key): bool =
    rs.exists(v => v.kind == "revoke" and tgt(v).contains(a))
    or (DEV.keys().contains(a) and rs.exists(x => x.kind == "device" and ROOT_KEYS.contains(x.signer) and x.target == DEV.get(a)
      and rs.exists(n => n.kind == "admin" and n.target == a and n.id < x.id)))
  pure def grantedAbove(counted: Set[Record], a: Key, r: Record): bool = {
    val gs = counted.filter(n => n.kind == "admin" and n.target == a and ROOT_KEYS.contains(n.signer))
    GRANT_ABOVE and gs != Set() and gs.forall(n => n.signer == r.signer and n.seq > r.seq)
  }
  pure def ackedAll(counted: Set[Record], r: Record): bool =
    liveAdmins(counted).filter(a => not(grantedAbove(counted, a, r))).forall(a => counted.exists(x => x.signer == a and lineOf(x.seen, r.signer).length() >= r.seq))
  // An admission under FLAG (every admin and device record without it).
  pure def isAdmission(r: Record): bool = not(FLAG) or r.flag == 0
  pure def admitsOf(rs: Set[Record], k: Key): Set[Record] = admissionsOf(rs, k).filter(a => isAdmission(a))
  pure def dropsIn(rs: Set[Record]): int = rs.fold(0, (a, c) => if (c.kind == "checkpoint") max2(a, c.drops) else a)
  pure val REISSUE_DROP_ONLY = false
  pure val REISSUE_PACK_ANY = false
  // More mutations of the rule, each must fail (architecture 22:27Z): "newerSeen" (a Z's seen
  // entry for its keys is the writer's line now, newer than its X's), "notKept" (the first
  // checkpoint does not keep the Zs), "listX" (the list still names the Xs a Z covers).
  pure val REISSUE_MUT = ""
  // (J): the units the cut roots' listed records may take together.
  pure val RESERVE = ROOTC
  pure val MISSING_NEWEST_ONLY = false
  // A root pair held halts by the signatures alone: two records of the current root's key at one
  // seq within its stretch of the path halt the member whether or not either line is whole (the
  // reading of 11-13 16:51Z, and the core's eval). Off: the halt needs both lines whole; a pair
  // held but not whole only bars checkpoints at or above its seq.
  pure val HALT_ON_HELD_PAIR = true
  // F-7 for every key: a key in two histories has its records at or above the fork stop
  // counting, except its removals on a whole chain, which keep barring on either history (as a
  // root's do). Off: only a root's removals keep barring.
  pure val F7_EVERY_KEY = true
  // Remedy (a) for a forked key the root removes: its removals on a whole chain count whatever
  // the root's removal saw. Off: the root's removal cuts off what it did not see (remedy (c) is
  // the root's writer's, a scenario).
  pure val F7_SEEN_IGNORED = false
  // The fold: a root's checkpoint, and the list of a change of root, leave out an older root
  // removal when a newer kept root removal (of the same root, or of a later one on the path
  // for the list) names every key the older one names.
  pure val FOLD_REMOVALS = true

  pure val NONE = 10000000
  // A record's ID as the hash orders it: not the order it was signed in.
  pure def hid(i: Id): int = (i * 7) % 23

  // The powers of the three sets the apps write; no set takes the group over (rule 33).
  pure def powersOf(kit: str): Set[str] =
    if (KIT_BASE.keys().contains(kit)) powersOf0(KIT_BASE.get(kit)) else powersOf0(kit)
  pure def powersOf0(kit: str): Set[str] =
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
  // The keys a record names: target with its pair, and a packed removal's further keys.
  pure def tgt(r: Record): Set[Key] = r.also.fold(withPair(r.target), (a, k) => a.union(withPair(k)))
  pure def devOf(r: Record): Key =
    if (r.kind == "admin" and KIT_DEV.keys().contains(r.kit)) KIT_DEV.get(r.kit)
    else if (r.kind == "admin" and DEV.keys().contains(r.target)) DEV.get(r.target) else if (r.kind == "device") r.target else ""
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
  // Two removals see alike every key either names (the core, #530 2bccc9ef): only then may the
  // older fold into the newer, or a record of the key signed between them would count.
  pure def sameSeen(r: Record, n: Record): bool =
    tgt(r).union(tgt(n)).forall(k => lineOf(r.seen, k) == lineOf(n.seen, k))
  pure def rootRemoval(r: Record): bool = r.kind == "revoke" and ROOT_KEYS.contains(r.signer)
  // A checkpoint prunes what is below its heads and not kept, a root's removal too: whether a
  // removal stays is the writer's choice in the signed keep (members follow it).
  // (PREV_ROOM_WHEN_KEPT: the writer's own earlier checkpoint that c does not keep is pruned
  // though it heads c's line: it takes no room, and offered again after c counts, as a restart
  // does, it never enters the rooms; seed k.8702, where it left a mark that turned away the
  // root's next record.)
  pure def prunedBy(c: Record, r: Record): bool =
    c.heads.keys().contains(r.signer) and r.seq <= c.heads.get(r.signer).length()
      and (not(anchorsOf(c).contains(r.id))
        or (PREV_ROOM_WHEN_KEPT and r.kind == "checkpoint" and r.signer == c.signer and not(c.keep.contains(r.id))))
  // The records that admitted key k among rs: a root's admin record naming it or its device,
  // or a device record.
  pure def admissionsOf(rs: Set[Record], k: Key): Set[Record] =
    rs.filter(r => (r.kind == "admin" or r.kind == "device") and (r.target == k or devOf(r) == k))
  // What a root's checkpoint leaves out of the counted records: each root removal whose keys
  // are all plain device keys (no admin key, nothing they signed), of each of which the writer
  // holds an admission and every held admission is below its signer's head, with those
  // admissions. A removal that names an admin key is never pruned.
  pure def droppedAt(mine: Set[Record], counted: Set[Record]): Set[Id] = {
    val rms = counted.filter(r => rootRemoval(r)
      and tgt(r).forall(k => not(DEV.keys().contains(k)) and not(SIGNERS.contains(k))
        and not(ROOT_WAITS and mine.exists(n => n.kind == "admin" and devOf(n) == k))
        and admitsOf(mine, k) != Set()
        and admitsOf(mine, k).forall(a => headLine(mine, a.signer) != a.line))
      and not(mine.exists(x => tgt(r).contains(x.signer)))
      and (not(ROOT_WAITS) or ackedAll(counted, r)))
    val gone = rms.fold(Set(), (a, r) => a.union(tgt(r)))
    val folded = if (not(FOLD_REMOVALS)) Set() else counted.filter(r => rootRemoval(r) and counted.exists(n => rootRemoval(n)
      and n.signer == r.signer and n.seq > r.seq and not(rms.contains(n)) and tgt(r).subseteq(tgt(n))
      and sameSeen(r, n)))
    idsOf(rms).union(idsOf(folded)).union(idsOf(mine.filter(x => gone.contains(x.signer) or gone.exists(k => admissionsOf(Set(x), k) != Set()))))
  }

  pure val NONEREC: Record = {
    id: 0, signer: "", seq: 0, line: [], kind: "", target: "", kit: "", targetRec: 0, seen: Map(), heads: Map(), keep: Set(), units: 0, first: 0, follows: 0, off: false, also: Set(), drops: 0, epoch: 0, flag: 0,
  }

  // --- The recovery chain (rule 33) -------------------------------------------------------

  // A recovery record is valid by itself and the chain below it : the recovery
  // key signed it, and its new root differs from every root before it.
  pure def validAt(r: Record, path: List[Key]): bool =
    r.kind == "recover" and r.signer == RECOVERY and ROOT_KEYS.contains(r.target) and not(onList(path, r.target))
  // A head applies only with the new root's first checkpoint, signed by that root, which the
  // set keeps beside the chain (outside the rooms; nothing prunes it).
  pure def namesFirst(h: Record, c: Record): bool =
    isChain(h) and c.kind == "checkpoint" and c.id == h.first and c.signer == h.target
  // (REISSUE_REMOVALS: the head's re-signed removals Z, kit "z" naming the head in targetRec,
  // are its first records with the first checkpoint: the head counts as having its first only
  // with every Z too. The honest writer gives them the IDs between the head and the first.)
  pure def namesZ(h: Record, z: Record): bool = isChain(h) and reMark(z) and z.targetRec == h.id and z.signer == h.target
  // A re-signed first record: a Z, or under REISSUE_STATE a Y (state kinds, targetRec naming
  // its head; these kinds carry no targetRec otherwise).
  pure def reMark(z: Record): bool = z.kit == "z"
    or (REISSUE_STATE and z.targetRec > 0 and Set("admin", "device", "freeze", "copies").contains(z.kind))
  pure def hasFirst(r: Record, rs: Set[Record]): bool = r.first == 0 or
    (if (WHOLE_BY_SETTLER and r.first <= r.id + MAXREC)
      (r.id + 1).to(r.first).forall(i => rs.exists(x => x.id == i and (namesFirst(r, x) or namesZ(r, x)))
        or ((not(FIRST_REQUIRED) or i < r.first) and settledFirst(r, i, rs)))
    else (rs.exists(c => namesFirst(r, c))
    and (if (not(REISSUE_REMOVALS) or r.first > r.id + MAXREC) true
      else (r.id + 1).to(r.first - 1).forall(i => rs.exists(z => z.id == i and namesZ(r, z))))))
  // (WHOLE_BY_SETTLER, records 11-13 23:35Z: a first record of head r, its first checkpoint or a
  // Z, that a later checkpoint L of the new root settled counts as held: L has r's first on its
  // line, its heads reach the record for the new root, and it does not keep it.)
  pure def settledFirst(r: Record, i: Id, rs: Set[Record]): bool =
    rs.exists(l => l.kind == "checkpoint" and l.signer == r.target and l.id != i and inLine(l.line, r.first)
      and l.heads.keys().contains(r.target) and inLine(l.heads.get(r.target), i) and not(l.keep.contains(i))
      // (records 9dd3d9c8 (a): the settling checkpoint's own keep still counts: the change
      // waits for what that checkpoint keeps too.)
      and l.keep.forall(k => rs.exists(x => x.id == k))
      // And L keeps no record that r itself cuts: such an L does not follow r. Only a bent
      // writer signs one (the core's write_checkpoint signs only as the set's last root). A
      // search found it settling r live, r then cutting what L keeps, and a restart rebuilding
      // without r; with this, neither does.
      and not(rs.exists(x => l.keep.contains(x.id) and cutByChange(r, x))))
  // A record r's list cuts: an earlier root's record, or the new root's below r's from, that r's
  // list does not keep (core: a_checkpoint_that_keeps_what_its_change_cuts_settles_nothing).
  pure def cutByChange(r: Record, x: Record): bool =
    ROOT_KEYS.contains(x.signer) and not(r.keep.contains(x.id))
      and (x.signer != r.target or x.seq < r.targetRec)
  // The chain a member follows among the recovery records rs: from seq 1, a valid record
  // whose previous ID is the member's tip extends it; a gap ends the chain. Any two records the
  // recovery key signed at one seq, at any depth, valid or not, are a fork: the member stops
  // for good.
  pure def chainOf(rs: Set[Record]): Chain = chainRaw(rs).newestWithFirst(rs)
  // The chain by the records alone; under FIRST_NEWEST_ONLY no head needs its first checkpoint.
  pure def chainRaw(rs: Set[Record]): Chain = chainBy(rs, not(FIRST_NEWEST_ONLY))
  // The verified heads: the chain the recovery key's records make, firsts or not.
  pure def chainHeads(rs: Set[Record]): Chain = chainBy(rs, false)
  pure def chainBy(rs: Set[Record], needFirst: bool): Chain =
    range(1, MAXCHAIN + 1).foldl({ ids: [], recs: [], key: RECOVERY, stop: false, open: true }, (acc, i) =>
      if (not(acc.open)) acc
      else {
        val path = pathCutsOf(acc.recs)._1
        val cands = rs.filter(r => isChain(r) and r.seq == i and validAt(r, path) and r.line.slice(0, i - 1) == acc.ids
          and (not(needFirst) or hasFirst(r, rs)))
        if (cands.size() != 1) { ...acc, open: false }
        else {
          val c = cands.fold(NONEREC, (a, r) => r)
          { ...acc, ids: acc.ids.append(c.id), recs: acc.recs.append(c) }
        }
      })
  // Under FIRST_NEWEST_ONLY the chain ends at its newest head whose first checkpoint is held;
  // the heads below it need none.
  pure def newestWithFirst(ch: Chain, rs: Set[Record]): Chain =
    if (not(FIRST_NEWEST_ONLY)) ch
    else {
      val n = ch.recs.indices().filter(j => hasFirst(ch.recs[j], rs)).fold(0, (m, j) => max2(m, j + 1))
      { ...ch, ids: ch.ids.slice(0, n), recs: ch.recs.slice(0, n) }
    }
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
  type Order = { roots: Set[Key], cuts: Key -> List[Id], top: int, back: Set[Id] }
  pure def pos(r: Record, cur: Key, ord: Order): int = {
    val cp = r.signer == cur and r.kind == "checkpoint"
    val early = ord.roots.contains(r.signer) and (r.kind == "revoke" or r.kind == "freeze" or r.kind == "resolve")
    if (rootRemoval(r)) r.seq * 100 + hid(r.id)
    // (FIXED_CAPS: a root record that takes an admin key back comes first, as removals do.)
    else if (ord.back.contains(r.id)) r.seq * 100 + hid(r.id)
    else if (r.signer != cur and ord.cuts.keys().contains(r.signer)) {
      if (inLine(ord.cuts.get(r.signer), r.id)) 10000 + r.seq * 100 + hid(r.id)
      else 200000 + r.seq * 100 + hid(r.id)
    }
    // (NEWEST_CP_FIRST, records' order: older checkpoints last, newest first among them.)
    else if (cp and NEWEST_CP_FIRST and r.seq < ord.top) 300000 + (MAXREC + 4 - r.seq) * 100 + hid(r.id)
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
  pure def demand(owned: Set[Record], ceil: Key -> int, cut: Cut, s: int, pre: Key -> int): int =
    owned.map(r => r.signer).fold(0, (d, k) =>
      d + min2(max2(0, s - preOf(pre, k)), min2(ceil.get(k), dropped(cut, k) + sumUnits(ofKey(owned, k)))))
  // The units a key already holds in the room before the water-filling (a counting
  // checkpoint's records, kept first).
  pure def preOf(pre: Key -> int, k: Key): int = if (pre.keys().contains(k)) pre.get(k) else 0

  // What a set keeps of items, having dropped before what cut remembers: water-filling to one
  // level for every key with room (ceil), each key's records in its order.
  pure def keepAfter(items: Set[Record], ceil: Key -> int, cut: Cut, cur: Key, ord: Order): (Set[Id], Cut) =
    keepIn(items, ceil, cut, cur, ord, ROOM, Map())
  // The same in a room of the given size, where each key already holds pre of it: the level
  // is one for every key, counted with what it already holds.
  pure def keepIn(items: Set[Record], ceil: Key -> int, cut: Cut, cur: Key, ord: Order, room: int,
      pre: Key -> int): (Set[Id], Cut) = {
    val live = items.filter(r => not(past(cut, r, cur, ord)))
    val owned = live.filter(r => ceil.keys().contains(r.signer))
    val top = min2(cut.level, TOP)
    val level =
      if (demand(owned, ceil, cut, top, pre) <= room) top
      else 0.to(top).filter(s => demand(owned, ceil, cut, s, pre) <= room).fold(0, (m, s) => max2(m, s))
    val keptOwned = owned.filter(r =>
      prefix(ofKey(owned, r.signer), r, cur, ord) <= min2(max2(0, level - preOf(pre, r.signer)), ceil.get(r.signer)))
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

  // (FIXED_CAPS) A key's longest prefix of whole records, in its order, within cap.
  pure def prefixWithin(rs: Set[Record], cap: int, cur: Key, ord: Order): Set[Record] =
    rs.filter(r => prefix(rs, r, cur, ord) <= cap)
  // (FIXED_CAPS) What the rooms keep of items, where each key already holds pre of its cap
  // outside the rooms and outside holds those records (their root records name keys too).
  // (FIXED_CAPS) The roster the root records rs give (the core's not_live): the admin keys they
  // name, the keys no longer admins (removed, taken back, or past the first LIVE_MAX by their
  // newest admission's place on the path and seq), and the records that take a key back (a
  // device's newest root record naming another admin key or none).
  type Roster = { named: Set[Key], live: Set[Key], back: Set[Id] }
  pure def rosterOf(rs: Set[Record], path: List[Key]): Roster = {
    val adm = rs.filter(r => onList(path, r.signer) and (r.kind == "admin" or r.kind == "device") and devOf(r) != "")
    val named = adm.filter(r => r.kind == "admin" and not(onList(path, r.target))).map(r => r.target)
    val removed = rs.filter(r => onList(path, r.signer) and r.kind == "revoke").fold(Set(), (u, r) => u.union(tgt(r)))
    pure def at(r: Record): int = indexOf(path, r.signer) * 1000 + r.seq
    val devs = adm.map(r => devOf(r))
    pure def newestOf(d: Key): Record = adm.filter(r => devOf(r) == d).fold(NONEREC, (b, r) => if (b == NONEREC or at(r) > at(b)) r else b)
    pure def nowOf(d: Key): Key = if (newestOf(d).kind == "admin") newestOf(d).target else ""
    val current = devs.map(d => nowOf(d))
    val takenBy = devs.filter(d => adm.exists(r => devOf(r) == d and r.kind == "admin" and r.target != nowOf(d)))
    val taken = adm.filter(r => r.kind == "admin" and r.target != nowOf(devOf(r))).map(r => r.target)
    val back = takenBy.map(d => newestOf(d).id)
    pure def admAt(k: Key): int = adm.filter(r => r.kind == "admin" and r.target == k).fold(0, (m, r) => max2(m, at(r)))
    // (TAKEN_FOR_GOOD: a key a newer root record of its device took back is never live again.)
    val forGood = if (not(TAKEN_FOR_GOOD)) Set() else adm.filter(n => n.kind == "admin"
      and adm.exists(x => devOf(x) == devOf(n) and at(x) > at(n) and not(x.kind == "admin" and x.target == n.target))).map(n => n.target)
    val cands = named.filter(k => not(removed.contains(k)) and not(forGood.contains(k))
      and (current.contains(k) or not(taken.contains(k))))
    { named: named, live: cands.filter(k => cands.filter(j => admAt(j) < admAt(k)).size() < LIVE_MAX), back: back }
  }
  pure def keepTiers(items: Set[Record], path: List[Key], cur: Key, ord0: Order, pre: Key -> int,
      outside: Set[Record]): Set[Id] = {
    val ord = { ...ord0, back: rosterOf(items.union(outside), path).back }
    val curKept = prefixWithin(ofKey(items, cur), ROOTC - preOf(pre, cur), cur, ord)
    // The cut roots share one room (the core's CUT_ROOTS), their records in one order.
    val preCut = path.foldl(0, (a, k) => if (k == cur) a else a + preOf(pre, k))
    val cutKept = prefixWithin(items.filter(r => r.signer != cur and onList(path, r.signer)), RESERVE - preCut, cur, ord)
    // The roster from the root records those rooms keep and those kept outside.
    val ros = rosterOf(curKept.union(cutKept).union(outside.filter(r => onList(path, r.signer))), path)
    val n2 = ros.named.exclude(ros.live)
    val share = if (n2.size() == 0 or not(SHARE_REST)) 0
      else min2(ADMINC, max2(0, (ROOM - ROOTC - RESERVE - ADMINC * ros.live.size()) / n2.size()))
    // A key the roster does not name has no room (architecture 11-14 12:45Z: cap 0).
    val adminKept = ros.named.fold(Set(), (u, k) =>
      u.union(prefixWithin(ofKey(items, k), (if (ros.live.contains(k)) ADMINC else share) - preOf(pre, k), cur, ord)))
    idsOf(curKept.union(cutKept).union(adminKept))
  }

  // --- A member's set (the keys it knows, what it stores) --------------------------------

  // The admin keys a member knows: those the roots on its path name, each replaced root's
  // within its list.
  pure def learned(rs: Set[Record], path: List[Key], cuts: Key -> List[Id]): Set[Key] =
    rs.filter(r => onList(path, r.signer) and within(cuts, r) and r.kind == "admin").map(r => r.target)

  // The ceilings: a root's on the path, an admin key's.
  pure def ceilings(path: List[Key], admins: Set[Key]): Key -> int =
    // (Every root key: under REISSUE_STATE the third new root, NB, signs records in its room too.)
    SIGNERS.union(ROOT_KEYS).filter(k => onList(path, k) or admins.contains(k)).mapBy(k => if (onList(path, k)) ROOTC else ADMINC)

  pure def rootsOf(path: List[Key]): Set[Key] = path.indices().map(i => path[i])

  // The chain, the path and the lists a set keeps by: those of the recovery records it holds.
  pure def chainState(s: Store, db: Id -> Record): Chain =
    // (WHOLE_BY_SETTLER: the checkpoints the set got count toward a head's first records, so a
    // settler counts before the set keeps it.)
    chainOfAll(recsOf(s.chain, db).union(if (not(WHOLE_BY_SETTLER)) Set()
      else if (SETTLER_HELD) recsOf(s.recs.union(s.wait).union(earlyAside(s, db)), db).filter(c => not(isChain(c)))
      else recsOf(s.got, db).filter(c => not(isChain(c)))))
  pure def keptPath(s: Store, db: Id -> Record): List[Key] = pathCuts(chainState(s, db))._1
  pure def keptCuts(s: Store, db: Id -> Record): Key -> List[Id] = pathCuts(chainState(s, db))._2
  pure def orderOf(s: Store, db: Id -> Record): Order =
    { roots: rootsOf(keptPath(s, db)), cuts: keptCuts(s, db), top: topCp(s, db), back: Set() }
  // (NEWEST_CP_FIRST: the seq of the current root's newest checkpoint the set holds.)
  pure def topCp(s: Store, db: Id -> Record): int =
    recsOf(s.recs.union(s.wait), db).filter(c => c.kind == "checkpoint" and c.signer == last(keptPath(s, db)))
      .fold(0, (m, c) => max2(m, c.seq))

  // Whether a set stores r at all: its signer is known, it is within its root's list (a
  // replaced root keeps nothing else), and the checkpoint the set compacted on does not prune
  // it (unless a replaced root signed that checkpoint).
  pure def storable(s: Store, r: Record, db: Id -> Record): bool = {
    val cuts = keptCuts(s, db)
    storableBut(s, r, db)
      and (s.checkpoint == 0 or replaced(cuts, db.get(s.checkpoint).signer) or not(prunedBy(db.get(s.checkpoint), r)))
  }
  // The same without the checkpoint the set compacted on.
  pure def storableBut(s: Store, r: Record, db: Id -> Record): bool = {
    val got = recsOf(s.got, db)
    val path = keptPath(s, db)
    val cuts = keptCuts(s, db)
    val admins = learned(if (HELD_ADMISSIONS) recsOf(s.recs.union(s.wait), db) else got, path, cuts)
    not(isChain(r)) and not(s.chain.contains(r.id))
      and (admins.contains(r.signer) or onList(path, r.signer))
      and within(cuts, r)
  }

  // What a set keeps of items: of those within the lists, what the rooms keep.
  pure def settle(s: Store, items: Set[Record], cut: Cut, db: Id -> Record): (Set[Id], Cut) =
    if (not(HELD_ADMISSIONS)) settle0(s, items, cut, db)
    else {
      // (HELD_ADMISSIONS: the records of a key whose admission the rooms did not keep leave. The
      // rooms are not judged again: the level only goes down and the marks keep out what they
      // dropped, so the admission stays out too until the cut resets (records, 11-14).)
      val path = keptPath(s, db)
      val cuts = keptCuts(s, db)
      val r1 = settle0(s, items, cut, db)
      val ok = learned(recsOf(r1._1, db), path, cuts)
      (r1._1.filter(i => onList(path, db.get(i).signer) or ok.contains(db.get(i).signer)), r1._2)
    }
  pure def settle0(s: Store, items: Set[Record], cut: Cut, db: Id -> Record): (Set[Id], Cut) = {
    val path = keptPath(s, db)
    val cuts = keptCuts(s, db)
    val admins = learned(recsOf(s.got, db), path, cuts)
    // "gapless": above the head the set's checkpoint names for a key, only the gap-free run
    // of that key counts; a record past a gap has no count and no unit.
    val itemIds = idsOf(items)
    val cpsHeld = items.filter(c => c.kind == "checkpoint")
    pure def wholeForRoom(c: Record): bool =
      c.keep.forall(i => itemIds.contains(i))
        and c.line.indices().forall(j => itemIds.contains(c.line[j]) or (db.keys().contains(c.line[j])
          and cpsHeld.exists(c2 => c2.signer == c.signer and c2.id != c.id and prunedBy(c2, db.get(c.line[j])))))
    val shown0 = items.filter(r => within(cuts, r) and (CUT_MODE != "gapless" or gapFree(s, r, items, db))
      and not(CP_ROOM_WHEN_WHOLE and r.kind == "checkpoint" and r.signer == last(path) and not(wholeForRoom(r))))
    val shown = if (CUT_MODE == "follows") followsOk(s, shown0, db) else shown0
    val ceil = ceilings(path, admins)
    val plain = if (FIXED_CAPS) (keepTiers(shown, path, last(path), orderOf(s, db), Map(), Set()), NOCUT)
      else keepAfter(shown, ceil, cut, last(path), orderOf(s, db))
    // A record a held checkpoint names (its key's record below it, or one it keeps) settles
    // the set before the rooms are judged: when the checkpoint counts with what the rooms
    // keep and those records, it and the records it names are kept first and the rooms are
    // filled after them with what it leaves after pruning; if it still cannot count, the
    // usual rule stands.
    val cps = shown.filter(c => c.kind == "checkpoint" and c.signer == last(path))
    val named = shown.filter(r => cps.contains(r) or cps.exists(c => namedBy(c, r, shown))).filter(r => not(plain._1.contains(r.id)))
    if (named == Set()) plain
    else {
      val firsts = firstsHeld(s, db)
      val v = fullEvaluate(recsOf(plain._1, db).union(named).union(firsts), chainState(s, db))
      if (not(cps.exists(c => c.id == v.checkpoint))) plain
      else {
        val c = db.get(v.checkpoint)
        val left = shown.filter(r => not(prunedBy(c, r)))
        // Off NEWEST_ASIDE, the root's newest checkpoint is kept first too, alone.
        val newest = cps.filter(x => cps.forall(o => o == x or x.seq > o.seq or (x.seq == o.seq and x.id < o.id)))
        val first = left.filter(r => r == c or namedBy(c, r, shown) or (not(NEWEST_ASIDE) and newest.contains(r)))
        val ceil2 = ceil.keys().mapBy(k => ceil.get(k) - sumUnits(ofKey(first, k)))
        val room2 = ROOM - sumUnits(first)
        if (room2 < 0 or ceil2.keys().exists(k => ceil2.get(k) < 0) or first.exists(r => not(ceil.keys().contains(r.signer)))) plain
        else {
          // Under WAIT_SKIP the waiting checkpoints are judged after the other records: one the
          // rooms cannot take is skipped (it waits aside), not a stop for the records after it.
          val waits = if (WAIT_SKIP) left.exclude(first).filter(x => cps.contains(x)) else Set()
          val rest0 = if (FIXED_CAPS)
              (keepTiers(left.exclude(first).exclude(waits), path, last(path), orderOf(s, db),
                ceil.keys().mapBy(k => sumUnits(ofKey(first, k))), first), NOCUT)
            else keepIn(left.exclude(first).exclude(waits), ceil2, NOCUT, last(path), orderOf(s, db), room2,
              ceil.keys().mapBy(k => sumUnits(ofKey(first, k))))
          val base = recsOf(rest0._1, db).union(first)
          val fitW = waits.filter(w => {
            val upTo = waits.filter(o => o.seq > w.seq or (o.seq == w.seq and o.id <= w.id))
            sumUnits(base) + sumUnits(upTo) <= ROOM
              and sumUnits(ofKey(base, w.signer)) + sumUnits(upTo) <= ceil.get(w.signer)
          })
          val rest = (rest0._1.union(idsOf(fitW)), rest0._2)
          val res = (rest._1.union(idsOf(first)), rest._2)
          if (fullEvaluate(recsOf(res._1, db).union(firsts), chainState(s, db)).checkpoint == c.id) res else plain
        }
      }
    }
  }
  // A root's checkpoint can count only when it and the records it names fit the rooms among
  // themselves: each key within its ceiling and all within ROOM, judged on that set alone (the
  // admin keys it knows are those its own records name), so that whether it counts never
  // depends on what else a set holds or the order it came in.
  pure def fitsAlone(c: Record, items: Set[Record], path: List[Key], cuts: Key -> List[Id]): bool = {
    val named = items.filter(r => r == c or namedBy(c, r, items))
    val ceil = ceilings(path, learned(named, path, cuts))
    sumUnits(named) <= ROOM and named.map(r => r.signer).forall(k =>
      ceil.keys().contains(k) and sumUnits(ofKey(named, k)) <= ceil.get(k))
  }
  // The record checkpoint c waits for: its key's record just below it, among items.
  pure def waitedBy(c: Record, items: Set[Record]): Record =
    if (c.line.length() < 2) NONEREC
    else items.filter(r => r.id == c.line[c.line.length() - 2]).fold(NONEREC, (a, r) => r)
  // Checkpoint c names r: r is its key's record below it, or one it keeps.
  pure def namedBy(c: Record, r: Record, items: Set[Record]): bool =
    c.keep.contains(r.id) or (not(PREV_ROOM_WHEN_KEPT) and waitedBy(c, items) == r)
  // Drops what the set does not keep.
  pure def recut(s: Store, db: Id -> Record): Store = {
    val res = settle(s, recsOf(s.recs, db), cutOf(s, db), db)
    { ...s, recs: res._1, cut: res._2 }
  }
  // (I): of items, those whose chain of follows reaches the head (or none) through held
  // records; of two records of one key above its head that follow the same record, the
  // higher seq wins and the lower is void. A record at or below the head is never void, and
  // a record follows only its own key's records.
  pure def followsOk(s: Store, items: Set[Record], db: Id -> Record): Set[Record] = {
    val c0 = if (s.checkpoint == 0) NONEREC else db.get(s.checkpoint)
    val c = if (c0 != NONEREC and c0.signer == last(keptPath(s, db))) c0 else NONEREC
    pure def hd(k: Key): int = if (c != NONEREC and c.heads.keys().contains(k)) c.heads.get(k).length() else 0
    val live = items.filter(r => r.follows == 0 or r.seq <= hd(r.signer) or not(items.exists(y => y != r
      and y.signer == r.signer and y.follows == r.follows and y.seq > r.seq)))
    pure def base(r: Record): bool = r.follows == 0 or r.follows == -1 or r.seq <= hd(r.signer)
      or (db.keys().contains(r.follows) and db.get(r.follows).signer == r.signer
        and db.get(r.follows).seq <= hd(r.signer))
    val ok = range(0, MAXREC + 1).foldl(live.filter(r => base(r)), (acc, j) =>
      acc.union(live.filter(r => acc.exists(x => x.id == r.follows and x.signer == r.signer and x.seq < r.seq))))
    ok.union(items.filter(r => r.follows == 0))
  }
  // Every lower seq of r's key above the head the set's checkpoint names is among items.
  pure def gapFree(s: Store, r: Record, items: Set[Record], db: Id -> Record): bool = {
    // A replaced root's records count by its list.
    // A checkpoint of the current root is never past a gap: it is what moves the head over one.
    // The head is the furthest any held checkpoint of the current root names for the key
    // (the set's own or one in items): below it the checkpoint vouches for the run.
    val cur = last(keptPath(s, db))
    val cps = items.union(if (s.checkpoint == 0) Set() else Set(db.get(s.checkpoint)))
      .filter(c => c.kind == "checkpoint" and c.signer == cur)
    val hd = cps.fold(0, (m, c) => if (c.heads.keys().contains(r.signer)) max2(m, c.heads.get(r.signer).length()) else m)
    val ids = idsOf(items).union(s.chain).union(s.wait)
    replaced(keptCuts(s, db), r.signer)
      or (r.kind == "checkpoint" and r.signer == last(keptPath(s, db)))
      or r.line.indices().forall(j => j < hd or j >= r.line.length() - 1 or ids.contains(r.line[j]))
  }
  // The units of key k's records in rs above the head view's checkpoint names for k (all of
  // them with no checkpoint); checkpoints themselves not counted.
  pure def unitsAbove(rs: Set[Record], v: View, k: Key, db: Id -> Record): int = {
    val c = if (v.checkpoint == 0 or not(db.keys().contains(v.checkpoint))) NONEREC else db.get(v.checkpoint)
    val hd = if (c != NONEREC and c.heads.keys().contains(k)) c.heads.get(k).length() else 0
    sumUnits(rs.filter(r => r.signer == k and r.seq > hd and r.kind != "checkpoint" and not(isChain(r))))
  }
  // The memory of drops the set judges by (CUT_MODE).
  pure def cutOf(s: Store, db: Id -> Record): Cut =
    if (CUT_MODE == "none" or CUT_MODE == "gapless" or CUT_MODE == "follows") NOCUT
    else if (CUT_MODE == "mark") s.cut
    else {
      val cur = last(keptPath(s, db))
      val ord = orderOf(s, db)
      val held = recsOf(s.recs.union(s.wait), db)
      val marks = s.cut.marks.keys().filter(k => held.exists(r => past(s.cut, r, cur, ord) and r.signer == k))
        .mapBy(k => s.cut.marks.get(k))
      if (CUT_MODE == "lapse") { if (marks.keys() == Set()) NOCUT else { level: s.cut.level, marks: marks } }
      else {
        // "heads": the part of a key's mark at or below the head the counting checkpoint
        // names for it lapses; above the heads the mark stays.
        val v = fullEvaluate(recsOf(s.recs, db).union(firstsHeld(s, db)), chainState(s, db))
        val c = if (v.checkpoint == 0) NONEREC else db.get(v.checkpoint)
        val m2 = s.cut.marks.keys().fold(Map(), (acc, k) => {
          val dropped = recsOf(s.got.exclude(s.recs).exclude(s.wait), db)
            .filter(r => r.signer == k and past(s.cut, r, cur, ord))
          val above = if (c != NONEREC and c.heads.keys().contains(k)) dropped.filter(r => r.seq > c.heads.get(k).length()) else dropped
          if (c == NONEREC or not(c.heads.keys().contains(k))) acc.put(k, s.cut.marks.get(k))
          else if (above == Set()) acc
          else acc.put(k, (minPos(above, cur, ord), sumUnits(above)))
        })
        if (m2.keys() == Set()) NOCUT else { level: s.cut.level, marks: m2 }
      }
  }

  // A record offered to the set: a recovery record is held always, whatever any root or admin
  // signed before, a removal of the member itself included (brief v2, section 4);
  // another is stored when the set may store it and its key dropped nothing before it, then
  // the set cuts back.
  // (OWN_HEAD) A checkpoint whose head for its own key is not the line up to its prev.
  pure def malformedCp(r: Record): bool =
    r.kind == "checkpoint" and lineOf(r.heads, r.signer) != r.line.slice(0, r.line.length() - 1)
  pure def insertInto(s0: Store, r: Record, db: Id -> Record): Store =
    if (OWN_HEAD and malformedCp(r)) s0 else insertInto0(s0, r, db)
  pure def insertInto0(s0: Store, r: Record, db: Id -> Record): Store = {
    val s = { ...s0, got: s0.got.union(Set(r.id)) }
    // The set cuts its rooms by the new path at once, so that a record offered next is judged by
    // the path the set holds now, not the one it last cut by.
    // A head takes its first checkpoint along if the set got it before; a first checkpoint goes
    // beside the chain once its head is held. Either may apply the change.
    if (isChain(r)) applyChain({ ...s, chain: s.chain.union(Set(r.id)) }, db)
    else {
      val isFirst = recsOf(s.chain, db).exists(h => namesFirst(h, r) or namesZ(h, r)
        // (WHOLE_BY_SETTLER: a checkpoint of a held head's new root may settle its first
        // records, so it applies the chain again like a first record.)
        or (WHOLE_BY_SETTLER and isChain(h) and r.kind == "checkpoint" and r.signer == h.target))
      // A halted set (a fork of the recovery chain) takes recovery records only, a head's
      // first checkpoint among them.
      if (chainState(s, db).stop) (if (isFirst) applyChain(s, db) else s)
      else {
        // Two records of the current root at one seq are the proof of a root fork, kept
        // beside the rooms whatever the set pruned.
        val twin = recsOf(s.got, db).filter(o => o.id != r.id and not(isChain(o)) and o.signer == r.signer
          and o.seq == r.seq and r.signer == last(keptPath(s, db)))
        val s1 = if (twin == Set()) s
          else reopen({ ...s, chain: s.chain.union(idsOf(twin)).union(Set(r.id)), recs: s.recs.exclude(idsOf(twin)) }, db)
        val s3 = storeOne(if (isFirst) applyChain(s1, db) else s1, r, db)
        // (records 9dd3d9c8 (b): a change may be completed by another record than the one it
        // asked for: while a held head waits, any record re-chains the set.)
        if (WHOLE_BY_SETTLER and recsOf(s3.chain, db).exists(h => isChain(h) and not(chainState(s3, db).ids.indices().exists(j => chainState(s3, db).ids[j] == h.id))))
          applyChain(s3, db) else s3
      }
    }
  }
  // A head that may extend the set's chain: it follows the chain's records below its seq and
  // names a key no root before it was (a head that is not valid keeps no checkpoint aside).
  pure def validHead(s: Store, h: Record, db: Id -> Record): bool = {
    val ch = if (FIRST_NEWEST_ONLY) chainRaw(recsOf(s.chain, db)) else chainState(s, db)
    val below = h.seq - 1
    below <= ch.ids.length() and ch.ids.slice(0, below) == h.line.slice(0, below)
      and validAt(h, pathCutsOf(ch.recs.slice(0, below))._1)
  }
  // A set holds only its rooms, its chain and its waiting place: what the rooms turned away
  // comes back only when it is offered again.
  pure def storeOne(s0: Store, r: Record, db: Id -> Record): Store =
    if (s0.recs.contains(r.id) or s0.wait.contains(r.id) or not(storableW(s0, r, db))) s0
    else {
      // (NEWEST_CP_FIRST: a newer checkpoint of the current root moves its key's positions, so
      // the key's marks reset.)
      val cur0 = last(keptPath(s0, db))
      val s = if (NEWEST_CP_FIRST and r.kind == "checkpoint" and r.signer == cur0 and r.seq > topCp(s0, db))
        { ...s0, cut: { ...s0.cut, marks: s0.cut.marks.keys().exclude(Set(cur0)).mapBy(k => s0.cut.marks.get(k)) } }
        else s0
      // The current root's checkpoints the set holds, and the records they name, are not
      // turned away for their keys' earlier drops: they are judged again, all at once, with
      // each record, since a checkpoint may count only with all of them.
      val pool = recsOf(s.recs.union(s.wait), db).union(Set(r))
      val cps = pool.filter(c => c.kind == "checkpoint" and c.signer == last(keptPath(s, db)) and storableW(s, c, db))
      val back = pool.filter(x => (cps.contains(x) or cps.exists(c => namedBy(c, x, pool)))
        and not(s.recs.contains(x.id)) and storable(s, x, db))
      val turned = past(cutOf(s, db), r, last(keptPath(s, db)), orderOf(s, db)) and not(back.contains(r))
      // A record the counting checkpoint settled never enters the rooms: it waits aside.
      val add = if (turned or not(storable(s, r, db))) idsOf(back) else idsOf(back).union(Set(r.id))
      val s1 = if (add == Set()) s else recut({ ...s, recs: s.recs.union(add) }, db)
      withWait(s1, pool, db)
    }
  // The place aside: the checkpoints of the current root above the counting one that fit on
  // their own (below a fork's seq, not below the root's floor), and the records they name that
  // the rooms turned away or that the counting checkpoint settled. A settled record never
  // enters the rooms and the evaluation reads it only when a checkpoint keeping it counts:
  // then the set takes it, in one switch. What no such checkpoint names leaves.
  pure def asideOf(s1: Store, pool: Set[Record], db: Id -> Record): Set[Id] = {
    val cur = last(keptPath(s1, db))
    val held = recsOf(s1.recs, db)
    val v = fullEvaluate(held.union(firstsHeld(s1, db)), chainState(s1, db))
    val cseq = if (v.checkpoint == 0) 0 else db.get(v.checkpoint).seq
    val forkS = pool.filter(a => a.signer == cur and pool.exists(b => b != a and b.signer == cur and b.seq == a.seq))
      .fold(NONE, (m, x) => min2(m, x.seq))
    val floor = rootFloor(pool.union(firstsHeld(s1, db)), chainState(s1, db), cur)
    val cands0 = pool.filter(c => c.kind == "checkpoint" and c.signer == cur and c.seq > cseq and c.seq < forkS
      and c.seq >= floor and storableW(s1, c, db) and fitsAlone(c, pool, keptPath(s1, db), keptCuts(s1, db)))
    // ONE_SLOT (the rule at 1e9c92a1): only the newest candidate waits.
    val topC = cands0.fold(0, (x, c) => max2(x, c.seq))
    val cands = if (ONE_SLOT) cands0.filter(c => c.seq == topC) else cands0
    val all1 = pool.filter(x => not(s1.recs.contains(x.id)) and storableW(s1, x, db)
      and (cands.exists(c => c.keep.contains(x.id) or (ASIDE_TAKES_WAITED and namedBy(c, x, pool)))
        or (NEWEST_ASIDE and cands.contains(x))))
    // At most ASIDE_ROOM units, nothing while halted. Who stays: what the newest waiting
    // checkpoint keeps, then the next newest; inside one checkpoint by (seq, ID); never by
    // arrival.
    if (chainState(s1, db).stop) Set()
    else idsOf(all1.filter(x => sumUnits(all1.filter(y => asideBefore(y, x, cands))) <= ASIDE_ROOM))
  }
  // The newest candidate that keeps x: (seq, ID), the higher seq first, the smaller ID at one seq.
  pure def asideGroup(x: Record, cands: Set[Record]): (int, int) = {
    val ks = cands.filter(c => c.keep.contains(x.id) or c.line.length() >= 2 and c.line[c.line.length() - 2] == x.id or c == x)
    val top = ks.fold(0, (m, c) => max2(m, c.seq))
    (top, ks.filter(c => c.seq == top).fold(NONE, (m, c) => min2(m, c.id)))
  }
  pure def asideBefore(y: Record, x: Record, cands: Set[Record]): bool = {
    val gy = asideGroup(y, cands)
    val gx = asideGroup(x, cands)
    gy._1 > gx._1 or (gy._1 == gx._1 and gy._2 < gx._2)
      // Inside a group the checkpoint that heads it first, then by (seq, ID).
      or (gy == gx and (gy == (y.seq, y.id) or (gx != (x.seq, x.id) and (y.seq < x.seq or (y.seq == x.seq and y.id <= x.id)))))
  }
  pure def withWait(s1: Store, pool: Set[Record], db: Id -> Record): Store = {
    val aside = asideOf(s1, pool, db)
    val all1 = recsOf(s1.recs.union(aside), db)
    val v = fullEvaluate(recsOf(s1.recs, db).union(firstsHeld(s1, db)), chainState(s1, db))
    // The switch: a newer checkpoint that counts with what waits aside takes it into the set.
    val v2 = fullEvaluate(all1.union(firstsHeld(s1, db)), chainState(s1, db))
    if (v2.checkpoint != 0 and v2.checkpoint != v.checkpoint) {
      val c = db.get(v2.checkpoint)
      val take = aside.filter(i => i == c.id or namedBy(c, db.get(i), all1))
      // It compacts on it as any set would: what c prunes goes, even when an older checkpoint
      // c names keeps it (nothing is kept first by transitivity).
      val s1c = { ...s1, recs: s1.recs.union(take), checkpoint: c.id }
      val s2 = recut({ ...s1c, recs: s1c.recs.filter(i => storable(s1c, db.get(i), db)) }, db)
      { ...s2, wait: asideOf(s2, pool, db) }
    } else { ...s1, wait: aside }
  }
  // Storable, or settled by the counting checkpoint but kept by a checkpoint of the current
  // root above it that the set holds (review W-1: any of them).
  pure def storableW(s: Store, r: Record, db: Id -> Record): bool =
    storable(s, r, db) or (WAIT_TAKES_SETTLED and storableBut(s, r, db)
      and waitingCps(s, db).exists(c => c.keep.contains(r.id)))
  // The checkpoints of the current root the set holds above the one it compacted on.
  pure def waitingCps(s: Store, db: Id -> Record): Set[Record] = {
    val cseq = if (s.checkpoint == 0) 0 else db.get(s.checkpoint).seq
    recsOf(s.recs.union(s.wait), db).filter(c => c.kind == "checkpoint" and c.signer == last(keptPath(s, db)) and c.seq > cseq)
  }
  // The set cuts by the path its chain gives; the records of a root the change made, which the
  // set got while the change waited, it takes now (format 20.3, records of a waiting root).
  // The first checkpoints of the held heads that may extend the chain go beside it; each
  // head the chain takes may let the next one in.
  pure def gather(s: Store, db: Id -> Record): Store = {
    val heads = recsOf(s.chain, db).filter(h => isChain(h) and validHead(s, h, db))
    // (REISSUE_STATE: a Y is the new root's own record in its own room, counted like any root
    // record; the head applies only with it (hasFirst reads the set's records and what waits
    // aside), but it is not kept beside the chain as a Z is.)
    val firsts = idsOf(recsOf(s.got, db).filter(c => heads.exists(h => namesFirst(h, c) or (namesZ(h, c) and c.kit == "z"))))
    { ...s, chain: s.chain.union(firsts) }
  }
  // The chain applies whole: the set cuts once, by the path of every head it can take now.
  pure def applyChain(s: Store, db: Id -> Record): Store = {
    val s1 = range(0, MAXCHAIN).foldl(s, (x, j) => gather(x, db))
    val s2 = pathed({ ...s1, recs: s1.recs.exclude(s1.chain) }, db)
    val fresh = recsOf(s2.got, db).filter(x => not(isChain(x)) and onList(s2.path, x.signer) and not(onList(s.path, x.signer))
      and (not(EARLY_ROOM) or s1.chain.contains(x.id) or earlyKept(s1, db).contains(x.id)))
    val s3 = toList(idsOf(fresh)).foldl(s2, (x, i) => storeOne(x, db.get(i), db))
    // (FIXED_CAPS, the held set judged as a whole: a record of the new root that only a later one
    // of them vouches for (its checkpoint's heads over a gap) is offered again. A rebuild found
    // the settler of the change needing such a record, and the record needing the settler.)
    if (FIXED_CAPS) toList(idsOf(fresh)).foldl(s3, (x, i) => storeOne(x, db.get(i), db)) else s3
  }
  // What the room of early roots keeps: the records got of the roots the held heads name and
  // the path does not reach yet, the root of the lowest recovery seq first, each root's in seq
  // order, within one root's room; the first checkpoints beside the chain are not in it.
  pure def earlyKept(s: Store, db: Id -> Record): Set[Id] = {
    val heads = recsOf(s.chain, db).filter(h => isChain(h) and not(onList(s.path, h.target)))
    pure def rank(k: Key): int = heads.filter(h => h.target == k).fold(NONE, (m, h) => min2(m, h.seq))
    val early = recsOf(s.got, db).filter(r => not(isChain(r)) and not(s.chain.contains(r.id)) and rank(r.signer) < NONE)
    pure def before(x: Record, r: Record): bool =
      rank(x.signer) < rank(r.signer) or (rank(x.signer) == rank(r.signer)
        and (x.seq < r.seq or (x.seq == r.seq and x.id <= r.id)))
    idsOf(early.filter(r => sumUnits(early.filter(x => before(x, r))) <= ROOTC))
  }

  // When the chain changes the path, the set cuts its rooms again by the new path: the new
  // root gets a root's room, the replaced root keeps its list, and the set forgets the cut it
  // kept by the old path.
  pure def pathed(s: Store, db: Id -> Record): Store = {
    val pc = pathCuts(chainState(s, db))
    if (pc._1 == s.path and pc._2 == s.cuts) s
    else {
      // A change of root empties the place aside.
      val s2 = { ...s, path: pc._1, cuts: pc._2, cut: NOCUT, wait: Set() }
      // (FIXED_CAPS, the held set judged as a whole: the early roots' records the set held aside
      // go into the rooms with the change they settled; else the settler leaves the aside when
      // its root joins the path, and the change it completed falls back.)
      val early = if (FIXED_CAPS and EARLY_ASIDE) earlyAside(s, db).exclude(s2.chain) else Set()
      recut({ ...s2, recs: s2.recs.filter(i => storable(s2, db.get(i), db)).union(early) }, db)
    }
  }

  // Compaction: the set takes its state's checkpoint and drops what that prunes. When the
  // checkpoint it compacted by no longer counts (a root's resolve voids it, say), it forgets
  // it and takes again what that checkpoint left out (#530 51d25eaf).
  pure def compactStore(s: Store, v: View, db: Id -> Record): Store =
    if (v.checkpoint == s.checkpoint) s
    else if (CUT_RESET_ON_DROP and v.checkpoint != 0
        and not(recsOf(s.recs, db).exists(r => prunedBy(db.get(v.checkpoint), r))))
      // (CUT_RESET_ON_DROP: as the core's RecordSet::compact, a new counting checkpoint that
      // prunes nothing leaves the cut, its marks included.)
      recut({ ...s, checkpoint: v.checkpoint }, db)
    else {
      val s2 = { ...s, checkpoint: v.checkpoint, cut: NOCUT }
      reopen(s2, db)
    }
  // The set judges its rooms again from no cut and offers again what they turned away: after a
  // compaction, and when a root fork's pair leaves the rooms for the proof.
  pure def reopen(s2: Store, db: Id -> Record): Store = {
    val s3 = recut({ ...s2, cut: NOCUT, recs: s2.recs.filter(i => storable(s2, db.get(i), db)) }, db)
    val left = recsOf(s2.wait, db).filter(x => not(isChain(x)) and not(s3.recs.contains(x.id)))
    toList(idsOf(left)).foldl({ ...s3, wait: Set() }, (x, i) => storeOne(x, db.get(i), db))
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
    pure def floorAt(r: Record): int = {
      val top = r.line.indices().fold(-1, (m, j) => if (anchors.contains(r.line[j])) max2(m, j) else m)
      val low = if (cuts.keys().contains(r.signer)) floorOf(cuts.get(r.signer)) - 2 else -1
      max2(top, low)
    }
    // (I): a record that names what it follows needs only its line up to that record (the
    // records between are its key's void tail), and that record whole in turn.
    pure def followsAt(r: Record): int = r.line.indices().fold(-1, (f, i) => if (r.line[i] == r.follows) i else f)
    val fwhole = if (CUT_MODE != "follows") Set() else range(0, MAXREC + 1).foldl(
      rs.filter(r => r.follows != 0 and (r.follows == -1 or followsAt(r) <= floorAt(r))),
      (acc, j) => acc.union(rs.filter(r => r.follows > 0 and acc.exists(x => x.id == r.follows and x.signer == r.signer)
        and r.line.indices().forall(i => i <= floorAt(r) or i >= followsAt(r) or ids.contains(r.line[i])))))
    pure def whole(r: Record): bool =
      early(r) or replaced(cuts, r.signer)
        or (if (CUT_MODE == "follows" and r.follows != 0) fwhole.contains(r)
            else r.line.indices().forall(i => i <= floorAt(r) or ids.contains(r.line[i])))
    // The resolves of every root on the path; they void only admins' records, never a root's.
    val voids = rs.filter(r => onPath(r) and r.kind == "resolve" and whole(r)).map(r => r.targetRec)
      .filter(i => not(rs.exists(x => x.id == i and onList(path, x.signer) and not(isAdmin(x)))))
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
    // A root fork (two records of the root at one seq, at any depth): from its seq on the root
    // key has no power on either line, and the group halts until the recovery key changes the
    // root. A root's removal held on any line still bars its device.
    val heldPair = rs.exists(r => r.signer == cur and onPath(r) and within(cuts, r)
      and rs.exists(o => o != r and o.signer == cur and o.seq == r.seq))
    val rootForked = forkAt(cur) < NONE or (HALT_ON_HELD_PAIR and heldPair)
    pure def belowFork(r: Record): bool = r.seq < forkAt(r.signer) or (r.kind == "revoke" and (onPath(r) or F7_EVERY_KEY))
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
    pure def rootHas(d: Key): bool = rs.exists(r => devOf(r) == d and rootRec(r) and isAdmission(r))
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
    // (TAKEN_FOR_GOOD: every root record of a device newer than a record naming k there that
    // names no k takes k back for good: it works as a removal of k, whatever names k later.)
    pure def takeBacks(k: Key): Set[Record] = if (not(TAKEN_FOR_GOOD)) Set() else
      adminRecs.filter(n => n.target == k).fold(Set(), (u, n) =>
        u.union(about(devOf(n)).filter(x => not(x.kind == "admin" and x.target == k) and newer(x, n))))
    pure def current(k: Key): bool = adm.keys().contains(k) and replacers(k) == Set() and takeBacks(k) == Set()
    // The admin record that admits a device no root recorded: each admin's first, the
    // smallest ID.
    pure def admittedBy(d: Key): Id = {
      val ok = rs.filter(r => r.kind == "device" and r.target == d and isAdmin(r) and counted(r) and has(r.signer, "admit")
        and isAdmission(r))
      val firsts = ok.filter(r => not(ok.exists(o => o.signer == r.signer and o.seq < r.seq)))
      if (rootHas(d)) -1 else firsts.fold(NONE, (m, r) => min2(m, r.id))
    }
    // What an admin's record may do.
    pure def permitted(r: Record): bool =
      if (not(adm.keys().contains(r.signer))) false
      else if (SEEN_HOLDS_ROOT and not(Set("revoke", "freeze", "thaw").contains(r.kind))
        and not(adminRecs.exists(g => g.target == r.signer and g.signer == cur and inLine(lineOf(r.seen, cur), g.id)))) false
      // (SEEN_POS, the core's final wording: (a) r or a record of its key below it on its line has
      // seen holding the last root at or above the seq of any record of that root naming the key,
      // or (b) r sits at or above a record the counting checkpoint names for its key, a head or a
      // kept record.)
      else if (SEEN_POS and not(rs.exists(b => b.signer == r.signer and b.seq <= r.seq and inLine(r.line, b.id)
          and adminRecs.exists(g => g.target == r.signer and g.signer == cur and lineOf(b.seen, cur).length() >= g.seq))
        or anchors.exists(i => inLine(r.line, i)))) false
      else if (r.kind == "device") {
        val first = admittedBy(r.target)
        not(rootHas(r.target)) and (first == r.id or (first != NONE and first != -1 and has(r.signer, "manage")
          // (FLAG: an admin's update only narrows.)
          and (isAdmission(r) or rs.forall(a => a.id != first or r.units <= a.units))))
      }
      else if (r.kind == "revoke")
        if (tgt(r).exists(t => isRootKey(t))) false
        else if (isAdminKey(r.target)) has(r.signer, "removeAdmins")
        else has(r.signer, "remove")
      else if (r.kind == "freeze")
        has(r.signer, "freeze") and tgt(r).exists(t => adm.keys().contains(t))
          and tgt(r).forall(t => not(has(t, "removeAdmins")))
      else if (r.kind == "thaw") has(r.signer, "thaw") and has(r.signer, "removeAdmins")
      else if (r.kind == "copies") true
      else if (r.kind == "ack") ROOT_WAITS
      else false
    // a, a removal or freeze, cuts off b: it names a key of b's signer's device and did not
    // see b; of its own signer's key, it cuts off only what that key signs after it. A thaw of
    // a freeze leaves cut off what the freeze cut off and the thaw did not see. A record a
    // thawed key signs counts when its seen lists the thaw (rule 31).
    pure def thawedFor(f: Record, b: Record): bool = rs.exists(t => t.kind == "thaw" and t.targetRec == f.id
      and (onPath(t) or (isAdmin(t) and has(t.signer, "thaw") and has(t.signer, "removeAdmins"))) and saw(b, t))
    pure def cutsOffRm(a: Record, b: Record): bool =
      (a.kind == "revoke" or a.kind == "freeze") and a != b and tgt(a).contains(b.signer)
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
      or rootActs.exists(a => cutsOff(a, b) and not(F7_SEEN_IGNORED and b.kind == "revoke" and forkAt(b.signer) < NONE))
      or replacers(b.signer).union(takeBacks(b.signer)).exists(a => not(saw(a, b))))
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
    pure def counts0(r: Record): bool = rootRec(r) or (isAdmin(r) and ins.contains(r))
    // (FLAG: an update counts only while some admission of its key counts.)
    pure def counts(r: Record): bool = counts0(r) and (isAdmission(r) or devOf(r) == ""
      or rs.exists(a => devOf(a) == devOf(r) and isAdmission(a) and counts0(a)))
    val revoked = rs.filter(r => r.kind == "revoke" and counts(r)).fold(Set(), (s, r) => s.union(tgt(r)))
    val frozen = rs.filter(r => r.kind == "freeze" and counts(r) and not(rootThawed.contains(r.id)))
      .fold(Set(), (s, r) => s.union(tgt(r)))
    val currentAdmins = adm.keys().filter(a => current(a) and not(revoked.contains(a)))
    val stop = adminConflict or rootForked
    val devices = rs.filter(r => counts(r) and devOf(r) != "").map(r => devOf(r)).exclude(revoked)
    {
      path: path,
      counting: idsOf(rs.filter(r => counts(r))),
      revoked: revoked,
      frozen: frozen,
      admins: currentAdmins.mapBy(a => adm.get(a)),
      stop: stop,
      devices: devices,
      commanders: if (rootForked) Set() else currentAdmins.union(Set(cur)).filter(k => not(revoked.contains(k))
        and not(frozen.contains(k)) and not(forks.contains(k)) and (k == cur or not(stop))),
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
      // It counts only on a set that holds every record its keep names, none above its key's
      // head and no two at one seq: no ID in keep stands for a record nobody saw. Below the
      // heads it settles forks: it may keep a record of either sibling, and what it leaves
      // out is pruned (format 20.3).
      val ids = idsOf(acc._1)
      val kept = acc._1.filter(x => cp.keep.contains(x.id))
      val whole = cp.keep.forall(i => ids.contains(i)) and kept.forall(r =>
        (not(cp.heads.keys().contains(r.signer)) or r.seq <= cp.heads.get(r.signer).length())
          and kept.forall(o => o == r or o.signer != r.signer or o.seq != r.seq))
      if (cp != NONEREC and whole and fitsAlone(cp, acc._1, path, cuts) and v.counting.contains(c)) (pruned, anchors, { ...v, checkpoint: c }) else acc
    }

  // The state: the path from the recovery chain; the current root's newest checkpoint
  // applies, a replaced root's never; two recovery records at one seq stop everything.
  // The floor of the current root's checkpoints: none below the first checkpoint the head
  // that made it the root names (a checkpoint of the key signed before the change never
  // counts as the root's).
  pure def rootFloor(rs: Set[Record], ch: Chain, cur: Key): int = {
    val hs = ch.recs.select(h => h.target == cur)
    if (hs.length() == 0 or cur == ROOT) 0
    else {
      val h = hs[hs.length() - 1]
      rs.filter(c => c.id == h.first).fold(max2(h.targetRec, 1), (m, c) => c.seq)
    }
  }
  // (DROPS_EPOCH: a device record with epoch below the highest drops of the checkpoints held
  // counts only if a held checkpoint or a chain record's list keeps it.)
  pure def fullEvaluate(rs: Set[Record], ch: Chain): View =
    if (not(DROPS_EPOCH)) fullEvaluate0(rs, ch) else {
      val d = dropsIn(rs)
      val lists = rs.union(ch.recs.foldl(Set(), (a, c) => a.union(Set(c)))).filter(c => c.kind == "checkpoint" or isChain(c))
      fullEvaluate0(rs.filter(r => r.kind != "device" or r.epoch >= d or lists.exists(c => c.keep.contains(r.id))), ch)
    }
  // (LAST_ROOT_ONLY: after a change only the last root's records and those of the admin keys it
  // named count; the recovery records stay.)
  pure def fullEvaluate0(rs: Set[Record], ch: Chain): View = {
    val p = pathCuts(ch)._1
    val cur = last(p)
    if (not(LAST_ROOT_ONLY) or p.length() < 2) fullEvaluate1(rs, ch)
    else {
      val namedByCur = rs.filter(a => a.kind == "admin" and a.signer == cur).map(a => a.target)
      fullEvaluate1(rs.filter(r => isChain(r) or r.signer == cur or namedByCur.contains(r.signer)), ch)
    }
  }
  pure def fullEvaluate1(rs: Set[Record], ch: Chain): View = {
    val pc = pathCuts(ch)
    val cur = last(pc._1)
    val plain = epoch(rs, pc._1, pc._2, Set())
    // A holder of a root fork's pair counts no checkpoint of the root at or above the fork.
    val forkS = rs.filter(a => a.signer == cur and rs.exists(b => b != a and b.signer == cur and b.seq == a.seq))
      .fold(NONE, (m, r) => min2(m, r.seq))
    // The candidate is the newest checkpoint of the current root that counts (whole, fits):
    // a newer one that does not count yet takes nothing from it.
    val cs = rs.filter(r => r.signer == cur and r.kind == "checkpoint" and within(plain.cuts, r) and r.seq < forkS
      and r.seq >= rootFloor(rs, ch, cur))
    val v = range(0, MAXREC + 2).foldl((rs, Set(), plain), (acc, j) =>
      if (acc._3.checkpoint != 0) acc
      else {
        val at = cs.filter(x => x.seq == MAXREC + 1 - j)
        val c = at.filter(x => at.forall(o => x.id <= o.id)).fold(0, (m, x) => x.id)
        applyCheckpoint(pc._1, pc._2, c, acc)
      })._3
    if (ch.stop) { ...v, stop: true, commanders: Set() }
    else if (not(F12)) v
    else {
      // F-12: a device key, and the admin key an admission names, does not count while a
      // held checkpoint of the current root above the counting one (the candidates for
      // waiting, all of them) prunes every admission of it that counts. Nothing is masked:
      // what counts, removals, pairs and chains are read as before.
      val cseq = if (v.checkpoint == 0) 0 else rs.filter(c => c.id == v.checkpoint).fold(0, (m, c) => c.seq)
      // (One the member knows does not fit alone takes nothing away there; a member that
      // lacks some of its named records cannot know.)
      val above = cs.filter(c => c.seq > cseq and fitsAlone(c, rs, pc._1, pc._2))
      val adm = rs.filter(r => v.counting.contains(r.id) and (r.kind == "admin" or r.kind == "device"))
      pure def heldOut(k: Key): bool = {
        val ad = adm.filter(r => r.target == k or devOf(r) == k)
        ad != Set() and ad.forall(r => above.exists(c => prunedBy(c, r)))
      }
      { ...v, devices: v.devices.filter(d => not(heldOut(d))),
        admins: v.admins.keys().filter(a => not(heldOut(a))).mapBy(a => v.admins.get(a)),
        commanders: v.commanders.filter(k => k == cur or not(heldOut(k))) }
    }
  }

  // A member's state: its set evaluated (the evaluation keeps again what the set holds).
  pure def storeView(s: Store, db: Id -> Record): View =
    fullEvaluate(recsOf(settle(s, recsOf(s.recs, db), NOCUT, db)._1, db).union(firstsHeld(s, db)), chainState(s, db))
  // The first checkpoints of held heads, kept beside the chain and counted with the rooms.
  // (A re-signed removal Z counts only when a first checkpoint beside the chain keeps it: what
  // that checkpoint leaves out lies below its heads and is pruned, as in the core.)
  pure def firstsHeld(s: Store, db: Id -> Record): Set[Record] = {
    val side = recsOf(s.chain, db).filter(c => not(isChain(c)))
    side.filter(c => not(reMark(c)) or side.exists(f => f.kind == "checkpoint" and f.keep.contains(c.id))
      // (WHOLE_BY_SETTLER: or a held checkpoint in the rooms keeps it.)
      or (WHOLE_BY_SETTLER and recsOf(s.recs, db).exists(f => f.kind == "checkpoint" and f.keep.contains(c.id))))
  }

  // What a member given every record of got at once keeps, and its state.
  pure def pureKept(s: Store, db: Id -> Record): Set[Id] =
    settle(s, recsOf(s.got, db).filter(r => storable(s, r, db)), NOCUT, db)._1
  pure def pureView(s: Store, db: Id -> Record): View =
    fullEvaluate(recsOf(pureKept(s, db), db).union(firstsHeld(s, db)), chainState(s, db))

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
    recs: Set(), got: Set(), chain: Set(), cut: NOCUT, path: [ROOT], cuts: Map(), checkpoint: 0, wait: Set(),
  }

  pure def rootRemoved(v: View, db: Id -> Record): Set[Key] =
    recsOf(v.counting, db).filter(r => r.kind == "revoke" and onList(v.path, r.signer))
      .fold(Set(), (s, r) => s.union(tgt(r)))

  // A set cut by its chain's path, and its state. A counting checkpoint compacts at once
  // (there is no separate compacted state); taking it may make another count, so twice.
  pure def settled(s2: Store, db2: Id -> Record): Store = {
    val s3 = pathed(s2, db2)
    compactStore(s3, storeView(s3, db2), db2)
  }
  pure def finish(s2: Store, db2: Id -> Record): (Store, View) = {
    val s4 = settled(settled(s2, db2), db2)
    (s4, storeView(s4, db2))
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
      seen: seen, heads: heads, keep: keep, units: units, first: 0, follows: 0, off: false, also: Set(), drops: 0, epoch: 0, flag: 0 }

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
      hidden: bool, extraKeep: Set[Id]): bool =
    signFullX(k, kind, target, kit, targetRec, pretend, fork, units, hidden, extraKeep, WRITER_KEEPS)
  // (J): the admission of target by the writer on member h keeps every ceiling within ROOM.
  def capFits(h: str, target: Key): bool =
    if (FIXED_CAPS) {
      // (FIXED_CAPS: the root admits no key past LIVE_MAX live admin keys; removed keys leave the
      // count, their records sharing what the live keys leave.)
      val rs = recsOf(st.get(h).recs, db)
      val gone = rs.filter(r => r.kind == "revoke" and onList(views.get(h).path, r.signer)).fold(Set(), (u, r) => u.union(tgt(r)))
      learned(rs, views.get(h).path, views.get(h).cuts).union(Set(target))
        .filter(x => not(onList(views.get(h).path, x)) and not(gone.contains(x))).size() <= LIVE_MAX
    } else
    ROOTC + RESERVE + learned(recsOf(st.get(h).recs, db), views.get(h).path, views.get(h).cuts)
      .union(Set(target)).filter(x => not(onList(views.get(h).path, x))).size() * ADMINC <= ROOM
  // (J): a record of key k of the given units stays within k's ceiling on its writer's set.
  def ceilFits(k: Key, units: int): bool = {
    val h = HOLDER.get(k)
    sumUnits(ofKey(recsOf(st.get(h).recs, db), k)) + units <= (if (onList(views.get(h).path, k)) ROOTC else ADMINC)
  }
  // A writer that publishes what its own set turned away (it does not follow (E)).
  action signDeviant(k: Key, kind: str, target: Key, units: int): bool =
    signFullX(k, kind, target, "deviant", 0, false, false, units, false, Set(), false)
  // A deviating writer whose record names f as the record it follows (I).
  action signFollowing(k: Key, kind: str, units: int, f: Id): bool =
    signFullXF(k, kind, "", "deviant", 0, false, false, units, false, Set(), false, f)
  action signFullX(k: Key, kind: str, target: Key, kit: str, targetRec: Id, pretend: bool, fork: bool, units: int,
      hidden: bool, extraKeep: Set[Id], keeps: bool): bool =
    signFullXF(k, kind, target, kit, targetRec, pretend, fork, units, hidden, extraKeep, keeps, 0)
  action signFullXF(k: Key, kind: str, target: Key, kit: str, targetRec: Id, pretend: bool, fork: bool, units: int,
      hidden: bool, extraKeep: Set[Id], keeps: bool, followsAs: Id): bool = {
    val h = HOLDER.get(k)
    // (WRITER_LAST_ROOT: the honest writer of a checkpoint holds its own key's records and the
    // recovery records that made its key a root, and signs only as its set's last root, as the
    // core's write_checkpoint does; the model's holder may not have been given them.)
    val aug = WRITER_LAST_ROOT and kind == "checkpoint" and kit != "deviant" and not(hidden)
    val s = if (aug) withOwn(st.get(h), k, db) else st.get(h)
    val vh = if (aug) storeView(s, db) else views.get(h)
    val mine = recsOf(s.recs, db)
    val own = headLine(db.keys().map(i => db.get(i)), k)
    val base = if (fork and own.length() > 0) own.slice(0, own.length() - 1) else own
    val seen0 = SIGNERS.mapBy(x => if (x == k) base else headLine(mine, x))
    val seen1 = if (pretend) seen0.keys().mapBy(x => if (x != k and THIEVES.contains(x)) [] else seen0.get(x)) else seen0
    // A removal's seen names only the keys it takes, each with its pair (format 20.2).
    val seen = if (kind == "revoke" or kind == "freeze") seen1.keys().filter(x => withPair(target).contains(x)).mapBy(x => seen1.get(x)) else seen1
    val isCp = kind == "checkpoint"
    // A checkpoint keeps what its signer counts; one that keeps more is not the honest
    // writer's (kit "bent").
    val counted = recsOf(vh.counting, db).filter(x => x.kind != "checkpoint")
    val honestKeep = if (ROOT_KEYS.contains(k)) rootKeep(counted, mine, k) else idsOf(counted)
    // (CP_FIRST: a root's removal or take-back of an admin key not covered by its counting
    // checkpoint is the warned one: the honest writer signs it only when it cannot checkpoint
    // first (the search's actions check that, cpFirstOk; scenarios may sign it as they like).)
    val warned = kit == "" and not(hidden) and uncovered(k, kind, target)
    val r1 = rec(nextId, k, base.append(nextId), kind, target,
      if (isCp and not(extraKeep.subseteq(honestKeep))) "bent" else if (warned) "warned" else kit, targetRec,
      seen,
      // (POS_HEADS_COUNTING: an admin key's head is its newest record that counts at the writer.)
      if (isCp and POS_HEADS_COUNTING) seen.keys().mapBy(x => if (x == k or ROOT_KEYS.contains(x)) seen.get(x)
        else headLine(recsOf(vh.counting, db), x))
      else if (isCp) seen else Map(),
      if (isCp) honestKeep.union(extraKeep) else Set(),
      units)
    // (I): it follows its key's last record the writer's set keeps.
    val lastKept = ofKey(mine, k).fold((0, 0), (b, x) => if (x.seq > b._1) (x.seq, x.id) else b)._2
    val r2 = if (CUT_MODE == "follows" and not(isChain(r1)))
      { ...r1, follows: if (followsAs != 0) followsAs else if (lastKept == 0) -1 else lastKept } else r1
    // (DROPS_EPOCH: the writer's drops, plus one for a checkpoint that leaves a removal out.)
    val dH = dropsIn(mine)
    val r = if (not(DROPS_EPOCH)) r2
      else if (isCp) { ...r2, drops: dH + (if (counted.exists(x => x.kind == "revoke" and not(r2.keep.contains(x.id)))) 1 else 0) }
      else if (kind == "device") { ...r2, epoch: dH }
      else r2
    // (FLAG: the writer marks an update of a key that already counts at it.)
    val dk = devOf(r)
    val r3 = if (FLAG and dk != "" and vh.devices.contains(dk)) { ...r, flag: 1 } else r
    val db2 = db.put(nextId, { ...r3, off: hidden })
    all {
      SIGNERS.contains(k),
      // (ROOT_WAITS, code fact 11-14 21:04Z: the root never grants admin again to a key it
      // removed or took back; a returning device gets a new admin key.)
      not(ROOT_WAITS) or kit == "deviant" or BENT_KITS.contains(kit) or kind != "admin" or not(regrant(mine, target)),
      not(LAST_ROOT_ONLY) or kit == "deviant" or BENT_KITS.contains(kit) or kind != "admin"
        or not(db.keys().exists(i => db.get(i).kind == "admin" and db.get(i).target == target and db.get(i).signer != k)),
      // (SEEN_POS: an honest admin signs a removal, freeze or thaw only above its own record whose
      // seen holds its grant; any other record of it holds the grant in its own seen.)
      not(SEEN_POS) or kit == "deviant" or not(vh.admins.keys().contains(k)) or onList(vh.path, k) or posAnchored(mine, vh, k, kind),
      // (FRESH_KEY: an honest writer admits only a key no record names yet.)
      not(FRESH_KEY) or kit == "deviant" or dk == "" or vh.devices.contains(dk)
        or not(db.keys().exists(i => devOf(db.get(i)) == dk)),
      nextId <= FIRST + MAXREC,
      not(fork) or own.length() > 0,
      // The core's write_checkpoint signs only as the set's last root (state.roots.last()).
      not(aug) or last(vh.path) == k,
      // (J, core write_checkpoint: the honest checkpoint fits by itself and the trial set takes it
      // as the counting checkpoint; else the write is refused.)
      not(keeps) or not(isCp) or hidden or storeView(insertInto(s, r3, db2), db2).checkpoint == r.id,
      not(WRITER_CP_FLOOR) or kit == "deviant" or hidden or isChain(r) or isCp or not(onList(vh.path, k))
        or rootUnits(s, k) + r.units + CP_UNITS <= ROOTC - (if (floorExempt(r)) 0 else REMOVAL_MARGIN),
      // (WRITER_CP_FLOOR, architecture 11-14 09:03Z: the honest writer never spends the margin
      // down: an exempt record that would leave less than one more exempt record and the next
      // checkpoint waits for a checkpoint first, which the writer signs by itself. Under CP_FIRST
      // a removal is never refused: the search's actions checkpoint first, tightExempt.)
      not(WRITER_CP_FLOOR) or CP_FIRST or kit == "deviant" or hidden or not(floorExempt(r)) or not(onList(vh.path, k))
        or rootUnits(s, k) + r.units + 1 + CP_UNITS <= ROOTC,
      // (E): an honest writer publishes a record only when its own set keeps it; else the
      // write fails and the seq is not used. (A hidden record stays off its device.)
      not(keeps) or hidden or isChain(r) or insertInto(s, r3, db2).recs.contains(r.id),
      // (H): and only while its key's units above the head of the counting checkpoint stay
      // within FLOOR; the root admits no admin key past MAX_ADMINS.
      not(keeps) or not(WRITER_FLOOR) or hidden or isChain(r) or kind == "checkpoint"
        or unitsAbove(recsOf(s.recs, db).union(Set(r3)), vh, k, db2) <= (if (onList(vh.path, k)) ROOT_FLOOR else FLOOR),
      not(keeps) or not(CEIL_FIT) or hidden or isChain(r)
        or sumUnits(ofKey(recsOf(s.recs, db).union(Set(r3)).filter(x => not(isCp) or x == r3 or not(prunedBy(r, x))), k))
          <= (if (onList(vh.path, k)) ROOTC else ADMINC),
      not(keeps) or not(CEIL_FIT) or kind != "admin" or capFits(h, target),
      not(keeps) or not(WRITER_FLOOR) or kind != "admin" or learned(recsOf(s.recs, db), vh.path, vh.cuts)
        .union(Set(target)).size() <= MAX_ADMINS,
      commit(db2, nextId + 1, h, if (hidden) s else insertInto(s, r3, db2)),
    }
  }

  pure def liveKeep(counted: Set[Record], mine: Set[Record]): Set[Id] = {
    val k0 = counted.filter(x => not(droppedAt(mine, counted).contains(x.id)))
    // Admins' removals fold, with the device records they removed.
    val admRm = k0.filter(x => x.kind == "revoke" and not(ROOT_KEYS.contains(x.signer)))
    val k1 = k0.filter(x => not(admRm.contains(x))
      and not(x.kind == "device" and admRm.exists(a => tgt(a).contains(x.target))))
    idsOf(k1.filter(x => not(x.kind == "device" and k1.exists(y => y.kind == "device" and y.target == x.target and y.id > x.id))
      and not(x.kind == "copies" and k1.exists(y => y.kind == "copies" and y.signer == x.signer and y.id > x.id))))
  }
  pure def cpKeep(counted: Set[Record], mine: Set[Record], k: Key): Set[Id] = {
    pure def top(j: Key): int = counted.filter(y => y.signer == j).fold(0, (m, y) => max2(m, y.seq))
    // Settled plain device keys: not a signer, admitted by a held record under its signer's
    // head, nothing they signed held.
    // (ROOT_WAITS, records 655fcdac: a removal of a device that had an admin key is kept for
    // good and waits for nobody.)
    pure def plain(t: Key): bool = not(DEV.keys().contains(t)) and not(SIGNERS.contains(t))
      and not(ROOT_WAITS and mine.exists(n => n.kind == "admin" and devOf(n) == t))
      and admitsOf(mine, t) != Set()
      and admitsOf(mine, t).forall(a => headLine(mine, a.signer) != a.line)
      and not(mine.exists(x => x.signer == t))
    val rmGo = counted.filter(r => r.kind == "revoke" and r.seq < top(r.signer) and tgt(r).forall(t => plain(t))
      and (not(ROOT_WAITS) or ackedAll(counted, r)))
    val gone = rmGo.fold(Set(), (a, r) => a.union(tgt(r)))
    val folded = if (not(FOLD_REMOVALS)) Set() else counted.filter(r => rootRemoval(r) and counted.exists(n => rootRemoval(n)
      and n.signer == r.signer and n.seq > r.seq and not(rmGo.contains(n)) and tgt(r).subseteq(tgt(n)) and sameSeen(r, n)))
    val admGo = counted.filter(x => gone.exists(t => admissionsOf(Set(x), t) != Set()))
    val copiesGo = counted.filter(x => x.signer == k and x.kind == "copies"
      and counted.exists(y => y.signer == k and y.kind == "copies" and y.seq > x.seq))
    // (CP_DEV_ANY: a device's root records, admin namings included, but the oldest and the newest.
    // TAKEN_FOR_GOOD: never a naming of a key taken back, nor the oldest record taking it back.)
    pure def aboutK(x: Record): Set[Record] = counted.filter(y => y.signer == k and devOf(y) != "" and devOf(y) == devOf(x))
    pure def takesBack(y: Record, n: Record): bool = devOf(y) == devOf(n) and y.seq > n.seq
      and not(y.kind == "admin" and y.target == n.target)
    val namingsBack = counted.filter(n => n.signer == k and n.kind == "admin" and aboutK(n).exists(y => takesBack(y, n)))
    val firstBacks = namingsBack.map(n => aboutK(n).filter(y => takesBack(y, n)).fold(NONEREC, (b, y) =>
      if (b == NONEREC or y.seq < b.seq) y else b))
    val devGo = counted.filter(x => x.signer == k and (if (CP_DEV_ANY) devOf(x) != "" else x.kind == "device")
      and (if (CP_DEV_ANY) aboutK(x).exists(y => y.seq < x.seq) and aboutK(x).exists(y => y.seq > x.seq)
        else counted.exists(y => y.signer == k and y.kind == "device" and y.target == x.target and y.seq < x.seq)
          and counted.exists(y => y.signer == k and y.kind == "device" and y.target == x.target and y.seq > x.seq))
      and not(TAKEN_FOR_GOOD and (namingsBack.contains(x) or firstBacks.contains(x))))
    // (ROOT_WAITS: an admin's ack that a newer ack of its key supersedes goes.)
    val ackGo = if (not(ROOT_WAITS)) Set() else counted.filter(x => x.kind == "ack"
      and counted.exists(y => y.signer == x.signer and y.kind == "ack" and y.seq > x.seq))
    val go1 = idsOf(rmGo.union(folded).union(admGo).union(copiesGo).union(devGo).union(ackGo))
    val resGo = counted.filter(x => x.kind == "resolve" and go1.contains(x.targetRec))
    idsOf(counted).exclude(go1).exclude(idsOf(resGo))
  }
  // The honest root checkpoint's keep under the switches.
  pure def rootKeep(counted: Set[Record], mine: Set[Record], k: Key): Set[Id] =
    if (CP_KEEP) cpKeep(counted, mine, k)
    else if (CP_KEEP_LIVE) liveKeep(counted, mine)
    else idsOf(counted).exclude(droppedAt(mine, counted))
  // (WRITER_CP_FLOOR: a root's removal and its resolve share the margin; architecture 11-14
  // 08:30Z, the resolve provisional until records confirms.)
  pure def floorExempt(r: Record): bool = rootRemoval(r) or (r.kind == "resolve" and ROOT_KEYS.contains(r.signer))
  // (Promise rootCanRemove, under WRITER_CP_FLOOR: the current root can always write a removal,
  // or a resolve of its own removal, and still its next checkpoint.)
  // The honest writer may checkpoint first: the root's records its checkpoint would keep then
  // stand in for what it holds. A break is a state where even that checkpoint's keep leaves no
  // room for a removal, the margin and the next checkpoint.
  def rootCanRemove: bool = ROOT_KEYS.forall(k => {
    val h = HOLDER.get(k)
    val s = if (WRITER_LAST_ROOT) withOwn(st.get(h), k, db) else st.get(h)
    val v = if (WRITER_LAST_ROOT) storeView(s, db) else views.get(h)
    val mine = recsOf(s.recs, db)
    val counted = recsOf(v.counting, db).filter(x => x.kind != "checkpoint")
    val kept = counted.filter(x => x.signer == k
      and rootKeep(counted, mine, k).contains(x.id))
    v.stop or last(v.path) != k
      or rootUnits(s, k) + 1 + 1 + CP_UNITS <= ROOTC
      or sumUnits(kept) + 1 + 1 + CP_UNITS <= ROOTC
  })
  // (WRITER_CP_FLOOR: the units of root k's records its set holds, its checkpoints left out.)
  def rootUnits(s: Store, k: Key): int = sumUnits(ofKey(recsOf(s.recs, db), k).filter(x => x.kind != "checkpoint"))
  pure def withOwn(s: Store, k: Key, db: Id -> Record): Store = {
    val heads = db.keys().filter(i => isChain(db.get(i)) and db.get(i).target == k)
    val ids = db.keys().filter(i => db.get(i).signer == k and not(db.get(i).off))
      .union(heads.fold(Set(), (u, i) => u.union(db.get(i).line.indices().map(x => db.get(i).line[x]))))
    toList(ids.exclude(s.got)).foldl(s, (x, i) => insertInto(x, db.get(i), db))
  }

  // (Promise cpWritable, architecture 11-14: while the current root's holder follows it, an
  // honest checkpoint it signs now is not refused: its set keeps it and counts it. Expected to
  // hold under WRITER_CP_FLOOR.)
  def cpWritable: bool = ROOT_KEYS.forall(k => cpWritableK(k))
  def cpWritableK(k: Key): bool = {
    val h = HOLDER.get(k)
    val s = if (WRITER_LAST_ROOT) withOwn(st.get(h), k, db) else st.get(h)
    val v = if (WRITER_LAST_ROOT) storeView(s, db) else views.get(h)
    val mine = recsOf(s.recs, db)
    val counted = recsOf(v.counting, db).filter(x => x.kind != "checkpoint")
    val keep = rootKeep(counted, mine, k)
    val seen = SIGNERS.mapBy(x => if (x == k) headLine(db.keys().map(i => db.get(i)), k) else headLine(mine, x))
    val r = rec(nextId, k, headLine(db.keys().map(i => db.get(i)), k).append(nextId), "checkpoint", "", "", 0, seen, seen, keep, 2)
    val db2 = db.put(nextId, r)
    val s2 = insertInto(s, r, db2)
    v.stop or last(v.path) != k or nextId > FIRST + MAXREC
      or (s2.recs.contains(r.id) and storeView(s2, db2).checkpoint == r.id)
  }

  // A root key signs a checkpoint with a keep of its choosing, and may lower one key's head by
  // one record: not the honest writer's (kit "bent").
  action signCheckpointKeep(k: Key, keep: Set[Id], lower: Key, units: int): bool = {
    val h = HOLDER.get(k)
    val s = st.get(h)
    val mine = recsOf(s.recs, db)
    val own = headLine(db.keys().map(i => db.get(i)), k)
    // Each key's head: the longer of what the signer holds and what the keep names.
    val kept = recsOf(keep.filter(i => db.keys().contains(i)), db)
    val seen0 = SIGNERS.mapBy(x => if (x == k) own else {
      val a = headLine(mine, x)
      val b = headLine(kept, x)
      if (b.length() > a.length()) b else a })
    // (lower may be the signer's own key, its head one record short, or "none": its own head
    // left out; rule C, OWN_HEAD, makes both malformed.)
    val seen = seen0.keys().mapBy(x => if (x == k and lower == "none") []
      else if (x == lower and seen0.get(x).length() > 0)
      seen0.get(x).slice(0, seen0.get(x).length() - 1) else seen0.get(x))
    val r = rec(nextId, k, own.append(nextId), "checkpoint", "", "bent", 0, seen, seen, keep, units)
    val db2 = db.put(nextId, r)
    all {
      ROOT_KEYS.contains(k),
      nextId <= FIRST + MAXREC,
      commit(db2, nextId + 1, h, insertInto(s, r, db2)),
    }
  }
  action signBent = nondet k = ROOT_KEYS.exclude(Set("NB")).oneOf() nondet keep = db.keys().union(Set(NEVER)).powerset().oneOf()
    nondet lower = Set("", PHONE, COMPUTER, WATCH, k, "none").oneOf() nondet u = Set(1, 2).oneOf() signCheckpointKeep(k, keep, lower, u)

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
  action signChain(k: Key, kind: str, target: Key, at: int, mode: str): bool = signChainG(k, kind, target, at, mode, Set())
  // "given": the list is exactly `given` (a deviating recovery key's choice).
  action signChainG(k: Key, kind: str, target: Key, at: int, mode: str, given: Set[Id]): bool = {
    val h = HOLDER.get(k)
    val s = st.get(h)
    val v = views.get(h)
    val ch = chainState(s, db)
    val base = ch.ids.slice(0, at - 1)
    val before = pathCutsOf(ch.recs.slice(0, at - 1))._1
    val cur = last(before)
    val held = recsOf(s.recs, db).filter(r => onList(before, r.signer) or r.signer == target)
    val oldCp = if (v.checkpoint != 0 and db.get(v.checkpoint).signer == cur) db.get(v.checkpoint) else NONEREC
    // Every root removal held, on any line, is listed; a checkpoint is never listed; nothing a
    // held checkpoint of the root left out is listed (a root fork's lines included).
    val rootCps = held.filter(x => x.signer == cur and x.kind == "checkpoint")
    val leftOut = held.filter(x => rootCps.exists(c => prunedBy(c, x)))
    // The first checkpoint's heads: for each key the highest any held checkpoint of the root
    // named (the counting one's when it holds no other).
    val headKeys = rootCps.fold(oldCp.heads.keys(), (a, c) => a.union(c.heads.keys()))
    val heads = headKeys.mapBy(k => rootCps.union(if (oldCp == NONEREC) Set() else Set(oldCp))
      .filter(c => c.heads.keys().contains(k))
      .fold([], (l, c) => if (c.heads.get(k).length() > l.length()) c.heads.get(k) else l))
    val cp = heads.keys().filter(k => heads.get(k).length() > 0)
      .map(k => lastId(heads.get(k))).filter(i => onList(before, db.get(i).signer) and db.get(i).kind != "checkpoint")
    // (SPARE: the spare a counting ack of admin key a carries under the root being replaced,
    // never named before (S1); none while the writer has not applied the chain below (S2).)
    def spareFor(a: Key): Key = {
      val sps = recsOf(v.counting, db).filter(y => y.kind == "ack" and y.signer == a and y.target != "").map(y => y.target)
        .filter(t => not(db.keys().exists(i => db.get(i).kind == "admin" and db.get(i).target == t)))
      // (Never for a frozen admin.)
      if (not(SPARE) or v.path != before or sps.size() != 1 or v.frozen.contains(a)) "" else sps.fold("", (z, t) => t)
    }
    // (CORE_LIST_FILTER: the core's list today drops a removal of keys no held record names.)
    def unnamedRm(r: Record): bool = CORE_LIST_FILTER and rootRemoval(r)
      and tgt(r).forall(t => admissionsOf(recsOf(s.recs, db), t) == Set())
    val honest = idsOf(held.filter(r => ((v.counting.contains(r.id) and r.kind != "checkpoint" and not(leftOut.contains(r)))
      or rootRemoval(r)) and not(unnamedRm(r)))).union(cp)
    // (J): the cut roots' listed records fit RESERVE (carry-over). Every root removal stays
    // listed, and every live admission (an admin or device record of a key not removed) unless
    // a newer listed admission of the same key supersedes it; superseded admissions are dropped;
    // of the other records the newest are kept (by place on the path, then seq) while they fit.
    // The honest writer refuses a change whose removals and live admissions alone pass RESERVE.
    val beforeRecs = recsOf(honest, db).filter(x => onList(before, x.signer))
    def notOlder(a: Record, b: Record): bool =
      indexOf(before, a.signer) > indexOf(before, b.signer) or (a.signer == b.signer and a.seq >= b.seq)
    def isAdm(x: Record): bool = x.kind == "admin" or x.kind == "device"
    val superseded = beforeRecs.filter(x => isAdm(x)
      and beforeRecs.exists(y => y != x and isAdm(y) and y.target == x.target and notOlder(y, x)))
    val live = beforeRecs.filter(x => isAdm(x) and not(superseded.contains(x))
      and not(tgt(x).exists(t => v.revoked.contains(t))))
    val foldedRm = if (not(FOLD_REMOVALS)) Set() else beforeRecs.filter(x => rootRemoval(x)
      and beforeRecs.exists(n => n != x and rootRemoval(n) and notOlder(n, x) and tgt(x).subseteq(tgt(n))
        and sameSeen(x, n)))
    // REISSUE_REMOVALS (records 11-13 21:12Z): the honest writer re-signs the cut roots'
    // counting removals as the new root's first records Z, one per removal X (same key, same
    // seen entries, so X folds into Z by the fold condition), oldest first while they fit the
    // new root's room less a checkpoint's units; an X that does not fit rides in the list.
    // REISSUE_DROP_ONLY (a mutation that must fail): the list leaves out the Xs, no Z is signed.
    val ownUnits = sumUnits(ofKey(recsOf(s.recs.union(st.get(HOLDER.get(target)).recs), db), target))
    val reC = if (not(REISSUE_REMOVALS) or mode != "honest") []
      else range(1, nextId).select(i => v.counting.contains(i) and rootRemoval(db.get(i))
        and onList(before, db.get(i).signer) and not(foldedRm.contains(db.get(i))))
    val zSrc = reC.foldl(([], ownUnits), (a, i) =>
      if (a._2 + db.get(i).units + 2 <= ROOTC) (a._1.append(i), a._2 + db.get(i).units) else a)._1
    val zUnits = zSrc.foldl(ownUnits, (a, i) => a + db.get(i).units)
    // (REISSUE_STATE: the state Ys, oldest first while they fit beside the Zs and a checkpoint.)
    val ySrcAll = if (not(REISSUE_STATE) or mode != "honest") [] else {
      val cps = beforeRecs.filter(x => x.kind == "copies")
      // (LAST_ROOT_ONLY: an admin's freeze that counts is carried too, as the new root's own.)
      val heldRecs = recsOf(s.recs, db).filter(r => v.counting.contains(r.id) and not(leftOut.contains(r)))
      range(1, nextId).select(i => db.keys().contains(i) and {
        val x = db.get(i)
        beforeRecs.contains(x) or (LAST_ROOT_ONLY and (x.kind == "freeze" or x.kind == "device") and heldRecs.contains(x))
      } and {
        val x = db.get(i)
        (live.contains(x) and not(LAST_ROOT_ONLY and x.kind == "admin" and not(DEV.keys().contains(x.target))))
          // (LAST_ROOT_ONLY: a device an admin admitted that counts is carried too, as the new
          // root's own admission, once: its newest admin record, when no cut root's names it.)
          or (LAST_ROOT_ONLY and x.kind == "device" and not(onList(before, x.signer)) and v.devices.contains(x.target)
            and not(beforeRecs.exists(y => isAdm(y) and devOf(y) == x.target))
            and not(heldRecs.exists(y => y.kind == "device" and y.target == x.target and not(onList(before, y.signer)) and y.id > x.id)))
          // (LAST_ROOT_ONLY, architecture 22:45Z: every freeze that counts is carried as the new
          // root's own; only the new root thaws.)
          or (x.kind == "freeze" and (not(LAST_ROOT_ONLY) or (v.counting.contains(x.id) and tgt(x).exists(t => v.frozen.contains(t)))))
          or (x.kind == "copies" and cps.forall(y => y.signer != x.signer or y.seq <= x.seq))
      })
    }
    val ySrc = ySrcAll.foldl(([], zUnits), (a, i) =>
      if (a._2 + db.get(i).units + 2 <= ROOTC) (a._1.append(i), a._2 + db.get(i).units) else a)._1
    val yCovered = ySrc.foldl(Set(), (a, i) => a.union(Set(i)))
    val covered = zSrc.foldl(yCovered, (a, i) => a.union(Set(i)))
    // Packing (the core, architecture 22:00Z): each X goes whole into the first Z whose Xs agree
    // with it on the seen entries of every key both concern (their keys and their seen keys);
    // two Xs that saw a shared key differently go to different Zs. A Z's units are its Xs'.
    // REISSUE_PACK_ANY (a mutation that must fail): every X into one Z, the longest seen line.
    pure def concerns(x: Record): Set[Key] = tgt(x).union(x.seen.keys())
    pure def agree(y: Record, x: Record): bool =
      concerns(y).intersect(concerns(x)).forall(k => lineOf(y.seen, k) == lineOf(x.seen, k))
    val groups = zSrc.foldl([], (gs, i) => {
      val x = db.get(i)
      val j = range(0, gs.length()).foldl(-1, (f, g) =>
        if (f < 0 and (REISSUE_PACK_ANY or gs[g].foldl(true, (ok, y) => ok and agree(db.get(y), x)))) g else f)
      if (j < 0) gs.append([i]) else gs.replaceAt(j, gs[j].append(i))
    })
    // (LAST_ROOT_ONLY: removals from before the change are not carried: no Zs.)
    val zIds = if (REISSUE_DROP_ONLY or LAST_ROOT_ONLY) [] else range(0, groups.length()).foldl([], (l, j) => l.append(nextId + 1 + j))
    val remUnits = sumUnits(beforeRecs.filter(x => rootRemoval(x) and not(foldedRm.contains(x)) and not(covered.contains(x.id))))
    val fixedUnits = remUnits + sumUnits(live.filter(x => not(covered.contains(x.id))))
    val droppable = beforeRecs.filter(x => not(rootRemoval(x)) and not(live.contains(x)) and not(superseded.contains(x)))
    val trimmed = if (not(CEIL_FIT)) honest else honest.filter(i => not(superseded.contains(db.get(i))) and not(foldedRm.contains(db.get(i)))
      and (not(droppable.contains(db.get(i))) or fixedUnits + sumUnits(droppable.filter(d => notOlder(d, db.get(i)))) <= RESERVE))
    val keep = if (mode == "honest" or mode == "nocp" or mode == "from1")
        (if (REISSUE_MUT == "listX") trimmed else trimmed.exclude(covered))
      else if (mode == "literal") honest.filter(i => db.get(i).signer == cur or rootRemoval(db.get(i)) or cp.contains(i))
      else if (mode == "none") Set()
      else if (mode == "given") given
      else db.keys().filter(i => onList(before, db.get(i).signer))
    val own = headLine(db.keys().map(i => db.get(i)), target)
    val from = if (mode == "from1") 1 else own.length() + 1
    // "nocp": the head names a first checkpoint that is never released.
    // (NEW_ROOT_ONLY: a change naming a root already on the path is void; no writer signs a
    // first checkpoint for it (the core's write_change refuses the change; a deviant recovery
    // key may sign the void head, and that is all the step writes, in every mode, so that old
    // traces still replay).)
    val withCp = mode != "nocp" and not(NEW_ROOT_ONLY and onList(before, target))
    // A list the core does not write is marked "deviant" (the kit of a chain record is read nowhere else).
    // (Ghost: the root removals the writer held, under "_rm" of the head's seen, which nothing
    // else reads; removedStayOut does not excuse a cut-off removal an honest writer held.)
    val heldRm = range(1, nextId).select(i => s.recs.contains(i) and rootRemoval(db.get(i)) and onList(before, db.get(i).signer))
    val yIds = range(0, ySrc.length()).foldl([], (l, j) => l.append(nextId + 1 + zIds.length() + j))
    val cpId = nextId + 1 + zIds.length() + yIds.length()
    val r = { ...rec(nextId, k, base.append(nextId), kind, target, if (mode == "honest") "" else "deviant", from,
      Map("_rm" -> heldRm), Map(), keep, 0), first: if (withCp) cpId else NEVER }
    val ownZ = own.concat(zIds).concat(yIds)
    val dbH = db.put(nextId, r)
    val db2 = range(0, zIds.length()).foldl(dbH, (d, j) => {
      val xs = groups[j].foldl(Set(), (a, i) => a.union(Set(db.get(i))))
      val x0 = db.get(groups[j][0])
      val zKeys = xs.fold(Set(), (a, x) => a.union(x.seen.keys()))
      val seenZ = zKeys.mapBy(k => if (REISSUE_MUT == "newerSeen") headLine(recsOf(s.recs.union(s.got), db), k)
        else xs.fold([], (l, x) => if (lineOf(x.seen, k).length() > l.length()) lineOf(x.seen, k) else l))
      val z = rec(nextId + 1 + j, target, own.concat(zIds.slice(0, j + 1)), "revoke", x0.target, "z", nextId,
        seenZ, Map(), Set(), sumUnits(xs))
      d.put(nextId + 1 + j, { ...z, also: xs.exclude(Set(x0)).fold(Set(), (a, x) => a.union(Set(x.target)).union(x.also)).union(x0.also) })
    })
    val db2y = range(0, yIds.length()).foldl(db2, (d, j) => {
      val x = db.get(ySrc[j])
      // (LAST_ROOT_ONLY: admins are wiped at a change; an admin's device is re-issued as a plain
      // device.)
      // (KEPT_ADMINS: a device the writer keeps as an admin is named again under a new key.)
      val sp = spareFor(x.target)
      val kept = LAST_ROOT_ONLY and x.kind == "admin"
        and ((KEPT_ADMINS and NEWKEY.keys().contains(x.target)) or (SPARE and sp != ""))
      val newKey = if (SPARE and sp != "") sp else if (NEWKEY.keys().contains(x.target)) NEWKEY.get(x.target) else x.target
      val asDev = LAST_ROOT_ONLY and x.kind == "admin" and not(kept)
      // (A carried freeze of a wiped admin freezes its device.)
      val frzDev = LAST_ROOT_ONLY and x.kind == "freeze" and DEV.keys().contains(x.target)
      d.put(yIds[j], rec(yIds[j], target, own.concat(zIds).concat(yIds.slice(0, j + 1)),
        if (asDev) "device" else x.kind, if (asDev or frzDev) DEV.get(x.target) else if (kept) newKey else x.target,
        if (asDev) "" else x.kit, nextId,
        x.seen, Map(), Set(), x.units))
    })
    val s1 = zIds.concat(yIds).foldl(insertInto(s, r, dbH), (x, i) => insertInto(x, db2y.get(i), db2y))
    // The new root's first checkpoint: what the writer counts once the head applies (a look
    // ahead with the head as if its checkpoint were held).
    val r0 = { ...r, first: 0 }
    val db20 = db.put(nextId, r0)
    val v1 = finish(insertInto(s, r0, db20), db20)._2
    // (OWN_HEAD, rule C: the first checkpoint's head for its own key is its line up to its
    // prev: the new root's earlier records and the Zs.)
    val cHeads = if (OWN_HEAD and ownZ.length() > 0) heads.put(target, ownZ) else heads
    val c = rec(cpId, target, ownZ.append(cpId), "checkpoint", "", "", 0, cHeads, cHeads,
      v1.counting.filter(i => db2y.get(i).kind != "checkpoint" and not(idsOf(leftOut).contains(i)))
        .union(if (REISSUE_MUT == "notKept") Set() else zIds.concat(yIds).foldl(Set(), (a, i) => a.union(Set(i)))), 2)
    val db3 = if (withCp) db2y.put(cpId, c) else db2y
    all {
      RKEYS.contains(k),
      at >= 1,
      at <= ch.ids.length() + 1,
      cpId <= FIRST + MAXREC,
      // (LAST_ROOT_ONLY: every new root is a fresh key, never a former admin key.)
      not(LAST_ROOT_ONLY) or mode != "honest" or not(db.keys().exists(i => db.get(i).kind == "admin" and db.get(i).target == target)),
      // (REISSUE_REMOVALS: the writer's own check, as write_change's tests should assert: the
      // list names no removal a Z covers; listed twice it would take reserve for nothing.)
      not(REISSUE_REMOVALS) or mode != "honest" or keep.intersect(covered).size() == 0,
      // (J): the honest writer of a change refuses one whose new root's records and first
      // checkpoint would not fit the new root's ceiling.
      // (The new root's own device signs its first checkpoint, so its own set counts too.)
      // (A void change, NEW_ROOT_ONLY, writes no first checkpoint: nothing to fit.)
      not(CEIL_FIT) or mode != "honest" or not(withCp)
        or sumUnits(ofKey(recsOf(s.recs.union(st.get(HOLDER.get(target)).recs), db), target)) + 2 <= ROOTC,
      // (J): the root removals and the live admissions fit the reserve (else the writer cannot
      // list them all and refuses).
      not(CEIL_FIT) or mode != "honest" or fixedUnits <= RESERVE,
      // (Under NEW_ROOT_ONLY a void change leaves its first checkpoint's ID unused, so that old
      // traces keep their IDs.)
      commit(db3, if (withCp or (NEW_ROOT_ONLY and mode != "nocp" and onList(before, target))) cpId + 1 else cpId, h,
        if (withCp) insertInto(s1, c, db3) else s1),
    }
  }

  action signDevice = nondet k = Set(ROOT, PHONE, COMPUTER, "NA", "NK", MINTED).oneOf() nondet f = Set(true, false).oneOf()
    sign(k, "device", DEVICE, "", 0, false, f, 1)
  // A root (or a thief) names an admin; a root may name again one it removed.
  action signAdmin = nondet k = Set(ROOT, PHONE, "NA", "NK").oneOf() nondet a = Set(PHONE, COMPUTER, "C2", WATCH, MINTED, "NA").oneOf()
    nondet kit = Set("phone", "computer", "watch").oneOf() sign(k, "admin", a, kit, 0, false, false, 1)
  // A root takes the admin key off a device: a device record about it, with no admin key.
  action signDemote = nondet k = ROOT_KEYS.exclude(Set("NB")).oneOf() nondet d = Set("dA", "dC", "dW").oneOf() all {
    cpFirstOk(k, "device", d),
    sign(k, "device", d, "", 0, false, false, 1),
  }
  // Anyone removes or freezes anyone, the recovery key too (which no such record touches).
  action signRevoke = nondet k = SIGNERS.oneOf() nondet t = Set(PHONE, "dA", COMPUTER, WATCH, RECOVERY, DEVICE, MINTED).oneOf()
    nondet p = Set(true, false).oneOf() all { cpFirstOk(k, "revoke", t), sign(k, "revoke", t, "", 0, p, false, 1) }
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
    all { cpFirstOk(k, "resolve", ""), sign(k, "resolve", "", "", i, false, f, 1) }
  action signCheckpoint = nondet k = Set(ROOT, "NA", "NK").oneOf() sign(k, "checkpoint", "", "", 0, false, false, 2)
  // A root's record kept back from every member (a twin of its newest record, or the next
  // one), and a root's checkpoint whose keep names any record of its key, held or not.
  action signHidden = nondet k = ROOT_KEYS.exclude(Set("NB")).oneOf() nondet f = Set(true, false).oneOf()
    nondet kind = Set("admin", "revoke").oneOf() nondet t = Set(MINTED, PHONE, COMPUTER).oneOf()
    signFull(k, kind, t, "phone", 0, false, f, 1, true, Set())
  action signCheckpointNaming = nondet k = ROOT_KEYS.exclude(Set("NB")).oneOf() nondet i = db.keys().oneOf() all {
    db.get(i).signer == k,
    signFull(k, "checkpoint", "", "", 0, false, false, 2, false, Set(i)),
  }
  // An admin key uses a later root's key as a device's member key.
  action signUseKey = nondet k = Set(PHONE, COMPUTER, WATCH, MINTED).oneOf() nondet t = Set("NA", "NK", MINTED).oneOf()
    sign(k, "device", t, "", 0, false, false, 1)
  // (ROOT_WAITS: a live admin key acknowledges what it holds.)
  action signAck = nondet k = Set(PHONE, COMPUTER, WATCH).union(if (SPARE) Set("A1", "A2", "C2", "C3") else Set()).oneOf()
    all { ROOT_WAITS, ackS(k) }
  // (SPARE: the ack carries the signer's spare.)
  action ackS(k: Key): bool = sign(k, "ack", spareOf(k), "", 0, false, false, 1)
  action signCopies = nondet k = SIGNERS.oneOf() nondet u = Set(1, 2).oneOf() sign(k, "copies", "", "", 0, false, false, u)
  // Any recovery record at any place: a new root (or a key that was one, which is not
  // valid), any list.
  action signRecover = nondet t = Set("NA", "NK", ROOT).oneOf()
    nondet mode = Set("honest", "literal", "none", "all", "nocp", "from1").oneOf() nondet at = Set(1, 2, 3).oneOf()
    signChain(RECOVERY, "recover", t, at, mode)

  // A newcomer: m starts again from what admitter x hands it, the recovery chain and its
  // records (rule 33, point 9).
  pure def welcomeStore(sx: Store, db: Id -> Record): Store = {
    // In ID order, which puts each record after the records that name its signer's key, as the
    // core sends a set (in_dependency_order, section 4.9); a set's own fold order could offer a
    // key's record before its admission, and the newcomer would drop it for good (k.10501).
    val withChain = toList(sx.chain).foldl(EMPTY, (s, i) => insertInto(s, db.get(i), db))
    toList(sx.recs).foldl(pathed(withChain, db), (s, i) => insertInto(s, db.get(i), db))
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
  // (An ID no record has, a void change's unused first checkpoint under NEW_ROOT_ONLY, offers
  // nothing.)
  action giveOnly(m: str, i: Id): bool =
    commit(db, nextId, m, if (db.keys().contains(i)) insertInto(st.get(m), db.get(i), db) else st.get(m))
  // In the scenarios a head comes with its first checkpoint, when that was released.
  action give(m: str, i: Id): bool = if (not(db.keys().contains(i))) giveOnly(m, i) else {
    val r = db.get(i)
    val s1 = insertInto(st.get(m), r, db)
    // (REISSUE_REMOVALS: with the head's re-signed removals, its other first records.)
    val zs = if (isChain(r) and db.keys().contains(r.first) and r.first <= r.id + MAXREC)
      (r.id + 1).to(r.first - 1).filter(i => db.keys().contains(i) and namesZ(r, db.get(i))) else Set()
    val s2 = toList(zs).foldl(s1, (x, i) => insertInto(x, db.get(i), db))
    commit(db, nextId, m, if (isChain(r) and db.keys().contains(r.first)) insertInto(s2, db.get(r.first), db) else s2)
  }

  // Sync: a member is offered a record it does not keep (again, perhaps).
  action deliver = nondet m = MEMBERS.oneOf() nondet i = db.keys().oneOf() all {
    not(st.get(m).recs.contains(i)),
    not(st.get(m).chain.contains(i)),
    giveOnly(m, i),
  }

  // A member restarts: the core does not store the cut, so its marks are lost.
  // A restart reloads the saved set. RESTART_KEEPS_CUT: the cut (its marks) is saved too.
  // RESTART_REOFFERS: after the reload every record the member got is offered again, in ID
  // order, so what the old cut refused is judged under the new one (seed j.8004).
  pure val RESTART_KEEPS_CUT = false
  pure val RESTART_REOFFERS = true
  // A restart from what the set saves alone (the exhaustive-check thread, 11-13 23:56Z, after
  // the core's restore broke): the chain's heads, its first records unless a held checkpoint
  // prunes them, then the rooms and the place aside; got and the cut are forgotten.
  pure def savedChain(s: Store, db: Id -> Record): Set[Id] = {
    // Only the checkpoint the set compacted on drops first records (the core's compact uses the
    // counting checkpoints), not any checkpoint it merely holds (k.10967: a bent one).
    val cps = if (s.checkpoint == 0) Set() else Set(db.get(s.checkpoint))
    s.chain.filter(i => isChain(db.get(i)) or not(cps.exists(c => prunedBy(c, db.get(i))))
      or (SAVE_FIRSTS and s.chain.exists(h => isChain(db.get(h)) and namesFirst(db.get(h), db.get(i)))))
  }
  pure def rebuiltFromSaved(s: Store, db: Id -> Record): (Store, View) = {
    val ch = savedChain(s, db)
    val s1 = toList(ch).foldl(EMPTY, (x, i) => insertInto(x, db.get(i), db))
    val s2 = toList(s.recs.union(s.wait).union(earlyAside(s, db)).exclude(ch)).foldl(s1, (x, i) => insertInto(x, db.get(i), db))
    // A second pass, as the core loads in dependency order: a record whose signer only a later
    // record names (a root fork's proof, kept beside the chain) is taken once its signer is known.
    finish(toList(ch.union(s.recs).union(s.wait).union(earlyAside(s, db))).foldl(s2, (x, i) => insertInto(x, db.get(i), db)), db)
  }
  // (EARLY_ASIDE: what the set holds aside, and saves, of the roots its held heads name and its
  // path does not reach yet: under EARLY_ROOM what that room keeps, else all it got of them.)
  pure def earlyAside(s: Store, db: Id -> Record): Set[Id] =
    if (not(EARLY_ASIDE)) Set()
    else if (EARLY_ROOM) earlyKept(s, db).exclude(s.chain)
    else {
      val early = recsOf(s.chain, db).filter(h => isChain(h) and not(onList(s.path, h.target))).map(h => h.target)
      idsOf(recsOf(s.got, db).filter(r => not(isChain(r)) and not(s.chain.contains(r.id)) and early.contains(r.signer)))
    }
  action restartSaved(m: str): bool = commit(db, nextId, m, rebuiltFromSaved(st.get(m), db)._1)
  // Every member that is not halted shows, rebuilt from what it saves, the view it shows.
  // (A member halted on a root fork is exempt: it takes nothing more, and the counting
  // checkpoint it shows while halted depends on when the fork's proof came.)
  val savedStable = MEMBERS.forall(m => chainState(st.get(m), db).stop or views.get(m).stop
    or rebuiltFromSaved(st.get(m), db)._2 == views.get(m))

  action restart(m: str): bool = {
    val s0 = recut({ ...st.get(m), cut: if (RESTART_KEEPS_CUT) st.get(m).cut else NOCUT }, db)
    val s1 = if (RESTART_REOFFERS) range(1, nextId).select(i => s0.got.contains(i)).foldl(s0, (s, i) => insertInto(s, db.get(i), db)) else s0
    commit(db, nextId, m, s1)
  }
  // A member compacts: it takes its state's checkpoint.
  action compact = nondet m = MEMBERS.oneOf() compactAt(m)
  action compactAt(m: str): bool = commit(db, nextId, m, compactStore(st.get(m), views.get(m), db))

  action step = any {
    signDevice, signDemote, signAdmin, signRevoke, signFreeze, signThaw, signResolve, signCheckpoint, signCopies,
    signAck, signUseKey, signAfterThaw, signHidden, signCheckpointNaming, signRecover, welcomeNewcomer,
    deliver, fetch, fetch, fetch, compact,
  }

  // Only the honest writers and the network (no hidden, thief or bent record), for searches of
  // what honest groups reach.
  action stepHonest = any {
    signDevice, signDemote, signAdmin, signRevoke, signFreeze, signThaw, signResolve, signCheckpoint, signCopies,
    signAck, deliver, fetch, fetch, fetch, compact,
  }
  // (HELD_ADMISSIONS (a), a check, not a promise: every admin key's record a member holds has
  // its admission held beside it.)
  val admissionHeld = MEMBERS.forall(m => views.get(m).stop or {
    val rs = recsOf(st.get(m).recs, db)
    rs.forall(r => onList(views.get(m).path, r.signer) or admissionsOf(rs, r.signer) != Set())
  })

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
      // No change while the set holds a recovery record it has not applied (format 20.3).
      recsOf(st.get("k").got, db).filter(r => isChain(r)).forall(r => ch.ids.indices().exists(j => ch.ids[j] == r.id)),
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
  action rootRemovesPhone = nondet k = ROOT_KEYS.exclude(Set("NB")).oneOf() all {
    onList(views.get(HOLDER.get(k)).path, k),
    cpFirstOk(k, "revoke", PHONE),
    sign(k, "revoke", PHONE, "", 0, false, false, 1),
  }
  // (CP_FIRST) Root k's removal or take-back of an admin key its holder counts, with the root's
  // counting checkpoint not covering that key's whole line.
  def uncovered(k: Key, kind: str, target: Key): bool = {
    val h = HOLDER.get(k)
    val vh = views.get(h)
    val mine = recsOf(st.get(h).recs, db)
    val admins = vh.admins.keys()
    val takes = withPair(target).union(admins.filter(a => DEV.get(a) == target)).filter(a => admins.contains(a))
    val cpNow = if (vh.checkpoint == 0) NONEREC else db.get(vh.checkpoint)
    CP_FIRST and ROOT_KEYS.contains(k) and onList(vh.path, k)
      and ((kind == "revoke" and takes != Set()) or (kind == "device" and DEVS.contains(target) and takes != Set()))
      and not(cpNow.signer == k and takes.forall(a => lineOf(cpNow.heads, a) == headLine(mine, a)))
  }
  // The honest writer checkpoints first when it can: an uncovered removal only when no
  // checkpoint can be written (then it goes, warned).
  def cpFirstOk(k: Key, kind: str, target: Key): bool =
    not(uncovered(k, kind, target) or tightExempt(k, kind)) or not(cpWritableK(k))
  // (WRITER_CP_FLOOR with CP_FIRST, records b37218ee: before an exempt record (a root's removal or
  // resolve), the writer checkpoints first when the root's units, two exempt records and a
  // checkpoint would pass its ceiling; the exempt record itself is never refused.) Tight and the
  // root's newest record is not its counting checkpoint.
  def tightExempt(k: Key, kind: str): bool = {
    val h = HOLDER.get(k)
    val vh = views.get(h)
    val newest = ofKey(recsOf(st.get(h).recs, db), k).fold(NONEREC, (b, x) => if (x.seq > b.seq) x else b)
    WRITER_CP_FLOOR and CP_FIRST and ROOT_KEYS.contains(k) and onList(vh.path, k) and (kind == "revoke" or kind == "resolve")
      and rootUnits(st.get(h), k) + 2 + CP_UNITS > ROOTC and not(newest.id == vh.checkpoint and newest.id != 0)
  }
  // (CP_FIRST) A bent root removes an admin key without checkpointing first.
  action rootRemovesNoCp = nondet k = ROOT_KEYS.exclude(Set("NB")).oneOf() nondet t = Set(PHONE, COMPUTER, WATCH, MINTED).oneOf() all {
    CP_FIRST,
    onList(views.get(HOLDER.get(k)).path, k),
    sign(k, "revoke", t, "nocp", 0, false, false, 1),
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
  action offerEveryone(i: Id): bool = commitAll(MEMBERS.mapBy(m =>
    finish(if (db.keys().contains(i)) insertInto(st.get(m), db.get(i), db) else st.get(m), db)))
  action broadcast = nondet i = db.keys().oneOf() offerEveryone(i)
  action broadcastNewest = offerEveryone(nextId - 1)
  // Sync with fairness: every member is offered, in ID order, every record some member holds.
  action syncAll = {
    val held = MEMBERS.fold(Set(), (u, n) => u.union(st.get(n).recs).union(st.get(n).chain).union(st.get(n).wait))
    val order = range(1, nextId).select(i => held.contains(i))
    commitAll(MEMBERS.mapBy(m => finish(order.foldl(st.get(m), (s, i) => insertInto(s, db.get(i), db)), db)))
  }
  // --- Protocol-shaped sync -----------------------------------------------------------------
  // A peer lists what it keeps in its rooms and its chain. A member asks for what its missing()
  // names: what the current root's first checkpoint and the checkpoints that wait keep, which it
  // does not hold; a record so named is taken from anyone, from a peer's place aside too. One
  // record at a time, in any order. (The core gives a named record up after MISSING_ROUNDS
  // rounds and raises a local notice: liveness, not a rule; the model asks again.)
  pure def heldBy(s: Store): Set[Id] = s.recs.union(s.chain).union(s.wait)
  pure def missingOf(s: Store, db: Id -> Record): Set[Id] = {
    val cur = last(keptPath(s, db))
    val ws = waitingCps(s, db)
    val top = ws.fold(0, (x, c) => max2(x, c.seq))
    firstsHeld(s, db).filter(c => c.signer == cur).union(if (MISSING_NEWEST_ONLY) ws.filter(c => c.seq == top) else ws)
      .fold(Set(), (u, c) => u.union(c.keep)).exclude(heldBy(s)).filter(i => db.keys().contains(i))
  }
  pure def listedTo(n: Store, s: Store, db: Id -> Record): Set[Id] =
    n.recs.union(n.chain).union(n.wait.intersect(missingOf(s, db)))
  // SYNC_MEMBERS_ONLY: a member syncs only with a peer holding a key its state counts (a root
  // on its path, an admin, a device of one, the recovery key); NEWEST_HEAD_ANY (the remedy for
  // a recovery fork, simulator seed 5262): the newest recovery records of a peer's chain are
  // handed to and taken from any peer holding a key the member's set ever knew, member or not;
  // nothing else is.
  pure val SYNC_MEMBERS_ONLY = false
  pure val NEWEST_HEAD_ANY = false
  // The road for recovery heads (architecture 18:25Z, simulator 1460 and seed 5262): to a peer
  // whose standing is Unknown or that a change cut (its state counts no key of the other), a
  // member hands only the recovery heads with their lists, and takes only those from it. A
  // member that holds a verified head above what it applied whose list does not name it is
  // left out ("pair again"): it counts nobody and obeys nobody. The newcomer m's key is MDEV.
  pure val UNKNOWN_HEADS = false
  // The newcomer m's device key under UNKNOWN_HEADS (no other scenario names it).
  pure val MDEV = "dM"
  // With UNKNOWN_HEADS: the first checkpoints cross with the heads (random run u.9111: the new
  // root removes a member its list still admits; its peers then count it as no member and hand
  // it the heads alone, so it can never apply them, is not left out, and stays live on the old
  // root).
  pure val HEADS_WITH_FIRSTS = false
  // Members gone for good (a lost root device): they neither hand nor take anything.
  pure val LOST = Set()
  pure def keysOfMember(n: str): Set[Key] = {
    val ks = HOLDER.keys().filter(k => HOLDER.get(k) == n)
    ks.union(ks.filter(k => DEV.keys().contains(k)).map(k => DEV.get(k)))
      .union(if (UNKNOWN_HEADS and n == "m") Set(MDEV) else Set())
  }
  // Under UNKNOWN_HEADS: m holds a verified head (the recovery key's, on a valid chain) above
  // the chain it applied, and that head's list admits none of m's keys (or removes them), nor is one of them a
  // root on the path the heads make. (The recovery key's holder is known to every member.)
  def leftOut(m: str): bool = {
    val s = st.get(m)
    val raw = chainHeads(recsOf(s.chain, db))
    val applied = chainState(s, db).ids.length()
    val v = views.get(m)
    UNKNOWN_HEADS and keysOfMember(m) != Set() and raw.recs.length() > 0 and {
      val h = raw.recs[raw.recs.length() - 1]
      val listed = recsOf(h.keep.filter(i => db.keys().contains(i)), db)
      val named = keysOfMember(m).exists(x => onList(pathCutsOf(raw.recs)._1, x)
        or (admissionsOf(listed, x) != Set() and not(listed.exists(r => r.kind == "revoke" and tgt(r).contains(x)))))
      // Once it applied every head, its own state decides (a new root's record may admit it).
      val ownCounts = raw.recs.length() == applied and keysOfMember(m).exists(x =>
        onList(v.path, x) or v.admins.keys().contains(x) or v.devices.contains(x))
      not(named) and not(ownCounts)
    }
  }
  def counts(m: str, n: str): bool = {
    val v = views.get(m)
    keysOfMember(n).exists(x => onList(v.path, x) or v.admins.keys().contains(x) or v.devices.contains(x)
      or (UNKNOWN_HEADS and x == RECOVERY))
      // The newcomer m stands for a device admitted outside the scenario: known on the first
      // root while D is not removed; after a change only a list or a new root's record admits it.
      or (UNKNOWN_HEADS and n == "m" and v.path.length() == 1 and not(v.revoked.contains(MDEV)))
  }
  def everKnew(m: str, n: str): bool = {
    val known = recsOf(st.get(m).got, db).fold(Set(), (a, r) => a.union(Set(r.signer, r.target)).union(r.also))
    keysOfMember(n).exists(x => known.contains(x) or ROOT == x)
  }
  def listedFrom(n: str, m: str): Set[Id] =
    if (LOST.contains(n) or LOST.contains(m)) Set()
    else if (UNKNOWN_HEADS and not(counts(m, n) and counts(n, m))) headsOf(st.get(n))
    else if (not(SYNC_MEMBERS_ONLY) or counts(m, n)) listedTo(st.get(n), st.get(m), db)
    else if (NEWEST_HEAD_ANY and everKnew(m, n)) st.get(n).chain.filter(i => isChain(db.get(i)))
    else Set()
  def fetchable(m: str): Set[Id] =
    MEMBERS.exclude(Set(m)).fold(Set(), (u, n) => u.union(listedFrom(n, m))).exclude(heldBy(st.get(m)))
  action fetch = nondet m = MEMBERS.oneOf() nondet i = db.keys().oneOf() all {
    fetchable(m).contains(i),
    giveOnly(m, i),
  }
  // One round for every member: it takes, in ID order, what its peers listed to it when the
  // round began.
  action syncRound = commitAll(MEMBERS.mapBy(m => {
    val order = range(1, nextId).select(i => fetchable(m).contains(i))
    finish(order.foldl(st.get(m), (s, i) => insertInto(s, db.get(i), db)), db)
  }))
  // A member whose fetches would all leave it as it is.
  def syncedProto(m: str): bool = fetchable(m).forall(i => {
    val s2 = insertInto(st.get(m), db.get(i), db)
    s2.recs == st.get(m).recs and s2.chain == st.get(m).chain and s2.wait == st.get(m).wait
  })

  action guided = any {
    step, signChange, signChange, signChange, signNewRoot, signNewRoot, signNewRoot, signCopies, signCheckpoint,
    broadcast, broadcastNewest, broadcastNewest, broadcastNewest, broadcastNewest, fetch,
    compact, compact, syncRound, syncRound, oldRootThief, oldRootThief, oldRootThief, rootRemovesPhone,
    removedAdminThief, removedAdminThief, removedAdminThief, recoveryTwin, signRecover,
    signThaw, signAfterThaw, welcomeNewcomer, signHidden, signCheckpointNaming, signBent, restartAny,
    restartAny, deviateAny, rootRemovesNoCp, signAck, signAck,
  }
  action restartAny = nondet m = MEMBERS.oneOf() restart(m)
  // A key publishes past what its own set keeps (a deviating writer, kit "deviant").
  action deviateAny = nondet k = Set(PHONE, COMPUTER, WATCH, "X", "NA", "NK", ROOT).oneOf() nondet u = 1.to(MAXU).oneOf()
    nondet kind = Set("copies", "device").oneOf()
    signDeviant(k, kind, if (kind == "device") DEVICE else "", u)

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
    s.got.forall(i => { val s2 = insertInto(s, db.get(i), db) s2.recs == s.recs and s2.wait == s.wait })
  }

  // 1. One set, one state. (A halted set keeps what it had and takes recovery records only;
  // what it shows then is promise 11's.)
  val oneState = MEMBERS.forall(m => {
    val s = st.get(m)
    // With the honest writer always; otherwise under the place aside's assumption (1b) on
    // what the member got.
    ((honestOnly or asideAssumed(m, s.got)) and saturated(m) and not(chainState(s, db).stop))
      implies (s.recs == pureKept(s, db) and views.get(m) == pureView(s, db))
  })

  // 1b. Sync converges: a member offered, to no change, every record some member holds keeps
  // what a member given all those records at once keeps, and shows the same state.
  pure def freshOf(s: Store): Store = { ...s, checkpoint: 0, cut: NOCUT, wait: Set() }
  // The member given at once every record some member holds, after it compacts on the
  // checkpoint it counts.
  def heldAll: Set[Id] = MEMBERS.fold(Set(), (u, n) => u.union(st.get(n).recs).union(st.get(n).chain).union(st.get(n).wait))
  pure def freshKept(s: Store, items: Set[Id], db: Id -> Record): Set[Id] = {
    val k1 = settle(freshOf(s), recsOf(items, db).filter(r => storable(freshOf(s), r, db)), NOCUT, db)._1
    val c1 = fullEvaluate(recsOf(k1, db).union(firstsHeld(s, db)), chainState(s, db)).checkpoint
    val s1 = { ...freshOf(s), checkpoint: c1 }
    settle(s1, recsOf(items, db).filter(r => storable(s1, r, db)), NOCUT, db)._1
  }
  // What m can reach: everything under the default road; under UNKNOWN_HEADS its own, what the
  // peers it and that count it hold, and the heads of every other peer.
  def heldReach(m: str): Set[Id] =
    if (not(UNKNOWN_HEADS)) heldAll
    else MEMBERS.exclude(LOST).fold(heldBy(st.get(m)).union(st.get(m).chain), (u, n) =>
      if (n == m) u
      // (A peer's place aside holds records for a checkpoint of its current root; at the
      // exchange the member with the shorter chain takes the other's heads and judges its place
      // aside again, and a checkpoint of a root no longer current waits for nothing (the one
      // judgment, D1; fuzz replay of decW 11419 at 9e20ec86). So the place aside reaches m only
      // from a peer whose path m's path starts: its current root stays current at the exchange.)
      else if (counts(m, n) and counts(n, m)) u.union(st.get(n).recs).union(st.get(n).chain).union({
        val pm = keptPath(st.get(m), db)
        val pn = keptPath(st.get(n), db)
        if (pn.length() >= pm.length() and pn.slice(0, pm.length()) == pm) st.get(n).wait else Set() })
      else u.union(headsOf(st.get(n))))
  // What crosses to and from an Unknown peer: the recovery heads (their lists ride in them),
  // and under HEADS_WITH_FIRSTS what the set keeps beside its chain too, the heads' first
  // checkpoints among it (each verifies under the key its head names).
  // (REISSUE_STATE: a head's Ys are its first records too, though the set keeps them in the new
  // root's room: they cross with the head.)
  def headsOf(s: Store): Set[Id] = if (HEADS_WITH_FIRSTS) s.chain.union({
      val hs = recsOf(s.chain, db).filter(h => isChain(h))
      idsOf(recsOf(s.recs.union(s.wait), db).filter(y => hs.exists(h => namesZ(h, y)))) })
    else s.chain.filter(i => isChain(db.get(i)))
  def convergesAt(m: str): bool = {
    val s = st.get(m)
    val k = freshKept(s, heldReach(m), db)
    // (A member left out under UNKNOWN_HEADS is to pair again: it takes heads alone.)
    (syncedProto(m) and not(chainState(s, db).stop) and not(views.get(m).stop) and not(leftOut(m))) implies (s.recs == k
      and views.get(m) == fullEvaluate(recsOf(k, db).union(firstsHeld(s, db)), chainState(s, db)))
  }
  // What users get: with the honest writer (it never keeps what it pruned, never lowers a head,
  // keeps what counts) sync converges with no assumption.
  // (No bent checkpoint and no recovery list the core does not write: seed j.8015, a change
  // back to the root at "from1" past the new root's ceiling.)
  def honestOnly: bool = db.keys().forall(i => db.get(i).kit != "bent" and not(isChain(db.get(i)) and db.get(i).kit == "deviant"))
  val convergesHonest = honestOnly implies MEMBERS.forall(m => convergesAt(m))
  // In general, under a stated assumption on the place aside: a holder of the root key that
  // signs a checkpoint which can never be whole and keeps more old records than the place
  // aside holds can keep a member at an older checkpoint than its peers. The assumption: what
  // the checkpoints of the current root above the member's that some member holds, from the
  // newest one that can become whole on, keep outside the member's rooms fits the place aside. (A checkpoint can become whole when some
  // member holds every record it names.)
  pure def wholeableIn(c: Record, items: Set[Id]): bool = c.keep.subseteq(items)
    and (c.line.length() < 2 or items.contains(c.line[c.line.length() - 2]))
  def asideFits(m: str): bool = asideFitsIn(m, heldAll)
  def asideFitsIn(m: str, items: Set[Id]): bool = {
    val s = st.get(m)
    val cseq = if (s.checkpoint == 0) 0 else db.get(s.checkpoint).seq
    val ws = recsOf(items, db).filter(c => c.kind == "checkpoint" and c.signer == last(keptPath(s, db)) and c.seq > cseq)
    val top = ws.filter(c => wholeableIn(c, items)).fold(0, (x, c) => max2(x, c.seq))
    val over = ws.filter(c => c.seq >= top).fold(Set(), (u, c) =>
      u.union(c.keep).union(if (c.line.length() < 2) Set() else Set(c.line[c.line.length() - 2])))
      .exclude(s.recs).filter(i => db.keys().contains(i))
    top == 0 or sumUnits(recsOf(over, db)) <= ASIDE_ROOM
  }
  // Without the waited record aside, an older waiting checkpoint the rooms turn away is held
  // nowhere aside; the assumption then: the newest checkpoint of the current root above the
  // member's that some member holds can become whole.
  def newestWholeable(m: str): bool = newestWholeableIn(m, heldAll)
  def newestWholeableIn(m: str, items: Set[Id]): bool = {
    val s = st.get(m)
    val cseq = if (s.checkpoint == 0) 0 else db.get(s.checkpoint).seq
    val ws = recsOf(items, db).filter(c => c.kind == "checkpoint" and c.signer == last(keptPath(s, db)) and c.seq > cseq)
    val top = ws.fold(0, (x, c) => max2(x, c.seq))
    ws.filter(c => c.seq == top).forall(c => wholeableIn(c, items))
  }
  // The assumption on the records items.
  def asideAssumed(m: str, items: Set[Id]): bool =
    if (ASIDE_TAKES_WAITED) asideFitsIn(m, items) else newestWholeableIn(m, items)
  val converges = MEMBERS.forall(m => asideAssumed(m, heldAll) implies convergesAt(m))
  // 1c. No checkpoint of the current root newer than the counting one counts on the set alone:
  // a newer one that is not whole takes nothing from the counting one.
  val countsNewest = MEMBERS.forall(m => {
    val v = views.get(m)
    val rs = recsOf(st.get(m).recs, db)
    val cseq = if (v.checkpoint == 0) 0 else db.get(v.checkpoint).seq
    val floor = rootFloor(rs.union(firstsHeld(st.get(m), db)), chainState(st.get(m), db), last(v.path))
    // (A held root fork's pair, also one beside the rooms, bars the root's checkpoints at or
    // above its seq, as in fullEvaluate.)
    val all1 = rs.union(firstsHeld(st.get(m), db))
    val forkS = all1.filter(a => a.signer == last(v.path) and all1.exists(b => b != a and b.signer == a.signer and b.seq == a.seq))
      .fold(NONE, (x, r) => min2(x, r.seq))
    v.stop or rs.forall(c => not(c.kind == "checkpoint" and c.signer == last(v.path) and c.seq > cseq and c.seq >= floor and c.seq < forkS
      and applyCheckpoint(v.path, v.cuts, c.id, (rs, Set(), epoch(rs, v.path, v.cuts, Set())))._3.checkpoint == c.id))
  })

  // 2. A key a root removed stays removed, unless a change of root left the removal off its
  // list.
  pure def cutOff(v: View, r: Record): bool = not(within(v.cuts, r))
  // A gap is liveness, not a rule: an honest peer that holds a line serves it, so a member is
  // checked once it was offered, to no change, every record some member holds.
  def synced(m: str): bool = MEMBERS.forall(n => st.get(n).recs.union(st.get(n).chain).union(st.get(n).wait).forall(i => {
    val s2 = insertInto(st.get(m), db.get(i), db)
    s2.recs == st.get(m).recs and s2.chain == st.get(m).chain and s2.wait == st.get(m).wait
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
  // An honest head on the member's chain whose writer held the removal (the ghost "_rm"): a
  // list may leave out only what its writer never held (break 1 of 11-13 20:42Z: the core's
  // list dropped a held removal of a key no held record named, and a late admission revived it).
  // The newest recovery record written (the scenarios' last change).
  val lastHead = db.keys().filter(i => isChain(db.get(i))).fold(0, (a, i) => max2(a, i))
  def writerHeld(m: str, r: Record): bool = recsOf(st.get(m).chain, db).exists(h => isChain(h) and h.kit == ""
    and h.seen.keys().contains("_rm") and h.seen.get("_rm").indices().exists(j => h.seen.get("_rm")[j] == r.id))
  val removedStayOut = MEMBERS.forall(m => synced(m) implies {
    val v = views.get(m)
    // Removals by the roots on the member's path (a key that is a root elsewhere, not here,
    // removes nothing).
    val removals = recsOf(st.get(m).got, db).filter(r => r.kind == "revoke" and onList(v.path, r.signer))
    v.stop or gone.get(m).forall(k =>
      removals.filter(r => tgt(r).contains(k)).forall(r => not(writerHeld(m, r))
          and (cutOff(v, r) or (cutEarlier(m, r) and heldByNone(r))))
        or (not(v.admins.keys().contains(k)) and not(v.devices.contains(k)))
        or recsOf(v.counting, db).exists(x => admissionsOf(Set(x), k) != Set()
          and removals.forall(r => not(tgt(r).contains(k)) or x.id > r.id))
        // The current root brought it back itself: its counting checkpoint keeps the admission
        // and leaves out every root removal naming the key (review C, 11:54Z).
        or (v.checkpoint != 0 and db.get(v.checkpoint).signer == last(v.path) and recsOf(v.counting, db).exists(x =>
          admissionsOf(Set(x), k) != Set() and db.get(v.checkpoint).keep.contains(x.id)
            and removals.forall(r => not(tgt(r).contains(k)) or not(rootRemoval(r))
              or prunedBy(db.get(v.checkpoint), r)))))
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
    // A counting checkpoint of the current root and the records it names are kept first: the
    // fair share is of the room they leave, among the keys with a record they do not name.
    val cp = rs.filter(c => c.id == views.get(m).checkpoint and c.signer == last(path)).fold(NONEREC, (a, c) => c)
    val first = if (cp == NONEREC) Set() else rs.filter(r => r == cp or namedBy(cp, r, rs))
    val others = owners.filter(k => got.exists(r => r.signer == k and storable(s, r, db) and not(first.contains(r))))
    val fair = if (others.size() == 0) ROOM else (ROOM - sumUnits(first)) / others.size()
    // (FIXED_CAPS: each key's share is its cap from the roster alone: the current root's ceiling,
    // the cut roots' reserve, a live admin key's ceiling, 0 for any other key.)
    val ros = rosterOf(rs.union(firstsHeld(s, db)), path)
    def shareOf(k: Key): int =
      if (not(FIXED_CAPS)) fair
      else if (k == last(path)) ROOTC
      else if (onList(path, k)) RESERVE
      else if (ros.live.contains(k)) ADMINC
      else 0
    and {
      ceil.keys().forall(k => legit.contains(k)),
      sumUnits(rs) <= ROOM,
      rs.map(r => r.signer).forall(k => ceil.keys().contains(k) and sumUnits(ofKey(rs, k)) <= ceil.get(k)),
      // (A member halted on a root fork takes nothing more: no share is owed to it; dec seed 11415.)
      (saturated(m) and not(chainState(s, db).stop) and not(views.get(m).stop)) implies others.forall(k =>
        sumUnits(ofKey(rs, k)) + MAXU - 1 >= min2(shareOf(k), min2(ceil.get(k), sumUnits(ofKey(got.filter(r => storable(s, r, db)
          // Under "gapless" a record past a gap in what the set holds has no count.
          and (CUT_MODE != "gapless" or gapFree(s, r, recsOf(heldBy(s), db), db))), k))))),
    }
  })

  // 7. A member follows the recovery chain it holds: its path is the first root and the new
  // roots of that chain (each head with its first checkpoint), and its replaced roots keep
  // what the chain's records list.
  val followsRecovery = MEMBERS.forall(m => {
    val v = views.get(m)
    val pc = pathCutsOf(chainOf(recsOf(st.get(m).got, db)).recs)
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
  // (Made stricter 11-13 22:10Z, with removedStayOut: a removal a change cut off though an
  // honest writer on the member's chain held it still bars, as if it counted; packing two
  // removals that saw a key differently into one, REISSUE_PACK_ANY, fails here.)
  // (Architecture 11-14 20:06Z, limit A: the promise holds while the recovery key and every root
  // sign no twin and no checkpoint that omits a removal they count; deviant admins and former
  // admins stay inside it. A twin head at one seq, a list the core does not write (kit
  // "deviant", which also covers its first checkpoint), and a bent root checkpoint are outside.
  // dec seed 11422: a "literal" twin head of the recovery key, whose first checkpoint, signed
  // with the named root's key, leaves out that root's re-signed removal.)
  def topKeysHonest: bool = {
    val chains = db.keys().map(i => db.get(i)).filter(r => isChain(r))
    chains.forall(a => a.kit != "deviant" and chains.forall(b => b == a or b.seq != a.seq))
      and db.keys().forall(i => not(ROOT_KEYS.contains(db.get(i).signer) and db.get(i).kind == "checkpoint"
        and db.get(i).kit == "bent"))
  }
  val removedGainsNothing = not(topKeysHonest) or MEMBERS.forall(m => {
    val v = views.get(m)
    val cnt = recsOf(v.counting, db)
    val cutHeld = recsOf(st.get(m).got, db).filter(r => r.kind == "revoke" and cutOff(v, r) and writerHeld(m, r))
    val removals = cnt.filter(r => r.kind == "revoke").union(cutHeld)
    cnt.forall(r => removals.filter(rm => tgt(rm).contains(r.signer) and rm != r).forall(rm =>
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
  val compactedAgree = MEMBERS.forall(m1 => MEMBERS.forall(m2 => {
    val s1 = st.get(m1)
    val s2 = st.get(m2)
    (s1.chain == s2.chain and s1.got == s2.got and not(chainState(s1, db).stop) and firstCheckpointHeld(m1)
      and saturated(m1) and saturated(m2)) implies views.get(m1) == views.get(m2)
  }))
  // Promise 13 was tried: two members that agree in what it asks for, compacted on a
  // checkpoint.
  val agreeTried = MEMBERS.exists(m1 => MEMBERS.exists(m2 => {
    val s1 = st.get(m1)
    val s2 = st.get(m2)
    m1 != m2 and s1.chain == s2.chain and s1.got == s2.got and firstCheckpointHeld(m1) and s1.checkpoint != 0
      and saturated(m1) and saturated(m2)
  }))

  // F-12. A member held back counts no device or admin key that a member further on does not:
  // one with the same path that counts a checkpoint the first holds above its own, and holds
  // the same removals and freezes.
  val heldBackCountsLess = MEMBERS.forall(m => MEMBERS.forall(n => {
    val vm = views.get(m)
    val vn = views.get(n)
    val rm = recsOf(st.get(m).recs, db).filter(r => r.kind == "revoke" or r.kind == "freeze")
    val rn = recsOf(st.get(n).recs, db).filter(r => r.kind == "revoke" or r.kind == "freeze")
    val cm = if (vm.checkpoint == 0) 0 else db.get(vm.checkpoint).seq
    val ahead = not(vm.stop) and not(vn.stop) and vm.path == vn.path and vn.checkpoint != 0
      and st.get(m).recs.contains(vn.checkpoint) and db.get(vn.checkpoint).seq > cm and rm == rn
    ahead implies (vm.devices.subseteq(vn.devices) and vm.admins.keys().subseteq(vn.admins.keys()))
  }))

  // (H). With honest writers no record is turned away by the rooms: a synced member holds
  // every record it got that it may store and its counting checkpoint does not prune (that
  // it gets every record is converges').
  // (No bent, deviating or hidden record, and no recovery twin: two recovery records at one
  // seq. An honest recovery writer is the core's write_change: the list it builds from its own
  // set, mode "honest" in signChain; any other list is a deviating recovery key.)
  def honestW: bool = db.keys().forall(i => db.get(i).kit != "bent" and db.get(i).kit != "deviant" and db.get(i).kit != "unchecked" and not(db.get(i).off)
    and not(isChain(db.get(i)) and db.keys().exists(j => j != i and isChain(db.get(j)) and db.get(j).seq == db.get(i).seq)))
  val honestNeverDropped = ((WRITER_FLOOR or CEIL_FIT) and honestW) implies MEMBERS.forall(m => {
    val s = st.get(m)
    val v = views.get(m)
    val c = if (v.checkpoint == 0) NONEREC else db.get(v.checkpoint)
    (syncedProto(m) and not(v.stop) and not(chainState(s, db).stop) and not(leftOut(m))) implies recsOf(heldAll, db).forall(r =>
      isChain(r) or not(s.got.contains(r.id)) or not(storable(s, r, db)) or (c != NONEREC and prunedBy(c, r))
        or heldBy(s).contains(r.id)
        // (FIXED_CAPS: a key no longer an admin has cap 0; what it signed stays only as far as a
        // root's checkpoint keeps it.)
        or (FIXED_CAPS and not(onList(v.path, r.signer))
          and not(rosterOf(recsOf(s.recs, db).union(firstsHeld(s, db)), v.path).live.contains(r.signer)))
        // (LAST_ROOT_ONLY: after a change only the last root's records and those of the admin
        // keys it named are kept; what counted before was re-issued by the new root.)
        or (LAST_ROOT_ONLY and v.path.length() > 1 and r.signer != last(v.path) and not(v.admins.keys().contains(r.signer))))
  })

  // (J): with no bent checkpoint (deviating keys allowed), a mark never changes what a member
  // keeps: the set it would keep from no cut is the set it keeps (so a restart, which forgets
  // the cut, changes nothing).
  val marksInert = (CEIL_FIT and db.keys().forall(i => db.get(i).kit != "bent")) implies
    MEMBERS.forall(m => chainState(st.get(m), db).stop or recut({ ...st.get(m), cut: NOCUT }, db).recs == st.get(m).recs)
  // (J): with honest writers no member ever holds a mark.
  // (A member that holds a checkpoint before the records of its line can sit over a ceiling,
  // with a mark, until it syncs: the writer counted its own set after the prune; seed j.8012.)
  // (Under UNKNOWN_HEADS a removed member is out of the group and takes heads alone, not the
  // root's checkpoints: it may keep a mark; seed k.9501, a after R removed A. NOT a licence
  // under the decided rule: k.9501 fails without this exemption whenever UNKNOWN_HEADS is on,
  // and passes with PREV_ROOM_WHEN_KEPT + (J) without it. MARKS_GUARD turns it off.)
  pure val MARKS_GUARD = false
  val honestNoMarks = (CEIL_FIT and honestW) implies MEMBERS.forall(m =>
    (syncedProto(m) and (MARKS_GUARD or inGroup(m))) implies st.get(m).cut.marks.keys() == Set())

  // A restart keeps the state: a member's saved set, reloaded with no cut, keeps the same
  // records and shows the same state (what the simulator checks with restore, seed 47).
  val restartStable = MEMBERS.forall(m => {
    val s = st.get(m)
    val s2 = recut({ ...s, cut: NOCUT }, db)
    (not(views.get(m).stop) and not(chainState(s, db).stop)) implies
      (s2.recs == s.recs and fullEvaluate(recsOf(s2.recs, db).union(firstsHeld(s2, db)), chainState(s2, db)) == views.get(m))
  })

  // The members the root's device counts (all of them on the default road): under
  // UNKNOWN_HEADS a removed member, or one no list admits, takes heads alone and is not
  // expected to agree.
  def inGroup(m: str): bool = not(UNKNOWN_HEADS) or m == "r" or counts("r", m)

  // Under UNKNOWN_HEADS: no member stays live on an older root once a member past the change
  // can reach it: a member every peer has offered all it would hand keeps a path no shorter
  // than any reachable member's, unless it is left out or stopped.
  val noLiveOldRoot = UNKNOWN_HEADS implies MEMBERS.forall(m => syncedProto(m) implies MEMBERS.forall(n =>
    LOST.contains(n) or LOST.contains(m) or views.get(n).path.length() <= views.get(m).path.length()
      or leftOut(m) or chainState(st.get(m), db).stop or chainState(st.get(n), db).stop))

  // Not a promise yet: a member that holds two records of its current root at one seq, both
  // within its lists (in its rooms or beside its chain), is halted.
  val rootPairHalts = MEMBERS.forall(m => {
    val s = st.get(m)
    val v = views.get(m)
    val rs = recsOf(s.recs, db).union(firstsHeld(s, db))
    val cur = last(v.path)
    rs.exists(r => r.signer == cur and not(isChain(r)) and within(v.cuts, r)
      and rs.exists(o => o != r and o.signer == cur and o.seq == r.seq)) implies v.stop
  })

  val promises = and {
    oneState, converges, convergesHonest, countsNewest, removedStayOut, oneChainOneState, stopRootOnly, fairRoom, followsRecovery, pathGrows, newcomerTakes,
    oldRootListed, twinStops, removedGainsNothing, compactedAgree, F12 implies heldBackCountsLess, honestNeverDropped, honestNoMarks, marksInert,
    restartStable, noLiveOldRoot,
  }
  // (NEWEST_CP_FIRST's promise, architecture 11-14: a root's device records are never pushed out
  // of its room by its own checkpoints that do not count.) A member that got an admission record
  // of its current root within the lists, not pruned by its counting checkpoint, and does not
  // hold it, holds no later checkpoint of that root (by seq) other than the counting one and
  // the newest.
  val ownCpsNoCrowd = MEMBERS.forall(m => {
    val s = st.get(m)
    val v = views.get(m)
    val cur = last(v.path)
    val cps = recsOf(s.recs, db).filter(c => c.kind == "checkpoint" and c.signer == cur)
    val top = cps.fold(0, (x, c) => max2(x, c.seq))
    v.stop or recsOf(s.got, db).forall(d => not(d.signer == cur and (d.kind == "admin" or d.kind == "device")
      and within(v.cuts, d) and not(s.recs.contains(d.id))
      and (v.checkpoint == 0 or not(prunedBy(db.get(v.checkpoint), d))))
      or cps.forall(c => c.id == v.checkpoint or c.seq == top or c.seq < d.seq))
  })

  // (CP_FIRST's promise, architecture 11-14 12:50Z: an honest root's removal of an admin key loses
  // no device that counted before it.) A synced member that counts an honest removal of admin key
  // a by its current root still counts every device a admitted that the removal's seen covers,
  // unless another counting removal names that device.
  val cpFirstKeepsDevices = not(CP_FIRST) or MEMBERS.forall(m => {
    val v = views.get(m)
    val cnt = recsOf(v.counting, db)
    // (What the member got, not what it keeps now: a device the removal made it drop counted.)
    val held = recsOf(st.get(m).got, db).filter(x => not(isChain(x))).union(firstsHeld(st.get(m), db))
    v.stop or not(synced(m)) or cnt.forall(r => not(r.kind == "revoke" and r.kit == "" and r.signer == last(v.path)) or {
      // What counted just before r: the member's state without r (dec seed 11418: a device its
      // admitter signed after another counting removal of it never counted, so r loses nothing).
      val before = fullEvaluate(held.exclude(Set(r)), chainState(st.get(m), db)).devices
      tgt(r).forall(a => recsOf(st.get(m).got, db).forall(d => not(d.kind == "device" and d.signer == a
        and inLine(lineOf(r.seen, a), d.id) and before.contains(d.target)
        and not(cnt.exists(o => o.kind == "revoke" and o != r and tgt(o).contains(d.target))))
        or v.devices.contains(d.target)))
    })
  })

  // (FIXED_CAPS, records b37218ee P1: what a set holds is what the rooms keep of it, asserted in
  // the core's debug builds.)
  val tiersPure = not(FIXED_CAPS) or MEMBERS.forall(m => recut(st.get(m), db).recs == st.get(m).recs)
  // The invariant of the long random runs at the decided set: the promises and the decided
  // switches' own promises.
  // (Under a deviant top key too, architecture 11-14 20:06Z.) A member that holds two recovery
  // records at one seq, or two records of its current root at one seq, is halted: it shows a
  // stopped state with no commanders. (The pair is held beside the rooms and never dropped, so
  // the halt lasts until a change.)
  val twinHalts = MEMBERS.forall(m => {
    val s = st.get(m)
    val held = recsOf(heldBy(s), db)
    val cur = last(views.get(m).path)
    val chainTwin = held.exists(a => isChain(a) and held.exists(b => b != a and isChain(b) and b.seq == a.seq))
    val rootTwin = held.exists(a => a.signer == cur and not(isChain(a))
      and held.exists(b => b != a and b.signer == cur and not(isChain(b)) and b.seq == a.seq))
    (chainTwin or (HALT_ON_HELD_PAIR and rootTwin)) implies (views.get(m).stop and views.get(m).commanders == Set())
  })
  // Two members, each offered to no change what it got, that got the same records count the same
  // state, whoever signed them (convergence on equal sets, not on honest chains only). A halted
  // member is twinHalts' (what it counts while halted depends on when the pair came: random run
  // seed 777, four members halted at R's checkpoint 8 and R's own holder at 13 it signed first).
  def running(m: str): bool = not(views.get(m).stop) and not(chainState(st.get(m), db).stop)
  val sameGotSameState = MEMBERS.forall(m => MEMBERS.forall(n => (m == n
    or not(st.get(m).got == st.get(n).got and saturated(m) and saturated(n) and running(m) and running(n)))
    or (st.get(m).recs == st.get(n).recs and views.get(m) == views.get(n))))
  val decidedInv = and { promises, tiersPure, cpFirstKeepsDevices, ownCpsNoCrowd, twinHalts, sameGotSameState,
    not(GRANT_ABOVE) or grantHoldsRemoval, not(SPARE) or spareSafe }
  // (SPARE's promise: no key is named an admin key by two roots on the honest path, and no
  // record an admin key signed before its naming counts anywhere.)
  val spareSafe = and {
    db.keys().forall(i => db.keys().forall(j => {
      val a = db.get(i)
      val b = db.get(j)
      not(a.kind == "admin" and b.kind == "admin" and a.target == b.target and a.signer != b.signer
        and ROOT_KEYS.contains(a.signer) and ROOT_KEYS.contains(b.signer) and a.kit != "deviant" and b.kit != "deviant")
    })),
    MEMBERS.forall(m => views.get(m).stop or recsOf(views.get(m).counting, db).forall(x =>
      not(views.get(m).admins.keys().contains(x.signer)) or onList(views.get(m).path, x.signer)
      or recsOf(views.get(m).counting, db).exists(g => g.kind == "admin" and g.target == x.signer
        and g.signer == last(views.get(m).path) and g.id < x.id))),
  }
  // (GRANT_ABOVE's claim: a member that counts the root's grant of an admin key held by it, above
  // a removal of the same root on the grant's line, holds that removal, unless the counting
  // checkpoint it holds settled it.)
  val grantHoldsRemoval = MEMBERS.forall(m => views.get(m).stop or {
    val rs = recsOf(st.get(m).recs, db)
    val cp = views.get(m).checkpoint
    rs.forall(g => not(g.kind == "admin" and views.get(m).counting.contains(g.id) and ROOT_KEYS.contains(g.signer)
        and HOLDER.keys().contains(g.target)
        and HOLDER.get(g.target) == m) or
      db.keys().forall(i => {
        val r = db.get(i)
        not(r.kind == "revoke" and r.signer == g.signer and r.seq < g.seq and inLine(g.line, r.id))
          or st.get(m).recs.contains(r.id)
          or (cp != 0 and db.get(cp).signer == r.signer and db.get(cp).seq > r.seq and not(db.get(cp).keep.contains(r.id)))
          // (A new root re-signed it: m holds a Z of the change that covers its keys; GAr.13004.)
          // (Zs sit beside the chain, in chain, not in recs.)
          or recsOf(st.get(m).recs.union(st.get(m).chain), db).exists(z => z.kit == "z" and tgt(r).subseteq(tgt(z)))
      }))
  })

  // --- Scenarios ---------------------------------------------------------------------------

  action signAs(k: Key, kind: str, target: Key, targetRec: Id): bool =
    sign(k, kind, target, "", targetRec, false, false, if (kind == "checkpoint") 2 else 1)
  // A writer that skips its own checks ((E), (J), the admission's cap): an old or deviating
  // writer. The decided-set versions of scenarios whose over-cap records an honest writer no
  // longer signs (the "...D" runs) use it; what they check is how the sets treat such records.
  // (Its records carry kit "unchecked", the model's mark, so that the promises about honest
  // writers do not count them; an admission keeps its device's kind.)
  action signW(k: Key, kind: str, target: Key, kit: str, targetRec: Id, pretend: bool, fork: bool, units: int): bool =
    signFullW(k, kind, target, kit, targetRec, pretend, fork, units, false, Set())
  action signFullW(k: Key, kind: str, target: Key, kit: str, targetRec: Id, pretend: bool, fork: bool, units: int,
      hidden: bool, extraKeep: Set[Id]): bool =
    signFullX(k, kind, target, if (kit == "") "unchecked" else kit, targetRec, pretend, fork, units, hidden, extraKeep, false)
  action signAsW(k: Key, kind: str, target: Key, targetRec: Id): bool =
    signW(k, kind, target, "", targetRec, false, false, if (kind == "checkpoint") 2 else 1)
  // The recovery key's member changes the root to t at the end of its chain.
  action recoverAs(k: Key, t: Key): bool = signChain(k, "recover", t, chainState(st.get("k"), db).ids.length() + 1, "honest")

  // A head waits for the new root's first checkpoint: until the member holds it the path
  // stays, and the new root's records it got meanwhile wait beside; with the checkpoint the
  // change applies and they are taken.
  // (Void under LAST_ROOT_ONLY: the ids of the change's records assume no re-issued Ys.)
  run headWaitsForFirstTest = if (LAST_ROOT_ONLY) init else
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signAs("NK", "copies", "", 0))
      .then(giveOnly("m", 4))
      .then(giveOnly("m", 6))
      .expect(views.get("m").path == [ROOT] and not(st.get("m").recs.contains(6)) and promises)
      .then(giveOnly("m", 5))
      .expect(views.get("m").path == [ROOT, "NK"] and st.get("m").chain == Set(4, 5)
        and st.get("m").recs.contains(6) and promises)

  // A head whose first checkpoint is never released changes nothing anywhere, and the honest
  // writer signs no further change over it.
  run headWithoutFirstTest =
    init
      .then(signChain(RECOVERY, "recover", "NK", 1, "nocp"))
      .expect(db.get(4).first == NEVER and not(db.keys().contains(5)))
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).path == [ROOT]) and promises)
      .then(fail(signChange))

  // The recovery key changes the root: a member that holds the record follows it at once.
  // The new root's checkpoint (19) waits for its key's record below it (18), which fits in
  // the rooms only after that checkpoint prunes. Members that got 19 before 18 and those that
  // got 18 first end in one state: the checkpoint settles the set before the rooms are judged.
  run waitedRecordTest = init
      .then(offerEveryone(3))
      .then(compactAt("a"))
      .then(signFull("R", "checkpoint", "", "", 0, false, false, 2, false, Set(2)))
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "R", 2, "nocp"))
      .then(offerEveryone(7))
      .then(sign("C", "copies", "", "", 0, false, false, 1))
      .then(offerEveryone(8))
      .then(offerEveryone(8))
      .then(sign("R", "revoke", "K", "", 0, false, false, 1))
      .then(offerEveryone(9))
      .then(sign("R", "revoke", "A", "", 0, false, false, 1))
      .then(sign("A", "freeze", "W", "", 0, true, false, 1))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(sign("A", "thaw", "", "", 11, false, false, 1))
      .then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(sign("A", "copies", "", "", 0, true, false, 2))
      .then(offerEveryone(13))
      .then(sign("C", "copies", "", "", 0, false, false, 1))
      .then(sign("A", "copies", "", "", 0, true, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(offerEveryone(18))
      .then(signFull("NK", "checkpoint", "", "", 0, false, false, 2, false, Set(18)))
      .then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(compactAt("m"))
      .then(give("a", 6))
      .then(offerEveryone(20))
      .then(offerEveryone(20))
      .then(compactAt("c"))
      .then(syncAll)
      .expect(promises)
  // A twin head at seq 1 halts the set; the twin's first checkpoint, which comes after,
  // still goes beside the chain, so the set's path is the one its chain gives.
  run haltedTakesTwinFirstTest = init
      .then(recoverAs(RECOVERY, "NA"))
      .then(sign("R", "admin", "X", "phone", 0, false, false, 1))
      .then(sign("NA", "checkpoint", "", "", 0, false, false, 2))
      .then(offerEveryone(7))
      .then(signChain(RECOVERY, "recover", "NA", 1, "literal"))
      .expect(promises)
  // A root fork halts the group: two records of the root at one seq, and nothing commands,
  // admits or seals until the recovery key changes the root; then the new root commands.
  run rootForkHaltsTest =
    init
      .then(signAs(ROOT, "copies", "", 0))
      .then(sign(ROOT, "copies", "", "", 0, false, true, 1))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m).commanders == Set()) and promises)
      .then(recoverAs(RECOVERY, "NK"))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NK"] and not(views.get(m).stop)
        and views.get(m).commanders.contains("NK")) and promises)

  // The root's counting checkpoint prunes its removal of a plain device, with the device's
  // admission (the writer holds it below its head; a removal that is the root's head stays as
  // its anchor): a replay of either is refused, and the device counts again only by a new
  // admission.
  // A root's checkpoint whose named records do not fit the rooms on their own (A's three
  // records, 6 units, over an admin's ceiling of 5) counts for nobody, whatever the order.
  run namedOverCeilingTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set(1, 2, 3, 4, 5, 6)))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint != 7) and promises)

  // Review B: checkpoint 6 waits, 8 comes before it is whole, 6's records come later; after a
  // sync every member counts 8.
  run waitingNewerTest =
    init
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(give("m", 6))
      .expect(st.get("m").recs.contains(6) and views.get("m").checkpoint == 0)
      .then(give("m", 8))
      .expect(st.get("m").recs.contains(8) and views.get("m").checkpoint == 0)
      .then(give("m", 4))
      .then(give("m", 5))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8) and promises)

  // Review C: the root names again, in checkpoint 8, the device's admission that checkpoint 7
  // pruned with its removal; member k never compacted on 7 and holds the admission. Every member
  // takes it (the waiting checkpoint names it) and counts 8: the device counts again, brought
  // back by the root.
  run rootNamesPrunedTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(give("a", 6)).then(give("a", 7)).then(give("c", 6)).then(give("c", 7)).then(give("m", 6)).then(give("m", 7))
      .expect(views.get("m").checkpoint == 7 and not(st.get("m").recs.contains(4)) and st.get("k").recs.contains(4))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(4)))
      .then(syncAll)
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8 and views.get(m).devices.contains(DEVICE)) and promises)
  // The same with nobody holding the admission but the member it is given to.
  run rootNamesPrunedGivenTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncAll)
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(4)))
      .then(syncAll)
      .then(give("m", 4))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8 and views.get(m).devices.contains(DEVICE)) and promises)
  // The root keeps both the old admission and the removal: the device stays out.
  run rootKeepsBothTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(give("a", 6)).then(give("a", 7)).then(give("c", 6)).then(give("c", 7)).then(give("m", 6)).then(give("m", 7))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(4, 5)))
      .then(syncAll)
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8 and not(views.get(m).devices.contains(DEVICE))) and promises)

  // Review W-1: checkpoints 7 (counting), 9 and 11 (never whole: it keeps a record nobody
  // has). Member a, handed 9 first, counts 9; member m, handed 11 first, then 9, reaches 9
  // after a sync like everyone.
  run everyWaitingTest =
    init
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncAll)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(99)))
      .then(give("a", 8)).then(give("a", 9))
      .then(give("m", 11)).then(give("m", 9)).then(give("m", 8)).then(give("m", 10))
      .expect(views.get("a").checkpoint == 9)
      .then(syncAll)
      // 9 with what it names fills the root's ceiling; off NEWEST_ASIDE, with 11 kept first
      // beside it they do not fit, the rooms fall back to the plain rule and the members that
      // took 9 count nothing.
      .expect(if (NEWEST_ASIDE) MEMBERS.forall(m => views.get(m).checkpoint == 9) and promises
        else views.get("a").checkpoint == 0 and views.get("m").checkpoint == 7)

  // (Void under ROOT_WAITS: the checkpoint settles a removal no admin has acked; W keeps it until every live admin acks (the settle path: wSh1, wSh2, wFrozenBlocks).)
  run prunedRemovalTest = if (ROOT_WAITS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).revoked.contains(DEVICE)))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(syncAll)
      .expect(db.get(7).keep.intersect(Set(4, 5)) == Set() and MEMBERS.forall(m => views.get(m).checkpoint == 7
        and not(st.get(m).recs.contains(4)) and not(st.get(m).recs.contains(5))
        and not(views.get(m).devices.contains(DEVICE))) and promises)
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(st.get("m").recs.contains(4)) and not(st.get("m").recs.contains(5)) and promises)
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).devices.contains(DEVICE)) and promises)

  // A removal of an admin key is never pruned, even with nothing it signed.
  run adminKeyRemovalStaysTest =
    init
      .then(signAs(ROOT, "revoke", WATCH, 0))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(syncAll)
      .expect(db.get(6).keep.contains(4) and MEMBERS.forall(m => views.get(m).revoked.contains(WATCH)) and promises)

  // A root's resolve voids only admins' records: of its own records, nothing.
  run resolveSparesRootTest =
    init
      .then(signAs(ROOT, "revoke", WATCH, 0))
      .then(signAs(ROOT, "resolve", "", 4))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).revoked.contains(WATCH)) and promises)

  // Review F-1: the pair is a fork at any depth. Member a gets the root's record (4) and its
  // twin (5) before the root's checkpoint above them (6); member c counts the checkpoint
  // first, then gets the twin. Both halt and end in one state.
  run forkAnyDepthTest =
    init
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "copies", "", "", 0, false, true, 1, true, Set()))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(6).line == [1, 2, 3, 4, 6])
      .then(give("a", 4)).then(give("a", 5)).then(give("a", 6))
      .then(give("c", 4)).then(give("c", 6))
      .expect(views.get("c").checkpoint == 6 and not(views.get("c").stop))
      .then(give("c", 5))
      .expect(views.get("a").stop and views.get("c").stop and views.get("a").commanders == Set()
        and views.get("c").commanders == Set() and views.get("a") == views.get("c")
        and st.get("a").recs == st.get("c").recs and promises)
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m) == views.get("a")) and promises)

  // Review F-4: an admin key that signed records is never pruned out with its removal; its
  // key admitted again does not count while the removal stands.
  run adminRemovalKeptTest =
    init
      .then(signAs(PHONE, "copies", "", 0))
      .then(signAs(ROOT, "revoke", PHONE, 0))
      .then(signAs(ROOT, "copies", "", 0))
      .then(syncAll)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(syncAll)
      .expect(db.get(7).keep.contains(5) and MEMBERS.forall(m => views.get(m).checkpoint == 7
        and views.get(m).revoked.contains(PHONE)) and promises)
      // (ROOT_WAITS: the honest root never names a removed key again; a bent one does.)
      .then(sign(ROOT, "admin", PHONE, if (ROOT_WAITS) "phone!" else "phone", 0, false, false, 1))
      .then(syncAll)
      .expect(MEMBERS.forall(m => not(views.get(m).admins.keys().contains(PHONE))) and promises)

  // Review F-7: a device the root admitted below a fork and removed above it stays removed
  // during the halt (a root's removal on any line bars its device), and the change of root's
  // list leaves it out.
  run removalBarsDuringHaltTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "copies", "", "", 0, false, true, 1, true, Set()))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .expect(db.get(6).seq == 5 and db.get(7).seq == 6)
      .then(offerEveryone(6))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).stop and not(views.get(m).devices.contains(DEVICE))) and promises)
      .then(recoverAs(RECOVERY, "NK"))
      .then(syncAll)
      .expect(MEMBERS.forall(m => not(views.get(m).stop) and not(views.get(m).devices.contains(DEVICE))) and promises)

  // Review section 2: three records of the root at one seq, and a second fork above the first
  // on one line: the fork seq is the lowest, and every member halts alike.
  run threeLinesTest =
    init
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "copies", "", "", 0, false, true, 1, true, Set()))
      .then(signFull(ROOT, "copies", "", "", 0, false, true, 2, true, Set()))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "copies", "", "", 0, false, true, 1, true, Set()))
      .expect(db.get(5).seq == 4 and db.get(6).seq == 4 and db.get(8).seq == 5)
      .then(give("a", 8)).then(give("a", 7)).then(give("a", 6))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m) == views.get("r")) and promises)

  // --- The place aside's bound (N-1) ---------------------------------------------------------
  // The head of the change to t (the newest), with its first records.
  action giveHead(m: str, t: Key): bool =
    give(m, db.keys().filter(i => isChain(db.get(i)) and db.get(i).target == t).fold(0, (a, i) => max2(a, i)))
  // Every record k signed from seq on, in ID order.
  action giveBy(m: str, k: Key, from: int): bool =
    giveAll(Set(m), range(1, nextId).select(i => db.keys().contains(i) and db.get(i).signer == k and db.get(i).seq >= from))
  action giveAll(ms: Set[str], ids: List[Id]): bool =
    commitAll(MEMBERS.mapBy(m => if (ms.contains(m)) finish(ids.foldl(st.get(m), (s, i) => insertInto(s, db.get(i), db)), db)
      else (st.get(m), views.get(m))))
  // Three admins sign three 3-unit records each; the rooms keep the first of each, and every
  // member counts checkpoint 13.
  action asideBase =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 3))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 3))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 3))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 3))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 3))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 3))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 3))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 3))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 3))
      .then(giveAll(MEMBERS, [4, 5, 6, 7, 8, 9, 10, 11, 12]))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound)
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("m")).then(compactAt("k"))
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 13 and st.get(m).recs == Set(1, 2, 3, 4, 7, 10, 13)))
  // The root key signs 14, which can become whole, and 15, which never can (it names a record
  // nobody has) and names 10 units the rooms turn away. Member a gets 14 first and counts it; m
  // gets 15 first: what 15 keeps fills the place aside first, 14's records do not fit, and after
  // sync m still counts 13 while its peers count 14. Neither assumption holds there.
  run asideFullTest = asideBase
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 5, 8, 11), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6, 9, 12, NEVER), "", 1))
      .then(giveAll(Set("a"), [14, 5, 8, 11]))
      .then(giveAll(Set("m"), [15, 6, 9, 12, 14, 5, 8, 11]))
      .then(syncRound).then(syncRound).then(syncRound).then(syncRound)
      .expect(if (NEWEST_ASIDE) and { views.get("a").checkpoint == 14, views.get("m").checkpoint == 13, syncedProto("m"),
          not(convergesAt("m")), not(asideFits("m")), not(newestWholeable("m")), not(honestOnly), promises }
        // With 15 kept first beside 14 and what it names (14 units), the rooms overflow and fall
        // back to the plain rule: a member counts no checkpoint (the finding of everyWaitingTest).
        else views.get("a").checkpoint == 0)
  // The same with 15 keeping 3 units only: the place aside has room, but 14 itself (the record
  // 15 waits for, which 15 does not keep) is turned away by the full rooms and goes nowhere, so
  // the members that got 15 first stay at 13. With ASIDE_TAKES_WAITED every member counts 14.
  run olderWaitingTurnedAwayTest = asideBase
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 5, 8), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6, NEVER), "", 1))
      .then(giveAll(Set("a"), [14, 5, 8]))
      .then(giveAll(Set("m"), [15, 6, 14, 5, 8]))
      .then(syncRound).then(syncRound).then(syncRound).then(syncRound)
      .expect(and { asideFits("m"), not(newestWholeable("m")),
        if (ASIDE_TAKES_WAITED) MEMBERS.forall(m => views.get(m).checkpoint == 14 and convergesAt(m))
        else views.get("m").checkpoint == 13 and not(convergesAt("m")),
        promises })

  // --- The rule at 1e9c92a1 (ONE_SLOT, N-7) ---------------------------------------------------
  // As asideBase, with the watch's records of 2 units: the rooms have room for one more
  // checkpoint beside the newest.
  action slotBase =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 3))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 3))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 3))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 3))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 3))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 3))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(giveAll(MEMBERS, [4, 5, 6, 7, 8, 9, 10, 11, 12]))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound)
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("m")).then(compactAt("k"))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 5, 8), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6, NEVER), "", 1))
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 13
        and st.get(m).recs == Set(1, 2, 3, 4, 7, 10, 13).union(if (m == "r") Set(14, 15) else Set())))
  // 7/8/9: 14 can become whole, the newer 15 never. Member m gets 15 first: with one slot only
  // 15 waits, 14's records go nowhere, and m stays at 13 while a counts 14. Without
  // ASIDE_TAKES_WAITED the same happens for another reason: 14 itself is turned away (the
  // root is over its fair share) and nothing aside holds it.
  run oneSlotTest = slotBase
      .then(giveAll(Set("a"), [14, 5, 8]))
      .then(giveAll(Set("m"), [15, 6, 14, 5, 8]))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(and { views.get("a").checkpoint == 14, syncedProto("m"),
        if (ONE_SLOT or not(ASIDE_TAKES_WAITED)) views.get("m").checkpoint == 13 and not(convergesAt("m"))
        else MEMBERS.forall(m => views.get(m).checkpoint == 14 and convergesAt(m)) and promises })
  // N-7: 14's records wait aside on a (5) and c (8), whole nowhere; only missing() brings them.
  // Naming only the newest waiting checkpoint's records (15's), nobody asks for them.
  run missingNewestTest = slotBase
      .then(giveAll(Set("a"), [15, 14, 5]))
      .then(giveAll(Set("c"), [15, 14, 8]))
      .then(giveAll(Set("m"), [15, 14]))
      .expect(st.get("a").wait.contains(5) and st.get("c").wait.contains(8) and views.get("m").checkpoint == 13)
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(and { syncedProto("m") or not(ASIDE_TAKES_WAITED),
        // Without ASIDE_TAKES_WAITED nobody keeps 14 and 5, 8 at once: m, r and k take 14 and
        // lose it again, round after round (never synced).
        if (not(ASIDE_TAKES_WAITED)) views.get("m").checkpoint == 13
        else if (MISSING_NEWEST_ONLY or ONE_SLOT) views.get("m").checkpoint == 13 and not(convergesAt("m"))
        else MEMBERS.forall(m => views.get(m).checkpoint == 14 and convergesAt(m)) and promises })

  // --- The cut and a restart ------------------------------------------------------------------
  // A, C and W sign within their share; the root admits X, and X's one record lowers the fair
  // share: every member drops A's, C's and the root's newest record and holds a mark, though
  // no writer signed past what its own set kept.
  action shareFalls =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
  run honestShareFallsTest = shareFalls
      // (Under "gapless" and "follows" the level rises once the tails are dropped: X's
      // admission stays.)
      .expect(MEMBERS.forall(m => st.get(m).recs == (if (CUT_MODE == "gapless" or CUT_MODE == "follows") Set(1, 2, 3, 4, 6, 7, 9, 10) else Set(1, 2, 3, 4, 6, 7, 10))
        and (CUT_MODE == "none" or CUT_MODE == "gapless" or CUT_MODE == "follows" or st.get(m).cut.marks.keys() == Set(PHONE, COMPUTER, ROOT))) and promises)
  // Member a restarts (the core keeps no cut) and A writes again: a keeps it, the members
  // with the mark turn it away, and synced members differ in A's record past the mark until
  // the root's next checkpoint.
  // Under "gapless" A's 11 follows a seq nobody holds: (E) refuses it; published anyway (a
  // deviating writer), every member, restarted or not, turns it away alike.
  // Under "follows" A's 11 follows 4 and voids 5: every member keeps it at once.
  run restartSplitTest = shareFalls
      .then(restart("a"))
      .then(if (CUT_MODE == "gapless") signDeviant(PHONE, "copies", "", 2) else sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => syncedProto(m)) and
        if (CUT_MODE == "gapless") MEMBERS.forall(m => not(st.get(m).recs.contains(11)) and convergesAt(m))
        else if (CUT_MODE == "follows") MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 6, 7, 9, 10, 11) and convergesAt(m))
        // RESTART_REOFFERS: the restarted a, offered again what it got, builds the same marks,
        // so it turns 11 away like the others: no split.
        else if (RESTART_REOFFERS and CUT_MODE != "none") MEMBERS.forall(m => not(st.get(m).recs.contains(11)) and convergesAt(m))
        else st.get("a").recs.contains(11)
          and (CUT_MODE == "none" or (not(st.get("m").recs.contains(11)) and not(convergesAt("m")))))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound).then(syncRound).then(syncRound)
      // Under "gapless" the root's head for A stays at 4 (no member holds A's 5), so 11 still
      // follows a gap: A stays mute, alike everywhere.
      // (With RESTART_REOFFERS nobody kept 11, so it is gone for good, alike everywhere.)
      .expect(MEMBERS.forall(m => st.get(m).recs.contains(11) == (CUT_MODE != "gapless" and not(RESTART_REOFFERS and CUT_MODE != "none"))
        and views.get(m).checkpoint == 12
        and convergesAt(m)))

  // (I): a replay of the void 5 or of C's dropped 8, by every member, changes nothing.
  run followsReplayTest = shareFalls
      .then(restart("a"))
      .then(if (CUT_MODE == "gapless") signDeviant(PHONE, "copies", "", 2) else sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(syncRound).then(syncRound)
      .then(giveAll(MEMBERS, [5, 8])).then(syncRound)
      .expect(CUT_MODE != "follows" or MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 6, 7, 9, 10, 11)
        and convergesAt(m)) and promises)
  // (I): a key voids only its own tail above the head: once the root's checkpoint settles A's
  // 4, A's record that follows what 4 follows leaves 4 in place.
  run followsSettledTest = shareFalls
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound).then(syncRound)
      .then(signFollowing(PHONE, "copies", 1, -1))
      .then(syncRound).then(syncRound)
      .expect(CUT_MODE != "follows" or MEMBERS.forall(m => st.get(m).recs.contains(4) and st.get(m).recs.contains(12)
        and convergesAt(m)) and promises)

  // --- A twin checkpoint at the fork seq ---------------------------------------------------
  // A signs two records at seq 1 (4 and 5) and the root's resolve 6 voids 5, so 5 no longer
  // counts; the root, off its device, signs a checkpoint 7 at seq 5 that keeps what counts and
  // so prunes 5; then on its device a device record 8 at the same seq 5. Member a gets 7 then
  // 8, c gets 8 then 7, k gets 7, compacts on it (drops 5), then gets 8. The pair halts every
  // member alike; after a sync every member holds the same records.
  action twinCpBase =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1))
      .then(sign(PHONE, "device", DEVICE, "", 0, false, true, 1)).then(syncRound)
      .then(sign(ROOT, "resolve", "", "", 5, false, false, 1)).then(syncRound)
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, true, Set()))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, true, 1))
  run twinCheckpointOrderTest = twinCpBase
      .then(giveOnly("a", 7)).then(compactAt("a")).then(giveOnly("a", 8)).then(compactAt("a"))
      .then(giveOnly("c", 8)).then(giveOnly("c", 7)).then(compactAt("c"))
      .then(giveOnly("k", 7)).then(compactAt("k")).then(giveOnly("k", 8)).then(compactAt("k"))
      // All halt alike; a and k, which compacted on 7 before the pair, lack the voided 5 that c
      // holds until a sync: 7 no longer counts, so they forget it and take 5 back.
      .expect(Set("a", "c", "k").forall(m => heldBy(st.get(m)).contains(7) and heldBy(st.get(m)).contains(8)
        and views.get(m).stop and views.get(m) == views.get("c"))
        and st.get("a").recs == Set(1, 2, 3, 4, 6) and st.get("k").recs == Set(1, 2, 3, 4, 6)
        and st.get("c").recs == Set(1, 2, 3, 4, 5, 6) and promises)
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m) == views.get("c") and st.get(m).recs == st.get("c").recs) and promises)

  // The limit of the healing: every member, the root's own included, compacted on 7 before the
  // twin 8 came, so nobody holds the voided 5 any more. All halt alike and hold the same records:
  // 5 is lost and nobody splits.
  run twinCheckpointAllPrunedTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1))
      .then(sign(PHONE, "device", DEVICE, "", 0, false, true, 1)).then(syncRound)
      .then(sign(ROOT, "resolve", "", "", 5, false, false, 1)).then(syncRound)
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, true, Set()))
      .then(offerEveryone(7))
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("k")).then(compactAt("m"))
      .expect(MEMBERS.forall(m => not(heldBy(st.get(m)).contains(5))))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, true, 1))
      .then(offerEveryone(8)).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m) == views.get("c")
        and st.get(m).recs == st.get("c").recs and not(heldBy(st.get(m)).contains(5))) and promises)

  // A root pair held but not whole: the root signs 4, then 5 (an admin) and a twin 6 at 5's seq;
  // a gets 5 and 6 without 4. With HALT_ON_HELD_PAIR a halts at once; without it a goes on
  // (neither line is whole) until 4 comes; after a sync every member halts alike either way.
  run heldPairNotWholeTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, true, 1))
      .then(giveOnly("a", 5)).then(giveOnly("a", 6))
      .expect(not(heldBy(st.get("a")).contains(4)) and views.get("r").stop
        and views.get("a").stop == HALT_ON_HELD_PAIR and promises)
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m) == views.get("r")) and promises)

  // F-7 for every key: A removes the root's device D, then a thief with A's key signs a twin at
  // A's seq 1. A's records from the fork on stop counting, but its removal on a whole chain
  // keeps barring D on either history, whichever order a member gets them in (off: D comes back).
  action f7Base =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(PHONE, "copies", "", "", 0, false, true, 1))
  run f7AdminTwinTest = f7Base
      .then(giveOnly("a", 5)).then(giveOnly("a", 6))
      .then(giveOnly("c", 6)).then(giveOnly("c", 5))
      .then(giveOnly("k", 6))
      .expect(views.get("a") == views.get("c") and views.get("a").revoked.contains(DEVICE) == F7_EVERY_KEY
        and not(views.get("k").revoked.contains(DEVICE)) and promises)
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m) == views.get("r") and st.get(m).recs == st.get("r").recs
        and views.get(m).revoked.contains(DEVICE) == F7_EVERY_KEY and not(views.get(m).stop)) and promises)

  // F-7 when the root removes the forked A: the root's removal sees one of A's lines (6), so
  // A's removal of D on the other line stops counting and D comes back (as in the core). (a)
  // F7_SEEN_IGNORED keeps D out, but then A's key, after its removal, still bars a live device
  // (dC) for good. (c) The root's writer first removes D itself, then A: D stays out, nothing A
  // signs later counts, and members that held only one of A's lines agree after a sync.
  action f7RootRemovesBase =
    f7Base.then(giveOnly("r", 6)).then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1))
  run f7RootRemovesTest = f7RootRemovesBase
      .then(sign(PHONE, "revoke", "dC", "", 0, false, false, 1))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m) == views.get("r") and views.get(m).revoked.contains(PHONE)
        and views.get(m).revoked.contains(DEVICE) == F7_SEEN_IGNORED
        and views.get(m).revoked.contains(COMPUTER) == F7_SEEN_IGNORED) and (promises or F7_SEEN_IGNORED))
  run f7RootFirstRemovesTest = f7Base
      .then(giveOnly("a", 5)).then(giveOnly("c", 6)).then(giveOnly("r", 6)).then(giveOnly("r", 5))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1))
      .then(sign(PHONE, "revoke", "dC", "", 0, false, false, 1))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m) == views.get("r") and st.get(m).recs == st.get("r").recs
        and views.get(m).revoked.contains(DEVICE) and views.get(m).revoked.contains(PHONE)
        and views.get(m).revoked.contains(COMPUTER) == F7_SEEN_IGNORED and not(views.get(m).stop))
        and (promises or F7_SEEN_IGNORED))

  // The fold: the root removes D twice (4, 5); its checkpoint 6 leaves out the older 4, which 5
  // supersedes. a holds only the old removal, c only the fold (5 and 6), k both, m gets the
  // checkpoint before the old removal. D stays out at every member in every order, before and
  // after compaction and sync.
  run foldRemovalsTest =
    init
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set()))
      .expect(FOLD_REMOVALS implies not(db.get(6).keep.contains(4)) and db.get(6).keep.contains(5))
      .then(giveOnly("a", 4))
      .then(giveOnly("c", 5)).then(giveOnly("c", 6)).then(compactAt("c"))
      .then(giveOnly("k", 4)).then(giveOnly("k", 5)).then(giveOnly("k", 6)).then(compactAt("k"))
      .then(giveOnly("m", 5)).then(giveOnly("m", 6)).then(compactAt("m")).then(giveOnly("m", 4))
      .expect(Set("a", "c", "k", "m", "r").forall(m => if (LAST_ROOT_ONLY) not(views.get(m).devices.contains(DEVICE)) else views.get(m).revoked.contains(DEVICE)) and promises)
      .then(syncRound).then(compactAt("a")).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => (if (LAST_ROOT_ONLY) not(views.get(m).devices.contains(DEVICE)) else views.get(m).revoked.contains(DEVICE)) and views.get(m) == views.get("r")
        and st.get(m).recs == st.get("r").recs and not(st.get(m).recs.contains(4)) == FOLD_REMOVALS) and promises)

  // The fold in a change's list: R and NA both remove D; the list of the change to NK leaves
  // out R's older removal (4), which NA's (7) supersedes. Whichever removals a member got
  // first, D stays out everywhere.
  run foldListTest =
    init
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(sign("NA", "revoke", DEVICE, "", 0, false, false, 1)).then(giveOnly("k", 7))
      .then(recoverAs(RECOVERY, "NK"))
      .expect((CEIL_FIT and FOLD_REMOVALS) implies (not(db.get(8).keep.contains(4)) and db.get(8).keep.contains(7)))
      // a takes the change (holding R's 4, not NA's 7), c takes NA's 7 only.
      .then(giveOnly("a", 8)).then(giveOnly("a", 9)).then(giveOnly("c", 7))
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => if (LAST_ROOT_ONLY) not(views.get(m).devices.contains(DEVICE)) else views.get(m).revoked.contains(DEVICE)) and promises)
      .then(syncRound).then(compactAt("a")).then(compactAt("c")).then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => (if (LAST_ROOT_ONLY) not(views.get(m).devices.contains(DEVICE)) else views.get(m).revoked.contains(DEVICE)) and views.get(m) == views.get("r")
        and views.get(m).path == ["R", "NA", "NK"]) and promises)

  // A recovery fork (simulator seed 5262): with the root's device lost, the recovery key
  // writes two changes at seq 1, to NA listing only A's admission and to NK listing only C's
  // and W's, so each side counts the other as no member. With SYNC_MEMBERS_ONLY and LOST =
  // {r, k} (the root's device and the device that wrote the changes are gone) the sides never
  // sync and neither a nor c halts: two live groups. With NEWEST_HEAD_ANY the
  // newest heads cross anyway and every member halts, and nothing but chain records crosses;
  // under UNKNOWN_HEADS too, as each side's state counts no key of the other.
  run recForkSplitTest =
    init
      .then(signChainG(RECOVERY, "recover", "NA", 1, "given", Set(1)))
      .then(signChainG(RECOVERY, "recover", "NK", 1, "given", Set(2, 3)))
      .then(giveOnly("a", 4)).then(giveOnly("a", 5))
      .then(giveOnly("c", 6)).then(giveOnly("c", 7))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect((views.get("k").stop or LOST.contains("k")) and (
        if (SYNC_MEMBERS_ONLY and LOST.contains("r") and LOST.contains("k") and not(NEWEST_HEAD_ANY) and not(UNKNOWN_HEADS))
          not(views.get("a").stop) and not(views.get("c").stop) and views.get("a").path == ["R", "NA"] and views.get("c").path == ["R", "NK"]
        else Set("a", "c").forall(m => views.get(m).stop)))

  // The shape of simulator seed 47 (honest): NA, once an admin, becomes the root, admits X,
  // freezes and thaws C and checkpoints; members compact; NK becomes the root and checkpoints.
  // Every member restarted keeps the same records and state.
  // (Void under LAST_ROOT_ONLY: NA was an admin key; under L a new root is always a fresh key.)
  run restartAfterTwoChangesTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(sign("NA", "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "freeze", COMPUTER, "", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "thaw", "", "", 9, false, false, 1)).then(syncRound)
      .then(sign("NA", "checkpoint", "", "", 0, false, false, 2)).then(syncRound)
      .then(compactAt("a")).then(compactAt("c"))
      .then(recoverAs(RECOVERY, "NK")).then(syncRound)
      .then(sign("NK", "checkpoint", "", "", 0, false, false, 2)).then(syncRound)
      .then(compactAt("m")).then(syncRound)
      .expect(restartStable and promises)
      .then(restart("r")).then(restart("a")).then(restart("c")).then(restart("k")).then(restart("m"))
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m).path == ["R", "NA", "NK"] and views.get(m).checkpoint == 14
        and views.get(m).frozen == Set() and st.get(m).recs == Set(1, 2, 3, 4, 5, 8, 9, 10, 14)) and promises)

  // Seed 47's class: m gets the records of NA and NK, then NA's head without its first
  // checkpoint and NK's head with NK's. Under FIRST_NEWEST_ONLY both heads apply at once; under
  // EARLY_ROOM the early roots' records wait in one root's room, NA's (the lower recovery seq)
  // first, so NK's last two are turned away, while NK's first checkpoint, beside the chain, is
  // never trimmed. A restart keeps it; one sync brings the rest.
  // (Void under LAST_ROOT_ONLY: NA was an admin key; under L a new root is always a fresh key.)
  run earlyRoomTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(give("a", 5))
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(giveOnly("k", 7)).then(giveOnly("k", 8)).then(giveOnly("k", 9)).then(giveOnly("k", 10)).then(giveOnly("k", 11))
      .then(recoverAs(RECOVERY, "NK"))
      .then(sign("NK", "copies", "", "", 0, false, false, 1)).then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(sign("NK", "copies", "", "", 0, false, false, 1)).then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(giveOnly("m", 7)).then(giveOnly("m", 8)).then(giveOnly("m", 9)).then(giveOnly("m", 10)).then(giveOnly("m", 11))
      .then(giveOnly("m", 14)).then(giveOnly("m", 15)).then(giveOnly("m", 16)).then(giveOnly("m", 17)).then(giveOnly("m", 18))
      .then(giveOnly("m", 5)).then(give("m", 12))
      .expect(promises and (if (FIRST_NEWEST_ONLY) views.get("m").path == ["R", "NA", "NK"] and views.get("m").checkpoint == 13
          and ((EARLY_ROOM and not(CEIL_FIT)) implies st.get("m").recs == Set(1, 2, 3, 4, 7, 8, 9, 10, 11, 14, 15, 16))
        else views.get("m").path == ["R"]))
      .then(restart("m"))
      .expect(promises and (FIRST_NEWEST_ONLY implies views.get("m").path == ["R", "NA", "NK"] and views.get("m").checkpoint == 13))
      .then(syncRound)
      .expect(promises and views.get("m").path == ["R", "NA", "NK"] and views.get("m").checkpoint == 13
        and st.get("m").recs == st.get("k").recs
        and (not(CEIL_FIT) implies st.get("m").recs == Set(1, 2, 3, 4, 7, 8, 9, 10, 11, 14, 15, 16, 17, 18)))

  // Simulator 1460's shape: the root admits m's key (MDEV), and only m gets it; the recovery key,
  // which never held that admission, makes NA the root, and its list does not name D. Every
  // other member moves to NA and counts no key of m. Under UNKNOWN_HEADS they hand m the head
  // alone: m holds a verified head it cannot apply whose list leaves it out, so it is left out
  // instead of staying live on the old root. (Under SYNC_MEMBERS_ONLY m would hear nothing.)
  run leftOutTest =
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "device", MDEV, "", 0, false, false, 1)).then(giveOnly("m", 5))
      .then(recoverAs(RECOVERY, "NA"))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(promises and MEMBERS.exclude(Set("m")).forall(n => views.get(n).path == ["R", "NA"])
        and (if (UNKNOWN_HEADS) leftOut("m") and not(views.get("m").devices.contains(MDEV))
            and (if (HEADS_WITH_FIRSTS) views.get("m").path == ["R", "NA"] else views.get("m").path == ["R"] and st.get("m").chain == Set(6))
          else views.get("m").path == ["R", "NA"] and not(views.get("m").devices.contains(MDEV))))

  // Seed j.8001 (Mac, (J)): the root signs a checkpoint that never becomes whole, ahead of its
  // copies record 5 in its order; at the root's own device the room turned it away and 5 with
  // it, for good. Under WAIT_SKIP the device keeps 5 and every promise holds.
  // (Void under LAST_ROOT_ONLY: A grants W, a key another root named; the L writer refuses it.)
  run waitSkipJ8001Test = if (LAST_ROOT_ONLY) init else
    init
      .then(syncRound)
      .then(syncRound)
      .then(sign("R", "checkpoint", "", "", 0, false, false, 2))
      .then(giveOnly("c", 4))
      .then(syncRound)
      .then(syncRound)
      .then(offerEveryone(4))
      .then(restart("a"))
      .then(sign("R", "copies", "", "", 0, false, false, 1))
      .then(sign("A", "admin", "W", "computer", 0, false, false, 1))
      .then(offerEveryone(6))
      .then(compactAt("m"))
      .then(syncRound)
      .then(signCheckpointKeep("R", Set(5, 6, 99), "A", 2))
      .expect((CEIL_FIT and WAIT_SKIP) implies promises)

  // Seed j.8004 (Mac, (J)): a second writer on the root key signs 10, the root's room turns it
  // away, and the root's honest checkpoint 11 prunes it as its prev. A member holding 10 found
  // 11 over the root's ceiling and counted none. Under PREV_ROOM_WHEN_KEPT every promise holds.
  // (Void under LAST_ROOT_ONLY: NA grants C, a key another root named; the L writer refuses it.)
  run prevRoomJ8004Test = if (LAST_ROOT_ONLY) init else
    init      
      .then(sign("A", "copies", "", "", 0, false, false, 1))      
      .then(signDeviant("C", "device", "D", 1))      
      .then(signFull("NA", "admin", "C", "phone", 0, false, false, 1, true, Set()))      
      .then(welcomeFrom("a"))      
      .then(signFull("R", "checkpoint", "", "", 0, false, false, 2, false, Set(3)))      
      .then(offerEveryone(7))      
      .then(offerEveryone(5))      
      .then(offerEveryone(7))      
      .then(welcomeFrom("c"))      
      .then(compactAt("m"))      
      .then(sign("R", "copies", "", "", 0, false, false, 1))      
      .then(compactAt("k"))      
      .then(signFull("NA", "admin", "A", "phone", 0, false, false, 1, true, Set()))      
      .then(restart("r"))      
      .then(offerEveryone(9))      
      .then(signFull("R", "admin", "X", "phone", 0, false, false, 1, true, Set()))      
      .then(offerEveryone(10))      
      .then(sign("R", "checkpoint", "", "", 0, false, false, 2))      
      .then(offerEveryone(11))      
      .then(giveOnly("m", 4))      
      .then(offerEveryone(11))      
      .then(signFullX("X", "device", "D", "", 0, false, false, 1, false, Set(), not(FIXED_CAPS)))  // (FIXED_CAPS: X, the fifth admin key, has cap 0; its writer publishes anyway.)      
      .then(restart("c"))      
      .then(syncRound)      
      .then(give("c", 11))      
      .then(signCheckpointKeep("R", Set(3, 4, 5, 7, 8, 9, 10, 11, 99), "C", 2))      
      .then(offerEveryone(13))      
      .then(restart("r"))      
      .then(offerEveryone(13))      
      .then(sign("C", "copies", "", "", 0, false, false, 1))      
      .then(restart("m"))
      .expect((CEIL_FIT and PREV_ROOM_WHEN_KEPT) implies promises)

  // Case (d) of a root pair: NA signs two records at seq 1 while an admin (the second off its
  // device), m gets both before NA is a root and keeps neither; the change to NA lists only the
  // first, so m takes it and is not halted; offered the second again (re-offer is the rule), m
  // keeps the pair beside its chain and halts.
  run rootPairReofferTest =
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 2))
      .then(signFull("NA", "copies", "", "", 0, false, true, 2, true, Set()))
      .then(giveOnly("m", 5)).then(giveOnly("m", 6)).then(giveOnly("k", 5))
      .then(recoverAs(RECOVERY, "NA")).then(give("m", 7))
      .expect(views.get("m").path == ["R", "NA"] and st.get("m").recs.contains(5) and not(st.get("m").recs.contains(6))
        and not(views.get("m").stop) and rootPairHalts)
      .then(giveOnly("m", 6))
      .expect(views.get("m").stop and st.get("m").chain.contains(5) and st.get("m").chain.contains(6) and rootPairHalts)

  // The reserve and lost roots: R fills its ceiling (its fourth removal is refused) and is lost
  // without a checkpoint; the recovery key changes to NA, which is lost after its first
  // checkpoint, then to NK. Each list carries R's records, which fit R's ceiling and so the
  // reserve (RESERVE = ROOTC; checkpoints are never listed): neither change is refused.
  run reserveLostRootsTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", "dC", "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(recoverAs(RECOVERY, "NK")).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m).path == ["R", "NA", "NK"]) and promises
        and ((CEIL_FIT and not(REISSUE_REMOVALS)) implies db.get(9).keep == Set(1, 2, 3, 4, 5, 6))
        // (REISSUE_REMOVALS: record IDs move; the newest list names no root removal, NK re-signed them.)
        and (REISSUE_REMOVALS implies not(recsOf(db.get(lastHead).keep, db).exists(r => rootRemoval(r)))))

  // A late admission after a change (architecture 11-13 20:42Z, break 1): A admits D, the root
  // removes D, the recovery key's member holds the removal but never A's admission and changes
  // the root to NK; A's admission reaches everyone after the change. Every held removal is
  // listed, so D stays out; with the core's list of today (CORE_LIST_FILTER) the removal of a
  // key no held record names is left off and D counts again: removedStayOut fails.
  run lateAdmissionTest =
    init
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1)).then(giveOnly("r", 4))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(giveOnly("k", 5))
      .then(recoverAs(RECOVERY, "NK")).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == ["R", "NK"])
        and (CORE_LIST_FILTER implies (not(removedStayOut) and views.get("r").devices.contains(DEVICE)))
        and (not(CORE_LIST_FILTER) implies (promises and MEMBERS.forall(m => not(views.get(m).devices.contains(DEVICE))))))

  // A Welcome builds a fresh set: no mark survives a pairing (architecture 23:00Z). k.9501's
  // steps leave a mark at a (A removed; under UNKNOWN_HEADS a takes heads alone); m paired by
  // r, then by the marked a itself, holds no mark and r's records.
  // k.9521 (Mac run k3, minimal): the recovery key's holder writes a change back to NA, the
  // current root, and signs NA's checkpoint 18 on its own device while NA's device writes 19
  // and 20 without it; NA ends past its ceiling and the members part over 20. NEW_ROOT_ONLY
  // refuses that change (the core's write_change does, and eval::chain holds it void).
  run changeBackToRootTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(sign("R", "checkpoint", "", "", 0, false, false, 2))
      .then(recoverAs(RECOVERY, "NA"))
      .then(sign("R", "admin", "X", "phone", 0, false, false, 1))
      .then(syncRound)
      .then(sign("NA", "revoke", "A", "", 0, false, false, 1))
      .then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(signDeviant("X", "device", "D", 2))
      .then(signFullX("A", "thaw", "", "", 7, true, false, 1, false, Set(), not(FIXED_CAPS)))  // (FIXED_CAPS: A, removed, has cap 0; its writer publishes anyway.)
      .then(signFull("R", "revoke", "X", "phone", 0, false, true, 1, true, Set()))
      .then(signFullX("A", "revoke", "D", "", 0, true, false, 1, false, Set(), not(FIXED_CAPS)))
      .then(sign("NA", "revoke", "A", "", 0, false, false, 1))
      .then(if (NEW_ROOT_ONLY) syncRound else signChain(RECOVERY, "recover", "NA", 3, "honest"))
      .then(sign("NA", "copies", "", "", 0, false, false, 2))
      .then(offerEveryone(nextId - 1))
      // (Under WRITER_CP_FLOOR at ROOTC 8 NA's room has no unit left for this record.)
      .then(if (WRITER_CP_FLOOR and not(WIDE_ROOT)) offerEveryone(0) else sign("NA", "copies", "", "", 0, false, false, 1))
      .then(if (NEW_ROOT_ONLY) syncRound else giveOnly("a", 18))
      .then(syncRound)
      .then(offerEveryone(nextId - 1))
      .expect(NEW_ROOT_ONLY implies (MEMBERS.forall(m => views.get(m).path == ["R", "NK", "NA"]) and promises))

  run welcomeFreshTest =
    init
      .then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set(3)))
      .then(syncRound).then(offerEveryone(5))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set(4))).then(offerEveryone(6))
      .then(welcomeFrom("r"))
      .expect(st.get("m").cut.marks.keys() == Set() and st.get("m").recs == st.get("r").recs)
      .then(welcomeFrom("a"))
      .expect(st.get("m").cut.marks.keys() == Set())

  // REISSUE_REMOVALS, a member with the head and the first checkpoint but not the new root's
  // re-signed removal: the root removes D, the recovery key changes to NK (head, Z for D, first
  // checkpoint); m gets the head with its first checkpoint only. D must not count at m.
  run reissueNoFirstRecordsTest =
    init
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NK"))
      .then(giveOnly("m", 6)).then(giveOnly("m", db.get(6).first))
      .expect(not(views.get("m").devices.contains(DEVICE)) and (REISSUE_REMOVALS implies views.get("m").path == ["R"]) and promises)
      .then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m).path == ["R", "NK"]
        and not(views.get(m).devices.contains(DEVICE))) and promises)

  // REISSUE_REMOVALS, the reserve (seed 153's shape at scaled sizes): R's four admins are live
  // admissions; NA, the first new root, removes D and the devices of C and W (with C and W:
  // c is out). Under (J) the list would
  // need 4 + 3 units past RESERVE 6 and the honest writer refuses the change to NK; with the
  // removals re-signed by NK (3 units + its checkpoint's 2 within ROOTC 6) it is written.
  // (Void under LAST_ROOT_ONLY: L carries no Zs and lists nothing; the removed key stays out by lRejoin and lLateOld.)
  run reissueReserveTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(sign("NA", "revoke", DEVICE, "", 0, false, false, 1)).then(sign("NA", "revoke", "dC", "", 0, false, false, 1))
      .then(sign("NA", "revoke", "dW", "", 0, false, false, 1)).then(syncRound)
      .then(if (REISSUE_REMOVALS or not(CEIL_FIT)) recoverAs(RECOVERY, "NK") else syncRound).then(syncRound).then(syncRound)
      .expect(Set("r", "a", "k").forall(m =>
        views.get(m).path == (if (REISSUE_REMOVALS or not(CEIL_FIT)) ["R", "NA", "NK"] else ["R", "NA"])
        and Set(DEVICE, "dC", "dW", COMPUTER, WATCH).subseteq(views.get(m).revoked)
        and views.get(m).admins.keys() == Set(PHONE, "X")) and promises)

  // REISSUE_REMOVALS, packing: R removes A, A signs 5 after (R is handed it), R removes A again.
  // The two removals saw A differently ([] and [5]), so the change packs them into two Zs; the
  // first still bars 5. REISSUE_PACK_ANY packs them into one Z with A's seen [5]: 5 counts.
  // (Void under LAST_ROOT_ONLY: L carries no Zs.)
  run reissuePackTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1)).then(giveOnly("r", 5)).then(syncRound)
      .then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NK")).then(syncRound).then(syncRound)
      .expect(Set("r", "c", "k").forall(m => views.get(m).path == ["R", "NK"] and not(views.get(m).counting.contains(5)))
        // (Under FIXED_CAPS the root's member drops A's copies at once, A's cap being 0: the second
        // removal sees no more of A than the first, the two fold, and one Z re-signs them.)
        and (REISSUE_REMOVALS implies db.keys().filter(i => db.get(i).kit == "z").size()
          == (if (FIXED_CAPS and not(SHARE_REST)) 1 else 2)) and promises)

  // REISSUE_REMOVALS, a cut root full of removals, then changes: R removes two keys (with its
  // three admins, 5 of its 6 units under (J); three would pass MAXREC by the third change); the
  // recovery key changes to NA, NA removes one more key
  // before it is lost, the recovery key changes to NK, then to NB: three changes in a row.
  // Each change re-signs what counts.
  // (Void under LAST_ROOT_ONLY: L carries no Zs; three changes under L: lSecondChange.)
  run reissueChainTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(sign(ROOT, "revoke", "dW", "", 0, false, false, 1))
      .then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m).path == ["R", "NA"]
        and Set(DEVICE, "dW").subseteq(views.get(m).revoked)) and promises
        // (Packing: R's two removals name different keys, so NA re-signs them in one Z.)
        and (REISSUE_REMOVALS implies db.keys().filter(i => db.get(i).kit == "z").size() == 1))
      .then(sign("NA", "revoke", "dX", "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NK")).then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m).path == ["R", "NA", "NK"]
        and Set(DEVICE, "dW", "dX").subseteq(views.get(m).revoked)) and promises)
      .then(recoverAs(RECOVERY, "NB")).then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m).path == ["R", "NA", "NK", "NB"]
        and Set(DEVICE, "dW", "dX").subseteq(views.get(m).revoked)) and promises)

  // Restore after a change with re-issued removals (architecture 23:26Z: the core's restore
  // broke there): R removes D and dW, the change to NA re-signs them (Z) beside its first
  // checkpoint; NA writes on and a later checkpoint of NA's prunes the first one; then members
  // restart, NA's own device among them. Each rebuilds the state of a member that did not.
  // (Void under LAST_ROOT_ONLY: L carries no Zs.)
  run restartAfterReissueTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(sign(ROOT, "revoke", "dW", "", 0, false, false, 1))
      .then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(sign("NA", "checkpoint", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
      .then(restart("a")).then(restart("c")).then(restart("k"))
      .then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m).path == ["R", "NA"]
        and Set(DEVICE, "dW").subseteq(views.get(m).revoked)
        and views.get(m).checkpoint == views.get("r").checkpoint
        and st.get(m).recs == st.get("r").recs and st.get(m).cut.marks.keys() == Set()) and promises
        and (WHOLE_BY_SETTLER implies savedStable))

  // A search's trace (seed 77007): a bent checkpoint of the new root NA keeps R's records 1 and
  // 2, which the change to NA cuts (the honest writer signs only as its set's last root). It must not
  // settle the change: else the set applies it live, the change cuts 1 and 2, and a restart
  // rebuilds without it.
  run settlerKeepsWhatChangeCutsTest =
    init
      .then(offerEveryone(1)).then(recoverAs(RECOVERY, "NK")).then(syncRound)
      .then(signCheckpointKeep("NK", Set(4), "A", 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(restart("r")).then(giveOnly("a", 7))
      .then(signCheckpointKeep("NA", Set(1, 2, 3), "X", 2))
      .expect((WHOLE_BY_SETTLER implies (views.get("a").path == ["R", "NK"] and savedStable)) and promises)

  // EARLY_ASIDE (was HELD_ADMISSIONS (b)), core 066addaf: a record of the new root NA that comes while the head
  // to NA waits for its first checkpoint sits aside and is saved, so a member restarted from
  // what it saves still takes it once the head applies.
  // (Void under LAST_ROOT_ONLY: the ids of the change's records assume no re-issued Ys.)
  run earlyAsideSavedTest = if (LAST_ROOT_ONLY) init else
    init
      .then(recoverAs(RECOVERY, "NA")).then(giveOnly("a", 4)).then(giveOnly("a", 5))
      .then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(giveOnly("c", 4)).then(giveOnly("c", 6)).then(restartSaved("c")).then(giveOnly("c", 5))
      .expect(views.get("c").path == ["R", "NA"] and (EARLY_ASIDE iff st.get("c").recs.contains(6)) and promises)

  // NEWEST_CP_FIRST (architecture 11-14 03:00Z): R signs three checkpoints that never count.
  // Today they go before R's admission records and push one out; under the switch only the
  // newest goes first and the others take their place by seq.
  run ownCheckpointsCrowdTest =
    init
      .then(signCheckpointKeep(ROOT, Set(NEVER), "", 2)).then(signCheckpointKeep(ROOT, Set(NEVER), "", 2))
      .then(signCheckpointKeep(ROOT, Set(NEVER), "", 2)).then(syncRound)
      .expect(NEWEST_CP_FIRST iff ownCpsNoCrowd)

  // An honest-only search (seed 77101, J and the decided set): at a, R's checkpoints 8 and 13
  // are held but none counts (a lacks 4 and the resolve 6 their keep needs); they go first in R's
  // room, so R's newest admission (3, of W) is cut while W's freeze 5 stays. Under
  // NEWEST_CP_FIRST only the newest goes first and every admission stays.
  run honestCheckpointsCutAdmissionTest =
    init
      .then(sign("R", "checkpoint", "", "", 0, false, false, 2)).then(sign("W", "freeze", "dW", "", 0, false, false, 1))
      .then(sign("R", "resolve", "", "", 4, false, false, 1)).then(giveOnly("a", 5))
      .then(sign("A", "admin", "NA", "phone", 0, false, false, 1)).then(sign("R", "checkpoint", "", "", 0, false, false, 2))
      .then(sign("W", "revoke", "dA", "", 0, false, false, 1)).then(sign("C", "copies", "", "", 0, false, false, 2))
      .then(sign("A", "thaw", "", "", 5, false, false, 1)).then(sign("R", "checkpoint", "", "", 0, false, false, 2))
      .then(sign("R", "checkpoint", "", "", 0, false, false, 2)).then(giveOnly("a", 13)).then(give("a", 8))
      .expect((NEWEST_CP_FIRST implies admissionHeld) and ((CEIL_FIT and not(NEWEST_CP_FIRST)) implies not(admissionHeld)))

  // Records 11-14: an honest checkpoint keeps what counts, not its root's older checkpoints, so
  // its keep stays flat however many the root signs (the core's keep grew until the ~70th
  // checkpoint was refused). As many in a row as the model's IDs allow. (Without
  // PREV_ROOM_WHEN_KEPT the pruned previous checkpoints still take room: the members stop
  // taking R's checkpoints after the 14th, 17 counts.)
  run checkpointKeepFlatTest =
    init
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2))
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2)).then(syncRound)
      .expect(db.keys().forall(i => db.get(i).kind != "checkpoint" or db.get(i).keep == Set(1, 2, 3))
        and (PREV_ROOM_WHEN_KEPT implies MEMBERS.forall(m => views.get(m).checkpoint == FIRST + 15)) and promises)

  // The exhaustive-check thread's probe (11-13 23:56Z): the change to NK re-signs R's removal
  // of D (Z 7) beside its first checkpoint 8; NK's checkpoint 9 keeps 7 and prunes 8; then m
  // restarts and c restarts from what it saves alone.
  run firstPrunedTest =
    init
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NK")).then(syncRound).then(syncRound)
      .then(sign("NK", "checkpoint", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
      .expect(savedStable)
      .then(restart("m")).then(restartSaved("c"))
      .expect(MEMBERS.filter(x => inGroup(x)).forall(x => views.get(x).path == ["R", "NK"]
        and not(views.get(x).devices.contains(DEVICE))) and savedStable and promises)

  // The fold of an admin key's removals: R removes A, A signs on, R removes A again, and R's
  // checkpoint folds the first removal into the second. A's record after the first removal
  // never counts, before or after: the two removals saw A differently, so the first does not
  // fold (the core's "same seen entries"; without it, at the default sizes, the fold let A's
  // record count). R is handed A's record 5 directly: under UNKNOWN_HEADS a removed key's member
  // hands only heads, so 5 would never reach R and the two removals would see A alike.
  run foldAdminTest =
    init
      .then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1)).then(giveOnly("r", 5)).then(syncRound)
      .then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1)).then(syncRound)
      .expect(MEMBERS.exclude(Set("a")).forall(m => not(views.get(m).counting.contains(5))) and promises)
      // (Under (J) R, at its ceiling with both removals kept, cannot write the checkpoint.)
      .then(if (CEIL_FIT) syncRound else sign(ROOT, "checkpoint", "", "", 0, false, false, 2).then(giveOnly("c", 7)).then(compactAt("c")))
      .expect((not(CEIL_FIT) implies db.get(7).keep.contains(4))
        and MEMBERS.exclude(Set("a")).forall(m => not(views.get(m).counting.contains(5))) and promises)
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.exclude(Set("a")).forall(m => not(views.get(m).counting.contains(5))) and promises)

  // Liveness under CP_ROOM_WHEN_WHOLE: m gets the root's new checkpoint 6 before the records
  // it keeps (A's 4) and before the root's own 5 on its line; it waits aside, missing() asks for
  // what it names, and one sync later every member counts 6.
  run cpWholeLiveTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1)).then(giveOnly("r", 4))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set()))
      .then(giveOnly("m", 6))
      .expect(views.get("m").checkpoint == 0 and (CP_ROOM_WHEN_WHOLE implies
        (st.get("m").wait.contains(6) and missingOf(st.get("m"), db).contains(4))))
      .then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 6 and views.get(m) == views.get("r")
        and st.get(m).recs == st.get("r").recs) and promises)

  // The bound under CP_ROOM_WHEN_WHOLE: the root signs three checkpoints that can never be
  // whole (each keeps a record that does not exist). None takes room at any member; what waits
  // aside stays within ASIDE_ROOM, newest first, and all members agree.
  run cpWholeBoundTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 99), "", 1)).then(offerEveryone(5))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 99), "", 1)).then(offerEveryone(6))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 99), "", 1)).then(offerEveryone(7))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m) == views.get("a") and views.get(m).checkpoint == 0
        and st.get(m).recs == st.get("a").recs and sumUnits(recsOf(st.get(m).wait, db)) <= ASIDE_ROOM
        and (CP_ROOM_WHEN_WHOLE implies st.get(m).recs.intersect(Set(5, 6, 7)) == Set())))

  // --- (J): ceilings that fit the room -----------------------------------------------------
  // The cap: the root admits a fourth admin key (3 roots at 6 and 4 admins at 2 fill ROOM),
  // and refuses a fifth.
  run jCapTest = init
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .expect(MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4)) and promises
        and (CEIL_FIT implies not(capFits("r", "C2"))))
  // Every key with room writes to its ceiling, a member restarts and a newcomer is welcomed:
  // nothing is dropped, nobody holds a mark, all converge.
  action jFull =
    init
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(sign(COMPUTER, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 2)).then(syncRound)
  run jHonestFullTest = jFull
      .then(restart("c")).then(welcomeFrom("a")).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 5, 6, 7, 8, 9) and convergesAt(m)
        and st.get(m).cut.marks.keys() == Set()) and promises)
  // Every key at its ceiling: an honest writer refuses its next record (a failed write uses no
  // seq); the root's checkpoint that keeps all counts.
  run jRefusedTest = jFull
      .expect(CEIL_FIT implies not(ceilFits(PHONE, 1)))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set())).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 10 and convergesAt(m) and st.get(m).cut.marks.keys() == Set())
        and promises)
  // One deviating key: X publishes past its ceiling. Every member drops it alike and marks X
  // only; no other key's record differs. A member that restarts forgets the mark and keeps
  // X's next deviating record that the others turn away: members differ in X's records only.
  run jDeviantTest = jFull
      .then(signDeviant("X", "copies", "", 1)).then(offerEveryone(10)).then(syncRound)
      .expect(CEIL_FIT implies MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 5, 6, 7, 8, 9)
        // (FIXED_CAPS remembers nothing: no mark, and every member turns X's next record away alike.)
        and st.get(m).cut.marks.keys() == (if (FIXED_CAPS) Set() else Set("X"))))
      .then(restart("m"))
      .then(signDeviant("X", "copies", "", 1)).then(offerEveryone(11)).then(syncRound)
      .expect(CEIL_FIT implies MEMBERS.forall(m => recsOf(st.get(m).recs, db).filter(r => r.signer != "X")
        == recsOf(st.get("r").recs, db).filter(r => r.signer != "X")))
      // The root's next checkpoint, keeping what it counts, ends any difference.
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set())).then(syncRound).then(syncRound)
      .expect(CEIL_FIT implies MEMBERS.forall(m => st.get(m).recs == st.get("r").recs and views.get(m) == views.get("r")
        and views.get(m).checkpoint == 12))

  // (J) a deviating admin's admissions: X has one unit left and signs two device records past
  // its ceiling; a and c get them in opposite orders. Its line orders them, so every member
  // keeps the same prefix (10) and refuses 11: the devices are equal everywhere; only a and c
  // hold a mark for X, which changes nothing.
  run jDeviantDevicesTest =
    init
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(sign(COMPUTER, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signDeviant("X", "device", DEVICE, 1)).then(signDeviant("X", "device", "dN", 1))
      .then(giveOnly("a", 10)).then(giveOnly("a", 11)).then(giveOnly("c", 11)).then(giveOnly("c", 10))
      .then(syncRound).then(syncRound)
      .expect(CEIL_FIT implies MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        and views.get(m) == views.get("r") and not(views.get(m).devices.contains("dN"))) and promises)

  // (J) cap race: the root admits a fourth admin key while admin A, on another device, names
  // C2. Only the current root's admissions count, and the root key has one holder whose own set
  // refuses a fifth (a second holder signing is a root fork, which halts): A's record names no
  // admin, so no two admissions can pass the cap together.
  run jCapRaceTest =
    init
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1))
      .then(sign(PHONE, "admin", "C2", "computer", 0, false, false, 1))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 5)
        and views.get(m).admins.keys() == Set(PHONE, COMPUTER, WATCH, "X") and st.get(m).cut.marks.keys() == Set())
        and promises)

  // (J) reserve: two changes of root. Under NK the cut roots R and NA would list 4 + 3 units,
  // past RESERVE 6: the writer keeps every root removal and every live admission (R's four
  // admins) and drops NA's copies (7). Nothing revives; every admin stays; all agree.
  // (Under UNKNOWN_HEADS m's key is D, which NA removes: m is out of the group.)
  // (Void under LAST_ROOT_ONLY: the cut roots' list and its reserve do not apply under L.)
  run jReserveTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign("NA", "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NK")).then(syncRound).then(syncRound)
      .expect((REISSUE_REMOVALS implies not(recsOf(db.get(lastHead).keep, db).exists(r => rootRemoval(r))))
        and (CEIL_FIT implies ((REISSUE_REMOVALS or db.get(9).keep == Set(1, 2, 3, 4, 8))
        and MEMBERS.filter(m => inGroup(m)).forall(m => st.get(m).recs == st.get("r").recs and views.get(m) == views.get("r")
          and views.get(m).path == ["R", "NA", "NK"] and views.get(m).admins.keys() == Set(PHONE, COMPUTER, WATCH, "X")
          and views.get(m).revoked.contains(DEVICE)))) and promises)

  // (H): under WRITER_FLOOR the same group writes within FLOOR above the head: A's second
  // record waits for the root's next checkpoint; X's admission and record drop nothing.
  run floorShareTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 5, 6, 7, 8)) and promises)
      // The root's honest checkpoint keeps everything that counts (13 units with itself): A's
      // next record is within FLOOR above the new head but its own set cannot keep it, so (E)
      // refuses it; nobody writes again until a checkpoint prunes.
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set())).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 9 and sumUnits(recsOf(st.get(m).recs, db)) == 13) and promises)

  // --- F-12 -------------------------------------------------------------------------------
  // Every member counts checkpoint 5, which keeps device D's admission 4.
  action f12Base =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(syncRound)
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("m")).then(compactAt("k"))
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 5 and views.get(m).devices.contains(DEVICE)))
  // The root removes D and checkpoint 8 prunes the removal with the admission. Member a counts
  // 8; m holds 8 without the record 8 waits for. Today m still counts D; with F-12 it does not.
  // (Void under ROOT_WAITS: the checkpoint settles a removal no admin has acked; W keeps it until every live admin acks (the settle path: wSh1, wSh2, wFrozenBlocks).)
  run f12HeldBackTest = if (ROOT_WAITS) init else f12Base
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(giveAll(Set("a"), [6, 7, 8]))
      .then(giveAll(Set("m"), [8]))
      .expect(and { views.get("a").checkpoint == 8, not(views.get("a").devices.contains(DEVICE)),
        views.get("m").checkpoint == 5, views.get("m").devices.contains(DEVICE) == not(F12),
        heldBackCountsLess == F12 })
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8 and not(views.get(m).devices.contains(DEVICE))) and promises)
  // Two waiting checkpoints: 7 leaves D's admission out, 8 keeps it; neither is whole on m
  // (both wait for the record 6). With F-12, D is out on m while 7 is held; a member that
  // counts 8 counts D.
  run f12TwoWaitingTest = f12Base
      .then(signAs(ROOT, "copies", "", 0))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 4, 6), "", 1))
      .then(giveAll(Set("m"), [7, 8]))
      .then(giveAll(Set("a"), [6, 7, 8]))
      .expect(and { views.get("a").checkpoint == 8, views.get("a").devices.contains(DEVICE),
        views.get("m").checkpoint == 5, views.get("m").devices.contains(DEVICE) == not(F12),
        // The root counts 7 (it dropped 4 there): today m, held back, counts D and r does not.
        views.get("r").checkpoint == 7, heldBackCountsLess == F12 })
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8 and views.get(m).devices.contains(DEVICE)) and promises)
  // The price (P-8): the root signs a newer admission of D (6) and a checkpoint keeping it and
  // pruning the older one (4); m lacks 6. With F-12 the honest device D does not count on m
  // until 8 is whole there.
  run f12PriceTest = f12Base
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6), "", 1))
      .then(giveAll(Set("a"), [6, 7]))
      .then(giveAll(Set("m"), [7]))
      .expect(and { views.get("a").checkpoint == 7, views.get("a").devices.contains(DEVICE),
        views.get("m").checkpoint == 5, views.get("m").devices.contains(DEVICE) == not(F12) })
      .then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 7 and views.get(m).devices.contains(DEVICE)) and promises)

  // CP_FIRST: the root checkpoints, then removes admin key A; the device A admitted still counts
  // once A's cap is 0, as the checkpoint keeps it. (Without CP_FIRST the removal needs no
  // checkpoint; the expectation is the switches'.)
  run adminRemovalCheckpointFirstTest = init
      .then(sign("A", "device", "D", "", 0, false, false, 1))
      .then(syncAll)
      .then(sign("R", "checkpoint", "", "", 0, false, false, 2))
      .then(syncAll)
      .then(sign("R", "revoke", "A", "", 0, false, false, 1))
      .then(syncAll)
      .expect(cpFirstKeepsDevices and MEMBERS.forall(m => views.get(m).devices.contains(DEVICE)) and promises)
  // The bent root that skips the checkpoint: under FIXED_CAPS the device A admitted is lost with
  // A's room.
  run adminRemovalNoCheckpointTest = init
      .then(sign("A", "device", "D", "", 0, false, false, 1))
      .then(syncAll)
      .then(sign("R", "revoke", "A", "nocp", 0, false, false, 1))
      .then(syncAll)
      .expect((FIXED_CAPS and not(SHARE_REST)) iff MEMBERS.forall(m => not(views.get(m).devices.contains(DEVICE))))
  // The stated limit: a deviant recovery key's list (mode "from1" re-signs nothing) drops the cut
  // root's removal of A, and A's device record counts again (it did on 1612ae59 with the switches
  // of k6), unless A's room is 0 (FIXED_CAPS). The honest change re-signs the removal and is clean.
  run deviantRecoveryBringsBackTest = init
      .then(sign("R", "revoke", "A", "", 0, false, false, 1))
      .then(sign("A", "device", "D", "", 0, false, false, 1))
      .then(syncRound)
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "NA", 2, "from1"))
      .expect((FIXED_CAPS and not(SHARE_REST)) implies removedGainsNothing)
  run honestRecoveryKeepsRemovalTest = init
      .then(sign("R", "revoke", "A", "", 0, false, false, 1))
      .then(sign("A", "device", "D", "", 0, false, false, 1))
      .then(syncRound)
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "NA", 2, "honest"))
      .expect(removedGainsNothing)
  // Rule C (OWN_HEAD): R's bent checkpoint 8 leaves out its own head and keeps nothing. A member
  // that counted the older checkpoint 7 (which drops the device admission 4 and its removal 5)
  // and compacted cannot count 8 and refuses 5 again as settled; a member that judges 7 and 8
  // with 4 and 5 counts 8, which prunes nothing of R's line, and 5 counts. With OWN_HEAD off and
  // WIDE_ROOT on (R's room holds all ten units) members a and r end at 7 without the removal,
  // c, k and m at 8 with D revoked: converges fails (checked 11-14). OWN_HEAD refuses 8.
  run ownHeadTest = init
      .then(sign("R", "device", "D", "", 0, false, false, 1))
      .then(sign("R", "revoke", "D", "", 0, false, false, 1))
      .then(sign("R", "copies", "", "", 0, false, false, 1))
      .then(syncAll)
      .then(signCheckpointKeep("R", Set(1, 2, 3), "", 2))
      .then(giveOnly("a", 7))
      .then(compactAt("a"))
      .then(signCheckpointKeep("R", Set(), "none", 2))
      .then(giveOnly("a", 8))
      .then(giveOnly("c", 8))
      .then(giveOnly("c", 7))
      .then(syncAll)
      .expect((OWN_HEAD implies MEMBERS.forall(m => convergesAt(m) and views.get(m).checkpoint == 7))
        and ((WIDE_ROOT and not(OWN_HEAD) and not(CEIL_FIT) and not(FIXED_CAPS))
          implies not(MEMBERS.forall(m => convergesAt(m)))))
  // decW seed 11419 (decided set + WIDE_ROOT; at ROOTC 6 the old root's third checkpoint does
  // not fit), minimised: the old root key signs a checkpoint that can never be whole after
  // a change, member a (which never took the heads) holds a removed admin's record aside for it,
  // and k (two changes on) must not be held to that place aside (fuzz replay at 9e20ec86: a
  // drops it once it takes the heads).
  run oldRootAsideTest = if (CEIL_FIT and not(WIDE_ROOT)) init else
      init
        .then(signFull("R", "checkpoint", "", "", 0, false, false, 2, false, Set(3)))
        .then(signFull("R", "checkpoint", "", "", 0, false, false, 2, false, Set(1)))
        .then(sign("R", "revoke", "A", "", 0, false, false, 1))
        .then(sign("R", "checkpoint", "", "", 0, false, false, 2))
        .then(sign("A", "revoke", "D", "", 0, false, false, 1))
        .then(syncRound)
        .then(recoverAs(RECOVERY, "NA"))
        .then(sign("R", "revoke", "A", "", 0, false, false, 1))
        .then(offerEveryone(12))
        .then(sign("R", "revoke", "D", "", 0, false, false, 1))
        .then(signCheckpointKeep("R", Set(1, 2, 6, 7, 8, 9, 10, 11, 12, 13, NEVER), "W", 1))
        .then(offerEveryone(14))
        .then(recoverAs(RECOVERY, "NK"))
        .then(restart("a"))
        .expect(promises)
        .then(syncRound).then(syncRound)
        .expect(promises and not(st.get("a").wait.contains(8)))
  // dec seed 11418, minimised: an admin key removed by a re-issued removal (a Z) admits a device
  // that never counts; the new root's own removal of it later loses nothing.
  run removedAdminDeviceDecidedTest =
    init
      .then(signChain(RECOVERY, "recover", "NK", 1, "from1"))
      .then(sign("NK", "revoke", "A", "", 0, false, false, 1))
      .then(recoverAs(RECOVERY, "NA"))
      .then(sign("A", "device", "D", "", 0, false, false, 1))
      .then(syncRound)
      .expect(MEMBERS.forall(m => not(views.get(m).devices.contains(DEVICE))))
      .then(sign("NA", "revoke", "A", "", 0, false, false, 1))
      .expect(promises and cpFirstKeepsDevices)
  // The twin of seed 11418: A admits D while A is live, D counts, the root removes A with a seen
  // that covers D's admission, and its checkpoint first: D still counts.
  run liveAdminDeviceDecidedTest =
    init
      .then(sign("A", "device", "D", "", 0, false, false, 1))
      .then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).devices.contains(DEVICE)))
      .then(sign("R", "checkpoint", "", "", 0, false, false, 2))
      .then(syncRound)
      .then(sign("R", "revoke", "A", "", 0, false, false, 1))
      .then(syncRound)
      .expect(db.get(6).seen.get("A") == [4] and db.get(6).kit == "" and promises and cpFirstKeepsDevices
        and (CP_FIRST implies MEMBERS.forall(m => views.get(m).devices.contains(DEVICE))))
  // dec seed 11415, minimised: a root fork at seq 3 halts c, m and r; a halted member takes
  // nothing more and is owed no share of the room.
  run forkHaltShareDecidedTest =
    init
      .then(signFull("R", "revoke", "C", "phone", 0, false, true, 1, true, Set()))
      .then(offerEveryone(4))
      .then(sign("A", "copies", "", "", 0, false, false, 2))
      .then(signFull("R", "admin", "X", "phone", 0, false, true, 1, true, Set()))
      .then(offerEveryone(6))
      .then(sign("R", "copies", "", "", 0, false, false, 1))
      .then(signCheckpointKeep("R", Set(6, 7, 99), "", 2))
      .then(recoverAs(RECOVERY, "NA"))
      .then(sign("R", "revoke", "D", "", 0, false, false, 1))
      .then(signFull("NA", "checkpoint", "", "", 0, false, false, 2, false, Set(10)))
      .then(recoverAs(RECOVERY, "NK"))
      .then(sign("NA", "revoke", "A", "", 0, false, false, 1))
      .then(signDeviant("X", "device", "D", 2))
      .then(offerEveryone(18))
      .expect(promises and MEMBERS.exists(m => views.get(m).stop))
  run recoveryChangesRootTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .expect(views.get("k").path == [ROOT, "NK"])
      .then(give("m", 4))
      // (LAST_ROOT_ONLY: the admins are wiped, their devices stay as plain devices.)
      .expect(views.get("m").path == [ROOT, "NK"] and (if (LAST_ROOT_ONLY) views.get("m").admins.keys() == Set()
          and Set("dA", "dC", "dW").subseteq(views.get("m").devices)
        else views.get("m").cuts == Map(ROOT -> [1, 2, 3]) and views.get("m").admins.keys() == Set(PHONE, COMPUTER, WATCH))
        and promises)

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
      .then(signChain(RECOVERY, "recover", ROOT, 1, if (NEW_ROOT_ONLY) "nocp" else "honest"))
      .then(give("m", 4))
      .expect(views.get("m").path == [ROOT] and not(views.get("m").stop) and promises)

  // A head that is not valid (it names the current root) keeps nothing aside: the root's
  // checkpoint it names stays in the rooms like the root's other records, on every member,
  // whether or not it holds the head.
  run invalidHeadKeepsNothingAsideTest =
    init
      .then(signChain(RECOVERY, "recover", ROOT, 1, if (NEW_ROOT_ONLY) "nocp" else "honest"))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(give("m", 5)).then(give("m", 6)).then(give("m", if (NEW_ROOT_ONLY) 6 else 7))
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).path == [ROOT] and st.get(x).chain == Set(4)) and promises)

  // The phone admin's key signs twice at one seq: a fork, and it commands nothing. The
  // root's counting checkpoint settles what is below its heads: its head of that key is one
  // sibling, the other is pruned, and the phone admin commands again.
  run checkpointSettlesTwinsTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1))
      .then(sign(PHONE, "copies", "", "", 0, false, true, 1))
      .then(give("r", 4)).then(give("r", 5))
      .expect(not(views.get("r").commanders.contains(PHONE)))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(6).heads.get(PHONE).length() == 1 and db.get(6).keep.intersect(Set(4, 5)) == Set())
      .then(give("m", 4)).then(give("m", 5)).then(give("m", 6))
      .expect(views.get("m").checkpoint == 6 and views.get("m").commanders.contains(PHONE)
        and st.get("m").recs.contains(4) and not(st.get("m").recs.contains(5)) and promises)

  // The root's resolve voids its newest checkpoint after a member compacted by it: the member
  // forgets that checkpoint and takes again what it left out, and ends in the state of a
  // member that got the same records in another order.
  run resolvedCheckpointTest =
    init
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(signAs(ROOT, "resolve", "", 6))
      .then(give("m", 4)).then(give("m", 5)).then(give("m", 6))
      .expect(views.get("m").checkpoint == 6 and not(st.get("m").recs.contains(4)))
      .then(give("m", 7))
      .then(give("c", 7)).then(give("c", 6)).then(give("c", 5)).then(give("c", 4))
      .expect(views.get("m") == views.get("c") and st.get("m").recs == st.get("c").recs and promises)

  // A device the root removed does not come back by a new record for its key.
  // (Under WRITER_CP_FLOOR the root checkpoints after the removal, dropping the removed device's
  // admission, so that its next record leaves room for its next checkpoint.)
  run removedDeviceStaysOutTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(if (WRITER_CP_FLOOR) signAs(ROOT, "checkpoint", "", 0) else offerEveryone(0))
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
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
      // (SEEN_POS: A acks first, so that its writer signs above an anchor.)
      .then(if (SEEN_POS) ackS(PHONE) else syncRound).then(syncRound)
      .then(signAs(ROOT, "revoke", PHONE, 0))
      .then(sign(PHONE, "revoke", COMPUTER, "", 0, true, false, 1))
      .then(sign(PHONE, "freeze", WATCH, "", 0, true, false, 1))
      .then(sign(PHONE, "device", DEVICE, "", 0, true, false, 1))
      .then(giveBy("m", ROOT, 4)).then(giveBy("m", PHONE, 1))
      .expect(views.get("m").admins.keys() == Set(COMPUTER, WATCH) and not(views.get("m").devices.contains(DEVICE))
        and not(views.get("m").frozen.contains(WATCH)) and promises)
      .then(giveBy("k", ROOT, 4)).then(giveBy("k", PHONE, 1))
      .then(recoverAs(RECOVERY, "NK"))
      .then(giveHead("m", "NK"))
      // (LAST_ROOT_ONLY: nothing R signed counts under NK, its removal of A included; A, wiped
      // with the other admins, still counts nothing and D stays out.)
      .expect(views.get("m").path == [ROOT, "NK"] and (LAST_ROOT_ONLY or views.get("m").revoked.contains(PHONE))
        and not(views.get("m").admins.keys().contains(PHONE)) and not(views.get("m").frozen.contains(WATCH))
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
  // (Void under LAST_ROOT_ONLY: cuts and lists do not apply under L; lSecondChange.)
  run secondChangeTest = if (LAST_ROOT_ONLY) init else
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
      .then(giveHead("m", "NK"))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(giveHead("m", "NA"))
      .expect(views.get("m").stop and views.get("m").commanders == Set())
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).stop and views.get(x).commanders == Set()) and promises)

  // A halted set takes recovery records only: a record signed after the fork is not kept.
  run haltedTakesChainOnlyTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "NA", 1, "honest"))
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).stop))
      .then(signAs("NK", "device", DEVICE, 0))
      .then(give("m", nextId - 1))
      .expect(not(st.get("m").recs.contains(nextId - 1)) and st.get("m").got.contains(nextId - 1) and promises)

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
      .then(giveBy("m", ROOT, 5))
      .expect(not(views.get("m").devices.contains(DEVICE)))
      .then(giveHead("m", "NK"))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").devices.contains(DEVICE) and promises)

  // The owner unticks the computer admin: the new root signs its removal in the same act. The
  // root's earlier removal of the watch admin is on the list and stays.
  // (Void under LAST_ROOT_ONLY: L wipes every admin at a change; there is nothing left to untick.)
  run untickTest = if (LAST_ROOT_ONLY) init else
    init
      .then(signAs(ROOT, "revoke", WATCH, 0))
      .then(give("k", 4))
      .then(recoverAs(RECOVERY, "NK"))
      .then(signAs("NK", "revoke", COMPUTER, 0))
      .then(give("m", 4))
      .then(give("m", 5))
      .then(give("m", 6))
      .then(give("m", 7))
      // (REISSUE_REMOVALS: NK's removal of C is 8, after its re-signed removal of W.)
      .then(if (REISSUE_REMOVALS) give("m", 8) else give("m", 7))
      .expect(views.get("m").path == [ROOT, "NK"] and views.get("m").admins.keys() == Set(PHONE)
        and views.get("m").revoked.contains(WATCH) and promises)

  // The old root removes the phone admin on its own device, which has not yet got the change
  // to NK; that change does not list the removal. A second head, to NA, lists it again. The
  // old root's device takes both heads at once, keeps the removal (the newest list names it)
  // and has A out; once sync has offered it again, every member has A out.
  // (Void under LAST_ROOT_ONLY: lists do not apply under L.)
  run relistedRemovalTest = if (LAST_ROOT_ONLY) init else
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
  // (Void under LAST_ROOT_ONLY: lists do not apply under L.)
  run literalListTest = if (LAST_ROOT_ONLY) init else
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
  // of the old root; the change stays, since the recovery record and the new root's first
  // checkpoint are outside the rooms.
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
      .then(give("m", 6)).then(give("m", 7)).then(give("m", 8)).then(give("m", 9))
      .then(give("m", 10)).then(give("m", 11)).then(give("m", 12)).then(give("m", 13))
      .expect((LAST_ROOT_ONLY or st.get("m").chain == Set(4, 5)) and views.get("m").path == [ROOT, "NK"] and promises)

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
        and views.get("m").checkpoint != 6 and promises)

  // A newcomer takes the chain from its admitter's Welcome and has its path.
  run newcomerTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signAs("NK", "copies", "", 0))
      .then(recoverAs(RECOVERY, "NA"))
      .then(welcomeFrom("k"))
      .expect(views.get("m").path == [ROOT, "NK", "NA"] and welcomed == [ROOT, "NK", "NA"] and promises)

  // The replaced root's checkpoint compacts every member that takes it, at once (once that was
  // one member compacting and the other not); after the change they end in one state: the new
  // root's first checkpoint, signed with the head, prunes again what the old one pruned (A's
  // removal the root resolved).
  // (Void under LAST_ROOT_ONLY: the ids of the change's records assume no re-issued Ys.)
  run compactedChangeTest = if (LAST_ROOT_ONLY) init else
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
      .expect(views.get("m").checkpoint == 8 and not(st.get("m").recs.contains(5)) and not(st.get("c").recs.contains(5)))
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
      .then(give("m", 8))
      .expect(views.get("m").devices.contains(DEVICE) and promises)

  // The same with the writer's full list, by hand (the honest writer refuses a known key): the
  // admin record is listed, and counts.
  // (Void under LAST_ROOT_ONLY: NA was an admin key; under L a new root is always a fresh key.)
  run adminNamedRootListedTest = if (LAST_ROOT_ONLY) init else
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

  // --- Decided-set versions ------------------------------------------------------------------
  // Under the decided set (CEIL_FIT, WRITER_KEEPS, FIXED_CAPS and the rest) an honest writer no
  // longer signs the over-cap records these scenarios start from, so their steps are refused
  // there. Each "...DecidedTest" run is its scenario with those steps signed by a writer that
  // skips its own checks (signW, signFullW, signAsW: an old or deviating writer), so what the
  // scenario checks about the sets still runs at the decided set. Where an expectation named
  // exact record sets or IDs of the old sizes, the run checks the promises there instead
  // (foldListDecidedTest, prunedRemovalDecidedTest, rootKeepsBothDecidedTest,
  // restartAfterTwoChangesDecidedTest, honestShareFallsDecidedTest).
  // The originals stay as they are for the other configurations.

  run adminKeyRemovalStaysDecidedTest =
    init
      .then(signAs(ROOT, "revoke", WATCH, 0))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signAsW(ROOT, "checkpoint", "", 0))
      .then(syncAll)
      .expect(db.get(6).keep.contains(4) and MEMBERS.forall(m => views.get(m).revoked.contains(WATCH)) and promises)

  run everyWaitingDecidedTest =
    init
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncAll)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signFullW(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(99)))
      .then(give("a", 8)).then(give("a", 9))
      .then(give("m", 11)).then(give("m", 9)).then(give("m", 8)).then(give("m", 10))
      .expect(views.get("a").checkpoint == 9)
      .then(syncAll)
      // 9 with what it names fills the root's ceiling; off NEWEST_ASIDE, with 11 kept first
      // beside it they do not fit, the rooms fall back to the plain rule and the members that
      // took 9 count nothing.
      .expect(if (NEWEST_ASIDE) MEMBERS.forall(m => views.get(m).checkpoint == 9) and promises
        else views.get("a").checkpoint == 0 and views.get("m").checkpoint == 7)

  run f7RootFirstRemovesDecidedTest = f7Base
      .then(giveOnly("a", 5)).then(giveOnly("c", 6)).then(giveOnly("r", 6)).then(giveOnly("r", 5))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", PHONE, "", 0, false, false, 1))
      .then(signW(PHONE, "revoke", "dC", "", 0, false, false, 1))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m) == views.get("r") and st.get(m).recs == st.get("r").recs
        and views.get(m).revoked.contains(DEVICE) and views.get(m).revoked.contains(PHONE)
        and views.get(m).revoked.contains(COMPUTER) == F7_SEEN_IGNORED and not(views.get(m).stop))
        and (promises or F7_SEEN_IGNORED))

  run f7RootRemovesDecidedTest = f7RootRemovesBase
      .then(signW(PHONE, "revoke", "dC", "", 0, false, false, 1))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => views.get(m) == views.get("r") and views.get(m).revoked.contains(PHONE)
        and views.get(m).revoked.contains(DEVICE) == F7_SEEN_IGNORED
        and views.get(m).revoked.contains(COMPUTER) == F7_SEEN_IGNORED) and (promises or F7_SEEN_IGNORED))

  run followsSettledDecidedTest = init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound).then(syncRound)
      .then(signFollowing(PHONE, "copies", 1, -1))
      .then(syncRound).then(syncRound)
      .expect(CUT_MODE != "follows" or MEMBERS.forall(m => st.get(m).recs.contains(4) and st.get(m).recs.contains(12)
        and convergesAt(m)) and promises)

  run fullRoomAfterChangeDecidedTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(give("m", 4))
      .expect(views.get("m").path == [ROOT, "NK"])
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(signW(WATCH, "copies", "", "", 0, false, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(give("m", 6)).then(give("m", 7)).then(give("m", 8)).then(give("m", 9))
      .then(give("m", 10)).then(give("m", 11)).then(give("m", 12)).then(give("m", 13))
      .expect((LAST_ROOT_ONLY or st.get("m").chain == Set(4, 5)) and views.get("m").path == [ROOT, "NK"] and promises)

  run haltedTakesChainOnlyDecidedTest =
    init
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "NA", 1, "honest"))
      .then(syncAll)
      .expect(MEMBERS.forall(x => views.get(x).stop))
      .then(signAsW("NK", "device", DEVICE, 0))
      .then(give("m", nextId - 1))
      .expect(not(st.get("m").recs.contains(nextId - 1)) and st.get("m").got.contains(nextId - 1) and promises)

  run heldPairNotWholeDecidedTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1))
      .then(signW(ROOT, "device", DEVICE, "", 0, false, true, 1))
      .then(giveOnly("a", 5)).then(giveOnly("a", 6))
      .expect(not(heldBy(st.get("a")).contains(4)) and views.get("r").stop
        and views.get("a").stop == HALT_ON_HELD_PAIR and promises)
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m) == views.get("r")) and promises)

  run hiddenKeepDecidedTest =
    init
      .then(signAs(ROOT, "device", DEVICE, 0))
      .then(signFull(ROOT, "admin", MINTED, "phone", 0, false, true, 1, true, Set()))
      .then(signFullW(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set(5)))
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
        and views.get("m").checkpoint != 6 and promises)

  // (Void under LAST_ROOT_ONLY: the ids of the change's records assume no re-issued Ys.)
  run mintedKeyDecidedTest = if (LAST_ROOT_ONLY) init else
    init
      .then(signW("NA", "admin", MINTED, "computer", 0, false, false, 1))
      .then(signAsW(MINTED, "device", DEVICE, 0))
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

  run namedOverCeilingDecidedTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signFullW(ROOT, "checkpoint", "", "", 0, false, false, 2, false, Set(1, 2, 3, 4, 5, 6)))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint != 7) and promises)

  run oldRootThiefDecidedTest =
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
      .then(signW(ROOT, "revoke", DEVICE, "", 0, false, true, 1))
      .then(giveBy("m", ROOT, 5))
      .expect(views.get("m").devices.contains(DEVICE) and not(views.get("m").admins.keys().contains(MINTED))
        and recsOf(st.get("m").recs, db).forall(r => r.signer != ROOT or r.seq < 5) and promises)

  run removedAdminThiefDecidedTest =
    init
      // (SEEN_POS: A acks first, so that its writer signs above an anchor.)
      .then(if (SEEN_POS) ackS(PHONE) else syncRound).then(syncRound)
      .then(signAs(ROOT, "revoke", PHONE, 0))
      .then(sign(PHONE, "revoke", COMPUTER, "", 0, true, false, 1))
      .then(sign(PHONE, "freeze", WATCH, "", 0, true, false, 1))
      .then(signW(PHONE, "device", DEVICE, "", 0, true, false, 1))
      .then(giveBy("m", ROOT, 4)).then(giveBy("m", PHONE, 1))
      .expect(views.get("m").admins.keys() == Set(COMPUTER, WATCH) and not(views.get("m").devices.contains(DEVICE))
        and not(views.get("m").frozen.contains(WATCH)) and promises)
      .then(giveBy("k", ROOT, 4)).then(giveBy("k", PHONE, 1))
      .then(recoverAs(RECOVERY, "NK"))
      .then(giveHead("m", "NK"))
      // (LAST_ROOT_ONLY: nothing R signed counts under NK, its removal of A included; A, wiped
      // with the other admins, still counts nothing and D stays out.)
      .expect(views.get("m").path == [ROOT, "NK"] and (LAST_ROOT_ONLY or views.get("m").revoked.contains(PHONE))
        and not(views.get("m").admins.keys().contains(PHONE)) and not(views.get("m").frozen.contains(WATCH))
        and not(views.get("m").devices.contains(DEVICE)) and promises)

  run resolvedCheckpointDecidedTest =
    init
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(signAsW(ROOT, "resolve", "", 6))
      .then(give("m", 4)).then(give("m", 5)).then(give("m", 6))
      .expect(views.get("m").checkpoint == 6 and not(st.get("m").recs.contains(4)))
      .then(give("m", 7))
      .then(give("c", 7)).then(give("c", 6)).then(give("c", 5)).then(give("c", 4))
      .expect(views.get("m") == views.get("c") and st.get("m").recs == st.get("c").recs and promises)

  run rootForkHaltsDecidedTest =
    init
      .then(signAs(ROOT, "copies", "", 0))
      .then(signW(ROOT, "copies", "", "", 0, false, true, 1))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m).commanders == Set()) and promises)
      .then(recoverAs(RECOVERY, "NK"))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NK"] and not(views.get(m).stop)
        and views.get(m).commanders.contains("NK")) and promises)

  // (Void under ROOT_WAITS: the checkpoint settles a removal no admin has acked; W keeps it until every live admin acks (the settle path: wSh1, wSh2, wFrozenBlocks).)
  run rootNamesPrunedGivenDecidedTest = if (ROOT_WAITS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncAll)
      .then(signFullW(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(4)))
      .then(syncAll)
      .then(give("m", 4))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8 and views.get(m).devices.contains(DEVICE)) and promises)

  // (Void under ROOT_WAITS: the checkpoint settles a removal no admin has acked; W keeps it until every live admin acks (the settle path: wSh1, wSh2, wFrozenBlocks).)
  run rootNamesPrunedDecidedTest = if (ROOT_WAITS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(give("a", 6)).then(give("a", 7)).then(give("c", 6)).then(give("c", 7)).then(give("m", 6)).then(give("m", 7))
      .expect(views.get("m").checkpoint == 7 and not(st.get("m").recs.contains(4)) and st.get("k").recs.contains(4))
      .then(signFullW(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(4)))
      .then(syncAll)
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8 and views.get(m).devices.contains(DEVICE)) and promises)

  run twinCheckpointAllPrunedDecidedTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1))
      .then(sign(PHONE, "device", DEVICE, "", 0, false, true, 1)).then(syncRound)
      .then(sign(ROOT, "resolve", "", "", 5, false, false, 1)).then(syncRound)
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 2, true, Set()))
      .then(offerEveryone(7))
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("k")).then(compactAt("m"))
      .expect(MEMBERS.forall(m => not(heldBy(st.get(m)).contains(5))))
      .then(signW(ROOT, "device", DEVICE, "", 0, false, true, 1))
      .then(offerEveryone(8)).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).stop and views.get(m) == views.get("c")
        and st.get(m).recs == st.get("c").recs and not(heldBy(st.get(m)).contains(5))) and promises)

  // (Void under LAST_ROOT_ONLY: the ids of the change's records assume no re-issued Ys.)
  run waitedRecordDecidedTest = if (LAST_ROOT_ONLY) init else init
      .then(offerEveryone(3))
      .then(compactAt("a"))
      .then(signFull("R", "checkpoint", "", "", 0, false, false, 2, false, Set(2)))
      .then(recoverAs(RECOVERY, "NK"))
      .then(signChain(RECOVERY, "recover", "R", 2, "nocp"))
      .then(offerEveryone(7))
      .then(sign("C", "copies", "", "", 0, false, false, 1))
      .then(offerEveryone(8))
      .then(offerEveryone(8))
      .then(sign("R", "revoke", "K", "", 0, false, false, 1))
      .then(offerEveryone(9))
      .then(signW("R", "revoke", "A", "", 0, false, false, 1))
      .then(sign("A", "freeze", "W", "", 0, true, false, 1))
      .then(sign("NK", "copies", "", "", 0, false, false, 2))
      .then(sign("A", "thaw", "", "", 11, false, false, 1))
      .then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(signW("A", "copies", "", "", 0, true, false, 2))
      .then(offerEveryone(13))
      .then(sign("C", "copies", "", "", 0, false, false, 1))
      .then(signW("A", "copies", "", "", 0, true, false, 2))
      .then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(offerEveryone(18))
      .then(signFull("NK", "checkpoint", "", "", 0, false, false, 2, false, Set(18)))
      .then(sign("NK", "copies", "", "", 0, false, false, 1))
      .then(compactAt("m"))
      .then(give("a", 6))
      .then(offerEveryone(20))
      .then(offerEveryone(20))
      .then(compactAt("c"))
      .then(syncAll)
      .expect(promises)

  run waitingNewerDecidedTest =
    init
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(signW(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(give("m", 6))
      .expect(st.get("m").recs.contains(6) and views.get("m").checkpoint == 0)
      .then(give("m", 8))
      .expect(st.get("m").recs.contains(8) and views.get("m").checkpoint == 0)
      .then(give("m", 4))
      .then(give("m", 5))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 8) and promises)

  run followsReplayDecidedTest = init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
      .then(restart("a"))
      .then(if (CUT_MODE == "gapless") signDeviant(PHONE, "copies", "", 2) else signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(syncRound).then(syncRound)
      .then(giveAll(MEMBERS, [5, 8])).then(syncRound)
      .expect(CUT_MODE != "follows" or MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 6, 7, 9, 10, 11)
        and convergesAt(m)) and promises)

  run restartSplitDecidedTest = init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
      .then(restart("a"))
      .then(if (CUT_MODE == "gapless") signDeviant(PHONE, "copies", "", 2) else signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => syncedProto(m)) and
        if (CUT_MODE == "gapless") MEMBERS.forall(m => not(st.get(m).recs.contains(11)) and convergesAt(m))
        else if (CUT_MODE == "follows") MEMBERS.forall(m => st.get(m).recs == Set(1, 2, 3, 4, 6, 7, 9, 10, 11) and convergesAt(m))
        // RESTART_REOFFERS: the restarted a, offered again what it got, builds the same marks,
        // so it turns 11 away like the others: no split.
        else if (RESTART_REOFFERS and CUT_MODE != "none") MEMBERS.forall(m => not(st.get(m).recs.contains(11)) and convergesAt(m))
        else st.get("a").recs.contains(11)
          and (CUT_MODE == "none" or (not(st.get("m").recs.contains(11)) and not(convergesAt("m")))))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound).then(syncRound).then(syncRound)
      // Under "gapless" the root's head for A stays at 4 (no member holds A's 5), so 11 still
      // follows a gap: A stays mute, alike everywhere.
      // (With RESTART_REOFFERS nobody kept 11, so it is gone for good, alike everywhere.)
      .expect(MEMBERS.forall(m => st.get(m).recs.contains(11) == (CUT_MODE != "gapless" and not(RESTART_REOFFERS and CUT_MODE != "none"))
        and views.get(m).checkpoint == 12
        and convergesAt(m)))

  run foldListDecidedTest =
    init
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(sign("NA", "revoke", DEVICE, "", 0, false, false, 1)).then(giveOnly("k", 7))
      .then(recoverAs(RECOVERY, "NK"))
      .expect(promises)
      // a takes the change (holding R's 4, not NA's 7), c takes NA's 7 only.
      .then(giveOnly("a", 8)).then(giveOnly("a", 9)).then(giveOnly("c", 7))
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => if (LAST_ROOT_ONLY) not(views.get(m).devices.contains(DEVICE)) else views.get(m).revoked.contains(DEVICE)) and promises)
      .then(syncRound).then(compactAt("a")).then(compactAt("c")).then(syncRound).then(syncRound)
      .expect(MEMBERS.filter(m => inGroup(m)).forall(m => (if (LAST_ROOT_ONLY) not(views.get(m).devices.contains(DEVICE)) else views.get(m).revoked.contains(DEVICE)) and views.get(m) == views.get("r")
        and views.get(m).path == ["R", "NA", "NK"]) and promises)

  // (Void under ROOT_WAITS: the checkpoint settles a removal no admin has acked; W keeps it until every live admin acks (the settle path: wSh1, wSh2, wFrozenBlocks).)
  run prunedRemovalDecidedTest = if (ROOT_WAITS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .expect(MEMBERS.forall(m => views.get(m).revoked.contains(DEVICE)))
      .then(signAs(ROOT, "copies", "", 0))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(syncAll)
      .expect(db.get(7).keep.intersect(Set(4, 5)) == Set() and MEMBERS.forall(m => views.get(m).checkpoint == 7
        and not(st.get(m).recs.contains(4)) and not(st.get(m).recs.contains(5))
        and not(views.get(m).devices.contains(DEVICE))) and promises)
      .then(give("m", 4))
      .then(give("m", 5))
      .expect(not(st.get("m").recs.contains(4)) and not(st.get("m").recs.contains(5)) and promises)
      .then(signW(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(syncAll)
      .expect(promises)

  run rootKeepsBothDecidedTest =
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(signAs(ROOT, "revoke", DEVICE, 0))
      .then(syncAll)
      .then(signAs(ROOT, "copies", "", 0))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(give("a", 6)).then(give("a", 7)).then(give("c", 6)).then(give("c", 7)).then(give("m", 6)).then(give("m", 7))
      .then(signFullW(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set(4, 5)))
      .then(syncAll)
      .then(syncAll)
      .expect(promises)

  run restartAfterTwoChangesDecidedTest =
    init
      .then(sign(ROOT, "admin", "NA", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound)
      .then(sign("NA", "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "freeze", COMPUTER, "", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "thaw", "", "", 9, false, false, 1)).then(syncRound)
      .then(sign("NA", "checkpoint", "", "", 0, false, false, 2)).then(syncRound)
      .then(compactAt("a")).then(compactAt("c"))
      .then(recoverAs(RECOVERY, "NK")).then(syncRound)
      .then(sign("NK", "checkpoint", "", "", 0, false, false, 2)).then(syncRound)
      .then(compactAt("m")).then(syncRound)
      .expect(restartStable and promises)
      .then(restart("r")).then(restart("a")).then(restart("c")).then(restart("k")).then(restart("m"))
      .expect(promises)

  run honestShareFallsDecidedTest = init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2)).then(syncRound)
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(sign("X", "copies", "", "", 0, false, false, 2)).then(syncRound).then(syncRound)
      // (Under "gapless" and "follows" the level rises once the tails are dropped: X's
      // admission stays.)
      .expect(promises)

  // The place aside at the decided set (ADMINC 2): as asideBase, with 2-unit admin records
  // (one per admin fits its cap; the second and third come from a writer that skips its own
  // checks). Every member counts checkpoint 13.
  action asideBaseDecided =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(signW(WATCH, "copies", "", "", 0, false, false, 2))
      .then(signW(WATCH, "copies", "", "", 0, false, false, 2))
      .then(giveAll(MEMBERS, [4, 5, 6, 7, 8, 9, 10, 11, 12]))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound)
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("m")).then(compactAt("k"))
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 13 and st.get(m).recs == Set(1, 2, 3, 4, 7, 10, 13)))
  // asideFullTest at the decided set: 15 (never whole) keeps the third records at 7 units each,
  // past every admin's cap. The rooms turn them away before anything goes aside, so m, which
  // gets 15 first, counts 14 at once (nothing waits) and every member ends at 14.
  // (The overflow of the place aside itself needs two waiting checkpoints naming in-cap records
  // past ASIDE_ROOM together; not covered here.)
  run asideFullDecidedTest =
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signW(PHONE, "copies", "", "", 0, false, false, 2))
      .then(signW(PHONE, "copies", "", "", 0, false, false, 7))
      .then(sign(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 2))
      .then(signW(COMPUTER, "copies", "", "", 0, false, false, 7))
      .then(sign(WATCH, "copies", "", "", 0, false, false, 2))
      .then(signW(WATCH, "copies", "", "", 0, false, false, 2))
      .then(signW(WATCH, "copies", "", "", 0, false, false, 7))
      .then(giveAll(MEMBERS, [4, 5, 6, 7, 8, 9, 10, 11, 12]))
      .then(signFull(ROOT, "checkpoint", "", "", 0, false, false, 1, false, Set()))
      .then(syncRound)
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("m")).then(compactAt("k"))
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 13 and st.get(m).recs == Set(1, 2, 3, 4, 7, 10, 13)))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 5, 8, 11), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6, 9, 12, NEVER), "", 1))
      .then(giveAll(Set("a"), [14, 5, 8, 11]))
      .then(giveAll(Set("m"), [15, 6, 9, 12, 14, 5, 8, 11]))
      .expect(views.get("m").checkpoint == 14 and st.get("m").wait == Set())
      .then(syncRound).then(syncRound).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 14 and convergesAt(m)) and promises)
  // olderWaitingTurnedAwayTest at the decided set: 15 keeps one record; the place aside has
  // room, 14 is not turned away, and every member counts 14 (ASIDE_TAKES_WAITED).
  run olderWaitingTurnedAwayDecidedTest = asideBaseDecided
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 5, 8), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6, NEVER), "", 1))
      .then(giveAll(Set("a"), [14, 5, 8]))
      .then(giveAll(Set("m"), [15, 6, 14, 5, 8]))
      .then(syncRound).then(syncRound).then(syncRound).then(syncRound)
      .expect(and { asideFits("m"), not(newestWholeable("m")),
        if (ASIDE_TAKES_WAITED) MEMBERS.forall(m => views.get(m).checkpoint == 14 and convergesAt(m))
        else views.get("m").checkpoint == 13 and not(convergesAt("m")),
        promises })
  // oneSlotTest at the decided set (one slot is not decided): m gets 15 first, every member
  // ends at 14.
  run oneSlotDecidedTest = asideBaseDecided
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 5, 8), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6, NEVER), "", 1))
      .expect(MEMBERS.forall(m => views.get(m).checkpoint == 13
        and st.get(m).recs == Set(1, 2, 3, 4, 7, 10, 13).union(if (m == "r") Set(14, 15) else Set())))
      .then(giveAll(Set("a"), [14, 5, 8]))
      .then(giveAll(Set("m"), [15, 6, 14, 5, 8]))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(and { views.get("a").checkpoint == 14, syncedProto("m"),
        if (ONE_SLOT or not(ASIDE_TAKES_WAITED)) views.get("m").checkpoint == 13 and not(convergesAt("m"))
        else MEMBERS.forall(m => views.get(m).checkpoint == 14 and convergesAt(m)) and promises })
  // missingNewestTest at the decided set: 14's records wait aside on a (5) and c (8), whole
  // nowhere; missing() brings them and every member counts 14.
  run missingNewestDecidedTest = asideBaseDecided
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 5, 8), "", 1))
      .then(signCheckpointKeep(ROOT, Set(1, 2, 3, 6, NEVER), "", 1))
      .then(giveAll(Set("a"), [15, 14, 5]))
      .then(giveAll(Set("c"), [15, 14, 8]))
      .then(giveAll(Set("m"), [15, 14]))
      .expect(not(CEIL_FIT) or st.get("a").wait.contains(5) and st.get("c").wait.contains(8) and views.get("m").checkpoint == 13)
      .then(syncRound).then(syncRound).then(syncRound)
      // (The sizes are the decided set's; at others the shape differs and missingNewestTest covers it.)
      .expect(not(CEIL_FIT) or and { syncedProto("m") or not(ASIDE_TAKES_WAITED),
        if (not(ASIDE_TAKES_WAITED)) views.get("m").checkpoint == 13
        else if (MISSING_NEWEST_ONLY or ONE_SLOT) views.get("m").checkpoint == 13 and not(convergesAt("m"))
        else MEMBERS.forall(m => views.get(m).checkpoint == 14 and convergesAt(m)) and promises })

  // Candidate E (architecture 11-14 16:50Z, found by the exhaustive check on the honest writer):
  // A admits D (4) and signs on (5); C admits D too (6), a record the root never holds. The
  // root removes D (7), signs on (8) and checkpoints (9): CP_KEEP drops the removal with A's
  // admission (D is a settled plain device). C's 6 then arrives, above C's head (the root named
  // none for C), and D counts again everywhere. removedStayOut catches it at r, which counted
  // the removal (6 was signed before 7, so no later admission excuses it). With DROPS_EPOCH, 9
  // carries drops 1, 6 epoch 0, and no list keeps 6: D stays out and the promises hold.
  // (FRESH_KEY: C's second admission of D is never signed.)
  // (ROOT_WAITS: wAdminsTwiceTest.)
  run droppedRemovalLateAdmissionTest = if (FRESH_KEY or ROOT_WAITS) init else
    init
      .then(sign("A", "device", "D", "", 0, false, false, 1))
      .then(sign("A", "copies", "", "", 0, false, false, 1))
      .then(sign("C", "device", "D", "", 0, false, false, 1))
      .then(giveAll(Set("r", "c", "m", "k"), [4, 5]))
      .then(sign("R", "revoke", "D", "", 0, false, false, 1))
      .then(sign("R", "copies", "", "", 0, false, false, 1))
      .then(signAs("R", "checkpoint", "", 0))
      .expect(not(CP_KEEP) or (not(db.get(9).keep.contains(4)) and not(db.get(9).keep.contains(7))))
      .then(giveAll(Set("a", "c", "m", "k"), [7, 8, 9]))
      .then(compactAt("m"))
      .then(giveAll(MEMBERS, [6]))
      .then(syncRound).then(syncRound)
      .expect(if (DROPS_EPOCH) MEMBERS.forall(m => not(views.get(m).devices.contains(DEVICE))) and promises
        else if (CP_KEEP) MEMBERS.forall(m => views.get(m).devices.contains(DEVICE)) and not(removedStayOut)
        else true)

  // FLAG and FRESH_KEY, the 2x2 (architecture 11-14 20:46Z, E off). Shapes sh1 and sh2 of the
  // exhaustive check (traces-1514): A truly admits D without holding R's admission 4; R
  // removes D, and its checkpoint prunes the removal with R's admission. A's admission then
  // counts and D is back: the kept gap, which the flag does not close. Under FRESH_KEY A's
  // admission is never signed (D's key was offered once), so these runs start nothing there.
  run flagGapSh1Test = if (FRESH_KEY or ROOT_WAITS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(sign("A", "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(5).flag == 0 and not(db.get(8).keep.contains(4)) and not(db.get(8).keep.contains(6)))
      .then(giveAll(MEMBERS, [4, 6, 7, 8])).then(giveAll(MEMBERS, [5]))
      .then(syncRound).then(syncRound)
      .expect(not(CP_KEEP) or DROPS_EPOCH or (MEMBERS.forall(m => views.get(m).devices.contains(DEVICE)) and not(removedStayOut)))
  run flagGapSh2Test = if (FRESH_KEY or ROOT_WAITS) init else
    init
      .then(sign("A", "copies", "", "", 0, false, false, 1))
      .then(giveAll(Set("r"), [4]))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .then(sign("A", "device", DEVICE, "", 0, false, false, 1))
      .expect(db.get(9).flag == 0)
      .then(giveAll(MEMBERS, [4, 5, 6, 7, 8])).then(giveAll(MEMBERS, [9]))
      .then(syncRound).then(syncRound)
      // (A's 9 is signed after R's removal 6, so removedStayOut reads it as a new admission and
      // holds; D is back all the same.)
      .expect(not(CP_KEEP) or DROPS_EPOCH or MEMBERS.forall(m => views.get(m).devices.contains(DEVICE)))
  // The shape the flag is for: A holds R's admission 4 when it signs D's record 5 (it narrows
  // D, an update), never delivered to R. R removes D and its checkpoint prunes the removal with
  // its admission; 5 arrives. Without the flag 5 is read as the first admission and D is back;
  // with it 5 is an update with no admission under it, and D stays out.
  run flagNarrowTest = if (ROOT_WAITS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(giveAll(Set("a"), [4]))
      .then(sign("A", "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect((db.get(5).flag == 1) == FLAG and not(db.get(8).keep.contains(4)) and not(db.get(8).keep.contains(6)))
      .then(giveAll(MEMBERS, [4, 6, 7, 8])).then(giveAll(MEMBERS, [5]))
      .then(syncRound).then(syncRound)
      .expect(if (FLAG) MEMBERS.forall(m => not(views.get(m).devices.contains(DEVICE))) and promises
        else not(CP_KEEP) or DROPS_EPOCH or (MEMBERS.forall(m => views.get(m).devices.contains(DEVICE)) and not(removedStayOut)))

  // ROOT_WAITS (candidate W), each run only under it. dOut: no member counts D, promises hold.
  // (The directed W runs need the real root ratio and wider admin rooms; see wScaledTakeBackTest.)
  pure val wideW = ROOT_RATIO and WIDE_ADMIN
  val dOutL = MEMBERS.exclude(Set("m")).forall(m => not(views.get(m).devices.contains(DEVICE))) and promises
  val dOut = MEMBERS.forall(m => not(views.get(m).devices.contains(DEVICE))) and promises
  action acksAll = sign(PHONE, "ack", "", "", 0, false, false, 1)
    .then(sign(COMPUTER, "ack", "", "", 0, false, false, 1)).then(sign(WATCH, "ack", "", "", 0, false, false, 1))
  // sh1 under W: R's checkpoint 8 keeps the removal 6 (no admin acked it), so A's true
  // admission 5 arriving late changes nothing. After the three acks (A's line carries 5) the
  // checkpoint 13 settles the removal; 5 lies below A's head there and is gone with it.
  run wSh1Test = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(8).keep.contains(6) and db.get(8).keep.contains(4))
      .then(giveAll(MEMBERS, [4, 6, 7, 8])).then(giveAll(MEMBERS, [5]))
      .then(syncRound).then(syncRound)
      .expect(dOut)
      .then(acksAll).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(13).kind == "checkpoint" and not(db.get(13).keep.contains(6)) and not(db.get(13).keep.contains(4))
        and not(db.get(13).keep.contains(5)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // sh2 under W: A admits D (9) after R's checkpoint 8, which kept the removal; the removal
  // still counts, and after the acks the settling checkpoint prunes 9 below A's head.
  run wSh2Test = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1))
      .then(giveAll(Set("r"), [4]))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(8).keep.contains(6))
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1))
      .then(giveAll(MEMBERS, [4, 5, 6, 7, 8])).then(giveAll(MEMBERS, [9]))
      .then(syncRound).then(syncRound)
      .expect(dOut)
      .then(acksAll).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(14).kind == "checkpoint" and not(db.get(14).keep.contains(6)) and not(db.get(14).keep.contains(9)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // The narrowing update under W: A holds R's admission 4 when it signs 5; R's checkpoint keeps
  // the removal until every admin acked; 5 never brings D back.
  run wNarrowTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(giveAll(Set("a"), [4]))
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(8).keep.contains(6))
      .then(giveAll(MEMBERS, [4, 6, 7, 8])).then(giveAll(MEMBERS, [5]))
      .then(syncRound).then(syncRound)
      .expect(dOut)
      .then(acksAll).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(13).keep.contains(6)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // E's shape under W: A and C both truly admit D; the root never holds C's 6 until C's ack
  // carries it. Checkpoint 9 keeps the removal; the settling checkpoint 14 prunes 4 and 6.
  run wAdminsTwiceTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(PHONE, "copies", "", "", 0, false, false, 1))
      .then(sign(COMPUTER, "device", DEVICE, "", 0, false, false, 1))
      .then(giveAll(Set("r", "c", "m", "k"), [4, 5]))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(9).keep.contains(7))
      .then(giveAll(Set("a", "c", "m", "k"), [7, 8, 9]))
      .then(compactAt("m"))
      .then(giveAll(MEMBERS, [6]))
      .then(syncRound).then(syncRound)
      .expect(dOut)
      .then(acksAll).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(14).kind == "checkpoint" and not(db.get(14).keep.contains(7)) and not(db.get(14).keep.contains(4))
        and not(db.get(14).keep.contains(6)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // A change of root after the acks: the acks hold R's head, not NA's; NA's re-issued removal
  // of D (a Z) waits for new acks; D stays out throughout.
  def lastCpKeep(k: Key): Set[Id] = {
    val c = db.keys().filter(i => db.get(i).signer == k and db.get(i).kind == "checkpoint").fold(0, (m, i) => max2(m, i))
    if (c == 0) Set() else db.get(c).keep
  }
  def keepsRemovalOfD(k: Key): bool = lastCpKeep(k).exists(i => db.get(i).kind == "revoke" and tgt(db.get(i)).contains(DEVICE))
  run wChangeRootTest = if (not(ROOT_WAITS) or not(wideW) or LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(acksAll).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NA"]) and dOut)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs("NA", "checkpoint", "", 0))
      .expect(keepsRemovalOfD("NA"))
      .then(syncRound).then(syncRound).expect(dOut)
      // (The decided rule itself never settles a Z in this shape, W or not: NA keeps it.)
      .then(acksAll).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs("NA", "checkpoint", "", 0))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // W at the scaled rooms (no widening; run it on decided + ROOT_WAITS): R removes D, A and C
  // ack, W lags. The checkpoint that keeps the removal does not fit R's room, so the honest
  // root cannot sign it; it takes W back (9) and its checkpoint (10) settles and fits.
  run wScaledTakeBackTest = if (not(ROOT_WAITS) or ROOT_RATIO or WIDE_ROOT) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(sign(COMPUTER, "ack", "", "", 0, false, false, 1))
      .then(syncRound)
      .expect(sumUnits(ofKey(recsOf(st.get("r").recs, db), ROOT)) + CP_UNITS > ROOTC)
      .then(sign(ROOT, "device", "dW", "", 0, false, false, 1)).then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(9).kind == "checkpoint" and not(db.get(9).keep.contains(5)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // An admin always fits one more ack at the scaled rooms: three acks of A (ADMINC 2), the
  // root's checkpoints between them leave out the superseded one.
  run wAckFitsTest = if (not(ROOT_WAITS)) init else
    init
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0)).then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0)).then(syncRound).then(compactAt("a")).then(syncRound)
      .expect(not(db.get(7).keep.contains(4)))
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0)).then(syncRound).then(compactAt("a")).then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(syncRound)
      .expect(promises)
  // A deviant root grants admin again to W after taking it back: W's record 4, cut off by the
  // take-back, counts again once offered (a stated limit; the honest writer refuses it).
  run wRegrantLimitTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(WATCH, "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "device", "dW", "", 0, false, false, 1)).then(syncRound)
      .expect(MEMBERS.forall(m => not(views.get(m).counting.contains(4))))
      // (The honest writer's guard refuses the re-grant on R's set.)
      .expect(regrant(recsOf(st.get("r").recs, db), WATCH))
      .then(signFullX(ROOT, "admin", WATCH, "deviant", 0, false, false, 1, false, Set(), false)).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).admins.keys().contains(WATCH)))
      // (The sets dropped 4 at the take-back; anyone who kept it offers it again.)
      .then(giveAll(MEMBERS, [4])).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).counting.contains(4)))
  // A root twin around the settle: 10, R's checkpoint, settles the removal after all acks; 11,
  // a copies record at 10's seq, does not. A member that gets both, in either order, halts, and
  // the two orders give one state; D counts nowhere.
  run wTwinSettleTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(acksAll).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(10).keep.contains(5)))
      .then(signFull(ROOT, "copies", "", "", 0, false, true, 1, true, Set()))
      .expect(db.get(11).seq == db.get(10).seq)
      .then(giveAll(Set("m"), [9, 10])).then(giveAll(Set("c"), [9, 11]))
      .then(giveAll(Set("m"), [11])).then(giveAll(Set("c"), [10]))
      .expect(views.get("m").stop and views.get("c").stop and views.get("m").devices == views.get("c").devices
        and not(views.get("m").devices.contains(DEVICE)))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => not(views.get(m).devices.contains(DEVICE))) and promises)
  // A change of root while a removal waits: W never acked R's removal 5; the change to NA
  // writes NA's first checkpoint, which keeps the re-issued removal; D stays out.
  run wChangeWaitingTest = if (not(ROOT_WAITS) or not(wideW) or LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(sign(COMPUTER, "ack", "", "", 0, false, false, 1))
      .then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NA"]) and keepsRemovalOfD("NA") and dOut)
      .then(sign(WATCH, "ack", "", "", 0, false, false, 1)).then(syncRound).then(syncRound)
      .expect(dOut)
  // An admin named after the removal is live at the settle and must ack too: R names X (8)
  // after the acks; the checkpoint keeps the removal until X acks.
  run wNamedAfterTest = if (not(ROOT_WAITS) or not(wideW) or GRANT_ABOVE) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(acksAll).then(syncRound)
      .then(sign(ROOT, "admin", "X", "phone", 0, false, false, 1)).then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(10).keep.contains(5))
      .then(syncRound)
      .then(sign("X", "ack", "", "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(13).keep.contains(5)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // A lagging admin: W never acks. R checkpoints first (8 keeps the removal), takes W back
  // (9, a root device record of W's device), and its next checkpoint settles the removal.
  run wLagTakeBackTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(sign(COMPUTER, "ack", "", "", 0, false, false, 1))
      .then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(8).keep.contains(5))
      .then(syncRound)
      .then(sign(ROOT, "device", "dW", "", 0, false, false, 1)).then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(10).keep.contains(5)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut and MEMBERS.forall(m => not(views.get(m).admins.keys().contains(WATCH))))
  // An admin removed between the acks and the settle: R removes W (9) after the acks; W is
  // not live, the others acked, and the checkpoint settles.
  run wAdminRemovedTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(sign(COMPUTER, "ack", "", "", 0, false, false, 1))
      .then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(8).keep.contains(5))
      .then(syncRound)
      .then(sign(ROOT, "revoke", WATCH, "", 0, false, false, 1)).then(syncRound)
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(10).keep.contains(5)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)
  // A record in flight: A admits D (6) holding nothing of R's removal, then gets 4 and 5 and
  // acks (7). The root gets only 7: it does not count it without 6 below it on A's line, so its
  // checkpoint keeps the removal; 6 then arrives and D stays out; after it the root settles.
  run wInFlightTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(PHONE, "device", DEVICE, "", 0, false, false, 1))
      .then(giveAll(Set("a"), [4, 5]))
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1))
      .then(giveAll(Set("c", "m", "k"), [4, 5])).then(giveAll(Set("r"), [7]))
      .then(sign(COMPUTER, "ack", "", "", 0, false, false, 1)).then(sign(WATCH, "ack", "", "", 0, false, false, 1))
      .then(giveAll(Set("r"), [8, 9]))
      .expect(not(views.get("r").counting.contains(7)))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(10).keep.contains(5))
      .then(giveAll(MEMBERS, [4, 5, 7, 8, 9, 10])).then(giveAll(MEMBERS, [6]))
      .then(syncRound).then(syncRound)
      .expect(dOut and views.get("r").counting.contains(7))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(12).keep.contains(5)) and not(db.get(12).keep.contains(6)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut)

  // LAST_ROOT_ONLY (candidate L), on decided + ROOT_WAITS + REISSUE_STATE (+ROOT_RATIO,
  // WIDE_ADMIN for room). The recovery record of the newest change.
  def recId: int = db.keys().filter(i => db.get(i).kind == "recover").fold(0, (m, i) => max2(m, i))
  def firstOfChange: int = if (recId == 0) 0 else db.get(recId).first
  pure val onL = LAST_ROOT_ONLY and ROOT_WAITS and REISSUE_STATE and wideW
  // 1. An old admin's admission (5) and removal (6) and the old root's grant (7) reach no one
  // before the change; after it nothing of them counts: E out, D (re-issued) in, no admins.
  run lLateOldTest = if (not(onL) or KEPT_ADMINS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "device", "E", "", 0, false, false, 1))
      .then(sign(PHONE, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "admin", MINTED, "phone", 0, false, false, 1))
      .expect(not(st.get("k").got.contains(5)) and not(st.get("k").got.contains(7)))
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NA"] and views.get(m).devices.contains(DEVICE)
        and not(views.get(m).devices.contains("E")) and views.get(m).admins.keys() == Set()
        and not(views.get(m).revoked.contains(DEVICE))) and promises)
  // 2. A member that holds the change but only part of the re-issue stays on R and counts R's
  // group, whole; with all of it it moves to NA. Never empty, never mixed.
  run lHalfReissueTest = if (not(onL) or KEPT_ADMINS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA"))
      .then(giveAll(Set("m"), [recId]))
      .expect(views.get("m").path == [ROOT] and views.get("m").devices == Set("dA", "dC", "dW", DEVICE)
        and views.get("m").admins.keys() == Set(PHONE, COMPUTER, WATCH))
      .then(giveAll(Set("m"), range(recId + 1, recId + 3)))
      .expect(views.get("m").path == [ROOT] and views.get("m").devices == Set("dA", "dC", "dW", DEVICE)
        and views.get("m").admins.keys() == Set(PHONE, COMPUTER, WATCH))
      .then(giveAll(Set("m"), range(recId + 3, firstOfChange + 1)))
      .expect(views.get("m").path == [ROOT, "NA"] and views.get("m").devices == Set("dA", "dC", "dW", DEVICE)
        and views.get("m").admins.keys() == Set())
      .then(syncRound).then(syncRound)
      .expect(promises)
  // 3. A second change before the first re-issue spread.
  run lSecondChangeTest = if (not(onL)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA"))
      .then(recoverAs(RECOVERY, "NK"))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NA", "NK"] and views.get(m).devices.contains(DEVICE)
        and views.get(m).admins.keys() == Set()) and promises)
  // 4. A change while W lags on R's removal of D: D is not re-issued, so it is out; W's late
  // ack changes nothing.
  run lChangeWaitingTest = if (not(onL) or KEPT_ADMINS) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(sign(COMPUTER, "ack", "", "", 0, false, false, 1))
      .then(syncRound)
      // (W's ack, signed late, reaches the others only after the change; after it W's key is
      // nothing and its writer cannot sign at all.)
      .then(sign(WATCH, "ack", "", "", 0, false, false, 1))
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NA"]) and dOut
        and MEMBERS.forall(m => views.get(m).admins.keys() == Set()))
  // 5. A twin of the new root right after the change: who holds both halts, one state.
  run lNewRootTwinTest = if (not(onL)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(signFull("NA", "copies", "", "", 0, false, true, 1, true, Set()))
      .then(syncRound).then(giveAll(MEMBERS, [nextId - 1])).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).stop) and promises)
  // 6. A device the new root did not re-issue (R removed it) is out, and joins again with
  // the same key by the new root's admission.
  run lRejoinTest = if (not(onL)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .expect(dOut)
      .then(sign("NA", "device", DEVICE, "", 0, false, false, 1)).then(syncRound).then(syncRound)
      // (m, the model's device admitted outside the records, is not re-issued either: no peer
      // hands it anything after the change; it is not D's member.)
      .expect(MEMBERS.exclude(Set("m")).forall(m => views.get(m).devices.contains(DEVICE)))
      .expect(promises)

  // KEPT_ADMINS under L: C's device is kept as admin C2. 1: after the change every member
  // counts C2 as the only admin and dC as a device; C's record E, signed under the old key
  // before the change and delivered after, counts for nothing; C2 admits E2.
  run kaFreshKeyTest = if (not(onL and KEPT_ADMINS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(COMPUTER, "device", "E", "", 0, false, false, 1))
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NA"] and views.get(m).admins.keys() == Set("C2")
        and Set("dA", "dC", "dW", DEVICE).subseteq(views.get(m).devices) and not(views.get(m).devices.contains("E")))
        and promises)
      .then(sign("C2", "device", "E2", "", 0, false, false, 1)).then(syncRound).then(syncRound)
      // (m, the outside device no record admits, is out after the change under L: peers hand it
      // nothing, as in lRejoinTest.)
      .expect(MEMBERS.exclude(Set("m")).forall(m => views.get(m).devices.contains("E2")) and promises)
  // 2: with the head and part of the re-issue a member still counts R's group whole.
  run kaHalfTest = if (not(onL and KEPT_ADMINS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA"))
      .then(giveAll(Set("m"), [recId])).then(giveAll(Set("m"), range(recId + 1, recId + 3)))
      .expect(views.get("m").path == [ROOT] and views.get("m").admins.keys() == Set(PHONE, COMPUTER, WATCH)
        and views.get("m").devices == Set("dA", "dC", "dW", DEVICE))
      .then(giveAll(Set("m"), range(recId + 3, firstOfChange + 1)))
      .expect(views.get("m").path == [ROOT, "NA"] and views.get("m").admins.keys() == Set("C2")
        and views.get("m").devices == Set("dA", "dC", "dW", DEVICE))
  // 3 (W): NA removes D; its checkpoint keeps the removal until C2 acks, then settles it.
  run kaWaitTest = if (not(onL and KEPT_ADMINS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(sign("NA", "revoke", DEVICE, "", 0, false, false, 1)).then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(syncRound).then(signAs("NA", "checkpoint", "", 0))
      .expect(keepsRemovalOfD("NA"))
      .then(syncRound).expect(dOutL)
      .then(sign("C2", "ack", "", "", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs("NA", "checkpoint", "", 0))
      .expect(not(keepsRemovalOfD("NA")))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOutL)

  // GRANT_ABOVE (on W). X, named by R above R's removal 5, is not waited for; A, C, W are.
  run gaAboveTest = if (not(ROOT_WAITS and GRANT_ABOVE and wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(acksAll).then(syncRound)
      .then(sign(ROOT, "admin", MINTED, "phone", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(11).keep.contains(5)) and grantHoldsRemoval)
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut and grantHoldsRemoval)
  // Two admins, one below and one above: A (below) has not acked, so 5 waits though X (above)
  // never acks; after A's ack it settles.
  run gaBelowAboveTest = if (not(ROOT_WAITS and GRANT_ABOVE and wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(COMPUTER, "ack", "", "", 0, false, false, 1)).then(sign(WATCH, "ack", "", "", 0, false, false, 1))
      .then(sign(ROOT, "admin", MINTED, "phone", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(10).keep.contains(5))
      .then(syncRound)
      .then(sign(PHONE, "ack", "", "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(13).keep.contains(5)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOut and grantHoldsRemoval)
  // The grant through a checkpoint: X's holder a gets only R's checkpoint 9 (which keeps the
  // grant 6 and the removal 5) and compacts on it; it holds the removal with the grant.
  run gaThroughCpTest = if (not(ROOT_WAITS and GRANT_ABOVE and wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(giveAll(Set("a", "c", "k", "m"), [4]))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "admin", MINTED, "phone", 0, false, false, 1))
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1))
      .then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(8).keep.contains(5) and db.get(8).keep.contains(6))
      .then(giveAll(Set("a"), [8])).then(compactAt("a"))
      .expect(grantHoldsRemoval)
      .then(giveAll(Set("a"), [6])).expect(grantHoldsRemoval)
      .then(giveAll(Set("a"), [5, 7])).expect(grantHoldsRemoval)
      .then(sign(MINTED, "device", DEVICE, "", 0, false, false, 1))
      .then(syncRound).then(syncRound)
      .expect(grantHoldsRemoval and promises)
  // A device whose old key C was taken back (5), R removes D (6), then names its new key C2
  // above (7). c, which still holds the old state where D counts, gets only 7.
  run gaNewKeyTest = if (not(ROOT_WAITS and GRANT_ABOVE and wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "device", "dC", "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1))
      .then(sign(ROOT, "admin", "C2", "computer", 0, false, false, 1))
      .then(giveAll(Set("c"), [7]))
      .expect(grantHoldsRemoval)
      .then(giveAll(Set("c"), [5])).expect(grantHoldsRemoval)
      .then(giveAll(Set("c"), [6])).expect(grantHoldsRemoval)
      .then(syncRound).then(syncRound)
      .then(sign("C2", "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .expect(grantHoldsRemoval and promises)

  // SPARE (candidate S) under L, W, REISSUE_STATE (+ sizes). A and C ack under R with spares
  // A1 and C2; W never acks. The sleeper is c (C's device; NA's holder is a).
  pure val onS = onL and SPARE
  val notM = MEMBERS.exclude(Set("m"))
  pure val AWAKE = Set("r", "a", "k", "m")
  action spareStart = init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(ackS(PHONE)).then(ackS(COMPUTER)).then(syncRound)
  // 1. Asleep through one change, then wakes: A1 and C2 are the admins everywhere; C2 acks
  // (spare C3) and admits E.
  run sAsleepOneTest = if (not(onS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA"))
      .then(giveAll(AWAKE, range(recId, firstOfChange + 1)))
      .expect(Set("r", "a", "k").forall(m => views.get(m).path == [ROOT, "NA"] and views.get(m).admins.keys() == Set("A1", "C2"))
        and views.get("c").path == [ROOT])
      .then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).admins.keys() == Set("A1", "C2")) and spareSafe)
      .then(ackS("C2")).then(sign("C2", "device", "E", "", 0, false, false, 1)).then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains("E")) and promises and spareSafe)
  // 2. Asleep through two changes: C2 never acked under NA, so NK keeps A (as A2, from A1's
  // ack under NA) but not C; C2 counts for nothing when c wakes.
  run sAsleepTwoTest = if (not(onS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA"))
      .then(giveAll(AWAKE, range(recId, firstOfChange + 1)))
      .then(ackS("A1"))
      .then(giveAll(AWAKE, [nextId - 1]))
      .then(recoverAs(RECOVERY, "NK"))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).path == [ROOT, "NA", "NK"] and views.get(m).admins.keys() == Set("A2"))
        and promises and spareSafe)
  // 3. A second change before the first spread: no ack counts under NA, so NK keeps no admins.
  run sSecondChangeTest = if (not(onS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA")).then(recoverAs(RECOVERY, "NK"))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).path == [ROOT, "NA", "NK"] and views.get(m).admins.keys() == Set())
        and promises and spareSafe)
  // 4. A stale ack at the writer: C2 acks under NA (spare C3), but k never gets it; k holds
  // only C's ack under R, which does not count under NA: NK does not keep C.
  run sStaleAckTest = if (not(onS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(ackS("C2"))
      .then(recoverAs(RECOVERY, "NK"))
      .then(syncRound).then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).path == [ROOT, "NA", "NK"] and not(views.get(m).admins.keys().contains("C3"))
        and not(views.get(m).admins.keys().contains("C2"))) and promises and spareSafe)
  // 5. A deviant pre-signs with its spare A1 (E, 5, before the naming); after the naming 5 is
  // offered to everyone again. Without SEEN_HOLDS_ROOT E counts (spareSafe breaks); with it
  // E counts nowhere.
  run sPresignTest = if (not(onS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(signDeviant("A1", "device", "E", 1))
      .then(ackS(PHONE)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(giveAll(MEMBERS, [5])).then(syncRound)
      .expect(notM.forall(m => views.get(m).admins.keys().contains("A1")))
      .expect(if (SEEN_HOLDS_ROOT or SEEN_POS) notM.forall(m => not(views.get(m).devices.contains("E"))) and spareSafe
        else notM.forall(m => views.get(m).devices.contains("E")) and not(spareSafe))
  // 6. NA removes D while the kept C2 has not shown up (c asleep; A1 acked): the removal
  // waits; NA takes C2 back (a root device record of dC; the 35-day step is the same) and then
  // settles.
  run sTakeBackTest = if (not(onS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA"))
      .then(giveAll(AWAKE, range(recId, firstOfChange + 1)))
      .then(sign("NA", "revoke", DEVICE, "", 0, false, false, 1)).then(sign("NA", "copies", "", "", 0, false, false, 1))
      .then(giveAll(AWAKE, [nextId - 2, nextId - 1]))
      .then(ackS("A1")).then(giveAll(AWAKE, [nextId - 1]))
      .then(signAs("NA", "checkpoint", "", 0))
      .expect(keepsRemovalOfD("NA"))
      .then(giveAll(AWAKE, [nextId - 1]))
      .then(sign("NA", "device", "dC", "", 0, false, false, 1)).then(giveAll(AWAKE, [nextId - 1]))
      .then(signAs("NA", "checkpoint", "", 0))
      .expect(not(keepsRemovalOfD("NA")))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(syncRound)
      .expect(dOutL and spareSafe)

  // SEEN_POS under S. 1: the deviant spare A1 pre-signs a removal of D (5) and a freeze of C
  // (6) as its first records; A acks (spare A1) and the change names A1 (and C2). Offered after
  // the naming, nothing of them counts, also after A1's honest ack above them.
  run posPresignTest = if (not(onS and SEEN_POS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(signDeviant("A1", "revoke", DEVICE, 1)).then(signDeviant("A1", "freeze", "C2", 1))
      .then(ackS(PHONE)).then(ackS(COMPUTER)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(giveAll(MEMBERS, [5, 6])).then(syncRound)
      .expect(notM.forall(m => views.get(m).admins.keys() == Set("A1", "C2") and views.get(m).devices.contains(DEVICE)
        and not(views.get(m).frozen.contains("C2"))) and spareSafe)
      .then(ackS("A1")).then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains(DEVICE) and not(views.get(m).frozen.contains("C2"))
        and not(views.get(m).counting.contains(5)) and not(views.get(m).counting.contains(6))) and spareSafe and promises)
  // 2. The void records take no part in later records' room: A1 acks, admits E and the root's
  // checkpoint keeps neither 5 nor 6; after compaction the sets drop them, and E counts.
  run posRoomTest = if (not(onS and SEEN_POS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(signDeviant("A1", "revoke", DEVICE, 1)).then(signDeviant("A1", "freeze", "C2", 1))
      .then(ackS(PHONE)).then(ackS(COMPUTER)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(giveAll(MEMBERS, [5, 6])).then(syncRound)
      .then(ackS("A1")).then(sign("A1", "device", "E", "", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs("NA", "checkpoint", "", 0))
      .expect(not(lastCpKeep("NA").contains(5)) and not(lastCpKeep("NA").contains(6)))
      .then(syncRound).then(syncRound).then(compactAt("m")).then(compactAt("r")).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains("E")) and not(st.get("r").recs.contains(5))
        and not(st.get("r").recs.contains(6)) and promises and spareSafe)
  // 3. The honest path: A1 acks, then removes D: counts. Before the ack the writer's guard
  // refuses A1's removal (asserted on a's set).
  run posHonestTest = if (not(onS and SEEN_POS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .expect(not(posAnchored(recsOf(st.get("a").recs, db), views.get("a"), "A1", "revoke"))
        and posAnchored(recsOf(st.get("a").recs, db), views.get("a"), "A1", "ack"))
      .then(ackS("A1")).then(syncRound)
      .expect(posAnchored(recsOf(st.get("a").recs, db), views.get("a"), "A1", "revoke"))
      .then(sign("A1", "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound).then(syncRound)
      .expect(dOutL and spareSafe)
  // 4. Positions are per key: A's ack under R holds R's grant of A; after the change names A1,
  // A1's (deviant) removal of D without an A1 record holding NA's grant below it counts for
  // nothing.
  run posPerKeyTest = if (not(onS and SEEN_POS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(signDeviant("A1", "revoke", DEVICE, 1)).then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains(DEVICE) and not(views.get(m).counting.contains(nextId - 1)))
        and spareSafe)

  // SEEN_POS final wording. 1: A1 anchors (ack 12-ish) and admits E; NA names A1 again with
  // another kit (an update after the anchor) and its checkpoint drops the first grant: A1's
  // earlier records still count (by branch (b): the checkpoint keeps them).
  run posUpdateTest = if (not(onS and SEEN_POS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(ackS("A1")).then(sign("A1", "device", "E", "", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "admin", "A1", "computer", 0, false, false, 1)).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs("NA", "checkpoint", "", 0))
      .then(syncRound).then(syncRound).then(compactAt("r")).then(compactAt("c")).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains("E") and views.get(m).admins.keys().contains("A1"))
        and promises and spareSafe)
  // 2. Branch (b) against pre-signed records. (i) C's spare C2 pre-signs a freeze of A1 and a
  // removal of D (not delivered to NA's holder a); C acks; the change names C2 and A1; NA
  // checkpoints before C2's first good record; then everything is delivered.
  run posBranchBTest = if (not(onS and SEEN_POS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(signDeviant("C2", "revoke", DEVICE, 1)).then(signDeviant("C2", "freeze", "A1", 1))
      .then(ackS(PHONE)).then(ackS(COMPUTER)).then(giveAll(Set("r", "a", "k", "m"), [7, 8]))
      .then(recoverAs(RECOVERY, "NA")).then(giveAll(Set("r", "a", "k", "m"), range(recId, firstOfChange + 1)))
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(giveAll(Set("r", "a", "k", "m"), [nextId - 1]))
      .then(signAs("NA", "checkpoint", "", 0))
      .then(syncRound).then(syncRound).then(giveAll(MEMBERS, [5, 6])).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains(DEVICE) and not(views.get(m).frozen.contains("A1"))
        and not(views.get(m).counting.contains(5)) and not(views.get(m).counting.contains(6))) and spareSafe)
  // (ii) The same with the pre-signed records delivered to the root's holder before its
  // checkpoint: the checkpoint names a head for C2 (6, a void record); does 6 count?
  run posBranchBDeliveredTest = if (not(onS and SEEN_POS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(signDeviant("C2", "revoke", DEVICE, 1)).then(signDeviant("C2", "freeze", "A1", 1))
      .then(ackS(PHONE)).then(ackS(COMPUTER)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(giveAll(MEMBERS, [5, 6])).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs("NA", "checkpoint", "", 0))
      .expect(lastCpKeep("NA").contains(5) == false and lastCpKeep("NA").contains(6) == false)
      .then(syncRound).then(syncRound).then(compactAt("r")).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains(DEVICE) and not(views.get(m).frozen.contains("A1"))
        and not(views.get(m).counting.contains(5)) and not(views.get(m).counting.contains(6))) and spareSafe)
  // 3. A member holding the checkpoint but not the anchor: m gets NA's checkpoint (which keeps
  // A1's ack and E) without A1's ack itself; with all of them it counts E like the others.
  run posCpNoAnchorTest = if (not(onS and SEEN_POS)) init else
    spareStart
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(ackS("A1")).then(sign("A1", "device", "E", "", 0, false, false, 1))
      .then(giveAll(Set("r", "a", "c", "k"), [nextId - 2, nextId - 1]))
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(giveAll(Set("r", "a", "c", "k"), [nextId - 1]))
      .then(signAs("NA", "checkpoint", "", 0))
      .then(giveAll(Set("m"), [nextId - 1]))
      .then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).devices.contains("E")) and promises and spareSafe)

  // BREAK of branch (b) (11-14 23:00): C's spare C2 pre-signs a removal of D (5) and an
  // admission of E (6); both reach NA's holder before NA's checkpoint, which names C2's head
  // 6. Record 6 sits at that head, so it counts and E is in; spareSafe breaks. With
  // POS_HEADS_COUNTING the checkpoint names no void head and nothing counts.
  run posBranchBBreakTest = if (not(onS and SEEN_POS)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(signDeviant("C2", "revoke", DEVICE, 1)).then(signDeviant("C2", "device", "E", 1))
      .then(ackS(PHONE)).then(ackS(COMPUTER)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .then(giveAll(MEMBERS, [5, 6])).then(syncRound)
      .then(sign("NA", "copies", "", "", 0, false, false, 1)).then(syncRound)
      .then(signAs("NA", "checkpoint", "", 0))
      .then(syncRound).then(syncRound).then(compactAt("r")).then(syncRound)
      .expect(if (POS_HEADS_COUNTING) notM.forall(m => not(views.get(m).devices.contains("E"))) and spareSafe
        else views.get("r").counting.contains(6) and views.get("r").devices.contains("E") and not(spareSafe))
  // L carries freezes. A root's freeze of A and C's freeze of W: frozen before the change, and
  // after it their devices dA and dW are frozen (wiped admins re-issued as frozen plain
  // devices); under SPARE a frozen admin (A acked first) is not kept.
  run lFreezeTest = if (not(onL)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(if (SPARE) ackS(PHONE) else syncRound).then(if (SPARE) ackS(COMPUTER) else syncRound).then(syncRound)
      .then(sign(ROOT, "freeze", PHONE, "", 0, false, false, 1))
      .then(sign(COMPUTER, "freeze", WATCH, "", 0, false, false, 1)).then(syncRound)
      .expect(notM.forall(m => Set(PHONE, WATCH).subseteq(views.get(m).frozen)))
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .expect(notM.forall(m => views.get(m).path == [ROOT, "NA"] and Set("dA", "dW").subseteq(views.get(m).frozen)
        and not(views.get(m).admins.keys().contains("A1"))) and promises)

  // REISSUE_STATE: the change to NA re-issues R's live admissions (A, C, W and D) as NA's first
  // records 6 to 9; the list keeps none of R's records, the first checkpoint keeps the Ys, and
  // every member counts the same admins and devices under NA.
  // (LAST_ROOT_ONLY wipes the admins: lLateOldTest.)
  run reissueStateTest = if (LAST_ROOT_ONLY) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(recoverAs(RECOVERY, "NA")).then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).path == [ROOT, "NA"] and views.get(m).devices.contains(DEVICE)
        and views.get(m).admins.keys() == Set(PHONE, COMPUTER, WATCH)) and promises
        and ((REISSUE_STATE and REISSUE_REMOVALS) implies (db.get(5).keep == Set()
          and Set(6, 7, 8, 9).forall(i => db.get(i).signer == "NA" and db.get(i).targetRec == 5)
          and db.get(10).keep == Set(6, 7, 8, 9))))

  // TAKEN_FOR_GOOD (architecture 11-14 23:06Z). X's device dX: a plain device record (4), R
  // names X (5), R admits D (6); R takes X back (7, a device record of dX naming no admin),
  // X, not yet holding 7, removes D (8, void: 7 did not see it). Without the switch every test
  // below shows the revival (calibration); with it X counts for nothing and D stays.
  pure val onT = CP_KEEP and ROOT_WAITS and wideW and not(SEEN_POS)
  action tfgStart = init
      .then(sign(ROOT, "device", "dX", "", 0, false, false, 1))
      .then(sign(ROOT, "admin", MINTED, "computer", 0, false, false, 1))
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "device", "dX", "", 0, false, false, 1))
      .then(sign(MINTED, "revoke", DEVICE, "", 0, false, false, 1))
      .then(giveAll(MEMBERS, [7]))
  val xOut = MEMBERS.forall(m => not(views.get(m).admins.keys().contains(MINTED)) and views.get(m).devices.contains(DEVICE))
  val xBack = MEMBERS.exists(m => views.get(m).admins.keys().contains(MINTED) and not(views.get(m).devices.contains(DEVICE)))
  // The deviant root names X again (9) right away, no checkpoint between.
  run tfgDeviantTest = if (not(onT)) init else
    tfgStart
      .expect(xOut)
      .then(signFull(ROOT, "admin", MINTED, "computer!", 0, false, false, 1, true, Set()))
      .then(giveAll(MEMBERS, [9, 8])).then(syncRound).then(syncRound)
      .expect(if (TAKEN_FOR_GOOD) xOut and promises else xBack)
  // R checkpoints (9) and every member compacts: CP_DEV_ANY alone drops 5 (dX's middle root
  // record), so R no longer holds that X was named and taken back, and names X again honestly
  // (10); with the switch 5 and 7 stay and only a deviant naming is possible. 8 is sent again.
  run tfgForgetTest = if (not(onT)) init else
    tfgStart
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2)).then(giveAll(MEMBERS, [9]))
      .then(compactAt("r")).then(compactAt("a")).then(compactAt("c")).then(compactAt("k")).then(compactAt("m"))
      .expect(xOut and (TAKEN_FOR_GOOD implies MEMBERS.forall(m => Set(5, 7).subseteq(st.get(m).recs)))
        and ((CP_DEV_ANY and not(TAKEN_FOR_GOOD)) implies not(st.get("r").recs.contains(5))))
      .then(if (TAKEN_FOR_GOOD or not(CP_DEV_ANY)) signFull(ROOT, "admin", MINTED, "computer!", 0, false, false, 1, true, Set())
        else sign(ROOT, "admin", MINTED, "computer", 0, false, false, 1))
      .then(giveAll(MEMBERS, [10, 8])).then(syncRound).then(syncRound)
      .expect(if (TAKEN_FOR_GOOD) xOut and promises else xBack)
  // Two members: c keeps every old record (never compacts), m joins from r after the checkpoint.
  run tfgNewcomerTest = if (not(onT)) init else
    tfgStart
      .then(sign(ROOT, "checkpoint", "", "", 0, false, false, 2)).then(giveAll(MEMBERS, [9]))
      .then(compactAt("r")).then(welcomeFrom("r"))
      .then(signFull(ROOT, "admin", MINTED, "computer!", 0, false, false, 1, true, Set()))
      .then(giveAll(MEMBERS, [10, 8])).then(syncRound).then(syncRound)
      .expect(views.get("c").admins == views.get("m").admins and views.get("c").devices == views.get("m").devices
        and (if (TAKEN_FOR_GOOD) xOut and promises else xBack))
  // The deviant root names X again for another device (dZ).
  run tfgOtherDeviceTest = if (not(onT)) init else
    tfgStart
      .then(signFull(ROOT, "admin", MINTED, "phone@dZ!", 0, false, false, 1, true, Set()))
      .then(giveAll(MEMBERS, [9, 8])).then(syncRound).then(syncRound)
      .expect(if (TAKEN_FOR_GOOD) xOut and promises else xBack)

  // W (records b3d1df93, architecture 11-15 00:06Z): no automatic take-back of a frozen admin.
  // C is frozen and R removes D; C's ack, signed while frozen, does not count, so the removal
  // waits (the checkpoint keeps it) until R thaws C and C acks again; then it settles.
  // (Silence, 35 days on the root's clock, and the person's take_back(a) are signDemote, a
  // free root action in the model, which has no clock.)
  val rCp = db.keys().filter(i => db.get(i).kind == "checkpoint" and db.get(i).signer == ROOT).fold(0, (a, i) => max2(a, i))
  run wFrozenBlocksTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "device", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(sign(ROOT, "freeze", COMPUTER, "", 0, false, false, 1))
      .then(sign(ROOT, "revoke", DEVICE, "", 0, false, false, 1)).then(syncRound)
      .then(ackS(PHONE)).then(ackS(WATCH)).then(ackS(COMPUTER)).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1)).then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(rCp).keep.contains(6))
      .then(syncRound)
      .expect(dOut and promises)
      .then(sign(ROOT, "thaw", "", "", 5, false, false, 1)).then(syncRound)
      .then(ackS(COMPUTER)).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1)).then(signAs(ROOT, "checkpoint", "", 0))
      .expect(not(db.get(rCp).keep.contains(6)))
      .then(syncRound).then(syncRound)
      .expect(dOut and promises)
  // W point 3 (records 655fcdac): a removal of a device that had an admin key (dC, C's) is kept
  // for good: every live admin acks, and still the checkpoint keeps it.
  run wKeptForGoodTest = if (not(ROOT_WAITS) or not(wideW)) init else
    init
      .then(sign(ROOT, "revoke", "dC", "", 0, false, false, 1)).then(syncRound)
      .then(ackS(PHONE)).then(ackS(WATCH)).then(syncRound)
      .then(sign(ROOT, "copies", "", "", 0, false, false, 1)).then(signAs(ROOT, "checkpoint", "", 0))
      .expect(db.get(rCp).keep.contains(4))
      .then(syncRound).then(syncRound)
      .expect(MEMBERS.forall(m => views.get(m).revoked.contains("dC")) and promises)
}
