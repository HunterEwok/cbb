---------------------------- MODULE RecordsCore ----------------------------
(***************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                  *)
(* Copyright (C) 2026 HunterEwok                                           *)
(*                                                                         *)
(* The record rules of 0.6 (records v3), ported rule by rule from the      *)
(* Quint model docs/model/records-v3.qnt (branch                           *)
(* claude/project-thread-ukwxtl, head 6acf46ca) for an exhaustive check    *)
(* with TLC. The switches are fixed at the decided values (handover        *)
(* section 4): CEIL_FIT, WRITER_KEEPS, CUT_MODE "mark", HALT_ON_HELD_PAIR, *)
(* F7_EVERY_KEY, not F7_SEEN_IGNORED, FOLD_REMOVALS, RESTART_REOFFERS, not *)
(* RESTART_KEEPS_CUT, NEWEST_ASIDE, ASIDE_TAKES_WAITED, WAIT_TAKES_SETTLED, *)
(* EARLY_BEFORE_CHECKPOINTS, not ONE_SLOT, not MISSING_NEWEST_ONLY, not     *)
(* CP_ROOM_WHEN_WHOLE, not F12, not SYNC_MEMBERS_ONLY, not NEWEST_HEAD_ANY,*)
(* LOST empty. PREV_ROOM_WHEN_KEPT (open) is a constant.                   *)
(*                                                                         *)
(* Every operator keeps the name of the Quint definition it ports, with a  *)
(* capital first letter. Quint lists are 0-based, TLA+ sequences 1-based:  *)
(* the index arithmetic below is shifted by one where it reads a line.     *)
(* The universe (keys, members, sizes, the group as made) is a constant,   *)
(* so the same module replays the Quint scenarios in the Quint universe    *)
(* and runs the exhaustive check in a small one.                           *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    ROOT, RECOVERY,      \* the first root key, the recovery key
    SIGNERS,             \* the keys whose records live in the rooms
    ROOT_KEYS,           \* the keys that may become roots
    THIEVES,             \* the keys a pretending writer hides
    HOLDER,              \* key -> the member that holds it
    MEMBERS,
    NEWCOMER,            \* the member a Welcome resets ("" for none)
    DEV,                 \* admin key -> the member key of its device
    ROOM, ROOTC, ADMINC, RESERVE, MAXU,
    MAXREC,              \* as in the Quint model: positions, lists, seqs
    LASTID,              \* the highest record ID the run may sign
    MAXCHAIN,
    START,               \* the group as made: ID -> record
    FIRST,               \* the first free ID
    PREV_ROOM_WHEN_KEPT, \* open switch (off)
    CEIL_FIT,            \* (J), decided TRUE; FALSE is the Quint file's default (its scenarios)
    WRITER_KEEPS,        \* (E), decided TRUE; FALSE is the Quint file's default
    FIRST_NEWEST_ONLY,   \* decided TRUE 11-13 19:22Z: the newest head with a held first checkpoint applies
    EARLY_ROOM,          \* decided TRUE 11-13 19:22Z: early roots' records wait in one root's room
    WAIT_SKIP,           \* open (off): a turned-away waiting checkpoint is skipped, not a stop
    UNKNOWN_HEADS,       \* decided TRUE 11-13 19:22Z: only heads cross to and from an Unknown peer
    HEADS_WITH_FIRSTS,   \* decided TRUE 11-13 19:22Z: the first checkpoints cross with the heads
    DEVICE,              \* the newcomer's own key under UNKNOWN_HEADS
    \* Mutations (calibration only; FALSE is the rule):
    CORE_LIST_FILTER,    \* the core's change list of 11-13: a removal of keys no held record names is left off
    NO_SAME_SEEN,        \* the fold of root removals without the same-seen condition
    \* Open (records 11-13 21:12Z): a change re-signs the cut roots' counting removals (Zs).
    REISSUE_REMOVALS,
    REISSUE_DROP_ONLY,   \* mutation: the old removals leave the list, no Z is signed
    REISSUE_PACK_ANY,    \* mutation: every re-signed removal goes into one Z
    REISSUE_MUT,         \* mutations: "newerSeen", "notKept", "listX" ("" is the rule)
    MARKS_GUARD,         \* TRUE: honestNoMarks without the out-of-group exemption
    SAVE_FIRSTS,         \* probe switch: the saved set keeps the first records beside the chain
    WHOLE_BY_SETTLER,    \* records 23:35Z: a first record a held later checkpoint settles need not be held
    HELD_ADMISSIONS,     \* core 066addaf: admin keys learned from held records (its early-aside part is EARLY_ASIDE)
    NEWEST_CP_FIRST,     \* room order: removals/resolves, newest checkpoint, the rest, older checkpoints last
    WRITER_LAST_ROOT,    \* decided 11-14: an honest checkpoint is signed only as the set's last root
    SYNC_PAIRS,          \* architecture 11-14 08:35Z: synced means no single delivery and no pair of deliveries changes the set
    SKIP_UNAPPLIED,      \* candidate 11-15 05:16Z: a writer holding an unapplied head N writes N+1 (prev N) from its view before N
    FIRST_REQUIRED,      \* architecture 11-14 08:41Z, code eval.rs first_gap: the first checkpoint itself must be held; a settler covers only records below it
    SETTLER_HELD,        \* architecture 11-14 08:35Z: a settler counts only when held (stored or waiting), not when merely got
    WRITER_CP_FLOOR,     \* architecture 11-14 06:08Z: a root's record leaves room for its next checkpoint
    EARLY_ASIDE,         \* core 5eb8ab55: a record of a root a held head names, not on the path yet, is held aside and saved
    CP_KEEP_LIVE,        \* records' proposal (not decided): the honest root checkpoint keeps only live records
    TWO_TIERS,           \* core #530 c8a5eae0 keep_tiers: two tiers, rooms judged from what is held alone (no marks)
    CP_OWN_HEAD,         \* frozen rule C (architecture 11-14 13:15Z): a checkpoint's own head is there iff seq > 1, at seq - 1 and = prev
    TIER_MODE,           \* "levels" (c8a5eae0 with beyond), "single" (no beyond), "fixed" (tier 2 fixed caps, architecture 11-14 11:03Z)
    NEW_ROOT_ONLY,       \* decided 23:26Z (k.9521): no change names a root already on the path
    SEEN_IGNORED,        \* mutation (calibration only): a removal's seen is ignored, every record of its target counts
    UNKNOWN_DROP,        \* mutation (calibration only): a checkpoint may drop a removal of a key it holds no admission of
    KEEP_V2,             \* code #530 88b56f5d set.rs checkpoint_body: the root checkpoint's keep as built
    SETTLED_ANY_SIGNED,  \* mutation (calibration only): KEEP_V2's settled key ignores whether its signed records count
    CLOSED_LIST,         \* code eval::closed: the current root's counting checkpoint narrows the list to what it keeps with its anchors
    E_EPOCH,             \* candidate E (architecture 11-14 15:54Z): checkpoint drops counter, admin device records carry the epoch they held
    E_ALL,               \* E variant 11-14 16:31Z: every device record carries the epoch, roots too; anchors keep; drops monotone over path roots
    HEAD_KEPT,           \* #530 9e20ec86 checkpoint_body: anchor = head && (own || !counting)
    CP_BEFORE_GOING,     \* #530 9e20ec86 write_one: the root writes a checkpoint before a record that makes an admin key go
    ADMIN_MAX,           \* eval::not_live: only the first ADMIN_MAX named admin keys are live (code 16; directed start 2)
    NEVER_DROP,          \* calibration: a root checkpoint never leaves out a settled removal (fold only)
    CHANGE_AT_NEW,       \* a root change is written on the new root's device, after it took what the recovery key's device holds
    E_STORED,            \* (conditional) a Device record that fails E stays stored, held and not counting
    E_TIE,               \* "first" or "last": which of two root twins at the newest seq gives D(m)
    GRANT_ABOVE,         \* W 11-14 22:10Z: a removal does not wait for an admin key a root record named above the removal's seq
    SEEN_LINE,           \* 11-14 22:45Z: an admin key's record counts only at or above one whose seen holds a root record naming it (or a checkpoint anchor)
    SPARE,               \* S 11-14 22:52Z: an admin's ack carries a one-time spare key; under L the new root names old admins by their spares
    LAST_ROOT,           \* L 11-14 22:52Z: after a change only the chain, the last root and the admin keys it named count; the new root re-issues devices and freezes
    W,                   \* candidate W 11-14 20:54Z: the root's checkpoint settles a removal only after every live admin key acked it
    FRESH_KEY,           \* environment 11-14 20:46Z: an honest device offers its key to one admitter once (no second admission of a key)
    UPD,                 \* flag variant 11-14 20:39Z: Device carries upd (0 admission, 1 update); an update never admits
    E_PAIR,              \* code rule: with a held pair of current-root records, every checkpoint at or above it and the newest below decide D together
    HND_NEWEST,          \* honestNeverDropped prunes by the current root's newest counting checkpoint (first included)
    SEEN_ORDER,          \* removedStayOut: an admission is newer than a removal only when it saw it (not by ID alone)
    PREV_NAMED,          \* code eval::named_first: a checkpoint names its prev (own head) even under PREV_ROOM_WHEN_KEPT unless it is a checkpoint
    CUT_RESET_ON_DROP    \* decided 23:26Z (k.9521): a new counting checkpoint resets the cut only when it prunes

TOP == ROOTC
ASIDE_ROOM == ROOM
NONE == 10000000
NEVER == 99

Range(f) == {f[x] : x \in DOMAIN f}
DEVS == Range(DEV)
EmptyFn == [x \in {} |-> 0]
NOCUT == [level |-> TOP, level2 |-> TOP, marks |-> EmptyFn]

Hid(i) == (i * 7) % 23

PowersOf(kit) ==
    IF kit = "phone" THEN {"admit", "manage", "remove", "freeze", "hub", "removeAdmins", "thaw"}
    ELSE IF kit = "computer" THEN {"admit", "manage", "remove", "freeze", "hub"}
    ELSE IF kit = "watch" THEN {"remove", "freeze"}
    ELSE {}

\* --- Helpers ----------------------------------------------------------------

Min2(a, b) == IF a < b THEN a ELSE b
Max2(a, b) == IF a > b THEN a ELSE b
MinS(S, d) == IF S = {} THEN d ELSE CHOOSE x \in S : \A y \in S : x <= y
MaxS(S, d) == IF S = {} THEN d ELSE CHOOSE x \in S : \A y \in S : x >= y

RECURSIVE SumU(_)
SumU(S) == IF S = {} THEN 0 ELSE LET x == CHOOSE x \in S : TRUE IN x.units + SumU(S \ {x})

OfKey(rs, k) == {r \in rs : r.signer = k}
RecsOf(xs, db) == {db[i] : i \in xs}
IdsOf(rs) == {r.id : r \in rs}
OnList(l, k) == \E i \in 1..Len(l) : l[i] = k
InLine(l, x) == \E i \in 1..Len(l) : l[i] = x
\* 0-based, -1 for none, as Quint's (the last match; paths hold each key once).
IndexOf(l, k) == IF OnList(l, k) THEN (CHOOSE i \in 1..Len(l) : l[i] = k /\ \A j \in 1..Len(l) : l[j] = k => j <= i) - 1 ELSE -1
Last(l) == l[Len(l)]
IsPrefix(a, b) == Len(a) <= Len(b) /\ \A i \in 1..Len(a) : a[i] = b[i]
IsChain(r) == r.kind = "recover"
KeysOfDev(d) == {d} \cup {a \in DOMAIN DEV : DEV[a] = d}
WithPair(k) ==
    IF k \in DOMAIN DEV THEN KeysOfDev(DEV[k]) ELSE IF k \in DEVS THEN KeysOfDev(k) ELSE {k}
\* The keys a record names: target with its pair, and a packed removal's further keys.
Tgt(r) == WithPair(r.target) \cup (UNION {WithPair(k) : k \in r.also})
DevOf(r) ==
    IF r.kind = "admin" /\ r.target \in DOMAIN DEV THEN DEV[r.target]
    ELSE IF r.kind = "device" THEN r.target ELSE ""
LineOf(m, k) == IF k \in DOMAIN m THEN m[k] ELSE <<>>
\* x is on the chain that ends at the head of line l, as far as a set can tell.
OnChain(l, x, ids, anchors) ==
    \E p \in 1..Len(l) : l[p] = x /\ (x \in anchors \/ \A j \in (p + 1)..Len(l) : l[j] \in ids \/ l[j] \in anchors)
SawIn(a, t, ids, anchors) == OnChain(LineOf(a.seen, t.signer), t.id, ids, anchors)
Floored(l) == Len(l) > 0 /\ l[1] < 0
FloorOf(l) == IF Floored(l) THEN 0 - l[1] ELSE 0
Replaced(cuts, k) == k \in DOMAIN cuts /\ ~Floored(cuts[k])
Within(cuts, r) ==
    \/ r.signer \notin DOMAIN cuts
    \/ InLine(cuts[r.signer], r.id)
    \/ (Floored(cuts[r.signer]) /\ r.seq >= FloorOf(cuts[r.signer]))
\* A set of IDs as a list in ID order (Quint's range(1, MAXREC + 6)).
RECURSIVE ToListR(_)
ToListR(s) == IF s = {} THEN <<>> ELSE LET m == MinS(s, 0) IN <<m>> \o ToListR(s \ {m})
ToList(s) == ToListR({i \in s : 1 <= i /\ i < MAXREC + 6})
RECURSIVE AnyList(_)
AnyList(S) == IF S = {} THEN <<>> ELSE LET x == CHOOSE x \in S : TRUE IN <<x>> \o AnyList(S \ {x})

AnchorsOf(c) == {Last(c.heads[k]) : k \in {k \in DOMAIN c.heads : Len(c.heads[k]) > 0}} \cup c.keep
RootRemoval(r) == r.kind = "revoke" /\ r.signer \in ROOT_KEYS
\* (PREV_ROOM_WHEN_KEPT: the writer's own earlier checkpoint that c does not keep is pruned
\* though it heads c's line; seed k.8702.)
PrunedBy(c, r) ==
    r.signer \in DOMAIN c.heads /\ r.seq <= Len(c.heads[r.signer])
    /\ (r.id \notin AnchorsOf(c)
        \/ (PREV_ROOM_WHEN_KEPT /\ r.kind = "checkpoint" /\ r.signer = c.signer /\ r.id \notin c.keep))
\* (CLOSED_LIST, code eval::closed: a record of a root before the checkpoint's signer that the
\* list carries goes unless the checkpoint keeps it or names it as the head of a key off the path.)
ClosedOut(path, c, r) ==
    /\ CLOSED_LIST
    /\ OnList(path, r.signer) /\ r.signer # c.signer /\ ~IsChain(r)
    /\ r.id \notin c.keep
    /\ ~\E k \in DOMAIN c.heads : ~OnList(path, k) /\ Len(c.heads[k]) > 0 /\ Last(c.heads[k]) = r.id
\* The newest of the checkpoints cs (highest seq; a twin tie by E_TIE: smallest or largest ID).
NewestCp(cs) ==
    LET mx == CHOOSE q \in {x.seq : x \in cs} : \A x \in cs : x.seq <= q
        ties == {x \in cs : x.seq = mx}
    IN CHOOSE x \in ties : \A y \in ties : IF E_TIE = "last" THEN x.id >= y.id ELSE x.id <= y.id
\* D(m) and its anchors from the current root's records own (E_PAIR: a held pair at seq p makes every
\* checkpoint at or above p plus the newest below p decide together: max drops, union of anchors).
DJudge(own) ==
    LET cps == {x \in own : x.kind = "checkpoint"}
        pairS == MinS({a.seq : a \in {a \in own : \E b \in own : b # a /\ b.seq = a.seq}}, NONE)
        below == {x \in cps : x.seq < pairS}
        S == {x \in cps : x.seq >= pairS} \cup (IF below = {} THEN {} ELSE {NewestCp(below)})
    IN IF cps = {} THEN [d |-> 0, anch |-> {}, any |-> FALSE]
       ELSE IF ~E_PAIR \/ pairS = NONE THEN [d |-> NewestCp(cps).ep, anch |-> AnchorsOf(NewestCp(cps)), any |-> TRUE]
       ELSE [d |-> MaxS({x.ep : x \in S}, 0), anch |-> UNION {AnchorsOf(x) : x \in S}, any |-> TRUE]
\* (E_EPOCH: an admin's device record of an older epoch than the checkpoint counts only if kept.)
EpochOut(path, c, r) ==
    /\ E_EPOCH /\ ~E_STORED
    /\ r.kind = "device" /\ (E_ALL \/ ~OnList(path, r.signer))
    /\ r.ep < c.ep /\ r.id \notin (IF E_ALL THEN AnchorsOf(c) ELSE c.keep)
PrunedByP(path, c, r) == PrunedBy(c, r) \/ ClosedOut(path, c, r) \/ EpochOut(path, c, r)
\* (UPD: a Device record flagged as an update is never an admission.)
IsUpd(r) == UPD /\ r.kind = "device" /\ r.upd = 1
AdmissionsOf(rs, k) == {r \in rs : r.kind \in {"admin", "device"} /\ ~IsUpd(r) /\ (r.target = k \/ DevOf(r) = k)}
\* The line of a key's newest record among rs (the highest seq, then the smallest ID).
HeadLine(rs, k) ==
    LET ks == OfKey(rs, k) IN
    IF ks = {} THEN <<>>
    ELSE (CHOOSE r \in ks : \A o \in ks : r.seq > o.seq \/ (r.seq = o.seq /\ r.id <= o.id)).line
\* A root removal folds into a newer one only when both saw alike every key they name.
SameSeen(r, n) == NO_SAME_SEEN \/ \A k \in Tgt(r) \cup Tgt(n) : LineOf(r.seen, k) = LineOf(n.seen, k)
DroppedAt(mine, counted) ==
    LET rms == {r \in counted : RootRemoval(r)
                   /\ (\A k \in Tgt(r) : k \notin DOMAIN DEV /\ k \notin SIGNERS
                         /\ (UNKNOWN_DROP \/ AdmissionsOf(mine, k) # {})
                         /\ \A a \in AdmissionsOf(mine, k) : HeadLine(mine, a.signer) # a.line)
                   /\ ~\E x \in mine : x.signer \in Tgt(r)}
        gone == UNION {Tgt(r) : r \in rms}
        folded == {r \in counted : RootRemoval(r) /\ \E n \in counted : RootRemoval(n)
                     /\ n.signer = r.signer /\ n.seq > r.seq /\ n \notin rms
                     /\ Tgt(r) \subseteq Tgt(n) /\ SameSeen(r, n)}
    IN IdsOf(rms) \cup IdsOf(folded)
         \cup IdsOf({x \in mine : x.signer \in gone \/ \E k \in gone : AdmissionsOf({x}, k) # {}})

\* (SPARE: the model's fixed spare of each admin key that has one; C2 is a second key of C's device.)
SpareOf(k) == IF k = "C" THEN "C2" ELSE ""
NONEREC == [id |-> 0, signer |-> "", seq |-> 0, line |-> <<>>, kind |-> "", target |-> "", kit |-> "",
            targetRec |-> 0, seen |-> EmptyFn, heads |-> EmptyFn, keep |-> {}, units |-> 0, first |-> 0,
            off |-> FALSE, also |-> {}, ep |-> 0, upd |-> 0, wv |-> {}, wr |-> {}, spare |-> "", akit |-> "", lo |-> {}]

Rec(id, signer, line, kind, target, kit, targetRec, seen, heads, keep, units) ==
    [id |-> id, signer |-> signer, seq |-> Len(line), line |-> line, kind |-> kind, target |-> target,
     kit |-> kit, targetRec |-> targetRec, seen |-> seen, heads |-> heads, keep |-> keep, units |-> units,
     first |-> 0, off |-> FALSE, also |-> {}, ep |-> 0, upd |-> 0, wv |-> {}, wr |-> {}, spare |-> "", akit |-> "", lo |-> {}]

\* --- The recovery chain (rule 33) ------------------------------------------

ValidAt(r, path) ==
    r.kind = "recover" /\ r.signer = RECOVERY /\ r.target \in ROOT_KEYS /\ ~OnList(path, r.target)
NamesFirst(h, c) == IsChain(h) /\ c.kind = "checkpoint" /\ c.id = h.first /\ c.signer = h.target
\* (REISSUE_REMOVALS: the head's re-signed removals Z, kit "z" naming the head, are first
\* records too; the head has its first only with every Z, IDs between the head and the first.)
NamesZ(h, z) == IsChain(h) /\ z.kit = "z" /\ z.targetRec = h.id /\ z.signer = h.target
\* (WHOLE_BY_SETTLER, records 11-13 23:35Z: a change is whole with its head, its list, the new
\* root's first checkpoint and each record of that root's line below it, unless a held later
\* checkpoint settles the record: of the new root above the first, or of a root after it on the
\* chain; it names a head of the record's key at or above the record and does not keep it.)
\* A record r's list cuts: an old root's record other than a checkpoint that r does not keep.
CutByChange(r, x) == x.signer \in ROOT_KEYS /\ x.id \notin r.keep /\ (x.signer # r.target \/ x.seq < r.targetRec)
SettledFirst(r, i, rs) ==
    LET ids == IdsOf(rs) IN
    \E l \in rs : l.kind = "checkpoint" /\ l.signer = r.target /\ l.id # i /\ InLine(l.line, r.first)
                 /\ r.target \in DOMAIN l.heads /\ InLine(l.heads[r.target], i) /\ i \notin l.keep
                 \* (records 9dd3d9c8 (a): the settler's own keep is held too; and it keeps no old
                 \* root's record that r itself cuts, Quint 01858aed.)
                 /\ l.keep \subseteq ids
                 /\ ~\E x \in rs : x.id \in l.keep /\ CutByChange(r, x)
HasFirst(r, rs) == r.first = 0 \/
    IF WHOLE_BY_SETTLER /\ r.first <= r.id + MAXREC
    THEN \A i \in (r.id + 1)..r.first :
            \/ \E x \in rs : x.id = i /\ (NamesFirst(r, x) \/ NamesZ(r, x))
            \/ ((~FIRST_REQUIRED \/ i # r.first) /\ SettledFirst(r, i, rs))
    ELSE
    ((\E c \in rs : NamesFirst(r, c))
     /\ (~REISSUE_REMOVALS \/ r.first > r.id + MAXREC
         \/ \A i \in (r.id + 1)..(r.first - 1) : \E z \in rs : z.id = i /\ NamesZ(r, z)))

\* The path and the replaced roots' lists the chain gives.
PathCutsOf(l) ==
    LET path == <<ROOT>> \o [i \in 1..Len(l) |-> l[i].target]
        list == IF Len(l) = 0 THEN <<>> ELSE ToList(l[Len(l)].keep)
        from == IF Len(l) = 0 THEN 0 ELSE l[Len(l)].targetRec
        olds == [k \in {path[i] : i \in 1..(Len(path) - 1)} |-> list]
    IN [path |-> path,
        cuts |-> IF from > 1 THEN [k \in DOMAIN olds \cup {Last(path)} |->
                                      IF k = Last(path) THEN <<0 - from>> \o list ELSE olds[k]]
                 ELSE olds]

RECURSIVE ChainFrom(_, _, _, _)
ChainFrom(rs, needFirst, acc, i) ==
    IF i > MAXCHAIN \/ ~acc.open THEN acc
    ELSE LET path == PathCutsOf(acc.recs).path
             cands == {r \in rs : IsChain(r) /\ r.seq = i /\ ValidAt(r, path)
                         /\ SubSeq(r.line, 1, i - 1) = acc.ids /\ (~needFirst \/ HasFirst(r, rs))}
         IN IF Cardinality(cands) # 1 THEN [acc EXCEPT !.open = FALSE]
            ELSE LET c == CHOOSE c \in cands : TRUE
                 IN ChainFrom(rs, needFirst, [acc EXCEPT !.ids = Append(@, c.id), !.recs = Append(@, c)], i + 1)
ChainBy(rs, needFirst) ==
    ChainFrom(rs, needFirst, [ids |-> <<>>, recs |-> <<>>, key |-> RECOVERY, stop |-> FALSE, open |-> TRUE], 1)
ChainRaw(rs) == ChainBy(rs, ~FIRST_NEWEST_ONLY)
ChainHeads(rs) == ChainBy(rs, FALSE)
\* Under FIRST_NEWEST_ONLY the chain ends at its newest head whose first checkpoint is held.
NewestWithFirst(ch, rs) ==
    IF ~FIRST_NEWEST_ONLY THEN ch
    ELSE LET n == MaxS({j \in 1..Len(ch.recs) : HasFirst(ch.recs[j], rs)}, 0)
         IN [ch EXCEPT !.ids = SubSeq(ch.ids, 1, n), !.recs = SubSeq(ch.recs, 1, n)]
ChainOf(rs) == NewestWithFirst(ChainRaw(rs), rs)
Forked(rs) ==
    LET cs == {x \in rs : IsChain(x) /\ x.signer = RECOVERY}
    IN \E a, b \in cs : a # b /\ a.seq = b.seq
ChainOfAll(rs) == [ChainOf(rs) EXCEPT !.stop = Forked(rs)]
PathCuts(ch) == PathCutsOf(ch.recs)

\* --- Keeping (rule 6) -----------------------------------------------------

Pos(r, cur, ord) ==
    LET cp == r.signer = cur /\ r.kind = "checkpoint"
        early == r.signer \in ord.roots /\ r.kind \in {"revoke", "freeze", "resolve"}
    IN IF RootRemoval(r) THEN r.seq * 100 + Hid(r.id)
       ELSE IF r.signer # cur /\ r.signer \in DOMAIN ord.cuts THEN
            (IF InLine(ord.cuts[r.signer], r.id) THEN 10000 + r.seq * 100 + Hid(r.id)
             ELSE 200000 + r.seq * 100 + Hid(r.id))
       ELSE IF cp /\ NEWEST_CP_FIRST /\ r.seq < ord.top THEN 300000 + (MAXREC + 4 - r.seq) * 100 + Hid(r.id)
       ELSE IF cp THEN 10000 + (MAXREC + 4 - r.seq) * 100 + Hid(r.id)
       ELSE IF early THEN r.seq * 100 + Hid(r.id)
       ELSE 100000 + r.seq * 100 + Hid(r.id)
MinPos(rs, cur, ord) == MinS({Pos(r, cur, ord) : r \in rs}, NONE)
Prefix(rs, r, cur, ord) == LET p == Pos(r, cur, ord) IN SumU({x \in rs : Pos(x, cur, ord) <= p})
Past(cut, r, cur, ord) == r.signer \in DOMAIN cut.marks /\ Pos(r, cur, ord) >= cut.marks[r.signer][1]
Dropped(cut, k) == IF k \in DOMAIN cut.marks THEN cut.marks[k][2] ELSE 0
PreOf(pre, k) == IF k \in DOMAIN pre THEN pre[k] ELSE 0

RECURSIVE DemandSum(_, _, _, _, _, _)
DemandSum(ks, owned, ceil, cut, s, pre) ==
    IF ks = {} THEN 0
    ELSE LET k == CHOOSE k \in ks : TRUE
         IN Min2(Max2(0, s - PreOf(pre, k)), Min2(ceil[k], Dropped(cut, k) + SumU(OfKey(owned, k))))
              + DemandSum(ks \ {k}, owned, ceil, cut, s, pre)
Demand(owned, ceil, cut, s, pre) == DemandSum({r.signer : r \in owned}, owned, ceil, cut, s, pre)

\* (TWO_TIERS, core #530 c8a5eae0 keep.rs keep_tiers: each key keeps its first records in pos
\* order, whole, within min(level - pre, ceiling); tier 1 (roots, live admins) is filled first at
\* the highest level that fits the room, tier 2 (admin keys no longer admins) at the highest level
\* that fits the room less tier 1's demand; nothing is remembered between judgments.)
KeptAtT(rsk, cap, cur, ord) == {r \in rsk : Prefix(rsk, r, cur, ord) <= cap}
CapT(ceil, pre, k, s) == Min2(Max2(0, s - PreOf(pre, k)), ceil[k])
RECURSIVE DemandT(_, _, _, _, _, _, _)
DemandT(ks, owned, ceil, pre, s, cur, ord) ==
    IF ks = {} THEN 0
    ELSE LET k == CHOOSE k \in ks : TRUE
         IN SumU(KeptAtT(OfKey(owned, k), CapT(ceil, pre, k, s), cur, ord)) + DemandT(ks \ {k}, owned, ceil, pre, s, cur, ord)
FillT(ks, owned, ceil, pre, cur, ord, room) ==
    IF DemandT(ks, owned, ceil, pre, TOP, cur, ord) <= room THEN TOP
    ELSE MaxS({s \in 0..TOP : DemandT(ks, owned, ceil, pre, s, cur, ord) <= room}, 0)
KeepTiers(items, ceil, cur, ord, room, pre, sec) ==
    LET owned == {r \in items : r.signer \in DOMAIN ceil}
        ks == {r.signer : r \in owned}
        k1 == ks \ sec
        k2 == ks \cap sec
        \* ("fixed", core #530 88b56f5d: tier 1 keeps within its ceilings alone, no level.)
        level == IF TIER_MODE \in {"fixed", "zero"} THEN TOP ELSE FillT(k1, owned, ceil, pre, cur, ord, room)
        level2 == FillT(k2, owned, ceil, pre, cur, ord, room - DemandT(k1, owned, ceil, pre, level, cur, ord))
        \* ("fixed": each tier-2 key gets min(ADMINC, rest / n2), rest = ROOM - ROOTC - RESERVE -
        \* ADMINC x live admins, read from the root records alone.)
        live == Cardinality({k \in DOMAIN ceil : ~(k \in ROOT_KEYS) /\ k \notin sec})
        n2 == Cardinality({k \in DOMAIN ceil : k \in sec})
        fixed == IF n2 = 0 THEN 0 ELSE Min2(ADMINC, Max2(0, ROOM - ROOTC - RESERVE - ADMINC * live) \div n2)
        cap2(k) == IF TIER_MODE = "zero" THEN 0 ELSE IF TIER_MODE = "fixed" THEN Min2(Max2(0, fixed - PreOf(pre, k)), ceil[k]) ELSE CapT(ceil, pre, k, level2)
        kept == UNION {KeptAtT(OfKey(owned, k), IF k \in sec THEN cap2(k) ELSE CapT(ceil, pre, k, level), cur, ord) : k \in ks}
    IN [kept |-> IdsOf(kept), cut |-> [level |-> level, level2 |-> level2, marks |-> EmptyFn]]
\* What a set keeps of items in a room of the given size: water-filling to one level.
KeepIn(items, ceil, cut, cur, ord, room, pre) ==
    LET live == {r \in items : ~Past(cut, r, cur, ord)}
        owned == {r \in live : r.signer \in DOMAIN ceil}
        top == Min2(cut.level, TOP)
        level == IF Demand(owned, ceil, cut, top, pre) <= room THEN top
                 ELSE MaxS({s \in 0..top : Demand(owned, ceil, cut, s, pre) <= room}, 0)
        keptOwned == {r \in owned : Prefix(OfKey(owned, r.signer), r, cur, ord)
                         <= Min2(Max2(0, level - PreOf(pre, r.signer)), ceil[r.signer])}
        out == owned \ keptOwned
        markKeys == DOMAIN cut.marks \cup {r.signer : r \in out}
        marks == [k \in markKeys |->
                    LET o == OfKey(out, k) IN
                    IF o = {} THEN cut.marks[k]
                    ELSE IF k \in DOMAIN cut.marks
                         THEN <<Min2(MinPos(o, cur, ord), cut.marks[k][1]), SumU(o) + cut.marks[k][2]>>
                         ELSE <<MinPos(o, cur, ord), SumU(o)>>]
    IN [kept |-> IdsOf(keptOwned), cut |-> [level |-> level, level2 |-> TOP, marks |-> marks]]
KeepAfter(items, ceil, cut, cur, ord) == KeepIn(items, ceil, cut, cur, ord, ROOM, EmptyFn)
KeepInS(items, ceil, cut, cur, ord, room, pre, sec) ==
    IF TWO_TIERS THEN KeepTiers(items, ceil, cur, ord, room, pre, sec) ELSE KeepIn(items, ceil, cut, cur, ord, room, pre)

\* --- A member's set --------------------------------------------------------

Learned(rs, path, cuts) ==
    {r.target : r \in {r \in rs : OnList(path, r.signer) /\ Within(cuts, r) /\ r.kind = "admin"}}
\* (TWO_TIERS: the admin keys that are no longer admins: a root on the path removed them.)
SecondOf(rs, path, cuts) ==
    IF ~TWO_TIERS THEN {}
    ELSE LET named == Learned(rs, path, cuts)
             gone == {k \in named : \E r \in rs : RootRemoval(r) /\ OnList(path, r.signer) /\ Within(cuts, r) /\ k \in Tgt(r)}
             \* (ADMIN_MAX: of the rest, those named after the first ADMIN_MAX (by the first naming record) have no room.)
             at(k) == MinS({r.id : r \in {r \in rs : OnList(path, r.signer) /\ Within(cuts, r) /\ r.kind = "admin" /\ r.target = k}}, NONE)
             rest == named \ gone
             past == {k \in rest : Cardinality({j \in rest : at(j) < at(k)}) >= ADMIN_MAX}
         IN gone \cup past
Ceilings(path, admins) ==
    [k \in {k \in SIGNERS : OnList(path, k) \/ k \in admins} |-> IF OnList(path, k) THEN ROOTC ELSE ADMINC]
RootsOf(path) == {path[i] : i \in 1..Len(path)}

\* What the room of early roots keeps (EARLY_ROOM).
EarlyKept(s, db) ==
    LET heads == {h \in RecsOf(s.chain, db) : IsChain(h) /\ ~OnList(s.path, h.target)}
        Rank(k) == MinS({h.seq : h \in {h \in heads : h.target = k}}, NONE)
        early == {r \in RecsOf(s.got, db) : ~IsChain(r) /\ r.id \notin s.chain /\ Rank(r.signer) < NONE}
        Before(x, r) == Rank(x.signer) < Rank(r.signer)
                          \/ (Rank(x.signer) = Rank(r.signer) /\ (x.seq < r.seq \/ (x.seq = r.seq /\ x.id <= r.id)))
    IN IdsOf({r \in early : SumU({x \in early : Before(x, r)}) <= ROOTC})
\* (SETTLER_HELD, code #530 8b72f2c9: a record of a held head's new root, which the path does not
\* list yet when it arrives, is held aside (side), not refused; the change offers it to the set and
\* forgets it once its root is listed. EARLY_ROOM is not applied to side here.)
HeldAside(s, db) == s.side
HeldOf(s, db) == s.recs \cup s.wait \cup HeldAside(s, db)
\* (WHOLE_BY_SETTLER: a held settler counts toward whole whether or not the set kept it yet.)
ChainState(s, db) == ChainOfAll(RecsOf(s.chain, db) \cup
    (IF WHOLE_BY_SETTLER THEN {c \in RecsOf(IF SETTLER_HELD THEN HeldOf(s, db) ELSE s.got, db) : ~IsChain(c)} ELSE {}))
KeptPath(s, db) == PathCuts(ChainState(s, db)).path
KeptCuts(s, db) == PathCuts(ChainState(s, db)).cuts
\* (NEWEST_CP_FIRST: the seq of the current root's newest checkpoint the set holds.)
TopOf(s, cur, db) ==
    IF ~NEWEST_CP_FIRST THEN 0
    ELSE MaxS({c.seq : c \in {c \in RecsOf(s.recs \cup s.wait, db) : c.kind = "checkpoint" /\ c.signer = cur}}, 0)
TopCp(s, db) == TopOf(s, Last(KeptPath(s, db)), db)
OrderOf(s, db) ==
    LET pc == PathCuts(ChainState(s, db))
    IN [roots |-> RootsOf(pc.path), cuts |-> pc.cuts, top |-> TopOf(s, Last(pc.path), db)]

\* (CP_OWN_HEAD, rule C: a checkpoint names its own key's head iff its seq > 1, with that head at
\* seq - 1 and equal to its prev; one that breaks it is malformed and refused by everyone.)
CpOwnOK(r) ==
    r.kind # "checkpoint"
    \/ (LET l == LineOf(r.seen, r.signer)
        IN IF r.seq > 1 THEN r.signer \in DOMAIN r.seen /\ Len(l) = r.seq - 1 /\ l[Len(l)] = r.line[r.seq - 1]
           ELSE r.signer \notin DOMAIN r.seen \/ l = <<>>)
StorableBut(s, r, db) ==
    LET pc == PathCuts(ChainState(s, db))
        admins == Learned(IF HELD_ADMISSIONS THEN RecsOf(s.recs \cup s.wait, db) ELSE RecsOf(s.got, db), pc.path, pc.cuts)
    IN ~IsChain(r) /\ r.id \notin s.chain
       /\ (~CP_OWN_HEAD \/ CpOwnOK(r))
       /\ (r.signer \in admins \/ OnList(pc.path, r.signer))
       /\ Within(pc.cuts, r)
Storable(s, r, db) ==
    StorableBut(s, r, db)
    /\ (s.checkpoint = 0 \/ Replaced(KeptCuts(s, db), db[s.checkpoint].signer)
        \/ ~PrunedBy(db[s.checkpoint], r))

\* Checkpoint c names r: r is one it keeps, or its key's record just below it.
NamedBy(c, r, items) ==
    \/ r.id \in c.keep
    \/ ((~PREV_ROOM_WHEN_KEPT \/ (PREV_NAMED /\ r.kind # "checkpoint")) /\ Len(c.line) >= 2 /\ c.line[Len(c.line) - 1] = r.id /\ r \in items)
FitsAlone(c, items, path, cuts) ==
    LET named == {r \in items : r = c \/ NamedBy(c, r, items)}
        ceil == Ceilings(path, Learned(named, path, cuts))
    IN SumU(named) <= ROOM
       /\ \A k \in {r.signer : r \in named} : k \in DOMAIN ceil /\ SumU(OfKey(named, k)) <= ceil[k]

\* (A re-signed removal Z counts only when a first checkpoint beside the chain keeps it.)
FirstsHeld(s, d) ==
    LET side == {c \in RecsOf(s.chain, d) : ~IsChain(c)}
        \* (WHOLE_BY_SETTLER: or a held later checkpoint keeps it.)
        cps == side \cup (IF WHOLE_BY_SETTLER THEN RecsOf(s.recs, d) ELSE {})
    IN {c \in side : c.kit # "z" \/ \E f \in cps : f.kind = "checkpoint" /\ c.id \in f.keep}

\* --- Evaluation -------------------------------------------------------------

RECURSIVE LabelFix(_, _, _, _)
LabelFix(toLabel, att, ins, outs) ==
    LET open == (toLabel \ ins) \ outs
        newOut == {b \in open : \E a \in att[b] : a \in ins}
        newIn == {b \in open : \A a \in att[b] : a \in outs}
    IN IF newOut = {} /\ newIn = {} THEN <<ins, outs>>
       ELSE LabelFix(toLabel, att, ins \cup newIn, outs \cup newOut)

Epoch(rs, path, cuts, anchors) ==
    LET cur == Last(path)
        adminKeys == Learned(rs, path, cuts)
        ids == IdsOf(rs)
        Saw(a, t) == SEEN_IGNORED \/ SawIn(a, t, ids, anchors)
        IsAdmin(r) == r.signer \in adminKeys /\ ~OnList(path, r.signer)
        OnPath(r) == ~IsAdmin(r) /\ OnList(path, r.signer) /\ Within(cuts, r)
        Early(r) == OnPath(r) /\ r.kind \in {"revoke", "freeze", "resolve"}
        FloorAt(r) ==
            Max2(MaxS({j - 1 : j \in {j \in 1..Len(r.line) : r.line[j] \in anchors}}, -1),
                 IF r.signer \in DOMAIN cuts THEN FloorOf(cuts[r.signer]) - 2 ELSE -1)
        Whole(r) ==
            \/ Early(r)
            \/ Replaced(cuts, r.signer)
            \/ LET f == FloorAt(r) IN \A i \in 1..Len(r.line) : i - 1 <= f \/ r.line[i] \in ids
        voids == {i \in {r.targetRec : r \in {r \in rs : OnPath(r) /\ r.kind = "resolve" /\ Whole(r)}} :
                    ~\E x \in rs : x.id = i /\ OnList(path, x.signer) /\ ~IsAdmin(x)}
        wholes == {r \in rs : Whole(r) /\ Within(cuts, r)}
        deadIds == {i \in voids : \E x \in rs : x.id = i /\ \E o \in rs : o # x /\ o.signer = x.signer /\ o.seq = x.seq}
        lives == {r \in wholes : ~\E j \in 1..Len(r.line) : r.line[j] \in deadIds}
        forkSeq == [k \in SIGNERS |-> MinS({r.seq : r \in {r \in lives : r.signer = k
                        /\ \E o \in lives : o # r /\ o.signer = k /\ o.seq = r.seq}}, NONE)]
        ForkAt(k) == IF k \in SIGNERS THEN forkSeq[k] ELSE NONE
        forks == {k \in SIGNERS : ForkAt(k) < NONE}
        heldPair == \E r \in rs : r.signer = cur /\ OnPath(r) /\ Within(cuts, r)
                      /\ \E o \in rs : o # r /\ o.signer = cur /\ o.seq = r.seq
        rootForked == ForkAt(cur) < NONE \/ heldPair
        \* F7_EVERY_KEY: a removal on a whole chain keeps barring on either history.
        BelowFork(r) == r.seq < ForkAt(r.signer) \/ r.kind = "revoke"
        Counted(r) == r \in lives /\ r.id \notin voids /\ BelowFork(r)
        RootRec(r) == OnPath(r) /\ Counted(r)
        Newer(a, b) ==
            LET pa == IndexOf(path, a.signer)
                pb == IndexOf(path, b.signer)
            IN pa > pb \/ (pa = pb /\ a.seq > b.seq)
        adminRecs == {r \in rs : r.kind = "admin" /\ RootRec(r)}
        named == {r.target : r \in adminRecs}
        adm == [a \in named |->
                  LET mine == {r \in adminRecs : r.target = a}
                      top == {r \in mine : \A o \in mine : o = r \/ Newer(r, o)}
                  IN IF top = {} THEN "" ELSE LET t == CHOOSE r \in top : TRUE IN IF t.kit = "z" THEN t.akit ELSE t.kit]
        Has(a, p) == a \in DOMAIN adm /\ p \in PowersOf(adm[a])
        IsAdminKey(k) == \E x \in WithPair(k) : x \in DOMAIN adm
        IsRootKey(k) == OnList(path, k)
        RootHas(d) == \E r \in rs : DevOf(r) = d /\ RootRec(r) /\ ~IsUpd(r)
        About(d) == {r \in rs : DevOf(r) = d /\ RootRec(r)}
        Replacers(k) ==
            IF k \notin DOMAIN DEV THEN {}
            ELSE LET naming == {r \in adminRecs : r.target = k}
                 IN {r \in About(DEV[k]) : ~(r.kind = "admin" /\ r.target = k) /\ \A n \in naming : Newer(r, n)}
        Current(k) == k \in DOMAIN adm /\ Replacers(k) = {}
        AdmittedBy(d) ==
            LET ok == {r \in rs : r.kind = "device" /\ ~IsUpd(r) /\ r.target = d /\ IsAdmin(r) /\ Counted(r) /\ Has(r.signer, "admit")}
                firsts == {r \in ok : ~\E o \in ok : o.signer = r.signer /\ o.seq < r.seq}
            IN IF RootHas(d) THEN -1 ELSE MinS({r.id : r \in firsts}, NONE)
        Permitted(r) ==
            IF r.signer \notin DOMAIN adm THEN FALSE
            ELSE IF IsUpd(r) THEN AdmittedBy(r.target) # NONE /\ Has(r.signer, "manage")
            ELSE IF r.kind = "device" THEN
                LET first == AdmittedBy(r.target)
                IN ~RootHas(r.target) /\ (first = r.id \/ (first # NONE /\ first # -1 /\ Has(r.signer, "manage")))
            ELSE IF r.kind = "revoke" THEN
                IF \E t \in Tgt(r) : IsRootKey(t) THEN FALSE
                ELSE IF IsAdminKey(r.target) THEN Has(r.signer, "removeAdmins")
                ELSE Has(r.signer, "remove")
            ELSE IF r.kind = "freeze" THEN
                Has(r.signer, "freeze") /\ (\E t \in Tgt(r) : t \in DOMAIN adm)
                /\ \A t \in Tgt(r) : ~Has(t, "removeAdmins")
            ELSE IF r.kind = "thaw" THEN Has(r.signer, "thaw") /\ Has(r.signer, "removeAdmins")
            ELSE IF r.kind = "copies" THEN TRUE
            ELSE FALSE
        ThawedFor(f, b) ==
            \E t \in rs : t.kind = "thaw" /\ t.targetRec = f.id
              /\ (OnPath(t) \/ (IsAdmin(t) /\ Has(t.signer, "thaw") /\ Has(t.signer, "removeAdmins")))
              /\ Saw(b, t)
        CutsOffRm(a, b) ==
            /\ a.kind \in {"revoke", "freeze"} /\ a # b /\ b.signer \in Tgt(a)
            /\ IF a.signer = b.signer THEN b.seq > a.seq ELSE ~Saw(a, b)
            /\ ~(a.kind = "freeze" /\ ThawedFor(a, b))
        CutsOff(a, b) ==
            IF a.kind = "thaw"
            THEN (\E f \in rs : f.id = a.targetRec /\ f.kind = "freeze" /\ CutsOffRm(f, b)) /\ ~Saw(a, b)
            ELSE CutsOffRm(a, b)
        rootThawed == {r.targetRec : r \in {r \in rs : r.kind = "thaw" /\ RootRec(r)}}
        rootActs == {r \in rs : RootRec(r)
                       /\ (r.kind = "revoke" \/ r.kind = "thaw" \/ (r.kind = "freeze" /\ r.id \notin rootThawed))}
        \* (SEEN_LINE: a's record counts only if it, or a record of a below it on its line, has a seen holding a
        \* root record naming a as admin at that record's seq or later, or is at or above a checkpoint anchor of a.)
        \* (architecture 11-15 00:56Z: judged on seq AND id: the entry at the naming record's seq is that held record.)
        SeenHoldsGrant(x, a) == \E n \in adminRecs : n.target = a /\ n.signer \in DOMAIN x.seen /\ Len(x.seen[n.signer]) >= n.seq
                                   /\ x.seen[n.signer][n.seq] = n.id
        \* (#530 30dcfafc eval find_grant_lines: after a change of root an anchor carries a record of a only when
        \* that record's seen names the current root at or above a record of it naming a, held or pruned.)
        AnchorOk(x, a) == Len(path) <= 1 \/ \E n \in adminRecs : n.target = a /\ n.signer = Last(path)
                             /\ n.signer \in DOMAIN x.seen /\ Len(x.seen[n.signer]) >= n.seq
        SeenOk(b) == ~SEEN_LINE \/ \E x \in rs : x.signer = b.signer /\ x.seq <= b.seq
                       /\ (SeenHoldsGrant(x, b.signer) \/ (x.id \in anchors /\ AnchorOk(x, b.signer)))
        toLabel == {r \in rs : IsAdmin(r) /\ Counted(r) /\ SeenOk(r)}
        outFirst == {b \in toLabel : ~Permitted(b) \/ (b.kind = "freeze" /\ b.id \in rootThawed)
                       \/ (\E a \in rootActs : CutsOff(a, b))
                       \/ (\E a \in Replacers(b.signer) : ~Saw(a, b))}
        att == [b \in toLabel |-> {a \in toLabel : a \notin outFirst
                   /\ (CutsOff(a, b) \/ (b.kind = "freeze" /\ a.kind = "thaw" /\ a.targetRec = b.id))}]
        labels == LabelFix(toLabel, att, {}, outFirst)
        ins == labels[1]
        undecided == (toLabel \ ins) \ labels[2]
        adminConflict == \E r \in undecided : r.kind \in {"revoke", "freeze", "thaw"}
        Counts(r) == RootRec(r) \/ (IsAdmin(r) /\ r \in ins)
        countsSet == {r \in rs : Counts(r)}
        revoked == UNION {Tgt(r) : r \in {r \in countsSet : r.kind = "revoke"}}
        frozen == UNION {Tgt(r) : r \in {r \in countsSet : r.kind = "freeze" /\ r.id \notin rootThawed}}
        currentAdmins == {a \in DOMAIN adm : Current(a) /\ a \notin revoked}
        stop == adminConflict \/ rootForked
        devices == {DevOf(r) : r \in {r \in countsSet : DevOf(r) # "" /\ ~IsUpd(r)}} \ revoked
    IN [path |-> path,
        counting |-> IdsOf(countsSet),
        revoked |-> revoked,
        frozen |-> frozen,
        admins |-> [a \in currentAdmins |-> adm[a]],
        stop |-> stop,
        devices |-> devices,
        commanders |-> IF rootForked THEN {}
                       ELSE {k \in currentAdmins \cup {cur} : k \notin revoked /\ k \notin frozen
                               /\ k \notin forks /\ (k = cur \/ ~stop)},
        rootsCount |-> \A r \in {r \in rs : OnPath(r) /\ r.signer = cur /\ Counted(r)} : Counts(r),
        cuts |-> cuts,
        checkpoint |-> 0]

\* The state with checkpoint c tried, or acc when c is 0 or does not count.
ApplyCheckpoint(path, cuts, c, acc) ==
    IF c = 0 THEN acc
    ELSE LET cps == {r \in acc.rs : r.id = c}
             cp == IF cps = {} THEN NONEREC ELSE CHOOSE r \in cps : TRUE
             ids == IdsOf(acc.rs)
             kept == {x \in acc.rs : x.id \in cp.keep}
             whole == cp.keep \subseteq ids
                      /\ \A r \in kept : (r.signer \notin DOMAIN cp.heads \/ r.seq <= Len(cp.heads[r.signer]))
                           /\ \A o \in kept : o = r \/ o.signer # r.signer \/ o.seq # r.seq
             pruned == {r \in acc.rs : ~PrunedByP(path, cp, r)}
             anchors == acc.anchors \cup AnchorsOf(cp)
             v == Epoch(pruned, path, cuts, anchors)
         IN IF cp # NONEREC /\ whole /\ FitsAlone(cp, acc.rs, path, cuts) /\ c \in v.counting
            THEN [rs |-> pruned, anchors |-> anchors, view |-> [v EXCEPT !.checkpoint = c]]
            ELSE acc

RootFloor(rs, ch, cur) ==
    LET hs == {i \in 1..Len(ch.recs) : ch.recs[i].target = cur}
    IN IF hs = {} \/ cur = ROOT THEN 0
       ELSE LET h == ch.recs[MaxS(hs, 0)]
                fc == {c \in rs : c.id = h.first}
            IN IF fc = {} THEN Max2(h.targetRec, 1) ELSE (CHOOSE c \in fc : TRUE).seq

\* Try the current root's checkpoints, the highest seq first; at one seq only the smallest ID
\* (Quint's fold over range(0, MAXREC + 2) does the same; seqs above MAXREC + 1 are tried too).
RECURSIVE TryCps(_, _, _, _, _)
TryCps(path, cuts, cs, seqs, acc) ==
    IF seqs = {} \/ acc.view.checkpoint # 0 THEN acc
    ELSE LET q == MaxS(seqs, 0)
             c == MinS({x.id : x \in {x \in cs : x.seq = q}}, 0)
         IN TryCps(path, cuts, cs, seqs \ {q}, ApplyCheckpoint(path, cuts, c, acc))

\* (E_STORED, conditional: a Device record that fails E is stored but does not count; D from the
\* current root's newest checkpoint among the records evaluated.)
EOldIn(rs, path, cuts, r) ==
    LET j == DJudge({x \in rs : x.signer = Last(path)})
        listedE == UNION {Range(cuts[x]) : x \in DOMAIN cuts}
    IN E_ALL /\ j.any /\ r.kind = "device" /\ r.ep < j.d /\ r.id \notin j.anch /\ r.id \notin listedE
FullEvaluate(rs00, ch) ==
    LET pc == PathCuts(ch)
        \* (LAST_ROOT: only the chain, the last root's records and the admin keys it named count.)
        lastR == Last(pc.path)
        namedL == {x.target : x \in {x \in rs00 : x.kind = "admin" /\ x.signer = lastR}}
        rs0 == IF LAST_ROOT THEN {r \in rs00 : IsChain(r) \/ r.signer = lastR \/ r.signer \in namedL} ELSE rs00
        rs == IF E_STORED THEN {r \in rs0 : ~EOldIn(rs0, pc.path, pc.cuts, r)} ELSE rs0
        cur == Last(pc.path)
        plain == Epoch(rs, pc.path, pc.cuts, {})
        forkS == MinS({a.seq : a \in {a \in rs : a.signer = cur /\ \E b \in rs : b # a /\ b.signer = cur /\ b.seq = a.seq}}, NONE)
        floor == RootFloor(rs, ch, cur)
        cs == {r \in rs : r.signer = cur /\ r.kind = "checkpoint" /\ Within(plain.cuts, r) /\ r.seq < forkS /\ r.seq >= floor}
        v == TryCps(pc.path, pc.cuts, cs, {x.seq : x \in cs}, [rs |-> rs, anchors |-> {}, view |-> plain]).view
    IN IF ch.stop THEN [v EXCEPT !.stop = TRUE, !.commanders = {}] ELSE v

\* --- What a set keeps -------------------------------------------------------

\* (E_CUR, architecture 17:52Z: D = the drops of the current root's newest checkpoint the member
\* got, counting or not, no memory; an older-epoch device record stays only as that checkpoint
\* keeps or anchors it, or the list keeps it.)
EOld(s, path, cuts, r, db) ==
    LET j == DJudge({x \in RecsOf(s.got, db) : x.signer = Last(path)})
        listedE == UNION {Range(cuts[x]) : x \in DOMAIN cuts}
    IN E_ALL /\ r.kind = "device" /\ r.ep < j.d /\ r.id \notin j.anch /\ r.id \notin listedE
Settle0(s, items, cut, db) ==
    LET ch == ChainState(s, db)
        pc == PathCuts(ch)
        path == pc.path
        cuts == pc.cuts
        cur == Last(path)
        ord == [roots |-> RootsOf(path), cuts |-> cuts, top |-> TopOf(s, cur, db)]
        src == IF TWO_TIERS THEN RecsOf(s.recs \cup s.wait, db) ELSE RecsOf(s.got, db)
        admins == Learned(src, path, cuts)
        sec == SecondOf(src, path, cuts)
        oldOut(r) == ~E_STORED /\ EOld(s, path, cuts, r, db)
        shown == {r \in items : Within(cuts, r) /\ ~oldOut(r)}
        ceil == Ceilings(path, admins)
        plain == KeepInS(shown, ceil, cut, cur, ord, ROOM, EmptyFn, sec)
        cps == {c \in shown : c.kind = "checkpoint" /\ c.signer = cur}
        named == {r \in shown : (r \in cps \/ \E c \in cps : NamedBy(c, r, shown)) /\ r.id \notin plain.kept}
    IN IF named = {} THEN plain
       ELSE LET firsts == FirstsHeld(s, db)
                v == FullEvaluate(RecsOf(plain.kept, db) \cup named \cup firsts, ch)
            IN IF ~\E c \in cps : c.id = v.checkpoint THEN plain
               ELSE LET c == db[v.checkpoint]
                        left == {r \in shown : ~PrunedByP(path, c, r)}
                        first == {r \in left : r = c \/ NamedBy(c, r, shown)}
                        ceil2 == [k \in DOMAIN ceil |-> ceil[k] - SumU(OfKey(first, k))]
                        room2 == ROOM - SumU(first)
                    IN IF room2 < 0 \/ (\E k \in DOMAIN ceil2 : ceil2[k] < 0) \/ (\E r \in first : r.signer \notin DOMAIN ceil)
                       THEN plain
                       ELSE LET waits == IF WAIT_SKIP THEN {x \in left \ first : x \in cps} ELSE {}
                                rest0 == KeepInS((left \ first) \ waits, ceil2, NOCUT, cur, ord, room2,
                                                [k \in DOMAIN ceil |-> SumU(OfKey(first, k))], sec)
                                base == RecsOf(rest0.kept, db) \cup first
                                fitW == {w \in waits :
                                           LET upTo == {o \in waits : o.seq > w.seq \/ (o.seq = w.seq /\ o.id <= w.id)}
                                           IN SumU(base) + SumU(upTo) <= ROOM
                                              /\ SumU(OfKey(base, w.signer)) + SumU(upTo) <= ceil[w.signer]}
                                rest == [kept |-> rest0.kept \cup IdsOf(fitW), cut |-> rest0.cut]
                                res == [kept |-> rest.kept \cup IdsOf(first), cut |-> rest.cut]
                            IN IF FullEvaluate(RecsOf(res.kept, db) \cup firsts, ch).checkpoint = c.id THEN res ELSE plain

\* (HELD_ADMISSIONS: the records of a key whose admission the rooms did not keep leave; the
\* rooms are not judged again.)
Settle(s, items, cut, db) ==
    IF ~HELD_ADMISSIONS THEN Settle0(s, items, cut, db)
    ELSE LET pc == PathCuts(ChainState(s, db))
             r1 == Settle0(s, items, cut, db)
             ok == Learned(RecsOf(r1.kept, db), pc.path, pc.cuts)
         IN [r1 EXCEPT !.kept = {i \in r1.kept : OnList(pc.path, db[i].signer) \/ db[i].signer \in ok}]
Recut(s, db) == LET res == Settle(s, RecsOf(s.recs, db), s.cut, db) IN [s EXCEPT !.recs = res.kept, !.cut = res.cut]

WaitingCps(s, db) ==
    LET cseq == IF s.checkpoint = 0 THEN 0 ELSE db[s.checkpoint].seq
        cur == Last(KeptPath(s, db))
    IN {c \in RecsOf(s.recs \cup s.wait, db) : c.kind = "checkpoint" /\ c.signer = cur /\ c.seq > cseq}
StorableW(s, r, db) ==
    Storable(s, r, db) \/ (StorableBut(s, r, db) /\ \E c \in WaitingCps(s, db) : r.id \in c.keep)

AsideGroup(x, cands) ==
    LET ks == {c \in cands : x.id \in c.keep \/ (Len(c.line) >= 2 /\ c.line[Len(c.line) - 1] = x.id) \/ c = x}
        top == MaxS({c.seq : c \in ks}, 0)
    IN <<top, MinS({c.id : c \in {c \in ks : c.seq = top}}, NONE)>>
AsideBefore(y, x, cands) ==
    LET gy == AsideGroup(y, cands)
        gx == AsideGroup(x, cands)
    IN \/ gy[1] > gx[1]
       \/ (gy[1] = gx[1] /\ gy[2] < gx[2])
       \/ (gy = gx /\ (gy = <<y.seq, y.id>> \/ (gx # <<x.seq, x.id>> /\ (y.seq < x.seq \/ (y.seq = x.seq /\ y.id <= x.id)))))

AsideOf(s1, pool, db) ==
    LET ch == ChainState(s1, db)
        pc == PathCuts(ch)
        cur == Last(pc.path)
        v == FullEvaluate(RecsOf(s1.recs, db) \cup FirstsHeld(s1, db), ch)
        cseq == IF v.checkpoint = 0 THEN 0 ELSE db[v.checkpoint].seq
        forkS == MinS({a.seq : a \in {a \in pool : a.signer = cur /\ \E b \in pool : b # a /\ b.signer = cur /\ b.seq = a.seq}}, NONE)
        floor == RootFloor(pool \cup FirstsHeld(s1, db), ch, cur)
        cands == {c \in pool : c.kind = "checkpoint" /\ c.signer = cur /\ c.seq > cseq /\ c.seq < forkS
                    /\ c.seq >= floor /\ StorableW(s1, c, db) /\ FitsAlone(c, pool, pc.path, pc.cuts)}
        all1 == {x \in pool : x.id \notin s1.recs /\ StorableW(s1, x, db)
                   /\ ((\E c \in cands : x.id \in c.keep \/ NamedBy(c, x, pool)) \/ x \in cands)}
    IN IF ch.stop THEN {}
       ELSE IdsOf({x \in all1 : SumU({y \in all1 : AsideBefore(y, x, cands)}) <= ASIDE_ROOM})

WithWait(s1, pool, db) ==
    LET aside == AsideOf(s1, pool, db)
        ch == ChainState(s1, db)
        all1 == RecsOf(s1.recs \cup aside, db)
        v == FullEvaluate(RecsOf(s1.recs, db) \cup FirstsHeld(s1, db), ch)
        v2 == FullEvaluate(all1 \cup FirstsHeld(s1, db), ch)
    IN IF v2.checkpoint # 0 /\ v2.checkpoint # v.checkpoint
       THEN LET c == db[v2.checkpoint]
                take == {i \in aside : i = c.id \/ NamedBy(c, db[i], all1)}
                s1c == [s1 EXCEPT !.recs = @ \cup take, !.checkpoint = c.id]
                s2 == Recut([s1c EXCEPT !.recs = {i \in s1c.recs : Storable(s1c, db[i], db)}], db)
            IN [s2 EXCEPT !.wait = AsideOf(s2, pool, db)]
       ELSE [s1 EXCEPT !.wait = aside]

\* (TWO_TIERS, core set.rs beyond: a record that comes after every record its key holds, with
\* which the key would pass its share at the levels of the last judgment, is turned away unjudged;
\* a checkpoint or an early root record never is.)
BeyondT(s, r, db) ==
    LET pc == PathCuts(ChainState(s, db))
        src == RecsOf(s.recs \cup s.wait, db)
        ceil == Ceilings(pc.path, Learned(src, pc.path, pc.cuts))
        ord == OrderOf(s, db)
        cur == Last(pc.path)
        k == r.signer
        mine == OfKey(RecsOf(s.recs, db), k)
        share == IF k \in SecondOf(src, pc.path, pc.cuts) THEN s.cut.level2 ELSE s.cut.level
    IN /\ r.kind # "checkpoint"
       /\ ~(r.signer \in ord.roots /\ r.kind \in {"revoke", "freeze", "resolve"})
       /\ k \in DOMAIN ceil
       /\ SumU(mine) + r.units > Min2(share, ceil[k])
       /\ \A x \in mine : Pos(x, cur, ord) < Pos(r, cur, ord)
StoreOne(s0, r, db) ==
    IF r.id \in s0.recs \/ r.id \in s0.wait \/ ~StorableW(s0, r, db) THEN s0
    ELSE LET cur0 == Last(KeptPath(s0, db))
             \* (NEWEST_CP_FIRST: a newer checkpoint of the current root resets its key's marks.)
             s == IF NEWEST_CP_FIRST /\ r.kind = "checkpoint" /\ r.signer = cur0 /\ r.seq > TopOf(s0, cur0, db)
                  THEN [s0 EXCEPT !.cut = [@ EXCEPT !.marks = [k \in DOMAIN @ \ {cur0} |-> @[k]]]]
                  ELSE s0
             pool == RecsOf(s.recs \cup s.wait, db) \cup {r}
             cur == Last(KeptPath(s, db))
             cps == {c \in pool : c.kind = "checkpoint" /\ c.signer = cur /\ StorableW(s, c, db)}
             back == {x \in pool : (x \in cps \/ \E c \in cps : NamedBy(c, x, pool))
                         /\ x.id \notin s.recs /\ Storable(s, x, db)}
             turned == (IF TWO_TIERS THEN TIER_MODE = "levels" /\ BeyondT(s, r, db) ELSE Past(s.cut, r, cur, OrderOf(s, db))) /\ r \notin back
             add == IF turned \/ ~Storable(s, r, db) THEN IdsOf(back) ELSE IdsOf(back) \cup {r.id}
             s1 == IF add = {} THEN s ELSE IF REISSUE_MUT = "noRecut" THEN [s EXCEPT !.recs = @ \cup add] ELSE Recut([s EXCEPT !.recs = @ \cup add], db)
         IN WithWait(s1, pool, db)

RECURSIVE StoreAll(_, _, _)
StoreAll(s, l, db) == IF l = <<>> THEN s ELSE StoreAll(StoreOne(s, db[Head(l)], db), Tail(l), db)

Pathed(s, db) ==
    LET pc == PathCuts(ChainState(s, db))
    IN IF pc.path = s.path /\ pc.cuts = s.cuts THEN s
       ELSE LET s2 == [s EXCEPT !.path = pc.path, !.cuts = pc.cuts, !.cut = NOCUT, !.wait = {}]
            IN Recut([s2 EXCEPT !.recs = {i \in s2.recs : Storable(s2, db[i], db)}], db)

Reopen(s2, db) ==
    LET s3 == Recut([s2 EXCEPT !.cut = NOCUT, !.recs = {i \in s2.recs : Storable(s2, db[i], db)}], db)
        left == {x \in RecsOf(s2.wait, db) : ~IsChain(x) /\ x.id \notin s3.recs}
    IN IF REISSUE_MUT = "noReopen" THEN [s3 EXCEPT !.wait = {}] ELSE StoreAll([s3 EXCEPT !.wait = {}], ToList(IdsOf(left)), db)

CompactStore(s, v, db) ==
    IF v.checkpoint = s.checkpoint THEN s
    ELSE IF CUT_RESET_ON_DROP /\ v.checkpoint # 0 /\ ~\E r \in RecsOf(s.recs, db) : PrunedBy(db[v.checkpoint], r)
    THEN Recut([s EXCEPT !.checkpoint = v.checkpoint], db)
    ELSE Reopen([s EXCEPT !.checkpoint = v.checkpoint, !.cut = NOCUT], db)

ValidHead(s, h, db) ==
    LET ch == IF FIRST_NEWEST_ONLY THEN ChainRaw(RecsOf(s.chain, db)) ELSE ChainState(s, db)
        below == h.seq - 1
    IN below <= Len(ch.ids) /\ SubSeq(ch.ids, 1, below) = SubSeq(h.line, 1, below)
       /\ ValidAt(h, PathCutsOf(SubSeq(ch.recs, 1, below)).path)
Gather(s, db) ==
    LET heads == {h \in RecsOf(s.chain, db) : IsChain(h) /\ ValidHead(s, h, db)}
        firsts == IdsOf({c \in RecsOf(s.got, db) : \E h \in heads : NamesFirst(h, c) \/ NamesZ(h, c)})
    IN [s EXCEPT !.chain = @ \cup firsts]
RECURSIVE GatherN(_, _, _)
GatherN(s, n, db) == IF n = 0 THEN s ELSE GatherN(Gather(s, db), n - 1, db)
ApplyChain(s, db) ==
    LET s1 == GatherN(s, MAXCHAIN, db)
        s2 == Pathed([s1 EXCEPT !.recs = @ \ s1.chain], db)
        ek == IF EARLY_ROOM THEN EarlyKept(s1, db) ELSE {}
        fresh == {x \in RecsOf(IF SETTLER_HELD THEN HeldOf(s, db) \cup s1.chain ELSE s2.got, db) : ~IsChain(x) /\ OnList(s2.path, x.signer) /\ ~OnList(s.path, x.signer)
                    /\ (~EARLY_ROOM \/ x.id \in s1.chain \/ x.id \in ek)}
    IN LET s5 == StoreAll(s2, ToList(IdsOf(fresh)), db)
       IN IF SETTLER_HELD THEN [s5 EXCEPT !.side = {i \in @ : ~OnList(s5.path, db[i].signer)}] ELSE s5

InsertInto(s0, r, db) ==
    LET early0 == {h.target : h \in {h \in RecsOf(s0.chain, db) : IsChain(h) /\ ~OnList(s0.path, h.target)}}
        s == [s0 EXCEPT !.got = @ \cup {r.id},
                        !.side = IF SETTLER_HELD /\ ~IsChain(r) /\ r.signer \in early0 /\ r.id \notin s0.chain THEN @ \cup {r.id} ELSE @]
    IN IF IsChain(r) THEN ApplyChain([s EXCEPT !.chain = @ \cup {r.id}], db)
       ELSE LET isFirst == \E h \in RecsOf(s.chain, db) : NamesFirst(h, r) \/ NamesZ(h, r)
                             \/ (WHOLE_BY_SETTLER /\ IsChain(h) /\ r.kind = "checkpoint" /\ r.signer = h.target)
            IN IF ChainState(s, db).stop THEN (IF isFirst THEN ApplyChain(s, db) ELSE s)
               ELSE LET lastRoot == Last(KeptPath(s, db))
                        twin == IF r.signer # lastRoot THEN {}
                                ELSE {o \in RecsOf(s.got, db) : o.id # r.id /\ ~IsChain(o) /\ o.signer = r.signer /\ o.seq = r.seq}
                        s1 == IF twin = {} THEN s
                              ELSE Reopen([s EXCEPT !.chain = @ \cup IdsOf(twin) \cup {r.id}, !.recs = @ \ IdsOf(twin)], db)
                        s3 == StoreOne(IF isFirst THEN ApplyChain(s1, db) ELSE s1, r, db)
                        \* (records 9dd3d9c8 (b): while a held head waits, any record re-chains.)
                    IN IF WHOLE_BY_SETTLER /\ ((LET cids == Range(ChainState(s3, db).ids) IN \E h \in RecsOf(s3.chain, db) : IsChain(h) /\ h.id \notin cids)
                                              \/ (SETTLER_HELD /\ KeptPath(s3, db) # s3.path))
                       THEN ApplyChain(s3, db) ELSE s3

RECURSIVE InsertAll(_, _, _)
InsertAll(s, l, db) == IF l = <<>> THEN s ELSE InsertAll(InsertInto(s, db[Head(l)], db), Tail(l), db)

StoreView(s, db) ==
    FullEvaluate(RecsOf(Settle(s, RecsOf(s.recs, db), NOCUT, db).kept, db) \cup FirstsHeld(s, db), ChainState(s, db))
PureKept(s, db) == Settle(s, {r \in RecsOf(s.got, db) : Storable(s, r, db)}, NOCUT, db).kept
PureView(s, db) == FullEvaluate(RecsOf(PureKept(s, db), db) \cup FirstsHeld(s, db), ChainState(s, db))

Settled(s2, db2) == LET s3 == Pathed(s2, db2) IN CompactStore(s3, StoreView(s3, db2), db2)
Finish(s2, db2) == LET s4 == Settled(Settled(s2, db2), db2) IN <<s4, StoreView(s4, db2)>>

EMPTY == [recs |-> {}, got |-> {}, chain |-> {}, cut |-> NOCUT, path |-> <<ROOT>>, cuts |-> EmptyFn,
          checkpoint |-> 0, wait |-> {}, side |-> {}]
STARTSTORE == InsertAll(EMPTY, ToList(DOMAIN START), START)

RootRemoved(v, db) ==
    UNION {Tgt(r) : r \in {r \in RecsOf(v.counting, db) : r.kind = "revoke" /\ OnList(v.path, r.signer)}}

\* --- The system ---------------------------------------------------------------

VARIABLES db, nextId, st, views, gone, welcomed
vars == <<db, nextId, st, views, gone, welcomed>>

Init ==
    /\ db = START
    /\ nextId = FIRST
    /\ st = [m \in MEMBERS |-> STARTSTORE]
    /\ views = [m \in MEMBERS |-> StoreView(STARTSTORE, START)]
    /\ gone = [m \in MEMBERS |-> {}]
    /\ welcomed = <<>>

AllRecs == {db[i] : i \in DOMAIN db}
CP_UNITS == 2
\* (WRITER_CP_FLOOR, decided 11-14 08:28Z: a margin of the root's ceiling stays for removals; the
\* core's 1/24 of 1536, at least two exempt records; two units here.)
REMOVAL_MARGIN == 2
\* (WRITER_CP_FLOOR: a root's removal and its resolve share the margin.)
FloorExempt(r) == RootRemoval(r) \/ (r.kind = "resolve" /\ r.signer \in ROOT_KEYS)
\* (The units of root k's records a set holds, its checkpoints left out.)
RootUnits(s, k, d) == SumU({x \in OfKey(RecsOf(s.recs, d), k) : x.kind # "checkpoint"})
\* (CP_KEEP_LIVE: the honest root checkpoint keeps only the newest record of each device and of
\* each writer's settings, and folds admins' removals with the device records they removed.)
LiveKeep(counted, mine) ==
    LET k0 == {x \in counted : x.id \notin DroppedAt(mine, counted)}
        admRm == {x \in k0 : x.kind = "revoke" /\ x.signer \notin ROOT_KEYS}
        k1 == {x \in k0 : x \notin admRm /\ ~(x.kind = "device" /\ \E a \in admRm : x.target \in Tgt(a))}
    IN IdsOf({x \in k1 : ~(x.kind = "device" /\ \E y \in k1 : y.kind = "device" /\ y.target = x.target /\ y.id > x.id)
                         /\ ~(x.kind = "copies" /\ \E y \in k1 : y.kind = "copies" /\ y.signer = x.signer /\ y.id > x.id)})
HonestKeepOf(k, counted, mine) ==
    IF CP_KEEP_LIVE /\ k \in ROOT_KEYS THEN LiveKeep(counted, mine)
    ELSE IdsOf(counted) \ (IF k \in ROOT_KEYS THEN DroppedAt(mine, counted) ELSE {})
\* KEEP_V2 (code #530 88b56f5d, set.rs checkpoint_body): what root k's checkpoint keeps, from its
\* store s, view vh and heads seen. Heads: none for other roots on the path (their records stay only
\* as the list keeps them: here, as they count). A removal goes, with the records naming its keys,
\* when it is under a head and every key it names is settled: admissions held, none of an admin key,
\* all under heads, nothing the key signed counts. A root removal a later one covers goes (the fold:
\* path position then seq, keys a superset, the same seen on what it concerns). The root's own older
\* copies under its head go. Kept: held records, counting ones and the root's own, below a head, not
\* a head itself, not the root's own checkpoints; a resolve whose every target goes is left out.
HonestKeepV2(k, s, vh, seen) ==
    LET mine == RecsOf(s.recs, db)
        aside == RecsOf(s.wait \cup s.side, db)
        all == {r \in mine \cup aside \cup RecsOf(s.chain, db) : ~IsChain(r)}
        cnt == RecsOf(vh.counting, db)
        path == vh.path
        HS(x) == IF OnList(path, x) /\ x # k THEN 0 ELSE Len(LineOf(seen, x))
        listed(r) == OnList(path, r.signer) /\ r.signer # k /\ r \in cnt
        below(r) == listed(r) \/ r.seq <= HS(r.signer)
        under(r) == listed(r) \/ r.seq < HS(r.signer)
        adms(key) == AdmissionsOf(all, key)
        settled(key) ==
            /\ UNKNOWN_DROP \/ adms(key) # {}
            /\ key \notin DOMAIN DEV /\ key \notin DEVS /\ key \notin SIGNERS
            /\ \A a \in adms(key) : a.kind = "device" /\ under(a)
            /\ SETTLED_ANY_SIGNED \/ ~\E x \in cnt : x.signer = key
        \* (NEVER_DROP, calibration only: removals never drop, only fold.)
        \* (W: every live admin key has a counting record whose seen holds the removal's signer at its seq or later.)
        \* (GRANT_ABOVE: a root removal does not wait for an admin key whose every naming record by that root is above it.)
        grantedAbove(a, r) == GRANT_ABOVE /\ r.signer = Last(path)
            /\ LET ns == {n \in cnt : n.kind = "admin" /\ n.target = a /\ n.signer = r.signer} IN ns # {} /\ \A n \in ns : n.seq > r.seq
        acked(r) == ~W \/ \A a \in DOMAIN vh.admins : grantedAbove(a, r)
            \/ \E x \in cnt : x.signer = a /\ r.signer \in DOMAIN x.seen /\ Len(x.seen[r.signer]) >= r.seq
        dropped0 == {r \in cnt : ~NEVER_DROP /\ r.kind = "revoke" /\ under(r) /\ acked(r) /\ \A key \in Tgt(r) : settled(key)}
        goneK == UNION {Tgt(r) : r \in dropped0}
        rms == {r \in all : RootRemoval(r) /\ OnList(path, r.signer) /\ r \notin dropped0}
        Later(a, b) == IndexOf(path, a.signer) > IndexOf(path, b.signer)
                       \/ (a.signer = b.signer /\ a.seq > b.seq)
        folded == {r \in rms : under(r) /\ r \in cnt /\ \E n \in rms : n # r /\ Later(n, r)
                     /\ Tgt(r) \subseteq Tgt(n) /\ \A x \in Tgt(r) \cup DOMAIN r.seen : LineOf(r.seen, x) = LineOf(n.seen, x)}
        ownCopies == {r \in mine : r.signer = k /\ r.kind = "copies"}
        newestCopy == {r \in ownCopies : \A o \in ownCopies : o.seq <= r.seq}
        sup == IF newestCopy # {} /\ newestCopy \subseteq cnt
               THEN {r \in ownCopies : r \notin newestCopy /\ under(r)} ELSE {}
        dropped == IdsOf(dropped0) \cup IdsOf(folded) \cup IdsOf(sup)
        headIds == {LineOf(seen, x)[HS(x)] : x \in {x \in DOMAIN seen : HS(x) > 0}}
        Names(r) == r.kind \in {"device", "admin"} /\ r.target \in goneK
        \* (HEAD_KEPT, #530 9e20ec86: a counting head of another key goes into keep, not only anchors.)
        keep0 == {r \in all : (r.id \notin headIds \/ (HEAD_KEPT /\ r.signer # k /\ r \in cnt)) /\ r.id \notin dropped /\ below(r) /\ ~Names(r)
                     /\ ~(r.signer = k /\ r.kind = "checkpoint")
                     /\ (r \in aside \/ r \in cnt \/ listed(r) \/ r.signer = k)}
        keepIds == IdsOf(keep0)
        goes(i) == i \notin keepIds /\ i \notin headIds /\ i \in DOMAIN db /\ below(db[i])
        void == {r \in keep0 : r.kind = "resolve" /\ under(r) /\ r.targetRec # 0 /\ goes(r.targetRec)}
    IN keepIds \ IdsOf(void)

Put(f, k, v) == [x \in DOMAIN f \cup {k} |-> IF x = k THEN v ELSE f[x]]

\* A record of a non-root key that no record of that key at or below it saw the current root's grant in.
VoidAt(m, r) ==
    LET cur == Last(views[m].path)
    IN SEEN_LINE /\ r.signer \notin ROOT_KEYS
       /\ ~\E x \in RecsOf(st[m].got \cap DOMAIN db, db) \cup {r} : x.signer = r.signer /\ x.seq <= r.seq
             /\ \E i \in DOMAIN db : db[i].kind = "admin" /\ db[i].target = r.signer /\ db[i].signer = cur
                  /\ cur \in DOMAIN x.seen /\ Len(x.seen[cur]) >= db[i].seq

\* (Each argument is bound once by \E over a one-element set: TLC does not cache LET values
\* inside an action, so a value used several times would be computed again each time.)
\* (E_EPOCH: each record signed in this step gets its epoch from what its writer m holds:
\* a root checkpoint the highest drops it holds, plus one if it leaves out a removal no record it
\* keeps or names covers; an admin's device record the drops of the checkpoint counting at m.)
\* (g, vw: the writer's state after the write; with CHANGE_AT_NEW it holds what it took from the recovery key's device.)
EpNew(d, i, m, g, vw) ==
    LET r == d[i]
        v == vw
        news == {j \in nextId..(i - 1) : j \in DOMAIN d}
        ids == (st[m].got \cup g \cup news) \cap DOMAIN d
        cps == {d[j] : j \in {j \in ids : d[j].kind = "checkpoint" /\ d[j].signer \in ROOT_KEYS}}
        prev == MaxS({x.ep : x \in {x \in cps : ~E_ALL \/ OnList(v.path, x.signer)}}, 0)
        \* (E_CUR: a device record's epoch is the writer's D: its current root's newest checkpoint's drops.)
        ccs == {x \in cps : x.signer = Last(v.path)}
        dcur == DJudge({d[j] : j \in {j \in ids : d[j].signer = Last(v.path)}}).d
        anchorsNew == {Last(r.heads[x]) : x \in {x \in DOMAIN r.heads : Len(r.heads[x]) > 0}}
        kept == {d[j] : j \in (r.keep \cup anchorsNew \cup news) \cap DOMAIN d}
        leaves == \E x \in RecsOf(v.counting \cap DOMAIN d, d) :
                    /\ x.kind = "revoke" /\ x.id \notin r.keep /\ x.id \notin anchorsNew
                    /\ ~\E n \in kept : n.kind = "revoke" /\ Tgt(x) \subseteq Tgt(n)
    IN IF r.kind = "checkpoint" /\ r.signer \in ROOT_KEYS THEN prev + (IF leaves THEN 1 ELSE 0)
       ELSE IF E_ALL /\ r.kind = "device" THEN dcur
       ELSE IF r.kind = "device" /\ ~OnList(v.path, r.signer)
            THEN (IF v.checkpoint = 0 \/ v.checkpoint \notin DOMAIN d THEN 0 ELSE d[v.checkpoint].ep)
       ELSE 0
WithEp(d, n2, m, g, vw) ==
    [i \in DOMAIN d |-> IF i >= nextId /\ i < n2 THEN [d[i] EXCEPT !.ep = EpNew(d, i, m, g, vw)] ELSE d[i]]
\* The writer's view when it signs: before the new records, after what it took from the recovery key's device (CHANGE_AT_NEW).
PreView(m, s2, n2) ==
    LET extra == (s2.got \ st[m].got) \ {j \in nextId..(n2 - 1) : TRUE}
    IN IF ~CHANGE_AT_NEW \/ extra = {} THEN views[m] ELSE Finish(InsertAll(st[m], ToList(extra), db), db)[2]
Commit(db2, n2, m, s2) ==
    \E d \in {IF E_EPOCH /\ n2 > nextId THEN WithEp(db2, n2, m, s2.got, PreView(m, s2, n2)) ELSE db2} : \E sv \in {Finish(s2, d)} :
    /\ db' = d
    /\ nextId' = n2
    /\ st' = [st EXCEPT ![m] = sv[1]]
    /\ views' = [views EXCEPT ![m] = sv[2]]
    /\ gone' = [gone EXCEPT ![m] = @ \cup RootRemoved(sv[2], d)]
    /\ welcomed' = welcomed

\* (CHANGE_AT_NEW: the recovery key's device m2 keeps what it signed: it gets the new chain records too.)
Commit2(db2, n2, m, s2, m2) ==
    IF m2 = m THEN Commit(db2, n2, m, s2) ELSE
    \E d \in {IF E_EPOCH /\ n2 > nextId THEN WithEp(db2, n2, m, s2.got, PreView(m, s2, n2)) ELSE db2} :
    \E sv \in {Finish(s2, d)} :
    \E sv2 \in {Finish(InsertAll(st[m2], ToList({i \in nextId..(n2 - 1) : i \in DOMAIN d /\ IsChain(d[i])}), d), d)} :
    /\ db' = d
    /\ nextId' = n2
    /\ st' = [st EXCEPT ![m] = sv[1], ![m2] = sv2[1]]
    /\ views' = [views EXCEPT ![m] = sv[2], ![m2] = sv2[2]]
    /\ gone' = [gone EXCEPT ![m] = @ \cup RootRemoved(sv[2], d), ![m2] = @ \cup RootRemoved(sv2[2], d)]
    /\ welcomed' = welcomed

CommitAll(nx) ==
    \E f \in {nx} :
    /\ db' = db
    /\ nextId' = nextId
    /\ st' = [m \in MEMBERS |-> f[m][1]]
    /\ views' = [m \in MEMBERS |-> f[m][2]]
    /\ gone' = [m \in MEMBERS |-> gone[m] \cup RootRemoved(f[m][2], db)]
    /\ welcomed' = welcomed

CapFits(h, target) ==
    ROOTC + RESERVE
      + Cardinality({x \in Learned(RecsOf(st[h].recs, db), views[h].path, views[h].cuts) \cup {target} :
                       ~OnList(views[h].path, x)}) * ADMINC
    <= ROOM
CeilFits(k, units) ==
    LET h == HOLDER[k] IN
    SumU(OfKey(RecsOf(st[h].recs, db), k)) + units <= (IF OnList(views[h].path, k) THEN ROOTC ELSE ADMINC)

\* k signs a record; its own device stores it at once (signFullX of the Quint model).
\* (WRITER_LAST_ROOT: the honest checkpoint writer first takes its own key's records and the
\* recovery records that made its key a root.)
WithOwn(s, k, d) ==
    LET heads == {i \in DOMAIN d : IsChain(d[i]) /\ d[i].target = k}
        ids == {i \in DOMAIN d : d[i].signer = k /\ ~d[i].off}
               \cup UNION {{d[i].line[x] : x \in 1..Len(d[i].line)} : i \in heads}
    IN InsertAll(s, ToList(ids \ s.got), d)
SignFullX(k, kind, target, kit, targetRec, pretend, fork, units, hidden, extraKeep, keeps) ==
    LET h == HOLDER[k]
        aug == WRITER_LAST_ROOT /\ kind = "checkpoint" /\ kit # "deviant" /\ ~hidden
    IN \E s \in {IF aug THEN WithOwn(st[h], k, db) ELSE st[h]} :
       \E vh \in {IF aug THEN StoreView(s, db) ELSE views[h]} :
    LET mine == RecsOf(s.recs, db)
        own == HeadLine(AllRecs, k)
        base == IF fork /\ Len(own) > 0 THEN SubSeq(own, 1, Len(own) - 1) ELSE own
        seen0 == [x \in SIGNERS |-> IF x = k THEN base ELSE HeadLine(mine, x)]
        seen1 == IF pretend THEN [x \in SIGNERS |-> IF x # k /\ x \in THIEVES THEN <<>> ELSE seen0[x]] ELSE seen0
        seen == IF kind \in {"revoke", "freeze"} THEN [x \in {x \in SIGNERS : x \in WithPair(target)} |-> seen1[x]] ELSE seen1
        isCp == kind = "checkpoint"
        counted == {x \in RecsOf(vh.counting, db) : x.kind # "checkpoint"}
        \* (#530 checkpoint_body: a checkpoint names a key's head only at its newest record that counts at the
        \* writer, nothing if none counts; the writer's own line and root keys as held.)
        CountHead(x) == LET cs == {y \in counted : y.signer = x}
                            m == MaxS({y.seq : y \in cs}, 0)
                        IN IF cs = {} \/ Len(seen[x]) < m THEN <<>> ELSE SubSeq(seen[x], 1, m)
        cpHeads == [x \in DOMAIN seen |-> IF ~isCp \/ x = k \/ x \in ROOT_KEYS \/ kit = "deviant" \/ hidden THEN seen[x] ELSE CountHead(x)]
        honestKeep == IF KEEP_V2 /\ isCp /\ k \in ROOT_KEYS THEN HonestKeepV2(k, s, vh, cpHeads) ELSE HonestKeepOf(k, counted, mine)
        r == Rec(nextId, k, Append(base, nextId), kind, target,
                 IF isCp /\ ~(extraKeep \subseteq honestKeep) THEN "bent" ELSE kit, targetRec,
                 seen, IF isCp THEN cpHeads ELSE EmptyFn, IF isCp THEN honestKeep \cup extraKeep ELSE {}, units)
        \* (UPD: an honest writer marks a record for a device that already counts at it as an update.)
        db2 == Put(db, nextId, [r EXCEPT !.off = hidden, !.upd = IF UPD /\ kind = "device" /\ target \in vh.devices THEN 1 ELSE 0,
                                        !.spare = IF SPARE /\ kind = "copies" /\ kit # "deviant" /\ ~hidden /\ ~OnList(vh.path, k) THEN SpareOf(k) ELSE ""])
    IN /\ k \in SIGNERS
       /\ nextId <= LASTID
       \* (FRESH_KEY: an honest signer writes a Device record only in the one pairing with that key,
       \* or for a key that already counts at it.)
       /\ ~FRESH_KEY \/ kind # "device" \/ kit = "deviant" \/ hidden \/ target \in vh.devices
          \/ ~\E i \in DOMAIN db : db[i].kind = "device" /\ db[i].target = target /\ db[i].upd = 0
       /\ ~fork \/ Len(own) > 0
       /\ ~aug \/ Last(vh.path) = k
       \* (Owner 11-15 12:20Z: after a change of root an admin key is always a new key: an honest writer
       \* does not name as admin a key an earlier root on its path named.)
       /\ kind # "admin" \/ kit = "deviant" \/ hidden
          \/ ~\E i \in DOMAIN db : db[i].kind = "admin" /\ db[i].target = target /\ db[i].signer # Last(vh.path)
                                /\ OnList(vh.path, db[i].signer)
       \* (SEEN_LINE: an honest admin signs only when its record, or one of its own below, has a seen holding
       \* a counting root record that names it; so the first record after counting the grant is the ack.)
       /\ ~SEEN_LINE \/ kit = "deviant" \/ hidden \/ OnList(vh.path, k) \/ k \in ROOT_KEYS
          \/ \E x \in {r} \cup {db[i] : i \in {i \in DOMAIN db : db[i].signer = k}} :
               \E n \in RecsOf(vh.counting, db) : n.kind = "admin" /\ n.target = k /\ OnList(vh.path, n.signer)
                 /\ n.signer \in DOMAIN x.seen /\ Len(x.seen[n.signer]) >= n.seq /\ x.seen[n.signer][n.seq] = n.id
       /\ ~keeps \/ ~CEIL_FIT \/ hidden
          \/ SumU(OfKey({x \in mine \cup {r} : ~isCp \/ x = r \/ ~PrunedBy(r, x)}, k))
               <= (IF OnList(vh.path, k) THEN ROOTC ELSE ADMINC)
       /\ ~keeps \/ ~CEIL_FIT \/ kind # "admin" \/ CapFits(h, target)
       \* (CP_BEFORE_GOING, #530 9e20ec86 write_one: a root record that makes an admin key go (its
       \* removal or its device's, or a take-back of its device) comes right after a checkpoint of the root.)
       \* (CP_BEFORE_GOING is a level: 0 off, else binding from that TLC level, i.e. the free steps only.)
       /\ CP_BEFORE_GOING = 0 \/ TLCGet("level") < CP_BEFORE_GOING \/ kit = "deviant" \/ hidden \/ isCp \/ ~OnList(vh.path, k)
          \/ ~(\/ (kind = "revoke" /\ \E a \in DOMAIN vh.admins : target = a \/ (a \in DOMAIN DEV /\ target = DEV[a]))
               \/ (kind = "admin" /\ \E a \in DOMAIN vh.admins : vh.admins[a] = kit /\ a # target))
          \/ (Len(own) > 0 /\ db[Last(own)].kind = "checkpoint")
       \* (WRITER_CP_FLOOR: a root's record leaves room for its next checkpoint, and an ordinary
       \* record also for the removals' margin.)
       /\ ~WRITER_CP_FLOOR \/ kit = "deviant" \/ hidden \/ IsChain(r) \/ isCp \/ ~OnList(vh.path, k)
          \/ RootUnits(s, k, db) + r.units + CP_UNITS <= ROOTC - (IF FloorExempt(r) THEN 0 ELSE REMOVAL_MARGIN)
       \* (WRITER_CP_FLOOR, architecture 11-14 09:03Z: an exempt record that would leave less than one
       \* more exempt record and the next checkpoint waits for a checkpoint first.)
       /\ ~WRITER_CP_FLOOR \/ kit = "deviant" \/ hidden \/ ~FloorExempt(r) \/ ~OnList(vh.path, k)
          \/ RootUnits(s, k, db) + r.units + 1 + CP_UNITS <= ROOTC
       /\ \E s2 \in {IF hidden THEN s ELSE InsertInto(s, r, db2)} :
            /\ ~keeps \/ hidden \/ r.id \in s2.recs
            \* (J, core write_checkpoint: the trial set takes the honest checkpoint as the counting one.)
            /\ ~keeps \/ ~isCp \/ hidden \/ StoreView(s2, db2).checkpoint = r.id
            /\ Commit(db2, nextId + 1, h, s2)

\* A bent root checkpoint with a chosen keep (signCheckpointKeep of the Quint model); lower:
\* that key's head is shown one record short.
SignCheckpointKeep(k, keep, lower, units) ==
    LET h == HOLDER[k]
        s == st[h]
        mine == RecsOf(s.recs, db)
        own == HeadLine(AllRecs, k)
        kept == RecsOf(keep \cap DOMAIN db, db)
        seen0 == [x \in SIGNERS |-> IF x = k THEN own
                   ELSE IF Len(HeadLine(kept, x)) > Len(HeadLine(mine, x)) THEN HeadLine(kept, x) ELSE HeadLine(mine, x)]
        seen == [x \in SIGNERS |-> IF x = lower /\ Len(seen0[x]) > 0 THEN SubSeq(seen0[x], 1, Len(seen0[x]) - 1) ELSE seen0[x]]
        r == Rec(nextId, k, Append(own, nextId), "checkpoint", "", "bent", 0, seen, seen, keep, units)
        db2 == Put(db, nextId, r)
    IN /\ k \in ROOT_KEYS
       /\ nextId <= LASTID
       /\ Commit(db2, nextId + 1, h, InsertInto(s, r, db2))

\* A bent root checkpoint with the honest keep whose own head is wrong (rule C's case): "noOwn"
\* names no head of its own key, "ownShort" names its own head one record below seq - 1.
SignCpBent(k, mode) ==
    LET h == HOLDER[k]
        s == st[h]
        mine == RecsOf(s.recs, db)
        own == HeadLine(AllRecs, k)
        counted == {x \in RecsOf(views[h].counting, db) : x.kind # "checkpoint"}
        seen0 == [x \in SIGNERS |-> IF x = k THEN own ELSE HeadLine(mine, x)]
        keep == IF KEEP_V2 THEN HonestKeepV2(k, s, views[h], seen0) ELSE HonestKeepOf(k, counted, mine)
        seen == IF mode = "noOwn" THEN [x \in SIGNERS \ {k} |-> seen0[x]]
                ELSE [seen0 EXCEPT ![k] = SubSeq(own, 1, Len(own) - 1)]
        r == Rec(nextId, k, Append(own, nextId), "checkpoint", "", "bent", 0, seen, seen, keep, 2)
        db2 == Put(db, nextId, r)
    IN /\ k \in ROOT_KEYS
       /\ Len(own) > 0
       /\ nextId <= LASTID
       /\ Last(views[h].path) = k
       /\ Commit(db2, nextId + 1, h, InsertInto(s, r, db2))

\* The keep an honest checkpoint of k would carry now (for the bent free steps).
HonestKeepNow(k) ==
    LET h == HOLDER[k]
        mine == RecsOf(st[h].recs, db)
        counted == {x \in RecsOf(views[h].counting, db) : x.kind # "checkpoint"}
        own == HeadLine(AllRecs, k)
        seen == [x \in SIGNERS |-> IF x = k THEN own ELSE HeadLine(mine, x)]
    IN IF KEEP_V2 /\ k \in ROOT_KEYS THEN HonestKeepV2(k, st[h], views[h], seen) ELSE HonestKeepOf(k, counted, mine)

SignFull(k, kind, target, kit, targetRec, pretend, fork, units, hidden, extraKeep) ==
    SignFullX(k, kind, target, kit, targetRec, pretend, fork, units, hidden, extraKeep, WRITER_KEEPS)
Sign(k, kind, target, kit, targetRec, pretend, fork, units) ==
    SignFull(k, kind, target, kit, targetRec, pretend, fork, units, FALSE, {})
SignAs(k, kind, target, targetRec) ==
    Sign(k, kind, target, "", targetRec, FALSE, FALSE, IF kind = "checkpoint" THEN 2 ELSE 1)
SignDeviant(k, kind, target, units) ==
    SignFullX(k, kind, target, "deviant", 0, FALSE, FALSE, units, FALSE, {}, FALSE)

\* A deviant record with a made-up seen (fake: a function from keys to lines of IDs that need not exist).
SignForgedSeen(k, kind, target, fake) ==
    LET h == HOLDER[k]
        own == HeadLine(AllRecs, k)
        r == Rec(nextId, k, Append(own, nextId), kind, target, "deviant", 0, fake, EmptyFn, {}, 1)
        db2 == Put(db, nextId, r)
    IN /\ k \in SIGNERS
       /\ nextId <= LASTID
       /\ Commit(db2, nextId + 1, h, InsertInto(st[h], r, db2))

\* The longest line of key kk among the checkpoints cs (a tie keeps the first; see README).
LongestHead(cs, kk) ==
    LET ls == {c.heads[kk] : c \in {c \in cs : kk \in DOMAIN c.heads}}
    IN IF ls = {} THEN <<>> ELSE CHOOSE l \in ls : \A o \in ls : Len(l) >= Len(o)

\* REISSUE_REMOVALS helpers: the removals that fit the new root's room (oldest first, a
\* checkpoint's units kept free) and their packing into Zs that agree on every shared key.
RECURSIVE ZFit(_, _, _)
ZFit(l, u, d) ==
    IF l = <<>> THEN <<>>
    ELSE IF u + d[Head(l)].units + 2 <= ROOTC THEN <<Head(l)>> \o ZFit(Tail(l), u + d[Head(l)].units, d)
    ELSE ZFit(Tail(l), u, d)
Concerns(x) == Tgt(x) \cup DOMAIN x.seen
Agree(y, x) == \A k \in Concerns(y) \cap Concerns(x) : LineOf(y.seen, k) = LineOf(x.seen, k)
RECURSIVE PackZ(_, _, _)
PackZ(l, gs, d) ==
    IF l = <<>> THEN gs
    ELSE LET x == d[Head(l)]
             ok == {g \in 1..Len(gs) : REISSUE_PACK_ANY \/ \A j \in 1..Len(gs[g]) : Agree(d[gs[g][j]], x)}
             gs2 == IF ok = {} THEN Append(gs, <<Head(l)>>) ELSE [gs EXCEPT ![MinS(ok, 0)] = Append(@, Head(l))]
         IN PackZ(Tail(l), gs2, d)
LongestLineOf(xs, kk) ==
    LET ls == {LineOf(x.seen, kk) : x \in xs} IN CHOOSE l \in ls : \A o \in ls : Len(l) >= Len(o)

\* The recovery key signs a recovery record at seq `at` (signChainG of the Quint model).
\* The change's checks (bound once, see Commit).
\* (CHANGE_AT_NEW: the change and the new root's first checkpoint are written on the new root's
\* device; before writing, that device takes everything the recovery key's device holds.)
CanAt(k, kind) == CHANGE_AT_NEW /\ kind = "recover"
WriterOf(k, kind, target) == IF CanAt(k, kind) THEN HOLDER[target] ELSE HOLDER[k]
WriterState(k, kind, target) ==
    IF CanAt(k, kind) THEN Finish(InsertAll(st[HOLDER[target]], ToList(LET a == st[HOLDER[k]] IN (a.recs \cup a.chain \cup a.wait \cup a.side) \ (st[HOLDER[target]].recs \cup st[HOLDER[target]].chain)), db), db)[1]
    ELSE st[HOLDER[k]]
WriterView(k, kind, target) ==
    IF CanAt(k, kind) THEN StoreView(WriterState(k, kind, target), db) ELSE views[HOLDER[k]]
SignChainC(k, kind, target, at, mode, given) ==
    LET h == WriterOf(k, kind, target)
        s == WriterState(k, kind, target)
        v == WriterView(k, kind, target)
        \* (SKIP_UNAPPLIED: the head is placed on every head the writer holds (applied ones plus unapplied ones), but
        \* the writer re-issues from its applied view: before is the applied path.)
        chA == ChainState(s, db)
        ch == IF SKIP_UNAPPLIED THEN ChainRaw(RecsOf(s.chain, db)) ELSE chA
        skipping == SKIP_UNAPPLIED /\ Len(ch.ids) > Len(chA.ids)
        base == SubSeq(ch.ids, 1, at - 1)
        before == IF SKIP_UNAPPLIED THEN PathCutsOf(SubSeq(chA.recs, 1, IF at - 1 < Len(chA.ids) THEN at - 1 ELSE Len(chA.ids))).path
                  ELSE PathCutsOf(SubSeq(ch.recs, 1, at - 1)).path
        cur == Last(before)
        held == {r \in RecsOf(s.recs, db) : OnList(before, r.signer) \/ r.signer = target}
        oldCp == IF v.checkpoint # 0 /\ db[v.checkpoint].signer = cur THEN db[v.checkpoint] ELSE NONEREC
        rootCps == {x \in held : x.signer = cur /\ x.kind = "checkpoint"}
        leftOut == {x \in held : \E c \in rootCps : PrunedBy(c, x)}
        headKeys == DOMAIN oldCp.heads \cup UNION {DOMAIN c.heads : c \in rootCps}
        hcs == rootCps \cup (IF oldCp = NONEREC THEN {} ELSE {oldCp})
        heads == [kk \in headKeys |-> LongestHead(hcs, kk)]
        \* (CLOSED_LIST: as in the code, a checkpoint names no head of an earlier root, only its own.)
        cp == {i \in {Last(heads[kk]) : kk \in {kk \in DOMAIN heads : Len(heads[kk]) > 0 /\ (~CLOSED_LIST \/ kk = cur)}} :
                 OnList(before, db[i].signer) /\ db[i].kind # "checkpoint"}
        \* (CORE_LIST_FILTER: the core's list of 11-13 drops a removal of keys no held record names.)
        unnamedRm(r) == CORE_LIST_FILTER /\ RootRemoval(r)
                        /\ \A t \in Tgt(r) : AdmissionsOf(RecsOf(s.recs, db), t) = {}
        \* (E_ALL: the writer's monotone drops; a device record of an older epoch that the counting
        \* checkpoint does not keep or anchor is neither listed nor kept by the first checkpoint.)
        \* (E_CUR: the writer lists or keeps nothing that does not count at it, which the counting set
        \* already says; no extra filter.)
        oldEp(x) == FALSE
        honest == IdsOf({r \in held : ((r.id \in v.counting /\ r.kind # "checkpoint" /\ r \notin leftOut) \/ RootRemoval(r))
                                      /\ ~unnamedRm(r) /\ ~oldEp(r)}) \cup cp
        \* Ghost: the root removals the writer held, under "_rm" of the head's seen (read only by
        \* removedStayOut: a list may leave out only what its writer never held).
        heldRm == ToList({i \in s.recs : RootRemoval(db[i]) /\ OnList(before, db[i].signer)})
        beforeRecs == {x \in RecsOf(honest, db) : OnList(before, x.signer)}
        NotOlder(a, b) == IndexOf(before, a.signer) > IndexOf(before, b.signer) \/ (a.signer = b.signer /\ a.seq >= b.seq)
        IsAdm(x) == x.kind \in {"admin", "device"}
        superseded == {x \in beforeRecs : IsAdm(x) /\ \E y \in beforeRecs : y # x /\ IsAdm(y) /\ y.target = x.target /\ NotOlder(y, x)}
        live == {x \in beforeRecs : IsAdm(x) /\ x \notin superseded /\ ~\E t \in Tgt(x) : t \in v.revoked}
        foldedRm == {x \in beforeRecs : RootRemoval(x) /\ \E n \in beforeRecs : n # x /\ RootRemoval(n)
                       /\ NotOlder(n, x) /\ Tgt(x) \subseteq Tgt(n)
                       /\ SameSeen(x, n)}
        \* REISSUE_REMOVALS: the honest writer re-signs the cut roots' counting removals as
        \* the new root's first records Z (oldest first while they fit); REISSUE_DROP_ONLY
        \* leaves them off the list without a Z.
        ownUnits == SumU(OfKey(RecsOf(s.recs \cup st[HOLDER[target]].recs, db), target))
        reC == IF ~REISSUE_REMOVALS \/ LAST_ROOT \/ mode \notin {"honest", "honestnr"} THEN <<>>
               ELSE ToList({i \in DOMAIN db : i < nextId /\ i \in v.counting /\ RootRemoval(db[i])
                              /\ OnList(before, db[i].signer) /\ db[i] \notin foldedRm})
        zSrc == ZFit(reC, ownUnits, db)
        covered == Range(zSrc)
        groups == PackZ(zSrc, <<>>, db)
        \* (LAST_ROOT: the honest new root re-issues every counting device (an admin's own device too, as a plain device; its rights go with
        \* the old root) and every counting freeze as its own first records; no list, no re-issued removals.)
        \* (SPARE: each old admin whose newest counting ack in the writer's view carries a spare that no root
        \* the writer holds a record of ever named is named again by that spare, with its old kit.)
        cntV == RecsOf(v.counting, db)
        \* (S2, architecture 11-15 00:56Z: a writer holding an earlier change still pending, no counting checkpoint
        \* of the current root at it, names no spares.)
        spareL == IF ~SPARE \/ (Len(before) >= 2 /\ oldCp = NONEREC) \/ skipping THEN {}
                  ELSE {<<"admin", x.spare, v.admins[x.signer]>> :
                          x \in {x \in cntV : x.kind = "copies" /\ x.signer \in DOMAIN v.admins /\ x.spare # ""
                                 /\ (\A o \in cntV : (o.kind = "copies" /\ o.signer = x.signer) => o.seq <= x.seq)
                                 /\ ~\E y \in RecsOf(s.got, db) : y.kind = "admin" /\ y.target = x.spare /\ y.signer \in ROOT_KEYS}}
        \* (LEAVE_OUT: the honest writer leaves the devices the person names out of the change ("who stays",
        \* owner 11-15 15:32Z); in the honest modes `given` is that set, empty unless SignChangeLO passes one.)
        LO == IF mode \in {"honest", "honestnr"} THEN given ELSE {}
        reL == IF LAST_ROOT /\ mode \in {"honest", "honestnr"}
               THEN AnyList({<<"device", d>> : d \in v.devices \ LO} \cup {<<"freeze", f>> : f \in v.frozen} \cup spareL)
               ELSE <<>>
        nz == IF REISSUE_DROP_ONLY THEN 0 ELSE IF LAST_ROOT THEN Len(reL) ELSE Len(groups)
        zIds == [j \in 1..nz |-> nextId + j]
        cpId == nextId + 1 + nz
        remUnits == SumU({x \in beforeRecs : RootRemoval(x) /\ x \notin foldedRm /\ x.id \notin covered})
        fixedUnits == remUnits + SumU(live)
        droppable == {x \in beforeRecs : ~RootRemoval(x) /\ x \notin live /\ x \notin superseded}
        trimmed == {i \in honest : db[i] \notin superseded /\ db[i] \notin foldedRm
                      /\ (db[i] \notin droppable \/ fixedUnits + SumU({d \in droppable : NotOlder(d, db[i])}) <= RESERVE)}
        keep == IF LAST_ROOT /\ mode \in {"honest", "honestnr"} THEN {}
                ELSE IF mode \in {"honest", "honestnr", "nocp", "from1"} THEN (IF CEIL_FIT THEN trimmed ELSE honest) \ (IF REISSUE_MUT = "listX" THEN {} ELSE covered)
                ELSE IF mode = "literal" THEN {i \in honest : db[i].signer = cur \/ RootRemoval(db[i]) \/ i \in cp}
                ELSE IF mode = "none" THEN {}
                ELSE IF mode = "given" THEN given
                ELSE {i \in DOMAIN db : OnList(before, db[i].signer)}
        own == HeadLine(AllRecs, target)
        from == IF mode = "from1" THEN 1 ELSE Len(own) + 1
        \* (NEW_ROOT_ONLY: a change naming a root already on the path writes its void head only.)
        withCp == mode # "nocp" /\ ~(NEW_ROOT_ONLY /\ OnList(before, target))
        r == [Rec(nextId, k, Append(base, nextId), kind, target, IF mode \in {"honest", "honestnr"} THEN "" ELSE "deviant",
                  from, [x \in {"_rm"} |-> heldRm], EmptyFn, keep, 0) EXCEPT !.first = IF withCp THEN cpId ELSE NEVER, !.lo = LO]
        dbH == Put(db, nextId, r)
        MkZ0(j) ==
            LET xs == {db[i] : i \in Range(groups[j])}
                x0 == db[groups[j][1]]
                zKeys == UNION {DOMAIN x.seen : x \in xs}
                seenZ == [kk \in zKeys |-> IF REISSUE_MUT = "newerSeen" THEN HeadLine(RecsOf(s.recs \cup s.got, db), kk)
                                            ELSE LongestLineOf(xs, kk)]
            IN [Rec(nextId + j, target, own \o SubSeq(zIds, 1, j), "revoke", x0.target, "z", nextId,
                    seenZ, EmptyFn, {}, SumU(xs))
                EXCEPT !.also = (UNION {{x.target} \cup x.also : x \in xs \ {x0}}) \cup x0.also]
        \* (wv, wr: ghost fields for LReissueW, the writer's counting devices and the keys its view holds a counting removal for.)
        MkZ(j) == IF LAST_ROOT THEN [Rec(nextId + j, target, own \o SubSeq(zIds, 1, j), reL[j][1], reL[j][2], "z", nextId, EmptyFn, EmptyFn, {}, 1)
                                      EXCEPT !.wv = v.devices, !.wr = UNION {Tgt(x) : x \in {x \in RecsOf(v.counting, db) : x.kind = "revoke"}},
                                             !.akit = IF reL[j][1] = "admin" THEN reL[j][3] ELSE ""]
                  ELSE MkZ0(j)
        db2 == [i \in DOMAIN dbH \cup Range(zIds) |-> IF i \in Range(zIds) THEN MkZ(i - nextId) ELSE dbH[i]]
        s1 == InsertAll(InsertInto(s, r, dbH), zIds, db2)
        r0 == [r EXCEPT !.first = 0]
        db20 == Put(db, nextId, r0)
        v1 == Finish(InsertInto(s, r0, db20), db20)[2]
        c == Rec(cpId, target, Append(own \o zIds, cpId), "checkpoint", "", "", 0, heads, heads,
                 {i \in v1.counting : db2[i].kind # "checkpoint" /\ i \notin IdsOf(leftOut) /\ (i \notin DOMAIN db \/ ~oldEp(db[i]))} \cup (IF REISSUE_MUT = "notKept" THEN {} ELSE Range(zIds)), 2)
        db3 == IF withCp THEN Put(db2, cpId, c) ELSE db2
    IN [ok |-> /\ k = RECOVERY
               /\ at >= 1
               \* (LEAVE_OUT: only devices that count at the writer, never the new root's own device.)
               /\ LO \subseteq v.devices
               /\ target \notin DOMAIN DEV \/ DEV[target] \notin LO
               /\ at <= Len(ch.ids) + 1
               /\ cpId <= LASTID
               \* (REISSUE_REMOVALS: the writer's own check: the list names no removal a Z covers.)
               /\ ~REISSUE_REMOVALS \/ mode # "honest" \/ keep \cap covered = {}
               /\ ~CEIL_FIT \/ mode \notin {"honest", "honestnr"} \/ SumU(OfKey(RecsOf(s.recs \cup st[HOLDER[target]].recs, db), target)) + 2 <= ROOTC
               \* ("honestnr": the same change with the reserve check left out; only RecoveryLive uses it.)
               /\ ~CEIL_FIT \/ LAST_ROOT \/ mode # "honest" \/ fixedUnits <= RESERVE,
        h |-> h]
\* The change's new set and store, computed only when its checks pass (bound once, see Commit).
SignChainS(k, kind, target, at, mode, given) ==

    LET h == WriterOf(k, kind, target)
        s == WriterState(k, kind, target)
        v == WriterView(k, kind, target)
        \* (SKIP_UNAPPLIED: the head is placed on every head the writer holds (applied ones plus unapplied ones), but
        \* the writer re-issues from its applied view: before is the applied path.)
        chA == ChainState(s, db)
        ch == IF SKIP_UNAPPLIED THEN ChainRaw(RecsOf(s.chain, db)) ELSE chA
        skipping == SKIP_UNAPPLIED /\ Len(ch.ids) > Len(chA.ids)
        base == SubSeq(ch.ids, 1, at - 1)
        before == IF SKIP_UNAPPLIED THEN PathCutsOf(SubSeq(chA.recs, 1, IF at - 1 < Len(chA.ids) THEN at - 1 ELSE Len(chA.ids))).path
                  ELSE PathCutsOf(SubSeq(ch.recs, 1, at - 1)).path
        cur == Last(before)
        held == {r \in RecsOf(s.recs, db) : OnList(before, r.signer) \/ r.signer = target}
        oldCp == IF v.checkpoint # 0 /\ db[v.checkpoint].signer = cur THEN db[v.checkpoint] ELSE NONEREC
        rootCps == {x \in held : x.signer = cur /\ x.kind = "checkpoint"}
        leftOut == {x \in held : \E c \in rootCps : PrunedBy(c, x)}
        headKeys == DOMAIN oldCp.heads \cup UNION {DOMAIN c.heads : c \in rootCps}
        hcs == rootCps \cup (IF oldCp = NONEREC THEN {} ELSE {oldCp})
        heads == [kk \in headKeys |-> LongestHead(hcs, kk)]
        \* (CLOSED_LIST: as in the code, a checkpoint names no head of an earlier root, only its own.)
        cp == {i \in {Last(heads[kk]) : kk \in {kk \in DOMAIN heads : Len(heads[kk]) > 0 /\ (~CLOSED_LIST \/ kk = cur)}} :
                 OnList(before, db[i].signer) /\ db[i].kind # "checkpoint"}
        \* (CORE_LIST_FILTER: the core's list of 11-13 drops a removal of keys no held record names.)
        unnamedRm(r) == CORE_LIST_FILTER /\ RootRemoval(r)
                        /\ \A t \in Tgt(r) : AdmissionsOf(RecsOf(s.recs, db), t) = {}
        \* (E_ALL: the writer's monotone drops; a device record of an older epoch that the counting
        \* checkpoint does not keep or anchor is neither listed nor kept by the first checkpoint.)
        \* (E_CUR: the writer lists or keeps nothing that does not count at it, which the counting set
        \* already says; no extra filter.)
        oldEp(x) == FALSE
        honest == IdsOf({r \in held : ((r.id \in v.counting /\ r.kind # "checkpoint" /\ r \notin leftOut) \/ RootRemoval(r))
                                      /\ ~unnamedRm(r) /\ ~oldEp(r)}) \cup cp
        \* Ghost: the root removals the writer held, under "_rm" of the head's seen (read only by
        \* removedStayOut: a list may leave out only what its writer never held).
        heldRm == ToList({i \in s.recs : RootRemoval(db[i]) /\ OnList(before, db[i].signer)})
        beforeRecs == {x \in RecsOf(honest, db) : OnList(before, x.signer)}
        NotOlder(a, b) == IndexOf(before, a.signer) > IndexOf(before, b.signer) \/ (a.signer = b.signer /\ a.seq >= b.seq)
        IsAdm(x) == x.kind \in {"admin", "device"}
        superseded == {x \in beforeRecs : IsAdm(x) /\ \E y \in beforeRecs : y # x /\ IsAdm(y) /\ y.target = x.target /\ NotOlder(y, x)}
        live == {x \in beforeRecs : IsAdm(x) /\ x \notin superseded /\ ~\E t \in Tgt(x) : t \in v.revoked}
        foldedRm == {x \in beforeRecs : RootRemoval(x) /\ \E n \in beforeRecs : n # x /\ RootRemoval(n)
                       /\ NotOlder(n, x) /\ Tgt(x) \subseteq Tgt(n)
                       /\ SameSeen(x, n)}
        \* REISSUE_REMOVALS: the honest writer re-signs the cut roots' counting removals as
        \* the new root's first records Z (oldest first while they fit); REISSUE_DROP_ONLY
        \* leaves them off the list without a Z.
        ownUnits == SumU(OfKey(RecsOf(s.recs \cup st[HOLDER[target]].recs, db), target))
        reC == IF ~REISSUE_REMOVALS \/ LAST_ROOT \/ mode \notin {"honest", "honestnr"} THEN <<>>
               ELSE ToList({i \in DOMAIN db : i < nextId /\ i \in v.counting /\ RootRemoval(db[i])
                              /\ OnList(before, db[i].signer) /\ db[i] \notin foldedRm})
        zSrc == ZFit(reC, ownUnits, db)
        covered == Range(zSrc)
        groups == PackZ(zSrc, <<>>, db)
        \* (LAST_ROOT: the honest new root re-issues every counting device (an admin's own device too, as a plain device; its rights go with
        \* the old root) and every counting freeze as its own first records; no list, no re-issued removals.)
        \* (SPARE: each old admin whose newest counting ack in the writer's view carries a spare that no root
        \* the writer holds a record of ever named is named again by that spare, with its old kit.)
        cntV == RecsOf(v.counting, db)
        \* (S2, architecture 11-15 00:56Z: a writer holding an earlier change still pending, no counting checkpoint
        \* of the current root at it, names no spares.)
        spareL == IF ~SPARE \/ (Len(before) >= 2 /\ oldCp = NONEREC) \/ skipping THEN {}
                  ELSE {<<"admin", x.spare, v.admins[x.signer]>> :
                          x \in {x \in cntV : x.kind = "copies" /\ x.signer \in DOMAIN v.admins /\ x.spare # ""
                                 /\ (\A o \in cntV : (o.kind = "copies" /\ o.signer = x.signer) => o.seq <= x.seq)
                                 /\ ~\E y \in RecsOf(s.got, db) : y.kind = "admin" /\ y.target = x.spare /\ y.signer \in ROOT_KEYS}}
        \* (LEAVE_OUT: the honest writer leaves the devices the person names out of the change ("who stays",
        \* owner 11-15 15:32Z); in the honest modes `given` is that set, empty unless SignChangeLO passes one.)
        LO == IF mode \in {"honest", "honestnr"} THEN given ELSE {}
        reL == IF LAST_ROOT /\ mode \in {"honest", "honestnr"}
               THEN AnyList({<<"device", d>> : d \in v.devices \ LO} \cup {<<"freeze", f>> : f \in v.frozen} \cup spareL)
               ELSE <<>>
        nz == IF REISSUE_DROP_ONLY THEN 0 ELSE IF LAST_ROOT THEN Len(reL) ELSE Len(groups)
        zIds == [j \in 1..nz |-> nextId + j]
        cpId == nextId + 1 + nz
        remUnits == SumU({x \in beforeRecs : RootRemoval(x) /\ x \notin foldedRm /\ x.id \notin covered})
        fixedUnits == remUnits + SumU(live)
        droppable == {x \in beforeRecs : ~RootRemoval(x) /\ x \notin live /\ x \notin superseded}
        trimmed == {i \in honest : db[i] \notin superseded /\ db[i] \notin foldedRm
                      /\ (db[i] \notin droppable \/ fixedUnits + SumU({d \in droppable : NotOlder(d, db[i])}) <= RESERVE)}
        keep == IF LAST_ROOT /\ mode \in {"honest", "honestnr"} THEN {}
                ELSE IF mode \in {"honest", "honestnr", "nocp", "from1"} THEN (IF CEIL_FIT THEN trimmed ELSE honest) \ (IF REISSUE_MUT = "listX" THEN {} ELSE covered)
                ELSE IF mode = "literal" THEN {i \in honest : db[i].signer = cur \/ RootRemoval(db[i]) \/ i \in cp}
                ELSE IF mode = "none" THEN {}
                ELSE IF mode = "given" THEN given
                ELSE {i \in DOMAIN db : OnList(before, db[i].signer)}
        own == HeadLine(AllRecs, target)
        from == IF mode = "from1" THEN 1 ELSE Len(own) + 1
        \* (NEW_ROOT_ONLY: a change naming a root already on the path writes its void head only.)
        withCp == mode # "nocp" /\ ~(NEW_ROOT_ONLY /\ OnList(before, target))
        r == [Rec(nextId, k, Append(base, nextId), kind, target, IF mode \in {"honest", "honestnr"} THEN "" ELSE "deviant",
                  from, [x \in {"_rm"} |-> heldRm], EmptyFn, keep, 0) EXCEPT !.first = IF withCp THEN cpId ELSE NEVER, !.lo = LO]
        dbH == Put(db, nextId, r)
        MkZ0(j) ==
            LET xs == {db[i] : i \in Range(groups[j])}
                x0 == db[groups[j][1]]
                zKeys == UNION {DOMAIN x.seen : x \in xs}
                seenZ == [kk \in zKeys |-> IF REISSUE_MUT = "newerSeen" THEN HeadLine(RecsOf(s.recs \cup s.got, db), kk)
                                            ELSE LongestLineOf(xs, kk)]
            IN [Rec(nextId + j, target, own \o SubSeq(zIds, 1, j), "revoke", x0.target, "z", nextId,
                    seenZ, EmptyFn, {}, SumU(xs))
                EXCEPT !.also = (UNION {{x.target} \cup x.also : x \in xs \ {x0}}) \cup x0.also]
        \* (wv, wr: ghost fields for LReissueW, the writer's counting devices and the keys its view holds a counting removal for.)
        MkZ(j) == IF LAST_ROOT THEN [Rec(nextId + j, target, own \o SubSeq(zIds, 1, j), reL[j][1], reL[j][2], "z", nextId, EmptyFn, EmptyFn, {}, 1)
                                      EXCEPT !.wv = v.devices, !.wr = UNION {Tgt(x) : x \in {x \in RecsOf(v.counting, db) : x.kind = "revoke"}},
                                             !.akit = IF reL[j][1] = "admin" THEN reL[j][3] ELSE ""]
                  ELSE MkZ0(j)
        db2 == [i \in DOMAIN dbH \cup Range(zIds) |-> IF i \in Range(zIds) THEN MkZ(i - nextId) ELSE dbH[i]]
        s1 == InsertAll(InsertInto(s, r, dbH), zIds, db2)
        r0 == [r EXCEPT !.first = 0]
        db20 == Put(db, nextId, r0)
        v1 == Finish(InsertInto(s, r0, db20), db20)[2]
        c == Rec(cpId, target, Append(own \o zIds, cpId), "checkpoint", "", "", 0, heads, heads,
                 {i \in v1.counting : db2[i].kind # "checkpoint" /\ i \notin IdsOf(leftOut) /\ (i \notin DOMAIN db \/ ~oldEp(db[i]))} \cup (IF REISSUE_MUT = "notKept" THEN {} ELSE Range(zIds)), 2)
        db3 == IF withCp THEN Put(db2, cpId, c) ELSE db2
    IN [db |-> db3, n |-> IF withCp \/ (NEW_ROOT_ONLY /\ mode # "nocp" /\ OnList(before, target)) THEN cpId + 1 ELSE cpId,
        s |-> IF withCp THEN InsertInto(s1, c, db3) ELSE s1]
SignChainG(k, kind, target, at, mode, given) ==
    \E g \in {SignChainC(k, kind, target, at, mode, given)} :
       g.ok /\ \E x \in {SignChainS(k, kind, target, at, mode, given)} :
                  IF CanAt(k, kind) THEN Commit2(x.db, x.n, g.h, x.s, HOLDER[k]) ELSE Commit(x.db, x.n, g.h, x.s)

SignChain(k, kind, target, at, mode) == SignChainG(k, kind, target, at, mode, {})
RecoverAs(k, t) == SignChain(k, "recover", t, Len(ChainState(WriterState(k, "recover", t), db).ids) + 1, "honest")

KnownTo(s, t) == \E r \in RecsOf(s.got, db) : r.signer = t \/ (r.kind = "admin" /\ r.target = t) \/ r.target = t
\* The recovery key's member changes the root to a key its state does not know (guided step).
SignChange(t) ==
    LET kh == HOLDER[RECOVERY]
        ws == WriterState(RECOVERY, "recover", t)
        wv == WriterView(RECOVERY, "recover", t)
        ch == ChainState(ws, db)
    IN /\ ~ch.stop
       /\ ~OnList(wv.path, t)
       /\ ~KnownTo(ws, t)
       /\ \A r \in {r \in RecsOf(ws.got, db) : IsChain(r)} : InLine(ch.ids, r.id)
       /\ SignChain(RECOVERY, "recover", t, Len(ch.ids) + 1, "honest")
\* Probe (seed 153): whenever the honest change could be signed but for the cut roots' reserve,
\* it can be signed. Not a promise of records-v3.qnt; it shows whether the checker reaches a
\* change that the reserve refuses.
SignChangeG(t, mode) ==
    LET kh == HOLDER[RECOVERY]
        ws == WriterState(RECOVERY, "recover", t)
        wv == WriterView(RECOVERY, "recover", t)
        ch == ChainState(ws, db)
    IN /\ ~ch.stop /\ ~OnList(wv.path, t) /\ ~KnownTo(ws, t)
       /\ \A r \in {r \in RecsOf(ws.got, db) : IsChain(r)} : InLine(ch.ids, r.id)
       /\ SignChain(RECOVERY, "recover", t, Len(ch.ids) + 1, mode)
\* (SKIP_UNAPPLIED: the honest writer over an unapplied head: every head it holds is on its heads chain.)
SignChangeSkip(t, mode) ==
    LET ws == WriterState(RECOVERY, "recover", t)
        wv == WriterView(RECOVERY, "recover", t)
        chH == ChainRaw(RecsOf(ws.chain, db))
    IN /\ SKIP_UNAPPLIED /\ ~Forked(RecsOf(ws.got, db)) /\ ~OnList(wv.path, t) /\ ~KnownTo(ws, t)
       /\ \A r \in {r \in RecsOf(ws.got, db) : IsChain(r)} : InLine(chH.ids, r.id)
       /\ SignChain(RECOVERY, "recover", t, Len(chH.ids) + 1, mode)
\* (LEAVE_OUT: the honest change of root that leaves the devices `lo` out.)
SignChangeLO(t, lo) ==
    LET ws == WriterState(RECOVERY, "recover", t)
        wv == WriterView(RECOVERY, "recover", t)
        ch == ChainState(ws, db)
    IN /\ ~ch.stop /\ ~OnList(wv.path, t) /\ ~KnownTo(ws, t)
       /\ \A r \in {r \in RecsOf(ws.got, db) : IsChain(r)} : InLine(ch.ids, r.id)
       /\ SignChainG(RECOVERY, "recover", t, Len(ch.ids) + 1, "honest", lo)
RecoveryLive == \A t \in ROOT_KEYS \ {ROOT} : (ENABLED SignChangeG(t, "honestnr")) => ENABLED SignChangeG(t, "honest")
\* The recovery key signs a second record at a seq its chain already has.
RecoveryTwin(t, at) ==
    LET ch == ChainState(st[HOLDER[RECOVERY]], db)
    IN at <= Len(ch.ids) /\ SignChain(RECOVERY, "recover", t, at, "honest")

\* A newcomer starts again from what admitter x hands it.
WelcomeStore(sx) ==
    LET withChain == InsertAll(EMPTY, ToList(sx.chain), db)
    IN InsertAll(Pathed(withChain, db), ToList(sx.recs), db)
WelcomeFrom(x) ==
    \E sv \in {Finish(WelcomeStore(st[x]), db)} :
    /\ x # NEWCOMER
    /\ db' = db
    /\ nextId' = nextId
    /\ st' = [st EXCEPT ![NEWCOMER] = sv[1]]
    /\ views' = [views EXCEPT ![NEWCOMER] = sv[2]]
    /\ gone' = [gone EXCEPT ![NEWCOMER] = RootRemoved(sv[2], db)]
    /\ welcomed' = views[x].path

GiveOnly(m, i) == Commit(db, nextId, m, IF i \in DOMAIN db THEN InsertInto(st[m], db[i], db) ELSE st[m])
Give(m, i) == IF i \notin DOMAIN db THEN GiveOnly(m, i) ELSE
    LET r == db[i]
        s1 == InsertInto(st[m], r, db)
        \* (REISSUE_REMOVALS: with the head's re-signed removals, its other first records.)
        zs == IF IsChain(r) /\ r.first \in DOMAIN db /\ r.first <= r.id + MAXREC
              THEN {j \in (r.id + 1)..(r.first - 1) : j \in DOMAIN db /\ NamesZ(r, db[j])} ELSE {}
        s2 == InsertAll(s1, ToList(zs), db)
    IN Commit(db, nextId, m, IF IsChain(r) /\ r.first \in DOMAIN db THEN InsertInto(s2, db[r.first], db) ELSE s2)
Deliver(m, i) == /\ i \notin st[m].recs /\ i \notin st[m].chain /\ GiveOnly(m, i)

Restart(m) ==
    \E s0 \in {Recut([st[m] EXCEPT !.cut = NOCUT], db)} :
       Commit(db, nextId, m, InsertAll(s0, ToList({i \in s0.got : i < nextId}), db))
CompactAt(m) == Commit(db, nextId, m, CompactStore(st[m], views[m], db))

HeldBy(s) == s.recs \cup s.chain \cup s.wait \cup s.side
HeldAll == UNION {HeldBy(st[n]) : n \in MEMBERS}
OfferEveryone(i) == CommitAll([m \in MEMBERS |-> Finish(IF i \in DOMAIN db THEN InsertInto(st[m], db[i], db) ELSE st[m], db)])
SyncAll == CommitAll([m \in MEMBERS |-> Finish(InsertAll(st[m], ToList(HeldAll), db), db)])

MissingOf(s, d) ==
    LET cur == Last(KeptPath(s, d))
        ws == WaitingCps(s, d)
    IN {i \in (UNION {c.keep : c \in {c \in FirstsHeld(s, d) : c.signer = cur} \cup ws}) \ HeldBy(s) : i \in DOMAIN d}
\* (SETTLER_HELD, code #530 21cafa45 set.rs for_peer: a group device that is not revoked gets every
\* record the set holds, waiting and aside ones included, in a full send; kept-aside not confirmed.)
ListedTo(n, s, d) == n.recs \cup n.chain \cup (IF SETTLER_HELD THEN n.wait \cup n.side ELSE n.wait \cap MissingOf(s, d))
KeysOfMember(n) ==
    LET ks == {k \in DOMAIN HOLDER : HOLDER[k] = n}
    IN ks \cup {DEV[k] : k \in ks \cap DOMAIN DEV} \cup (IF UNKNOWN_HEADS /\ n = NEWCOMER THEN {DEVICE} ELSE {})
CountsKey(m, n) ==
    \E x \in KeysOfMember(n) : OnList(views[m].path, x) \/ x \in DOMAIN views[m].admins \/ x \in views[m].devices
                              \/ (UNKNOWN_HEADS /\ x = RECOVERY)
    \* The newcomer stands for a device admitted outside the scenario: known on the first root
    \* while its key is not removed; after a change only a list or a new root's record admits it.
    \/ (UNKNOWN_HEADS /\ n = NEWCOMER /\ Len(views[m].path) = 1 /\ DEVICE \notin views[m].revoked)
HeadsOf(s) == IF HEADS_WITH_FIRSTS THEN s.chain ELSE {i \in s.chain : IsChain(db[i])}
ListedFrom(n, m) ==
    IF UNKNOWN_HEADS /\ ~(CountsKey(m, n) /\ CountsKey(n, m)) THEN HeadsOf(st[n])
    ELSE ListedTo(st[n], st[m], db)
Fetchable(m) == (UNION {ListedFrom(n, m) : n \in MEMBERS \ {m}}) \ HeldBy(st[m])
\* What m can reach: everything; under UNKNOWN_HEADS its own, what the peers that count it and
\* that it counts hold, and the heads of every other peer.
HeldReach(m) ==
    IF ~UNKNOWN_HEADS THEN HeldAll
    ELSE HeldBy(st[m]) \cup st[m].chain
         \cup UNION {IF CountsKey(m, n) /\ CountsKey(n, m)
                     \* (SETTLER_HELD: what a counted peer offers, ListedTo.)
                     THEN (IF SETTLER_HELD THEN ListedTo(st[n], st[m], db) ELSE HeldBy(st[n])) ELSE HeadsOf(st[n]) : n \in MEMBERS \ {m}}
\* m holds a verified head above the chain it applied whose list admits none of its keys.
LeftOut(m) ==
    LET s == st[m]
        raw == ChainHeads(RecsOf(s.chain, db))
        applied == Len(ChainState(s, db).ids)
        v == views[m]
    IN UNKNOWN_HEADS /\ KeysOfMember(m) # {} /\ Len(raw.recs) > 0 /\
       LET h == raw.recs[Len(raw.recs)]
           listed == RecsOf({i \in h.keep : i \in DOMAIN db}, db)
           named == \E x \in KeysOfMember(m) : OnList(PathCutsOf(raw.recs).path, x)
              \/ (AdmissionsOf(listed, x) # {} /\ ~\E r \in listed : r.kind = "revoke" /\ x \in Tgt(r))
           \* Once it applied every head, its own state decides (a new root's record may admit it).
           ownCounts == Len(raw.recs) = applied /\ \E x \in KeysOfMember(m) :
              OnList(v.path, x) \/ x \in DOMAIN v.admins \/ x \in v.devices
       IN ~named /\ ~ownCounts
InGroup(m) == ~UNKNOWN_HEADS \/ m = "r" \/ CountsKey("r", m)
Fetch(m, i) == i \in Fetchable(m) /\ GiveOnly(m, i)
SyncRound == CommitAll([m \in MEMBERS |-> Finish(InsertAll(st[m], ToList(Fetchable(m)), db), db)])

\* --- Promises ---------------------------------------------------------------

Unchanged3(s, s2) == s2.recs = s.recs /\ s2.chain = s.chain /\ s2.wait = s.wait /\ s2.side = s.side
Saturated(m) == \A i \in st[m].got : LET s2 == InsertInto(st[m], db[i], db) IN s2.recs = st[m].recs /\ s2.wait = st[m].wait
SyncedProto(m) == \A i \in Fetchable(m) : LET s1 == InsertInto(st[m], db[i], db) IN
    Unchanged3(st[m], s1) /\ (~SYNC_PAIRS \/ \A j \in Fetchable(m) \ {i} : Unchanged3(st[m], InsertInto(s1, db[j], db)))
Synced(m) == \A i \in HeldAll : Unchanged3(st[m], InsertInto(st[m], db[i], db))

HonestOnly == \A i \in DOMAIN db : db[i].kit # "bent" /\ ~(IsChain(db[i]) /\ db[i].kit = "deviant")
HonestW == \A i \in DOMAIN db : db[i].kit # "bent" /\ db[i].kit # "deviant" /\ ~db[i].off
              /\ ~(IsChain(db[i]) /\ \E j \in DOMAIN db : j # i /\ IsChain(db[j]) /\ db[j].seq = db[i].seq)

WholeableIn(c, items) == c.keep \subseteq items /\ (Len(c.line) < 2 \/ c.line[Len(c.line) - 1] \in items)
AsideFitsIn(m, items) ==
    LET s == st[m]
        cseq == IF s.checkpoint = 0 THEN 0 ELSE db[s.checkpoint].seq
        ws == {c \in RecsOf(items, db) : c.kind = "checkpoint" /\ c.signer = Last(KeptPath(s, db)) /\ c.seq > cseq}
        top == MaxS({c.seq : c \in {c \in ws : WholeableIn(c, items)}}, 0)
        over == {i \in (UNION {c.keep \cup (IF Len(c.line) < 2 THEN {} ELSE {c.line[Len(c.line) - 1]}) :
                                c \in {c \in ws : c.seq >= top}}) \ s.recs : i \in DOMAIN db}
    IN top = 0 \/ SumU(RecsOf(over, db)) <= ASIDE_ROOM
AsideAssumed(m, items) == AsideFitsIn(m, items)

\* 1. One set, one state.
OneState == \A m \in MEMBERS :
    LET s == st[m] IN
    ((HonestOnly \/ AsideAssumed(m, s.got)) /\ ~ChainState(s, db).stop /\ Saturated(m))
      => (s.recs = PureKept(s, db) /\ views[m] = PureView(s, db))

\* 1b. Sync converges.
FreshOf(s) == [s EXCEPT !.checkpoint = 0, !.cut = NOCUT, !.wait = {}]
FreshKept(s, items, d) ==
    LET f == FreshOf(s)
        k1 == Settle(f, {r \in RecsOf(items, d) : Storable(f, r, d)}, NOCUT, d).kept
        c1 == FullEvaluate(RecsOf(k1, d) \cup FirstsHeld(s, d), ChainState(s, d)).checkpoint
        s1 == [f EXCEPT !.checkpoint = c1]
    IN Settle(s1, {r \in RecsOf(items, d) : Storable(s1, r, d)}, NOCUT, d).kept
ConvergesAt(m) ==
    LET s == st[m] IN
    (~ChainState(s, db).stop /\ ~views[m].stop /\ ~LeftOut(m) /\ SyncedProto(m))
      => LET k == FreshKept(s, HeldReach(m), db)
         IN s.recs = k /\ views[m] = FullEvaluate(RecsOf(k, db) \cup FirstsHeld(s, db), ChainState(s, db))
ConvergesHonest == HonestOnly => \A m \in MEMBERS : ConvergesAt(m)
Converges == \A m \in MEMBERS : AsideAssumed(m, HeldAll) => ConvergesAt(m)

\* 1c. A newer checkpoint that is not whole takes nothing from the counting one.
CountsNewest == \A m \in MEMBERS :
    LET v == views[m]
        rs == RecsOf(st[m].recs, db)
        cseq == IF v.checkpoint = 0 THEN 0 ELSE db[v.checkpoint].seq
        all1 == rs \cup FirstsHeld(st[m], db)
        floor == RootFloor(all1, ChainState(st[m], db), Last(v.path))
        forkS == MinS({a.seq : a \in {a \in all1 : a.signer = Last(v.path) /\ \E b \in all1 : b # a /\ b.signer = a.signer /\ b.seq = a.seq}}, NONE)
    IN v.stop \/ \A c \in rs : ~(c.kind = "checkpoint" /\ c.signer = Last(v.path) /\ c.seq > cseq /\ c.seq >= floor
                                 /\ c.seq < forkS
                                 /\ ApplyCheckpoint(v.path, v.cuts, c.id, [rs |-> rs, anchors |-> {}, view |-> Epoch(rs, v.path, v.cuts, {})]).view.checkpoint = c.id)

\* 2. A key a root removed stays removed.
CutOff(v, r) == ~Within(v.cuts, r)
HeldByNone(r) == \A n \in MEMBERS : r.id \notin st[n].recs
CutEarlier(m, r) ==
    LET ch == ChainState(st[m], db).recs
    IN \E j \in 1..Len(ch) : ~Within(PathCutsOf(SubSeq(ch, 1, j)).cuts, r)
\* An honest head on m's chain whose writer held the removal r (the ghost "_rm").
WriterHeld(m, r) == \E h \in RecsOf(st[m].chain, db) : IsChain(h) /\ h.kit = "" /\ "_rm" \in DOMAIN h.seen
                        /\ \E j \in DOMAIN h.seen["_rm"] : h.seen["_rm"][j] = r.id
RemovedStayOut == \A m \in MEMBERS : Synced(m) =>
    LET v == views[m]
        removals == {r \in RecsOf(st[m].got, db) : r.kind = "revoke" /\ OnList(v.path, r.signer)}
        cpr == IF v.checkpoint = 0 THEN NONEREC ELSE db[v.checkpoint]
    IN v.stop \/ \A k \in gone[m] :
         \/ \A r \in {r \in removals : k \in Tgt(r)} : ~WriterHeld(m, r) /\ (CutOff(v, r) \/ (CutEarlier(m, r) /\ HeldByNone(r)))
         \/ (k \notin DOMAIN v.admins /\ k \notin v.devices)
         \/ \E x \in RecsOf(v.counting, db) : AdmissionsOf({x}, k) # {}
               /\ \A r \in removals : (k \notin Tgt(r) \/ x.id > r.id)
               /\ (~SEEN_ORDER \/ \E n \in removals : k \in Tgt(n) /\ (x.signer = n.signer \/ (n.signer \in DOMAIN x.seen /\ InLine(x.seen[n.signer], n.id))))
         \/ (v.checkpoint # 0 /\ cpr.signer = Last(v.path) /\ \E x \in RecsOf(v.counting, db) :
               AdmissionsOf({x}, k) # {} /\ x.id \in cpr.keep
               /\ \A r \in removals : k \notin Tgt(r) \/ ~RootRemoval(r) \/ PrunedBy(cpr, r))

\* 3. One chain, one state.
OneChainOneState == \A m1, m2 \in MEMBERS :
    (st[m1].chain = st[m2].chain /\ st[m1].recs = st[m2].recs /\ st[m1].got = st[m2].got
       /\ Saturated(m1) /\ Saturated(m2)) => views[m1] = views[m2]

\* 5. During a stop only the current root commands; during a full stop nothing runs.
StopRootOnly == \A m \in MEMBERS :
    LET v == views[m] IN
    v.rootsCount /\ (v.stop => \A k \in v.commanders : k = Last(v.path))
    /\ (ChainState(st[m], db).stop => v.commanders = {})

\* 6. No key takes another key's room.
FairRoom == \A m \in MEMBERS :
    LET s == st[m]
        rs == RecsOf(s.recs, db)
        got == RecsOf(s.got, db)
        pc == PathCuts(ChainState(s, db))
        path == pc.path
        admins == Learned(got, path, pc.cuts)
        ceil == Ceilings(path, admins)
        legit == RootsOf(path) \cup {r.target : r \in {r \in got : OnList(path, r.signer) /\ r.kind = "admin"}}
        owners == {k \in {r.signer : r \in {r \in got : ~IsChain(r)}} : k \in DOMAIN ceil}
        cps == {c \in rs : c.id = views[m].checkpoint /\ c.signer = Last(path)}
        first == IF cps = {} THEN {} ELSE LET cp == CHOOSE c \in cps : TRUE IN {r \in rs : r = cp \/ NamedBy(cp, r, rs)}
        others == {k \in owners : \E r \in got : r.signer = k /\ Storable(s, r, db) /\ r \notin first}
        fair == IF others = {} THEN ROOM ELSE (ROOM - SumU(first)) \div Cardinality(others)
    IN /\ \A k \in DOMAIN ceil : k \in legit
       /\ SumU(rs) <= ROOM
       /\ \A k \in {r.signer : r \in rs} : k \in DOMAIN ceil /\ SumU(OfKey(rs, k)) <= ceil[k]
       /\ (~ChainState(s, db).stop /\ Saturated(m)) =>
            \A k \in others : SumU(OfKey(rs, k)) + MAXU - 1
                >= Min2(fair, Min2(ceil[k], SumU(OfKey({r \in got : Storable(s, r, db)}, k))))

\* 7. A member follows the recovery chain it holds.
FollowsRecovery == \A m \in MEMBERS :
    LET pc == PathCutsOf(ChainOf(RecsOf(st[m].got, db)).recs)
    IN views[m].path = pc.path /\ views[m].cuts = pc.cuts

\* 8. A path never grows shorter (an action property: Quint's `before` is the previous state).
PathGrows == [][\A m \in MEMBERS : IsPrefix(views[m].path, views'[m].path) \/ ChainState(st'[m], db').stop]_vars

\* 9. A newcomer takes its admitter's chain.
NewcomerTakes == NEWCOMER \notin MEMBERS \/ IsPrefix(welcomed, views[NEWCOMER].path) \/ ChainState(st[NEWCOMER], db).stop

\* 10. Of a replaced root only what its recovery record listed counts.
OldRootListed == \A m \in MEMBERS :
    LET v == views[m] IN
    \A i \in 1..(Len(v.path) - 1) : \A r \in {r \in RecsOf(v.counting, db) : r.signer = v.path[i]} : InLine(v.cuts[v.path[i]], r.id)

\* 11. Two recovery records at one seq stop every member that holds both.
TwinStops ==
    /\ \A m \in MEMBERS : ChainState(st[m], db).stop => (views[m].stop /\ views[m].commanders = {})
    /\ (\A m, n \in MEMBERS : st[n].chain \subseteq st[m].chain)
         => ((\A m \in MEMBERS : views[m].stop) \/ (\A m \in MEMBERS : ~ChainState(st[m], db).stop))

\* 12. A removed key gains nothing.
RemovedGainsNothing == \A m \in MEMBERS :
    LET cnt == RecsOf(views[m].counting, db)
        \* (Stricter 11-13 22:10Z: a removal a change cut off, though an honest writer on the
        \* member's chain held it, still bars.)
        cutHeld == {r \in RecsOf(st[m].got, db) : r.kind = "revoke" /\ CutOff(views[m], r) /\ WriterHeld(m, r)}
        removals == {r \in cnt : r.kind = "revoke"} \cup cutHeld
    IN \A r \in cnt : \A rm \in {rm \in removals : r.signer \in Tgt(rm) /\ rm # r} :
         IF rm.signer = r.signer THEN r.seq < rm.seq ELSE InLine(LineOf(rm.seen, r.signer), r.id)

\* 13. After a change of root, members alike in chain and got are in one state.
FirstCheckpointHeld(m) ==
    LET ch == ChainState(st[m], db) IN
    Len(ch.recs) > 0 /\ LET tip == ch.recs[Len(ch.recs)] IN
      \E r \in RecsOf(st[m].got, db) : r.signer = tip.target /\ r.kind = "checkpoint" /\ r.seq = Max2(tip.targetRec, 1)
CompactedAgree == \A m1, m2 \in MEMBERS :
    (st[m1].chain = st[m2].chain /\ st[m1].got = st[m2].got /\ ~ChainState(st[m1], db).stop
       /\ FirstCheckpointHeld(m1) /\ Saturated(m1) /\ Saturated(m2)) => views[m1] = views[m2]

\* (J) and (H): honest writers drop nothing and leave no marks; marks change nothing.
HonestNeverDropped == HonestW => \A m \in MEMBERS :
    LET s == st[m]
        v == views[m]
        c == IF v.checkpoint = 0 THEN NONEREC ELSE db[v.checkpoint]
    IN (~v.stop /\ ~ChainState(s, db).stop /\ SyncedProto(m) /\ ~LeftOut(m)) =>
         \A r \in RecsOf(HeldAll, db) : IsChain(r) \/ r.id \notin s.got \/ ~Storable(s, r, db)
           \/ (c # NONEREC /\ PrunedBy(c, r)) \/ r.id \in HeldBy(s)
MarksInert == (\A i \in DOMAIN db : db[i].kit # "bent") =>
    \A m \in MEMBERS : ChainState(st[m], db).stop \/ Recut([st[m] EXCEPT !.cut = NOCUT], db).recs = st[m].recs
HonestNoMarks == HonestW => \A m \in MEMBERS : (SyncedProto(m) /\ (MARKS_GUARD \/ InGroup(m))) => DOMAIN st[m].cut.marks = {}
\* Probe (architecture 23:30Z, the core's break of 11-13): a restart that rebuilds the member
\* from what it saved (chain with its first records, kept records, the aside), forgetting what
\* it got and did not keep. Restart above re-offers the whole got set and so cannot show a
\* record the saved set lacks. SavedStable: the rebuilt member shows the same state.
\* (EARLY_ASIDE: what the set holds aside, and saves, of the roots its held heads name and its path
\* does not reach yet: under EARLY_ROOM what that room keeps, else all it got of them.)
EarlyAside(s, d) ==
    IF ~EARLY_ASIDE THEN {}
    ELSE IF EARLY_ROOM THEN EarlyKept(s, d) \ s.chain
    ELSE LET early == {h.target : h \in {h \in RecsOf(s.chain, d) : IsChain(h) /\ ~OnList(s.path, h.target)}}
         IN IdsOf({r \in RecsOf(s.got, d) : ~IsChain(r) /\ r.id \notin s.chain /\ r.signer \in early})
\* (HELD_ADMISSIONS (a), a check: every admin key's record a member holds has its admission held.)
AdmissionHeld == \A m \in MEMBERS : views[m].stop \/
    LET rs == RecsOf(st[m].recs, db)
    IN \A r \in rs : OnList(views[m].path, r.signer) \/ AdmissionsOf(rs, r.signer) # {}
\* (NEWEST_CP_FIRST's promise: a root's device records are never pushed out of its room by its own
\* checkpoints that do not count.)
\* (Promise cpWritable, architecture 11-14: while the current root's holder follows it, an
\* honest checkpoint it signs now is not refused: its set keeps it and counts it. Expected to
\* hold under WRITER_CP_FLOOR. Checked on its own, not part of Inv.)
CpWritable == \A k \in ROOT_KEYS :
    LET h == HOLDER[k]
        s == IF WRITER_LAST_ROOT THEN WithOwn(st[h], k, db) ELSE st[h]
        v == IF WRITER_LAST_ROOT THEN StoreView(s, db) ELSE views[h]
        mine == RecsOf(s.recs, db)
        counted == {x \in RecsOf(v.counting, db) : x.kind # "checkpoint"}
        keep == HonestKeepOf(k, counted, mine)
        seen == [x \in SIGNERS |-> IF x = k THEN HeadLine(AllRecs, k) ELSE HeadLine(mine, x)]
        r == Rec(nextId, k, Append(HeadLine(AllRecs, k), nextId), "checkpoint", "", "", 0, seen, seen, keep, 2)
        db2 == Put(db, nextId, r)
        s2 == InsertInto(s, r, db2)
    IN v.stop \/ Last(v.path) # k \/ nextId > FIRST + MAXREC
       \/ (r.id \in s2.recs /\ StoreView(s2, db2).checkpoint = r.id)
\* (Promise rootCanRemove, under WRITER_CP_FLOOR: the current root can always write a removal,
\* or a resolve of its own removal, and still its next checkpoint; the honest writer may
\* checkpoint first, so the records that checkpoint would keep stand in for what it holds.)
RootCanRemove == \A k \in ROOT_KEYS :
    LET h == HOLDER[k]
        s == IF WRITER_LAST_ROOT THEN WithOwn(st[h], k, db) ELSE st[h]
        v == IF WRITER_LAST_ROOT THEN StoreView(s, db) ELSE views[h]
        mine == RecsOf(s.recs, db)
        counted == {x \in RecsOf(v.counting, db) : x.kind # "checkpoint"}
        kept == {x \in counted : x.signer = k /\ x.id \in HonestKeepOf(k, counted, mine)}
    IN v.stop \/ Last(v.path) # k
       \/ RootUnits(s, k, db) + 1 + 1 + CP_UNITS <= ROOTC
       \/ SumU(kept) + 1 + 1 + CP_UNITS <= ROOTC
OwnCpsNoCrowd == \A m \in MEMBERS :
    LET s == st[m]
        v == views[m]
        cur == Last(v.path)
        cps == {c \in RecsOf(s.recs, db) : c.kind = "checkpoint" /\ c.signer = cur}
        top == MaxS({c.seq : c \in cps}, 0)
    IN v.stop \/ \A d \in RecsOf(s.got, db) :
         ~(d.signer = cur /\ d.kind \in {"admin", "device"} /\ Within(v.cuts, d) /\ d.id \notin s.recs
           /\ (v.checkpoint = 0 \/ ~PrunedBy(db[v.checkpoint], d)))
         \/ \A c \in cps : c.id = v.checkpoint \/ c.seq = top \/ c.seq < d.seq
Reload(s) ==
    \* (~SAVE_FIRSTS: a first record that a held checkpoint prunes is not saved; heads and kept
    \* first records are.)
    \* (Quint 01858aed: only the counting checkpoint prunes; a second pass takes records whose
    \* signer only a later record names, as the core loads in dependency order.)
    LET pruned == {i \in s.chain : ~IsChain(db[i]) /\ s.checkpoint # 0 /\ PrunedBy(db[s.checkpoint], db[i])}
        ch == IF SAVE_FIRSTS THEN s.chain ELSE s.chain \ pruned
        aside == EarlyAside(s, db) \cup (IF SETTLER_HELD THEN HeldAside(s, db) ELSE {})
        s2 == InsertAll(InsertAll(EMPTY, ToList(ch), db), ToList((s.recs \cup s.wait \cup aside) \ ch), db)
    IN InsertAll(s2, ToList(ch \cup s.recs \cup s.wait \cup aside), db)
RestartSaved(m) == Commit(db, nextId, m, Reload(st[m]))
SavedStable == \A m \in MEMBERS :
    (~ChainState(st[m], db).stop /\ ~views[m].stop) => Finish(Reload(st[m]), db)[2] = views[m]
RestartStable == \A m \in MEMBERS :
    LET s == st[m]
        s2 == Recut([s EXCEPT !.cut = NOCUT], db)
    IN (~views[m].stop /\ ~ChainState(s, db).stop) =>
         (s2.recs = s.recs /\ FullEvaluate(RecsOf(s2.recs, db) \cup FirstsHeld(s2, db), ChainState(s2, db)) = views[m])

\* Under UNKNOWN_HEADS no member stays live on an older root once a member past the change can reach it.
NoLiveOldRootWith(sp) == UNKNOWN_HEADS => \A m \in MEMBERS : sp[m] => \A n \in MEMBERS :
    Len(views[n].path) <= Len(views[m].path) \/ LeftOut(m) \/ ChainState(st[m], db).stop \/ ChainState(st[n], db).stop
NoLiveOldRoot == NoLiveOldRootWith([m \in MEMBERS |-> SyncedProto(m)])
\* Not a promise yet in the Quint model: a held pair of the current root halts the member.
RootPairHalts == \A m \in MEMBERS :
    LET rs == RecsOf(st[m].recs, db) \cup FirstsHeld(st[m], db)
        cur == Last(views[m].path)
    IN (\E r \in rs : r.signer = cur /\ ~IsChain(r) /\ Within(views[m].cuts, r)
          /\ \E o \in rs : o # r /\ o.signer = cur /\ o.seq = r.seq) => views[m].stop

\* The cheap promises (no re-insertion), and all of them.
PromisesCheap == CountsNewest /\ StopRootOnly /\ FollowsRecovery /\ NewcomerTakes /\ OldRootListed
                 /\ TwinStops /\ RemovedGainsNothing /\ MarksInert /\ RestartStable
Promises == OneState /\ Converges /\ ConvergesHonest /\ CountsNewest /\ RemovedStayOut /\ OneChainOneState
            /\ StopRootOnly /\ FairRoom /\ FollowsRecovery /\ NewcomerTakes /\ OldRootListed /\ TwinStops
            /\ RemovedGainsNothing /\ CompactedAgree /\ HonestNeverDropped /\ HonestNoMarks /\ MarksInert
            /\ RestartStable /\ NoLiveOldRoot
\* The same promises with the expensive per-member facts computed once per state (TLCEval
\* forces each table to a value, so no promise recomputes another's re-insertions).
PromisesFast ==
    LET sat == TLCEval([m \in MEMBERS |-> Saturated(m)])
        sp == TLCEval([m \in MEMBERS |-> SyncedProto(m)])
        halted == TLCEval([m \in MEMBERS |-> ChainState(st[m], db).stop])
        held == TLCEval(HeldAll)
        honestOnly == HonestOnly
        honestW == HonestW
        oneState == \A m \in MEMBERS :
            ((honestOnly \/ AsideAssumed(m, st[m].got)) /\ ~halted[m] /\ sat[m])
              => (st[m].recs = PureKept(st[m], db) /\ views[m] = PureView(st[m], db))
        convAt(m) ==
            (~halted[m] /\ ~views[m].stop /\ ~LeftOut(m) /\ sp[m])
              => LET k == FreshKept(st[m], HeldReach(m), db)
                 IN st[m].recs = k /\ views[m] = FullEvaluate(RecsOf(k, db) \cup FirstsHeld(st[m], db), ChainState(st[m], db))
        conv == TLCEval([m \in MEMBERS |-> convAt(m)])
        converges == \A m \in MEMBERS : AsideAssumed(m, held) => conv[m]
        convergesHonest == honestOnly => \A m \in MEMBERS : conv[m]
        synced(m) == \A i \in held : Unchanged3(st[m], InsertInto(st[m], db[i], db))
        \* (LAST_ROOT probe, the accepted price of L (owner 11-14 23:59Z): no re-issued device record (kit "z") names
        \* a device that an honest removal signed before the change removed with no honest admission between them.
        \* Expected to fire when the writer never got the removal; reported as price, never as a violation.)
        LReissuePrice == ~LAST_ROOT \/ \A i \in DOMAIN db : (db[i].kit = "z" /\ db[i].kind = "device") =>
            LET c == db[i].targetRec
                d == db[i].target
            IN ~\E j \in DOMAIN db : j < c /\ db[j].kind = "revoke" /\ db[j].kit # "deviant" /\ d \in Tgt(db[j])
                   /\ ~\E x \in DOMAIN db : j < x /\ x < c /\ db[x].kit # "deviant" /\ AdmissionsOf({db[x]}, d) # {}
        \* (LAST_ROOT form (b), binding: a re-issue never revives in the writer's own view. Every re-issued device
        \* counted in the writer's view when it signed the change, and that view held no counting removal for it.)
        LReissueW == ~LAST_ROOT \/ \A i \in DOMAIN db : (db[i].kit = "z" /\ db[i].kind = "device") =>
            db[i].target \in db[i].wv /\ db[i].target \notin db[i].wr
        \* (LEAVE_OUT, owner 11-15: a device a change left out never counts again at a member on that change's
        \* path, unless the current root, or an admin key it named, admits it afresh after the change.)
        LeftOutStaysOut == \A m \in MEMBERS : ~views[m].stop =>
            LET v == views[m]
            IN \A h \in RecsOf(DOMAIN db, db) : (IsChain(h) /\ OnList(v.path, h.target)) =>
                 \A d \in h.lo \cap v.devices : \E x \in RecsOf(v.counting, db) :
                    AdmissionsOf({x}, d) # {} /\ x.id > h.id /\ x.kit # "z" /\ x.kit # "deviant"
                    /\ (x.signer = Last(v.path) \/ \E n \in RecsOf(v.counting, db) : n.kind = "admin" /\ n.target = x.signer /\ n.signer = Last(v.path))
        \* (SPARE: along any member's path no key is named admin by two roots; a spare one root named is never
        \* named again by a later root on the same path. A recovery fork halts instead, so it is not judged here.)
        SpareFresh == ~SPARE \/ \A m \in MEMBERS : ~views[m].stop =>
            \A i, j \in st[m].got : (db[i].kind = "admin" /\ db[j].kind = "admin" /\ db[i].target = db[j].target
                 /\ OnList(views[m].path, db[i].signer) /\ OnList(views[m].path, db[j].signer)
                 /\ db[i].kit # "deviant" /\ db[j].kit # "deviant"
                 \* (architecture 11-15 08:18Z: a new root may name an old admin key again; only a SPARE (a re-issued
                 \* admin record, kit "z") must be a key no other root on the path named.)
                 /\ (db[i].kit = "z" \/ db[j].kit = "z")) => db[i].signer = db[j].signer
        \* (LAST_ROOT form (c): nothing old revives. Every counting device or admin key of a member has a
        \* counting admission signed by the last root or by an admin key it named.)
        LNoOldRevive == ~LAST_ROOT \/ \A m \in MEMBERS : ~views[m].stop =>
            LET v == views[m]
            IN \A k \in v.devices \cup DOMAIN v.admins : \E x \in RecsOf(v.counting, db) :
                 AdmissionsOf({x}, k) # {}
                 \* (named by the current root, not "a current admin": a record of an admin the current root later
                 \* revoked stays when the revoke saw it; s31ST 11-15 03:23Z, invariant form.)
                 /\ (x.signer = Last(v.path) \/ \E n \in RecsOf(v.counting, db) : n.kind = "admin" /\ n.target = x.signer /\ n.signer = Last(v.path))
        RSO(m, adm) == (gone[m] # {} /\ ~views[m].stop) => (synced(m) =>
            LET v == views[m]
                \* (LAST_ROOT, architecture 11-14 23:56Z, form (a): only the last root's removals bind; an old
                \* root's removal is forgotten after a change, see LReissueW and LNoOldRevive for the rest.)
                removals == {r \in RecsOf(st[m].got, db) : r.kind = "revoke"
                               /\ IF adm THEN r.signer \in DOMAIN v.admins
                                  ELSE IF LAST_ROOT THEN r.signer = Last(v.path) ELSE OnList(v.path, r.signer)}
                cpr == IF v.checkpoint = 0 THEN NONEREC ELSE db[v.checkpoint]
            IN \A k \in gone[m] :
                 \/ \A r \in {r \in removals : k \in Tgt(r)} : ~WriterHeld(m, r) /\ (CutOff(v, r) \/ (CutEarlier(m, r) /\ HeldByNone(r)))
                 \/ (k \notin DOMAIN v.admins /\ k \notin v.devices)
                 \/ \E x \in RecsOf(v.counting, db) : AdmissionsOf({x}, k) # {}
                       /\ \A r \in removals : (k \notin Tgt(r) \/ x.id > r.id)
                       /\ (~SEEN_ORDER \/ \E n \in removals : k \in Tgt(n) /\ (x.signer = n.signer \/ (n.signer \in DOMAIN x.seen /\ InLine(x.seen[n.signer], n.id))))
                 \/ (v.checkpoint # 0 /\ cpr.signer = Last(v.path) /\ \E x \in RecsOf(v.counting, db) :
                       AdmissionsOf({x}, k) # {} /\ x.id \in cpr.keep
                       /\ \A r \in removals : k \notin Tgt(r) \/ ~RootRemoval(r) \/ PrunedBy(cpr, r)))
        removedStayOut == \A m \in MEMBERS : RSO(m, FALSE)
        \* (LAST_ROOT form (a), second clause: removals by the admin keys the last root named, same shape.)
        removedStayOutAdm == ~LAST_ROOT \/ \A m \in MEMBERS : RSO(m, TRUE)
        \* (E_EPOCH, architecture 11-14 15:54Z: a device no removal names never stops counting, but
        \* for the stated price: an admin's admission of an older epoch than the counting checkpoint
        \* that the checkpoint does not keep.)
        deviceStays == \A m \in MEMBERS :
            (~views[m].stop /\ ~halted[m] /\ sat[m] /\ synced(m)) =>
            LET v == views[m]
                cp == IF v.checkpoint = 0 THEN NONEREC ELSE db[v.checkpoint]
            IN \A x \in RecsOf(st[m].recs, db) :
                 (x.kind = "device" /\ ~\E r \in RecsOf(DOMAIN db, db) : r.kind = "revoke" /\ (x.target \in Tgt(r) \/ x.signer \in Tgt(r)))
                 => \/ x.target \in v.devices
                    \/ (cp # NONEREC /\ x.ep < cp.ep /\ x.id \notin (IF E_ALL THEN AnchorsOf(cp) ELSE cp.keep))
                    \/ (x.signer \notin DOMAIN v.admins /\ ~OnList(v.path, x.signer))
                    \* (scope, architecture 11-14: in code the current root's own device writes its records,
                    \* so a device whose admission that device never got is not promised.)
                    \/ x.id \notin st[HOLDER[Last(v.path)]].got
                    \* (LEAVE_OUT: a device a later change on the path left out is out.)
                    \/ \E h \in RecsOf(DOMAIN db, db) : IsChain(h) /\ x.target \in h.lo /\ OnList(v.path, h.target) /\ h.id > x.id
        oneChainOneState == \A m1, m2 \in MEMBERS :
            (st[m1].chain = st[m2].chain /\ st[m1].recs = st[m2].recs /\ st[m1].got = st[m2].got
               /\ sat[m1] /\ sat[m2]) => views[m1] = views[m2]
        compactedAgree == \A m1, m2 \in MEMBERS :
            (st[m1].chain = st[m2].chain /\ st[m1].got = st[m2].got /\ ~halted[m1]
               /\ FirstCheckpointHeld(m1) /\ sat[m1] /\ sat[m2]) => views[m1] = views[m2]
        fairRoom == \A m \in MEMBERS :
            LET s == st[m]
                rs == RecsOf(s.recs, db)
                got == RecsOf(s.got, db)
                pc == PathCuts(ChainState(s, db))
                path == pc.path
                ceil == Ceilings(path, Learned(got, path, pc.cuts))
                legit == RootsOf(path) \cup {r.target : r \in {r \in got : OnList(path, r.signer) /\ r.kind = "admin"}}
                owners == {k \in {r.signer : r \in {r \in got : ~IsChain(r)}} : k \in DOMAIN ceil}
                cps == {c \in rs : c.id = views[m].checkpoint /\ c.signer = Last(path)}
                first == IF cps = {} THEN {} ELSE LET cp == CHOOSE c \in cps : TRUE IN {r \in rs : r = cp \/ NamedBy(cp, r, rs)}
                stor == {r \in got : Storable(s, r, db) /\ ~EOld(s, path, pc.cuts, r, db)}
                \* (TIER_MODE "zero", #530 9e20ec86: fixed caps from the roster; a key with no room is
                \* promised nothing, every other key its cap.)
                zero == TWO_TIERS /\ TIER_MODE = "zero"
                noRoom == IF zero THEN SecondOf(got, path, pc.cuts) ELSE {}
                others == {k \in owners : k \notin noRoom /\ \E r \in stor : r.signer = k /\ r \notin first}
                fair == IF others = {} \/ zero THEN ROOM ELSE (ROOM - SumU(first)) \div Cardinality(others)
            IN /\ \A k \in DOMAIN ceil : k \in legit
               /\ SumU(rs) <= ROOM
               /\ \A k \in {r.signer : r \in rs} : k \in DOMAIN ceil /\ SumU(OfKey(rs, k)) <= ceil[k]
               \* (a stopped view promises no room: under fixed caps "fair" is the cap itself.)
               /\ (~halted[m] /\ sat[m] /\ (~zero \/ ~views[m].stop)) =>
                    \A k \in others : SumU(OfKey(rs, k)) + MAXU - 1 >= Min2(fair, Min2(ceil[k], SumU(OfKey(stor, k))))
        honestNeverDropped == honestW => \A m \in MEMBERS :
            LET cc == {x \in RecsOf(views[m].counting \cap DOMAIN db, db) : x.kind = "checkpoint" /\ x.signer = Last(views[m].path)}
                c == IF HND_NEWEST /\ cc # {} THEN NewestCp(cc)
                     ELSE IF views[m].checkpoint = 0 THEN NONEREC ELSE db[views[m].checkpoint]
            IN (~views[m].stop /\ ~halted[m] /\ sp[m] /\ ~LeftOut(m)) =>
                 \A r \in RecsOf(held, db) : IsChain(r) \/ r.id \notin st[m].got \/ ~Storable(st[m], r, db)
                   \/ (c # NONEREC /\ PrunedByP(views[m].path, c, r)) \/ r.id \in HeldBy(st[m])
                   \* (Seen line: a record its key signed before it saw the current root's grant is void, held while
                   \* there is room, charged, never counting; dropping it for room loses nothing that counts.)
                   \/ VoidAt(m, r)
                   \* (TIER_MODE "zero", #530 9e20ec86: a key with no room keeps nothing outside a checkpoint.)
                   \/ (TWO_TIERS /\ TIER_MODE = "zero"
                       /\ r.signer \in SecondOf(RecsOf(st[m].got, db), views[m].path, PathCuts(ChainState(st[m], db)).cuts))
        honestNoMarks == honestW => \A m \in MEMBERS : sp[m] => DOMAIN st[m].cut.marks = {}
    IN /\ PromisesCheap
       /\ oneState /\ deviceStays /\ converges /\ convergesHonest /\ removedStayOut /\ oneChainOneState /\ LReissueW /\ LNoOldRevive /\ removedStayOutAdm /\ SpareFresh /\ LeftOutStaysOut
       /\ fairRoom /\ compactedAgree /\ honestNeverDropped /\ honestNoMarks /\ NoLiveOldRootWith(sp)

PFParts ==
    LET sat == TLCEval([m \in MEMBERS |-> Saturated(m)])
        sp == TLCEval([m \in MEMBERS |-> SyncedProto(m)])
        halted == TLCEval([m \in MEMBERS |-> ChainState(st[m], db).stop])
        held == TLCEval(HeldAll)
        honestOnly == HonestOnly
        honestW == HonestW
        oneState == \A m \in MEMBERS :
            ((honestOnly \/ AsideAssumed(m, st[m].got)) /\ ~halted[m] /\ sat[m])
              => (st[m].recs = PureKept(st[m], db) /\ views[m] = PureView(st[m], db))
        convAt(m) ==
            (~halted[m] /\ ~views[m].stop /\ ~LeftOut(m) /\ sp[m])
              => LET k == FreshKept(st[m], HeldReach(m), db)
                 IN st[m].recs = k /\ views[m] = FullEvaluate(RecsOf(k, db) \cup FirstsHeld(st[m], db), ChainState(st[m], db))
        conv == TLCEval([m \in MEMBERS |-> convAt(m)])
        converges == \A m \in MEMBERS : AsideAssumed(m, held) => conv[m]
        convergesHonest == honestOnly => \A m \in MEMBERS : conv[m]
        synced(m) == \A i \in held : Unchanged3(st[m], InsertInto(st[m], db[i], db))
        \* (LAST_ROOT probe, the accepted price of L (owner 11-14 23:59Z): no re-issued device record (kit "z") names
        \* a device that an honest removal signed before the change removed with no honest admission between them.
        \* Expected to fire when the writer never got the removal; reported as price, never as a violation.)
        LReissuePrice == ~LAST_ROOT \/ \A i \in DOMAIN db : (db[i].kit = "z" /\ db[i].kind = "device") =>
            LET c == db[i].targetRec
                d == db[i].target
            IN ~\E j \in DOMAIN db : j < c /\ db[j].kind = "revoke" /\ db[j].kit # "deviant" /\ d \in Tgt(db[j])
                   /\ ~\E x \in DOMAIN db : j < x /\ x < c /\ db[x].kit # "deviant" /\ AdmissionsOf({db[x]}, d) # {}
        \* (LAST_ROOT form (b), binding: a re-issue never revives in the writer's own view. Every re-issued device
        \* counted in the writer's view when it signed the change, and that view held no counting removal for it.)
        LReissueW == ~LAST_ROOT \/ \A i \in DOMAIN db : (db[i].kit = "z" /\ db[i].kind = "device") =>
            db[i].target \in db[i].wv /\ db[i].target \notin db[i].wr
        \* (LEAVE_OUT, owner 11-15: a device a change left out never counts again at a member on that change's
        \* path, unless the current root, or an admin key it named, admits it afresh after the change.)
        LeftOutStaysOut == \A m \in MEMBERS : ~views[m].stop =>
            LET v == views[m]
            IN \A h \in RecsOf(DOMAIN db, db) : (IsChain(h) /\ OnList(v.path, h.target)) =>
                 \A d \in h.lo \cap v.devices : \E x \in RecsOf(v.counting, db) :
                    AdmissionsOf({x}, d) # {} /\ x.id > h.id /\ x.kit # "z" /\ x.kit # "deviant"
                    /\ (x.signer = Last(v.path) \/ \E n \in RecsOf(v.counting, db) : n.kind = "admin" /\ n.target = x.signer /\ n.signer = Last(v.path))
        \* (SPARE: along any member's path no key is named admin by two roots; a spare one root named is never
        \* named again by a later root on the same path. A recovery fork halts instead, so it is not judged here.)
        SpareFresh == ~SPARE \/ \A m \in MEMBERS : ~views[m].stop =>
            \A i, j \in st[m].got : (db[i].kind = "admin" /\ db[j].kind = "admin" /\ db[i].target = db[j].target
                 /\ OnList(views[m].path, db[i].signer) /\ OnList(views[m].path, db[j].signer)
                 /\ db[i].kit # "deviant" /\ db[j].kit # "deviant"
                 \* (architecture 11-15 08:18Z: a new root may name an old admin key again; only a SPARE (a re-issued
                 \* admin record, kit "z") must be a key no other root on the path named.)
                 /\ (db[i].kit = "z" \/ db[j].kit = "z")) => db[i].signer = db[j].signer
        \* (LAST_ROOT form (c): nothing old revives. Every counting device or admin key of a member has a
        \* counting admission signed by the last root or by an admin key it named.)
        LNoOldRevive == ~LAST_ROOT \/ \A m \in MEMBERS : ~views[m].stop =>
            LET v == views[m]
            IN \A k \in v.devices \cup DOMAIN v.admins : \E x \in RecsOf(v.counting, db) :
                 AdmissionsOf({x}, k) # {}
                 \* (named by the current root, not "a current admin": a record of an admin the current root later
                 \* revoked stays when the revoke saw it; s31ST 11-15 03:23Z, invariant form.)
                 /\ (x.signer = Last(v.path) \/ \E n \in RecsOf(v.counting, db) : n.kind = "admin" /\ n.target = x.signer /\ n.signer = Last(v.path))
        RSO(m, adm) == (gone[m] # {} /\ ~views[m].stop) => (synced(m) =>
            LET v == views[m]
                \* (LAST_ROOT, architecture 11-14 23:56Z, form (a): only the last root's removals bind; an old
                \* root's removal is forgotten after a change, see LReissueW and LNoOldRevive for the rest.)
                removals == {r \in RecsOf(st[m].got, db) : r.kind = "revoke"
                               /\ IF adm THEN r.signer \in DOMAIN v.admins
                                  ELSE IF LAST_ROOT THEN r.signer = Last(v.path) ELSE OnList(v.path, r.signer)}
                cpr == IF v.checkpoint = 0 THEN NONEREC ELSE db[v.checkpoint]
            IN \A k \in gone[m] :
                 \/ \A r \in {r \in removals : k \in Tgt(r)} : ~WriterHeld(m, r) /\ (CutOff(v, r) \/ (CutEarlier(m, r) /\ HeldByNone(r)))
                 \/ (k \notin DOMAIN v.admins /\ k \notin v.devices)
                 \/ \E x \in RecsOf(v.counting, db) : AdmissionsOf({x}, k) # {}
                       /\ \A r \in removals : (k \notin Tgt(r) \/ x.id > r.id)
                       /\ (~SEEN_ORDER \/ \E n \in removals : k \in Tgt(n) /\ (x.signer = n.signer \/ (n.signer \in DOMAIN x.seen /\ InLine(x.seen[n.signer], n.id))))
                 \/ (v.checkpoint # 0 /\ cpr.signer = Last(v.path) /\ \E x \in RecsOf(v.counting, db) :
                       AdmissionsOf({x}, k) # {} /\ x.id \in cpr.keep
                       /\ \A r \in removals : k \notin Tgt(r) \/ ~RootRemoval(r) \/ PrunedBy(cpr, r)))
        removedStayOut == \A m \in MEMBERS : RSO(m, FALSE)
        \* (LAST_ROOT form (a), second clause: removals by the admin keys the last root named, same shape.)
        removedStayOutAdm == ~LAST_ROOT \/ \A m \in MEMBERS : RSO(m, TRUE)
        \* (E_EPOCH, architecture 11-14 15:54Z: a device no removal names never stops counting, but
        \* for the stated price: an admin's admission of an older epoch than the counting checkpoint
        \* that the checkpoint does not keep.)
        deviceStays == \A m \in MEMBERS :
            (~views[m].stop /\ ~halted[m] /\ sat[m] /\ synced(m)) =>
            LET v == views[m]
                cp == IF v.checkpoint = 0 THEN NONEREC ELSE db[v.checkpoint]
            IN \A x \in RecsOf(st[m].recs, db) :
                 (x.kind = "device" /\ ~\E r \in RecsOf(DOMAIN db, db) : r.kind = "revoke" /\ (x.target \in Tgt(r) \/ x.signer \in Tgt(r)))
                 => \/ x.target \in v.devices
                    \/ (cp # NONEREC /\ x.ep < cp.ep /\ x.id \notin (IF E_ALL THEN AnchorsOf(cp) ELSE cp.keep))
                    \/ (x.signer \notin DOMAIN v.admins /\ ~OnList(v.path, x.signer))
                    \* (scope, architecture 11-14: in code the current root's own device writes its records,
                    \* so a device whose admission that device never got is not promised.)
                    \/ x.id \notin st[HOLDER[Last(v.path)]].got
                    \* (LEAVE_OUT: a device a later change on the path left out is out.)
                    \/ \E h \in RecsOf(DOMAIN db, db) : IsChain(h) /\ x.target \in h.lo /\ OnList(v.path, h.target) /\ h.id > x.id
        oneChainOneState == \A m1, m2 \in MEMBERS :
            (st[m1].chain = st[m2].chain /\ st[m1].recs = st[m2].recs /\ st[m1].got = st[m2].got
               /\ sat[m1] /\ sat[m2]) => views[m1] = views[m2]
        compactedAgree == \A m1, m2 \in MEMBERS :
            (st[m1].chain = st[m2].chain /\ st[m1].got = st[m2].got /\ ~halted[m1]
               /\ FirstCheckpointHeld(m1) /\ sat[m1] /\ sat[m2]) => views[m1] = views[m2]
        fairRoom == \A m \in MEMBERS :
            LET s == st[m]
                rs == RecsOf(s.recs, db)
                got == RecsOf(s.got, db)
                pc == PathCuts(ChainState(s, db))
                path == pc.path
                ceil == Ceilings(path, Learned(got, path, pc.cuts))
                legit == RootsOf(path) \cup {r.target : r \in {r \in got : OnList(path, r.signer) /\ r.kind = "admin"}}
                owners == {k \in {r.signer : r \in {r \in got : ~IsChain(r)}} : k \in DOMAIN ceil}
                cps == {c \in rs : c.id = views[m].checkpoint /\ c.signer = Last(path)}
                first == IF cps = {} THEN {} ELSE LET cp == CHOOSE c \in cps : TRUE IN {r \in rs : r = cp \/ NamedBy(cp, r, rs)}
                stor == {r \in got : Storable(s, r, db) /\ ~EOld(s, path, pc.cuts, r, db)}
                \* (TIER_MODE "zero", #530 9e20ec86: fixed caps from the roster; a key with no room is
                \* promised nothing, every other key its cap.)
                zero == TWO_TIERS /\ TIER_MODE = "zero"
                noRoom == IF zero THEN SecondOf(got, path, pc.cuts) ELSE {}
                others == {k \in owners : k \notin noRoom /\ \E r \in stor : r.signer = k /\ r \notin first}
                fair == IF others = {} \/ zero THEN ROOM ELSE (ROOM - SumU(first)) \div Cardinality(others)
            IN /\ \A k \in DOMAIN ceil : k \in legit
               /\ SumU(rs) <= ROOM
               /\ \A k \in {r.signer : r \in rs} : k \in DOMAIN ceil /\ SumU(OfKey(rs, k)) <= ceil[k]
               \* (a stopped view promises no room: under fixed caps "fair" is the cap itself.)
               /\ (~halted[m] /\ sat[m] /\ (~zero \/ ~views[m].stop)) =>
                    \A k \in others : SumU(OfKey(rs, k)) + MAXU - 1 >= Min2(fair, Min2(ceil[k], SumU(OfKey(stor, k))))
        honestNeverDropped == honestW => \A m \in MEMBERS :
            LET cc == {x \in RecsOf(views[m].counting \cap DOMAIN db, db) : x.kind = "checkpoint" /\ x.signer = Last(views[m].path)}
                c == IF HND_NEWEST /\ cc # {} THEN NewestCp(cc)
                     ELSE IF views[m].checkpoint = 0 THEN NONEREC ELSE db[views[m].checkpoint]
            IN (~views[m].stop /\ ~halted[m] /\ sp[m] /\ ~LeftOut(m)) =>
                 \A r \in RecsOf(held, db) : IsChain(r) \/ r.id \notin st[m].got \/ ~Storable(st[m], r, db)
                   \/ (c # NONEREC /\ PrunedByP(views[m].path, c, r)) \/ r.id \in HeldBy(st[m])
                   \* (Seen line: a record its key signed before it saw the current root's grant is void, held while
                   \* there is room, charged, never counting; dropping it for room loses nothing that counts.)
                   \/ VoidAt(m, r)
                   \* (TIER_MODE "zero", #530 9e20ec86: a key with no room keeps nothing outside a checkpoint.)
                   \/ (TWO_TIERS /\ TIER_MODE = "zero"
                       /\ r.signer \in SecondOf(RecsOf(st[m].got, db), views[m].path, PathCuts(ChainState(st[m], db)).cuts))
        honestNoMarks == honestW => \A m \in MEMBERS : sp[m] => DOMAIN st[m].cut.marks = {}
    IN [PromisesCheap |-> PromisesCheap, oneState |-> oneState, converges |-> converges, convergesHonest |-> convergesHonest, removedStayOut |-> removedStayOut, oneChainOneState |-> oneChainOneState, fairRoom |-> fairRoom, compactedAgree |-> compactedAgree, honestNeverDropped |-> honestNeverDropped, honestNoMarks |-> honestNoMarks, deviceStays |-> deviceStays, LReissueW |-> LReissueW, LNoOldRevive |-> LNoOldRevive, removedStayOutAdm |-> removedStayOutAdm, SpareFresh |-> SpareFresh, LeftOutStaysOut |-> LeftOutStaysOut, LReissuePrice |-> LReissuePrice, noLiveOld |-> NoLiveOldRootWith(sp)]



\* --- Order probes (architecture 11-14 08:09Z) -------------------------------------
\* Rebuild a member's view from what it holds (stored, waiting, aside, chain; not got), in a given order, re-offered once.
RECURSIVE RevL(_)
RevL(l) == IF l = <<>> THEN <<>> ELSE RevL(Tail(l)) \o <<Head(l)>>
FromHeld(l) == Finish(InsertAll(InsertAll(EMPTY, l, db), l, db), db)[2]
\* FuncOfHeld: what a member keeps and sees equals the function of the records it holds
\* (ascending order). Confluent: the same held set in ascending and descending order ends equal.
\* FuncOfHeld and Confluent at once: the ascending rebuild is shared, and the broken one is printed.
HeldAgree == \A m \in MEMBERS :
    LET v == views[m]
        l == ToList(HeldBy(st[m]))
        a == FromHeld(l)
    IN IF ~(v.stop \/ a = v) THEN PrintT(<<"VIOLATED", "FuncOfHeld", m>>) /\ FALSE
       ELSE IF a # FromHeld(RevL(l)) THEN PrintT(<<"VIOLATED", "Confluent", m>>) /\ FALSE
       ELSE TRUE
\* All the named parts of PFParts in one pass (PFParts is built once per state, not once per part);
\* the broken parts are printed by name.
PFAll(names) == LET p == PFParts IN \A f \in names : p[f] \/ (PrintT(<<"VIOLATED", f>>) /\ FALSE)
FuncOfHeld == \A m \in MEMBERS :
    LET v == views[m] IN v.stop \/ FromHeld(ToList(HeldBy(st[m]))) = v
Confluent == \A m \in MEMBERS :
    LET l == ToList(HeldBy(st[m])) IN FromHeld(l) = FromHeld(RevL(l))

=============================================================================
