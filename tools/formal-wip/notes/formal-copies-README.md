<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Model 1: copies sealed end to end (Tamarin)

Files: `copies.spthy` (the model; tactic `copies` and the KU helpers),
`copies_v1.spthy` (the earlier version without the tactic, kept for the
record). Logs: `out/`, summary `out/runs.sum`.

Tools: Tamarin 1.10, Maude 3.4. Run one lemma:
`tamarin-prover --prove=<lemma> copies.spthy +RTS -M3g -N1 -RTS`.

## What is modelled, against the code

Sources: format-0.6-bytes sections 10 and 21, plans/e2e-copies-0.6-ru.md,
`core/src/copies`, `core/src/records/statement.rs`, `core/src/keystore`
at #530.

- One group with a root key and an admin key; both sign the records that
  admit a device (rights `rw`, or `fwd` for a forward-only hub that cannot
  read) and that remove one.
- A device: a member key and weekly sealing epochs. Each epoch is a fresh
  X-Wing secret, published in a keys statement signed by the member key
  alone (no root or admin signs it). An erased epoch is gone for good.
- A copy: a fresh key K; header = id, origin, time, readers with epochs,
  commit(K); h = H(header); payload = AEAD(H(K, h), content); one HPKE wrap
  of K per reader, bound to h; the origin's ES256 signature over h, the
  wraps and the payload.
- A reader checks the origin is counted with send rights in its own view,
  the signature, its wrap, the commit, the payload, and that the signed
  time is newer than the last it took from that origin (A-61).
- Sealing again (`reseal`) to a former reader the origin still counts.

Abstractions: HPKE, ChaCha20-Poly1305 and ES256 are ideal. The symbolic
AEAD commits to its key and the real one does not; that is why the format
carries `commit`, and `consistent_content` is about the model's AEAD. A
sender may seal to any statement of a device it saw, not only the newest:
this gives the attacker more. The records' evaluation is abstracted to "a
record signed by root or admin counts at once". One group.

Attacker: the network (relay, hub link, forwarder); any device's member key
and any epoch secret still held, at any time (so a removed device with all
it ever held is covered); the root key and the admin key.

## Results

Clean run from the top (20:43Z), 1800 s per lemma, heap 3 GB.

| Lemma | What it says | Result |
|---|---|---|
| foreign_reader | a reader epoch not made by its device means that device's member key leaked, or a stolen root/admin key admitted a fake device | verified (713) |
| key_secret, key_secret_ku | a copy key is learnt only through a reader's leaked epoch or a fake reader | verified (5000, 5000) |
| content_via_key | the content is learnt only after the copy key | verified (26) |
| content_secret | a copy's content is learnt only through one of its readers | verified (3537) |
| root_admin_open_nothing | the root and admin keys alone open no copy of real devices | verified (11541) |
| removed_not_reader, removed_reader_none | a removed device is never sealed to afterwards | verified (44, 9) |
| removed_cannot_read | a copy sealed after a removal is not opened through the removed device | verified (945) |
| forward_only_not_reader | a forward-only hub is never a reader (unless root/admin key leaked) | verified (2215) |
| origin | an accepted copy was sealed by its origin, or the origin's key leaked | verified (170) |
| origin_counted | no copy is accepted from an origin after its removal | verified (52) |
| no_replay | one copy per origin and signed time | verified (4) |
| consistent_content | two readers of one signed copy get one content | verified (27) |
| reader_was_sealed_to | a reader accepts only copies sealed to it | verified (113) |
| erased_stays_erased | an erased epoch never leaks afterwards | verified (2) |
| newcomer_reads_nothing_older | a device admitted later reads no older copy | **open** (time, 1800 s) |
| admin_key_admits_reader | illustration: a stolen admin key admits the attacker as a reader | **open** (time) |
| exec_one_open | reachability: a reader accepts a copy with no key leaked | verified (24, heuristic S) |
| exec_both_open, exec_reseal | reachability: both readers; a resealed copy | **open** (time) |

## The weekly epoch, in plain words

A leaked sealing secret opens only the copies sealed to that epoch. Once
the sender holds the device's newer keys statement, later copies go to the
new epoch and are safe from the old secret. A network that withholds the
newer statement can stretch this window up to 35 days
(`STATEMENT_MAX_AGE_MS`); after that the sender refuses the old statement.

## Statement changes (reported, not silent)

- `content_secret`, `root_admin_open_nothing` and `removed_cannot_read`
  now say `KU(m)` instead of `K(m)`. KU is the attacker's construction
  of m, which happens whenever K(m) does, so the new form is at least as
  strong.
- Helpers added: `content_via_key` (the content is learnt only after the
  copy key), `key_secret_ku` (the copy key is learnt only from a reader's
  epoch secret or a foreign epoch), `removed_reader_none` (a device removed
  before a copy was sealed is never its reader).

## Not claimed

- Rules of incoming copies other than A-61 (lifetime, clock allowance,
  too-old rules, halted groups), content types, reduced copies for a leaf,
  blobs: covered by tests, not here.
- Indistinguishability ("a removed device cannot tell two later copies
  apart") and strong secrecy: those are ProVerif's, see `../formal-copies-pv/`.
- `newcomer_reads_nothing_older`: open (time). Related and proven:
  `reader_was_sealed_to`, a reader accepts only copies sealed to it.
- Reachability of both readers in one trace and of a resealed copy
  (`exec_both_open`, `exec_reseal`): open. The full accept path itself is
  reachable (`exec_one_open`), so the lemmas above are not vacuous.
