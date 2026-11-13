<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Model 3: binding a guarded leaf (Tamarin)

Files: `leaf.spthy` (the rule as built), `leaf_fork.spthy` (the same plus a
fork of the root, `Kept.forked`), `leaf_remote.spthy` (a variant that is NOT
the design: a waiting leaf takes a remote grant after a change of root; it
shows what the rule is for). Logs: `out/`, summary `out/runs.sum`.

Tools: Tamarin 1.10, Maude 3.4. Run one lemma:
`tamarin-prover --prove=<lemma> leaf.spthy +RTS -M3g -N1 -RTS`.
Each lemma carries its own heuristic (`[heuristic={name}]` or `=S`);
the tactics are declared before the lemmas.

## What is modelled, against the code

The code at #530: `core/src/format/grant.rs` (`Kept`, `read_bound`,
`Kept::needs_rebind`, `accept_leaf` filters `!kept.forked && !needs_rebind`),
`core/src/join/invitation.rs` (`Matched::binding(self, kept, head, exporter)`,
heads 93e0c288 and 7ed330f0), `core/src/commands/mod.rs` (`Nonces`).

The rule, in its fixed form (audit 11-13):

- The leaf waits for the root at the seq it keeps: the first root at seq 1,
  or the new root a head signed by both recovery halves named. The wait is
  derived from the stored seq.
- A binding exists only after the root's device answered with the code read
  at the leaf (a shown code alone binds nothing), is used once, and is valid
  only for the (root, seq) the leaf keeps.
- A bound leaf takes later grants of the same root and seq from anyone
  (refresh), each counter once.
- A head at seq s+1 ends seq s: the leaf obeys nobody until bound in person
  at s+1.
- Fork (`leaf_fork.spthy`): a leaf that sees two different records its root
  signed at one position marks the root forked, obeys nobody, takes no grant
  of that seq, and comes back only by a head and a new binding.

Abstractions: the PAKE is ideal (key = H(code, both nonces)); six digits
guessed online are not symbolic (the attempt bound is the counting model's
question); seqs are natural numbers; one commander per grant (more are the
same case); no clocks, so staleness after 35 days of running time is not
here (an attacker who withholds grants makes the leaf stale: that is
availability, not modelled).

Attacker: the network and every neighbour of the leaf, any admin key, the
root key of any seq, a commander's key (a stolen member device), and the
recovery pair only where a lemma says so. It never reads the code on the
leaf's screen.

## Results

Clean run of each file from the top (helpers before the lemmas that reuse
them), 900 s per lemma, heap 2–3 GB. Steps are Tamarin's proof steps.

| Lemma | What it says | leaf | leaf_fork |
|---|---|---|---|
| code_secret, code_secret_bind, bind_key_secret | the code and the PAKE key stay with the person and the two devices | verified (7, 7, 3) | verified (9, 9, 3) |
| bind_mac_origin | a MAC under the binding key comes from the root's device | verified (8) | verified (10) |
| root_key_secret | a root key is known only by its reveal | verified (7) | verified (7) |
| bound_root_genuine | the root a leaf is bound to is a real root of that seq | verified (10) | verified (12) |
| bound_grant_signed, regrant_signed | a grant taken was issued by that root, or the root key leaked | verified (2, 11) | verified (2, 13) |
| bind_needs_code | a binding needs the root device's answer to the code | verified (2) | verified (2) |
| binding_after_answer | the answer comes after the code was shown at the leaf | verified (7) | verified (9) |
| binding_for_kept_root | binding only for the (root, seq) the leaf keeps | verified (7) | verified (9) |
| binding_once | one binding per seq | verified (22) | verified (30) |
| binding_ends_at_head | no grant of seq s used after the head at s+1 | verified (5) | verified (8) |
| obeys_nobody_until_rebound | after a change of root, obeys nobody until bound in person at the new seq | verified (11) | verified (16) |
| head_from_recovery | the new root is one both recovery halves named, unless the pair leaked | verified (44) | verified (74) |
| obeys_bound | obeys only under a binding it holds | verified (3) | verified (3) |
| obeys_granted | the commander was granted by that root, or the root key leaked | verified (8) | verified (8) |
| obeys_signed | an honest commander signed the order, or its key leaked | verified (5) | verified (5) |
| no_command_replay | an order is obeyed once (honest commander, or its key leaked) | verified (20) | verified (20) |
| forked_obeys_nobody | after a fork no grant of that seq is used | n/a | verified (2) |
| fork_needs_root_key | a fork the leaf takes needs that root's key | n/a | verified (13) |
| exec_bind_and_obey | reachability: bind and obey with no key leaked | verified (56) | verified (56) |
| leaked_pair_stops_lock | expected trace: with the pair leaked, a network can stop the lock | trace found (61) | trace found (61) |
| no_older_seq_grant | after a head at s2, no grant of any lower seq is taken | **open** (memory) | not run |
| exec_rebind_after_head | reachability: new root, new binding, command | **open** (time) | not run |
| exec_fork_then_rebind | reachability: fork, head, new binding, command | n/a | **open** (time) |

Helpers wait_once, show_once, show_for_kept: verified in both.

`leaf_remote.spthy` (not the design): the reachability `remote_bind_without_code`
(bound at the new seq with no code read) timed out at 900 s; open.

## Statement fixes (reported, not silent)

- `obeys_only_bound_root` was false as written: if the root key of a seq
  leaks, the attacker issues a grant naming its own commander and signs
  commands with it. It is split into `obeys_bound` (the leaf obeys only
  under a binding it holds), `obeys_granted` (the commander was granted by
  that root, or the root key leaked) and `obeys_signed` (an honest
  commander signed the order, or its key leaked).
- `no_command_replay` gains the same condition: the commander is an honest
  one (`CommanderKey`), or its key leaked.
- `binding_ends_at_head` was first written `#u < #h`; the rule that takes a
  head also uses the old grant in the same step, so it now reads
  `not (#h < #u)`: no grant of seq s is used after the head at s+1.
- Helpers added (labels only, no rule changed): `RootKey`, `WaitMade`,
  `ShowAt`, `ShowFor`, `LeafWaits`, `BindMac`. `!Bound` was split into
  `!BoundRoot` (made once at binding) and `!Grant` (rewritten by refresh);
  the behaviour is the same.

## Not claimed

- The ordinary (unguarded) leaf: it takes admin grants and is out of this
  model.
- Availability: a network that withholds heads or grants can stop a bound
  lock for good if the recovery pair leaked (`leaked_pair_stops_lock`, an
  expected trace), or make it stale.
- `no_older_seq_grant`: open. What is proven: `binding_ends_at_head`, no
  grant of seq s is used (refresh, obey, nonce) after the head at s+1.
  Argued on paper only: a fresh binding at an older seq needs that seq's
  waiting state, which the head consumed and which is made once
  (`wait_once`, `show_once`, verified); the induction over seqs further
  back did not finish in Tamarin.
- Reachability at seq 2 with a new binding (`exec_rebind_after_head`,
  `exec_fork_then_rebind`): open; a head at seq 2 itself is reachable
  (12 steps).

## How to keep these proofs terminating

See the formal-join README, section "How to keep these proofs terminating":
tactics with `prio`/`deprio` per lemma, helpers on explicit terms, never
reuse an unproven helper, `not (#h < #u)` when one rule carries both labels.
