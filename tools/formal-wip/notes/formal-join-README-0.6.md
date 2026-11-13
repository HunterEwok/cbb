<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Entry by code in Tamarin: results of 2026-11-13

Tamarin 1.10 and Maude 3.4, in the cloud. Run one lemma with `./run2.sh . <theory> <lemma> <seconds>`, or all of them with `./runall2.sh . <theory> <seconds>`. The results land in `out2/runs.sum` (time and peak memory per lemma) and `out2/<theory>__<lemma>.txt`.

## The models

| File | What it models |
|---|---|
| `jm2.spthy` | **The protocol with J-1, as built** at #530 8f48962. The invitation ID goes into CPace's channel identifier (`cbb pair channel v3` 0x00, member key hash, joiner key hash, invitation ID) and into the short code (`cbb short code v3` 0x00, exporter, nj, nm, invitation ID). The all-zero ID is refused for an invitation. |
| `jd2.spthy` | **The protocol before J-1.** The same model without the invitation ID in the CPace key and in the code. |
| `home/jhome.spthy` | **Pairing at home without an invitation.** A variant of jm2: the CPace password is public, the zero ID is used in CI, the code and Info, and a home window takes one attempt. The person comparing six digits is the only step outside the network. |
| `jcex3.spthy` | jmain without the reveal rules, with the guided search that found the trace for the mis-stated lemma (below). |

Three labels were added to jmain to make jm2 and jd2, and no rule changed: `MacSent(mk, x)` on J_Confirm and M_Welcome, `WelcomeMac(mk, g, pkS, pkC, s, sid, k)` on M_Welcome, and `JAccMk(mk, s, k)` on J_Welcome. They serve the helpers `mac_origin` and `welcome_mac`.

**Wiring assumption.** CPace's session_id is the TLS exporter, and its AD is Info / ADb. The new join flow did not call CPace yet at 8f48962. Architecture made this a wave 5 rule with a test.

## Results

"verified" means proved for every attacker move. "no trace found" on an exists-trace lemma means Tamarin proved that no trace exists: the attack it describes is impossible in the model.

### jm2 (with J-1), full rerun ending 20:25Z

| Lemma | Says | Result |
|---|---|---|
| secret_s, secret_ca, secret_mk, secret_cb | the invitation secret and the CPace values stay secret unless the invitation leaked | verified (4 to 33 steps) |
| joiner_reply_origin, same_sid_same_invitation, welcome_origin, joiner_key_origin, welcome_key_origin, mac_origin, welcome_mac | helpers | verified |
| one_code_one_pair | a matched code binds the admitted key to the device whose screen was compared, and that device ran TLS with this admitter, unless six digits collided | verified (12) |
| admitted_holder_none | without a code, only a holder of the invitation is admitted, unless it leaked | verified (402) |
| **admitted_holder_match_same_session** | with the code, the session the person approved admits only a joiner of this invitation, unless six digits collided in this session | **verified (13)** |
| admitted_holder_match_same_session_unless_revealed | the same, with a stolen key named | verified (13) |
| **joiner_agreement** | the joiner joins the admitter that admitted it in this TLS session, unless the invitation leaked | **verified (742)** |
| admin_key_proven_here | an offered admin key goes in only with its holder's proof over this session | verified (419) |
| single_use | an invitation admits once | verified (846) |
| secret_only_by_leak | the secret reaches the network only by a leak | verified (2) |
| other_invitation_admitted, _no_reveal, _s_kept, _no_leak | a joiner of another invitation admitted under this one | no trace found |
| same_session_member_key_only, same_session_admin_key_only, member_key_only_own_kept, member_key_only_same_group | the same with one stolen key | no trace found |
| exec_match, exec_none | reachability: an admission with the code and without | trace found (33, 27) |
| admitted_holder_match_even_if_leaked, admitted_holder_match_unless_revealed | the first wording, **not claimed** (see below) | not run to the end |

### jd2 (before J-1), full run ending 19:17Z

Every lemma in the jm2 table has the same result in jd2: the same lemmas verified, the same "no trace found". Steps differ, for example joiner_agreement took 1562 steps and single_use 3166.

### jhome (at home without an invitation)

| Lemma | Says | Result |
|---|---|---|
| one_code_one_pair | the admitted key is the key of the device whose screen the person saw, and that device ran TLS with this member, unless six digits collided in this attempt | verified (12) |
| home_admitted_is_shown_device | a device joins only with the key of a real joiner, unless six digits collided | verified (4) |
| single_use | one home window admits once | verified (48) |
| **home_joiner_agreement** | with the person's "match" ON THE JOINER, the joiner joins only the member that admitted it in this TLS session, unless six digits collided on the joiner's side | **verified (1664)** |
| capture_without_answer | a joiner that takes a Welcome without the person's answer is taken by the attacker's own group, with no collision | trace found (27): this is why the rule below exists |
| admin_key_proven_here | as in jm2 | open (no result within 30 min) |
| exec_home | reachability | trace found (17) |

**The rule this gives**, accepted by architecture: at home without an invitation, the core takes a Welcome only after the person said "match" on the joiner, in the same session, with the admitter the TLS of that session proved. In the code at #530 7ed330f0: `Way::Home { matched, exporter }`, `Matched` carries the session mark (SHA-256 of `cbb pairing session mark v1` 0x00 and the exporter), and `binding(self)` makes one answer serve one grant. The tie to the member's key is being built.

**What rests on the person:** one guess in 1 000 000 per attempt and one attempt per window. The symbolic model cannot count, so it gives the attacker one chance per side (Collide, J_Collide). The count rests on the commitment (neither end picks its nonce after seeing the other's) and on six digits, and it is stated here, not proved.

## Not claimed, in plain words

The lemma `admitted_holder_match_even_if_leaked` (and its `_unless_revealed` twin) said: "if a session was approved with a matched code, the admitted key belongs to a joiner of this invitation, unless six digits collided in this session". Read literally, the matched code it quotes could come from a **different session** of the same invitation. The trace (jcex3, 60 steps) has one leaked invitation and two sessions. Session A admits without a code (a camera, or the typed secret), while in session B a matched code comes by chance. The lemma excludes the chance only for A. That is a fault of the wording, not of the protocol. The promise is `admitted_holder_match_same_session`, verified above. Architecture added a rule to the wave 5 brief: the admission mode is fixed by the invitation, not by what the joiner claims.

## Not modelled here

- How many attempts an invitation gives, and the timers: the counting model (join_counting.qnt) and the core tests (MAX_FAILURES, ATTEMPT_MS).
- The byte encoding, CBOR, TLS 1.3 itself (an ideal key exchange whose server signs the transcript), CPace itself (an ideal balanced PAKE): these are covered by the vectors (testdata/format/messages3.json) and the core tests.
- The Welcome's records beyond the root, the admitter's record and the joiner's own: covered by the records model and the core tests.

## How to keep these proofs terminating

1. **Loops over a counter.** A rule that reads a persistent fact keyed by a counter (`!Root(G, %s, r)` made from `!Root(G, %s-1, …)`), or a persistent fact rewritten by itself (`!Bound` → `!Bound`), lets the backward search unroll earlier steps without end. Split the fact so the part a lemma needs is made once (leaf: `!BoundRoot` made at binding, `!Grant` refreshed).
2. **Order the goals.** A `tactic:` with `prio:` on the goals that close the proof and `deprio:` on the chain premises, given per lemma with `[heuristic={name}]`, does not change what is proved, only the order. Lemmas that hung then verified in 5 to 12 steps.
3. **State secrecy on the term.** Write `KU(h(<'pake', c, nl, nr>))` rather than `KU(key)` with a free variable, and `KU` rather than `K` in helpers that later lemmas reuse.
4. **Reuse only what is proved.** A `[reuse]` lemma that timed out makes every later "verified" conditional. After changing a helper, run again from the top.
5. **Time in a statement.** When one rule carries both labels, `#u < #h` is false at the shared instant. Write `not (#h < #u)`.
6. **Memory.** The container has about 13 GB for all processes, so cap each run (`+RTS -M3g`) and run at most three or four at once.
