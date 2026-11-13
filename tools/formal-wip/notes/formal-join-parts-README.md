<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The Welcome in parts (Tamarin)

File: `parts.spthy`. Controls: `ctrl_mac_no_digest.spthy`,
`ctrl_no_sig_check.spthy`. Outputs: `out/`.

Design: plans/second-builder/welcome-in-parts.md (decided 2026-11-13, frozen
with 0.6), with the bytes the second builder gave: message 67 gains field 4
Tw = HMAC-SHA-512(K_w, "cbb welcome v1"\0 ‖ field 3 as it travels), K_w from
the CPace ISK; field 12 digest = SHA-256("cbb welcome digest v1"\0 ‖ set
digest ‖ count of lists ‖ sorted list hashes); field 13 parts (absent = 0,
at most 64). A record's ID is SHA-256 of its body; its first signature is
over body ‖ SHA-256(sig2).

## What is modelled

- The confirmed session is ideal here: `jm2.spthy` proves the joiner's
  session key is shared only with the admitter the person confirmed.
- Tw: `mac(k, <sid, root, digest, count>)` (deterministic CBOR, so Tw
  covers every field, an absent field 13 included).
- digest = h(label, multiset of record IDs): the multiset is the
  order-free form of the sorted hashes.
- Parts travel with no protection at all (stronger than TLS): the attacker
  drops, reorders, replays parts from other sessions, alters sig2 and adds
  parts. The joiner verifies each record's signature on arrival and checks
  the digest after the last part; any failure ends the session with
  nothing kept. Two parts per Welcome, the zero-part form, and a one-part
  joiner path the admitter never takes (to show the count is bound).

## Results

| Lemma | What it says | Result |
|---|---|---|
| exec_parts | reachability: the joiner finishes with no key leaked | verified (12) |
| parts_exact | the joiner finishes only with exactly the records, signatures included, that the confirmed admitter sent in this session, unless the session key or a signer key leaked | verified (237) |
| parts_ids_exact | with signer keys stolen, the record IDs are still exactly the admitter's | verified (51) |
| finish_once | one finish per session | verified (40) |

Controls (not the design):

| Control | parts_exact | parts_ids_exact |
|---|---|---|
| Tw without digest and count | falsified (trace, 12) | falsified (trace, 12) |
| joiner skips the signature check | falsified (trace, 11: sig2 swapped) | verified |

Both pieces are needed (Tw over the digest and count, and the signature
check of every record in a part) and together they are enough.

## Not modelled

The part limits (64 parts, 120 s per part, 20 min in all) are availability.
The records' own evaluation is the records model's. SHA-256 and HMAC are
ideal.
