<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Group records, version 2

For engineers, anyone writing another implementation and security reviewers: why the group's
authority records moved to version 2 (`v:2`) in 0.6, and how the four implementations are
kept in step. The specification itself is now [protocol.md](protocol.md), section 10, from
"Records" to "The state", and the canonical form of a record in its Conventions, "Signed
bodies"; this page was that specification until the switch ([roadmap](roadmap.md), item 42).

There is no migration. A member that holds records of version 1, or a group made before the
switch, refuses them, and the group is set up again; until 1.0.0 the project keeps no
backward compatibility. `cbb upgrade` of a legacy group went with version 1.

## Why a new version

The rules of version 1 derive a signer's powers from other records (whether a root is a
computer, whether an admin CA is a phone's), undo what a removed admin signed and make the
remover list in `keep` what stays, freeze with lists of record IDs, keep the signer outside
the signed body and ignore unknown fields in it. Records carry no order, so a removal cannot
say what it saw. The rule for removed admin phones was bypassed four times in a row in the
security audit, each time through one of these properties. Version 2 removes them:

- **The signer is inside the body**, and a body has one signer.
- **Powers are written down**: the record that makes an admin lists what it may do.
- **Each signer numbers its records** (`seq`, and `prev`, the ID of its previous record), and
  every record that changes powers says how many records of each signer its author held
  (`seen`). A removal keeps what the remover saw and nothing after, so a removed admin's
  later records never count, whenever they arrive.
- **Conflicts are shown and stop the exchange** instead of being settled silently: two
  admins that remove or freeze each other without either having seen the other's record,
  two claims on the group, or one signer that signs two records with one number.
- **Handing the group over waits** (72 hours by default), every device is told, and the root
  cancels it at any time.
- **Bodies are closed and canonical**: an unknown field refuses the body, and a receiver
  checks that encoding what it read gives the bytes it received.

## Evaluation in one place

The rules are evaluated by a pure function from the record set to the group's **state**
(protocol.md, section 10, "The state"). It is written twice: in Go (`internal/group`) for the computers, and in
Rust (`cbb_core`, `lite/core`) for the lite member and, through bindings, for both phone
apps, which no longer evaluate records themselves. The vectors and the differential run
compare the whole state, not single answers.

## Where the rules are

Every rule of version 2 is in [protocol.md](protocol.md), section 10:

- "Records": the envelope, "Fields every record has", "Records of a later version",
  "Types" and "Field rows";
- "Who signs what", with the powers the apps and `cbb` write, and "Watches";
- "Chains and numbers", "Checkpoints" and "Limits";
- "The hubs table";
- "Removals and freezes keep what the author saw" and "Which admin records count";
- "Handing the group over", "The recovery key" and "Certificates";
- "Stopping the exchange" and "The state", the one result all four implementations must
  give byte for byte.

## Vectors and tests

- `testdata/interop/v2-records.json` (and `v2-flood.json`, the sets at the limit on records,
  apart for the size of a file), written by Go (`go test ./internal/authority -run
  TestV2Vectors -update`, from the evaluation tests' scenarios): record sets with the expected state, at
  least the cases of the audit findings of version 1 (each with every order): an admin that
  removes another after a claim took effect (X1 and X2 of the second verification), two admin
  phones that remove each other crossed and in order, a chain of three claims, a claim
  cancelled before and after its delay, two claims, a claim disputed by a removal of its
  claimant and resolved either way, a claim after its author's removal, two histories of an admin and of the root,
  a removed admin's later `device` and `claim` records, freezes that cross, a `resolve` of each
  kind; and each limit: 262 devices, 65 admin keys, 16 handovers, a set of 1033 records, then
  the same with the root's checkpoint; and the hubs table: an admin's, an admin's without
  `hub`, a later admin's, the root's, and one naming a removed device; and the recovery key:
  its claim waiting the delay, taking effect and cancelled, a delay the root set, its other
  records, a removed key, a key replaced, a `recovery` record an admin signed, and one whose `cert`
  another root issued; and `handover`: a claim at once, one made before it and another admin's
  waiting, the root cancelling it, a newer one replacing it. (The 1 MiB limit has a Go test only: its set would be
  over a megabyte of vectors.)
- `testdata/interop/strict-generated.json` and `strict-files.json`, written from the tables of
  protocol.md; their records are of version 1 and are all refused, and the record bodies of
  version 2 are checked by the tests of `internal/authority` and `cbb_core::authority`.
- An order-independence fuzz in Go: random sets over a few phones, computers and roots,
  evaluated in several orders, batch and one by one, checking the same state, no hang and an
  iteration limit.
- The differential run ([differential.md](differential.md)) compares the state bytes of Go
  and Rust, and the strict verdicts of all four, manifests included.
- [`docs/model/claims.qnt`](model/claims.qnt) states the rules for claims of "Handing the
  group over" in Quint, and CI's `model` job checks its scenarios and, over random runs of
  signing, syncing and waiting by the root, two admins and their claimed roots, the promises
  of protocol.md: the root always wins, an objection stops the group, a claim after its author's
  removal and two claims never take the group.

## What else changes with it

- **Commands** (section 15) get `v` 2, `signer` in the body as records have it, the canonical
  form, and `by` that MUST name the device whose records hold the signing key (or the root's
  device); an admin signs only the types in its `commands`.
- **Server credentials** (section 18) and **release files** (section 16) get `v` 2 and the
  canonical form; their fields stay.
- **The servers read no records.** A forwarder and a relay take only server credentials
  (section 18); the registrations with records and with `admin_sig`, and the phone hub's
  registration without one, go. A group has a period from the moment it is made, and a new
  root starts one when its claim takes effect. Both servers stay open to every group.
- **The phones** evaluate records with `cbb_core` through bindings (an xcframework and an
  AAR, as the tunnel's), and sign records in their kits as before (Secure Enclave, Keystore).
- **Legacy groups, `cbb upgrade`, `keep` and the records' `by`** go.
