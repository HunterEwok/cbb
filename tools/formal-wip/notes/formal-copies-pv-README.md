<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Model 1 in ProVerif: copies cannot be told apart

File: `copies_ind.pv`. Controls: `ctrl_removed_reader.pv`,
`ctrl_old_epoch.pv`. Outputs: `out/`.

Tool: ProVerif 2.05. Run: `proverif copies_ind.pv`.

## What it checks

One diff-equivalence (`choice[m1, m2]`): the attacker picks two contents
for every copy the origin seals after the removal, and the origin seals the
first in one world and the second in the other. Equivalence means no
attacker can tell the worlds apart. This is real-or-real
indistinguishability, which implies strong secrecy of a copy's content.

The attacker holds, from the start:

- the removed device's member key and every sealing secret it ever held
  (so "a removed device cannot tell two later copies apart");
- the remaining reader's OLD sealing secret (so "a leaked old epoch tells
  nothing about copies sealed to the newer one");
- the network: it reads, drops, replays and injects everything, and it can
  ask the origin to seal contents of its choice to the removed device and
  to the old epoch (copies it can open).

Copies after the removal go to the remaining reader's newer epoch only,
as the origin's view and the newer keys statement dictate. Who the readers
are (the records, admission, removal) is checked in Tamarin, in
`copies.spthy` (`removed_reader_none`, `removed_cannot_read`); this file
takes that as given.

## Results

| Query | Result |
|---|---|
| `copies_ind.pv`: later copies to the newer epoch, attacker holds the removed device's keys and the old epoch | **true** (observational equivalence proved) |
| control `ctrl_removed_reader.pv`: same, but the copy is sealed to the removed device | cannot be proved (as expected: it can open it) |
| control `ctrl_old_epoch.pv`: same, but the copy is sealed to the leaked old epoch | cannot be proved (as expected) |

The two controls show the property is not vacuous: the model does let the
attacker open what it should be able to open.

## Abstractions

HPKE (X-Wing), the AEAD and ES256 are ideal. The header carries the reader
keys and `commit(K)`; the payload key is derived from K and the header
hash. The origin and the remaining reader are honest. Sealing several times
and replays are unbounded (`!`).
