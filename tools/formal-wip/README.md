<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Protocol models in progress (backup)

A working backup of the Tamarin models of the 0.6 protocol, kept here while
the project's shared folder is out of reach. Whether these models live in the
repository later is decided separately; this folder is not built, tested or
documented elsewhere yet.

- `entry/`: entry by code; `jm2.spthy` with the invitation ID in the code and
  the channel, `jd2.spthy` without it.
- `recovery/`: change of root by the recovery key.
- `copies/`: copies end to end; `copies_tactic.spthy` adds a goal-ordering
  tactic and helper lemmas stated with `KU`.
- `leaf/`: binding a guarded leaf; `leaf_fork.spthy` adds the leaf's handling of
  a root fork.
- `run2.sh <dir> <theory> <lemma> <seconds>`, `runall2.sh <dir> <theory> <seconds> [lemma...]`:
  run one lemma or all, with Tamarin 1.10 and Maude 3.4 on `PATH`.

Results and the full write-ups go with the models' reports, not here.
