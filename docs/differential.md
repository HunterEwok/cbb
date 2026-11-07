<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Differential fuzzing

For engineers and security reviewers: how CI checks that the four implementations (Go, the
lite member's Rust core, the Swift kit and the Kotlin kit) read what comes from the network
alike, and how a case they read differently becomes a test vector.

The interop vectors ([testing](testing.md#interop-vectors)) fix the verdict on bodies chosen
by hand or written from the tables of [the protocol](protocol.md). The differential run adds
bodies nobody chose: it changes the vectors' bodies at random and checks that every
implementation gives each changed body the same verdict, and that every implementation makes
the same record set of the same signed records in any order and subset.

## The parts

- `tools/difffuzz gen` writes a **corpus**, one case to a line, from a seed: the same seed
  gives the same corpus. It starts from every body of `testdata/interop/strict-generated-*.json`,
  `strict-mutants-*.json` (record bodies of version 1, which every member refuses), `strict-files.json` (records, commands, manifests, server credentials, `keys.json`,
  `release.json`, channel files and `attest-status.json`) and the records of `v2-records.json`, and changes them: bits and bytes,
  bytes that JSON treats specially, members twice, missing, in another place or with their
  names in another case or escaped, values of another JSON type, integers at the edges of
  each reader's types and in forms the strict form refuses, strings with escapes, control and
  direction characters, invalid UTF-8, hex in capitals, base64 in another alphabet, and
  strings and lists at the sizes of the limits. It also writes the **record sets** of the
  vectors (`go-*.json`, `swift-*.json`: removed admin phones, takeovers, freezes, admin
  computers, watches and the others), each as it is and changed: some of its records, in
  another order, some twice, one with its chain dropped or its signature or body changed.
- Each implementation has a **verdict test** that reads a corpus and writes one line per
  case: Go's `TestVerdicts` in `internal/group` (and in `internal/release` for the release
  files), the lite core's `command::verdicts`, the Kotlin kit's `VerdictTest` and the Swift
  kit's `VerdictTests`. Without a corpus each runs on a small one of its own, so the normal
  test runs keep it working.
- `tools/difffuzz compare` reads the corpus and the verdicts and fails on any case the
  implementations read differently. It prints each such case (its body, also in base64,
  and every implementation's line) and writes them to a corpus of their own
  (`-failures`).

## Verdicts

A verdict is one line:

- `refused` when the implementation refuses the body;
- `skip` when it does not read bodies of that kind: the lite member reads no
  `attest-status.json`, and the kits read records (version 2) and record sets only through
  the Rust core (docs/core-api.md), which the comparison reads as the lite core's;
- `taken` and, for records, commands and server credentials, every field the body gives, as
  ` name=value` in a fixed order (`tools/difffuzz/main.go` lists them): strings as the hex of
  their UTF-8 bytes, integers in decimal, booleans as 0 or 1, bytes in hex, lists joined by
  `.`, and a command's text as its SHA-256;
- for a record set, `set` and how many records it took, the SHA-256 of each root's
  certificate, each device (ID, name, role, store, admin, its admin CA's key, frozen), a 0 or
  1 per key of the case for revoked and for frozen, and the set's digest.

An exception that is not the reader's own refusal is a verdict of its own (`threw ...` in the
kits), so a reader that fails in another way also shows as a difference.

## In CI

- The `differential` job of `ci.yml` runs `.github/differential.sh` with seed 1, 20 000
  changed bodies and 500 record sets on every pull request that changes Go, the lite member,
  the kits or the tools. The Swift kit runs in the Swift container, as the phone kit job runs
  it on Linux.
- The `nightly` workflow runs it with a fresh seed (printed in the log) and 200 000 bodies,
  and the native fuzz targets for ten minutes each: Go's `FuzzRecordBody`, `FuzzCommand`
  (`internal/group`), `FuzzRelayWire` (`internal/relay`), `FuzzForwardWire`
  (`internal/forward`) and `FuzzDecodeDIB` (`internal/pasteboard`), and the lite core's
  `cargo fuzz` targets in `core/fuzz` (`record_body`, `command`, `credential`,
  `release`, `wire`, and `api`, the core's entry point of [core-api.md](core-api.md)),
  seeded by `go run ./tools/difffuzz seeds`. `api` starts from requests for every operation,
  each case of `v2-records.json` among them, and checks that any bytes get one answer of the
  ABI, with `ok` or a listed error code, and that a request answered twice gets the same
  answer.

Manifests are read by the rules of signed bodies in their canonical form ([roadmap](roadmap.md),
item 42), so they fail the run as the other kinds do; `compare -report-only KIND` still prints
the differences of a kind without failing on them, for a kind added before its form is settled.

A failed run uploads the cases it found (`failures.jsonl`, or the fuzzer's input).

## Running it yourself

From the repository root, with Go, Rust, JDK 17 and Docker (for the Swift container):

```sh
sh .github/differential.sh 1 20000 500 /tmp/differential
```

To run the nightly's corpus of a seed: `sh .github/differential.sh SEED 200000 5000 DIR`.
One implementation alone, with a corpus from `go run ./tools/difffuzz gen -o corpus.jsonl`:

```sh
CBB_VERDICTS=$PWD/corpus.jsonl CBB_VERDICTS_OUT=$PWD/go.txt go test ./internal/group -run '^TestVerdicts$'
```

and `go run ./tools/difffuzz compare -corpus corpus.jsonl go=go.txt,go-release.txt rust=rust.txt`
compares any of them.

## When a case is read differently

1. Find the row of the protocol's tables that decides it. When the protocol says nothing, the
   rule is a decision of the protocol, not of the implementation that happens to be right.
2. Add the case to the generator of `strict-generated-*.json` or `strict-files.json`
   (`internal/group/strictgen_test.go`, `strictgen_files_test.go`) under that rule, or, for a
   record set, to the Go test that writes the set's vector, and write the file again
   (`go test ./internal/group -run TestStrictGenerated -update`).
3. Fix every implementation that reads it otherwise in the same pull request.
