<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Differential fuzzing

For engineers and security reviewers: how CI verifies that the Go release parser, the Rust core,
and the Kotlin kit agree on mutated network inputs, which native fuzz targets run nightly, and how
to turn a divergence into a permanent test vector.

Interoperability vectors ([Testing](testing.md#interop-vectors)) pin verdicts for hand-authored and
table-generated inputs from [Protocol](protocol.md). Differential fuzzing complements those vectors
by mutating them pseudo-randomly and verifying that every implementation produces the same verdict
on each mutated body.

## Components

- **Corpus generator (`tools/difffuzz gen`)**: Produces a deterministic JSONL corpus from a numeric
  seed (one `{"kind", "body"}` case per line). It seeds from
  `testdata/interop/strict-generated-*.json` (manifests) and `testdata/interop/strict-files.json`
  (`keys.json`, `release.json`, channel files, and `attest-status.json`), applying mutations across
  bits and bytes, JSON syntax characters, duplicate or reordered or differently cased or escaped
  member names, mismatched JSON types, boundary integers and non-canonical numeric forms, control
  and bidirectional characters, invalid UTF-8, uppercase hex, alternate base64 alphabets, and
  limit-boundary strings and arrays. Binary CBOR records are parsed only by the Rust core and are
  fuzzed by the `format` cargo-fuzz target using vectors in `testdata/format`.
- **Verdict tests**: Each implementation provides a test that reads a corpus from `CBB_VERDICTS`
  and writes one verdict line per case to `CBB_VERDICTS_OUT`:
  - Go: `TestVerdicts` in `internal/release` (release files)
  - Rust core: `verdicts::verdicts` in `core/src/verdicts.rs`
  - Kotlin kit: `VerdictTest` in `apps/android/kit`

  The Swift kit has no separate verdict test because it parses network bodies solely through the
  Rust core (D-126). When `CBB_VERDICTS` is unset, each verdict test runs a small built-in corpus
  during normal test runs.
- **Comparator (`tools/difffuzz compare`)**: Reads the corpus and every implementation's verdict
  file, fails on any disagreement, prints differing cases (body, base64, and each verdict), and
  writes failing cases to a corpus file (`-failures`).

## Verdicts

Each verdict line has one of four values:

- `refused`: The implementation rejected the body.
- `taken`: The implementation accepted the body.
- `skip`: The implementation does not parse bodies of that kind (matches any other verdict).
- An unexpected exception (such as `threw ...` in the Kotlin kit): Treated as a distinct verdict so
  crashes and unhandled errors surface as disagreements.

## CI and nightly runs

- **Pull request CI** (`.github/workflows/ci.yml`, `differential` job): Runs
  `.github/differential.sh` with seed `1` and 20,000 mutated bodies on changes to Go, Rust, the
  phone kits, or tools.
- **Nightly differential run** (`.github/workflows/nightly.yml`, `differential` job): Runs
  `.github/differential.sh` with a fresh timestamp seed (logged for replay) and 200,000 bodies.
- **Nightly Go fuzz targets** (`go-fuzz` job, 10 minutes each):
  - `FuzzForwardWire` and `FuzzRegister` (`internal/forward`): Hub registration and forwarder
    responses (`cbb-forward/3`), seeded from `testdata/format/messages3.json`.
  - `FuzzCredential` (`internal/blind`): Forwarder parser for the CBOR profile, frames, and server
    credentials, seeded from `testdata/format/credentials.json` and `testdata/format/frames.json`.
  - `FuzzDecodeDIB` (`internal/pasteboard`): Windows DIB image decoding.
  - `FuzzUnpack` and `FuzzDecodePlist` (`internal/tvremote/appletv/wire`): Apple TV Companion
    protocol framing and binary plist decoding.
- **Nightly Rust core fuzz targets** (`cargo-fuzz` job, `core/fuzz`, 10 minutes each, seeded by
  `go run ./tools/difffuzz seeds -o core/fuzz/corpus` from `testdata/interop` and
  `testdata/format`):
  - `command`: Wire commands ([Wire format](format.md), section 6), round-trip stability, and order
    parsing.
  - `release`: Signed release file parsing.
  - `wire`: Member protocol frames.
  - `vless`: Forwarder VLESS and XHTTP responses split at arbitrary chunk boundaries, checking
    chunk-size independence.
  - `format`: Strict CBOR profile, records, and envelopes.
  - `welcome_message`: Pairing message 67 authentication before its tag (must accept no forged
    bytes).
  - `sheet`: Recovery sheet text and QR parsing and round-trip stability.
  - `yubikey_object`: YubiKey PIV recovery object parsing (must reject unsealed inputs).
  - `welcome_parts`: Reassembly of message 67 Welcome parts in any order, with duplicates or
    truncation.
  - `welcome_fields`: Forward-compatible Welcome fields canonicalization.
  - `api`: The `cbb_core::api` entry point ([The core's entry point](core-api.md)), verifying every
    input yields a valid ABI response (`ok` or a defined error code) and deterministic repeat
    answers.
- **Nightly Rust service fuzz targets** (`cargo-fuzz-service` job, `member/fuzz`, 10 minutes each):
  - `control`: Local control socket and `cbb-helper` channel framing (round-trip stability).
  - `next_frames`: ZX Spectrum Next UART frames and character-set conversion.
  - `relay_wire`: Blind relay protocol (`cbb-relay/3`) registrations and notes (round-trip
    stability).

Manifests follow the canonical signed-body rules and fail the differential run on disagreement like
other kinds. `tools/difffuzz compare -report-only KIND` prints disagreements for a kind without
failing the run, for use while a new format is under development.

Any failing CI or nightly job uploads its failing inputs (`failures.jsonl` or fuzzer artifacts).

## Run differential fuzzing locally

From the repository root, with Go, Rust, and JDK 17 installed:

1. Run the standard CI corpus (seed `1`, 20,000 bodies):

   ```sh
   sh .github/differential.sh 1 20000 /tmp/differential
   ```

2. To reproduce a nightly run, pass its logged seed and 200,000 bodies:

   ```sh
   sh .github/differential.sh SEED 200000 /tmp/differential
   ```

3. To test a single implementation against a generated corpus:

   ```sh
   go run ./tools/difffuzz gen -o corpus.jsonl
   CBB_VERDICTS=$PWD/corpus.jsonl CBB_VERDICTS_OUT=$PWD/go-release.txt go test ./internal/release -run '^TestVerdicts$'
   ```

4. Compare any subset of verdict files:

   ```sh
   go run ./tools/difffuzz compare -corpus corpus.jsonl go=go-release.txt rust=rust.txt
   ```

## Resolve a disagreement

When implementations return different verdicts for a case:

1. Identify the rule in [Protocol](protocol.md) that governs the input. If the specification is
   silent, decide the normative rule and update [Protocol](protocol.md) first.
2. Add the failing case to `testdata/interop/strict-generated-*.json` or
   `testdata/interop/strict-files.json` under that rule with its expected verdict.
3. Fix every diverging implementation in the same pull request.
