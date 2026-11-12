<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Testing

For contributors and reviewers: how Copy Beyond Borders is tested, from a single function to
real devices, and which level answers which question. The commands are in
[CONTRIBUTING.md](../CONTRIBUTING.md#development), the CI jobs one by one in
[maintaining](maintaining.md#ci), and the tests on real devices in the
[test bench](testbench.md).

## Levels

| Level | What it shows | Where | Runs |
|---|---|---|---|
| Unit tests | one package or type does what its comment says | `*_test.go`, `cargo test`, `swift test`, `./gradlew -p kit test` | every push, in CI |
| Interop vectors | the four implementations (Go, Rust, Swift, Kotlin) read and write the same bytes | `testdata/interop` | every push, in CI |
| Cross tests | two implementations talk over a real connection | Go tests that start the Swift or Kotlin `cbb-interop`, or the lite member | every push, in CI |
| Service tests | several members, with their real services, in one process or as programs | `internal/service`, `member/tests` | every push, in CI |
| System tests | the built program on a real system: containers, sockets, a desktop, an installer | the `e2e`, `mdns with avahi`, `desktop clipboards`, `packaging`, `windows installer`, `OpenWrt`, `freebsd` jobs | every push, in CI |
| App builds and tests | the apps build and their unit tests pass on simulators and runners | the `iPhone app`, `Mac app`, `tray app`, `Android app` jobs | every push, in CI |
| Bench scenarios | real devices pass real copies over real networks | the [test bench](testbench.md), its [catalogue](testbench-catalogue.md) | before each release |

A change is not done before the levels it touches pass locally (CONTRIBUTING lists the
commands per part); CI then runs the jobs of every part the pull request changes, and the
`ci-ok` job sums them up for the branch rules. Which part a path belongs to, and which parts
read another's files, is in `.github/ci-changes.sh`; a path it does not know, the workflow,
`go.mod` and `testdata/` run every job. A skipped job has nothing new to test: the pull
request is up to date with main, whose run tested those files when they last changed.

## Unit tests

- Go tests run with the race detector on Linux x86-64, Linux ARM64 and macOS, under QEMU
  for big-endian 32-bit MIPS, and on FreeBSD.
- Time comes from the caller (`now time.Time`), so a test sets the clock; lifetimes and
  renewals are tested at their edges without waiting.
- The TPM code runs against swtpm (`internal/tpmkey`), the ei protocol against a test EIS
  server (`internal/ei/eitest`), the clipboards against wl-clipboard and xclip.
- The Rust core is `no_std`; its tests run on the host, and CI builds it for the ESP32-C6
  and ESP32-S3 and runs the firmware's self-test in Espressif's QEMU.

## Interop vectors

`testdata/interop` holds JSON files of fixed inputs and the exact bytes each implementation
must produce or accept: certificates, device and revocation records, freezes, takeovers,
admin CAs, commands, quick actions, server credentials, releases, attestation evidence, the
watch's state, content hashes, join QR codes and a CPace exchange.

- The files named `go-*.json` and those without a prefix are written by Go tests with
  `-update` and read by the Swift kit, the Kotlin kit and, for what it implements, the lite
  core (`core/src/vectors.rs`).
- Files named `swift-*.json` are written by the Swift kit (`CBB_INTEROP_OUT`) and read by
  Go; the Kotlin kit writes the same files, so Go checks both phones against one set.
- A Go test fails when a committed vector is out of date, and names the command that
  writes it again.

A change to the wire format changes the vectors in the same pull request, together with
[the protocol](protocol.md) and every implementation.

The [differential run](differential.md) changes these bodies and record sets at random and
checks that all four implementations still read them alike; a case they read differently
becomes a vector here.

## Cross tests

- The Swift kit's `cbb-interop` and the Kotlin kit's (built by `./gradlew -p kit
  interopScript`) play the phone in Go's pairing and member tests: over plain TCP on Linux,
  over real TLS on macOS and with Conscrypt on Linux.
- `TestAloneMember`, `TestAloneRemotePaste`, `TestAloneQuickActions` and `TestAloneMemberAway`
  run the built cbb without its helper (`CBB_TEST_ALONE`) among Go members, at home and through the hub's
  tunnel.
- `TestEmbassyJoiner` runs the Nano ESP32's network code on Linux over a TAP interface
  (`CBB_ESP32_ON_LINUX`).

## Service and system tests

- `internal/service` starts whole members in one test: sync, pairing, remote paste, quick
  actions, sync away from home through a hub, a forwarder (`TestAwayThroughForwarder`) and a
  relay (`TestAwayThroughRelay`), with obfuscation (`TestAwayObfuscated`).
- `member/tests` runs the Rust `cbb service` as programs on the loopback, without mDNS, and
  talks to them over the control and admin sockets as plain JSON (`common/mod.rs`):
  `control_contract` checks that every operation answers once and on the right socket and
  that a broken client never stops the service; `control_admin` admits, renames, removes,
  freezes, makes admins, hands over and takes over; `remote_commands` carries out remote
  paste and quick actions through a member's watchers; `helper_faults` runs a fake
  cbb-helper that crashes, hangs, writes garbage or plays a TPM. `cli_commands` checks the
  command line against a fake service.
- `tools/e2e/e2e.sh` runs the built static binary as three members and an avahi browser
  in Docker containers: mDNS, pairing with codes, sync, a wrong code.
- The installer jobs install, run and remove the service on each system they cover.

## Bench scenarios

Unit and CI tests cannot show that a copy on an iPhone reaches a Windows PC through a café's
Wi-Fi. The [test bench](testbench.md) does, on the real devices of each platform, with the
rules R1 to R7 ([cases](testbench-cases.md)), a catalogue of the cases of a release with how
each runs, and a coverage report of the product's functions
([functions](testbench-functions.md)). Security cases block a release; a case that cannot
run yet is skipped with its reason and stays on the list.

## Coverage

CI measures how much of the code the tests run, part by part, and its `coverage` job prints
the table in the run's summary. `tools/coverage` adds the reports up and fails when a part
falls more than one point below its floor in `tools/coverage/floor.json`, so coverage can
rise but not fall. When the table says "raise the floor", raise it in the same pull request.

| Part | What counts | Measured by |
|---|---|---|
| `go` | statements of `cmd`, `internal` and `mobile`, without `third_party` and the packages only tests use (`eitest`, `testnet` and the others `tools/coverage` lists) | the `go coverage` job: every test across packages (`-coverpkg`, so a test of `internal/service` counts for `internal/group` too), the desktop clipboards under sway and Xvfb, the uinput keyboard against the kernel, mDNS beside avahi-daemon, the e2e's members built with `-cover`; and each system's own files from the `test` jobs on Linux, macOS and Windows |
| `go-core` | the same, in `internal/group`, `pair`, `node`, `clip` and `hlc` | as `go` |
| `rust-core` | lines of `core/src`, without `third_party` | `cargo llvm-cov` in the `rust` job |
| `rust-member` | lines of `member/src/`, by the Rust tests alone | as `rust-core` |
| `rust-service` | lines of `member/src/`, by the Rust cbb's own tests and Go's tests of the service together (`internal/service` and the desktop connector, run against a `cbb` built with instrument-coverage) | `cargo llvm-cov` in the `service tests on the Rust cbb` job |
| `swift-kit` | lines of the Swift kit's `Sources` | `swift test --enable-code-coverage` in the `phone kit (macos-latest)` job |
| `kotlin-kit` | lines of the Kotlin kit | JaCoCo in the `Android app` job |

The aims are 80% for `go`, 85% to 90% for the protocol's core in each implementation, and 90% for `rust-service`.
A number is a hint, not the goal: a test that runs a line without checking what it did
raises it and proves nothing.

To see Go's numbers locally:

```sh
go test -coverpkg=./cmd/...,./internal/... -coverprofile=cover.out ./cmd/... ./internal/...
go run ./tools/coverage -go cover.out -floor tools/coverage/floor.json
```

And the Rust service's, on Linux (the tests of `internal/service` need mDNS, so a computer on a
network or a container with one of its own):

```sh
eval "$(cargo llvm-cov show-env --sh)"
cargo llvm-cov clean --workspace
cargo test --release -p cbb-member && cargo build --release -p cbb-member
CGO_ENABLED=0 go build -o target/release/cbb-helper ./cmd/cbb-helper
CBB_TEST_RUST_SERVICE=$PWD/target/release/cbb CBB_TEST_ALONE=$PWD/target/release/cbb go test ./internal/service
cargo llvm-cov report --release --json --summary-only --output-path service.json
go run ./tools/coverage -llvm rust-service=service.json -floor tools/coverage/floor.json
```

## Unsafe code

The Rust core has no unsafe code (`forbid(unsafe_code)`). The unsafe code in `member/src` (system
calls) and `ffi/src` (the C functions the phones call) is checked by the nightly workflow: Miri
runs `ffi`'s tests of its C functions pointer by pointer (`cargo +nightly miri test -p cbb-ffi
--features join --lib`), and AddressSanitizer runs the Rust tests of `cbb-member` and `cbb-ffi`
and Go's tests of the service against a `cbb` built with it, which reaches the system calls
Miri cannot.

## Mutation testing

Coverage says a line ran; mutation testing says whether a test would notice if it were wrong.
The nightly workflow changes the records' code one place at a time (drops a check, turns `<`
into `<=`, returns early) and runs the tests against each change: `cargo mutants` on
`core/src/authority.rs` and `strict.rs`, in eight shards, and `gremlins` on
`internal/authority`. A change that every test still passes is listed as missed, in the run's
summary and its artifacts. The jobs report and do not fail yet; each missed change gets a
test, or a note why it cannot matter, and then the jobs fail on a new one.

The service's readers of outside input already fail on a new one: `cargo mutants` on the
control socket's messages (`member/src/control.rs`), the pairing window
(`member/src/window.rs`), the server credentials (`core/src/credential.rs`) and the seals of
the copies (`core/src/seal.rs`), in four shards each, with `tools/mutants/check.sh`, which
compares what lived with the known list, `tools/mutants/missed.txt`, line and column aside. A
mutant on that list either changes nothing a caller can see (an equivalent mutant, with why
in a comment) or lives in code that only Go's end-to-end tests reach, which `cargo mutants`
does not run (the window's exchange with a joiner). A new survivor gets a test; a mutant that
the tests now catch can leave the list.

To run them locally:

```sh
cargo mutants --in-place -p cbb-core -f core/src/authority.rs -f core/src/strict.rs
cargo mutants --in-place -p cbb-member -f member/src/control.rs -f member/src/window.rs
tools/mutants/check.sh mutants.out/missed.txt tools/mutants/missed.txt
go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash ./internal/authority
```

## Not tested yet

What has not run on real devices is listed in the [README](../README.md#status): the
Android phones' hardware keys and the fingerprint, Android 17's local network permission,
the iPhone's background app refresh and takeover, and the Windows service on a real PC
among them. Do not rely on
these before the bench has run them.

## Red tests

A failing test is a finding, never noise: find the cause before running it again. A test is
never skipped, disabled or retried until green to make CI pass.

## Unstable tests

A test that fails only now and then is a red test too, with a cause to find: a race in the
code, a wait too short for a slow runner, or an order the test assumes. The nightly
workflow's `unstable` job runs the members' tests ten times over, with the Go service and
with the Rust `cbb`, and its summary lists every test that failed and how often. A test
found there goes into this table with what is known of its cause, and leaves it with the
fix that removes the cause. The bench finds them too: `go run ./tools/bench -repeat 5
-scenario NAME fleet` lists in `flaky.txt` the cases that both passed and failed
([test bench](testbench.md#11-automation)).

| Test | Where | Seen | What is known |
|---|---|---|---|
| `TestSeveralHubs` | `internal/service` | about one run in six, 2026-11 | not yet found |
| `TestAloneHubs` | `internal/service`, against the Rust service | about two runs in five in CI, 2026-11 | after the first hub stops, the client's tunnel connection to the second hub ends right after it comes up, and the copy made then is lost |
| `TestWindow` | `apps/desktop`, Windows | rarely, 2026-11 | Chrome gave no DevTools port within 30 seconds; the test now prints Chrome's error output, to be read when it fails again |
