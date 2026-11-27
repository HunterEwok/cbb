<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Testing

For contributors, engineers, and security reviewers: how Connect Beyond Borders is tested from single
functions to physical devices, and which test level verifies each property. For per-component build
and test commands, see [Contributing](../CONTRIBUTING.md#development). For the full CI job list, see
[Maintaining](maintainers/maintaining.md#ci). For differential and native fuzzing, see
[Differential fuzzing](differential.md). For physical hardware procedures, see
[Test bench](maintainers/testbench.md).

## Levels

| Level | What it verifies | Where | When it runs |
|---|---|---|---|
| Static checks and lints | Formatting, linters, vulnerability scans, license compliance, workflow security, spelling, design tokens, translations, and repository rules | `check` and `advisories (Rust, Android, tray app)` jobs | Every pull request in CI |
| Unit tests | Individual packages, types, and functions meet their contracts | `*_test.go`, `cargo test`, `swift test`, `./gradlew -p kit test`, Qt host tests, Node host tests | Every pull request in CI |
| Interop vectors | Go, Rust core, Swift kit, and Kotlin kit agree on shared formats and rules | `testdata/interop` | Every pull request in CI |
| Frozen format vectors | Binary CBOR format, envelopes, records, commands, grants, credentials, copies, and push payloads match deterministic generators and independent readers | `testdata/format`, `the frozen format (testdata/format)` job | Every pull request in CI |
| Formal model | Record evaluation rules satisfy safety invariants in Quint | `docs/model/records-v3.qnt`, `model of the records' rules (Quint)` job | Pull requests touching the core or model |
| Differential fuzzing | Go, Rust core, and Kotlin kit produce identical verdicts on mutated inputs | `differential (Go, Rust, Kotlin)` job; nightly `differential, a fresh seed` | Every relevant pull request; nightly |
| Cross tests | Implementations interoperate over real connections | Go service tests starting `cbb`, phone kit tests joining groups through `cbb_core` | Every pull request in CI |
| Service tests | Full multi-member groups running real services over loopback or local networks | `internal/service`, `member/tests` | Every pull request in CI |
| System tests | Built binaries on real operating systems: containers, sockets, clipboards, installers, upgrades, and hook isolation | `e2e`, `mdns with avahi`, `desktop clipboards`, `packaging`, `windows installer`, `OpenWrt`, `upgrade from the last release`, `test (freebsd)`, `test (linux/mips under qemu)`, `docker image`, `cbb (Rust), the optimized builds and the installers`, `a release build ignores the test hooks` | Every pull request in CI |
| App and firmware builds and tests | Phone, watch, desktop, and embedded targets build and pass automated tests on simulators, emulators, QEMU, and runners | `phone kit (Linux)`, `iPhone app`, `tray app`, `Android app`, `Android app on an emulator`, `F-Droid build reproduces`, `Aurora app`, `HarmonyOS app (native module)`, `Aurora and HarmonyOS apps' code on the computer`, `phone core`, `the core on the ESP32`, `ZX Spectrum Next`, and the Mac app part of `test and build (macOS), homebrew, Mac app` | Every pull request in CI |
| Nightly deep checks | Native fuzzers, deterministic group simulation, slow tests, Miri, AddressSanitizer, mutation testing, reproducible builds, branch coverage, and flakiness repeats | `.github/workflows/nightly.yml` | Nightly |
| Bench scenarios | Physical devices sync real copies over real networks | [Test bench](maintainers/testbench.md) and [Test bench catalogue](maintainers/testbench-catalogue.md) | Before each release |

Run the local checks for every component a change touches before pushing (see
[Contributing](../CONTRIBUTING.md#development)). In CI, the `changes` job runs
`.github/ci-changes.sh` to determine which parts a pull request modifies, and only the jobs that
build or test those parts run. Changes to unrecognized paths, `.github/workflows/ci.yml`,
`.github/workflows/release.yml`, `.github/actions/*`, `.github/*.sh`, `.github/*.ps1`, `go.mod`,
`go.sum`, or `testdata/*` trigger all jobs. The `ci-ok` job aggregates every required job for branch
protection; skipped jobs count as passed because `main` already tested those unchanged files.

## Unit tests

- **Go**: `go test -race` runs on Linux x86-64 (`ubuntu-latest`), Linux ARM64 (`ubuntu-24.04-arm`),
  Windows (`windows-latest`), and macOS (inside `test and build (macOS), homebrew, Mac app`), with a
  32-bit x86 run (`GOARCH=386`) on `internal/group`, `internal/clip`, and `internal/helper`, a
  big-endian 32-bit MIPS run under QEMU (`test (linux/mips under qemu)`), and a FreeBSD run
  (`test (freebsd)`). Test Go changes under `-race` on macOS as well as Linux because OS-specific
  race-detector issues can surface on only one platform.
- **Clock injection**: Go code takes time from the caller (`now time.Time`), so unit tests exercise
  lifetimes and renewals at exact boundaries without sleeping.
- **System integrations**: TPM tests run against `swtpm` (`internal/tpmkey`), the `ei` remote-input
  protocol runs against a test EIS server (`internal/ei/eitest`), and Linux clipboard tests run
  against `wl-clipboard` under headless Sway and `xclip` under Xvfb.
- **Rust core and firmware**: `cbb_core` is `no_std`. Its unit tests run on the host, and the
  `the core on the ESP32` job cross-compiles `cbb_core` with TLS for ESP32-C6 (RISC-V) and ESP32-S3
  (Xtensa), builds the Arduino Nano ESP32 firmware (`esp32/`), and runs the firmware console, flash
  persistence, and TLS 1.3 self-test in Espressif's QEMU (`esp32/qemu-test.sh`).

## Interop vectors

`testdata/interop` holds JSON test vectors that keep Go, the Rust core (`cbb_core`), the Swift kit,
and the Kotlin kit aligned on shared encodings and rules:

- **Go-generated vectors** (`go-attest.json`, `go-entries.json`, `go-netid.json`,
  `go-release.json`, `go-release-envelopes.json`, `go-sekey-seal.json`, `go-zxnext.json`,
  `media-names.json`, `tunnel-state.json`): Written by Go tests with `-update` and verified by
  `cbb_core` (`core/src/vectors.rs`, `core/src/attest.rs`, `core/src/api/signed.rs`), the Swift kit,
  and the Kotlin kit. A Go test fails if a committed vector is out of date and prints the command to
  regenerate it.
- **Rust-generated and cross-checked vectors**: `seal-go.json` holds messages sealed by Go's
  `crypto/hpke`, and `seal-rust.json` holds messages sealed by `core/src/seal.rs` (regenerated with
  `CBB_UPDATE_VECTORS=1`); `core/src/seal.rs` opens both. `keyboard.json` and `push-open.json` are
  generated by `cbb_core` tests and checked by the phone kits. Other shared JSON vectors cover
  strict manifests and release files (`strict.json`, `strict-files.json`, `strict-generated-1.json`),
  copy verdicts (`copy-verdicts.json`), content (`content.json`), hybrid logical clocks
  (`hlc-ahead.json`), member certificates (`member-certs.json`), group state (`member-group.json`),
  and join QR payloads (`joinqr.json`).
- **External standard vectors**: `xwing-hpke-pq.json` (from `draft-ietf-hpke-pq-05`) is verified by
  `core/src/seal.rs`, and `nist-slh-dsa-sha2-128s.json` (NIST SLH-DSA-SHA2-128s) is verified by both
  `core/src/vectors.rs` and `internal/release/release_test.go`. Neither file is regenerated by tests.

For the binary CBOR wire format (`testdata/format`), `gen.py` and `push_gen.py` deterministically
generate vectors covering strict CBOR rules, keys, signed envelopes, records, key statements,
commands, grants, server credentials, frames, copies, recovery sheets, push payloads, and TLS key
containers. Three independent implementations verify them: `cbb_core` (`core/src/format`,
`core/src/push`), the standalone Go checker (`testdata/format/check`), and `gen.py`'s own strict
reader. The `the frozen format (testdata/format)` CI job runs on every pull request to verify
`testdata/format/FROZEN` with `tools/formatfreeze`, confirm deterministic regeneration with
`gen.py`, and run `testdata/format/check`.

Any change to the wire format must update [Protocol](protocol.md), [Wire format](format.md), the
vectors, and every implementation in the same pull request.

[Differential fuzzing](differential.md) mutates vectors from `testdata/interop` and checks that Go,
the Rust core, and the Kotlin kit return identical verdicts; any disagreement is promoted to a
permanent vector.

## Cross tests

- **Phone kits and core**: The Swift kit (`CoreMemberTests`, `CorePairingTests`, `WindowTests` in
  `apps/ios/CBBKit/Tests/CBBKitTests`) and the Kotlin kit (`CoreMemberTest`, `CorePairingTest` in
  `apps/android/kit/src/test/kotlin/tools/cbb/kit`) join groups and sync through `cbb_core` and the
  Rust member.
- **Standalone `cbb` interoperability**: `TestAloneMember`, `TestAloneRemotePaste`,
  `TestAloneQuickActions`, and `TestAloneMemberAwayXHTTP` in `internal/service/alone_test.go` run
  the built `cbb` binary without `cbb-helper` (`CBB_TEST_ALONE`) alongside full-computer members.
- **Away-from-home live tests**: `member/tests/away_live.rs` and `member/tests/away_hubs.rs` (with
  `--features testhooks`) run real Rust members syncing through hub tunnels.

## Service and system tests

- **Go multi-member service tests (`internal/service`)**: Start real `cbb` and `cbb-helper`
  processes to test syncing, pairing, remote paste, quick actions, recovery, and away-from-home sync
  through a hub, a forwarder (`TestAwayThroughForwarder`), a blind relay (`TestAwayThroughRelay`),
  and obfuscated tunnels (`TestAwayObfuscated`).
- **Rust service integration tests (`member/tests`)**: Run `cbb service` on loopback without mDNS
  and exercise the control and admin sockets with plain JSON (`member/tests/common/mod.rs`):
  - `control_contract.rs`: Verifies every operation replies once on the expected socket and that a
    broken client cannot stop the service.
  - `control_admin.rs`: Exercises admitting, renaming, removing, freezing, promoting admins,
    handover, and moving the group.
  - `remote_commands.rs`: Delivers remote paste and quick actions through member watchers.
  - `helper_faults.rs`: Runs a fake `cbb-helper` that crashes, hangs, writes garbage, or emulates a
    TPM.
  - `cli_commands.rs`: Exercises CLI commands against a fake service.
  - `next_link.rs`: Exercises `cbb next link` UART framing against a real echo server.
  - `phone_push.rs`: Runs `phone-on-linux` with `pushd` and real computer members to verify push
    registration, sealed push delivery, and re-registration requests.
- **Container e2e (`tools/e2e/e2e.sh`)**: Runs the built `cbb` (and `cbb-helper` when present) as
  three members (`a`, `b`, `c`) plus a fourth member (`d`) and an `avahi-browse` container on a
  Docker network to test mDNS discovery, pairing with codes, clipboard and secret sync, and wrong
  pairing codes.
- **Installer and upgrade jobs**: `packaging`, `windows installer`, `OpenWrt`, `test (freebsd)`,
  `cbb (Rust), the optimized builds and the installers`, `upgrade from the last release`, and the
  macOS installer steps in `test and build (macOS), homebrew, Mac app` install, start, verify,
  update, and cleanly uninstall the service on each target platform.

## Running tests in parallel

Go runs packages in `go test ./...` concurrently, and Cargo runs tests within each test binary
concurrently. Tests in `internal/service` cannot run in parallel inside one process because each
test starts live member services that discover each other over mDNS on the same network. CI splits them
across runners instead:

- `service tests on the Rust cbb, the build`: Builds instrumented binaries once (`cbb`,
  `phone-on-linux`, `cbb-helper` with `-cover`, and the `service.test` and `connector.test` Go test
  binaries), runs the Rust member's own tests, and uploads one archive (`service-build`).
- `service tests on the Rust cbb (1)` to `(3)`: Each job runs one shard of `internal/service`;
  shard `3` also runs `internal/connector` and `TestPreviousRelease`. Each shard uploads its Go
  coverage (`cover-go-service-PART.out`) and Rust `.profraw` profiles.
- `service tests on the Rust cbb, the coverage`: Merges the Rust profiles from the build job and
  all three shards into `coverage-rust-service.json` (the `rust-service` coverage row).

`tools/shard` computes balanced shards by reading test names from `service.test -test.list .` and
assigning them longest-first using durations recorded in `tools/shard/service.txt`. Every test
lands in exactly one shard; new tests default to the median duration until recorded. After test
durations shift, refresh `tools/shard/service.txt` from a full `-v` run:

```sh
go run ./tools/shard -record tools/shard/service.txt <service-test.log
```

On a machine with Docker, `tools/e2e/parallel.sh` builds the binaries in one container and runs the
shards concurrently, each in its own container and isolated Docker network. `IMAGE` must provide Go,
Rust, `swtpm`, `Xvfb`, and `xclip`:

```sh
sh tools/e2e/parallel.sh -n 6 IMAGE              # all tests in internal/service
sh tools/e2e/parallel.sh -run 'Takeover' IMAGE   # only tests matching the regexp
```

Other long CI jobs also split across runners where splitting shortens wall-clock time:

- **Rust workspace tests**: `cbb (Rust), the checks and the Raspberry Pi builds` and
  `cbb (Rust), the optimized builds and the installers` run alongside the test pipeline.
  `cbb (Rust), the build of the tests` compiles all tests once into a `cargo-nextest` archive; two
  `cbb (Rust) (1)` / `(2)` jobs partition the tests (`--partition hash:PART/2`, `.config/nextest.toml`,
  with timing-sensitive tests isolated via `threads-required = "num-cpus"` and the two longest tests,
  `powerloss::a_power_cut_at_every_byte_of_every_save` and
  `records::tests::differential::a_set_agrees_with_evaluate`, pinned one per shard); and
  `cbb (Rust), the coverage` combines the profiles into `coverage-rust.json`.
- **iPhone and iPad UI tests**: `iPhone app (iPhone)` and `iPhone app (iPad)` run in parallel, each
  booting its simulator while building only the simulator Rust library for the runner's architecture
  (`ffi/bind.sh ios-sim`).
- **Android**: `Android app` runs the Kotlin kit tests before building and testing the Android and
  Wear OS apps in one job.
- **Cross-compilation**: `build (Linux, FreeBSD, Windows)` builds all Linux, FreeBSD, and Windows
  targets in one job because splitting it would not reduce overall CI latency.

To stay within the five-runner macOS concurrency limit, CI keeps macOS work compact:

- Changes that touch only Go skip `iPhone app` (`iosapp` in `.github/ci-changes.sh`), while the
  Swift kit's tests still run.
- Shorter macOS tasks share one runner in `test and build (macOS), homebrew, Mac app`: Swift kit
  tests, CodeQL analysis for macOS-only Go files, `go test -race`, macOS release archives and hook
  checks, Homebrew formula and installer tests, Mac app tests and `.pkg` verification, and
  `ffi/bind.sh ios` with the latest stable Rust.
- `codeql-swift.yml` runs on pull requests modifying `apps/ios/**` alongside the other jobs and
  takes the next free macOS runner.

Jobs with heavy Rust builds (`iPhone app`, `codeql-swift`, the Swift kit step of `test and build
(macOS), homebrew, Mac app`, `phone core (android)`, `service tests on the Rust cbb, the build`,
`cbb (Rust), the build of the tests`, and `Aurora and HarmonyOS apps' code on the computer`) cache
incremental artifacts per pull request via `.github/actions/rust-cache`. Pull requests do not share
caches with each other, and release and F-Droid builds compile from scratch.

## Before and beside CI

Test changes locally on every platform available before pushing:

- **Linux**: Rust and Go tests, service tests on the Rust `cbb`, container e2e, and format vectors.
- **macOS**: Apple builds, unit tests, and `go test -race` on macOS.
- **Android and Windows**: Local Linux machines can build and unit-test Android apps, screenshots,
  lint, and F-Droid reproducibility; Windows machines run Windows Go/Rust tests and the installer.
  The Android emulator job (`Android app on an emulator`) requires hardware virtualization and runs
  in CI.

CI remains the merge gate (`ci-ok`).

## Time

Time-dependent rules that span minutes or days are tested with a controlled clock rather than real
wall-clock waits:

- **Rust core (`core/src/longrules.rs`)**: `cbb_core` reads no system clock; callers supply wall
  clock time and device running time. `longrules.rs` advances both hour by hour and day by day to
  verify weekly sealing-key rotation (including a device offline for three weeks requesting
  re-sealing), backward wall-clock jumps, a guarded leaf's 35-day running-time grant, and immediate
  recovery-key root changes regardless of clock skew.
- **Rust service (`member/src/uptime.rs`)**: The service reads wall time only through
  `uptime::wall_ms()` and running time through `uptime::now()`. `tools/repocheck` rejects direct
  `SystemTime::now()` calls elsewhere in `member/src` outside allowed non-rule files. Service tests
  in `internal/service/time_test.go` (`TestPairingWindowCloses`, `TestSetWallClockMovesNoRunningTime`)
  shift both clocks via `CBB_TEST_AHEAD_FILE` using `testClock.set` (wall clock only) and
  `testClock.run` (both wall clock and running time). `cbb-helper` reads no clock.

## Power loss

Interrupted saves must leave either the complete previous state or the complete new state, and a
member must never act on state it has not finished saving:

- **Flash two-slot store (`core/src/powerloss.rs`)**: Runs a member's lifecycle (records, removal,
  repeated commands, repeated secret copies, and recovery-key root changes) through `crate::store`
  and cuts every write after every single byte, leaving the remainder either erased or stale. After
  each cut, the member restarts from flash and replays its inputs; tests verify that state loads
  cleanly as pre-save or post-save, no command runs twice or is lost, no copy is written twice, and
  reported root changes persist.
- **Service files (`member/src/files.rs`)**: The Rust service saves state through
  `files::write_atomic` (write temporary file, sync, rename). Unit tests inject faults at every byte
  and step—both abrupt process termination and OS errors—and verify either the old or new file
  remains intact. Leftover temporary files older than one hour are removed on startup by
  `files::sweep`.

## The simulation

`core/src/sim` runs a deterministic multi-member simulation of 3 to 12 members in one process. Every
network event, clock offset, and group action derives from a single numeric seed so any failure
replays deterministically.

- **Faults and actions**: The simulated network delivers, drops, duplicates, delays, and reorders
  messages, partitions the group, and heals. Members crash mid-message and restart from persisted
  state; clocks skew by up to two minutes. Actions include copies, admissions, removals, freezes and
  thaws, admin promotions, checkpoints, recovery-key root changes, forks at the same sequence
  number, and devices offline for days across key rotations.
- **Invariants during the run**: No member shows the same copy as new twice; no removed member opens
  a copy sealed after all other members persisted its removal (unless a root change restores it);
  any member holding both heads of a fork halts.
- **Quiescence checks**: After healing the network, restoring clocks, and syncing every pair until
  quiescent, all group members hold identical record digests (or all halt on the same fork), removed
  members know they were removed, restarted members match their saved state, and in non-halted
  groups a final copy reaches and opens on every reader.
- **Running locally and nightly**: `cargo test -p cbb-core --lib sim::` runs 16 seeds of 300 steps
  by default. Configure runs with `SIM_SEEDS`, `SIM_FIRST`, `SIM_STEPS`, `SIM_SEED` (single seed),
  and `SIM_ALL=1` (report all failing seeds instead of stopping at the first). Failures shrink to
  the minimum failing step count and print the exact replay command:
  `SIM_SEED=… SIM_STEPS=… cargo test -p cbb-core --lib sim::`. The nightly `the group simulation,
  a thousand fresh seeds` job runs 1,000 fresh seeds.

## Recovery drills

Recovery tests in `internal/service` exercise complete recovery flows across real services:

- `TestRecovery` (`internal/service/recovery_test.go`): A lost main device is recovered with the
  recovery key on a computer, then handed over to an admin.
- `TestFFIPhoneChangeRoot` (`internal/service/recovery_test.go`) and `TestFFIPhoneYubiKey`
  (`internal/service/phone_yubikey_test.go`): A phone member (`phone-on-linux`) moves the group
  using the recovery sheet or a YubiKey-sealed secret.
- `TestDrillRestoreFromYesterday` (`internal/service/drill_test.go`): A device restored from an
  older backup rejoins an active group.
- `TestDrillRemovedStaysOut` (`internal/service/drill_test.go`): A removed device restored from a
  pre-removal backup remains rejected.

`sh tools/e2e/drills.sh [COUNT]` builds `cbb`, `cbb-helper`, and `phone-on-linux` and runs all
five drills, with the environment variables they need (`CBB_TEST_RUST_SERVICE`, `CBB_TEST_ALONE`,
`CBB_PHONE_ON_LINUX`). Real
iPhone Secure Enclave and Face ID recovery steps are verified manually on the
[test bench](maintainers/testbench.md).

## Soak

`tools/soak/soak.sh` runs a local loopback (`127.0.0.1`) group of `cbb` and `cbb-helper` processes
for days, verifies that copies arrive on every member, kills random members with `SIGKILL` (leaving
member 1 alive for the full run so slow leaks surface), and checks that restarted members recover
intact. Multiple stands can run concurrently by setting `SOAK_NAME`, `SOAK_DIR`, and `SOAK_PORT`.

Two profiles are supported (`SOAK_PROFILE`):

- **calm** (default): 3 members; one checked text copy every 2 minutes; one random `SIGKILL` every
  10 to 60 minutes.
- **load**: 8 members; the calm schedule plus a 60-second burst of one copy per second every 10
  minutes (one in ten near the 1 MiB text limit, last copy verified on all members) and a random
  file up to 64 MiB every 30 minutes (verified by SHA-256 on all members), with kills timed inside
  bursts. Runs under `nice 10` and pinned to one CPU core (`taskset`) so a calm stand beside it is
  not perturbed.

Commands: `sh tools/soak/soak.sh start BINDIR`, `status`, `verdict`, and `stop`.

Every 24 hours, a summary line is written to `soak.log` with copies sent, checked, arrived, and
missed; kills and whole vs. broken restarts; checked-copy delivery percentiles (`p50`, `p95`, `max`
across the slowest member, plus per-member `p95`); peak RSS and open file descriptors; RSS and
descriptor floor movement; and disk growth rate. Because single RSS samples fluctuate with large
copies, memory and open files are evaluated using hourly floors (six samples at 10-minute intervals
after a 1-hour warm-up following start or restart), while single-sample metrics are printed as
`raw_*` for inspection.

`verdict` (and `stop`) reports `PASS` only when all fixed bounds hold:

- Zero missed copies (a checked text copy must reach all members within 60 s; a file within 240 s),
  including copies sent immediately after a kill. These timeouts reflect the member reconnect
  backoff (`FIRST_WAIT` of 1 s up to `MAX_WAIT` of 30 s in `member/src/discovery.rs`) and the 15 s
  silent-peer `TIMEOUT` in `member/src/mesh.rs`.
- Zero broken restarts.
- Delivery `p95` at most 10 s (`10000 ms`).
- No member's RSS floor grows by more than 1 MiB (`calm`) or 4 MiB (`load`) over its first window's
  floor, and no member's RSS floor rises for three consecutive windows (a rise being at least 64 KiB
  over the previous window).
- No member's open-file floor rises above its first window's floor.
- Combined member state, record, and log directories grow by at most 20 MiB per member per day
  (measured starting 6 hours after the first sample).

These bounds are fixed ahead of measurement: exceeding a bound is a defect, not a reason to relax the
limit. Soak reports record duration, commit, hardware (CPU architecture and core count logged by
`start`), copy and restart counts, delivery percentiles, memory and file-descriptor growth, and
verdict. For release-gating plans around soak runs, see [Roadmap](roadmap.md).

## Bench scenarios

Unit and CI tests cannot prove that a copy on a physical iPhone reaches a Windows PC across café
Wi-Fi. The [test bench](maintainers/testbench.md) verifies physical devices across every platform
using rules R1–R7 ([Test bench cases](maintainers/testbench-cases.md)), a release
[catalogue](maintainers/testbench-catalogue.md), and a function coverage matrix
([Test bench functions](maintainers/testbench-functions.md)). Security cases block a release; cases
that cannot run remain on the list with a recorded skip reason.

## App languages, accessibility, and screenshots

Every app is verified across all eight project languages (`zh`, `en`, `es`, `ru`, `ar`, `sw`, `he`,
`hi`) and for screen readers, large text, and keyboard navigation
([Test bench catalogue](maintainers/testbench-catalogue.md), cases `A9` and `U14`–`U18`):

- **Static checks**: `tools/repocheck` verifies that every app string catalog, Android
  `strings.xml`, tray JSON, and CLI translation covers all eight languages, is complete, and
  preserves format placeholders. `tools/tokens -check` verifies WCAG AA contrast for every palette.
- **Tray app (`apps/desktop`, `TestWindow` in headless Chrome)**: Verifies all eight languages with
  no untranslated English, no clipped text, and no horizontal overflow; right-to-left layout in
  Arabic and Hebrew; accessible names for all controls; contrast across all ten palettes in light
  and dark themes; layout at 2x text size; and keyboard Tab focus across the header and Settings.
- **Android (`LanguagesTest`, `AccessibilityTest` on Robolectric)**: Verifies Start and Settings
  screens in all eight languages with no truncated text or ellipsis, right-to-left layout in Arabic
  and Hebrew, accessible names, at least 48 dp touch targets, and no clipping at font scale 2.
- **iPhone and Mac (`ReadersUITests`)**: Launches each language with `-AppleLanguages`, checks
  rendered strings against the catalog, verifies right-to-left header layout on iPhone, and runs
  Xcode's accessibility audit (clipped text, labels, touch targets, and Dynamic Type at the largest
  accessibility size in English, Swahili, and Hindi on iPhone). On iPhone and iPad, `ReadersUITests`
  also tests Home's legacy-group and member notice cards in English and Arabic using `-showcase
  -showcaseAlerts -showcaseNoDevices` (a group with no device tiles, since the audit counts text
  running past the screen edge as clipped), confirming that **Hide** hides only dismissible notices. Text and iPhone button
  contrast is verified directly on captured screenshots (at least 4.5:1 between darkest and lightest
  pixels) because Xcode's built-in audit reports false contrast failures on high-contrast elements.
  CI exports all `.xcresult` screenshots (`ios-screens-iPhone`, `ios-screens-iPad`, `mac-windows`),
  embeds English, failed-audit, and lost-tap screenshots in failed job logs (`.github/pictures.py`),
  and records failed iPhone test activities (`.github/activities.py`).
- **iPad (`PadUITests`, skipped on iPhone)**: Launches a debug build with `-showcase`
  (`apps/ios/CBB/App/Showcase.swift`, local fixture only) to verify the sidebar, detail card beside
  tiles, arrow keys, Escape (sent via `XCUIKeyboardKey.simulatorEscape`, `U+241B`), Settings,
  Command-1, portrait layout, Arabic right-to-left card placement, and largest-text clipping.
- **iOS CI image**: `iPhone app` runs on GitHub's `xcode-27` image with Xcode 27.2 and the latest
  iOS runtime so clipped-text audits handle Devanagari conjuncts and Chinese punctuation accurately.
- **Other big screens**: Android `TabletHomeTest` verifies sidebar section state across restarts.
  HarmonyOS ArkTS (including sidebar, keys, and drops) is compiled and linted by
  `apps/harmony/check.sh`.

Pixel screenshot comparisons run where rendering is deterministic across machines: the tray app on
Linux with Noto fonts (`fonts-noto-core`, `fonts-noto-mono`, `fonts-droid-fallback`) and Android
screens under Robolectric native graphics (`ScreenshotTest`). Up to 0.3% differing pixels are
tolerated for font-smoothing differences across browser builds; failures upload actual and diff
images as CI artifacts (`tray-screenshots`, `android-screenshots`). Simulator screenshots vary by
Xcode and iOS release, so iPhone and Mac screenshots are attached for visual review rather than
pixel-diffed.

After intentional UI changes, regenerate and inspect reference screenshots before committing:

```sh
cd apps/desktop && CBB_UPDATE_SCREENSHOTS=1 go test -run 'TestWindow/screenshots' .
cd apps/android && ./gradlew :app:recordRoborazziFullDebug
```

Tray screenshot references match CI's Linux Chrome build; if a local Chrome version differs by more
than 0.3%, verify the local screenshots visually and adopt the reference images from the failed CI
job's `tray-screenshots` artifact.

### Dangerous screens

`TestWindow/dangerous screens` (`apps/desktop/dangerous_test.go`) renders every security-critical
tray screen in all eight languages into a single HTML review sheet with captions: the six-digit
pairing code, invitation fingerprint comparison, removing a device, promoting an admin computer,
conflict and split-group alerts, voiding conflicting histories, moving the group with the recovery
key, and lost-group warnings. `DangerousScreensTest` on Android Robolectric contributes the
Android invitation fingerprint, removing a device or main device, conflict alerts, and recovery
sheet screens.

This sheet is for human and native-speaker review before a release and is not pixel-compared. Run
Android first so the tray test embeds its images into the HTML sheet:

```sh
export CBB_DANGEROUS_SHEET=/tmp/sheet
(cd apps/android && ./gradlew :app:testFullDebugUnitTest --tests 'tools.cbb.DangerousScreensTest')
(cd apps/desktop && go test -run 'TestWindow/dangerous' .)
```

iPhone screens are not yet included in the combined sheet.

## Coverage

CI measures line or statement coverage per component (and branch coverage where supported) and
publishes a summary table in the `coverage` job. `tools/coverage` aggregates reports and fails CI if
any row drops more than 1 percentage point below its floor in `tools/coverage/floor.json`.

Targets above the floors emit warnings without failing CI:

- **Lines / statements**: 90% (`-target 90`)
- **Branches**: 80% (`-branch-target 80`), and 90% for protocol cores (`-core-branch-target 90`)

Floors only rise as coverage improves, locking in gains. Test-only Rust modules compiled under
`#[cfg(test)]` (listed in `rustTestOnly` in `tools/coverage/main.go`, including `sim/`,
`vectors.rs`, `verdicts.rs`, `longrules.rs`, `powerloss.rs`, `testkit.rs`, `msg/mutants.rs`, and
`member/src/nettest/`) are excluded from product line totals.

Branch rows appear as `PART/branches` where the toolchain reports them: JaCoCo for Kotlin,
`llvm-cov` for Swift, and the nightly `rust core, branch coverage` job for `cbb_core` (which
requires nightly Rust). Go reports statement coverage only.

Below the coverage table, `tools/coverage` enforces three hard gates that fail CI immediately:

- **Closed audit findings (`-audit testdata/audit/closed.json`)**: Every closed security audit
  finding lists one or more regression tests by opaque ID; removing a listed test fails the gate.
  If a test is removed along with the feature it tested, update its entry to the replacement named
  in `tools/repocheck/removed-tests.txt`.
- **Format refusal rules (`-rules core/src -vectors testdata/format`)**: Every rule named with
  `Rule::field("...")` in `core/src` (outside `tests.rs`) must appear as an expected refusal in
  `testdata/format/*.json`—either with `"rule"` and `"verdict": "refuse"` (or omitted verdict) or
  with `"verdict"` set directly to the rule name—or be covered by a stateful Rust test annotated
  with `// refuses: <rule>` whose body references the rule string or constant.
- **Mutation survivors (`-mutants`)**: Every surviving mutant must be explicitly listed in
  `tools/mutants/missed.txt` (enforced nightly via `tools/mutants/check.sh`).

| Part | What counts | Measured by |
|---|---|---|
| `go` | Statements in `cmd/` and `internal/`, excluding `third_party/` and test-fake packages listed in `testFakes` (`tools/coverage/main.go`) | `go coverage` (cross-package `-coverpkg`, desktop clipboards under Sway and Xvfb, `uinput`, Avahi mDNS, e2e `cbb-helper` built with `-cover`, desktop connector), `service tests on the Rust cbb` shards (`cover-go-service-PART.out`), and per-OS profiles from `test` and macOS `go test` |
| `go-core` | Statements in `internal/group` and `internal/clip` | Same profiles as `go` |
| `go-tray` | Statements in `apps/desktop` | `go test -coverprofile` in `tray app (ubuntu-latest)` (including `TestWindow` in headless Chrome) |
| `rust-core` | Lines in `core/src`, excluding `third_party/` and `rustTestOnly` | `cargo llvm-cov nextest` across the two `cbb (Rust)` shards, merged by `cbb (Rust), the coverage` |
| `rust-member` | Lines in `member/src`, excluding `rustTestOnly` (Rust tests alone) | Same as `rust-core` |
| `rust-service` | Lines in `member/src` from Rust member tests and Go service/connector/phone-tunnel tests combined | `cargo llvm-cov` in `service tests on the Rust cbb, the coverage` |
| `swift-kit` | Lines (and branches) in `apps/ios/CBBKit/Sources` | `swift test --enable-code-coverage` in `test and build (macOS), homebrew, Mac app` |
| `kotlin-kit` | Lines (and branches) in `apps/android/kit` | JaCoCo in `Android app` |
| `kotlin-watch` | Lines (and branches) in `apps/android/shared` (`WatchState` and shared design) | `createDebugUnitTestCoverageReport` (JaCoCo) in `Android app` |
| `js-tray` | Lines in `apps/desktop/frontend` scripts | Browser coverage under `TestWindow` (`CBB_JS_COVERAGE`, LCOV) in `tray app (ubuntu-latest)` |
| `cpp-aurora` | Lines in headless Aurora C++ sources (`apps/silica/src`: `errors.cpp`, `events.cpp`, `membership.cpp`, `core.cpp`, `platform/keystore_file.cpp`) | `apps/silica/tests/qt/run.sh` (Qt 5 + `gcovr` LCOV) in `Aurora and HarmonyOS apps' code on the computer` |
| `ets-harmony` | Lines in HarmonyOS phone model, core, and common ArkTS (`apps/harmony/entry/src/main/ets`) | `apps/harmony/nodetest/run.sh` (compiled TypeScript + Node test runner against host `libcbb_ffi.a`) in `Aurora and HarmonyOS apps' code on the computer` |
| `ets-harmony-watch` | Lines in HarmonyOS watch ArkTS (`apps/harmony/wearable/src/main/ets`) | `apps/harmony/nodetest/run.sh` with `watch.test.cjs` in `Aurora and HarmonyOS apps' code on the computer` |

Tests that compare their own execution time against cryptographic operations are skipped under
`cfg(coverage)` because instrumentation slows only the measured crate:
`a_full_group_fills_in_about_the_time_of_its_signatures` (`core/src/records/tests/insert_cost.rs`)
runs uninstrumented in `cbb (Rust), the checks and the Raspberry Pi builds`.

Tests too slow for pull requests carry `#[ignore]` with a reason and run nightly in
`the core's slow tests`: step-by-step record-set restore tests (`core/tests/read_records.rs`) and
constant-time secret comparison tests (`core/src/secret.rs`, Welch's t-test on one thread; excluded
from `cfg(coverage)` builds).

Coverage is a diagnostic signal, not proof of correctness: executing a line without asserting its
effect raises the percentage without catching bugs.

To measure Go coverage locally:

```sh
go test -coverpkg=./cmd/...,./internal/... -coverprofile=cover.out ./cmd/... ./internal/...
go run ./tools/coverage -go cover.out -floor tools/coverage/floor.json
```

To measure `rust-service` coverage locally on Linux (requires a network interface with a private
home address for mDNS):

```sh
eval "$(cargo llvm-cov show-env --sh)"
cargo llvm-cov clean --workspace
cargo test --release -p cbb-member && cargo build --release -p cbb-member --features testhooks
CGO_ENABLED=0 go build -tags testhooks -o target/release/cbb-helper ./cmd/cbb-helper
CBB_TEST_RUST_SERVICE=$PWD/target/release/cbb CBB_TEST_ALONE=$PWD/target/release/cbb go test ./internal/service
cargo llvm-cov report --release --json --summary-only --output-path service.json
go run ./tools/coverage -llvm rust-service=service.json -floor tools/coverage/floor.json
```

Because members discover peers only on private, link-local, or unique-local home addresses, run
`internal/service` inside an isolated network namespace with a private bridge if your container has
only a public IP address (requires root and `iproute2`):

```sh
unshare -n sh -c 'ip link set lo up && ip link add home0 type bridge &&
  ip link set home0 multicast on && ip addr add 10.77.0.2/24 dev home0 &&
  ip link set home0 up && ip route add default dev home0 && exec "$@"' _ \
  env CBB_TEST_RUST_SERVICE=$PWD/target/release/cbb CBB_TEST_ALONE=$PWD/target/release/cbb \
  go test ./internal/service
```

## Firmware size

Small devices link only the `cbb_core` modules they call, so flash footprint is measured on linked
binaries. `tools/size` (`cbb-size`) builds for ESP32-C6 RISC-V (`riscv32imac-unknown-none-elf`,
release profile) with opaque inputs that prevent dead-code elimination; it is never executed.

`sh tools/size/size.sh` builds an empty binary, one binary per feature (`p256`, `json`, `records`,
`seal`, `copy`, `pair`, `tls`), one binary with all seven (`all`), and one binary calling the full
C ABI entry point (`api`). For each build, it sums flash sections (`.text`, `.rodata`, `.data`,
`.sdata`, `.srodata`), computes the delta over the empty binary, and compares against
`tools/size/baseline.txt`. Because features overlap (for example, `copy` pulls in `records`,
`seal`, and `json`), individual deltas do not sum to `all`.

The `the core on the ESP32` CI job runs `size.sh` on every Rust change, appends the table to the job
summary, and fails if `all` grows more than 10% over baseline. Intentional size increases update
`tools/size/baseline.txt` in the same pull request with `sh tools/size/size.sh -update`.

## Unsafe code

`cbb_core` forbids unsafe code (`#![forbid(unsafe_code)]` in `core/src/lib.rs`). Unsafe code lives
only in `member/src` (OS syscalls) and `ffi/src` (C ABI entry points) and is checked nightly in
`.github/workflows/nightly.yml`:

- **Miri (`miri (the C functions of ffi)`)**: Runs
  `cargo +nightly miri test --locked -p cbb-ffi --features join --lib` to validate FFI pointer
  handling.
- **AddressSanitizer (`address sanitizer (the Rust cbb and ffi)`)**: Runs Rust tests for
  `cbb-member` and `cbb-ffi --features member,tunnel` and runs `go test -timeout 60m ./internal/service`
  against an ASan-instrumented `cbb` binary, covering OS syscalls that Miri cannot execute.

## Mutation testing

Coverage shows that code ran; mutation testing checks whether tests catch deliberate bugs (such as
dropped checks, boundary shifts like `<` to `<=`, or early returns). The nightly workflow runs
`cargo mutants` on parsers of untrusted input:

- `mutants-rust`: Mutates `core/src/strict.rs` across 8 shards.
- `mutants-service`: Mutates `core/src/seal.rs` (`--lib`) and `member/src/control.rs` across 4
  shards each.

Each shard runs `tools/mutants/check.sh` against `tools/mutants/missed.txt` (ignoring line and
column numbers) and fails on any unlisted surviving mutant. Write a test to kill each new survivor;
if a mutant is strictly equivalent and unobservable to callers, document why in
`tools/mutants/missed.txt`.

To run mutation testing locally:

```sh
cargo mutants --in-place -p cbb-core -f core/src/strict.rs
cargo mutants --in-place -p cbb-core -f core/src/seal.rs --cargo-test-arg=--lib
cargo mutants --in-place -p cbb-member -f member/src/control.rs
tools/mutants/check.sh mutants.out/missed.txt tools/mutants/missed.txt
```

## Not tested yet

Components built and tested in CI that have not yet run on physical hardware are listed in
[README status](../README.md#status) and [Platform parity](parity.md#on-real-devices) (including
physical Windows PCs, physical Android phones and hardware attestation, HarmonyOS phones, FreeBSD,
OpenWrt, Sailfish OS, Wear OS, Linux tray app, and physical ESP32 boards). Do not treat those
platforms as hardware-verified until the test bench has run on them.

## Red tests

Every failing test is a real defect until its root cause is fixed. Never skip, disable, or retry a
failing test to make CI pass.

Tests requiring host capabilities (an X server, Wayland compositor, IPv6 loopback, `swtpm`, or
`uinput`) may skip with an explanation on a developer machine, but fail in CI when the environment
variable `CI` or the explicit switch (`CBB_TEST_IPV6=1`, `CBB_TEST_UINPUT=1`, `CBB_TEST_WAYLAND=1`,
`CBB_TEST_X11=1`, `CBB_TEST_AVAHI=1`, `CBB_TPM_REQUIRED=1`) is set.

## Known failures

When an external platform defect causes a test step to fail with documented evidence, keep the test
running inside a strict expected-failure wrapper (such as `XCTExpectFailure` with `isStrict`) so
the test fails as soon as the external defect is fixed, tag it `KNOWN-ISSUE(<release>)`, and verify
the covered behavior manually until resolved. Only the maintainer approves entries.

No steps are currently marked as known failures.

## Unstable tests

An intermittent failure is a real bug (a race condition, an overly tight timeout, or an assumed
ordering). The nightly workflow runs `unstable tests (service)` and `unstable tests (alone)`
(10 repetitions each of `internal/service` and `internal/tunnel` against `cbb` with and without
`cbb-helper`) and `unstable tests (tray app)` (10 repetitions of `apps/desktop`), summarizing every
failing test and failure count. The hardware test bench also detects flakes via
`go run ./tools/bench -repeat 5 -scenario NAME fleet`, recording intermittent cases in `flaky.txt`
([Test bench automation](maintainers/testbench.md#11-automation)).

Track any test observed failing intermittently in the table below until its root cause is fixed:

| Test | Where | Observed rate | Known details |
|---|---|---|---|
| `TestSeveralHubs` | `internal/service` | ~1 in 6 runs | Cause not yet identified |
| `TestWindow` | `apps/desktop` (Linux, Windows) | Rarely (~1 in 300 runs on Linux) | Chrome starts but does not expose its DevTools port within 30 s; on Linux the last log line appears ~5 s after launch following failed desktop-portal D-Bus calls. The test logs startup timing to the job summary and keeps the last 200 lines of Chrome `--v=1` output for diagnosis |
