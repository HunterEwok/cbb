<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Maintaining

For the project maintainer. This page documents repository settings, GitHub Actions workflows,
release procedures, offline signing keys, server monitoring, abuse handling, and platform
distribution that live outside the source tree. Checked boxes mark one-time settings that are
already in place.

## Account

- [x] Enable two-factor authentication on the GitHub account with a passkey or hardware security
  key.
- [ ] Optional: sign commits with an SSH key (`git config gpg.format ssh`) and add the public key
  to GitHub as a signing key so commits appear as Verified.

## Repository settings

### General

**Settings → General**

- [x] Features: disable Wiki and Projects; enable Issues.
- [x] Pull Requests: allow **squash merging** only; enable **Automatically delete head branches**.
- [x] Releases: enable **release immutability**.

### Moderation

**Settings → Moderation**

- Interaction limits stay off unless needed for a temporary cool-down.
- Code of conduct reports go to GitHub Support through **Report content**, as described in
  [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md). A personal repository has no maintainer report
  inbox and publishes no email address for conduct reports.

### Code security

**Settings → Advanced Security** (named **Code security** on some accounts)

- [x] Enable **Private vulnerability reporting** ([SECURITY.md](../../SECURITY.md) relies on it).
- [x] Enable **Dependency graph**, **Dependabot alerts**, and **Dependabot security updates**.
- [x] Enable **Secret scanning** and **Push protection**.
- [ ] Keep **CodeQL** default setup off. GitHub rejects advanced workflow results while default
  setup is active, and default setup cannot build the Android Kotlin app or the XcodeGen-generated
  iPhone app. Instead, two custom workflows upload SARIF results:
  - [`.github/workflows/codeql.yml`](../../.github/workflows/codeql.yml) scans GitHub Actions, Go
    (Linux and Windows), Rust, and Java/Kotlin on every pull request, on pushes to `main`, and
    weekly. Go files compiled only on macOS run inside `ci.yml`'s macOS job on pull requests, and
    in `codeql.yml`'s `analyze (go, macos)` job on pushes to `main` that touch macOS Go files and
    on the weekly schedule.
  - [`.github/workflows/codeql-swift.yml`](../../.github/workflows/codeql-swift.yml) scans the
    iPhone app and `CBBKit` on pull requests (called from `ci.yml` when `apps/ios` changes), on
    pushes to `main` touching `apps/ios/**`, weekly, by manual dispatch, and during releases when
    `main` has no passing analysis for the tagged commit.
- [`.github/workflows/scorecard.yml`](../../.github/workflows/scorecard.yml) runs OpenSSF Scorecard
  weekly, on pushes to `main`, and on manual dispatch, uploading findings to Code scanning and
  publishing the score for the README badge. Its `Binary-Artifacts` check passes Android's
  `gradle-wrapper.jar` only when the first workflow containing the wrapper validation step passes
  on `main`'s latest commit:
  [`.github/workflows/android-wrapper.yml`](../../.github/workflows/android-wrapper.yml) runs on
  every push to `main`, sorts alphabetically before `ci.yml`, and completes before `scorecard.yml`
  runs.

### Actions

**Settings → Actions → General**

- [x] Workflow permissions: **Read repository contents and packages permissions**.
- [x] Disable **Allow GitHub Actions to create and approve pull requests**.
- [x] Fork pull request workflows: **Require approval for all external contributors**.

### Environments

**Settings → Environments**

- [ ] **release**: holds every release signing and distribution secret
  ([Release secrets](#release-secrets)). Restrict **Deployment branches and tags** to *Selected
  branches and tags*: tag pattern `v*` and branch `main`. Configure no required reviewers because
  pushing a release tag is the maintainer's approval.
- [ ] **aurora**: holds the Aurora OS developer certificate
  ([Signing for Aurora OS](#signing-for-aurora-os)). Require the maintainer as reviewer and allow
  every branch.

### Rulesets

**Settings → Rules → Rulesets**

Branch ruleset **Production Branch Protection** (active, targeting the default branch `main`):

- [x] Restrict deletions and block force pushes.
- [x] Require linear history.
- [x] Require a pull request before merging: 0 required approvals and **Require extra approval for
  unattributed changes** off (a single maintainer cannot approve their own pull request); allow
  squash merging only.
- [x] Require status checks `ci-ok` (from [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml))
  and `prcheck` (from [`.github/workflows/prcheck.yml`](../../.github/workflows/prcheck.yml)) from
  the GitHub Actions app, with branches up to date before merging. Because `ci-ok` aggregates
  every CI job, individual jobs can change without editing the ruleset.
- [x] Keep the bypass list empty.

Tag ruleset **releases** (active, targeting `refs/tags/v*`):

- [x] Restrict updates and deletions, and block force pushes, so release tags cannot move. Keep
  the bypass list empty.

Tag ruleset **release tags: create** (active, targeting `refs/tags/v*`):

- [ ] Restrict tag creation, with **Repository admin** in the bypass list (always allow). Only the
  maintainer can create release tags; apps and tokens with write access cannot. Keep this separate
  from **releases** so **releases** keeps an empty bypass list.

### Release secrets

Store all release keys as environment secrets in **Settings → Environments → release**, never as
repository secrets (a repository secret is accessible to any workflow on any branch).

The jobs that read these secrets name the `release` environment: `build`, `macos-app`, `testflight`,
`android`, and `openwrt-feed` in `.github/workflows/release.yml`, and `homebrew` in
`.github/workflows/published.yml`. `tools/repocheck` fails if any job in either workflow reads a
secret outside the `release` environment. To verify secrets without releasing, trigger a manual run
from `main` with an empty tag input (a manual run with a tag input is a rehearsal that reads no
secrets; see [A rehearsal of a release](#a-rehearsal-of-a-release)).

| Secret | Purpose | Procedure |
|---|---|---|
| `CBB_ANDROID_KEYSTORE_BASE64`, `CBB_ANDROID_KEYSTORE_PASSWORD`, `CBB_ANDROID_KEY_ALIAS`, `CBB_ANDROID_KEY_PASSWORD` | Android release signing key | [Android signing key](#android-signing-key) |
| `CBB_FIREBASE_APP_ID`, `CBB_FIREBASE_PROJECT_ID`, `CBB_FIREBASE_API_KEY`, `CBB_FIREBASE_SENDER_ID` | Firebase app credentials for Android full-build push | [Firebase for push](#firebase-for-push) |
| `CBB_WINDOWS_CERT_BASE64`, `CBB_WINDOWS_CERT_PASSWORD` | Windows Authenticode certificate | [Signing for Windows](#signing-for-windows) |
| `CBB_APPLE_DEVID_APP_P12`, `CBB_APPLE_DEVID_APP_PASSWORD` | Apple Developer ID Application certificate | [Signing for macOS](#signing-for-macos) |
| `CBB_APPLE_DEVID_INSTALLER_P12`, `CBB_APPLE_DEVID_INSTALLER_PASSWORD` | Apple Developer ID Installer certificate (`.pkg`) | [Signing for macOS](#signing-for-macos) |
| `CBB_APPLE_DISTRIBUTION_P12`, `CBB_APPLE_DISTRIBUTION_PASSWORD`, `CBB_APPLE_PROFILES` | Apple Distribution certificate and App Store profiles (TestFlight) | [Signing for macOS](#signing-for-macos) |
| `CBB_ASC_KEY`, `CBB_ASC_KEY_ID`, `CBB_ASC_ISSUER_ID` | App Store Connect API key (App Manager role) for notarization and TestFlight | [Signing for macOS](#signing-for-macos) |
| `CBB_OPENWRT_FEED_KEY` | OpenWrt apk feed ECDSA P-256 signing key | [The OpenWrt feed](#the-openwrt-feed) |
| `CBB_HOMEBREW_TAP_KEY` | SSH deploy key for `HunterEwok/homebrew-tap` | [Homebrew](#homebrew) |

GitHub does not allow reading secret values back. Generate every key on the maintainer's Mac and
store an encrypted offline backup (an encrypted disk image or password manager) before uploading
it:

```sh
gh secret set NAME --env release < file
```

You can also add secrets in **Settings → Environments → release → Add environment secret**.

## CI

[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs on every pull request. It does
not rerun on `main` because branch protection requires every pull request to be up to date with
`main` before squash merging.

The `changes` job detects which areas a pull request touches (`.github/ci-changes.sh`) so untouched
areas skip their jobs while `ci-ok` still counts them as passed. The jobs are:

- **check**: `gofmt`, `go mod tidy -diff`, `go mod verify`, `go vet`, `staticcheck`,
  `govulncheck`, `actionlint`, `zizmor`, [`tools/repocheck`](../../tools/repocheck/main.go) (with
  `-tests-since` against the pull request base), `tools/strings -lint` (termbase and Vale),
  `tools/tokens -check`, `tools/icon -check`, `tools/site check -strict`, `.github/shellcheck.sh`,
  `.github/release-targets.sh`, `typos`, Biome (`biome.json`), and `reuse lint` (`REUSE.toml`).
- **test**: `go test -race` with coverage on Linux x86-64, Linux ARM64, and Windows (plus 32-bit
  Go tests on Linux and Rust Windows ACL unit tests on Windows). macOS `go test -race` runs inside
  `buildmac`.
- **go coverage** and **coverage**: cross-package Go coverage (`-coverpkg`, including TPM, desktop
  clipboards, and container e2e) combined with Rust, Swift, Kotlin, Qt, and JS coverage against
  `tools/coverage/floor.json` ([Testing: coverage](../testing.md#coverage)).
- **build (Linux, FreeBSD, Windows)**: builds release targets across Linux (including ARMv6 for
  Raspberry Pi Zero W), FreeBSD, and Windows (`CGO_ENABLED=0` for Go helpers; see
  [Design: build](../design.md#build)).
- **test and build (macOS), homebrew, Mac app** (`buildmac`): runs `CBBKit` tests, macOS Go CodeQL
  analysis, `go test -race`, macOS release builds with ad hoc hardened-runtime signing and hook
  checks, Homebrew formula install test (`packaging/homebrew/formula.sh`), Mac app tests and
  unsigned `.pkg` install/uninstall test, and iOS Rust core build.
- **test (linux/mips under qemu)** and **cbb for MIPS (no tunnel)** (`rustmips`): big-endian and
  little-endian softfloat MIPS Go tests under QEMU and Rust router builds without the tunnel.
- **test (freebsd)** and **OpenWrt**: FreeBSD tests inside a VM and OpenWrt rootfs and apk feed
  install/remove tests (`tools/e2e/openwrt.sh`).
- **upgrade from the last release**: tests upgrading from the previous release (`tools/e2e/upgrade.sh`).
- **mdns with avahi**, **e2e**, and **desktop clipboards**: real-socket mDNS tests beside
  `avahi-daemon`, three-member Docker e2e tests (`tools/e2e/e2e.sh`), and Wayland (headless sway)
  and X11 (Xvfb) clipboard tests.
- **packaging** and **windows installer**: `systemd-analyze verify` and `security`, desktop entry
  validation, OPNsense hook check, `get.sh` and `cbb update` verification against signed test
  releases, SBOM generation, winget manifest check, and Windows `install.ps1` / `uninstall.ps1`
  tests on `windows-latest`.
- **a release build ignores the test hooks** (`hooks`): verifies on Linux and Windows that release
  builds carry no test-hook marker (`.github/hooks-marker.sh`) and ignore all test hooks
  (`.github/release-ignores-hooks.sh`), and that test builds fail those checks
  (`.github/hooks-refused.sh`).
- **phone kit (Linux)**, **iPhone app** (iPhone and iPad simulators), and **codeql-swift**: `CBBKit`
  tests and Go cross-tests on Linux, XcodeGen + `xcodebuild test` without signing on simulators,
  and Swift CodeQL analysis when `apps/ios` changes.
- **tray app**: builds and tests `apps/desktop` (including browser UI and screenshot checks) on
  Linux and Windows.
- **Android app**, **Android app on an emulator**, and **F-Droid build reproduces**: Kotlin `kit`
  tests and cross-tests, full and `fdroid` APK and Wear OS builds, unit tests, lint, SBOM,
  instrumented emulator tests, and F-Droid reproducibility (`packaging/fdroid/reproduce.sh`).
- **Aurora app**, **HarmonyOS app (native module)**, **Aurora and HarmonyOS apps' code on the
  computer**, and **phone core**: unsigned Aurora 5, Aurora 4, and Sailfish OS RPMs, HarmonyOS
  Node-API build and ArkTS compiler/linter checks, host-side Qt 5 and Node tests, and `ffi/bind.sh`
  builds for Android.
- **cbb (Rust)** jobs (`rustcheck`, `rust-build`, `rust`, `rust-coverage`, `rustinstall`): MSRV
  `cargo check`, `cargo fmt`, `clippy` per target, ARM64/ARMv6 builds, sharded `cargo-nextest` runs
  with coverage, optimized stack verification, and `--no-helper` / rootless installer tests.
- **service tests on the Rust cbb** (`service-build`, `service`, `service-coverage`): sharded
  `internal/service` tests against the Rust `cbb` binary with coverage
  ([Testing: running tests in parallel](../testing.md#running-tests-in-parallel)).
- **the core on the ESP32** and **ZX Spectrum Next**: `cbb-core` `no_std` builds for ESP32-C6
  (RISC-V) and ESP32-S3 (Xtensa), Nano ESP32 firmware self-test in QEMU, and `.cbb` / `.pibridge`
  builds with z88dk plus host frame-parser tests.
- **advisories**, **docker image**, **website**, **differential**, **model**, and **the frozen
  format**: OSV-Scanner and `cargo-deny`, multi-arch Docker build and container e2e, `nginx -t` +
  HTML validation + Lighthouse, Go/Rust/Kotlin differential fuzzing (`.github/differential.sh`),
  Quint record-model tests (`docs/model/records-v3.qnt`), and `tools/formatfreeze` + `gen.py`
  vector checks.
- **ci-ok**: final aggregation job required by the branch ruleset.

Companion workflows outside `ci.yml`:

- [`prcheck.yml`](../../.github/workflows/prcheck.yml): verifies commit author/committer/co-author
  addresses and pull request metadata (`tools/prcheck`); required by the branch ruleset.
- [`nightly.yml`](../../.github/workflows/nightly.yml): daily extended differential fuzzing,
  native Go and Cargo fuzz targets, 1,000-seed group simulation, slow core tests, mutation testing
  (`cargo-mutants`), reproducible-build checks, Miri on `ffi/`, ASan on `cbb` and `ffi/`, Rust core
  branch coverage, and 10× unstable-test sweeps.
- [`pins.yml`](../../.github/workflows/pins.yml): weekly check (`tools/pins`) for outdated
  manually pinned tool versions and nightly toolchains that Dependabot does not manage.
- [`channel.yml`](../../.github/workflows/channel.yml),
  [`monitor.yml`](../../.github/workflows/monitor.yml),
  [`aurora.yml`](../../.github/workflows/aurora.yml),
  [`release.yml`](../../.github/workflows/release.yml), and
  [`published.yml`](../../.github/workflows/published.yml): release channel, server monitoring,
  Aurora signing, and release automation described below.

### Workflow rules

- Pin every third-party action to a full commit SHA with the version in a trailing comment;
  Dependabot updates them.
- Set `permissions: contents: read` at the workflow level; grant elevated permissions only on the
  individual job that needs them.
- Check out with `persist-credentials: false` unless a job pushes commits (annotate any exception
  with `# zizmor: ignore[...]`).
- Resolve every `zizmor` finding or document a required exception with `# zizmor: ignore[<audit>]`
  stating the reason.
- Never pass secrets to pull request workflows.
- Pin Go development tools (`staticcheck`, `govulncheck`, `actionlint`) in `go.mod` and run them
  with `go tool`. Allow them explicitly in
  [`.github/dependabot.yml`](../../.github/dependabot.yml) because Go records them as indirect
  dependencies that Dependabot otherwise skips.

## Releases

### Prepare and publish a release

1. Open a release preparation pull request on a branch from `main` that updates:
   - [`CHANGELOG.md`](../../CHANGELOG.md): move items from `## [Unreleased]` to
     `## [X.Y.Z] - YYYY-MM-DD` and update the comparison links at the bottom.
     `packaging/release-notes.sh` reads this section and fails the release if it is missing.
   - `apps/android/version.properties`: set `versionName=X.Y.Z` and
     `versionCode=X*10000 + Y*100 + Z` (`tools/repocheck` verifies agreement with `CHANGELOG.md`,
     and `release.yml` fails if a non-prerelease tag differs).
   - `apps/silica/packaging/aurora4/tools.cbb.aurora.spec`,
     `apps/silica/packaging/aurora5/tools.cbb.aurora.spec`, and
     `apps/silica/packaging/sailfish/harbour-cbb.spec`: update `Version:` to `X.Y.Z`
     (`tools/repocheck` checks these against `CHANGELOG.md`).
   - `apps/android/app/fastlane/metadata/android/en-US/changelogs/<versionCode>.txt`: add the
     F-Droid release notes (at most 500 characters).
2. Merge the pull request once `ci-ok` and `prcheck` pass.
3. Tag `main` and push the tag (never build releases on a workstation):

   ```sh
   git tag -a vX.Y.Z -m vX.Y.Z
   git push origin vX.Y.Z
   ```

   `.github/workflows/release.yml` verifies pinned root keys, builds all platform archives, APKs,
   macOS `.pkg`, TestFlight upload, OpenWrt feed, ZX Spectrum Next archive, SBOMs, `SHA256SUMS`,
   winget manifest, and Sigstore build provenance attestations (`actions/attest-build-provenance`
   and `provenance.intoto.jsonl`). Once Swift CodeQL passes for the tagged commit (reusing `main`'s
   passing analysis when present), it creates a draft release and builds and pushes the unsigned
   Docker image (`ghcr.io/hunterewok/cbb:X.Y.Z-unsigned`), appending its attested digest to the
   draft notes.
4. Sign and publish the draft release on your Mac with `release-sign publish`
   ([Signed releases](#signed-releases)).
5. After publication, `.github/workflows/published.yml` verifies the published release files under
   the pinned roots, tags the signed Docker image digest as `X.Y.Z` (and `latest` when moving
   forward on a stable release), verifies all attestations and image digests (`release-check`), and
   updates the Homebrew tap (`homebrew`).

A tag of the form `vX.Y.Z-rc.N` creates a pre-release, which `releases/latest`, `get.sh`, Homebrew,
`winget-manifest.zip`, `stable.json`, and Docker `latest` skip. Pre-releases need no preparation
pull request: `packaging/release-notes.sh` reads `CHANGELOG.md`'s *Unreleased* section, and the
Android build derives `versionName` and `versionCode` from the tag.

For the first Docker image push to `ghcr.io/hunterewok/cbb`, change package visibility from private
to public once in GitHub package settings.

### Release archives

Archive names omit the version (`cbb-<os>-<arch>.tar.gz`, or `cbb-windows-<arch>.zip` on Windows)
so `releases/latest/download/` URLs stay fixed for `get.sh` and `get.ps1`. Each archive contains a
`cbb/` directory with:

- `cbb` (`cbb.exe` and windowless `cbbw.exe` on Windows);
- `cbb-helper`, `cbb-forward`, and `cbb-relay` on every target except MIPS routers (where `cbb`
  runs alone);
- `cbb-push` on Linux targets except MIPS;
- the tray app `cbb-desktop` on Linux `amd64`/`arm64` and `cbb-desktop.exe` on Windows;
- `LICENSE`, `THIRD_PARTY_NOTICES` (Rust crate licenses from `packaging/notices.sh`, followed by
  Go module licenses, copied third-party code licenses, and Go runtime notices from
  `packaging/archive.sh`), and `packaging/`.

### Test builds

Test-only builds—Rust features `benchtime`, `testhooks`, and `fuzzing`, and Go build tags
`benchtime` and `testhooks`—must never ship in a release. Multiple guards prevent this
(`member/src/testbuild.rs`, `internal/testhook/testhook.go`):

- `CBB_RELEASE_BUILD=1` (set by `release.yml`) causes Rust compilation to fail if `benchtime`,
  `testhooks`, or `fuzzing` is enabled.
- Test builds print the marker `cbb-test-build-not-for-release` in `cbb version` and
  `cbb-helper version` and embed it in the binary.
- `release.yml` runs `.github/hooks-marker.sh absent` on every program it archives, and
  `.github/release-go.sh` checks `go version -m` to reject `-tags=.*(benchtime|testhooks)` on
  every Go binary.
- Test hook variables (`CBB_TEST_*`, `CBB_TPM_SIMULATOR`, `CBB_HELPER`, `CBB_RELEASE_DIR`, and
  `CBB_RELEASE_ROOTS`; see [Settings and environment variables](../reference/config.md)) are read
  only through `member/src/testbuild.rs` and `internal/testhook`, which release builds ignore.
  `tools/repocheck` fails if production code reads any hook directly.
- CI's `hooks`, `buildmac`, and `packaging` jobs verify that release builds ignore all test hooks
  (`.github/release-ignores-hooks.sh`) and that test builds are caught by both
  `.github/hooks-marker.sh` and `.github/release-ignores-hooks.sh` (`.github/hooks-refused.sh`).

### What a release is built from

`tools/sbom` generates deterministic CycloneDX 1.6 JSON software bills of materials (no timestamps;
UUID serial numbers derived from content) listed in `SHA256SUMS` and `release.json`:

- `sbom-go.cdx.json`: Go modules embedded in every Go binary inside the release archives
  (`cbb-helper`, `cbb-forward`, and `cbb-desktop` / `cbb-desktop.exe`) and the Go standard library.
- `sbom-member.cdx.json`: crates compiled into `cbb-member` across all release targets (excluding
  dev and build dependencies), with checksums from `Cargo.lock`.
- `sbom-phone-core.cdx.json`: crates compiled into `cbb-ffi` across iOS and Android targets.
- `sbom-ios-kit.cdx.json`: Swift packages from `apps/ios/CBBKit/Package.resolved`.
- `sbom-android.cdx.json`: Maven dependencies for the full Android build, F-Droid build, and Wear
  OS app, collected by `packaging/sbom.init.gradle.kts` without modifying Gradle build files.

The Docker image receives its own SBOM as a GitHub registry attestation (`actions/attest` with
`sbom-path`) rather than a Buildx SBOM attestation, which would add an `unknown` platform entry to
the image index. CI's `packaging` and `Android app` jobs generate these SBOMs on every pull request.

### A rehearsal of a release

To test the release pipeline without signing or publishing anything, run
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) manually (**Actions →
release → Run workflow**) from any branch with the **tag** input set to `vX.Y.Z` or `vX.Y.Z-rc.N`.

The `roots` job validates the tag characters (`0-9`, `a-z`, `.`, `-`) and sets `sign=false` for
rehearsals (`sign=true` is set only for a pushed tag or a manual keys check from `main` with an
empty tag input). Because `sign` is `false`, jobs do not enter the `release` environment and read
no secrets: binaries stay unsigned or ad hoc signed, and the rehearsal omits APKs, `.pkg`,
TestFlight, OpenWrt feed, draft release, Swift CodeQL, and Docker image pushes. The `release-files`
job uploads the built archives, `SHA256SUMS`, SBOMs, `get.sh`, `get.ps1`, and (for non-prerelease
tags) `winget-manifest.zip` as the `release-files` artifact for 7 days.

If `TestPinnedRootsComplete` fails during a rehearsal, the `roots` job logs a warning and summary
and continues; pushed tags and manual keys checks stop on failure.

## Signed releases

`tools/release-sign` creates and signs the release metadata files specified in
[Protocol](../protocol.md), section 16, on the maintainer's Mac. Signing keys never enter CI.

### Root keys and release keys

- **Root keys** (one-time setup): generate one P-256 key on each of two YubiKeys kept in separate
  locations, in an unused retired PIV slot (slot `82`, confirmed empty with
  `ykman piv keys info 82`; nothing else on the YubiKey is reset):

  ```sh
  ykman piv keys generate --algorithm ECCP256 --pin-policy ALWAYS --touch-policy ALWAYS 82 root-N.pem
  ykman piv certificates generate --subject "CN=Connect Beyond Borders release signing root N" 82 root-N.pem
  ykman piv keys attest 82 > root-N-attest.pem
  ```

  Export the slot `f9` attestation certificate alongside `root-N-attest.pem` into
  `internal/release/roots/attestation/` (`internal/release/roots/README.md`). Create each root's
  post-quantum half beside it ([Two signatures](#two-signatures)). Commit both halves of `root-1`
  and `root-2` to `internal/release/roots/roots.pem` (read by Go's `internal/release.Roots` and
  Rust's `release::ROOTS_PEM`) and mirror them in `packaging/get.sh` (`release_roots`) and, for
  the P-256 halves, `packaging/windows/get.ps1` (`$releaseRoots`).
- **Release key**: create a P-256 key in the Mac's Secure Enclave requiring Touch ID per signature,
  or in retired PIV slot `83` on a YubiKey:

  ```sh
  swift tools/release-sign/se.swift create ~/.config/cbb-release/release.se
  ```

  Generate its post-quantum half sealed to the same hardware ([Two signatures](#two-signatures)). A
  root key certifies both halves in `keys.json` (valid for 90 days).
- **The `channel` branch**: stores the active `keys.json`, `stable.json`, and `entries.json`
  ([Protocol](../protocol.md), section 16, "Where the files are") because published GitHub releases
  are immutable. `release-sign publish` creates the branch on the first signed release; only
  `release-sign` and `.github/workflows/channel.yml` write to it.

### Channel key and automatic renewal

Generate the channel key once on `cbb.tools`, readable only by root:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out /etc/cbb-channel/channel-key.pem
```

Create its post-quantum half as a systemd encrypted credential and export both public halves to
`channel.pem` ([Two signatures](#two-signatures)), then copy `channel.pem` to your Mac and certify
it once with `release-sign publish -channel cbb.tools=channel.pem` (or `release-sign renew`).

Build `release-sign` for `cbb.tools` with `GOOS=linux GOARCH=amd64 go build ./tools/release-sign`
and install it at `/usr/local/bin/release-sign`. A twice-weekly systemd timer
(`site/deploy/cbb-channel.service` and `site/deploy/cbb-channel.timer`, Monday and Thursday at
05:00 UTC, running as user `cbb-channel` with both key halves passed as systemd credentials) runs:

```sh
/usr/local/bin/release-sign extend \
  -key "file:$CREDENTIALS_DIRECTORY/channel-key.pem+slh:$CREDENTIALS_DIRECTORY/channel-pq.pem" \
  -out /srv/cbb.tools/channel
```

`extend` reads the `channel` branch, verifies it under the pinned roots, re-signs `stable.json`
for **14 days** with the same release and a higher sequence number, re-signs `entries.json` for
**30 days** with the same forwarders and relays if present, and writes them beside `keys.json` at
`https://cbb.tools/channel/`.

The daily `.github/workflows/channel.yml` workflow runs `release-sign take channel`, which commits
the renewed `stable.json` and `entries.json` to the `channel` branch only if they verify under the
pinned roots, advance the sequence number within bounds, and keep the same release, forwarders, and
relays. GitHub holds no signing key and `cbb.tools` holds no GitHub token.

### Publishing with release-sign

Once `release.yml` finishes the draft release and its `docker` job appends the image digest to the
draft notes, run on your Mac with `gh` authenticated:

```sh
release-sign publish -version X.Y.Z [-min-from X.Y.Z]
```

`publish` performs these steps:

1. Verifies that pinned roots are complete (`release.CompleteRoots`).
2. Downloads all draft files and verifies each file's Sigstore build provenance attestation—and the
   Docker image's attestation in `ghcr.io`—against `refs/tags/vX.Y.Z` and
   `.github/workflows/release.yml`.
3. Keeps the `channel` branch's `keys.json` if it has at least 45 days of validity left and already
   certifies the release key and any requested extra keys; otherwise signs a new `keys.json` (valid
   90 days) with a YubiKey root key (PIN and touch).
4. Signs `release.json`, `zxnext.json` (when `cbb-zxnext.tar.gz` is present), and `stable.json`
   (for non-prereleases, valid 14 days) with the release key (Touch ID per file).
5. Verifies all signed files and assets under the pinned roots as a client device would.
6. Uploads `release.json` (and `zxnext.json`) to the draft, prompts for confirmation, publishes the
   release, and commits `keys.json` and `stable.json` to the `channel` branch.

Useful flags:

- `-no-publish`: stops after uploading `release.json`, leaving the release as a draft.
- `-docker none`: signs a release with no Docker image.
- Manual subcommands for individual steps: `release-sign manifest`, `sign`, `channel`, `keys`, and
  `verify` (see usage comments in `tools/release-sign/main.go`).
- Test drill with throwaway keys in files: `release-sign drill -version X.Y.Z DIR ROOTS.pem`.

### Entry points and server key pins

- **Entry points** ([Protocol](../protocol.md), section 16, "Entry points"): to publish or update
  non-built-in server entry points without a release, check out the `channel` branch on your Mac
  and run:

  ```sh
  release-sign entries -key se:~/.config/cbb-release/release.se -in in.json channel
  ```

  `in.json` lists forwarder VLESS paths and optional relay endpoints:

  ```json
  {
    "forwarders": [
      {
        "name": "cbb.tools:8764",
        "vless": [
          {"transport": "xhttp", "server_name": "cbb.tools", "port": 443, "path": "/banMEJvnYJJap8S"}
        ]
      }
    ],
    "relays": [
      {"name": "cbb.tools:8765", "endpoints": ["relay.cbb.tools:8765"]}
    ]
  }
  ```

  Omitting `endpoints` defaults a relay to its `name`. `entries` signs `entries.json` valid for
  30 days (`-days`, maximum 100), verifies it under the pinned roots, and writes it to `channel`;
  commit and push the file. `release-sign extend` on `cbb.tools` renews it automatically, `take`
  accepts renewals only when both forwarders and relays match, `due` warns when expiry approaches,
  and `mirror` serves the newest verified copy.
- **Push service key**: `cbb-push` has no built-in pin, so groups reach it only after `keys.json`
  lists its public key. On `cbb.tools`, `cbb-push` creates `/var/lib/private/cbb-push/push.pem` on
  first start (preserve this file). Extract its public key and certify it on your Mac:

  ```sh
  # On cbb.tools:
  sudo openssl pkey -in /var/lib/private/cbb-push/push.pem -pubout -out push-pub.pem

  # On the Mac:
  release-sign renew -push cbb.tools:8767=push-pub.pem
  ```

- **Rotating a forwarder, relay, or push service key** without a release:
  1. Generate the new server key beside the active key on `cbb.tools` and export its public key
     (`openssl pkey -in relay.pem -pubout -out relay-2.pem`; OpenSSL skips the WireGuard block of
     a relay key file).
  2. Add the new pin alongside the old pin on your Mac:
     `release-sign renew -relay cbb.tools:8765=relay-2.pem` (or `-forwarder cbb.tools:8764=...` or
     `-push cbb.tools:8767=...`).
  3. Wait for `dl.cbb.tools` and the `channel` branch to serve the new `keys.json` and allow a few
     days for devices to fetch it.
  4. Switch the server to the new key file and restart the service.
  5. After a few more days, remove the old pin with `release-sign renew -drop <old-pin>`.
     `keys.json` holds at most 64 key entries (`maxKeys` in `internal/release/release.go`), so drop
     retired keys before adding more.

### Renewal reminders and key compromise

- **Renewal reminders**: `.github/workflows/channel.yml` runs `release-sign due channel` daily and
  opens the issue **Release channel: renewal due** when:
  - `keys.json` expires within **21 days** (run `release-sign renew -new-keys` on your Mac with a
    YubiKey);
  - `stable.json` expires within **5 days** (check `cbb-channel.timer` on `cbb.tools`, or run
    `release-sign renew` on your Mac);
  - `entries.json` expires within **10 days** (check `cbb-channel.timer` on `cbb.tools`, or run
    `release-sign entries` on your Mac).
- **Lost or stolen Mac**: sign a new `keys.json` with a YubiKey root key certifying a new release
  key and dropping the old one (`-drop NAME`).
- **Lost YubiKey**: sign with the second YubiKey root key and pin a replacement second root in the
  next release.
- **Compromised channel key**: generate a new key on `cbb.tools`, copy its public PEM to your Mac,
  and run `release-sign renew -drop cbb.tools -channel cbb.tools-2=channel.pem`.

### The status key

`cbb-attest.service` on `cbb.tools` mirrors Google's Android key-attestation revocation list as
`attest-status.json` ([Protocol](../protocol.md), section 17, "Revoked attestations"). The status
key signs only `attest-status.json`, limiting compromise impact to serving a stale revocation list
until the key is dropped from `keys.json`.

Generate the key in `/etc/cbb-attest/`, readable only by root, with its post-quantum half stored as
a systemd encrypted credential:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out /etc/cbb-attest/status-key.pem
release-sign pq-new -key file:/etc/cbb-attest/status-key.pem -out - -public /etc/cbb-attest/status.pem | \
  systemd-creds encrypt --name=status-pq.pem - /etc/cbb-attest/status-pq.cred
```

Certify both halves in `keys.json` with `-status mirror=status.pem`. A daily systemd timer
(`site/deploy/cbb-attest.service` and `site/deploy/cbb-attest.timer`, 04:00 UTC, running as user
`cbb-attest`) runs `/usr/local/bin/attest-status` (valid for 8 days) into `/srv/cbb.tools/attest`
and copies `keys.json` beside it from `/srv/cbb.tools/channel`. If Google's list removes a
previously revoked serial number, `attest-status` stops safely; verify Google's list and run
`attest-status` once with `-allow-drop`.

### TPM makers' certificates

`internal/attest/tpmroots/roots.pem` lists the root and intermediate CA certificates trusted for
TPM endorsement key (EK) attestation ([Protocol](../protocol.md), section 17, "TPM evidence").
Before each release:

1. Download Microsoft's `TrustedTpm.cab` (URL in `internal/attest/tpmroots/README.md`).
2. Verify its Authenticode signature.
3. Extract the root and intermediate certificates as PEM into `internal/attest/tpmroots/roots.pem`.
4. Review the diff for added or removed manufacturers and record the source date in
   `internal/attest/tpmroots/README.md`.

### Two signatures

Every release signing key has an ECDSA P-256 half and an SLH-DSA-SHA2-128s half, and every signed
release file carries signatures from both ([Protocol](../protocol.md), section 16, "Two
signatures"). Devices accept a file only when both signatures verify under the two halves of the
same named key.

Because YubiKeys and the Mac Secure Enclave do not support SLH-DSA, each hardware key's
post-quantum half is sealed in two layers (`tools/release-sign/seal.go`):

1. Symmetric encryption under the maintainer's passphrase (`scrypt` + `XChaCha20-Poly1305`), which
   protects a copied file even against an adversary who breaks P-256.
2. `age` encryption to a P-256 key stored in the same hardware (a second retired PIV slot on the
   YubiKey, or the Mac Secure Enclave), which requires the hardware for every decryption.

Keep the encrypted files only on the Mac's encrypted disk and encrypted backup image—never in a
repository, message, or unencrypted cloud folder. `release-sign` prompts for the passphrase once
per run on `/dev/tty` (never via flag or environment variable, never logged), decrypts the
post-quantum half for each signature, and clears it from memory immediately afterward. The hardware
prompts twice per signed file: once for the P-256 signature and once to unwrap the post-quantum
half.

Every pinned root in `internal/release/roots/roots.pem` carries both halves (`root-1` and `root-2`).
Three checks enforce completeness: `release-sign publish` checks `release.CompleteRoots`,
`release.yml`'s `roots` job runs `TestPinnedRootsComplete` before building, and `publish` verifies
every signed output under the pinned roots.

Every signing key in `keys.json` pairs one P-256 half and one SLH-DSA half under one `(name, use)`.
Readers reject duplicate algorithms under the same `(name, use)` (except server TLS pins for
forwarders, relays, and push services). `release-sign` refuses reusing an existing key name, and
`-drop` with either half's pin drops both halves of a signing key.

#### Hardware post-quantum halves (Mac)

1. Install tools on the Mac:

   ```sh
   brew install age age-plugin-yubikey age-plugin-se
   ```

2. Choose one strong passphrase shared across all hardware halves (at least 5 random words, 24
   characters, and 10 distinct characters; `pq-new` enforces length, word count, and character
   diversity). The first `pq-new` run prompts twice and writes `passphrase.check` in
   `~/.config/cbb-release/pq` (`CBB_RELEASE_PQ_DIR`) so later runs catch typos before touching the
   hardware. Store the passphrase in a password manager and on paper with your offline backup:
   `passphrase.check` is not hardware-wrapped (allowing offline scrypt guesses at ~1 s each), and
   losing the passphrase makes every hardware post-quantum half unrecoverable. If `passphrase.check`
   is missing beside existing `.age` files, restore it from backup before running `release-sign`.
3. Create an `age` key in an empty retired PIV slot on each YubiKey (for example slot 3 = PIV `84`,
   leaving `82` and `83` untouched):

   ```sh
   age-plugin-yubikey --generate --slot 3 --pin-policy always --touch-policy always > yubikey-K.identity
   ```

   Note the printed recipient (`age1yubikey1...`). The identity file points to the YubiKey and holds
   no secret key material.
4. Create the Mac Secure Enclave `age` key once:

   ```sh
   age-plugin-se keygen --access-control any-biometry -o release-se.identity
   ```

   Note the printed recipient (`age1se1...`).
5. Generate and verify each hardware key's post-quantum half (`piv:82` for a root, `piv:83` for a
   YubiKey release key, or `se:~/.config/cbb-release/release.se` for the Mac release key):

   ```sh
   release-sign pq-new -key piv:82 -to age1yubikey1... -identity yubikey-K.identity -name root-K -public root-K-public.pem
   release-sign pq-check -key piv:82 -public root-K-public.pem
   ```

   `pq-new` stores `HASH.age`, `HASH.identity`, and `HASH.pub` in `~/.config/cbb-release/pq` and
   test-decrypts the half once. `pq-check` signs a test body with both halves and prints
   `both halves sign, and the signatures check out under root-K-public.pem`.
6. Back up `~/.config/cbb-release/pq`, the `.identity` files, and the `.pub`/public PEM files in an
   AES-256 encrypted disk image (`pq-keys.dmg`) with an off-site copy. A lost YubiKey permanently
   loses its sealed halves; replace it by signing a new `keys.json` with the remaining root and
   pinning a new second root in the next release.

#### Server post-quantum halves (`cbb.tools`)

Server keys (the channel key and status key) have no interactive passphrase; systemd encrypts their
post-quantum halves to the server host key with `systemd-creds`:

```sh
release-sign pq-new -key file:/etc/cbb-channel/channel-key.pem -out - -public /etc/cbb-channel/channel.pem | \
  systemd-creds encrypt --name=channel-pq.pem - /etc/cbb-channel/channel-pq.cred
```

(`-out -` writes only into a pipe; `-out FILE` creates a mode-`0600` file.) Verify the pair as the
systemd unit reads it (never via a pipe, because `pq-check` opens the half twice):

```sh
systemd-run --pipe --wait \
  -p LoadCredential=channel-key.pem:/etc/cbb-channel/channel-key.pem \
  -p LoadCredentialEncrypted=channel-pq.pem:/etc/cbb-channel/channel-pq.cred \
  /bin/sh -c 'exec release-sign pq-check -key "file:$CREDENTIALS_DIRECTORY/channel-key.pem+slh:$CREDENTIALS_DIRECTORY/channel-pq.pem" -public /etc/cbb-channel/channel.pem'
```

Install `site/deploy/cbb-channel.service`, `site/deploy/cbb-attest.service`, and their `.timer`
units in `/etc/systemd/system/` and run `systemctl daemon-reload`. Verify encrypted credential
loading with `systemctl cat cbb-attest.service | grep LoadCredentialEncrypted`, and confirm hybrid
signatures on served JSON with `jq -c '[.sigs[].alg]'` (expected output: `[1,4]`).

## Watching cbb.tools

Updates, the attestation revocation mirror, the forwarder, and the open blind relay depend on
`cbb.tools`. [`.github/workflows/monitor.yml`](../../.github/workflows/monitor.yml) runs
`go run ./tools/monitor` every six hours from GitHub Actions and fails—notifying the maintainer by
email—when any check fails:

- `https://cbb.tools/` or `https://dl.cbb.tools/` fails over HTTPS, or its TLS certificate expires
  within 14 days (nginx's built-in ACME module in `site/deploy/nginx.conf` renews certificates
  automatically; check `/var/log/nginx/error.log` and reload nginx if renewal stalled).
- The forwarder (`cbb.tools:8764`) or open blind relay (`cbb.tools:8765`) refuses a TCP connection
  (UDP cannot be probed externally without group keys).
- A served signed file approaches expiry: `cbb.tools/channel/keys.json` or `dl.cbb.tools/keys.json`
  within **21 days** (run `release-sign renew -new-keys` or check `cbb-mirror.timer`),
  `cbb.tools/channel/stable.json` or `dl.cbb.tools/stable.json` within **5 days** (check
  `cbb-channel.timer` or `cbb-mirror.timer`), or `cbb.tools/attest/attest-status.json` within
  **5 days** (check `cbb-attest.timer`).
- Rolling 24-hour traffic in `https://cbb.tools/status/traffic.json` exceeds 1 TB (half the
  hosting plan's 2 TB throttle threshold) or the file is older than 2 hours (`cbb-traffic.timer`
  stopped). See [The servers' budget: money and traffic](../relay-budget.md#money-and-traffic) for
  the response order.

Pass `-require-files` to `tools/monitor` in `monitor.yml` once signed release files and
`traffic.json` are served, so HTTP 404 responses fail the check instead of passing. Server rebuild
procedures, configuration backups, and user communication templates live in the maintainer's
private runbook outside the repository.

### An abuse report

Handle abuse reports sent to `abuse@cbb.tools` as defined in
[The servers' budget: abuse reports](../relay-budget.md#abuse-reports):

1. If the report is a security vulnerability rather than server abuse, follow
   [SECURITY.md](../../SECURITY.md) instead.
2. If the report does not include a group tag or period tag, reply that the servers keep no logs,
   IP addresses, or clipboard content and request the group tag (16 hex characters from `cbb status`)
   or period tag (`period TAG`, 32 hex characters).
3. When the report includes a valid tag, append it with the date to `refused-groups` beside the
   forwarder and relay keys on `cbb.tools`:

   ```sh
   echo "TAG  # YYYY-MM-DD, report of DATE" | sudo tee -a /var/lib/cbb-forward/refused-groups
   echo "TAG  # YYYY-MM-DD, report of DATE" | sudo tee -a /var/lib/cbb-relay/refused-groups
   ```

   Both services reload the file within 10 seconds and drop active registrations for the tag. An
   invalid line keeps the previous list active and logs a warning (`journalctl -u cbb-forward`,
   `journalctl -u cbb-relay`). Removing the line admits the group again immediately.
4. Reply to the reporter confirming the group is refused and noting that the servers hold no logs,
   addresses, or content.
5. For deliberate traffic floods against the servers, block the offending source at the firewall,
   network, or hosting-provider level per the service terms.

## Ways out carry only cbb

The forwarder, VLESS over XHTTP, the blind relay, and the release mirror on `cbb.tools` must never
act as a general-purpose proxy to arbitrary destinations:

- The forwarder relays only WireGuard packets between a registered hub and its clients.
- VLESS routes every outbound connection only to the forwarder, its registration listener, or the
  local release mirror, ignoring the client's requested destination.
- A hub's in-process network stack opens only the member port and forwards nothing else.

Automated tests verify these invariants by dialing arbitrary TCP/UDP IPv4, IPv6, hostname, and
loopback targets and asserting failure:

- VLESS over XHTTP: `internal/vless/onlycbb_test.go`.
- Hub tunnel: `internal/tunnel/onlycbb_test.go` and `member/src/hub.rs`
  (`a_client_reaches_only_the_member_listener`).
- Blind relay: `member/src/nettest/relayd.rs` (`a_dial_reaches_no_address`).
- `cbb` tunnel: `member/src/tunnel.rs` (`link_reaches_nothing_from_the_tunnel`).
- Forwarder packet routing: `internal/forward` (`FuzzForwardWire`).

After any server configuration change on `cbb.tools`, run this read-only audit and record the
output in the private runbook:

1. Verify kernel forwarding and NAT are off and no tunnel interfaces exist:
   - `sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` both return `0`.
   - `iptables -S` and `ip6tables -S` show `FORWARD DROP`.
   - `iptables -t nat -S` and `ip6tables -t nat -S` have no rules.
   - `ip -br link` shows no `wg` or `tun` interface.
2. Verify every `proxy_pass` in `/etc/nginx` targets loopback only, and no `stream` block exists.
3. Verify `cbb-forward` runs without `-vless-mirror`, or points `-vless-mirror` only at the loopback
   `dl.cbb.tools` server serving `/*.json` and `/vX.Y.Z/*` (404 for all other paths).
4. Verify no unexpected proxy or subscription service listens on any public address beyond the
   ports permitted in `ufw status`.

## Homebrew

The Homebrew tap lives at [HunterEwok/homebrew-tap](https://github.com/HunterEwok/homebrew-tap)
with formula `Formula/cbb.rb` (`brew install hunterewok/tap/cbb`). After each stable release
publication (not pre-releases), `.github/workflows/published.yml` verifies the published release
files under the pinned roots, generates `Formula/cbb.rb` with `packaging/homebrew/formula.sh` from
`SHA256SUMS`, and pushes it to the tap's `main` branch. CI's `buildmac` job verifies formula
installation on every pull request.

One-time setup:

- [x] Create public repository `HunterEwok/homebrew-tap` (empty).
- [x] Generate an SSH key pair: `ssh-keygen -t ed25519 -N '' -C homebrew-tap -f homebrew-tap`.
- [x] Add `homebrew-tap.pub` to `HunterEwok/homebrew-tap` under **Settings → Deploy keys → Add
  deploy key** with **Allow write access**.
- [ ] Store the private key (`homebrew-tap`) in the `release` environment as
  `CBB_HOMEBREW_TAP_KEY`, then delete both local key files (a lost key is replaced by generating a
  new pair).

To verify the deploy key without a release, trigger **Actions → published → Run workflow** from
`main`; the `homebrew` job runs `git push --dry-run` against the tap. Without
`CBB_HOMEBREW_TAP_KEY`, the release still succeeds with a warning; you can update the tap manually
by running `sh packaging/homebrew/formula.sh vX.Y.Z SHA256SUMS` and committing `Formula/cbb.rb`.

## winget

The package `HunterEwok.cbb` installs the Windows release zip as winget's portable `cbb` command
(users then run `cbb install` in an administrator terminal). For each non-prerelease tag, the
`release-files` job in `.github/workflows/release.yml` runs `packaging/winget/manifest.sh` against
`SHA256SUMS` and packages the three YAML manifests into `winget-manifest.zip`, which the `release`
job attaches to the draft release. CI's `packaging` job checks `manifest.sh` on every pull request.

After each stable release, submit the manifest to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) from a Windows PC:

1. Unpack `winget-manifest.zip` into a local folder.
2. Validate and test-install the manifest:

   ```powershell
   winget validate --manifest <folder>
   winget install --manifest <folder>
   ```

3. Submit the pull request (`manifests/h/HunterEwok/cbb/<version>`):

   ```powershell
   wingetcreate submit <folder>
   ```

## The OpenWrt feed

The `openwrt-feed` job in `.github/workflows/release.yml` wraps each Linux release archive into a
`noarch` apk package for OpenWrt 25.12 and later (`packaging/openwrt/feed.sh`, run inside the
pinned `alpine:3.23` image because OpenWrt's own `apk` omits `mkpkg` and `mkndx`), creates one feed
per Go architecture, signs each `packages.adb` index with an ECDSA P-256 key, and attaches
`openwrt-feed.tar.gz` (`<arch>/packages.adb`, `<arch>/cbb-<version>.apk`, and public key `cbb.pem`)
to the release. CI's `OpenWrt` job builds, installs, and removes a feed signed with a test key on
every pull request.

One-time setup:

- [ ] Generate the feed key: `openssl ecparam -name prime256v1 -genkey -noout -out feed.pem`.
- [ ] Store `feed.pem` in the `release` environment as `CBB_OPENWRT_FEED_KEY` and keep an encrypted
  offline backup (rotating the key requires routers to fetch the new public key).

Publishing a feed after a release:

Because `CBB_OPENWRT_FEED_KEY` lives in CI, deploy `openwrt-feed.tar.gz` only from a published,
offline-signed release—never from a draft:

1. Download the published release files and verify them with `release-sign verify` under the pinned
   roots (using `keys.json` and `stable.json` from the `channel` branch, or `keys.json` with
   `-pinned` for a pre-release).
2. Unpack the verified `openwrt-feed.tar.gz` into the site's `openwrt/` directory on `cbb.tools`
   (served at `https://cbb.tools/openwrt/<arch>/packages.adb`).

Without `CBB_OPENWRT_FEED_KEY`, the release still succeeds with a warning and omits the feed.

## The ZX Spectrum Next's files

The `zxnext` job in `.github/workflows/release.yml` extracts the ARMv6 `cbb` binary for the
Raspberry Pi Zero from `cbb-linux-armv6.tar.gz`, builds `.cbb` (`CBB`), its overlay (`CBB.OVL`),
its driver (`CBB.DRV`), and `CBBPI.GZ` with the SHA-256 hashes of the overlay, driver, and Pi `cbb`
embedded inside `CBB` (`make PI_CBB=...`, `apps/zxnext/pins.sh`, `ovl.sh`), and lays them out with
`packaging/zxnext/site.sh` into `cbb-zxnext.tar.gz`. The archive holds `zxnext/` with five files
(`CBB`, `CBB.OVL`, `CBB.DRV`, `cbb`, and `cbb.gz`) plus `LIST` (name, size, CRC-32, and SHA-256 per
file). All files must come from one build; `.cbb install` refuses files whose hashes do not match
those embedded in `CBB`.

`release-sign publish` signs the same list as `zxnext.json` ([Protocol](../protocol.md), section
16) and uploads it with the release. On every run, `release-sign mirror` writes `zxnext/SIGNED`
(the current `keys.json` followed by `zxnext.json`, one JSON object per line), which `.cbb update`
verifies on the attached Pi before accepting a newer `CBB`.

Because NextZXOS's `.http` and the ESP8266 do not support TLS, `site/deploy/nginx.conf` serves
`/zxnext` and `/zxnext/` over plain HTTP on port 80 while keeping the HTTPS redirect inside
`location /` (a server-level `return 301` would preempt the `/zxnext` locations):

```nginx
location = /zxnext { alias /srv/cbb.tools/zxnext/CBB; default_type application/octet-stream; }
location /zxnext/ { root /srv/cbb.tools; default_type application/octet-stream; }
```

`/srv/cbb.tools/zxnext` lives outside `www` so website deploys leave it untouched. Do not copy
files there manually: `cbb-mirror.timer` ([The mirror](#the-mirror)) unpacks verified releases
automatically. The initial `.http -h cbb.tools -u /zxnext -f CBB` download trusts the network;
`.cbb install` guards against download corruption, and `.cbb update` verifies signatures against
pinned roots ([Threat model](../threat-model.md)).

## The mirror

`https://dl.cbb.tools/` mirrors releases on `cbb.tools` using the layout in
[Protocol](../protocol.md), section 16, "Where the files are": `keys.json`, `stable.json`, and
`entries.json` at the root, and each release's files plus `release.json` under `vX.Y.Z/`.
`cbb update`, installers, the Android app, and small devices fall back to the mirror when GitHub is
unreachable; every client verifies signatures locally, so the mirror is untrusted.

An hourly systemd timer (`site/deploy/cbb-mirror.service` and `site/deploy/cbb-mirror.timer`, user
`cbb-mirror`, holding no keys) runs `release-sign mirror`. Each run:

1. Fetches `keys.json`, `stable.json`, and `entries.json` from the `channel` branch,
   `/srv/cbb.tools/channel`, and the mirror itself, keeping the newest verified files so the mirror
   never rolls back.
2. Downloads the release named in `stable.json` and recursively any older release referenced by
   `min_from`, verifies every file against `release.json`, moves verified directories into place,
   and updates the top-level JSON files last. Previously mirrored releases remain on disk for
   devices upgrading across `min_from` steps.
3. With `-zxnext /srv/cbb.tools/zxnext`, unpacks the newest verified `cbb-zxnext.tar.gz` (writing
   `LIST` last) and refreshes `zxnext/SIGNED`.

Because pre-releases are not listed in `stable.json`, mirror a pre-release manually after
`release-sign publish`:

```sh
sudo -u cbb-mirror release-sign mirror -out /srv/dl.cbb.tools -zxnext /srv/cbb.tools/zxnext -version X.Y.Z-rc.N
```

One-time setup on `cbb.tools`:

- [x] Create a DNS `A` record for `dl.cbb.tools` pointing to the server (DNS only).
- [x] Install `release-sign` (`GOOS=linux GOARCH=amd64 go build ./tools/release-sign`) at
  `/usr/local/bin/release-sign`, create the system user, and prepare directories:

  ```sh
  useradd --system --no-create-home --shell /usr/sbin/nologin cbb-mirror
  install -d -o cbb-mirror -g cbb-mirror -m 755 /srv/dl.cbb.tools /srv/cbb.tools/zxnext
  ```

- [x] Merge the `dl.cbb.tools` server blocks and `/zxnext` locations from `site/deploy/nginx.conf`
  into the live nginx configuration, verify with `nginx -t`, and run `systemctl reload nginx` (the
  ACME module obtains the certificate automatically).
- [x] Install `cbb-mirror.service` and `cbb-mirror.timer` in `/etc/systemd/system/`, run
  `systemctl daemon-reload`, and run `systemctl enable --now cbb-mirror.timer`. Verify with
  `systemctl start cbb-mirror` and `journalctl -u cbb-mirror`.

## Signing for Windows

When `CBB_WINDOWS_CERT_BASE64` and `CBB_WINDOWS_CERT_PASSWORD` are set in the `release`
environment, `.github/workflows/release.yml` signs all six Windows executables (`cbb.exe`,
`cbbw.exe`, `cbb-desktop.exe`, `cbb-helper.exe`, `cbb-forward.exe`, and `cbb-relay.exe`) with
Authenticode (`osslsigncode`, SHA-256, timestamped via `http://timestamp.digicert.com`). Without
these secrets, the binaries stay unsigned and SmartScreen warns on first launch. Once installed
binaries are signed, `cbb update` on Windows accepts only updates from the same signer.

One-time setup:

- [ ] Obtain an OV code-signing certificate exportable as PKCS#12 (`.pfx`).
- [ ] Add `CBB_WINDOWS_CERT_BASE64` (`base64 -w0 cert.pfx`) and `CBB_WINDOWS_CERT_PASSWORD` to the
  `release` environment.

To test signing without a release, trigger `release.yml` manually from `main` with an empty tag
input.

## Signing for macOS

### Command-line binaries

When `CBB_APPLE_DEVID_APP_P12`, `CBB_APPLE_DEVID_APP_PASSWORD`, and `CBB_ASC_*` are set in the
`release` environment, `.github/workflows/release.yml` signs `cbb` (`tools.cbb.cli`), `cbb-helper`
(`tools.cbb.helper`), `cbb-forward` (`tools.cbb.forward`), and `cbb-relay` (`tools.cbb.relay`) with
the **Developer ID Application** certificate and hardened runtime (`packaging/macos/sign.sh`), then
notarizes each binary with `notarytool` (`packaging/macos/notarize.sh`). Certificates live only in
a temporary per-step keychain (`packaging/macos/keychain.sh`). Without the secrets, binaries are
signed ad hoc. No binary carries entitlements (`sign.sh` rejects any signature with one). CI's
`buildmac` job signs pull request builds ad hoc with the same hardened-runtime flags and runs each
binary to verify startup.

### Mac app and `.pkg` installer

The `macos-app` job in `release.yml` combines the signed ARM64 and Intel slices of `cbb` and
`cbb-helper` with `lipo`, builds universal `CBB.app`, signs and notarizes `CBB.app`, packages both
with `packaging/macos/pkg.sh` signed by **Developer ID Installer** (`CBB_APPLE_DEVID_INSTALLER_P12`
and `CBB_APPLE_DEVID_INSTALLER_PASSWORD`), notarizes and staples `cbb-X.Y.Z.pkg`, and validates it
with `spctl --assess --type install`. Installing the `.pkg` copies `CBB.app` to `/Applications` and
runs `install.sh` non-interactively for the console user (preserving prior firewall and auto-update
answers). Without the secrets, the release omits `.pkg`. CI's `buildmac` job builds, installs, and
uninstalls an unsigned `.pkg` on every pull request.

The Mac app updates through the signed `.pkg`; planned Sparkle self-updates are tracked in
[Roadmap](../roadmap.md).

### iPhone app to TestFlight

The `testflight` job in `release.yml` (`apps/ios/testflight.sh`) archives the iPhone app with its
share extension, widgets, Apple Watch app, and notification service extension, signs all five
targets manually with **Apple Distribution** (`CBB_APPLE_DISTRIBUTION_P12`,
`CBB_APPLE_DISTRIBUTION_PASSWORD`) and their App Store provisioning profiles (`CBB_APPLE_PROFILES`,
a base64-encoded `.tar.gz` of the five `.mobileprovision` files matched by App ID), exports the
`.ipa`, and uploads it to App Store Connect using `CBB_ASC_*`. Its version is the numeric prefix of
the tag (for example `0.6.0` for `v0.6.0-rc.1`), and its build number is `GITHUB_RUN_NUMBER`. A
manual keys-check run from `main` builds and signs version `0.0.0` without uploading.

App Store Connect prompts for encryption export compliance on each uploaded build until
`ITSAppUsesNonExemptEncryption` is set in `Info.plist`. App Store provisioning profiles expire
annually: regenerate them in the Apple Developer portal and update `CBB_APPLE_PROFILES`.

### Apple Developer account inventory

Team `U2ZJ8F2JCJ` holds the following assets (all certificates generated on the maintainer's Mac
with dedicated keys via `openssl genrsa 2048` and CSRs—never Xcode automatic signing—and backed up
offline beside the other release keys):

- **Certificates**: Developer ID Application (binaries and `CBB.app`), Developer ID Installer
  (`.pkg`), Apple Distribution (TestFlight and App Store), and Apple Development (local testing on
  maintainer devices). Each `.p12` has its own password.
- **Identifiers**: App Groups `group.tools.cbb` and `group.tools.cbb.push`; App IDs `tools.cbb`
  (both App Groups, NFC Tag Reading, Push Notifications), `tools.cbb.share` (`group.tools.cbb`),
  `tools.cbb.widgets`, `tools.cbb.watchkitapp`, `tools.cbb.push` (`group.tools.cbb.push`), and
  `tools.cbb.mac`.
- **Provisioning profiles**: App Store profiles for the five iPhone App IDs (renewed yearly; edit,
  re-save, and re-download any profile after changing its App ID capabilities).
- **Keys**: App Store Connect API key (App Manager role) for CI, plus two APNs keys (Sandbox for
  development builds and Production for `cbb-push`).

Never revoke a Developer ID certificate when rotating it: revoking invalidates all previously
signed releases. Let the old certificate expire and sign future releases with the new one; existing
timestamped signatures remain valid.

To verify macOS signing and notarization without a release, trigger `release.yml` manually from
`main` with an empty tag input.

## Android signing key

The `android` job in `.github/workflows/release.yml` builds three signed APKs from the tag—the full
phone build (`cbb-X.Y.Z.apk`), the F-Droid build (`cbb-fdroid-X.Y.Z.apk`), and the Wear OS app
(`cbb-wear-X.Y.Z.apk`)—verifies all three with `apksigner verify --print-certs`, and generates
`sbom-android.cdx.json`. Android accepts app updates only when signed with the same key, so create
the keystore once and keep an encrypted offline backup permanently:

```sh
keytool -genkeypair -v -keystore cbb-release.jks -alias cbb \
  -keyalg EC -groupname secp256r1 -validity 36500 -dname "CN=cbb"
base64 -i cbb-release.jks | pbcopy   # macOS; Linux: base64 -w0 cbb-release.jks
```

Upload four secrets to the `release` environment:

- `CBB_ANDROID_KEYSTORE_BASE64`: base64-encoded keystore;
- `CBB_ANDROID_KEYSTORE_PASSWORD`: keystore password;
- `CBB_ANDROID_KEY_ALIAS`: `cbb`;
- `CBB_ANDROID_KEY_PASSWORD`: key password (same as keystore password for PKCS#12).

Without these secrets, the release omits all APKs. To test the key without a release, run
`release.yml` manually from `main` with an empty tag input; the job builds, signs, and verifies the
APKs as workflow artifacts without publishing.

## Firebase for push

The Android full build receives closed-app push notifications through Firebase Cloud Messaging
(FCM); the F-Droid build uses UnifiedPush and requires no Firebase configuration.

The Firebase project contains one Android app (`tools.cbb`) with Analytics disabled.
`apps/android/app/build.gradle.kts` reads four values from `release` environment secrets
(`CBB_FIREBASE_APP_ID`, `CBB_FIREBASE_PROJECT_ID`, `CBB_FIREBASE_API_KEY`, and
`CBB_FIREBASE_SENDER_ID`) or local Gradle properties (`-Pcbb.firebase.appId=...`, `projectId`,
`apiKey`, `senderId`), restricting the web API key to the Firebase Installations and Cloud Messaging
APIs and to `tools.cbb`'s signing certificate. Never commit `google-services.json`. Without these
values, the full build compiles normally without push support.

On `cbb.tools`, `cbb-push` sends FCM HTTP v1 requests using a service account restricted to the
*Firebase Cloud Messaging API Admin* role. Its JSON key resides at `/etc/cbb/push/fcm.json` (owned
by `root:root`, mode `0600`) and is injected via systemd credentials
(`packaging/linux/cbb-push.service`). To rotate the key:

1. Create a new JSON key for the service account in the Firebase console.
2. Replace `/etc/cbb/push/fcm.json` (mode `0600`) and run `sudo systemctl restart cbb-push`.
3. Delete the old key in the Firebase console.

## Signing for Aurora OS

Aurora OS installs an RPM only when signed with an Open Mobile Platform developer certificate
(profile `regular`, `CN=hunterewok`, GOST R 34.10-2012 key). Updates require the same certificate,
and uninstalling removes the app's OP-TEE key, so every build installed on a phone uses this
certificate.

CI's `Aurora app` jobs build unsigned RPMs. To build signed RPMs from any branch, run
[`.github/workflows/aurora.yml`](../../.github/workflows/aurora.yml) manually (**Actions → aurora →
Run workflow**) and approve the deployment in the **aurora** environment (which requires maintainer
review so arbitrary branches cannot access the key).

Upload the three secrets from `ci-keys.dmg` on the maintainer's Mac:

```sh
base64 -i hunterewok_key.pem | gh secret set CBB_AURORA_KEY_BASE64 -R HunterEwok/cbb --env aurora
base64 -i hunterewok_cert.pem | gh secret set CBB_AURORA_CERT_BASE64 -R HunterEwok/cbb --env aurora
gh secret set CBB_AURORA_KEY_PASSWORD -R HunterEwok/cbb --env aurora
```

`apps/silica/ci.sh` signs the RPMs inside the Platform SDK using `rpmsign-external` (passing the
passphrase via `KEY_PASSPHRASE`) and uploads `tools.cbb.aurora-X.Y.Z-1.armv7hl.rpm` and
`tools.cbb.aurora-X.Y.Z-1.aarch64.rpm` as workflow artifacts.

## F-Droid

F-Droid publishes the `fdroid` flavor ([App specification: F-Droid](../apps.md#f-droid)) using the
build recipe in `packaging/fdroid/tools.cbb.yml`, submitted to
[fdroiddata](https://gitlab.com/fdroid/fdroiddata) as `metadata/tools.cbb.yml`.

One-time submission steps:

1. Fill in `AllowedAPKSigningKeys` with the release certificate SHA-256 from
   `apksigner verify --print-certs cbb-fdroid-X.Y.Z.apk`, and confirm `ndk` matches `cbb.ndk` in
   `apps/android/gradle.properties`.
2. Verify reproducibility on F-Droid's buildserver image in a clone of `fdroiddata`:

   ```sh
   fdroid build -v -l tools.cbb
   ```

3. Open a merge request to `fdroiddata` adding `metadata/tools.cbb.yml`.

After acceptance, F-Droid's update check (`UpdateCheckData` reading
`apps/android/version.properties`) detects each new tag automatically and publishes the project's
signed `cbb-fdroid-X.Y.Z.apk` whenever F-Droid's build reproduces it bit for bit. CI's `fdroid`
job runs `packaging/fdroid/reproduce.sh` on pull requests to catch reproducibility regressions before
tagging.
