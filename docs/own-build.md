<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Your own build and your own keys

For anyone building Connect Beyond Borders from source: distribution package maintainers, fork
maintainers, or users building for their own devices. For trademark and naming rules for modified
builds, see [BRAND.md](../BRAND.md). This guide explains what ties a build to this project's
releases, how to replace the release keys and update addresses with your own, and how to verify a
reproducible release build.

## What ties a build to this project

Unless modified, every build checks for and installs updates published by this project using two
sets of built-in values:

- **Pinned release roots**: Two hybrid root keys (`root-1` and `root-2`, each with an ECDSA P-256
  half and an SLH-DSA-SHA2-128s half) stored in `internal/release/roots/roots.pem`. Updaters accept
  an update only when `keys.json` verifies under both halves of a pinned root
  ([protocol.md](protocol.md), section 16).
- **Update addresses**: GitHub Releases for `HunterEwok/cbb`, the release mirror at
  `https://dl.cbb.tools`, and the `channel` branch (`keys.json` and `stable.json`).

Choose one of three paths depending on your build:

1. **Unmodified release source** (a distribution package or your own compile of a release tag):
   Change nothing. For a distribution package, run `cbb update -installed-by package` during
   packaging so `cbb update` delegates upgrades to the system package manager.
2. **Modified build without your own release server**: Disable self-updates on devices running the
   build by running `cbb update -installed-by package` and `cbb update -auto off`; otherwise the
   first update replaces your build with this project's release.
3. **Modified build with your own signed releases**: Replace the release roots and update addresses
   using the procedures below.

## Use your own release roots

1. Generate two hybrid release root keys (ECDSA P-256 and SLH-DSA-SHA2-128s under the same `Name`
   header, on hardware keys or in files for a private build) as described in
   [Maintaining](maintainers/maintaining.md) ("Signed releases").
2. Replace `internal/release/roots/roots.pem` with your root public keys. Both `internal/release`
   in Go and `core/src/release.rs` (`include_str!`, used by `cbb` and the phone kits through `ffi/`)
   read this file directly.
3. Update the copies embedded in the standalone installers, which `TestRootCopies` in
   `internal/release/roots_test.go` verifies against `roots.pem`:
   - `release_roots` in `packaging/get.sh`
   - The P-256 root keys in `packaging/windows/get.ps1`
4. Replace or remove the YubiKey attestation proofs in `internal/release/roots/attestation/` and
   `internal/release/roots/release-keys.pem`:
   - If your roots live on YubiKeys, place your attestation certificates there and update the serial
     numbers in `internal/release/roots_test.go`.
   - If your keys are not on YubiKeys, remove those files along with `TestRootsAttested` and
     `TestReleaseKeysAttested` in `internal/release/roots_test.go`.
5. Sign your releases with `tools/release-sign` as described in
   [Maintaining](maintainers/maintaining.md).

## Use your own update addresses

1. Update the primary constants in `member/src/update.rs`: `GITHUB`, `MIRROR`, and `CHANNEL_FILES`.
2. Update the copies checked against `member/src/update.rs` by `TestProjectAddresses` in
   `internal/release/project_test.go`:
   - `apps/android/app/src/main/kotlin/tools/cbb/ApkUpdate.kt`: `GITHUB`, `MIRROR`,
     `CHANNEL_FILES`, and `allowedHost` (which restricts redirect targets)
   - `packaging/get.sh`: `repo`, `channel_files`, and the `--repo` flag of `gh attestation verify`
   - `packaging/windows/get.ps1`: `$repo`, `$channelFiles`, and the `--repo` argument of
     `gh attestation verify`
   - `tools/release-sign/publish.go`: `defaultRepo`
3. Update the remaining project references not covered by `TestProjectAddresses`:
   - `tools/release-sign/channel.go`: `renewedChannel` (where your server renews `stable.json`, or
     renew manually with `release-sign renew`)
   - `.github/workflows/release.yml` and `dockerRE` in `tools/release-sign/publish.go`: container
     image name
   - `.github/workflows/published.yml`: Homebrew tap repository
   - `.github/workflows/channel.yml`: issue assignee
   - Project page links in app settings and `packaging/`
4. Run `go test ./internal/release` to verify that no root key or address copy was missed.

## Checking a release

`cbb` and `cbb-helper` build reproducibly: the same commit produces identical bytes regardless of
the source directory or Cargo cache path. To verify that a published Linux `amd64` release matches
its source tag:

1. Install the Go version pinned in `go.mod` and the stable Rust version recorded in the release
   workflow run log (named by the release's build provenance).
2. Clone the repository at the release tag and build both binaries:

   ```sh
   git clone https://github.com/HunterEwok/cbb && cd cbb && git checkout vX.Y.Z
   CBB_RELEASE_BUILD=1 CBB_VERSION=X.Y.Z CBB_SOURCE="$(git rev-parse HEAD)" sh packaging/build.sh linux/amd64
   go build -trimpath -ldflags "-s -w -X github.com/HunterEwok/cbb/internal/version.Version=vX.Y.Z" ./cmd/cbb-helper
   ```

3. Compare `target/x86_64-unknown-linux-musl/release/cbb` and `./cbb-helper` byte for byte against
   the binaries in the release archive.

Reproducibility relies on relative workspace paths, `--remap-path-prefix` to `/cargo` in
`packaging/build.sh`, locked dependency versions in `Cargo.lock` and `go.sum`, and `-trimpath` in
Go. The nightly workflow verifies reproducibility by building both programs twice in separate
directories with separate Cargo homes (`.github/reproducible.sh`).

## Forwarder and blind relay

The forwarder (`cbb forward`) and blind relay (`cbb relay`) embed no release keys or project
addresses; each group configures whichever servers it chooses
([Running your own servers](admin/self-hosting.md)). Each server generates its own identity key on
first start.
