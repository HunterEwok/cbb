<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Your own build and your own keys

For anyone who builds Copy Beyond Borders from source: a distribution package, a fork with
changes, or a build for your own devices. [BRAND.md](../BRAND.md) says what a build with
changes may call itself; this page says what in the code ties a build to this project's
releases and how to tie it to your own.

## What ties a build to this project

Every build checks and installs updates from this project unless it is changed:

- **The release roots**: two public keys pinned in every program
  (`internal/release/roots/roots.pem`). An update installs only when its `keys.json` is
  signed by one of them ([protocol.md](protocol.md), section 16).
- **The addresses**: GitHub's releases of `HunterEwok/cbb`, their mirror
  `dl.cbb.tools`, and the branch `channel` with the current `keys.json` and `stable.json`.

So there are three cases.

1. **The source of a release, unchanged** (a distribution package, your own compile of a
   tag): nothing to change. The build checks and installs this project's signed releases,
   the same files the official build installs. A distribution package records itself with
   `cbb update -installed-by package`, and `cbb update` then leaves updating to the package
   manager.
2. **A build with changes that keeps this project's roots and addresses**: its first update
   replaces it with this project's release, and the changes are gone. Change the addresses
   and the roots as below, or turn updates off on its devices: `cbb update -installed-by
   package` and `cbb update -auto off`.
3. **A build with changes and releases of your own**: your own roots and addresses, below.

## Your own roots

Make two root keys as [maintaining.md](maintaining.md), "Signed releases", describes (on two
hardware keys, or in files for a build only you use), and replace:

- `internal/release/roots/roots.pem`, the pinned roots;
- their copies, which `internal/release/roots_test.go` (`TestRootCopies`) compares with it:
  `release_roots` in `packaging/get.sh`, the roots in `packaging/windows/get.ps1`, `ROOTS`
  in `member/src/update.rs`, `Releases.kt` in the Android kit and `Releases.swift` in the
  Swift kit;
- `internal/release/roots/attestation/` and `roots/release-keys.pem`, the proof that this
  project's keys live on YubiKeys: put your own keys' attestations there and change the
  serial numbers in `roots_test.go`, or, for keys without one, remove those files and
  `TestRootsAttested` and `TestReleaseKeysAttested`.

Then sign your releases with `tools/release-sign` and your keys as maintaining.md describes.

## Your own addresses

`internal/update/source.go` holds them for the Go program: `GitHub`, `Mirror` and
`ChannelFiles`, and the hosts `allowedHost` lets the updater reach. Their copies, which
`internal/update/project_test.go` (`TestProjectAddresses`) compares with them:

- `member/src/update.rs`: `GITHUB`, `MIRROR`, `CHANNEL_FILES`, and the hosts in `allowed`;
- `apps/android/app/.../ApkUpdate.kt`: `GITHUB`, `MIRROR`, `CHANNEL_FILES`, and its hosts;
- `packaging/get.sh` and `packaging/windows/get.ps1`: `repo`, `channel_files` and the
  `--repo` of `gh attestation verify`;
- `tools/release-sign/publish.go`: `defaultRepo`.

Not checked by the test, and to change by hand:

- `tools/release-sign/channel.go`: `renewedChannel`, where your server renews `stable.json`
  (or leave the channel key out and renew it with `release-sign renew`);
- the workflows: the image's name in `.github/workflows/release.yml` and `publish.go`'s
  `dockerRE`, the tap in `published.yml`, the issue's assignee in `channel.yml`;
- the links to the project's page in the apps' settings and in `packaging/`.

`go test ./internal/release ./internal/update` then tells whether a copy was left behind.

## The other servers

The forwarder and the blind relay hold no release keys and no project address: a group
uses the ones it is given ([running your own servers](admin/self-hosting.md)). Their own
keys are made on their first start.
