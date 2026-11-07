# Maintaining

Settings and routines that live outside the repository files. Only the owner can change them;
a checked box means the setting is in place.

## Account

- [x] Two-factor authentication on the GitHub account, preferably with a passkey or a
  security key. This protects the repository more than any setting below.
- [ ] Optional: sign commits with an SSH key (`git config gpg.format ssh`) and add the key
  to GitHub as a signing key, so commits show as Verified.

## Repository settings

**Settings → General**

- [x] Features: Wiki and Projects off; Issues on.
- [x] Pull Requests: only **squash merging**; **Automatically delete head branches** on.
- [x] Releases: **release immutability** on.

**Settings → Moderation**

- Interaction limits are for a temporary cool-down only and are normally off.
- Conduct reports go to GitHub Support through **Report content**, as
  [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) says. A repository of a personal account has no
  option to send reports to the repository admins, and no email address is published.

**Settings → Advanced Security** (named Code security on some accounts)

- [x] **Private vulnerability reporting**. [SECURITY.md](../SECURITY.md) relies on it.
- [x] **Dependency graph**, **Dependabot alerts** and **Dependabot security updates**.
- [x] **Secret scanning** and **Push protection**.
- [ ] **CodeQL** default setup off: the workflows `.github/workflows/codeql.yml` (advanced
  setup) scan GitHub Actions, Go, Rust and Kotlin on every pull request, and
  `codeql-swift.yml` scans the iPhone app and its kit when `apps/ios` changes, weekly, by
  hand and before each release. GitHub rejects their results while the default setup is on.
  The default setup cannot build the Kotlin app and builds only the kit, not the iPhone app.

**Settings → Actions → General**

- [x] Workflow permissions: **Read repository contents and packages permissions**.
- [x] **Allow GitHub Actions to create and approve pull requests** off.
- [x] Fork pull request workflows: **Require approval for all external contributors**.

**Settings → Environments**

- [ ] Environment **release**, which holds every release secret (below, "Release secrets").
- [ ] Environment **aurora**, which holds the Aurora developer certificate (below, "Signing
  for Aurora OS"): required reviewer the maintainer, every branch allowed.

**Settings → Rules → Rulesets**

Branch ruleset **Production Branch Protection** (made from the GitHub template), active,
targeting the default branch:

- [x] Restrict deletions and block force pushes.
- [x] Require linear history.
- [x] Require a pull request before merging: 0 required approvals and **Require extra
  approval for unattributed changes** off, because a single maintainer cannot approve their
  own pull request; squash is the only merge method.
- [x] Require the status check `ci-ok` from the GitHub Actions app, with the branch up to date
  before merging. `ci-ok` is the last job of [the CI workflow](../.github/workflows/ci.yml)
  and passes only when every other job passed, so CI jobs can change without touching the
  ruleset.
- [x] Bypass list empty.

Tag ruleset **releases**, active, targeting `refs/tags/v*`:

- [x] Restrict updates and deletions, and block force pushes, so a release tag cannot be
  moved. Its bypass list stays empty.

Tag ruleset **release tags: create**, active, targeting `refs/tags/v*`:

- [ ] Restrict creations, with the role **Repository admin** in the bypass list (always
  allow): only the maintainer starts a release; an app or a token with write access cannot.
  It is a ruleset of its own so that the one above keeps an empty bypass list.

### Release secrets

The keys that sign release files are Actions secrets of the environment **release**
(**Settings → Environments → release**), never repository secrets: a repository secret
reaches any workflow on any branch, so anyone who may push a branch could read it. The
environment's **Deployment branches and tags** are *Selected branches and tags*: the tag
pattern `v*` and the branch `main`. The jobs that sign (`build`, `android` and
`openwrt-feed` in the release workflow, `homebrew` in the published workflow) name the
environment; a run by hand to check a key therefore starts from `main`. No required
reviewers: the release tag is the maintainer's decision already.

| Secret | What it is | Section |
| --- | --- | --- |
| `CBB_ANDROID_KEYSTORE_BASE64`, `CBB_ANDROID_KEYSTORE_PASSWORD`, `CBB_ANDROID_KEY_ALIAS`, `CBB_ANDROID_KEY_PASSWORD` | the Android release key | [Android signing key](#android-signing-key) |
| `CBB_WINDOWS_CERT_BASE64`, `CBB_WINDOWS_CERT_PASSWORD` | the Windows code signing certificate | [Signing for Windows](#signing-for-windows) |
| `CBB_APPLE_DEVID_APP_P12`, `CBB_APPLE_DEVID_APP_PASSWORD` | the Developer ID Application certificate and key | [Signing for macOS](#signing-for-macos) |
| `CBB_APPLE_DEVID_INSTALLER_P12`, `CBB_APPLE_DEVID_INSTALLER_PASSWORD` | the Developer ID Installer certificate and key, for the `.pkg` | [Signing for macOS](#signing-for-macos) |
| `CBB_APPLE_DISTRIBUTION_P12`, `CBB_APPLE_DISTRIBUTION_PASSWORD`, `CBB_APPLE_PROFILES` | the Apple Distribution certificate and the App Store profiles, for TestFlight | [Signing for macOS](#signing-for-macos) |
| `CBB_ASC_KEY`, `CBB_ASC_KEY_ID`, `CBB_ASC_ISSUER_ID` | the App Store Connect API key (role App Manager): notarization and TestFlight uploads | [Signing for macOS](#signing-for-macos) |
| `CBB_OPENWRT_FEED_KEY` | the OpenWrt feed's key | [The OpenWrt feed](#the-openwrt-feed) |
| `CBB_HOMEBREW_TAP_KEY` | the tap's deploy key | [Homebrew](#homebrew) |

GitHub never shows a secret again, so each key is made on the maintainer's Mac and kept
there with an offline backup (an encrypted drive or a password manager) before it goes into
the environment; a key that exists only in GitHub is lost with it. To put one in:
`gh secret set NAME --env release < file`, or **Settings → Environments → release → Add
environment secret**.

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every pull request and on
`main`:

- **check**: `gofmt`, `go mod tidy`, `go mod verify`, `go vet`, `staticcheck`,
  `govulncheck`, `actionlint` and zizmor (their security) for the workflows,
  [the repository rules](../tools/repocheck/main.go) (English only, apart from the apps'
  translations; license headers in Go and Rust files; copied code with its license; the documentation's
  links, the old name, the command reference with every flag, the environment variables,
  the ports, the index of the documentation), and the design
  tokens (`go run ./tools/tokens -check`);
- **test**: `go test -race` on Linux x86-64, Linux ARM64, macOS and Windows, each with its
  own files' coverage;
- **go coverage**: Go's tests across packages with `-coverpkg`, the desktop clipboards, the
  uinput keyboard, mDNS beside avahi and the e2e built with `-cover`;
- **coverage**: the coverage of every part that ran, in the run's summary, held to
  `tools/coverage/floor.json` ([testing](testing.md#coverage));
- **build**: a cgo-free build (`CGO_ENABLED=0`) for every Linux and Windows target, static
  on Linux, including ARMv6 for the Raspberry Pi Zero W; the macOS targets on macOS runners
  with cgo, for the pasteboard agent (see the Build section of [the design](design.md#build));
- **mdns with avahi**: the mDNS tests on real sockets, beside avahi-daemon, in a Debian
  container;
- **e2e**: the built binary as three members and an avahi browser in Docker containers:
  pairing, sync, mDNS as avahi sees it, a wrong code
  ([tools/e2e/e2e.sh](../tools/e2e/e2e.sh));
- **desktop clipboards**: the Wayland data-control client under a headless sway and the X11
  client under Xvfb, against wl-clipboard and xclip;
- **packaging**: shellcheck for the scripts, `systemd-analyze verify` and `security` for the
  unit, and the desktop entry;
- **homebrew**: the formula written by `packaging/homebrew/formula.sh`, installed with
  Homebrew on macOS;
- **windows installer**: `install.ps1`, the service, the agent and `uninstall.ps1` on
  windows-latest;
- **phone kit**: CBBKit's tests on Linux and macOS, and its cross tests with the Go
  code (pairing over plain TCP on Linux; pairing and a member connection over TLS on macOS);
- **iPhone app**: the Xcode project from XcodeGen, built and tested on an iPhone simulator
  without signing;
- **Android app**: the Kotlin kit's tests and its cross tests with the Go code, and the app
  built, unit-tested and linted;
- **lite member (Rust)**: `cargo fmt`, `clippy` and the tests of the Rust workspace, the ARM64 and
  ARMv6 builds, and the e2e test of the lite member among Go members;
- **lite core on the ESP32**: the lite protocol core with its TLS built for the ESP32-C6 (RISC-V) and the
  ESP32-S3 (Xtensa), and the Nano ESP32 firmware (`esp32/`) built, its console and
  flash settings tested and its self-test run in Espressif's QEMU (both downloaded by hash);
- **ZX Spectrum Next**: the tests of the `.cbb` frame parser on the host, and the dot commands `.cbb`
  and `.pibridge` built with z88dk (from its release source, checked by hash, cached);
- **ci-ok**: the summary that the ruleset requires.

Rules for workflows:

- Pin every action to a full commit SHA, with the version in a comment; Dependabot updates
  them.
- Set `permissions: contents: read` at the workflow level; grant more to a single job only
  when it needs it.
- Check out with `persist-credentials: false`.
- zizmor (CI's check job) looks for holes in the workflows; a finding that has to stay gets a
  `# zizmor: ignore[<audit>]` comment beside it that says why.
- Pull request workflows get no secrets.
- Tools such as `staticcheck`, `govulncheck` and `actionlint` are pinned in `go.mod` and run
  with `go tool`. Go records them as indirect requirements, so `.github/dependabot.yml` allows
  them by name; otherwise Dependabot would never update them.

## Releases

- Before the tag, a pull request moves the changes under `## [Unreleased]` in
  `CHANGELOG.md` to a new `## [X.Y.Z] - YYYY-MM-DD` section and updates the link
  references at the end of the file; the release notes are built from that section
  (`packaging/release-notes.sh`), which fails the release if it is missing.
  The same pull request sets `apps/android/version.properties` to `X.Y.Z` and its
  `versionCode` to `X*10000 + Y*100 + Z` (`tools/repocheck` asks for it), and adds the
  F-Droid changelog `apps/android/app/fastlane/metadata/android/en-US/changelogs/<versionCode>.txt`
  (500 characters at most); the release fails on a tag that differs from the file.
- Built by CI from a tag, never on a laptop: push a tag `vX.Y.Z` on main
  (`git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`), and
  `.github/workflows/release.yml` builds the archives, `SHA256SUMS` and the attestations and,
  once the iPhone app's CodeQL analysis passes on the tag (about 45 minutes),
  makes a draft release, with notes generated from the merged pull requests. The maintainer
  signs and publishes it on their Mac with `release-sign publish` ("Signed releases" below).
  A tag `vX.Y.Z-rc.N` makes a pre-release, which `releases/latest` and so `get.sh` skip;
  it needs no pull request first: its notes take CHANGELOG's *Unreleased*, and the Android apps
  take the tag's version.
- The archives are `cbb-<os>-<arch>.tar.gz` without the version, so that
  `releases/latest/download/` has fixed names for `get.sh`; each holds `cbb/` with the
  binary, `LICENSE`, `THIRD_PARTY_NOTICES` (the licenses of the Go modules, the copied code
  and Go itself, written by `packaging/archive.sh`) and `packaging/`. The
  `cbb-lite-linux-*` archives hold `cbb-lite/` in the same way (`member/packaging/archive.sh`), with the crates'
  licenses (`member/packaging/notices.sh`), the same Linux installer and the lite member's unit.
- Published with `SHA256SUMS` and a build provenance attestation
  (`actions/attest-build-provenance`), which users can check with `gh attestation verify`.
- What a release is built from: a software bill of materials in CycloneDX 1.6 JSON for each
  part, made by `tools/sbom` and listed in `SHA256SUMS` and the signed `release.json` like the
  other files:
  - `sbom-go.cdx.json`: the Go modules of every program in the archives (`cbb` and the tray
    app), read from the programs' own build information, and Go's standard library;
  - `sbom-lite.cdx.json`: the crates the lite member is built with on its targets, without the
    ones only tests and build scripts use, with their checksums from `Cargo.lock`;
  - `sbom-phone-core.cdx.json`: the same for the Rust core both phone apps link (`ffi/`);
  - `sbom-ios-kit.cdx.json`: the Swift packages of the iPhone kit (`Package.resolved`);
  - `sbom-android.cdx.json`: the Maven modules of the Android app's two builds and the Wear OS
    app, listed by `packaging/sbom.init.gradle.kts`, an init script that leaves the apps' build
    files as they are.

  The Docker image carries its own as a GitHub attestation in the registry
  (`actions/attest-sbom`), not as buildx's, which would add a platform "unknown" to the index.
  The same input makes the same file (no time; a serial number derived from the content).
  CI's `packaging` and `Android app` jobs make them on every change, as the release does.
- After the draft, the `docker` job builds the image of `packaging/docker` from the
  release's own Linux archives for amd64, arm64 and armv7, pushes it to
  `ghcr.io/hunterewok/cbb` as `X.Y.Z` (and `latest`, but not for a pre-release),
  attests it in the registry and adds its digest to the release notes. The first push makes
  the package private: once, in the package's settings on GitHub, make it public.

## Signed releases

The release files of docs/protocol.md, section 16, are made with `tools/release-sign` on
the maintainer's Mac; the keys never reach CI. The roots were made on 2026-10-28
(`internal/release/roots`, with their attestations); releases from 0.6 on are signed.

- **The root keys**, once: one on each of two YubiKeys, kept apart, with a PIN and touch
  for every signature. The YubiKeys may be in daily use for other things: the root goes
  into a free retired PIV slot (82 when `ykman piv keys info 82` finds no key), and nothing
  else on the key is reset or changed. `ykman piv keys generate --algorithm ECCP256
  --pin-policy ALWAYS --touch-policy ALWAYS 82 root-N.pem`, then `ykman piv certificates
  generate --subject "CN=Copy Beyond Borders release signing root N (2026)" 82 root-N.pem` so
  the key can be read from the slot, and `ykman piv keys attest 82` with the `f9`
  certificate as proof that the key was made on the YubiKey.
  Their public keys go into `packaging/get.sh` (`release_roots`), `packaging/windows/get.ps1`
  (`$releaseRoots`) and the programs (`internal/release.Roots`, the lite member's
  `update::ROOTS` in `member/src/update.rs`, and the phone kits' `Releases.roots`, which
  also turn on the Android app's own update).
- **The release key**, in the Mac's Secure Enclave, asking for Touch ID at each signature:
  `swift tools/release-sign/se.swift create ~/.config/cbb-release/release.se`. A root
  certifies it in `keys.json`, which lives 90 days.
- **The branch `channel`** holds the current `keys.json` and `stable.json`
  (docs/protocol.md, section 16, "Where the files are"), since a published release takes no
  new files. `release-sign publish` makes it with the first signed release, and only
  `release-sign` and the `channel` workflow write to it.
- **The channel key**, once, on cbb.tools beside the status key, readable only by root:
  `openssl ecparam -name prime256v1 -genkey -noout -out /etc/cbb-channel/channel-key.pem`
  and its public key `openssl ec -in channel-key.pem -pubout -out channel.pem`, copied to the
  Mac. The first `release-sign publish` certifies it with `-channel cbb.tools=channel.pem`;
  later ones keep it. A weekly systemd timer on cbb.tools
  (`site/deploy/cbb-channel.service` and `.timer`, as the user `cbb-channel`, which gets the
  root-only key as a credential for the run) runs `release-sign extend -key
  file:channel-key.pem -out /srv/cbb.tools/channel`, which reads the
  branch, checks it, signs `stable.json` again for 30 days with the same release and a
  higher number, and serves it with `keys.json` at `https://cbb.tools/channel/` (build it
  with `GOOS=linux GOARCH=amd64 go build ./tools/release-sign`). The daily `channel`
  workflow (`.github/workflows/channel.yml`) takes it into the branch with `release-sign
  take`, which refuses one that does not check out, names another release or is not newer.
  GitHub holds no key and cbb.tools no GitHub token.
- **Each release**: once the release workflow has made the draft (its `docker` job adds the
  image's digest to the notes), `release-sign publish -version X.Y.Z [-min-from X.Y.Z]` on
  the Mac, with `gh` signed in. It downloads the draft's files, checks each one's build
  attestation against the tag (`gh attestation verify --source-ref refs/tags/vX.Y.Z`), keeps
  the branch's `keys.json` when it is valid for 45 more days and certifies the release key
  and the keys asked for (otherwise a root signs a new one, numbered above it, with the same
  keys: the YubiKey's PIN and a touch), signs `release.json` and `stable.json` (numbered
  above the branch's) with the release key (Touch ID for each), checks all of it under the
  pinned roots as a device would, uploads `release.json` to the draft and, after a yes,
  publishes it and commits `keys.json` and `stable.json` to the branch. `-no-publish` stops
  before publishing, `-docker none` signs a release without the image; a pre-release
  changes no `stable.json`. `published.yml` then checks what GitHub serves and updates the
  Homebrew tap. The steps by hand: `release-sign manifest`, `sign`, `channel`, `keys` and
  `verify` (the comment in `tools/release-sign/main.go`).
- **The entry points** (docs/protocol.md, section 16, "Entry points"): the ways in to the
  project's servers that are not built in. On the Mac, in a checkout of the branch `channel`,
  `release-sign entries -key se:~/.config/cbb-release/release.se -in in.json channel`, where
  `in.json` is `{"forwarders": [{"name": "cbb.tools:8764", "vless": [{"transport": "xhttp",
  "server_name": "cbb.tools", "port": 443, "path": "/banMEJvnYJJap8S"}]}]}`, signs
  `entries.json` numbered above the branch's, valid for 30 days (`-days`, at most 100), and
  checks it under the pinned roots; commit and push it. From then on `release-sign extend`
  on cbb.tools signs it again with the channel key, the same forwarders and a higher number,
  `take` brings that into the branch only when it names the same forwarders, `due` reminds
  when it runs out, and `mirror` serves the newest copy that checks out. A blocked way in is
  replaced by signing a new list with another `in.json`, without a release. `in.json` may
  also name where the project's relay is reached, `"relays": [{"name": "cbb.tools:8765",
  "endpoints": ["relay.cbb.tools:8765"]}]` (no `endpoints`: its name), for moving it to
  another server; the devices on it follow at their next failed registration.
- **A new key for the project's forwarder or relay**, without a release: make the new key
  file beside the running one, take its public key (`openssl pkey -in relay.pem -pubout -out
  relay-2.pem`; the WireGuard block of a relay's file is skipped), and on the Mac
  `release-sign renew -relay cbb.tools:8765=relay-2.pem` (`-forwarder cbb.tools:8764=...` for
  the forwarder), which keeps the old key listed. Wait until the mirror and the branch serve
  the new `keys.json` and a few days for the devices to get it (`cbb update` once a day, the
  group, and a device that fails at the relay fetches it from the mirror itself), then switch
  the server to the new key file. After a few more days drop the old one: `release-sign renew
  -drop <the old pin>`. `keys.json` holds at most 8 keys in all, so drop old ones before
  adding more.
- **Reminders**: the `channel` workflow opens the issue "Release channel: renewal due" when
  the branch's `keys.json` expires within 21 days (run `release-sign renew -new-keys` on the
  Mac with a YubiKey) or its `stable.json` within 10, which means cbb.tools stopped renewing
  it (check its timer, or run `release-sign renew`, which signs it with the release key).
- A lost or stolen Mac: a root signs a `keys.json` with a new release key and without the
  old one. A lost YubiKey: the other root signs, and the next release ships a new second root.
  A stolen channel key: a new one on cbb.tools, and `release-sign renew -drop cbb.tools
  -channel cbb.tools-2=channel.pem` (`-drop NAME` drops any key by its name in `keys.json`).
- **The status key** of the revocation mirror, on cbb.tools in a file readable only by the
  mirror's user (it signs nothing but `attest-status.json`, so a stolen one can at most keep
  a revoked phone proven until it is replaced): `openssl ecparam -name prime256v1 -genkey
  -noout -out status-key.pem`. `keys.json` certifies it with `-status mirror=status.pem`. A
  daily timer runs `attest-status -key status-key.pem -out /srv/cbb.tools/attest` and copies
  `keys.json` beside it from `/srv/cbb.tools/channel`. When it stops on a list that drops a serial number, check Google's
  list and run it once with `-allow-drop`; a stolen status key is dropped from the next
  `keys.json` like a release key.
- **The TPM makers' certificates** in `internal/attest/tpmroots/roots.pem`, which decide
  whose TPMs prove their keys (docs/protocol.md, section 17, "TPM evidence"): before a
  release, download Microsoft's TrustedTpm.cab (its README says where), check its
  Authenticode signature, extract the root and intermediate certificates as PEM, review the
  diff (a maker added or gone) and note the date in the README.
- `release-sign drill -version X.Y.Z DIR ROOTS.pem` signs DIR with throwaway keys in files,
  as CI does to test the installers, and for drills of the steps above.

## Watching cbb.tools

Updates, the revocation mirror, the forwarder and the relay all depend on `cbb.tools`, and a
stopped timer there stops everyone's updates without a sound. The `monitor` workflow runs
`go run ./tools/monitor` every six hours from GitHub and fails, which mails the maintainer,
when:

- `https://cbb.tools/` or `https://dl.cbb.tools/` does not answer over HTTPS, or a
  certificate expires within 14 days (renew it with certbot on the server);
- the forwarder's port (TCP 8764) or the project's relay's (TCP 8765) refuses a
  connection; UDP cannot be checked from outside without a group's keys;
- a signed file the devices fetch is close to its expiry: the channel's `keys.json` (21
  days: `release-sign renew -new-keys`) and `stable.json` (10 days: the `cbb-channel` timer
  stopped), the same two at `dl.cbb.tools`, and `attest/attest-status.json` (5 days: the
  `attest-status` timer stopped).

Before the first signed release these files are not served, which the check reports and
passes; from v0.6.0 on the workflow runs it with `-require-files`. The steps to rebuild the
server, where the backup of its configuration is and what to tell users are in the
maintainer's private runbook, outside the repository.

## Ways out carry only cbb

The forwarder, VLESS, the relay and the mirror on cbb.tools must never take a user anywhere
but cbb (docs/roadmap.md, item 61). The code holds this without any rule on the server;
the server must not add a way around it. After each change on the server, run this check,
reading only, and keep its result in the private runbook:

- `sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding` both 0; `iptables -S` and
  `ip6tables -S` with `FORWARD DROP`, `iptables -t nat -S` and `ip6tables -t nat -S` with no
  rules; `ip -br link` shows no `wg` or `tun` interface.
- Every `proxy_pass` in `/etc/nginx` goes to the loopback address, and there is no `stream`
  block.
- `cbb forward` runs without `-vless-mirror`, or with the mirror at the loopback
  `dl.cbb.tools` server, which serves only `/*.json` and `/vX.Y.Z/` files and 404 for the
  rest.
- No other proxy on the server listens on a public address beyond those `ufw status`
  allows, and x-ui's subscription server is off.

## Homebrew

The tap is the repository
[HunterEwok/homebrew-tap](https://github.com/HunterEwok/homebrew-tap),
the one tap for all of the owner's formulae; CBB's is `Formula/cbb.rb`, and users install with
`brew install hunterewok/tap/cbb`. After each release (not a
pre-release) is published, `.github/workflows/published.yml` checks its signed files and writes the formula with
`packaging/homebrew/formula.sh` from the release's `SHA256SUMS` and pushes it to the tap's
`main`. The formula installs the release archives as they are, so it needs no Apple signing,
and CI's `homebrew` job installs one with it on macOS on every pull request.

Setting it up, once:

- [x] Create the public repository `HunterEwok/homebrew-tap`, empty (no README,
  license or `.gitignore`).
- [x] Make a key for it, on any computer:
  `ssh-keygen -t ed25519 -N '' -C homebrew-tap -f homebrew-tap`.
- [x] In the tap, **Settings → Deploy keys → Add deploy key**: the contents of
  `homebrew-tap.pub`, with **Allow write access**. It can write to the tap and nothing else.
- [ ] In the environment **release** ("Release secrets" above), the secret
  `CBB_HOMEBREW_TAP_KEY`: the contents of `homebrew-tap`, the private key. Then delete both
  files: a lost tap key is replaced by making a new one the same way.

To check the key without a release, run the published workflow from `main` (**Actions →
published → Run workflow**): its `homebrew` job pushes to the tap with `--dry-run`, which
fails unless the key may write there.

Without the secret the release still succeeds and warns that the tap kept its formula. To
fill the tap for a release made before, run `formula.sh` with that tag and its
`SHA256SUMS` and commit the output to the tap by hand.

## winget

The package `HunterEwok.cbb` installs the release's zip for Windows as winget's
portable command `cbb`; `cbb install` then runs the installer from the same zip. For each
release (not a pre-release) the `release` job of `.github/workflows/release.yml` writes its
three manifest files with `packaging/winget/manifest.sh` from the release's `SHA256SUMS` and
publishes them with the release as `winget-manifest.zip` (nothing can be attached to a
release once published, as releases are immutable); CI's `packaging` job checks the script on every pull
request. winget takes a package only by a pull request to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs), which its reviewers merge:

- [ ] For each release, on a Windows PC: unpack `winget-manifest.zip`, check it with
  `winget validate --manifest <folder>` and `winget install --manifest <folder>`, then submit
  it with `wingetcreate submit <folder>` (it asks for a GitHub token and opens the pull
  request under `manifests/h/HunterEwok/cbb/<version>`).

## The OpenWrt feed

The release workflow's `openwrt-feed` job wraps each Linux archive in an apk package for
OpenWrt 25.12 and later (`packaging/openwrt/feed.sh`, run in the pinned `alpine:3.23`
image, whose apk has mkpkg and mkndx, which OpenWrt's leaves out), one feed per Go architecture, and signs each index
with the feed's ECDSA P-256 key. It publishes them with the release as
`openwrt-feed.tar.gz`: `<arch>/packages.adb`, `<arch>/cbb-<version>.apk` and
the public key `cbb.pem`. CI's `openwrt` job builds a feed with a test key on
every pull request and installs and removes the package from it. Setting it up, once:

- [ ] Make the key on any computer: `openssl ecparam -name prime256v1 -genkey -noout -out
  feed.pem`.
- [ ] In the environment **release**: `CBB_OPENWRT_FEED_KEY`, the contents of
  `feed.pem`. Keep a copy offline; a new key means every router fetches the new public key.

For each release, unpack `openwrt-feed.tar.gz` into the site's `openwrt/` directory on
cbb.tools (routers read `https://cbb.tools/openwrt/<arch>/packages.adb`). Without the
secret the release still succeeds and warns that there is no feed.

## The ZX Spectrum Next's files

The release workflow's `zxnext` job takes the lite member for the Pi Zero from the `lite`
job, builds `.cbb`, its overlay `CBB.OVL` and `CBB.DRV` with the SHA-256 of that member, of
the overlay and of the driver inside `.cbb` (`make PI_CBB=...`, `apps/zxnext/pins.sh` and
`ovl.sh`), and lays them out for cbb.tools (`packaging/zxnext/site.sh`) as
`cbb-zxnext.tar.gz`: `zxnext/` with the four files and `LIST`, a line of name, size, CRC-32
and SHA-256 for each. `.cbb install` installs only the overlay, the driver and the member its
own `.cbb` carries. The four files must come from one build: a `.cbb` refuses another
build's. `release-sign publish` signs the same list with the release key as `zxnext.json`
(docs/protocol.md, section 16; one more touch of the key) and puts it among the release's
files; `release-sign mirror` writes `zxnext/SIGNED`, that release's `zxnext.json` after the
current `keys.json`, a line each, on every run, so it follows a new `keys.json`. `.cbb
update` takes a newer `.cbb` only from `SIGNED`, checked by the Pi's `cbb`.

NextZXOS's `.http` and the ESP8266 have no TLS, so these two paths are served over plain HTTP
on port 80, where the rest of the site redirects to HTTPS (`site/deploy/nginx.conf`, the
port-80 server of cbb.tools):

```nginx
location = /zxnext { alias /srv/cbb.tools/zxnext/CBB; default_type application/octet-stream; }
location /zxnext/ { root /srv/cbb.tools; default_type application/octet-stream; }
```

The first serves the dot command at `/zxnext`, which `.http -h cbb.tools -u /zxnext -f CBB`
fetches. A `return 301` at the server's level runs before any location, so the redirect to
HTTPS has to stay inside `location / { ... }`. The files are in `/srv/cbb.tools/zxnext`, outside
`www`, so a deploy of the site leaves them alone, and nobody puts them there by hand:
`cbb-mirror.timer` ("The mirror" below) unpacks them from the newest release that has them,
once that release checks out under the pinned roots. The checks of `.cbb install` guard
against a damaged download, and `.cbb update`'s also against a changed one; the `CBB` that
the first `.http` fetches is as trustworthy as the network (docs/threat-model.md).

## The mirror

`https://dl.cbb.tools/` mirrors the releases with the layout of docs/protocol.md, section 16,
"Where the files are": `keys.json` and `stable.json` at its top, each release's files and its
`release.json` under `vX.Y.Z/`. `cbb update`, the installers, the Android app and the lite
member fall back to it when GitHub does not answer; they check every signature, so the
mirror is not trusted. It runs on cbb.tools beside the site, on a name of its own.

`release-sign mirror` keeps it, from an hourly systemd timer (`site/deploy/cbb-mirror.service`
and `.timer`, as the user `cbb-mirror`, which holds no key). Each run takes the newest
`keys.json` and `stable.json` that check out from the branch `channel`, from
`/srv/cbb.tools/channel` (renewed there every week) and from the mirror itself, so it never
goes back. Then it downloads the release `stable.json` names, and the `min_from` of each
release in turn, checks each file against its `release.json` as a device does and only then
moves the release into place, and writes the top files last. Releases once mirrored stay,
since a device below a release's `min_from` needs the older one. A run with nothing new
downloads only the two small files. With `-zxnext DIR` it unpacks the ZX Spectrum Next's
files of the newest mirrored release that has `cbb-zxnext.tar.gz` into `DIR`, `LIST` last.

A pre-release has no `stable.json`, so the timer does not take it; once, by hand, after
`release-sign publish`: `sudo -u cbb-mirror release-sign mirror -out /srv/dl.cbb.tools
-zxnext /srv/cbb.tools/zxnext -version 0.6.0-rc.1`.

Setting it up, once, on cbb.tools:

- [x] The DNS record `dl.cbb.tools`, A to the server's address, DNS only.
- [x] `release-sign` built from this version (`GOOS=linux GOARCH=amd64 go build
  ./tools/release-sign`) at `/usr/local/bin/release-sign`, the user and its directories:
  `useradd --system --no-create-home --shell /usr/sbin/nologin cbb-mirror`, then `install -d
  -o cbb-mirror -g cbb-mirror -m 755 /srv/dl.cbb.tools /srv/cbb.tools/zxnext`.
- [x] The two servers of `dl.cbb.tools` and the two `/zxnext` locations from
  `site/deploy/nginx.conf`, merged into the live configuration by hand; `nginx -t`, then
  `systemctl reload nginx`, and nginx's ACME module gets the certificate.
- [x] `cbb-mirror.service` and `.timer` in `/etc/systemd/system`, `systemctl daemon-reload`,
  `systemctl enable --now cbb-mirror.timer`. `systemctl start cbb-mirror` runs it at once,
  and `journalctl -u cbb-mirror` says what it took. Until the first signed release it fails,
  for want of a `keys.json`.

## Signing for Windows

The release workflow signs `cbb.exe`, `cbbw.exe` and the tray app `cbb-desktop.exe` with Authenticode (`osslsigncode`, SHA-256,
a timestamp from DigiCert) when the secrets hold a code signing certificate; without it they
stay unsigned and SmartScreen warns on the first start. Setting it up, once:

- [ ] Buy a code signing certificate whose key can be exported as a PKCS#12 file (an OV
  certificate; an EV one lives on a hardware token and needs a signing service instead).
- [ ] In the environment **release**: `CBB_WINDOWS_CERT_BASE64`, the `.pfx` file in
  base64 (`base64 -w0 cert.pfx`), and `CBB_WINDOWS_CERT_PASSWORD`, its password.

To check it without a release, run the release workflow from `main`: its Windows builds
sign the programs.

### SignPath Foundation

Microsoft's Artifact Signing does not take individuals outside the USA and Canada, so the
plan for a certificate without buying one is the [SignPath Foundation](https://signpath.org),
which signs open-source projects for free with its own certificate:

- [ ] Apply on signpath.org with this repository (AGPL-3.0, releases built by GitHub Actions
  from tags, the code-signing policy page they ask for).
- [ ] Once accepted, they give an organization id, a project slug and a signing policy; put
  `SIGNPATH_API_TOKEN` in the Actions secrets and the ids in Actions variables.
- [ ] The release workflow then uploads the unsigned `cbb.exe`, `cbbw.exe` and `cbb-desktop.exe` as an
  artifact, submits it with SignPath's GitHub action, and archives the signed programs it
  gets back, in place of the `osslsigncode` step (which stays for a bought certificate).

`cbb update` on Windows needs nothing more: once the installed programs carry a signature,
it installs only programs with the same signer.

## Signing for macOS

The release workflow signs `cbb` for macOS with the project's **Developer ID Application**
certificate and the hardened runtime (`packaging/macos/sign.sh`) and has Apple's notary
service check it (`packaging/macos/notarize.sh`, `notarytool` signed in with the App Store
Connect API key), so that Gatekeeper opens it without a warning. Without the secrets the
program is signed ad hoc, as before. The certificates live in a keychain of the run's own
(`packaging/macos/keychain.sh`), removed when the step ends. CI's build job signs every pull
request's build ad hoc with the same flags and runs `cbb version`, which loads the Rust core
under the hardened runtime. `cbb` carries one entitlement,
`com.apple.security.cs.allow-unsigned-executable-memory` (`packaging/macos/cbb.entitlements`):
wazero compiles the core to machine code at run time, and a Mac that enforces the hardened
runtime's memory rules (macOS 27) kills a `cbb` without it as it loads the core. sign.sh
refuses a signature without it, since a runner that does not enforce them passes the run.

The same secrets make the Mac's installer package, `cbb-X.Y.Z.pkg` (the job "the Mac app
and the .pkg"): `cbb` for Apple silicon and Intel in one program (`lipo` of the two signed
builds) and CBB.app, built for both, signed with the hardened runtime and notarized, in a
package signed with the **Developer ID Installer** certificate (`packaging/macos/pkg.sh`) and
notarized in turn, its ticket stapled. The package puts the app in `/Applications` and runs
`install.sh` for the user signed in at the screen; without a terminal it keeps the answers
given before about the firewall and automatic updates and asks nothing. Without the secrets
the release has no `.pkg`. CI's `Mac app` job builds one unsigned, installs it with
`installer`, and removes it with `uninstall.sh`.

The iPhone app goes to TestFlight from the same environment (the job "the iPhone app, to
TestFlight", `apps/ios/testflight.sh`): an archive of the app with its share extension,
widgets and watch app, each target signed by hand with the **Apple Distribution**
certificate and its own App Store profile from `CBB_APPLE_PROFILES` (a base64 `tar.gz` of
the four `.mobileprovision` files, found by their App IDs), exported for App Store Connect
and uploaded with the API key. Its version is the tag's numbers (`0.6.0` for `v0.6.0-rc.1`),
its build number the run's. A run by hand from `main` builds and signs it as `0.0.0` and
uploads nothing. Apple asks about the app's encryption (export compliance) in App Store
Connect for each build until the answer is in the app's `Info.plist`. The profiles expire
after a year: make new ones in the account, then set `CBB_APPLE_PROFILES` again.

The Apple Developer account (team `U2ZJ8F2JCJ`) holds, all made once on the maintainer's
Mac with a key of its own (`openssl genrsa 2048` and a CSR, never Xcode's automatic signing),
with the files and a backup beside the other release keys:

- Certificates: Developer ID Application (programs and the Mac app outside the App Store),
  Developer ID Installer (the `.pkg`), Apple Distribution (TestFlight and the App Store),
  Apple Development (builds on the maintainer's own devices). Each `.p12` has a password of
  its own.
- Identifiers: the App Group `group.tools.cbb`; the App IDs `tools.cbb` (App Groups, NFC Tag
  Reading, Push Notifications), `tools.cbb.share` (App Groups), `tools.cbb.widgets`,
  `tools.cbb.watchkitapp` and `tools.cbb.mac`.
- App Store profiles for the four iPhone IDs, which renew every year.
- Keys: the App Store Connect API key (App Manager) for CI, and two APNs keys, one for
  Sandbox (builds signed for development) and one for Production, for a push server.

A Developer ID certificate is never revoked to replace it: a revoked one stops every release
signed with it from opening. When it expires, a new one signs the next release; the releases
signed before keep opening, since their signatures carry a secure timestamp.

To check it without a release, run the release workflow from `main`: its macOS builds sign
and notarize `cbb`.

## Updates of the Mac app (Sparkle)

The Mac app is not yet in the releases; once the Apple developer account exists and the app
is signed with a Developer ID and notarized, it updates with [Sparkle](https://sparkle-project.org):

- [ ] Sparkle's own Ed25519 key, made with Sparkle's `generate_keys` on the maintainer's Mac
  and kept in its keychain; the public key goes into the app's `Info.plist`
  (`SUPublicEDKey`) in `apps/macos/project.yml`.
- [ ] The release workflow builds, signs and notarizes `CBB-X.Y.Z.zip`;
  `release-sign manifest` lists it like the other files.
- [ ] `appcast.xml` beside `stable.json`, with each version's EdDSA signature
  (`sign_update`), made when `stable.json` is signed, so both name the same release.
- [ ] The app checks the appcast once a day (`SUFeedURL` on GitHub's latest release, the
  mirror second), and Settings gets "Check for updates" and "Update automatically".

## Android signing key

The release workflow builds `cbb-X.Y.Z.apk` and `cbb-fdroid-X.Y.Z.apk`
from the tag (version code `X*10000 + Y*100 + Z`, from `apps/android/version.properties`)
and signs them with the project's release key, which lives in the environment **release**
("Release secrets" above) and, with a backup, on the maintainer's Mac. Android installs an update only when it is signed with the same
key, so the key is made once and kept, with a backup, for good:

```sh
keytool -genkeypair -v -keystore cbb-release.jks -alias cbb \
  -keyalg EC -groupname secp256r1 -validity 36500 -dname "CN=cbb"
base64 -i cbb-release.jks | pbcopy   # macOS; Linux: base64 -w0 cbb-release.jks
```

The secrets: `CBB_ANDROID_KEYSTORE_BASE64` (the keystore, in base64),
`CBB_ANDROID_KEYSTORE_PASSWORD`, `CBB_ANDROID_KEY_ALIAS` (`cbb`) and
`CBB_ANDROID_KEY_PASSWORD` (the same as the keystore's for a PKCS12 keystore). Without them
the release has no APK. F-Droid publishes our signed `cbb-fdroid-X.Y.Z.apk` once
its own build of the tag matches it (below).

To check the key without a release, run the release workflow by hand from `main` (Actions,
"release", "Run workflow"): it builds everything, checks the APK's signature and keeps the
files as the run's artifacts, and publishes nothing.

## Signing for Aurora OS

Aurora OS installs an RPM only when it is signed with a certificate from Open Mobile
Platform; the maintainer's has the profile `regular` (`CN=hunterewok`, a GOST R 34.10-2012
key, valid until 2049). A phone updates the app only from a package with the same
certificate, and removing the app removes its key in OP-TEE, so every build that reaches a
phone is signed with this one certificate. CI's `Aurora app` jobs build the RPMs unsigned;
the workflow **aurora**, run by hand on any branch (Actions, "aurora", "Run workflow"),
builds them and signs them, after the maintainer approves the run in the environment
**aurora**, which alone holds the key: an environment with a required reviewer, so that a
pushed branch cannot use the key unseen.

The secrets of the environment **aurora**, from the files kept in `ci-keys.dmg` on the
maintainer's Mac:

```sh
base64 -i hunterewok_key.pem | gh secret set CBB_AURORA_KEY_BASE64 -R HunterEwok/cbb --env aurora
base64 -i hunterewok_cert.pem | gh secret set CBB_AURORA_CERT_BASE64 -R HunterEwok/cbb --env aurora
gh secret set CBB_AURORA_KEY_PASSWORD -R HunterEwok/cbb --env aurora   # asks for the key's password
```

`rpmsign-external` of the Platform SDK signs; it reads the key's password from
`KEY_PASSPHRASE`. The run's artifacts are the signed `tools.cbb.aurora-X.Y.Z-1.armv7hl.rpm` and
`.aarch64.rpm`.

## F-Droid

The app's F-Droid build ([apps.md](apps.md#f-droid)) is published by F-Droid, from its
recipe in [fdroiddata](https://gitlab.com/fdroid/fdroiddata); `packaging/fdroid` holds the
recipe we submit. Once, for the first release with the fdroid flavor:

- [ ] Fill in the recipe: `AllowedAPKSigningKeys`, the SHA-256 of the release key's
  certificate (`apksigner verify --print-certs cbb-fdroid-X.Y.Z.apk`), and
  `ndk`, the `cbb.ndk` of the tag.
- [ ] Check that F-Droid's build reproduces ours: `fdroid build -v -l
  tools.cbb` in a clone of fdroiddata with the recipe, on
  F-Droid's buildserver image (`fdroid build` compares with `Binaries`).
- [ ] Open the merge request to fdroiddata (GitLab account), with the recipe as
  `metadata/tools.cbb.yml`, and answer the reviewers.

After that, each release's tag is picked up by F-Droid's update check
(`UpdateCheckData` reads `apps/android/version.properties`), usually within days. When a
release's F-Droid build does not reproduce, F-Droid does not publish it; CI's `fdroid` job
catches most causes before the tag.
