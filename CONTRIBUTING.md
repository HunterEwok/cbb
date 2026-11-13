# Contributing

Copy Beyond Borders is developed by one maintainer. Thank you for your interest. For help
with using CBB, see [SUPPORT.md](SUPPORT.md).

## Issues are welcome

- **Bugs:** open an issue with the bug report form.
- **Ideas and questions:** open an issue with the feature request form.
- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).
- **A commercial license:** open an issue with the commercial license form.

Forks and packages: see [BRAND.md](BRAND.md) for the icon, the name and official builds.

## Code contributions

Pull requests are not accepted at this time. This keeps the copyright of the whole project
with the maintainer, so the licensing stays simple and no contributor agreement is needed;
it is also what lets the maintainer offer a commercial license (see the
[README](README.md#license)).
If you have found a fix, please describe the problem and the idea of the fix in an issue.

Pull requests from forks are closed without review.

## Conventions

The maintainer follows these rules; they are written down to keep the history consistent.

- **English only** in code, comments, documentation, commit messages and issues; the apps'
  translations are the one exception.
- **License header.** Every Go file, except generated code and code copied from other
  projects, starts with:

  ```go
  // SPDX-License-Identifier: AGPL-3.0-only
  // Copyright (C) 2026 HunterEwok
  ```

  Scripts and other source files start with the same two lines in their own comment style.
  A file that cannot carry them, such as an image or a JSON file, takes its license from
  [REUSE.toml](REUSE.toml); `reuse lint` checks that every file has one.

- **Copied code** lives in its own directory below `internal/third_party`, with its
  `LICENSE` and a `README.md` that names the source and version; its files keep their own
  copyright notices, and REUSE.toml names its copyright and license for the whole directory.

- **Pull requests.** Every change goes into `main` through a pull request and is merged with
  squash. `main` is protected.
- **Commit messages.** A short summary line in the imperative mood ("Add the pairing
  window"), then a blank line and the details, if any.
- **Changelog.** User-visible changes go into [CHANGELOG.md](CHANGELOG.md) under
  *Unreleased*.
- **Go code.** `gofmt`, `go vet`, `staticcheck` and `govulncheck` pass, and tests cover the
  change.
- **Tests.** A change keeps every test function of every language, running: one that replaces
  a test keeps its name, and a test does not skip where it did not (`t.Skip`, `#[ignore]`,
  `XCTSkip`, `@Ignore`, an `assume`). `go run ./tools/repocheck -tests-since origin/main`
  lists the tests a branch lost or made skip, and CI runs it against the pull request's base.
  A test removed together with what it tests, by a decision of docs/decisions.md, gets a
  line in `tools/repocheck/removed-tests.txt` in the same change: the file, the test, the
  decision and why.
- **Installers.** Every platform has the same three: a one-line `get` that downloads a
  release and checks it against `SHA256SUMS`, an `install` for an unpacked archive, and an
  `uninstall` that the install leaves on the machine. `get.sh` serves Linux and macOS,
  `get.ps1` Windows; CI runs each of them.
  The installers speak the user's language through `packaging/l10n.sh` (`say`, `sayerr`, `t`,
  `note`) and `packaging/windows/l10n.ps1` (`T`): a message is a constant printf format whose
  only directive is `%s`, with its values as arguments, and every catalog
  `packaging/l10n/<language>.tsv` (English text, a tab, the translation) translates it with
  its `%s` in the same order. `repocheck` checks both ways. The release puts the catalogs
  into `get.sh` and `get.ps1` (`packaging/l10n-embed.sh`), which run alone.
- **Documentation.** Each page says at the top who it is for and sits in its reader's part
  of [docs/README.md](docs/README.md), which `repocheck` checks: users' guides in plain
  words (`docs/guide`), administrators' pages (`docs/admin`), exact reference without the
  reasons (`docs/reference`), and the engineers' pages. A new command, flag or `CBB_*`
  variable goes into the reference in the same change. A change to the wire format changes
  The users' guides (`docs/guide`) are also translated into every language of the website,
  in `site/docs/<language>/guide/<page>.md`: the same headings, links, pictures and code
  blocks as the English page, only the text translated. When you change a guide page, change
  its translations in the same pull request (or say in it which languages are left), then
  run `go run ./tools/site docs-sync`; `go run ./tools/site check -strict` fails on a
  translation that follows an older page. The text inside the pictures of `docs/images` is
  translated in `tools/diagrams/l10n/<language>.json`; `python3 tools/diagrams/diagrams.py`
  draws them again. Every other page stays English and opens on GitHub from the website.
    [the protocol](docs/protocol.md), which is normative (MUST, SHOULD), its registries
  (section 19), the interop vectors and every implementation together
  ([testing](docs/testing.md)). A design that is built moves from the roadmap into the
  design.
- **No secrets.** No tokens, keys, real addresses or device names in the repository.
  GitHub secret scanning with push protection is enabled.

## Development

The checks that CI runs, by part. CI also builds every target; see
`.github/workflows/ci.yml` and the job list in [docs/maintaining.md](docs/maintaining.md#ci).

### Go

Copy Beyond Borders needs Go; `go.mod` names the exact toolchain, and the `go` command downloads
it when needed. From the repository root:

```sh
gofmt -l .                     # prints nothing when the code is formatted
go mod tidy -diff
go mod verify
go vet ./...
go tool staticcheck ./...
go tool govulncheck ./...
go tool actionlint             # GitHub Actions workflows
pipx run zizmor==1.31.1 --offline --min-severity low .github/workflows   # their security
go run ./tools/repocheck       # English only, license headers, copied code, no programs or files over 1 MiB, documentation links and names
go run ./tools/tokens -check   # apps/design/tokens.json -> Swift and Kotlin, WCAG contrast
go run ./tools/strings -check  # apps/l10n -> the apps' String Catalogs, strings.xml, .ts and tray l10n
go run ./tools/icon -check     # the apps' icons
sh .github/shellcheck.sh       # every shell script
pipx run typos==1.51.1         # spelling of the English text (_typos.toml)
npx --yes @biomejs/biome@2.6.2 ci   # the tray app's HTML, CSS and JavaScript (biome.json)
pipx run reuse==6.2.0 lint     # every file's copyright and license (REUSE.toml)
go test -race ./...
go build -o /dev/null ./cmd/...
GOOS=linux GOARCH=arm GOARM=6 go build -o /dev/null ./cmd/cbb-helper   # Raspberry Pi Zero W
GOOS=freebsd go vet ./...                                         # FreeBSD (the freebsd job runs the tests)
# Big-endian, 32-bit MIPS, as on many routers (the mips job; qemu-user-static, or qemu-user and qemu-user-binfmt
# on Ubuntu 26.04 (then qemu-mips), with binfmt
# for the tests that start the test binary again):
GOARCH=mips GOMIPS=softfloat go test -exec qemu-mips-static ./internal/mdns ./internal/helper
```

### The other parts

The model of the records' rules for claims (Quint, Node; the `model` job in CI):

```sh
npx @informalsystems/quint@0.33.1 test --backend=typescript docs/model/claims.qnt
npx @informalsystems/quint@0.33.1 run --backend=typescript --invariant=promises --max-steps=12 --max-samples=20000 docs/model/claims.qnt
```

cbb and the Rust workspace (the `rust` job in CI):

The core and the phones' bindings deny panics outside their tests (`core/src/lib.rs`,
`ffi/src/lib.rs`): read with `get`, add with `checked_` or `saturating_` operations, and
return an error. Where something truly cannot fail, allow the lint on that item with a
`reason`.

```sh
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
cargo build -p cbb-core --target riscv32imac-unknown-none-elf   # the core without an OS
cargo deny --locked check licenses bans sources   # the crates' licenses and sources (deny.toml, CI's advisories job)
cargo build --release -p cbb-member --features testhooks && go build -tags testhooks -o target/release/cbb-helper ./cmd/cbb-helper && \
  CBB_TEST_ALONE=$PWD/target/release/cbb go test ./internal/service -run TestAloneMember   # joins by the phone, syncs with Go members, and through the hub's tunnel
```

The end-to-end tests run `cbb` and `cbb-helper` built with the test hooks (the feature and
build tag `testhooks`, which `benchtime` implies; `member/src/testhooks.rs`,
`internal/testhooks`): only such a build reads the variables that change whom they trust or
their clock (`CBB_TEST_AHEAD_FILE`, `CBB_RELEASE_ROOTS`, `CBB_HELPER`,
`CBB_TEST_ATTEST_ROOTS`, `CBB_TEST_TPM_ROOTS`, `CBB_TEST_BLUEZ`, `CBB_TEST_LISTS_MIRROR`), and says so in `cbb version`
and its log. Never install one; a release never has them. CI's `hooks` job runs
`.github/release-ignores-hooks.sh` on `cbb` and `cbb-helper` built as the release builds them:
with every hook set they answer as without, and `tools/hookprobe` checks that the helper still
refuses an attestation under the roots `CBB_TEST_ATTEST_ROOTS` names. The release workflow does
not run them; it looks with `.github/hooks-marker.sh` for the line a hooks build says itself
with in every program it publishes, and the `hooks` job checks that the same script finds that
line in a hooks build. A new `CBB_TEST_` variable goes into one of the lists in those files.

The Nano ESP32's network code on Linux (`embassy/`, root for the TAP interface):

```sh
sudo ip tuntap add name tap0 mode tap user "$USER" && sudo ip addr add 192.168.69.1/24 dev tap0 \
  && sudo ip link set tap0 up
cargo build --release -p cbb-embassy --features host && \
  CBB_ESP32_ON_LINUX=$PWD/target/release/esp32-on-linux go test ./internal/service -run TestEmbassyJoiner
```

The Android app (`apps/android`, Gradle 9 with JDK 17 or later): the protocol core `kit` has
no Android dependencies and builds anywhere with Rust, whose core its tests build (see below);
the app needs the Android SDK with the NDK of `cbb.ndk` in `apps/android/gradle.properties`,
the Rust of `cbb.rust` there with the Android targets and cargo-ndk for the core, Go for the
tunnel (see below) and Google's Maven repository (CI, or a Mac with Android Studio). It has two builds, full and fdroid
([docs/apps.md](docs/apps.md#f-droid)):

```sh
cd apps/android && ./gradlew -p kit test
cd apps/android && ./gradlew :app:assembleDebug :app:testFullDebugUnitTest :app:testFdroidDebugUnitTest :app:lintFullDebug :app:lintFdroidDebug
sh packaging/fdroid/reproduce.sh . /tmp/cbb-reproduce   # the F-Droid build is reproducible
cd apps/android && ./gradlew :shared:testDebugUnitTest :wear:assembleDebug :wear:lintDebug
```

The phone kit (Swift package, runs on Linux too), with the Rust core it links:

```sh
sh ffi/bind.sh host /tmp/cbb-core
cd apps/ios/CBBKit && swift test -Xlinker -L/tmp/cbb-core
```

The phones' tunnel (WireGuard for sync away from home) is in the Rust core's library
(`ffi/src/tunnel.rs`, feature `tunnel`), which `ffi/bind.sh` builds for both apps; its tests
run it against the Go hub, clients and forwarder:

```sh
cargo test -p cbb-ffi --features tunnel tunnel
cargo build --release -p cbb-ffi --features tunnel --example tunnel-on-linux
CBB_TUNNEL_ON_LINUX="$PWD/target/release/examples/tunnel-on-linux" go test -race ./internal/tunnel -run TestRustPhone
```

The group rules of records `v:2` (docs/records-v2.md) reach the phones from the Rust core:
`ffi/` exports the core's one entry point (`cbb_core::api`, docs/core-api.md) as the C
functions of `ffi/include/cbb_core.h`, which the Swift kit links as its module `CCbbCore`
and the Kotlin kit calls through JNA (`Core.swift`, `Core.kt`). Its `bind.sh` builds the
libraries; the Android app's `bindCore` task and the Kotlin kit's tests build them
themselves, and the `phone core` jobs build them with the latest Rust:

```sh
cargo test -p cbb-ffi
ANDROID_NDK_HOME=<ndk> ffi/bind.sh android OUT   # needs cargo-ndk
ffi/bind.sh ios OUT                              # macOS with Xcode
ffi/bind.sh host OUT                             # the static library, for swift test
```

The app for Aurora OS and Sailfish OS (`apps/silica`, Qt 5.6 with Silica QML around the same
core; docs/roadmap.md, item 60): one code in `src/` and `qml/`, and what differs by system in
`src/platform/` (where the key is kept, the application shell) and `packaging/<target>` (the
`.spec` and `.desktop`), chosen by qmake's `CBB_TARGET`: `aurora5` (the key in OP-TEE),
`aurora4` and `sailfish` (the package `harbour-cbb`), the last two with the key in a file
(level 3). Each RPM is built in its system's Platform SDK (Aurora 5.1.5, Aurora 4.0.2,
Sailfish OS 4.6), which `psdk.sh` sets up as root (about 10 GB) for the `SYSTEM` in the
environment; CI's `Aurora app` jobs build every package and architecture unsigned
(`ci.sh`), and the workflow `aurora` signs Aurora 5's with the developer certificate after
the maintainer approves ([docs/maintaining.md](docs/maintaining.md#signing-for-aurora-os)).
The translations are `translations/cbb-<language>.ts`, English being the source, made from
`apps/l10n` like every app's ([Translations](#translations)): a new `qsTr` text, or a message passed to
`QCoreApplication::translate("Errors", ...)`, gets an entry there with the place
`aurora:<context>`.
Aurora's own interfaces (the sandbox's permissions, the authentication service's client,
localization, packaging) are documented for 5.1.5, the version the app is built for, at
[developer.auroraos.ru/doc/5.1.5](https://developer.auroraos.ru/doc/5.1.5/); the pages
without the version describe newer releases.

```sh
sudo apps/silica/psdk.sh /srv/psdk setup armv7hl   # the SDK, its tooling and a target
apps/silica/build.sh prepare   # the core for armv7hl and aarch64, the icons (rustup, the GNU cross compilers, ImageMagick)
sudo cp -a apps/silica /srv/psdk/root/home/builder/ && sudo chroot /srv/psdk/root chown -R builder /home/builder/silica
sudo apps/silica/psdk.sh /srv/psdk run '~/silica/build.sh rpm AuroraOS-5.1.5.105-base-armv7hl.default'
# Sailfish OS: the same with SYSTEM=sailfish and its own folder
sudo SYSTEM=sailfish apps/silica/psdk.sh /srv/sfos setup armv7hl
sudo SYSTEM=sailfish apps/silica/psdk.sh /srv/sfos run '~/silica/build.sh rpm SailfishOS-4.6.0.13-armv7hl.default sailfish'
```

The differential run of all four implementations (Go, Rust, JDK 17 and Docker for the Swift
container; [docs/differential.md](docs/differential.md)):

```sh
sh .github/differential.sh 1 20000 500 /tmp/differential
```

Cross tests between Go and Swift: Swift tests write vectors that Go reads, and the other way.

- `CBB_INTEROP_OUT=<dir> swift test -Xlinker -L<core>` writes fresh `swift-records.json`,
  `swift-renewal.json` and `swift-admin.json`; then
  `CBB_INTEROP_OUT=<dir> go test ./internal/group -run 'TestSwift'` reads them.
  Without the variable Go reads the committed copies in `testdata/interop`.
- `CBB_SWIFT_INTEROP=<path to cbb-interop>` runs
  `TestSwiftMemberAdmitsGoJoiner` (pairing over plain TCP); on macOS
  `CBB_SWIFT_INTEROP_TLS` runs the real-TLS pairing and member tests (see the
  `phone kit` job in `.github/workflows/ci.yml` for the keychain setup).
- The Kotlin kit does the same: `CBB_INTEROP_OUT=<dir> ./gradlew -p kit test` writes the
  same files, and `./gradlew -p kit interopScript` builds
  `kit/build/interop/cbb-interop`, which plays the Android phone in those three
  Go tests on Linux too (TLS from Conscrypt; the `Android app` job runs them).

The app (macOS with Xcode):

```sh
sh ffi/bind.sh ios apps/ios/CbbCore   # the Rust core and tunnel the kit links; needs Rust
brew install xcodegen
cd apps/ios && xcodegen generate   # CBB.xcodeproj and Info.plist are not committed
xcodebuild test -project CBB.xcodeproj -scheme CBB \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=  # any installed iPhone simulator
```

#### The iPhone app on your own phone

No developer account is needed: Xcode signs the app with a free Personal Team, any Apple ID.
Such a build runs for 7 days, and a free team may have three apps on a phone at a time.

1. Sign in to Xcode (Settings, Accounts) with your Apple ID.
2. On the iPhone turn on Developer Mode (Settings, Privacy & Security), connect it by cable,
   unlock it and trust the Mac; for the watch app turn on Developer Mode on the paired
   Apple Watch too.
3. Run `apps/ios/device.sh`: it builds the tunnel and the core when missing, generates the
   project, builds the Debug app with the watch app, installs both and launches the app
   (`--test` runs the app's unit tests on the phone instead; `--all` adds the share
   extension and the widgets).
4. On the first run trust the developer on the phone (Settings, General, VPN & Device
   Management).

A free team's app runs only on the devices its profile lists, and a build for a device adds
it: when Xcode reaches the watch, `device.sh` builds the watch app for it first, which adds
the watch. When the watch shows only as paired (a watch new to Xcode often does), keep it
unlocked near the phone and open Xcode's Devices and Simulators window until the watch shows
as connected, then run the script again; otherwise the watch refuses the app as one whose
integrity it could not verify.

The build has its own bundle identifier (`CBB_BUNDLE_ID`, `dev.<team>.cbb`)
and goes without the app group and the shared keychain, which need the developer account,
as the simulator's build does: the share extension finds no group in it.

The tray app for Linux and Windows, a Go module of its own (Linux needs GTK 4 and
WebKitGTK: `sudo apt-get install libgtk-4-dev libwebkitgtk-6.0-dev`):

```sh
cd apps/desktop && go vet ./... && go test ./... && go build -o cbb-desktop .
# Windows: go build -ldflags -H=windowsgui -o cbb-desktop.exe .
```

The Mac app (macOS with Xcode):

```sh
cd apps/macos && xcodegen generate   # CBBMac.xcodeproj and Info.plist are not committed
xcodebuild test -project CBBMac.xcodeproj -scheme CBBMac \
  -destination 'platform=macOS' CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=
```


### Translations

The apps' strings have one source, `apps/l10n/<language>.json` (English and the seven
languages of the website), and `tools/strings` writes every app's files from it: the String
Catalogs of the iPhone, Watch and Mac apps, Android's `res/values*/strings.xml`, Aurora's
`translations/cbb-<language>.ts` and the tray's `frontend/l10n`. Edit only the source:
`en.json` gives each string's ID (its English text) and the places that show it, such as
`ios`, `mac`, `tray`, `aurora:MainPage` or `android:settings`
([tools/strings/catalog](tools/strings/catalog/catalog.go) lists them), and each language's
file has its translation under that ID. Texts are plain; the tool escapes them for Android
and Qt. When Xcode adds a new key to a catalog, move it into the source.

```sh
go run ./tools/strings          # sort the source and write the apps' files
go run ./tools/strings -check   # what tools/repocheck checks too
```
