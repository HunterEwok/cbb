<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Roadmap

For contributors, engineers, and reviewers: planned features, agreed designs not yet built, and
open research questions. For the current system architecture, see [Design](design.md). For recorded
architecture decisions, see [Architecture decisions](decisions.md). For hardware verification
status, see [README status](../README.md#status) and
[Platform parity](parity.md#on-real-devices).

## Order of work

Execution order can change. Items keep their permanent numbers because code and documentation cite
them. Completed items appear as one line each in [Done](#done) with a link to where the current
documentation describes them.

### Done

- **1.** Repository scaffolding.
- **2.** Service core: sync engine, group and pairing, discovery, member connections, control
  socket, command line, and headless Linux with `tmux`.
- **3.** macOS: `cbb` service as a LaunchDaemon and pasteboard LaunchAgent.
- **4.** Desktop connector: Wayland data-control, X11, and GNOME through XWayland.
- **5.** Initial iPhone support without an app (replaced by item 17, D-80).
- **6.** QR code setup and using a phone as the main device.
- **8.** Windows: service, clipboard agent, and installers (verified in CI on `windows-latest` and
  an Arm Windows 11 VM; physical PC testing pending).
- **9.** iPhone and Android apps making a phone the group's main device
  ([Design: the phone apps](design.md#the-phone-apps); iPhone tested on physical hardware, Android
  tested in the CI emulator; store distribution tracked in items 38, 43, and 59).
- **12.** Sync away from home (**Everywhere**) through the group's WireGuard tunnel: hubs, phones
  and small Linux devices as clients, remote invitations, forwarder, blind relay, AmneziaWG, and
  VLESS ([Design: sync away from home](design.md#sync-away-from-home)).
- **16.** Computers, admins, capabilities, and device operating systems
  ([Design: members, capabilities, admins, and the operating system](design.md#members-capabilities-admins-and-the-operating-system)).
- **17.** Every phone joins through its app with its own key (D-80;
  [Design: group and pairing](design.md#group-and-pairing)).
- **18.** Remote paste to computers, `tmux`, and Linux consoles (D-54, D-59;
  [Design: remote paste](design.md#remote-paste); remote paste onto phones waits for 0.7 per D-132).
- **19.** Per-device **Sync** switch ([Design: sync on and off](design.md#sync-on-and-off)).
- **20.** Images, files, folders, and formatted text
  ([Design: images and files](design.md#images-and-files)).
- **21.** OpenWrt routers ([Design: OpenWrt routers](design.md#openwrt-routers)).
- **23.** Docker image ([Design: Docker](design.md#docker)).
- **24.** FreeBSD and OPNsense ([Design: FreeBSD](design.md#freebsd)).
- **27.** Quick actions ([Design: quick actions](design.md#quick-actions)).
- **30.** No phone acts as a hub: only a computer, router, or small board serves as a hub (D-134;
  [Design: groups without a computer](design.md#groups-without-a-computer)).
- **32.** Short-lived per-server credentials for forwarders and blind relays
  ([Design: what the servers learn](design.md#what-the-servers-learn)).
- **34.** Local device collections and tile ordering across iPhone, iPad, Android, Aurora OS,
  HarmonyOS, Mac, tray, and paired watch apps (D-72;
  [App specification: collections](apps.md#collections-and-the-order-of-the-tiles)).
- **41.** End-to-end sealed command orders using X-Wing HPKE to each receiver's sealing key
  ([Protocol](protocol.md), section 15; `core/src/commands`, `member/src/commands.rs`).
- **42.** Simplified group authority protocol: strict canonical signed bodies, per-server
  credentials, shared `cbb_core` rules engine, certificate-free members, capability-based hellos,
  conflict halting, signed `hubs` priority records, and strict media manifests
  ([Protocol](protocol.md), section 10; D-93, D-100–D-115).
- **48.** Connect Beyond Borders (`CBB`) branding and `tools.cbb` app identifiers
  ([Brand: the name](../BRAND.md#the-name)).
- **61.** Ways out (forwarder, VLESS mirror, blind relay, hub tunnel) carry only CBB traffic and
  never proxy to the internet
  ([Maintaining: ways out carry only cbb](maintainers/maintaining.md#ways-out-carry-only-cbb)).
- **63.** End-to-end sealed copies (D-84; [Protocol](protocol.md), section 4).
- **64.** Rust `cbb` as the service and full command line across computers, with Go `cbb-helper` as
  a companion process, Rust `cbb-relay`, and removal of the Go member daemon (D-88, D-130;
  [Design: the service and its helper](design.md#the-service-and-its-helper)).
- **65.** Unified "Why it does not sync" diagnostics from `cbb_core::why` in `cbb status` and every
  app ([App specification: why it does not sync](apps.md#why-it-does-not-sync)).

### Partly done

- **7.** **Installers**: Linux, macOS, FreeBSD, OpenWrt, and Windows installers, Homebrew, winget
  manifest generation, signed checksums and provenance attestations, SteamOS `/opt` persistence
  (untested on a physical Steam Deck), and the signed and notarized macOS `.pkg` release workflow
  ([Maintaining: signing for macOS](maintainers/maintaining.md#signing-for-macos)) are built.
  Remaining: submitting the package to winget's repository, verifying SteamOS on a physical Steam
  Deck, and running the first published release end to end.
- **11.** **`cbb` in Rust**: Complete on Linux, macOS, Windows, FreeBSD, and OpenWrt. Remaining:
  additional ESP32 boards beyond the Arduino Nano ESP32 (item 15) on the shared `core/`.
- **13.** **Device keys in hardware**: Built for Linux TPM 2.0 (`internal/tpmkey`), Windows TPM 2.0
  (untested on a physical PC), and macOS Secure Enclave (`member/src/sekey.rs`, including sealing
  secrets and tunnel keys via `member/src/keys.rs`). Remaining: physical Windows PC testing,
  protecting fallback file keys on Linux with `systemd-creds` and on Intel Macs with the system
  keychain, and storing a computer main device's root key in hardware. See
  [Device keys in hardware](#device-keys-in-hardware).
- **14.** **ZX Spectrum Next** through its Raspberry Pi Zero: Built—`cbb next`, `cbb next link`
  (`member/src/nextlink/`), `.cbb` and `.pibridge` dot commands (`apps/zxnext`), `CBB.DRV` driver,
  `CBB.OVL`, `.cbb install` and `.cbb update` with signed `zxnext.json`, `.cbb net on/off` over the
  ESP8266, `.cbb show` / `.cbb show -tape`, and `.cbb speed` (up to 921600/2000000 baud). Remaining:
  real-hardware verification of newer commands (`show -tape`, `speed`, mobile-network forwarder
  path), slow-link timeout tuning, background key-feeder and Terminex shell integration, copying
  from the Next, and Cyrillic character encoding. See
  [The Next's network in the background](#the-nexts-network-in-the-background).
- **15.** **Arduino Nano ESP32** (ESP32-S3) on `core/`: Built—firmware (`esp32/`) persists settings
  in flash, joins Wi-Fi, passes its QEMU TLS 1.3 self-test, and acts as a USB or Bluetooth LE
  keyboard (`us` and `ru` layouts). Remaining: joining a group through a home window and clipboard
  or remote-paste sync (planned for 0.7), real-hardware verification, OTA updates (item 29), and an
  optional library for custom Arduino sketches.
- **22.** **Mac app with Network Extension**: The menu bar app (`apps/macos`,
  [App specification: the Mac app](apps.md#the-mac-app)) and its Developer ID–signed, notarized
  `.pkg` ([Maintaining: signing for macOS](maintainers/maintaining.md#signing-for-macos)) are built.
  Remaining: embedding the service and a Network Extension content filter so macOS enforces
  home-network address limits at the OS level, matching Linux systemd and Windows Firewall (beyond
  the service's own `internal/netguard` checks).
- **25.** **Devices that are hard to type into**: Built—Android TV app variant, Nano ESP32 USB and
  Bluetooth LE keyboards (`esp32/README.md`), Android and Linux Bluetooth LE keyboards
  ([App specification: Android Bluetooth keyboard](apps.md#android-the-bluetooth-keyboard),
  `cbb keyboard`), computer network remotes for Android TV/Google TV, Apple TV Companion, and Roku
  (`cbb remote`), and the universal iPad layout. Remaining: Samsung (Tizen) and LG (webOS) remotes,
  TV remotes inside the phone apps, addressing paired TVs by target name in `cbb paste -on`,
  real-device testing on Android TV, Roku, and Meta Quest, and Entware router support. See
  [Devices that are hard to type into](#devices-that-are-hard-to-type-into).
- **26.** **Watches**: Built—Apple Watch, Wear OS, and HarmonyOS watch apps displaying group devices,
  collections, and the away-from-home switch, plus watch notifications
  ([Design: watches](design.md#watches)). Remaining: signing admin and emergency actions from the
  wrist (deferred to 0.7 per D-124), physical verification on Wear OS and HarmonyOS watches, and
  live iPhone push delivery (item 57).
- **28.** **Blind relay**: Built—open relay server (`cbb-relay`, `member/src/relayd/`),
  `cbb global relay` / `cbb global relay default`, the project's open relay on `cbb.tools`, the
  self-hosting guide ([Running your own servers](admin/self-hosting.md)), signed `keys.json` and
  `entries.json` rotation ([Maintaining](maintainers/maintaining.md)), and `"default"` project relay
  selection across all four phone apps and `cbb` on small Linux devices. Remaining:
  - Including the relay's key in the first signed `keys.json` publish (`release-sign publish
    -relay cbb.tools:8765=...`).
  - Testing relay key rotation on the Windows virtual machine.
  - Adding AmneziaWG and VLESS transport support to the blind relay (`member/src/relayd/`).
- **29.** **Secure updates**: Built—`cbb update`, automatic update timers, signed releases backed by
  two pinned YubiKey hybrid roots (`internal/release/roots/roots.pem`, ES256 and
  SLH-DSA-SHA2-128s), Android APK self-updates, and group release propagation
  ([Design: secure updates](design.md#secure-updates)). Remaining: Sparkle updates in the Mac app,
  OTA updates on the Arduino Nano ESP32, exercising a published release upgrade end to end, and
  signing the Windows programs without a bought certificate through the
  [SignPath Foundation](https://signpath.org) (Microsoft's Artifact Signing takes no individuals
  outside the USA and Canada): apply with this repository, put `SIGNPATH_API_TOKEN` and the
  organization and project ids in the Actions settings, and let the release workflow submit the
  unsigned programs to SignPath's action in place of the `osslsigncode` step, which stays for a
  bought certificate. `cbb update` on Windows then installs only programs with the same signer.
- **31.** **Key levels**: Built—hardware attestation evidence verification, key storage marks in
  `cbb status` and apps, the `key_level` group setting ([Protocol](protocol.md), section 10),
  `cbb keys`, phone app **Admin keys** settings, and the daily Google attestation revocation mirror
  (`site/deploy/cbb-attest.service`). Remaining: external Level 1 checks (Apple App Attest and
  Intel/AMD TPM manufacturer EK certificate fetches) and storing a computer main device's root key
  in TPM or Secure Enclave. See [Key levels](#key-levels).
- **35.** **Full documentation review against the code**: In progress.
- **39.** **Rootless installs** (D-79): Built and verified in CI (`install.sh --rootless`,
  [Design: rootless installs](design.md#rootless-installs)). Remaining: verification in a real Linux
  desktop session.
- **46.** **VLESS over XHTTP for blocked networks**: Built—forwarder XHTTP listener
  (`cbb forward -vless-xhttp`), `cbb.tools` nginx configuration (`site/deploy/nginx.conf`), hub
  offers, and AmneziaWG + VLESS over XHTTP clients in `cbb` (`member/src/awg.rs`,
  `member/src/vless.rs`, `core/src/vless.rs`) and every phone app; REALITY is removed (D-91).
  Remaining (planned for 0.7): VLESS's own encryption (ML-KEM-768 with X25519), blind relay support
  (item 28), and ESP32 support. See [VLESS behind a web server](#vless-behind-a-web-server).
- **49.** **Eight project languages across every app and CLI**: Built—Chinese, English, Spanish,
  Russian, Arabic, Swahili, Hebrew, and Hindi across all phone, watch, Mac, and tray apps (with
  right-to-left layout in Arabic and Hebrew, per-app language picker, locale selection in `cbb`,
  and CI termbase/Vale linting). Remaining: native-speaker review of translations before release.
- **53.** **Pre-launch review for sceptical readers**: Done—Android skips
  `android.content.extra.IS_SENSITIVE` copies, guides and README state end-to-end encryption bounds
  and server visibility accurately, README includes the trust model, comparison table, checksum
  verification, and build instructions, and website copy and RTL formatting fixes are applied.
  Remaining:
  - README key architecture diagram and app screenshots.
  - GitHub repository description and search topics (set by the maintainer).
  - Website polish: trust facts above the fold, Hebrew prepositions before links, Hindi terminology
    consistency, link wrapping on page titles, and native-speaker review of every language.
- **55.** **Updates through the group's ways out**: Built—VLESS mirror access through the forwarder,
  `site/deploy/cbb-mirror.service`, hub archive caching, and `cbb update` fetching releases and
  archives from the group when GitHub and `dl.cbb.tools` are unreachable (`member/src/update.rs`,
  [Design: where updates come from](design.md#where-updates-come-from)). Remaining: Android APK
  fetching updates from the group, and deploying `dl.cbb.tools` live.
- **56.** **Hub registration over VLESS and signed entry points (`entries.json`)**: Built—hubs
  register over VLESS with per-group XHTTP data paths, signed `entries.json` propagates via
  `cbb.tools`, the GitHub `channel` branch, group sync, and QR/text (`cbb global entries`), and
  apps warn when entry lists are stale. Remaining: adding multiple domains or a CDN (such as
  Cloudflare) in front of XHTTP inside the signed entry list once a spare domain or CDN is in place.
- **57.** **Push notifications for closed phone apps**: Built in the repository—sealed push wire
  format (`core/src/push.rs`, `testdata/format/push.json`), push daemon (`member/src/pushd/` for
  APNs, FCM, and UnifiedPush; `packaging/linux/cbb-push.service`), member pusher
  (`member/src/pusher.rs`, `member/tests/phone_push.rs`), iOS Notification Service Extension
  (`apps/ios/NotificationService/`, `apps/ios/CBB/App/PushSetup.swift`), and Android push platform
  (`apps/android/app/src/full/kotlin/tools/cbb/PushPlatform.kt`). Remaining: deploying the push
  service on `cbb.tools`, testing end to end on physical phones, verifying whether the iOS
  Notification Service Extension can write to the clipboard without a tap, and verifying whether
  iPhone Back Tap's execution budget suffices away from home over VLESS.
- **60.** **Aurora OS and Sailfish OS app (`apps/silica`)**: Built—shared Qt 5.6 / Silica QML
  codebase over `cbb_core` (`cbb_call`), unsigned RPM builds in CI for Aurora 5 (`armv7hl`,
  `aarch64`), Aurora 4 (`armv7hl`), and Sailfish OS (`armv7hl`, `aarch64`, passes `rpmvalidation`),
  OP-TEE PKCS#11 member and PIN-guarded admin keys (D-94), blind relay, notices, collections, Qt
  host unit tests in CI, and initial physical testing on Aurora 5.1.5 (F+ R570E). Remaining:
  - Full physical testing on Aurora 5.1.5 (group creation, YubiKey over `pcscd`, away-from-home
    sync).
  - Verifying clipboard, networking, and file-key fallback in the Aurora 5.2 SDK emulator, and
    checking whether Aurora 5.2 adds hardware key attestation for Level 1.
  - Community testing on physical Sailfish OS hardware (file key, Level 3).
- **68.** **Fewer choices in the apps**: Built—**Advanced settings** toggle hiding key levels and
  detailed away-from-home settings behind sensible defaults, and **The lab** framing for
  experimental hardware features ([App specification: the lab](apps.md#the-lab),
  [The lab](guide/lab.md)); freezing and removing an admin remain separate actions. Remaining:
  making away-from-home a single switch with fully automatic hub, forwarder, relay, and
  blocked-network selection (depends on device consent, item 58).

### Next

- **10.** **Console helper double-press and auto-paste**: Double-press injection of the member's
  own text on Linux text consoles (`design.md`, "3. Console helper") and `Shift+Insert` auto-paste
  after a copy from a phone through the `uinput` helper. The helpers themselves already operate as
  remote paste targets.
- **33.** **Researched and not built (D-73; superseded by D-134)**: Running an iPhone as a
  background hub via a Network Extension. See
  [Research: the iPhone hub in a Network Extension](#research-the-iphone-hub-in-a-network-extension).
- **36.** **Russian user documentation in the repository** (postponed): Dedicated `docs/ru/` and
  `README.ru.md` translations using the apps' Russian terminology, with `tools/repocheck` checking
  section parity against English originals and D-8 allowing Cyrillic there. (Developer documents
  stay in English; website user guides already have translations in `site/docs/ru/guide/`.)
- **37.** **Planned for 0.7.** Sync away from home on 32-bit MIPS routers: `cbb` for `mips` and
  `mipsle` omits the WireGuard tunnel because GotaTun requires 64-bit atomics that 32-bit MIPS
  lacks, so those routers sync at home only. Add tunnel support by removing GotaTun's 64-bit atomic
  requirement or using another WireGuard implementation for MIPS
  ([Design: OpenWrt routers](design.md#openwrt-routers)).
- **38.** **Planned after 0.6.** Android app registration and Google Play (Play Console account
  exists):
  - Register `tools.cbb` with the release signing certificate
    ([Maintaining: Android signing key](maintainers/maintaining.md#android-signing-key)) so
    sideloaded release APKs and self-updates remain installable under Android's developer
    registration requirement.
  - Decide whether to publish on Google Play and with which key: Play App Signing uses a separate
    Play-managed key (preventing cross-updates with GitHub APKs), whereas uploading with the
    release key keeps one key across channels. Coordinate with the Wear OS app (which must share
    the phone app's key) and F-Droid.
- **40.** **Planned.** Apple Vision Pro (`visionOS`):
  1. Offer the iPad app in compatibility mode through TestFlight and the App Store (no build
     changes required).
  2. Add a native `visionOS` target for `CBBKit` and the app, omitting unavailable features (QR
     scanner—use the six-digit code instead—Watch link, and Live Activities); clipboard, Secure
     Enclave, and Optic ID work as on iPhone.
  3. Build the Rust core and phone tunnel (`ffi/bind.sh`) for `visionOS` to support away-from-home
     sync.
- **43.** **Planned for 0.7.** App store submission requirements:
  - **Apple App Store (iPhone, Apple Watch, Mac)**:
    - Add `PrivacyInfo.xcprivacy` declaring required-reason APIs (`UserDefaults`, file timestamps,
      and similar) and set `ITSAppUsesNonExemptEncryption` in each `Info.plist`, documenting the
      standard-encryption export answer in [Maintaining](maintainers/maintaining.md).
    - Provide review notes (demo video, test group QR code, and clarification that the tunnel runs
      inside the app rather than as a system VPN under Guideline 5.4), link a privacy policy in
      metadata and inside the app, ensure store text does not promise automatic background sending
      on iPhone, and provide beta description and feedback address for external TestFlight review.
  - **Google Play and IzzyOnDroid**:
    - Add a dedicated prominent disclosure screen for the accessibility service reachable from Home
      (a card "Send my copies by themselves, optional"), not only from Settings, clearly stating
      what the service reads and does not read, with **Agree** and **Not now** (Back counts as
      **Not now**); open Android Accessibility settings only after **Agree**, and reflect actual
      service state in Settings.
    - Cover remote paste through the accessibility service explicitly in the disclosure, store
      listing, Play Console declaration, and review video.
    - Verify on a physical phone whether `canRetrieveWindowContent` and cross-app events are needed
      for copy detection or only for remote paste's focused field, requesting only what is used.
    - Handle Android 17 Advanced Protection (and OEMs that disable accessibility services on
      reboot) by detecting the revocation, falling back to one-tap sync, and explaining why.
    - Complete the Data safety form, `connectedDevice` foreground service justification, target API
      level, and API 37 `ACCESS_LOCAL_NETWORK` declaration. (GitHub and F-Droid builds are
      unaffected.)
    - Prepare a concise explanation of the accessibility service and development process for
      IzzyOnDroid's manual review policy.
- **44.** **Planned for 0.7.** Additional CI code checks (all free, CI-only; Rust `cargo-mutants`
  is already running nightly):
  - Go mutation testing with `gremlins` on Go parsers/rules.
  - `golangci-lint` with `errcheck`, `exhaustive`, `gosec` `G115`, `errorlint`, and `bodyclose`,
    after cleaning up existing findings.
  - `goleak` in Go service, relay, and forwarder tests to fail on leaked goroutines.
  - Thread Sanitizer in the Mac app CI job, followed by Swift 6 strict concurrency mode for the
    remaining Swift networking and state code (`AppModel`, `LiveGroup`).
  - Note: Kani formal verification is ruled out for `cbb_core` parsers (`BTreeMap`, `Vec`,
    `String` proofs did not terminate); property tests, fuzzing, and mutation testing cover them.
- **45.** **Planned after 0.6.** Core multi-group and guest capabilities:
  - One device participating in multiple groups simultaneously (such as a personal and work group),
    scoping every core call and persisted state file by group.
  - Temporary guest devices whose device record carries an expiration date and leaves the group
    automatically without manual removal.
- **47.** **Planned.** Two-tap iPhone Back Tap setup: bundle a signed Shortcuts file
  (`shortcuts sign --mode anyone` on macOS) invoking the app's Sync clipboard action, add an "Add
  the double-tap shortcut" button in Settings and post-pairing onboarding that opens the shortcut
  for import, and show a card guiding the user to Settings → Accessibility → Touch → Back Tap →
  Double Tap. Sign with the release bundle identifier for TestFlight builds (`apps/ios/testflight.sh`)
  and verify first with a Personal Team build.
- **50.** **Planned for 0.7.** OpenWrt LuCI interface (`luci-app-cbb`) in the project's `apk` feed:
  JavaScript view with a small `rpcd` backend querying the service over its control socket under a
  minimal ACL, showing devices, QR pairing, away-from-home and hub controls, and network zones.
  After 1.0 (once backward compatibility is guaranteed), submit packages to official
  `openwrt/packages` and `openwrt/luci` feeds with dedicated maintainers.
- **51.** **Planned for 0.7 (research).** Arduino boards with an ESP32 Wi-Fi coprocessor (Arduino
  Uno R4 WiFi first, then Nano 33 IoT, MKR WiFi 1010, and Nano RP2040 Connect with u-blox
  NINA-W10x): flash CBB firmware onto the ESP32 module to run `core/` and TLS 1.3 while the main
  MCU types and displays text over the internal UART or SPI link, replacing stock Wi-Fi firmware
  while installed (restorable via Arduino's updater). Open questions: reflashing without an
  external programmer (`SerialNINAPassthrough` / Arduino updater) and fitting `core/` + TLS 1.3
  into a classic ESP32's 520 KB RAM without PSRAM.
- **52.** **Planned for 0.7.** Local, opt-in, encrypted clipboard history across every platform
  (iPhone, Android, Aurora OS, HarmonyOS, Mac, tray app, and `cbb` CLI):
  - Device-local only (never synced across the group).
  - Off by default, enabled with one switch.
  - Configurable retention (1 hour, 1 day, 7 days) with a **Clear** button.
  - Encrypted with the device's key (Secure Enclave, Android Keystore, TPM, or file key).
  - Excludes copies marked as secret (password managers and deliberate secrets).
  - Searchable, with one-tap resend to the group. (Updates the "no history" principle in
    [App specification](apps.md).)
- **54.** **Planned before launch.** Project funding metadata: add `.github/FUNDING.yml` and
  `funding.json` (for FLOSS/fund) once GitHub Sponsors and Liberapay accounts exist, plus a brief
  **Support** section in `README.md` stating what donations fund (Apple developer account,
  forwarder hosting, test hardware), that donations buy no priority, and that commercial licensing
  is available—with no paid features, license keys, or paid server tiers. Post-launch grant
  candidates: GitHub Secure Open Source Fund and FLOSS/fund (noting NLnet excludes code written
  with generative AI).
- **58.** **Planned for 0.7.** Sync away from home by one-time device consent (D-82): a device's
  user consents once at install, at pairing, or in the app, allowing the main device or an admin to
  enable away-from-home sync or promote the computer to a hub remotely without typing a local
  command on each computer. See [Consent to sync away from home](#consent-to-sync-away-from-home).
- **59.** **Planned before 0.6 release.** App store signing setup (must precede the 0.6 tag because
  an Android signing key cannot change after install):
  - Record the Android release key SHA-256 fingerprint (`alias cbb`, stored in the **release**
    environment) in [Maintaining: Android signing key](maintainers/maintaining.md#android-signing-key).
  - RuStore (Android): upload the signed `cbb-fdroid-X.Y.Z.apk` (no self-updater, no Wear OS) rather
    than an AAB so RuStore never holds the signing key and shares one certificate with GitHub and
    F-Droid builds.
  - RuStore (Aurora OS): sign Aurora 5 RPMs and device test builds with the `regular` developer
    certificate (via the `aurora` workflow after maintainer approval), never the public test key
    refused by Aurora 5.2.
  - F-Droid: submit with `AllowedAPKSigningKeys` set to the release certificate following
    [Maintaining](maintainers/maintaining.md).
- **62.** **Planned for 0.7.** Sound, files, and screenshots on the ZX Spectrum Next (building on
  `.cbb show`):
  - `.cbb play`: decode the group's latest audio (MP3, AAC, WAV) on the Pi and play via I2S into
    the Next's mixer if supported, or stream 8-bit mono samples (~11 kHz at 115200 baud) over UART
    to the Next's DACs.
  - `.cbb get`: save the group's latest files to the SD card with 8.3 filenames, with `-run` to
    launch `.nex`, `.tap`, `.tzx`, `.sna`, or `.z80` files directly.
  - `.cbb snap`: capture the Next screen (ULA or Layer 2) and send it to the group as a PNG.
- **66.** **Planned for 0.7.** Send a copy to a single device ("Share → laptop"): seal the copy for
  only the selected recipient and write it only to that device's clipboard.
- **67.** **Later (not planned).** Multiple people in one group, each with a separate clipboard. A
  group belongs to one person ([How it works: the group](guide/how-it-works.md#the-group)), and the
  versioned record format allows future extensions without breaking older devices
  ([Protocol](protocol.md), section 10).
- **69.** **Planned for 0.7.** Unified product experience across all apps and the CLI:
  - Complete screen-and-state inventory across every platform against [Platform parity](parity.md).
  - Task-frequency prioritization deciding Home screen layout versus deeper screens.
  - Shared object model (group, device, main device, admin, copy, invitation, recovery key) aligned
    with the termbase and written product principles.
  - Core-driven state machines for add-device, join, and recovery flows tested on every platform.
  - Single error, notice, and reason catalogue with codes, texts, and remedies shared by apps and
    `cbb status`.
  - Cross-platform UI pattern library (irreversible confirmations, progress, empty states, errors,
    pairing, secrets, offline states) and role-named design tokens.
  - CLI alignment with [Command Line Interface Guidelines](https://clig.dev) (consistent nouns and
    verbs, `--json`, uniform errors, meaningful exit codes).
  - CI visual gallery across platforms, states, and languages alongside CLI output,
    pseudo-localization, review checklist, heuristic review, and tap-count task walkthroughs.
- **70.** **Planned for 0.7.** The rest of the core and the binary format (D-131); Waves 1–5 are
  built in `core/` and `member/` for 0.6. Wave 6 moves the sans-I/O member session into
  `cbb_core`, replacing `core/src/sim/exchange.rs`, and runs a real ESP32 board in a group. Wave 7
  freezes the format in `testdata/format/FROZEN`, brings cross-version N / N-1 compatibility per
  D-131, and needs two consecutive clean security audit passes. See
  [The core and the format in 0.6](#the-core-and-the-format-in-06).
- **71.** **Planned for 0.7.** Release-gating soak runs: a seven-day `tools/soak` run on the
  release candidate build on the bench's Raspberry Pi 4 (calm and load stands side by side,
  restarting the day counter on any code change; [Testing: soak](testing.md#soak)) plus the
  24-hour container soak (`E10`, [Test bench](maintainers/testbench.md), section 10).

## Devices that are hard to type into

Partly built (item 25): Android TV, Nano ESP32 USB and Bluetooth LE keyboards, Android and Linux
Bluetooth LE keyboards, computer remotes for Android TV/Google TV, Apple TV, and Roku, and the
universal iPad app are built; Samsung/LG remotes, phone-app remotes, target-addressed
`cbb paste -on`, and real-device validation remain.

The goal is delivering copied text (logins, Wi-Fi passwords, URLs, search terms, codes) into text
fields on devices controlled only by a TV remote or gamepad, ordered from least to most hardware
required.

### 1. Our app on the device

Devices running Android use the Android app directly or its TV layout:

- **Android TV, Google TV, Fire TV**, set-top boxes, and projectors: TV layout in the main APK with
  launcher banner, D-pad navigation, no touch requirement, and QR pairing without typing on the TV.
- **Android car head units, Android e-readers (Onyx Boox), and Chromebooks**: run the standard
  Android app.
- **Meta Quest (Horizon OS)**: installs the APK; verify on a headset whether its accessibility
  service can enter text into other apps.

TV devices default to receive-only sync. Remote paste onto Android targets inserts text via the
accessibility service (`ACTION_SET_TEXT` or clipboard + `ACTION_PASTE`; deferred to 0.7 for phones
per D-132).

### 2. The device's own remote, from a member

A member pairs once with a TV on the home network using the TV's native remote protocol and sends
remote-paste text directly into the focused on-screen field without installing anything on the TV.

| Device | Protocol | Pairing | Transport | Status |
|---|---|---|---|---|
| Android TV, Google TV | Android TV Remote v2 | On-screen code | TLS | Built in Go (`cbb remote`), untried on physical TV |
| Apple TV | Companion protocol | On-screen PIN | Encrypted | Built in Go (`cbb remote add -appletv`), tested on Apple TV 4K |
| Samsung (Tizen) | TV remote WebSocket API (port 8002) | One-time on-TV prompt | TLS | Planned |
| LG (webOS) | SSAP over WebSocket (port 3001) | One-time on-TV prompt | TLS | Planned |
| Roku | External Control Protocol (per-character keys) | None | Plain HTTP | Built in Go (`cbb remote`), untried on physical TV |

Rules:

- **Target, not a member**: The TV holds no group key, receives no sync events, and belongs to the
  member that paired with it (which stores its pairing keys). Remote paste currently routes via
  `cbb remote pastes`; addressing a TV by target name with `cbb paste -on` comes with device-list
  targets.
- **Home network only**: The final hop uses the TV's own protocol, so a member connects only to
  home-network addresses (`internal/netguard`), never across the tunnel.
- **Roku requires explicit opt-in**: Disabled until the user acknowledges that text crosses the
  home network unencrypted.
- **No third-party cloud**: Every protocol runs locally in Go with full debug error details.
- **Supported hosts**: Computers, routers, and Docker images first; phone apps (Android and iOS
  local network) follow.

Apple TV pairing note: Apple TV accepts new remote pairings only when **Settings → AirPlay and
HomeKit → Allow Access** is set to **Everyone on the Same Network** (or **Everyone**); document
this step in onboarding and user guides.

### 3. A phone or computer as a Bluetooth keyboard

A group member with Bluetooth HID device support pairs with a TV, console, or tablet as a Bluetooth
keyboard and types incoming remote pastes.

| Member | Bluetooth keyboard | Platform constraint |
|---|---|---|
| Android (9+) | Yes | `BluetoothHidDevice` (detected at runtime; some OEMs omit it) |
| Linux | Yes | BlueZ HID profile (requires Bluetooth adapter permission at install) |
| Aurora OS, HarmonyOS | Yes | BlueZ (Aurora OS); HID over GATT without LED reports (HarmonyOS) |
| iPhone, iPad | No | iOS reserves Bluetooth HID for the system |
| macOS, Windows | No | No public API for the peripheral keyboard side of Bluetooth HID |

Open fixes from real Apple TV testing with a Linux Bluetooth keyboard:

- Give the BLE keyboard its own advertised name so the TV does not display duplicate entries for
  classic Bluetooth and BLE HID.
- Drop stored bonds automatically when the host forgets the keyboard ("PIN or Key Missing") and
  re-enter pairing mode cleanly.
- Add a **Switch keyboard layout** quick action (such as `Control-Space` on Apple devices) so users
  can switch the target host's active keyboard layout to match `-layout`.

### 4. The Nano ESP32 as a keyboard

For targets without an app, network remote protocol, or nearby Android/Linux member, the Arduino
Nano ESP32 (item 15) acts as a hardware keyboard:

- **USB boot keyboard** (built): PlayStation 5, Xbox, Nintendo Switch, TVs, KVM switches, BIOS/UEFI
  setup, boot loaders, and air-gapped servers. Switches USB-JTAG to a composite HID + CDC-ACM
  console with a `flash` command.
- **Bluetooth LE keyboard** (built, `ble on`): Apple TV, Samsung/LG TVs, iPads, and consoles;
  settings reset erases pairings.
- **Serial console** (planned): UART on a router, switch, or server console header.

Keyboards emit scancodes interpreted by the target's active layout (`us` and `ru` supported; other
layouts configurable per target). Login and disk-encryption prompts are typed only on explicit
remote paste, with Enter governed by a separate permission (D-59).

### Other devices

- **SteamOS**: Desktop Mode syncs as KDE Plasma (installed under `/opt`, item 7); Game Mode uses
  `uinput` remote paste.
- **iPad**: Universal iPhone/iPad app (built and tested in CI with `PadUITests`).
- **Keenetic and other Entware routers**: Planned after OpenWrt, using the same `cbb` binary with
  Entware init scripts.
- **WSL and Termux**: Covered by the Windows service and Android app with no separate target.
- **Not reachable**: Kindle e-readers accept neither apps nor keyboards; watches run companion apps
  (item 26).

## Key levels

Partly built (item 31, D-66, D-70). The main device and admins (including reading hubs) hold
hardware-backed keys by default; forwarding-only hubs read no copies and need no hardware key
(D-84).

Three group levels selected on the main device:

1. **Proven hardware only (Level 1)**: Main device and admins must prove via attestation that their
   keys live in hardware (Android Key Attestation through Remote Key Provisioning, TPM with
   manufacturer endorsement certificate, or Apple App Attest). Queries external services where
   necessary (Apple for App Attest, Intel/AMD for firmware TPM certificates); Google's revoked
   attestation key list is mirrored and signed daily on `cbb.tools` (`site/deploy/cbb-attest.service`)
   so devices never query Google directly. Only exception to D-47, strictly opt-in.
2. **Hardware (Level 2, default)**: Trusts the device's own report of hardware-backed keys (phones,
   Mac Secure Enclave, TPM without external fetch) while also marking offline-verifiable proofs
   (Android chains, on-chip TPM EK certificates) as **proven** without contacting outside servers
   (D-70).
3. **Files allowed (Level 3)**: Permits file-backed admin keys after an explicit warning per
   promotion. Required for computer-only groups without hardware security chips (D-44).

Current gaps and remaining work:

- **External Level 1 checks**: Apple App Attest (noted in user docs as proving a genuine app on
  Apple hardware rather than the specific key) and opt-in Intel/AMD firmware TPM EK fetches (with a
  privacy warning because the request identifies the TPM) are not yet built.
- **Computer main-device root key**: On a computer created with `cbb new`, the root key still sits
  in a file (starting the group at Level 3). Moving the computer root key into the TPM or Secure
  Enclave so a computer main device qualifies as hardware remains open.
- **Android attestation challenge**: Existing Android keys created without an attestation challenge
  must generate a new key to qualify as proven.
- **Compromised devices**: Devices reporting root/jailbreak, unlocked bootloaders, or software
  Keystore count as file keys and show a warning; relocked custom OS builds (such as GrapheneOS)
  count as hardware.

## Device keys in hardware

Partly built (item 13, D-44). Phones keep member, root, and admin keys in the Secure Enclave,
Android Keystore, OP-TEE (Aurora 5), or HUKS (HarmonyOS). Linux and Windows computers with TPM 2.0
and Macs with Apple silicon or a T2 chip keep member and admin keys in hardware and seal their
tunnel keys (`internal/tpmkey`, `member/src/sekey.rs`, `member/src/keys.rs`; Linux installer opens
`/dev/tpmrm0` via a systemd drop-in in `packaging/linux/install.sh`).

Remaining work:

- **Physical Windows PC verification**: Windows TPM 2.0 support (via TBS and Platform Crypto
  Provider) is tested in CI and a VM, not yet on physical PC hardware.
- **Protected fallback key files**: On computers without hardware security chips (older PCs,
  Raspberry Pis, Intel Macs without T2), seal file-backed keys with `systemd-creds` on Linux and
  store them in the system keychain on Intel Macs to protect offline disk copies and backups while
  documenting clearly that root access still exposes keys.
- **Computer main-device root key**: Move the root signing key into TPM or Secure Enclave (item 31).
- **Scheduled renewal and revocation**: Member and tunnel keys renew on schedule; removing a device
  remains the primary response to theft.

## VLESS behind a web server

Partly built (item 46, D-91). VLESS uses one transport: XHTTP behind the forwarder site's web
server (such as `cbb.tools` nginx), terminating TLS with the site's real certificate and forwarding
one configured path to the forwarder's loopback VLESS listener (no access logs on that location).
REALITY is removed (D-91). AmneziaWG and VLESS over XHTTP are equal transports: hubs with VLESS
enabled also speak AmneziaWG, clients try AmneziaWG over UDP first and VLESS over HTTPS when UDP is
blocked, and clients never fall back to plain WireGuard when VLESS is enabled.

Built:

- Go forwarder XHTTP listener (`cbb forward -vless-xhttp`) with random per-group data paths.
- `cbb` AmneziaWG (`member/src/awg.rs`) and VLESS over XHTTP (`member/src/vless.rs`,
  `core/src/vless.rs`, `TestAloneMemberAwayXHTTP`), plus the same transport in the phone apps.
- `site/deploy/nginx.conf` XHTTP location and `cbb.tools` forwarder deployment.
- User guide ([Networks that block VPNs](guide/blocked-networks.md)) and test bench cases (`W34`).

Remaining (planned for 0.7):

- **VLESS encryption**: Add VLESS's own encryption (ML-KEM-768 with X25519) when requested by a
  forwarder.
- **Blind relay**: Add AmneziaWG and VLESS over XHTTP to `cbb-relay` (item 28).
- **ESP32**: Evaluate whether AmneziaWG fits alongside ESP32 member sync (VLESS is excluded on
  ESP32 due to RAM constraints).
- **TLS ClientHello fingerprint**: If censoring networks single out `rustls` ClientHello fingerprints
  (JA3/JA4), align cipher suite and extension ordering closer to a browser profile for XHTTP.

## The Next's network in the background

Partly built (item 14, on a Raspberry Pi Zero without Wi-Fi). The Pi runs `cbb service` from the
writable `/NextPi` partition while NextZXOS stays in any program, using `CBB.DRV` (a 512-byte
interrupt-driven NextZXOS driver) to frame bytes between the ESP8266 UART and the Pi UART and feed
pastes into the ROM keyboard buffer (`LAST_K`, 50 characters/s).

Built and verified on the bench:

- `.pibridge`, `CBB.DRV`, `CBB.OVL`, `CBB` in `C:/DOT`, and `cbb next link` (`member/src/nextlink/`,
  `member/tests/next_link.rs`) carrying framed ESP traffic and `.cbb paste` / `copy` / `text` over
  the active link (only `.cbb pair` stops the link).
- `.cbb install` and `.cbb update` downloading from `cbb.tools/zxnext`, verifying SHA-256 and
  signed `zxnext.json` (`cbb next check-list`), transferring gzipped `cbb` to `/NextPi/nextpi` at
  up to 921600 baud with automatic step-down, and setting Pi time from the Next's DS1307 RTC.
- Bench-tested home and hub-tunnel sync through the ESP8266 at 19200 baud (`AT+UART_CUR`) with
  XON/XOFF flow control.

Remaining work and open bench questions:

1. **Slow-link timeouts and mobile-network forwarder test**: Tune member read timeouts for the
   ~2 KB/s ESP link (which occasionally reconnects on read timeout) and test a phone on cellular
   data through the forwarder to a hub with the Next behind it.
2. **NextPi shell and Terminex coexistence**: Decide whether `cbb next link` should own a
   pseudo-terminal for the `SUP>` shell so pastes work inside Terminex, and how `CBB.DRV` detects
   when Terminex directly accesses the Pi UART.
3. **Copying from the Next**: Choose between a driver hotkey (sending the current BASIC line or a
   marked screen region) and `.cbb copy` through the driver API.
4. **Driver and keyboard-driver layout**: Determine whether `CBB.DRV` and the replacement keyboard
   driver should be combined and how large a key buffer fits in 512 bytes.
5. **Real-hardware tests**: Verify `.cbb show -tape` (NextPi I2S audio via `aplay` into EAR) and
   `.cbb speed` on a physical Next, and add Cyrillic encoding support.

## Consent to sync away from home

Planned for 0.7 (item 58, D-82). Currently, turning sync away from home on requires typing
`cbb global on` (or `cbb global hub -away-on`) locally on each computer. With one-time device
consent, a device's user consents once at install, at pairing, or in the app, after which the main
device or an admin can enable away-from-home sync or promote the computer to a hub remotely.

**Consent storage and controls**:

- **At install**: Installers prompt `[y/N]` (off by default); non-interactive flags
  `--global on|off` / `CBB_GLOBAL` (`get.sh`, `install.sh`), `-Global on|off` (`get.ps1`,
  `install.ps1`), `.cbb install`, and the ESP32 console set it ahead of time.
- **Later changes**: `cbb global consent [on|off]` (requires root/administrator), phone Settings
  and onboarding switch, and Mac/tray app Settings.
- **File-backed keys**: Devices without hardware keys require the separate risk warning of D-45
  before consent takes effect. Rootless installs (D-79) may consent as clients only.
- **Revoking consent**: Prevents remote enabling (`away-on` / `hub`) without turning off an active
  session (`cbb global off` turns it off).

**Behavior with consent**:

1. On joining a group (or immediately when granted later), a consented device generates its tunnel
   key and offers it to group hubs automatically while keeping its role.
2. A new signed `away-on` command ([Protocol](protocol.md), section 15) from the main device or an
   admin re-enables away-from-home sync on a consented device (refused without consent; watches
   never sign it).
3. A `hub` command to a consented, eligible member enables away-from-home sync first and then
   promotes it to a hub (respecting key levels, capabilities, D-79, and D-134).
4. A device turned off via `away-off` or local `cbb global off` stays off across restarts until
   turned back on by `away-on`, `hub`, or its user.
5. **Visibility**: Hellos carry `away_consent` (informational only); signed device records record
   consent at admission and renewal so apps show remote enable/hub controls only where allowed and
   `cbb status` displays it.

**OS firewall boundaries**:

- With consent, elevated installers pre-allow the project's built-in `cbb.tools` forwarder and
  relay, and `cbb pair` adds the group's servers from the Welcome. If group servers change later,
  `cbb status` and apps prompt for `sudo cbb global allow` (administrator on Windows).
- Remote `hub` promotion creates a forwarder-backed hub (already permitted by outbound rules).
  Direct-address hubs require an open inbound UDP port and stay local (`sudo cbb global hub` or an
  elevated **Hub on its own address** switch in the Mac and tray apps, which first verifies public
  IP and port reachability via a loopback probe from `cbb.tools` and falls back to recommending a
  forwarder-backed hub).

**Implementation steps**: Protocol (`away_consent`, `away-on`, vectors) and `cbb_core` validation →
Rust service, control operations, and installers → small devices → phone kits and app UI → user
guides, translations, and moving this specification to [Design](design.md).

## The core and the format in 0.6

Waves 1–5 built for 0.6; Waves 6 and 7 planned for 0.7 (item 70). The binary wire format and
records core stay preliminary in 0.6 and freeze in 0.7 (D-131).

1. **Wave 1 — Core hardening without format changes (built)**: CI firmware size tracking
   (`tools/size`), saved copy clock mark, memory zeroization of secrets, external X-Wing vector,
   release test-hook guard, Windows TPM keys, and shorter channel expiry.
2. **Wave 2 — Strict CBOR wire format (built, D-100)**: Strict CBOR encoder/decoder in `cbb_core`,
   `cbb` inspection output, algorithm numbers, second-signature slot, padded frames, and
   deterministic vectors in `testdata/format`.
3. **Wave 3 — Deterministic record set (built, D-101–D-104, D-113–D-115)**: Self-contained signed
   bodies keyed by hash, order-independent evaluation with no clock reads, forward-compatible field
   zones, rights bitmasks, format ceilings, three core admin presets, Quint model, and property
   tests.
4. **Wave 4 — Certificate-free members (built, D-105, D-106, D-109)**: Fixed TLS key container
   without SNI, period-only server credentials, post-quantum TLS key exchange, hub-derived tunnel
   keys, and key-matched invitations.
5. **Wave 5 — Content, keys, and commands (built, D-108, D-112)**: Typed content envelope, weekly
   sealing-key rotation, unified `KeyStore` trait, sealed signed commands, and guarded-device
   nonce/consent rules.
6. **Wave 6 — Session in `cbb_core` and small-device board (open)**: Move the sans-I/O member
   session from `member/` into `cbb_core` (replacing `core/src/sim/exchange.rs`) so computers,
   phones, and microcontrollers run identical session code; run a physical ESP32 board in a real
   group taking copies, commands, and grants (targeting ~512 KB flash as an aim, not a hard limit).
7. **Wave 7 — Format freeze for 0.7 (open, D-131)**: Regenerate [Protocol](protocol.md) cleanly
   from `cbb_core` with no unused mechanisms, declare `frozen` in `testdata/format/FROZEN`, complete
   two consecutive security audit passes with no new high-severity findings, and verify N / N-1
   cross-release interoperability in CI.

Post-freeze items requiring no wire-format changes: locked ESP32 firmware builds, half of the
sealing key in the Secure Enclave, a hardware-key microcontroller board, a single peer-routing
selector, enabling the second signature, and multi-group app UI.

Explicitly out of scope: expiring records or rights (record rules read no clock), cross-group
rights (use a shared small group per D-111), a separate lightweight protocol for small devices
(D-107), and new admin types (D-102).

## Future research (not planned)

Questions to investigate before committing to a plan:

- **ZX Spectrum Next without a Raspberry Pi**: Must run on the Next's own hardware with no external
  gateway. Three candidate paths in priority order:
  1. Z80N runs the member directly while the stock ESP8266 AT firmware carries only TLS ciphertext
     (estimated 5–20 s per X25519 handshake, then multi-KB/s over the open session).
  2. Custom firmware on the ESP-01 acting as the member (~80 KB RAM for TLS 1.3; replaces stock AT
     firmware).
  3. An ESP32 module fitted into the ESP-01 socket running `core/`, if a compatible module exists.
  Measurements needed: P-256 signing cost on Z80N and TLS 1.3 RAM footprint on ESP8266.
- **No gateway and no plaintext tier (D-49)**: Devices too constrained for the member protocol do
  not delegate trust to another network member. Arduino boards whose Wi-Fi coprocessor hides TLS
  exporters cannot participate with stock firmware (see item 51 for custom coprocessor firmware).
  Devices without networking are unsupported.

### Research: the iPhone hub in a Network Extension

Researched and not built (D-73); superseded by D-134 (no phone acts as a hub). Running an iPhone
hub in the background via a `NEPacketTunnelProvider` Network Extension fails multiple constraints:

1. **App Store rules**: Guideline 5.4 restricts VPN apps to organization developer accounts (the
   project uses a personal account), and Guideline 2.5.4 plus Apple TN3120 prohibit using a packet
   tunnel provider to host a network listener or proxy server.
2. **Single VPN slot**: iOS allows only one active tunnel-type VPN; enabling a packet tunnel
   disables the user's own VPN (and vice versa). Keeping the tunnel inside the app (`ffi/` /
   `member/src/live/away.rs`) lets CBB coexist with any user VPN.
3. **Memory limit**: iOS packet tunnel extensions are capped at 50 MiB, leaving minimal headroom for
   the tunnel, forwarder transport, and member runtime.
4. **Battery and radio impact**: Keeping cellular radio active for forwarder keepalives (every
   15 s) and client keepalives (every 25 s) has no acceptable power budget.

Instead, computers, routers, and Docker containers serve as hubs (with priority failover per D-65),
groups without a hub use a blind relay (item 28), Android's `connectedDevice` foreground service
maintains connections without taking the VPN slot, and iPhone delivery while closed uses push
notifications with a Notification Service Extension (item 57).

Related finding worth preserving: phone member keys use "when unlocked" Keychain accessibility, so
background tasks cannot use them while the phone is locked.

An opt-in background packet-tunnel mode remains unplanned due to Guideline 5.4, TN3120, and the
50 MiB ceiling, and would be reconsidered only if the project enrolled as an organization.
