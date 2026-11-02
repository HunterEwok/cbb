<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Roadmap

What comes next, the designs that are agreed but not built yet, and the questions to study
before anything is planned. How Clipboard Bridge works today is in [design.md](design.md),
the decisions in [decisions.md](decisions.md); what works on real devices is the
[status table](../README.md#status).

## Order of work

The order may change. Items keep their numbers, since the code and the other documents cite
them; a done item keeps one line and points to where [design.md](design.md) describes it.

### Done

- **1.** Repository scaffolding.
- **2.** Service core: sync engine, group and pairing, discovery, member connections, control
   socket, command line; Linux without a desktop and tmux.
- **3.** macOS: the service as a LaunchDaemon and the pasteboard agent.
- **4.** Desktop connector: Wayland data-control, X11, GNOME through XWayland.
- **5.** iPhone: `/sync`, the pairing pages, the published shortcut.
- **6.** Simpler setup: QR codes, the generated shortcuts, the phone as the main device.
- **8.** Windows: the service, the clipboard agent and the installers; CI on windows-latest, not
   yet run on a real PC.
- **9.** Apps for iPhone and Android, which make the phone the group's root of trust
   ([design](design.md#the-phone-apps)); tested in CI, not yet on a real phone or in a store.
- **12.** Sync away from home through the group's own WireGuard tunnel: the hub, the phones and the
    lite member on Linux as clients, remote invitations for computers, the forwarder, the
    blind relay, AmneziaWG and VLESS ([design](design.md#sync-away-from-home)).
- **16.** Full members, admins and the device's system, in 0.3 and 0.4
    ([design](design.md#full-members-admins-and-the-operating-system)).
- **18.** Remote paste, in 0.6 ([design](design.md#remote-paste)).
- **19.** Sync modes, in 0.5 ([design](design.md#sync-modes)).
- **20.** Images, files, folders and formatted text, in 0.6
    ([design](design.md#images-and-files)).
- **21.** OpenWrt routers, in 0.6 ([design](design.md#openwrt-routers)).
- **23.** Docker, in 0.5 ([design](design.md#docker)).
- **24.** FreeBSD and OPNsense, in 0.6 ([design](design.md#freebsd)).
- **27.** Quick actions, in 0.6 ([design](design.md#quick-actions)).
- **30.** The phone as the hub while its app is open, in 0.5
    ([design](design.md#the-phone-as-the-hub-while-its-app-is-open)).
- **32.** What the forwarder and the relay learn, cut to short server credentials, in 0.6
    ([design](design.md#what-the-servers-learn)).

### Partly done

- **7.** Installers: the Linux, macOS, FreeBSD, OpenWrt and Windows installers, Homebrew, winget
   and releases with checksums and attestations are done; on SteamOS the Linux installer
   uses `/opt` and SteamOS's keep list (not yet run on a real Steam Deck); the signed
   `.pkg` for macOS waits for the Apple developer account.
- **11.** The lite member in Rust: done on Linux and OpenWrt. On the Arduino Nano ESP32 see item
    15; other ESP32 boards follow on the same `lite/core`.
- **13.** Device keys in hardware: done for Linux with a TPM; the Mac and Windows follow. See
    "Device keys in hardware" below.
- **14.** **The ZX Spectrum Next** through its own Raspberry Pi: `cbb next` on the lite member and
    the `.cbb` dot command (`apps/zxnext`) are written, not yet run on a real Next; the
    NextPi set-up and the path through the ESP8266 are next. The Accelerated Next carries a
    Raspberry Pi Zero on its accelerator header, wired to the FPGA's second UART, with
    NextPi (a read-only DietPi) and a root shell (`SUP>`) on that UART. The lite member runs
    on this Pi as an ordinary lite member, installed on the NextPi card itself (its user
    partition and a start script), so NextPi's own tools keep working. It speaks the member
    protocol with TLS 1.3 like any other member and reaches the network in one of two ways,
    both built: the Pi's own Wi-Fi on a Zero W, which NextPi turns off and we turn back on;
    or, on a Zero without a radio, the Next's built-in ESP8266, which then only carries the
    Pi's TLS bytes: the Z80 copies them between the Pi's UART and the ESP's, and the ESP
    never sees anything but ciphertext. A dot command on the Next, `.cbb`, talks to the lite
    member over the internal UART the way NextPi's own tools do (`.pisend`): it copies a text
    to the group, pastes the latest one, and joins by drawing the QR code for the phone app
    on the Next's screen (`cbb next`, lite/README.md). The UART is a trace on the Next's
    board and never leaves the case, so it carries the texts in the clear. The Pi converts
    between UTF-8 and the Spectrum character set: printable ASCII first, with every other
    character shown as `?`; Cyrillic follows later as an encoding of its own. No other
    device takes part: a Next without a Pi is future research (below), not a reason to lean
    on a computer in the group.
- **15.** **The Arduino Nano ESP32** (an ESP32-S3) as a lite member, on the same `lite/core` as
    the other ESP32 boards, with the member protocol and TLS 1.3 on the board itself. Done:
    the firmware (`lite/esp32`) builds, keeps its settings in flash, joins the Wi-Fi network
    set on its USB console, joins a group by the phone, passes its self-test in QEMU, and
    types as a USB keyboard in the layout set for the host; its network code
    (`lite/embassy`) also runs on Linux over a TAP interface, where CI has a Go member admit
    it by the phone. Next: sync on the board, OTA updates (item 29), and a library for one's
    own Arduino sketches may follow. It ships as a ready firmware flashed over USB with one
    command.
- **22.** **A Mac app** signed with Developer ID and notarized, when the Apple developer account
    is there, that carries the service and a Network Extension (a content filter): the
    system then keeps the service on the home network until sync away from home is on, and
    lets only the home network reach its port, as the systemd unit does on Linux and Windows
    Firewall on Windows. Until then the Mac has the service's own limit only
    (`internal/netguard`, and the member port's check of the address), which every computer
    has as well; macOS has no per-program limit without such an app (the application
    firewall allows or blocks a program, and pf is shared by the whole system), so this is
    the one difference between the computers, and it goes away with the app. The app's
    window and menu bar item over the installed service are there already (`apps/macos`,
    [apps.md](apps.md#the-mac-app)).
- **25.** Devices that are hard to type into: the Android TV variant of the app, the Nano
    ESP32's USB and Bluetooth LE keyboards (`lite/esp32/README.md`), the Android phone and a
    Linux computer as a Bluetooth keyboard ([apps.md](apps.md#android-the-bluetooth-keyboard),
    `cbb keyboard`), and a computer as the remote of an Android TV, a Google TV or a Roku
    (`cbb remote`) are done; the Apple TV, Samsung and LG remotes, and the remotes in the
    phones' apps, follow. See "Devices that are hard to type into" below.
- **26.** Watches: the notifications, both watch apps, the watch's admin key and its emergency
    actions are done ([design](design.md#watches)); prompt delivery on the iPhone waits for
    the Apple account.
- **28.** The blind relay: the open relay (`cbb relay -open`) with its limits, the choice in `cbb
    global relay` and in both phone apps, and the guide ([running your own
    servers](admin/self-hosting.md)) are done. Next: the project's relay on `cbb.tools`
    open to everyone, and AmneziaWG and VLESS on the relay.
- **29.** Secure updates: `cbb update`, automatic updates, the release passed through the group,
    the Android APK's own updates and the lite member's on Linux and OpenWrt are done
    ([design](design.md#secure-updates)); the project's root and release keys wait for the
    owner's hardware keys, then Sparkle in the Mac app and OTA on the Nano ESP32.

- **35.** The review of all the documentation against the code for 0.6: in progress.

### Next

- **42.** **Points 1 to 6, 8 and 9 are being built for 0.6**
    ([protocol.md](protocol.md), section 10; [records-v2.md](records-v2.md)), without a migration from `v:1`: groups made before
    are set up again; of point 4, the Welcome's format without a CA key is in 0.6 and the
    legacy path goes with item 17. Everything that changes the rules core or a format it
    reads or signs is done in 0.6, so 0.7 does not change the core: the Go service calls
    `cbb_core` too (natively on Linux, as WebAssembly elsewhere), for the records, every
    signed body and the certificate checks, and keeps its own code only as a test oracle. A simpler protocol for the group's authority, so that
    fewer of its rules can be read two ways. Today a signer's powers are derived from the
    records (whether a root is a computer, whether an admin CA is a phone's, a computer's or
    a watch's), removing an admin undoes what it signed so the remover lists in `keep` what
    stays, a freeze lists the records that stay in another way, the signer stands outside
    the signed body, signed bodies ignore unknown fields, four implementations evaluate the
    same rules, and the forwarder and the relay evaluate a group's records too. Every
    function stays, the open relay and forwarder among them. In order:
    1. **Records `v:2`**, one change of format: the record names its signer's key inside
       the body, and a body has one signer; the `device` record that names an admin CA says
       its powers from a closed list (admit, renew, remove members, remove admins, freeze,
       thaw, take over, be a hub, the commands it may sign), with defaults per role that
       give today's table; each signer numbers its records (`seq`, and `prev`, the ID of its
       previous one), so removing or freezing an admin, or handing the group over, says up
       to which number its records stay instead of lists of keys and record IDs, and two
       records of one signer with the same number freeze that signer and show it to the
       user; signed bodies (records, commands, server credentials, release files) refuse
       unknown fields and must be in one canonical form, which the receiver checks by
       encoding again. The root signs once a baseline record with the group's state in
       `v:2`; from then on only `v:2` records count, and once every member reads them the
       `v:1` rules go.
    2. **Servers check only server credentials** (protocol.md section 18): the forwarder
       and the relay stop taking a group's records, and a group has a period from the day it
       is made or upgraded. Both stay open to every group.
    3. **One rules core**: the phones use the lite member's Rust core (`cbb_core`) through
       bindings for Swift and Kotlin in place of their own evaluation of the records, with
       the result defined as one state (devices, powers, revoked, frozen, the path of roots)
       that the vectors and the differential fuzzing compare whole.
    4. **No CA keys between devices**: legacy groups must upgrade, and the Welcome carries
       no CA key (with item 17).
    5. **Features instead of versions**: the hello lists what the sender supports, each
       release names the oldest peer it takes, and the rules for members before that
       version go.
    6. **One form for each thing**, with the next ALPN version of each channel: one framing
       (a length and JSON), one fingerprint (SHA-256 of the SubjectPublicKeyInfo, one text
       form), one encoding of bytes.
    7. To decide: a fork of roots, two admins that freeze each other or two admin phones
       that remove each other show as a conflict in `status` and the apps, and while roots
       fork nobody new is admitted.
    8. Later: the hubs' order from a table the root signs (D-65) instead of one derived from
       the roles.
    9. **Manifests in the strict form**: the manifest of a media event (protocol.md section
       4) read by the rules of signed bodies (exact names, each once, valid UTF-8, integers
       of int64), with `null` only where its table allows it. Until then the four
       implementations' JSON readers decide names in another case, members written twice and
       invalid UTF-8 each in their own way, and the differential run
       ([differential.md](differential.md)) prints the manifests they read differently
       without failing on them.

- **10.** **Console helper and auto-paste**: the double press that injects the member's own text
    on the text console (design.md, "3. Console helper"), and Shift+Insert after a copy from
    a phone through the uinput helper (design.md, "Auto-paste"). The helpers themselves are
    done, as remote paste targets.
- **17.** **Removing the iPhone shortcut**, after TestFlight (the `shortcut` role), a legacy way,
    once the owner's Apple developer account puts the app on real iPhones: with it go the
    iPhone CA and its key on the admins, the shortcut endpoints and pages on the member port,
    the configuration profile and its plain-HTTP port, the tokens, and the rule for who
    holds `clipboardbridge.local`, which only the shortcut uses. The group then has one kind
    of trust, the member certificates, and no key that cannot be revoked by a record.
- **31.** **Key levels**: the user picks who may be the group's root, an admin or a hub: only
    devices whose hardware key is proven by attestation, devices with a key in hardware (the
    default), or, after a warning, devices with a key in a file too. The evidence and the
    marks are built, and so is the setting's format: `key_level` in the root's `settings`
    record ([protocol.md](protocol.md), section 10), which the state carries; the apps' setting and
    its checks are next. See "Key levels" below.
- **33.** **Researched; not built (D-73).** The iPhone as a hub in the background, as a Network
    Extension. See "Research: the iPhone hub in a Network Extension" below.
- **34.** **Collections** in the apps: the user's own sets of devices and the order of the tiles,
    arranged by dragging, personal to each app installation (D-72). The model, the same in Go,
    Kotlin and Swift against shared vectors, is done
    ([apps.md](apps.md#collections-and-the-order-of-the-tiles)); the apps' Arrange screens
    follow. See "Collections" below.
- **36.** **Russian versions of the documentation for users**, postponed: the README, the guide
    and the reference pages for users, in `docs/ru/` and `README.ru.md`; the documents for
    developers stay in English. The rule of D-8 then allows Cyrillic in those two places as
    well as in the apps' translations, and `tools/repocheck` checks that each Russian page
    has its English original with the same sections, so a translation cannot fall behind
    unnoticed. The Russian text uses the words of the apps' Russian translations.
- **37.** **Planned for 0.7.** Sync away from home for the lite member on MIPS routers. In 0.6 the
    lite member for mips and mipsle is built without the tunnel, since GotaTun, its
    WireGuard library, needs 64-bit atomics that 32-bit MIPS lacks; such a router syncs only
    at home. The aim is the full tunnel there too: GotaTun without 64-bit atomics, or
    another WireGuard for that build (design.md, "OpenWrt routers", step 5).
- **38.** **Planned after 0.6.** The Android app and Google: the project has a Google Play
    Console account (2026-10-27).
    - Before 2027, when Android installs sideloaded apps only from registered developers:
      register the package `io.github.hunterewok.clipboardbridge` there with the
      certificate of the release key that signs the APKs of the releases
      (docs/maintaining.md, "Android signing key"), so that those APKs and their own
      updates (docs/apps.md, "Updates") keep installing.
    - Whether the app goes to Google Play, and with which key: with Play App Signing, Play
      signs its copy with a key of its own, so the copy from Play and the APK of a release
      cannot update each other; the app already leaves a copy from a store to the store.
      Uploading with the release key itself keeps one key for both. The decision is the
      owner's, with the Wear OS app (which must share its key with the phone's) and the
      F-Droid build, planned at the end of 0.6 or in 0.7.
- **39.** **Rootless installs** (D-79), built in 0.6 and not yet run on a desktop session: a full member or a lite member on Linux installed and run without root,
    for a computer whose user has no `sudo` or does not want to give it. The service runs as
    the user's systemd user unit, with its files under the user's home; its hello and device
    record say `rootless`, and such a device is never the root, an admin or a hub, not even
    after a warning. It loses what the system install has: its own account, which keeps its
    keys from the user's other programs, systemd's sandbox and address limits, the TPM, the
    uinput and console helpers, the polkit rule of the quick actions, and the firewall rules.
- **40.** **Planned, after the Apple developer account.** Apple Vision Pro (visionOS):
    1. The iPad app on Vision Pro, in its compatibility mode, through TestFlight and the App
       Store; nothing to build.
    2. A visionOS build of the app: the kit and the app with visionOS among their platforms,
       without what visionOS lacks: the QR code scanner (the six digits instead), the watch
       link and the Live Activities. The clipboard, the Secure Enclave and Optic ID work as on
       the iPhone; like the iPhone, it syncs only while the app is open.
    3. Sync away from home there: gomobile builds no visionOS framework
       ([golang/go#65251](https://github.com/golang/go/issues/65251)), so the phones' tunnel
       needs another build of the same Go code or the lite member's tunnel in Rust.
- **41.** **Being built for 0.6**, with the rules core (item 42). Commands sealed for their receiver: a command's body (a
    paste's text among it) is signed but not encrypted, so a hub that passes a command on
    for a device the sender cannot reach reads it; since 0.6 only the hubs pass commands
    on. Each member gets a key for this beside its member key (X-Wing, ML-KEM-768 with
    X25519, so a recorded paste stays closed to a later quantum computer; the keys in the
    TPM, the Secure Enclave and the Keystore only sign), published in a statement its member
    key signs; the sender seals the body to it (HPKE, RFC 9180: X-Wing, HKDF-SHA256,
    ChaCha20-Poly1305; `internal/seal` and `cbb_core::seal`) with the open header (group, sender, receiver, ID, times) as its
    associated data, and signs the sealed command. A device that published no key gets a
    secret paste only directly. The same in Go, the lite member, both kits, with shared
    vectors and docs/protocol.md section 15.
- **43.** **Planned for 0.7.** What the app stores ask for, before the apps are submitted:
    - App Store (the iPhone, Apple Watch and Mac apps): a privacy manifest
      (`PrivacyInfo.xcprivacy`) with the reasons for the APIs that need them (`UserDefaults`,
      file times and the like), without which an upload is refused; and
      `ITSAppUsesNonExemptEncryption` in each `Info.plist`, with the export answer for the
      apps' encryption (standard algorithms) written down in docs/maintaining.md.
    - Google Play: the declaration for the accessibility service, which Play allows for an
      app that is not an accessibility tool only with a declaration in the console, a video
      and a prominent disclosure in the app before the user turns the service on; the Data
      safety form; the reason for the `connectedDevice` foreground service; the current
      target API level. The GitHub and F-Droid builds are not affected.
- **44.** More tools that check the code (all free and run only in CI, none ships in the
    product). Mutation testing of the records' code is done in 0.6 with the rules core
    (item 42); the rest is planned for 0.7, after the core settles:
    - Mutation testing, nightly, on the records' code only: cargo-mutants for `cbb_core` and
      gremlins for Go change the code (drop a check, turn `<` into `<=`) and report every
      change that no test notices, so a weakened check cannot go unseen.
    - golangci-lint with a few linters beside staticcheck: errcheck (an error left unread),
      exhaustive (a switch over the record kinds that misses one), gosec's G115 (an integer
      conversion that overflows), errorlint and bodyclose; first a clean-up of what they find.
    - Not Kani: tried on `cbb_core` in 0.6, its proofs did not finish on the parsers, which
      read JSON into `BTreeMap`, `Vec` and `String`; the property tests, the fuzzing and the
      mutation testing cover them instead.
    - goleak in the tests of the daemon, the relay and the forwarder: a goroutine a test
      leaves running fails it.
    - The Swift code that stays in Swift (the network, `AppModel`, `LiveGroup`): the
      Thread Sanitizer in the Mac app's CI job, then the Swift 6 language mode with its
      strict checks of concurrency.
- **45.** **Planned after 0.6.** Two things the rules core does not yet allow:
    - One device in several groups (a family's and a work group, or a phone that helps in a
      relative's group): every call into the core and every saved state names its group.
    - A temporary guest: a device record with an end date, after which the device leaves the
      group without being removed by hand.
- **46.** **Planned for 0.7.** Sync away from home through networks that block VPNs, on
    every member, the lite member included. There are two ways, equal options that the user
    or the server's operator picks, and more may join them: VLESS and AmneziaWG. VLESS comes
    in two kinds: with the site's real certificate, behind the server's own web server
    (XHTTP, which the site's nginx passes to the forwarder; the project's forwarder at
    cbb.tools runs it), or with REALITY, for forwarders without a web server. Every client
    speaks each of them; on the lite member VLESS comes first, then AmneziaWG and the blind
    relay ([below](#vless-behind-a-web-server)).
- **47.** **After TestFlight.** Back Tap on the iPhone in two taps: iOS lets no app make a
    shortcut or set Back Tap, so the app carries a signed shortcut file (`shortcuts sign
    --mode anyone` on a Mac) that runs its Sync clipboard action. A button "Add the
    double-tap shortcut", in Settings and after the first computer connects, opens it and iOS
    asks to add it; a card then gives the steps to Settings, Accessibility, Touch, Back Tap,
    Double Tap. The file names the release bundle identifier, so it waits for TestFlight; a
    copy for a Personal Team build tests it before.
- **48.** **Planned for 0.7.** The full name wherever a user reads it without typing it:
    the apps on the phones, the watches and the computers say "Clipboard Bridge" in their
    names, titles, menus, notifications, Shortcuts and Siri actions and the Mac's
    application bundle (today the iPhone's home screen, its Shortcuts actions and Siri
    phrases and `/Applications/CBB.app` say "CBB"). What a user types stays short: the
    command `cbb`, its subcommands and the paths. Icon labels show the full name too, even where the
    system shortens it: the iPhone's home screen, Android's launcher, the Windows Start menu
    and taskbar, the Linux desktop's menus and tray.
- **49.** **Planned for 0.7.** One set of languages across the project: every app (the
    phones, the watches, the Mac app, the tray app) speaks the languages of the website
    (Chinese, English, Spanish, Russian, Arabic, Swahili, Hebrew, Hindi) and offers a choice
    in Settings, System or one of them, remembered. Today only the phones offer System,
    English or Russian; the Mac app follows the system's language and the tray app the
    system's interface language on Windows and `LANGUAGE`/`LANG` on Linux. The command line
    (`cbb`, the lite member) picks the language from the locale, and English where the
    project has no translation for it. One list of the languages serves the site, the apps and
    the command line; Arabic and Hebrew lay the screens out right to left; a native speaker
    reads the new translations before a release.
- **50.** **Planned for 0.7.** A LuCI page on OpenWrt, `luci-app-clipboardbridge`, in the
    project's own apk feed: the group's devices and their state, adding a device with its
    QR code, sync away from home and the hub, the network zones; the same sections in the
    same order as the apps, in LuCI's own look. A JavaScript view with a small rpcd backend
    that asks the service over its control socket, with an ACL that allows only that. Later,
    after 1.0, when the protocol keeps backward compatibility: the official OpenWrt feeds,
    a package for `openwrt/packages` built from source with OpenWrt's Go or Rust package
    rules (likely the lite member, since the full `cbb` is too large for routers with 16 MB
    of flash) and the page for `openwrt/luci`, with a maintainer for each.

## Devices that are hard to type into

Partly built in 0.6: the TV variant of the Android app and the Nano ESP32's USB keyboard
(steps 1 and part of 4); the rest is next.

The aim: a text copied on any device of the group lands in a field of a device where typing
it is slow or impossible with what is in the user's hands, usually a TV remote or a gamepad.
Logins, Wi-Fi passwords, links, search queries and codes are the common cases. There are
four ways, from the one that needs least to the one that reaches most.

### 1. Our app on the device

Many such devices run Android, so the Android app reaches them with little more than a
layout for a remote:

- **Android TV, Google TV, Fire TV** and the Android set-top boxes and projectors: a TV
  variant of the Android app, with a launcher banner, a screen driven by the D-pad and no
  need for a touch screen. The TV shows the QR code and the phone scans it, so joining
  types nothing on the TV. Fire TV takes the signed APK of each release or the Amazon
  Appstore.
- **Android car head units, Android e-readers (Onyx Boox), Chromebooks** take the Android
  app as it is.
- **Meta Quest** (Horizon OS is Android) takes the APK; whether its accessibility service
  may put text into other apps is to be checked on a headset.

The app receives as it does on a phone, in its foreground service; a TV is receive only by
default (sync modes, item 19). The text goes into the field that has the focus through the
accessibility service (`ACTION_SET_TEXT`, or `ACTION_PASTE` after setting the clipboard),
on remote paste from any admin, so nothing is pressed on the TV. This is the Android target
of item 18, step 4.

### 2. The device's own remote, from a member

Most TVs can be driven over the home network by the maker's remote app on a phone, and those
apps can type into the field on screen. A member does the same: it pairs once with the TV as
its remote and, on remote paste, sends the text into the field. Nothing is installed on the
TV.

| Device | Protocol | Pairing | On the network |
|---|---|---|---|
| Android TV, Google TV | Android TV Remote v2, as in the Google TV app | a code shown on the TV | TLS |
| Apple TV | the Companion protocol of the Apple TV Remote, with its keyboard | a PIN shown on the TV | encrypted |
| Samsung (Tizen) | the TV's remote WebSocket API, port 8002 | allowed once on the TV | TLS |
| LG (webOS) | SSAP over WebSocket, port 3001 | allowed once on the TV | TLS |
| Roku | External Control Protocol, a key press per character | none | plain HTTP |

Apple TV is the main reason for this way: an iPhone already types on it with its own
keyboard, but Android, Linux and Windows have no way to, and a tvOS app cannot type into
other apps.

The rules:

- **The TV is a target, not a member.** It holds no key, gets no events and never joins the
  group; it belongs to the member that pairs with it, is shown under that member in the
  device list, and is addressed by remote paste (`cbb paste --on living-room-tv`) like the
  member's own screen. The member keeps the TV's pairing keys in its state.
- **Only on the home network.** The last hop leaves the group's encryption and is protected
  by the TV's own protocol, so a member reaches a TV only on its home network (the address
  checked as `internal/netguard` does) and never through the tunnel. Away from home, the
  text reaches the member through the tunnel and member TLS as always; only the member's
  last step to the TV is local.
- **Roku is off until the user turns it on** for that Roku, after being told that the text
  then crosses the home network in the clear.
- **The protocols are not all documented** (only Roku's is, and Samsung's in part), so
  firmware updates may change them; each one is ours in Go, with no third-party service
  and no maker's cloud, and a failure says which TV and protocol failed (the debug details
  as everywhere).
- **Who can be the remote.** Every computer, the routers and the Docker image (they are
  always on), and the Android app; the iPhone app too, where iOS lets it use the local
  network. The same remotes on Linux, Mac and Windows, and on both phones.

### 3. A phone or a computer as a Bluetooth keyboard

A device of the group that has Bluetooth can pair with the TV, console or tablet as a
Bluetooth keyboard and type what remote paste sends it, so no extra hardware is needed. The
paired device is a target of that member, as a TV is in way 2.

| Member | Bluetooth keyboard | Why |
|---|---|---|
| Android | yes, Android 9 and later | the HID Device profile (`BluetoothHidDevice`); a few makers leave it out, which the app detects and says |
| Linux | yes | BlueZ registers a keyboard profile; the service needs the Bluetooth adapter's permission, asked for at install |
| iPhone, iPad | no | iOS does not let an app act as a keyboard: the HID service is the system's own |
| Mac, Windows | no | neither has a public interface for the keyboard side of Bluetooth HID |

So in a group with an Android phone or a Linux computer near the TV, the iPhone sends the
text and that device types it. Bluetooth keyboards on Android and Linux are the one
difference within the phones and within the computers, and it is the operating system's:
iOS, macOS and Windows allow it to no app. Groups without such a device use the Nano ESP32
(way 4). The text crosses the air as a Bluetooth keyboard's does, with the link's own
encryption after pairing, a short hop next to the device; Enter and secrets follow the
same rule as the Nano ESP32 below.

### 4. The Nano ESP32 as a keyboard

For devices with no app and no protocol, and for groups with no Android phone or Linux
computer near them, the Nano ESP32 (item 15) plugs in or pairs as a keyboard and types what
remote paste sends it:

- **USB keyboard** (item 15): PlayStation 5, Xbox, Nintendo Switch in the fields that take a
  keyboard, TVs and set-top boxes with a USB port, KVM switches, BIOS and UEFI setup, boot
  loaders, servers without a network.
- **Bluetooth LE keyboard** (the ESP32-S3 has Bluetooth LE): Apple TV, Samsung and LG TVs,
  iPads, consoles that take a Bluetooth keyboard. The board keeps its pairings in flash.
- **Serial console:** its UART on the console header of a router, a switch or a server, or a
  USB serial adapter, typed as a terminal.

A keyboard sends key codes and the device's layout decides the characters, so the board
types Latin with a US layout first; other layouts are a setting per target, and Cyrillic
works where the target has a Russian layout to switch to. Login, disk encryption (LUKS,
BitLocker) and password screens are typed only on an explicit remote paste, with Enter a
separate permission (D-59), never on sync.

### Other devices

- **SteamOS**: in Desktop Mode the Steam Deck syncs as any KDE Plasma desktop, installed
  under `/opt` (item 7). Game Mode has no clipboard the desktop connector can use; remote
  paste types there through uinput (item 18, step 2).
- **iPad**: the iPhone app on iPad, built as a universal app.
- **Keenetic and other routers with Entware**: after OpenWrt, the same service with
  Entware's init scripts.
- **WSL and Termux** need nothing of their own: the Windows service and the Android app
  cover them.
- **Not reachable**: Kindle e-readers take neither apps nor keyboards; watches have apps of
  their own (item 26) but nothing worth typing into.

### Steps

One pull request each, smaller ones together:

1. The TV variant of the Android app, with the accessibility target of item 18, step 4.
2. Remotes in Go: Android TV Remote v2 and the Apple TV Companion protocol first, then
   Samsung and LG, Roku last; `cbb remote add` pairs a TV, and the apps add theirs (Android
   TV and Roku done in 0.6, untried on real TVs; for now the user sends a computer's remote
   pastes to one of its TVs with `cbb remote pastes`, as with `cbb keyboard on -pastes`,
   and addressing a TV by name with `cbb paste -on` comes with the device list's targets).
3. The Bluetooth keyboard on Android and Linux.
4. The Nano ESP32's Bluetooth LE keyboard, after its USB keyboard (item 15), the layouts,
   and the serial console (done in 0.6: `ble on` on its console).
5. The iPad build of the iPhone app (done in 0.6: CI tests it on an iPad simulator too,
   and a keyboard's shortcuts work).

The TV variant is part of the one APK of the phone app. For Apple TV the spike with pyatv is
done (2026-11-01, Apple TV 4K of the second generation, tvOS 27.2): the Companion protocol
pairs with a PIN shown on the TV and then sets the whole text of the focused field at once,
with no key presses, so the Companion protocol in Go comes next. The Bluetooth keyboard of a
Linux computer typed on the same Apple TV too (a Steam Deck, 2026-11-01), with two fixes to
make: the TV lists the computer twice under one name (its classic Bluetooth and the
keyboard over Bluetooth LE, the one with a battery), so the keyboard needs a name of its own;
and forgetting either entry on the TV forgets both, while the computer keeps its key and
then fails every connection ("PIN or Key Missing"), so the keyboard drops a bond its host
lost and becomes visible again. It typed in the TV's own layout: with Russian on the TV and
`-layout us` on the computer, "clipboardbridge ble 123" came out in Cyrillic, the
Russian letters on those keys, since a keyboard sends keys, not letters. For now the keyboard types as it is,
and the apps get a "switch the layout" action for the keyboard's device, with the quick
actions (restart and the others): the keyboard presses the device's shortcut
(Control-Space on Apple's). The Apple TV accepts a new
remote only while Settings, AirPlay and HomeKit, Allow Access is "Everyone on the Same
Network" (or "Everyone"); with "Only People Sharing This Home" it refuses every pairing, so
the app's steps and the user guide say to switch it before pairing. A keyboard types with
whatever layout the user sets for the target. In keyboard mode the Nano ESP32 swaps its
USB-JTAG console for a CDC console with a "reboot to flash" command, and a reset of its
settings also erases its Bluetooth pairings.

## Collections

Planned for 0.6 (D-72); the model and its rules are built ([apps.md](apps.md#collections-and-the-order-of-the-tiles)), the screens follow. A user with many devices puts them into collections and sets the
order of the tiles in every graphical app: the phones, the Mac app, the tray app, and the
watches, which show their phone's arrangement as sections.

- **The word.** "Collection", translated as such in the apps' String Catalogs: "group" is
  the sync group, "tag" the group tag, and "folder" will mean copied folders (item 20).
- **Personal.** Each app installation keeps its own arrangement beside its other settings
  (UserDefaults on the iPhone and the Mac, the app's preferences on Android, `desktop.json`
  in the tray app). A group record would need an admin's signature for every drag, would
  let two admins undo each other, would keep nobody but admins from arranging their own
  screen, and would bring the collections' names to the forwarder.
- **Simple.** One level; a device is in at most one collection; this device's own tile is
  always first. A device that joins goes to the end, a removed one leaves its collection.
- **Arranging.** An Arrange mode on every platform, as the iPhone's home screen has: drag a
  tile to its place, or onto another tile to make a collection. Every drag also has a menu
  item ("Move to collection…"), a VoiceOver and TalkBack action, and keyboard keys on the
  computers. A collection's tile shows how many devices it holds, how many are online, and a
  warning when one of them needs attention. Search and the filters "Online" and "Needs
  attention" help with many devices.
- **Display only in 0.6.** The device picker of remote paste follows the same order. Actions
  on a whole collection come later, if at all; remote paste to several devices at once never.

Per platform: SwiftUI's own grid reordering needs iOS and macOS 27 while the apps support
iOS 17 and macOS 14, so they use drop delegates; Android uses the `sh.calvin.reorderable`
library (Apache-2.0); the tray app uses pointer events of its own, not HTML drag and drop
(WebKitGTK bug 265857), and pauses its redraw of the list every 4 s while a drag is on.

Steps: the docs and a shared model with test vectors first, then the iPhone, Android, the
watches, the Mac and the tray app.

## Key levels

Partly built in 0.6 (D-66): each device's evidence, checked by the root, and where its key
lives in `cbb status` (the KEYS column) and the apps; the group's setting below is next. The owner's rule: the root, the admins and the hub hold keys in
hardware. A key in hardware cannot be copied, even from a device that is broken into; it
can only be misused on that device while the attacker holds it. A key in a file can be
copied once and used anywhere, for as long as nobody removes the device.

The user picks one of three levels for the group, at its root:

1. **Proven hardware only.** A device may be the root, an admin or a hub only when
   attestation proves its key is in hardware: Android's Key Attestation, a TPM with its
   maker's certificate, the iPhone through App Attest. This asks outside servers, and the
   guide says which: Apple's for each iPhone that makes a key, Google's public list of
   revoked attestation keys, and for some TPMs their maker's server. The public lists are
   mirrored on cbb.tools, signed like the releases (item 29), so the devices ask only us;
   the per-device requests (Apple, the TPM makers) cannot be mirrored. This level is the
   one exception to D-47, and only for a group whose user chose it.
2. **Hardware (the default).** The device's own word that its key is in hardware: the
   phones, a Mac's Secure Enclave, a TPM without its maker's certificate. Nothing about the
   device leaves the group, which is why it is the default (D-47).
3. **Files allowed.** A device whose key is in a file may also be an admin or the hub, each
   time after the user allows it, with a warning that the key can be copied and must be
   watched. A group of computers only, while they have no TPM or Secure Enclave support
   (D-44), works only at this level.

- A device that shows signs of being broken into (a jailbreak or root, an unlocked
  bootloader, a Keystore in software, which attestation reports) counts as a key in a file,
  and the devices list marks it. A custom system whose bootloader is locked again with its
  own key, such as GrapheneOS, counts as hardware.
- Decided after the research (D-70):
  - Proofs that need nobody outside the group (Android chains, a TPM whose maker's
    certificate is on the chip) mark a key "proven" at level 2 as well.
  - Level 1 accepts App Attest for Apple devices, and the guide says it proves a genuine
    copy of the app on Apple's hardware, not that our own key is in the Secure Enclave.
  - Level 1 accepts only Android chains issued through Remote Key Provisioning, since
    leaked factory keys can forge a green, locked attestation on a rooted phone.
  - Only level 1 asks Intel or AMD for a TPM's certificate. The address of that request
    names the TPM for good, so the user is warned first.
  - `cbb.tools` fetches Google's list of revoked attestation keys once a day and serves it
    signed. No device asks Google, and no copy goes into the releases.
  - Groups made before 0.6 are offered, never forced, a move of the root to a proven key.
- Found on the way:
  - Android keys made today carry no attestation challenge, so each phone makes a new key
    to be proven.
  - The Mac's service runs as a LaunchDaemon, and a daemon cannot use the Secure Enclave,
    so the signing moves to the user's LaunchAgent.
  - The Linux unit's `PrivateDevices=yes` hides `/dev/tpmrm0` and changes with the TPM
    work.
- Groups made before 0.6 keep working; one whose root or admins hold keys in files shows a
  warning and suggests moving the root to a phone.
- The guide "Keys and attestation" (docs/guide) says all of this plainly.

## Device keys in hardware

On the phones the member key and the root and admin keys live in the Secure Enclave or the
Android Keystore and cannot be exported. A Linux computer with a TPM 2.0 keeps its new
member, admin and tunnel keys there (built in 0.6, `internal/tpmkey`). On the other
computers the member key, the WireGuard key and the CA keys sit in files readable only by
the service, so whoever gets root on such a computer, or a copy of its disk, can copy them
and act as that device until it is removed. The plan, of which the Linux TPM part and the
marks in `cbb status` are built:

- **Hardware where there is some.** Linux and Windows keep the member key (P-256) and the
  admin key in the TPM 2.0 (Linux through the kernel's TPM device, Windows through the
  Platform Crypto Provider; the Go library go-attestation cannot make such keys on Windows,
  so the calls are our own), and a Mac in the Secure Enclave (Apple silicon or the T2
  chip), so the keys are used there and never leave it. WireGuard's X25519 is not offered
  by these chips; that key is kept sealed by the TPM or the Secure Enclave and opened only
  in the service's memory. A LaunchDaemon cannot use the Secure Enclave, so on a Mac the
  keys are used by the user's LaunchAgent on the service's behalf; on Linux the unit gives
  the service `/dev/tpmrm0` in place of `PrivateDevices=yes`.
- **Without hardware** (many Raspberry Pis and older PCs, Intel Macs without the T2): the
  key stays in a file readable only by the service, on Linux sealed with `systemd-creds`
  (by the TPM when there is one, else by the machine's own key readable only by root), on
  an Intel Mac in the system keychain. This protects a copy of the file alone, such as a
  backup or a memory card read elsewhere, not a device whose root is taken; it is said
  plainly rather than hidden. At home that is how every computer works today; for sync
  away from home such a device needs the user's separate consent (see "Turning it on, step
  by step").
- `cbb status` and the devices list show where each device keeps its key (hardware or a
  file), so the user sees which devices are weaker.
- **Regular renewal**: the member key and the WireGuard key are replaced on a schedule
  (the certificate renewal and a new tunnel key through the tunnel), so a copied key stops
  working even when nobody noticed the theft.
- Removing a device stays the main answer to a stolen key in every case.
- **Attestation.** A TPM can sign that a key was made inside it and cannot leave it, with a
  chain up to its maker's certificate (the endorsement key); Android's Key Attestation does
  the same with Google's root, and App Attest proves a genuine copy of the app on Apple's
  hardware. How these mark a device, and which of them ask a server outside the group, is
  in "Key levels" above (D-66, D-70). What attestation does not do: it does not stop malware
  on the device itself from using the key while it runs there, and it is no stronger than
  the chip.

## VLESS behind a web server

Item 46, decided by the owner on 2026-11-01, for 0.7. Today VLESS runs only inside REALITY
([design](design.md#blocked-networks)): the forwarder listens on TCP 443 itself and borrows
another site's TLS. A server that already serves a site on 443, as cbb.tools does with
nginx, cannot do that, and the lite member cannot speak REALITY at all: REALITY needs a
browser's ClientHello and its own check inside the session ID, which rustls does not
make. So VLESS gets a second kind beside REALITY, with the site's real certificate behind
a web server; neither replaces the other. VLESS and AmneziaWG stay two equal ways, and the
user or the server's operator picks the one their network lets through; more ways may
join them later. REALITY suits forwarders that people run on servers of their own without
a site.

- **The transport.** VLESS over XHTTP over TLS, as cbb.tools' nginx already passes VLESS
  for other uses. The web server (nginx) ends the TLS with the site's own certificate and
  passes one path to the forwarder's VLESS listener on the loopback address; every other
  request gets the site. XHTTP is plain HTTP requests that nginx passes as they are;
  WebSocket is the fallback if a client cannot carry XHTTP.
- **What stays the same.** VLESS carries WireGuard's UDP packets (VLESS's UDP command,
  each packet with its length), the forwarder passes them to its own UDP port and routes
  them as every packet, by `mac1` and the indices, and the group's VLESS user ID is let in
  only while its hub is registered. VLESS and the web server add no security and the
  design does not rely on them: the boundary stays the member TLS, then WireGuard. The web
  server sees the VLESS user ID and WireGuard packets, nothing more; that location keeps no
  access log.
- **The forwarder.** Its operator picks the transport: REALITY as today, or XHTTP with the
  public host and the path the web server passes, the forwarder listening only on the
  loopback address. The path is made at random and kept in the forwarder's key file; it
  keeps scanners off the VLESS listener and is not a secret the design relies on. The
  forwarder tells a registering hub which transport it runs and its settings.
- **The hub's offer** (docs/protocol.md, sections 11 and 13) names the transport: today's
  `public_key`, `short_id` and site for REALITY, or the host, port and path for XHTTP, with
  the group's VLESS user ID either way. A client that does not know the transport says that
  it needs an update and stays at home; it never falls back to plain WireGuard, which would
  show the network what it hides.
- **Clients.**
  - `cbb` and the phones' tunnel (`mobile/cbbtun`): Xray-core has VLESS over XHTTP; its TLS
    uses Xray's browser fingerprint (uTLS), so the ClientHello looks like a browser's.
  - The lite member: a VLESS and XHTTP client of its own in `cbb_core` (sans-I/O, `no_std`
    with alloc, so the ESP32 can have it later), on the TLS it has (rustls with the
    RustCrypto provider), with VLESS's own encryption (ML-KEM-768 with X25519, as
    Xray-core's) when the forwarder asks for it. It checks the site's certificate against
    the public CAs (the Mozilla list built in, or the system's bundle on Linux and OpenWrt),
    which its member TLS never needed. GotaTun's packets go over that connection instead of
    its UDP socket.
  - Interop vectors for the VLESS header, the XHTTP framing and the encryption in
    `testdata/interop`, checked against Xray-core, and a test of the lite member against
    the Go forwarder in CI's `lite` job.
- **Risks.** rustls' ClientHello is not a browser's, and a censor that singles out TLS
  fingerprints (JA3, JA4) may notice it; a real site and its certificate still hide far more
  than plain WireGuard, and the order of the cipher suites and extensions can be brought
  closer to a browser's. WireGuard over TCP adds latency on a lossy network (TCP inside
  TCP), which a clipboard tolerates.
- **cbb.tools.** `site/deploy/nginx.conf` gains the XHTTP location, which reads the path
  from a file made on the server (as `cbb-preview.conf`), so the path stays out of the
  repository; `site/README.md` gains the step, and the forwarder runs with XHTTP.
- **Then, on the lite member:** AmneziaWG (its changes to WireGuard's packets: junk
  packets, shifted sizes and headers, padding) as a layer around GotaTun's UDP socket,
  ported from amneziawg-go (MIT, already in `internal/third_party/amneziawg-go`) to a
  sans-I/O layer in `cbb_core` under `src/third_party`, checked against it with interop
  vectors, an end-to-end test against a hub with `-obfuscate` and fuzzing of the incoming
  packets, so the lite member also reaches an obfuscated hub (today `lite/src/tunnel.rs`
  refuses one). WireGuard's Noise and keys stay GotaTun's; the layer recomputes `mac1` for
  the changed message types. Padding inside the encrypted packets and random rekey times
  live inside GotaTun and need a small patch of it (`[patch]` in `lite/Cargo.toml`, as for
  the ring stand-in). Then the blind relay (item 28), which the lite member does not reach
  yet.

Steps: the protocol and the Go forwarder and hub first, with Xray's XHTTP transport; then
the phones' tunnel; then the lite member's client and its vectors; then cbb.tools' nginx
and forwarder; then the guide for blocked networks (with its translations), the reference
and the bench's cases for a network that blocks WireGuard (P20, S9, F7), run from a real
network that blocks VPNs; then AmneziaWG and the relay on the lite member.

## Future research (not planned)

Questions to study before anything is planned for them.

- **A ZX Spectrum Next without a Pi**, on its own hardware only: no other device in the
  network may do its part. Three paths, in the order to try them:
  (1) the Z80N is the member itself and the built-in ESP8266, with its stock AT firmware,
  only carries the TCP bytes, so the ESP never sees anything but ciphertext; TLS 1.3, the
  P-256 signatures and X25519 in Z80N assembly would take minutes per connection (one
  X25519 is estimated at 5-20 s), then the connection stays open and texts move at
  several KB/s; (2) our own firmware for the ESP-01, which then is the member and the
  Z80 only shows the text, with about 80 KB of RAM for TLS 1.3 and at the cost of the AT
  programs that need the stock firmware; (3) an ESP32 module in place of the ESP-01 in
  its socket, running `lite/core`, if such a module exists for that socket. To measure:
  the cost of P-256 on the Z80N and the RAM a TLS 1.3 member needs on the ESP8266.
- **No gateway and no plain tier.** A device too weak for the member protocol does not
  lean on another member over the network to do its part, neither through a gateway with
  a simpler encrypted protocol nor in the clear. Such a device joins through hardware of
  its own (the Next's Pi, an ESP32 on the board) or not at all. Arduino boards whose
  Wi-Fi chip runs its own TLS (Uno R4 WiFi, Nano 33 IoT, MKR WiFi 1010) cannot be lite
  members, because that TLS gives no access to the exporter the member protocol needs,
  so they are not supported; boards without a network are not either.

### Research: the iPhone hub in a Network Extension

Researched for 0.6 and not built (D-73). Today the iPhone is the hub only while its app is
open, and that stays. The one way known to keep it running in the background is a Network
Extension, a packet tunnel provider, and each condition for it fails or is doubtful:

1. **Apple's rules.** Guideline 5.4 allows VPN apps only from developers enrolled as an
   organization, and App Review applies it to every app that installs a VPN profile; the
   project's Apple developer account is a personal one. Guideline 2.5.4 and Apple's TN3120
   ("Do not use a packet tunnel provider to host a network listener or proxy server") make a
   rejection likely in any case.
2. **One VPN at a time.** iOS keeps one tunnel-type VPN on; any other VPN app turns ours off
   and stops its on-demand rules. Per-app VPN, app proxies and DNS proxies need a managed
   device.
3. **Memory.** A packet tunnel extension gets 50 MiB on iOS 15 to 26. cbbtun's hub alone uses
   about 4 MiB with no clients and 11 MiB with 256 on Linux, so a small group would fit only
   after tuning (the forwarder code pulls Xray-core into the hub, gVisor allows 1 MiB per
   connection), and the Swift member node comes on top.
4. **The cost.** A hub on cellular keeps the radio from idling (a packet every 15 s to the
   forwarder plus each client's keepalive every 25 s); there are no published measurements.

Instead, a computer, the router or a Docker container is the hub, a group without one uses
the blind relay (item 28), and a second hub (D-65) covers the hours the first is off.

Found on the way and worth fixing anyway: the phones' member key is kept with the keychain's
"when unlocked" accessibility, so nothing in the background can use it while the phone is
locked.
