<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Roadmap

What comes next, the designs that are agreed but not built yet, and the questions to study
before anything is planned. How Copy Beyond Borders works today is in [design.md](design.md),
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
- **5.** The first iPhone support, without the app; replaced by the app (item 17).
- **6.** Simpler setup: QR codes, the phone as the main device.
- **8.** Windows: the service, the clipboard agent and the installers; CI on windows-latest, not
   yet run on a real PC.
- **9.** Apps for iPhone and Android, which make the phone the group's root of trust
   ([design](design.md#the-phone-apps)); tested in CI, not yet on a real phone or in a store.
- **12.** Sync away from home through the group's own WireGuard tunnel: the hub, the phones and the
    lite member on Linux as clients, remote invitations for computers, the forwarder, the
    blind relay, AmneziaWG and VLESS ([design](design.md#sync-away-from-home)).
- **16.** Full members, admins and the device's system, in 0.3 and 0.4
    ([design](design.md#full-members-admins-and-the-operating-system)).
- **17.** Every phone joins through its app, with a key of its own, in 0.6 (D-80;
    [design](design.md#group-and-pairing)).
- **18.** Remote paste, in 0.6 ([design](design.md#remote-paste)).
- **19.** Sync on and off, in 0.6 ([design](design.md#sync-on-and-off)).
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
- **48.** The name Copy Beyond Borders, short CBB, in 0.6 ([BRAND.md](../BRAND.md#the-name)):
    CBB under the icons, the full name in the stores, the docs and the site; the apps'
    identifiers start with `tools.cbb`.

### Partly done

- **7.** Installers: the Linux, macOS, FreeBSD, OpenWrt and Windows installers, Homebrew, winget
   and releases with checksums and attestations are done; on SteamOS the Linux installer
   uses `/opt` and SteamOS's keep list (not yet run on a real Steam Deck); the signed
   `.pkg` for macOS waits for the Apple developer account.
- **11.** The lite member in Rust: done on Linux and OpenWrt. On the Arduino Nano ESP32 see item
    15; other ESP32 boards follow on the same `lite/core`.
- **13.** Device keys in hardware: done for Linux and Windows with a TPM (Windows not yet
    tested on a real PC) and for a Mac's Secure Enclave; sealing the Mac's tunnel key
    follows. See
    "Device keys in hardware" below.
- **14.** **The ZX Spectrum Next** through its own Raspberry Pi: `cbb next` on the lite member and
    the `.cbb` dot command (`apps/zxnext`) are written, not yet run on a real Next; the
    NextPi set-up and the path through the ESP8266 are next (see "The Next's network in the
    background" below). The Accelerated Next carries a
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
    servers](admin/self-hosting.md)) and the project's open relay on `cbb.tools` (`cbb global
    relay default`) are done, and so is a new key or address for the project's relay without
    a release (`keys.json` and `entries.json`, [maintaining.md](maintaining.md)). Next:
    - the relay's own key in the signed `keys.json` from the first `release-sign publish`
      (`-relay cbb.tools:8765=...`), before the relay ever gets a new key;
    - the rotation run once on the Windows virtual machine, as the other changes;
    - "The project's relay" in both phone apps and on the lite member: today a phone enters
      the relay's address and key by hand and the lite member has no relay; the kits would
      take the relay's keys and address from the signed lists they already keep, as `cbb`
      does;
    - AmneziaWG and VLESS on the relay.
- **29.** Secure updates: `cbb update`, automatic updates, the release passed through the group,
    the Android APK's own updates and the lite member's on Linux and OpenWrt are done
    ([design](design.md#secure-updates)); the project's root and release keys wait for the
    owner's hardware keys, then Sparkle in the Mac app and OTA on the Nano ESP32.

- **34.** **Collections** in the apps: the user's own sets of devices and the order of the
    tiles, personal to each app installation (D-72), are done: the model, the same in Go,
    Kotlin and Swift against shared vectors
    ([apps.md](apps.md#collections-and-the-order-of-the-tiles)), and the Arrange screens on
    the iPhone and the iPad, on Android, in the Mac app and in the tray app; both watches show
    their phone's collections as sections. See "Collections" below.
- **35.** The review of all the documentation against the code for 0.6: in progress.
- **42.** **A simpler protocol for the group's authority**, so that fewer of its rules can be
    read two ways ([protocol.md](protocol.md), section 10; [records-v2.md](records-v2.md)).
    Done in 0.6, so that 0.7 does not change the core, without a migration from `v:1` (groups
    made before are set up again):
    1. records `v:2`: the signer inside the body, powers written down, each signer's records
       numbered, two records with one number shown as two histories, and signed bodies in one
       canonical form that refuses unknown fields;
    2. the servers check only server credentials (section 18) and read no records; both stay
       open to every group;
    3. one rules core, `cbb_core`, for the phones (through Swift and Kotlin bindings), the lite
       member and the Go service (natively on Linux, as WebAssembly elsewhere), which keeps
       its own rules only as a test oracle;
    4. no CA keys between devices, and a Welcome without one;
    5. features instead of versions in the hello;
    6. one form for each thing: one framing, one fingerprint, one encoding of bytes;
    7. a fork of roots, two admins acting against each other or two claims stop the group,
       shown as a conflict in `status` and in every app, until the root decides;
    9. manifests in the strict form: the manifest of a media event (protocol.md section 4) is
       read by the rules of signed bodies in their canonical form (exact names, each once, none
       its table does not name, no null, valid UTF-8, integers of int64), in Go, the core and
       both kits alike, and the differential run ([differential.md](differential.md)) fails on
       a manifest they read differently.

    Later, point 8: the hubs' order from a table the root signs (D-65) instead of one derived
    from the roles.

### Next

- **10.** **Console helper and auto-paste**: the double press that injects the member's own text
    on the text console (design.md, "3. Console helper"), and Shift+Insert after a copy from
    a phone through the uinput helper (design.md, "Auto-paste"). The helpers themselves are
    done, as remote paste targets.
- **31.** **Key levels**: the user picks who may be the group's root or an admin (a trusted hub is one): only
    devices whose hardware key is proven by attestation, devices with a key in hardware (the
    default), or, after a warning, devices with a key in a file too. The evidence and the
    marks are built, and so is the setting's format: `key_level` in the root's `settings`
    record ([protocol.md](protocol.md), section 10), which the state carries, `cbb keys` with
    its checks on a root computer, and the phone apps' setting (Settings, Admin keys) with
    theirs. Level 1's outside checks (App Attest, the TPM makers' services) are next. See "Key levels" below.
- **33.** **Researched; not built (D-73).** The iPhone as a hub in the background, as a Network
    Extension. See "Research: the iPhone hub in a Network Extension" below.
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
      register the package `tools.cbb` there with the
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
      target API level. The GitHub and F-Droid builds are not affected. Found in the
      study of Play's rules (2026-11-02):
        - The disclosure is its own screen, reached from Home (a card "Send my copies by
          themselves, optional") and not only from Settings; it says what the service reads
          and what it does not, with "Agree" and "Not now" (Back counts as "Not now"); only
          "Agree" opens Android's accessibility settings, and the switch in Settings shows
          the service's real state. Play turned down another app in 2026 for a disclosure
          reached only through Settings.
        - Remote paste through the same service is its own point in the disclosure, the
          listing, the declaration and the video; a change in what the service does needs
          a new declaration.
        - The service asks for no more than it uses: whether `canRetrieveWindowContent` and
          events from every app are needed for noticing a copy, or only for remote paste's
          focused field (to be tried on a real phone).
        - Android 17's Advanced Protection takes the accessibility service away from every
          app that is not an accessibility tool: the app notices it (and an OEM that turned
          the service off after a reboot), switches to sending with one tap and says why.
        - The listing names the tunnel for sync away from home (Android's VpnService) and
          the accessibility service; targeting API 37 adds a declaration for
          `ACCESS_LOCAL_NETWORK`.
        - IzzyOnDroid reviews an accessibility service by hand and has a policy on code
          written with AI: a short paragraph that explains both is ready before applying.
    - App Store, from the study of Apple's rules (2026-11-02): the review notes say how the
      reviewer sees sync work (a video and a group with its QR code) and that the tunnel
      for sync away from home runs inside the app, not as a VPN (rule 5.4 is for VPN
      services); a privacy policy linked in the metadata and in the app; the store text
      promises no automatic sending on the iPhone (iOS allows no background reading of the
      clipboard: Share, the Action button, Back Tap, a widget, Control Center); an external
      TestFlight group needs a beta description, a feedback address and the first build's
      beta review.
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
- **46.** **XHTTP in 0.6 for `cbb`, the phones and the lite member.** Sync away from home through networks that block VPNs, on
    every member, the lite member included. There are two ways, equal options that the user
    or the server's operator picks, and more may join them: VLESS and AmneziaWG. VLESS comes
    in two kinds: with the site's real certificate, behind the server's own web server
    (XHTTP, which the site's nginx passes to the forwarder; the project's forwarder at
    cbb.tools runs it), or with REALITY, for forwarders without a web server. Every client
    speaks each of them; the lite member on Linux speaks AmneziaWG and VLESS over XHTTP in
    0.6 (the owner, 2026-11-07), not REALITY; the ESP32 and the blind relay come later
    ([below](#vless-behind-a-web-server)).
- **47.** **After TestFlight.** Back Tap on the iPhone in two taps: iOS lets no app make a
    shortcut or set Back Tap, so the app carries a signed shortcut file (`shortcuts sign
    --mode anyone` on a Mac) that runs its Sync clipboard action. A button "Add the
    double-tap shortcut", in Settings and after the first computer connects, opens it and iOS
    asks to add it; a card then gives the steps to Settings, Accessibility, Touch, Back Tap,
    Double Tap. The file names the release bundle identifier, so it waits for TestFlight; a
    copy for a Personal Team build tests it before.
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
- **50.** **Planned for 0.7.** A LuCI page on OpenWrt, `luci-app-cbb`, in the
    project's own apk feed: the group's devices and their state, adding a device with its
    QR code, sync away from home and the hub, the network zones; the same sections in the
    same order as the apps, in LuCI's own look. A JavaScript view with a small rpcd backend
    that asks the service over its control socket, with an ACL that allows only that. Later,
    after 1.0, when the protocol keeps backward compatibility: the official OpenWrt feeds,
    a package for `openwrt/packages` built from source with OpenWrt's Go or Rust package
    rules (likely the lite member, since the full `cbb` is too large for routers with 16 MB
    of flash) and the page for `openwrt/luci`, with a maintainer for each.
- **51.** **Planned for 0.7, research.** Arduino boards whose Wi-Fi module is an ESP32, as
    devices of their own: the Uno R4 WiFi (an RA4M1 with an ESP32-S3 module), and the Nano 33
    IoT, MKR WiFi 1010 and Nano RP2040 Connect (u-blox NINA-W10x, a classic ESP32). Our
    firmware on the module makes it the lite member (`lite/core`, TLS 1.3, joining by the
    phone's QR code), and the board's main chip only types the texts as a USB keyboard and
    shows them, over the UART or SPI already between the two, in frames like `cbb next`'s:
    the split of the ZX Spectrum Next, where the Pi is the member and the Z80 only types.
    Everything runs on the board's own hardware, so it is no gateway. The cost: Arduino's
    own Wi-Fi firmware is gone while ours is on (its updater puts it back). To find out:
    whether each module takes new firmware without an external programmer (the Uno R4
    WiFi's through Arduino's own tool, NINA through the SerialNINAPassthrough sketch), and
    whether a classic ESP32 (520 KB of RAM, no PSRAM) holds `lite/core` with TLS 1.3, which
    builds today for the C6 and the S3 only. The Uno R4 WiFi first.
- **52.** **Planned for 0.7.** A clipboard history in the phone apps, where the system keeps
    none (the iPhone has none, even in iOS 27; Android only on some phones). The computers
    keep using the system's history (Klipper, Win+V, Spotlight), where received copies
    already land. The history:
    - stays on the device; it is never synced between the group's devices;
    - is off by default, one switch turns it on;
    - keeps entries for a time the user picks (1 hour, 1 day, 7 days), with a "Clear" button;
    - is encrypted with the device's key (Secure Enclave, Android Keystore);
    - never holds copies marked as secret (password managers' marks);
    - can be searched, and an entry is sent again with one tap.
    docs/apps.md's principle "no history" changes to say this. Why: users of the other
    clipboard tools ask for a history more than for almost anything else, and phones lack
    one.
- **53.** **Planned for 0.6, before the launch.** What a sceptical reader checks first,
    found by reading the project as one would (2026-11-02):
    - Done in 0.6: Android's automatic sending skips a copy that carries
      `android.content.extra.IS_SENSITIVE`, as the computers skip the password managers'
      marks.
    - Done in 0.6: the guides (privacy, how it works, keys, away from home) and the README
      say "end to end" for the clipboard only once it was true (D-84): who reads the copies,
      the two kinds of hub, and what the devices that pass a copy on still see; the forwarder's addresses, timing and sizes on the site and in the guides;
      the status notes and the README's status link in the guides of keys and away from
      home; "each signature" of the root's and the admins' keys only; "only over TLS" linking what is not encrypted; winget named only where
      it says "once the package is in winget's repository"; docs/security-audit.md says it
      is a plan.
    - Done in 0.6: the README's trust model ("Who can read what": who holds which key, who
      reads the copies, who admits devices, what the hub, the forwarder and the relay see;
      the pairing code as the only secret), one line on what
      is tested, a security section with links, the comparison with KDE Connect, ClipCascade
      and Universal Clipboard with its weak points, an install that checks SHA256SUMS first,
      links to the ports and to removing it, and how the project is built. Still to do: a
      picture of the keys, screenshots.
    - The repository's description and topics on GitHub, so that a search for "clipboard
      sync" finds it (the owner sets them).
    - Done in 0.6 on the website: the first screen's title says what it does ("Copy on one
      device, paste on another", also in the link picture), the iPhone card says the app
      comes with TestFlight, no "trademarks", no "the one that does all of it", no "simpler"
      for the recommended computer, X11 and Wayland instead of "any desktop", the privacy
      page's keys in a TPM or Secure Enclave and the forwarder's addresses, timing and
      sizes; the Chinese "全程", the Swahili "haimripoti" and "huru"/"huria", Hindi's
      pairing and Hebrew's mixed singular and plural fixed; `dir="ltr"` on code and no
      letter spacing in Arabic and Hebrew. Still to do: the trust facts above the fold,
      Hebrew's prepositions before links, Hindi's mixed terms, links that wrap a whole page
      title, and a native speaker's read of each language before the launch.
- **54.** **Planned for 0.6, before the launch.** Support for the project: a
    `.github/FUNDING.yml` and a `funding.json` (the format FLOSS/fund reads), once the
    author's GitHub Sponsors and Liberapay accounts exist, and a short "Support" section in
    the README: what the money pays for (the Apple developer account, the forwarder,
    devices to test on), that a donation buys no priority, and the commercial license for
    companies. No paid features, no "license key" in the apps and no paid tier on the
    forwarder: the app store builds may later be the same free code at a small price. Grants
    after the launch: the GitHub Secure Open Source Fund, then FLOSS/fund once the project
    has users; NLnet's calls since 20 October 2026 do not fund code written with generative
    AI.
- **55.** **Built for 0.6 (the owner, 2026-11-03): the mirror over VLESS, the release from the group, and the hub fetching the archives its members install; the lite member and the Android APK do not take them from the group yet.** Updates through the group's ways
    out, for devices on networks that block GitHub or the mirror. GitHub stays reached
    directly, as now. Where the user switched AmneziaWG or VLESS on, the mirror on cbb.tools
    is reached only through them: over VLESS the forwarder lets a group's registered VLESS
    user ID reach the mirror on its own server as well as its UDP port, and nothing else, so
    the server still gives no way to the internet; with AmneziaWG the devices get the
    update from the group, inside its tunnel. The members already pass the signed release
    to each other (the `release` message, docs/protocol.md section 16); the archives follow
    over the member protocol ([design](design.md#where-updates-come-from)), so about one
    device per group asks the internet, and each still checks the signatures itself; `cbb update` asks the group when GitHub and the mirror do not answer. The
    Android app's APK the same way where it can. `dl.cbb.tools` is not set up yet: it comes
    with this item, on the same server.
- **56.** **Built for 0.6 in `cbb` (the owner, 2026-11-03): a hub registers over VLESS, each group has an XHTTP path of its own, and the signed entry points (`entries.json`) pass from cbb.tools, the `channel` branch, the group and a string or QR code (`cbb global entries`); the phones and the lite member take, keep and (the lite member) pass on the list, a phone hub registers over VLESS through its ways, and a hub whose forwarder does not answer says in every app when its list is stale (2026-11-04).** A hub that reaches its forwarder
    only over VLESS, for a phone hub on a trip in a network that lets nothing else through.
    The project's forwarder's VLESS settings (XHTTP, cbb.tools, port 443, the path) are built
    into `cbb` and the kits beside its key, as they are no secret the design relies on; a
    forwarder of one's own prints them with its key (`cbb forward`), and the user enters
    them once. A hub keeps what the forwarder's answer says and uses that afterwards. It
    tries TCP and UDP 8764 first and VLESS on 443 after them, as its clients do: over VLESS
    go the registration (its TLS, with the forwarder's key pinned, inside VLESS) and the
    hub's own tunnel packets, and the forwarder passes the clients' packets to such a hub
    over that connection instead of UDP (docs/protocol.md, sections 11 and 13).
    Nothing secret is compiled in: the builds stay reproducible (F-Droid) and the code
    public. Instead the built-in path, and the `xhttp://host/path#key` string or QR code of
    one's own forwarder, serve only a hub's first registration: the forwarder then gives each
    group a data path of its own (random, kept with the group's registration), the hub hands
    it to its clients in the offer, and the forwarder carries the group's packets only on
    that path. The entry points (domains, ports, registration paths, the forwarders' keys)
    are also published as a signed list in the release channel (`cbb.tools/channel/`, signed
    with the channel key), so a blocked entry is replaced without a release; hubs and clients
    pick the list up. Every device fetches the list with its update check, whether or not
    VLESS is on, and takes it from any source, as the signature is what it trusts: cbb.tools,
    the `channel` branch on GitHub, any member of its group (over the member protocol, as the
    signed release), or a QR code or string another device shares; when none of them answers
    and the list is stale, the app says so and where to get a new one. Later, once there is a spare domain or a CDN: several domains, or
    Cloudflare in front of XHTTP, in the same signed list, as the name a network sees in TLS
    is what it can block.
- **57.** **Planned for 0.7 (the owner, 2026-11-03).** Push notifications on the iPhone, so
    that a copy and the group's events reach it while its app is closed (Android needs
    none: its foreground service keeps the connections). A member or the hub asks the
    project's push service on cbb.tools to notify the phone; the service holds the APNs keys
    and the phones' device tokens, never a group's keys. A Notification Service Extension
    (about 30 seconds and 24 MiB) opens what is sealed to that phone: a short copy (a push
    carries 4 KiB) shown with a "Copy" button, or a line that a larger copy or a file waits.
    The service sees the tokens and the times, not the content: the privacy page says so,
    and push can be switched off. Back Tap, the Action button and Share stay
    as they are. To check on a device: whether the extension may put the text in the
    clipboard without a tap, and whether Back Tap's 5 seconds are enough away from home
    over VLESS (iOS allows about 30).
- **58.** **Planned for 0.6 (the owner, 2026-11-04).** Sync away from home by consent (D-82):
    the device's user consents once, at install, at pairing or in the app, and the root or an
    admin then turns it on and makes hubs from the app, without a command on each computer
    (see [Consent to sync away from home](#consent-to-sync-away-from-home)).
- **59.** **Planned for 0.6, before the release (the owner, 2026-11-06).** The stores' signing,
    set up before 0.6 is tagged, since an Android app's key can never change once its APKs
    are installed:
    - One release key for every Android channel: the key that replaced 0.5.0's on 2026-11-03
      (alias `cbb`, certificate SHA-256 `16:99:CD:37:…:7C:E6:B3:6D`), which the environment
      **release** already holds. Write its fingerprint in docs/maintaining.md, "Android
      signing key"; 0.5.0's APK is signed by the old key, so 0.5.0 does not update to 0.6.0
      in place (no compatibility before 1.0.0).
    - RuStore, Android: upload the release's signed `cbb-fdroid-X.Y.Z.apk` (the flavor
      without an update of its own and without Wear OS), not an AAB, so that RuStore never
      holds the key and its copy, the GitHub APK and F-Droid's share one certificate. The
      app already leaves a copy from a store to its store (docs/apps.md,
      "Updates").
    - RuStore, Aurora OS: the developer certificate with the profile `regular` (issued
      2025-12-05 by Open Mobile Platform's root, valid until 2049) signs the Aurora build's
      RPM, and every test build that reaches a phone too (the workflow `aurora`, after the
      maintainer's approval): not the public test key ("Noname developer"), which 5.2's
      installer refuses, and a change of certificate installs only after the app is removed,
      which removes its key. What a
      `regular` app may do on Aurora 5.1.5 was measured on a device (2026-11-06): it listens
      and is reached over Wi-Fi in the background, mDNS works both ways, the OP-TEE
      PKCS#11 token makes non-extractable P-256 keys that sign, it writes the clipboard from the
      background but reads another app's copy only in the foreground (so the phone sends
      on a gesture: opening the app, a notification or Share), and a second executable in
      the package is installed without its execute bit.
    - F-Droid: the steps in docs/maintaining.md, "F-Droid", with `AllowedAPKSigningKeys`
      set to that certificate. The fdroid flavor already has no update of its
      own (`SELF_UPDATE` false, no installer permission), as F-Droid's inclusion policy
      requires: an app it publishes must not download or install code outside F-Droid.
- **60.** **Planned (the owner, 2026-11-06).** The app for Aurora OS (`apps/silica`), in Qt 5.6 with Silica
    QML around the Rust core through `cbb_call` (docs/core-api.md), one binary with its
    libraries, since the installer leaves a second executable in a package without its execute
    bit: two packages from one
    code, one for Aurora 4 and one for Aurora 5 (5.1 and 5.2), since the two have different
    SDKs, sandbox permissions and installers. The Aurora 5 package is built with the SDK of
    the oldest 5.x it supports, 5.1.5 (each release has its own SDK on OMP's site), for both
    armv7hl (phones with a 64-bit kernel and a 32-bit system, such as the F+ R570E) and
    aarch64, and tested on a 5.1.5 phone first; the app reads `VERSION_ID` in
    `/etc/os-release` for what differs within a major version. The same code makes a third
    package for Sailfish OS, built with the Sailfish SDK for armv7hl
    and aarch64 and published in Jolla's store or OpenRepos: only the installer, the signing
    and the key store differ, so the platform layer keeps them apart from the start and CI
    builds all the packages. Sailfish ships together with Aurora (the owner, 2026-11-06),
    tested only in the Sailfish SDK's emulator and marked as not yet tested on a phone,
    for the community to try, as the Android app first was. All three packages build
    (2026-11-06; CI's `Aurora app` jobs): Sailfish's passes Jolla's store check
    (`rpmvalidation`), and Aurora 4's keeps its key in a file too, as no Aurora 4 phone has
    been measured for a key in its TEE.
    Sailfish has no TEE key through PKCS#11, so its key is a file (level 3). Its key fits
    [Key levels](#key-levels) as the other phones' do:
    - Level 2, "hardware", the default. How the key is kept, measured on the R570E with
      5.1.5 (2026-11-06): the app asks Aurora's QCA keystore (provider
      `qca-aurora-pkcs11`, keystore `USERAPP`, PKCS#11 provider `cktee`, PIN `0000`) once
      to initialize its token, which gives the app a slot of its own in OP-TEE (model
      "Aurora TA"; another app sees the same slot number empty); then, through `libckteec`
      directly, it logs in with that PIN and keeps a P-256 key there with `CKA_TOKEN`,
      `CKA_SENSITIVE` and not `CKA_EXTRACTABLE`. The key is found again after the app's
      restart and the phone's reboot, refuses its value and signs. QCA itself handles only
      RSA and GOST keys and aborts the process when the keystore holds an EC key, so the
      app never calls QCA again once its key is there. The app checks that the key is in
      OP-TEE, not in a software token that sets the same flags: `/dev/tee0` and
      `libckteec` are there, the token is the initialized "Aurora TA" one, and the key
      reads back `CKA_NEVER_EXTRACTABLE` and `CKA_ALWAYS_SENSITIVE`. Nothing about the
      device leaves the group (D-47).
    - Level 1, "proven", only when the group's user chooses it, as everywhere, and only
      if Aurora offers key attestation (a proof that the key was made in the TEE, not only
      that the system is unmodified): 5.1.5 has none, and whether the attestation that 5.2's
      release notes list covers keys is to be checked in its SDK later, with no date, once
      phones with 5.2 exist. Until then an Aurora phone is never "proven".
    - The package for Aurora 5 is meant to run on 5.2 too, without level 1; the SDK's 5.2
      emulator checks it first (the clipboard, which 5.2 reworked, and the network), and,
      having no OP-TEE, the file key's path: the app says its key is not hardware and is no
      admin without the user's consent.
    - A phone without OP-TEE keeps its key in a file and is an admin or the hub only at
      level 3, after the user allows it.
    - Ed25519 works in the same token when the template names `CKA_KEY_TYPE`
      (`CKK_EC_EDWARDS`) and `CKA_EC_PARAMS` is the printable string `edwards25519`;
      `CKM_EDDSA` needs a `CK_EDDSA_PARAMS`, since `libckteec` crashes on a null parameter.
    - Removing the app removes its token and key: a reinstalled app finds its slot
      uninitialized again, initializes it through QCA and joins as a new device.
- **61.** **Planned for 0.6, before rc.1 (the owner, 2026-11-06).** Make sure the ways out
    carry only cbb and never lead to the internet: the forwarder, VLESS (REALITY and XHTTP)
    with the mirror, the relay and the hub's tunnel, on every member and both phones. This
    rests on the code (the forwarder only passes WireGuard packets between a group's hub
    and its clients, VLESS's one outbound goes to the forwarder, its registrations or the
    mirror whatever the client asked for, the hub's in-process stack opens only the member
    port and forwards nothing), with no route, NAT or firewall rule needed on the server.
    Done: tests in which a client that is not ours asks for other addresses, TCP and UDP,
    IPv4, IPv6 and names, the server's own loopback services among them, and reaches
    nothing: VLESS over REALITY and XHTTP (`internal/vless/onlycbb_test.go`: packets reach
    only the forwarder's port, streams only the mirror, the registrations' ID neither), the
    hub's tunnel (`internal/tunnel/onlycbb_test.go`), the phones' hub
    (`mobile/cbbtun/onlycbb_test.go`), the relay (`internal/relay/onlycbb_test.go`) and the
    lite member's tunnel, whose end a fake hub on GotaTun sends to (`lite/src/tunnel.rs`,
    `link_reaches_nothing_from_the_tunnel`); the forwarder's `FuzzForwardWire` sends a
    packet only to an endpoint it knows. The check of cbb.tools is written down in
    docs/maintaining.md, "Ways out carry only cbb", and was run on 2026-11-07.

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
   TV, Apple TV and Roku done in 0.6, untried on real TVs; for now the user sends a computer's remote
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
with no key presses; the Companion protocol in Go (`cbb remote add -appletv`) followed in
0.6. The Bluetooth keyboard of a
Linux computer typed on the same Apple TV too (a Steam Deck, 2026-11-01), with two fixes to
make: the TV lists the computer twice under one name (its classic Bluetooth and the
keyboard over Bluetooth LE, the one with a battery), so the keyboard needs a name of its own;
and forgetting either entry on the TV forgets both, while the computer keeps its key and
then fails every connection ("PIN or Key Missing"), so the keyboard drops a bond its host
lost and becomes visible again. It typed in the TV's own layout: with Russian on the TV and
`-layout us` on the computer, "cbb ble 123" came out in Cyrillic, the
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

Built in 0.6 (D-72; the model and its rules in [apps.md](apps.md#collections-and-the-order-of-the-tiles)). A user with many devices puts them into collections and sets the
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
lives in `cbb status` (the KEYS column) and the apps; the group's setting below is next. The owner's rule: the root and the admins hold keys in
hardware. A trusted hub is an admin and follows it; a hub that only passes copies on reads
no copy and needs no key in hardware (D-84). A key in hardware cannot be copied, even from a device that is broken into; it
can only be misused on that device while the attacker holds it. A key in a file can be
copied once and used anywhere, for as long as nobody removes the device.

The user picks one of three levels for the group, at its root:

1. **Proven hardware only.** A device may be the root or an admin only when
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
3. **Files allowed.** A device whose key is in a file may also be an admin, each
   time after the user allows it, with a warning that the key can be copied and must be
   watched. A group of computers only, while they have no TPM or Secure Enclave support
   (D-44), works only at this level.

- A computer that is the group's root counts as a key in a file, whatever its TPM or Secure
  Enclave holds, since the group's CA key, which signs the records and the certificates, is
  kept in its identity file; `cbb new` therefore starts its group at level 3. Next: make the
  root's CA key in the TPM or the Secure Enclave, as the member and admin keys are, and
  count such a root as hardware.
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
  - A group is offered, never forced, a move of the root to a proven key.
- Found on the way:
  - Android keys made today carry no attestation challenge, so each phone makes a new key
    to be proven.
  - The Mac's service runs as a LaunchDaemon, and a daemon can use the Secure Enclave
    after all: a key that no keychain keeps needs no entitlement, and the service keeps
    the enclave's encrypted copy of it (checked on a Mac with macOS 27).
  - The Linux unit's `PrivateDevices=yes` hides `/dev/tpmrm0` and changes with the TPM
    work.
- A group whose root or admins hold keys in files shows a warning and suggests moving the
  root to a phone.
- The guide "Keys and attestation" (docs/guide) says all of this plainly.

## Device keys in hardware

On the phones the member key and the root and admin keys live in the Secure Enclave or the
Android Keystore and cannot be exported. A Linux computer with a TPM 2.0 keeps its new
member, admin and tunnel keys there (built in 0.6, `internal/tpmkey`), and so does a
Windows PC (through TBS, under Windows' own storage root key). On the other
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
  in the service's memory. On a Mac the LaunchDaemon itself uses the Secure Enclave (built
  in 0.6, `internal/sekey`, through Security.framework); on Linux the unit gives
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

Item 46, decided by the owner on 2026-11-01. In 0.6 (moved there by the owner on 2026-11-03):
the forwarder's XHTTP behind a web server (`cbb forward -vless-xhttp`), the transport in the
hub's offer, and the clients in `cbb` and the phones' tunnel, the default on cbb.tools
([design](design.md#blocked-networks)). Also in 0.6 (the owner, 2026-11-03): a hub that sets
VLESS speaks AmneziaWG too, and its clients try AmneziaWG over UDP first and VLESS after it,
never plain WireGuard; the client's XHTTP reuses its connections and spaces its uploads at
random, with Xray's usual numbers. Brought into 0.6 (the owner, 2026-11-07): the lite member's
AmneziaWG and its VLESS client over XHTTP on Linux. Left for 0.7: VLESS's own encryption. Before it, VLESS ran only inside REALITY: the forwarder
listens on TCP 443 itself and borrows another site's TLS. A server that already serves a site on 443, as cbb.tools does with
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
  - The lite member, on Linux only (the owner, 2026-11-03: not on the ESP32, whose memory
    it would not fit, and after AmneziaWG): a VLESS and XHTTP client of its own in
    `cbb_core` (sans-I/O, `no_std` with alloc), on the TLS it has (rustls with the
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
- **First, on the lite member (built in 0.6):** AmneziaWG (its changes to WireGuard's packets: junk
  packets, shifted sizes and headers, padding) as a layer around GotaTun's UDP socket,
  ported from amneziawg-go (MIT, already in `internal/third_party/amneziawg-go`) to a
  sans-I/O layer in `cbb_core` under `src/third_party`, checked against it with interop
  vectors, an end-to-end test against a hub with `-obfuscate` and fuzzing of the incoming
  packets, so the lite member also reaches an obfuscated hub (today `lite/src/tunnel.rs`
  refuses one). WireGuard's Noise and keys stay GotaTun's; the layer recomputes `mac1` for
  the changed message types. Padding inside the encrypted packets and random rekey times
  live inside GotaTun and need a small patch of it (`[patch]` in `lite/Cargo.toml`, as for
  the ring stand-in). The same layer serves the ESP32 later. As built, the layer is
  `lite/src/awg.rs` (checked end to end against the Go hub), and the VLESS client
  `lite/src/vless.rs` over HTTP/1.1 with `cbb_core::vless`, checked against the Go forwarder
  behind a web server (`TestLiteMemberAwayXHTTP`); the blind relay (item 28) comes later.

Steps: the protocol and the Go forwarder and hub first, with Xray's XHTTP transport; then
the phones' tunnel; then the lite member's client and its vectors; then cbb.tools' nginx
and forwarder; then the guide for blocked networks (with its translations), the reference
and the bench's cases for a network that blocks WireGuard (P20, S9, F7), run from a real
network that blocks VPNs; AmneziaWG and VLESS on the lite member came in 0.6, the relay later.

## The Next's network in the background

Item 14 on a Pi Zero without a radio. The owner's choice (November 2026): the Pi stays in
the group while any program runs on the Next, and a text from the group is typed into
whatever program has the keyboard, without leaving it. Running a dot command to sync, or a
terminal of our own, was turned down: nobody leaves a program to paste. What the bench
showed first: `.pibridge` (apps/zxnext) carried 12.5 KB of the Pi's shell through the ESP8266
without a lost byte once the Z80 ran at 28 MHz, while at 3.5 MHz a polling loop lost bytes
after about 1 KB.

**What NextZXOS gives.** An installable driver (`.install`) is 512 bytes of code, may take
8K banks of memory, and is called on every frame's interrupt, 50 times a second, while
NextBASIC and most programs run; four may be installed. The keyboard driver can be replaced
by one of 512 bytes, and the API document names a buffer of several keys as a use. Each of
the two UARTs has a 512-byte receive buffer and a 64-byte send buffer; port 0x133B says when
the receive buffer overflowed, and port 0x163B turns on hardware flow control, which on the
Pi's side uses GPIO 16 and 17 (the ESP honours it only on an issue 4 board). NextZXOS's own
`uart.drv` and `espat.drv` are interrupt-driven drivers of this kind.

**The pieces.**

- *The driver on the Next* is a dumb pipe and a key feeder. On each interrupt it moves the
  ESP's received bytes into a frame towards the Pi, the Pi's frames for the ESP into the
  ESP's send buffer, and the Pi's paste frames into a key buffer in its own bank. It restores
  the UART selection it found, so the program in front is not disturbed. It knows nothing of
  AT commands, TCP or TLS.
- *Keys.* One character a frame goes into the ROM's `LAST_K` with the new-key flag, as the
  ROM's keyboard routine does: 50 characters a second, so a text of 1 KB types in 20
  seconds. Programs that read the keyboard through the system take it: NextBASIC, the
  editors, most applications; games that read the ports themselves do not.
- *The lite member on the Pi* runs `cbb service` as a service from the user partition
  (`/NextPi`) and drives the ESP through the pipe: AT commands, then passthrough to one
  member or the hub, the member protocol with TLS 1.3 on the Pi, so the ESP sees only
  ciphertext. The stock firmware (AT 1.2) holds one passthrough connection, which is enough
  for a lite member that dials one peer. A new `cbb next link` holds the Pi's UART for the
  frames.
- *Frames on the Pi's UART.* A start byte, a type (bytes from the ESP, bytes for the ESP,
  a paste, a status), a length and the bytes; the start byte doubled inside a frame. The
  UART is a trace inside the case, so it carries no encryption of its own; the texts in
  paste frames are already the user's, as on every other member's screen.

**Time.** The Pi Zero has no clock of its own (NextPi keeps a saved time, which is wrong
after every power-up), and TLS checks certificates against the time. The Next has a
battery-backed DS1307 that NextZXOS reads (`.date`, `.time`), so the driver or `.cbb` reads
it at the start and sends it to the Pi in a frame of its own, and the lite member sets the
system clock. The DS1307 keeps local time without a zone, so the lite member takes the zone
from its own setting; the group's time is the fallback when the Next's battery has run down.

**What NextPi gives** (read on the bench, NextPi 1.91D): the user partition `/NextPi` is
writable and on the shell's `PATH` (`/NextPi/nextpi`), and NextPi's start script runs
`/NextPi/nextpi/autoexec.sh` when it exists, so the lite member is installed and started
without touching the read-only root. The shell on the UART is a systemd service that
restarts bash at once; GPIO 16 and 17 are plain inputs, so there is no RTS and CTS, and
flow control towards the Next is XON and XOFF.

**Speeds.** At 115200 baud the 512-byte buffer holds about two frames' worth of bytes, so
one missed interrupt (a long SD card access runs with interrupts off) loses data. The ESP
runs at 19200 baud instead (`AT+UART_CUR`), about 2 KB a second, which a text and a TLS
handshake need, with more than 0.2 s of margin; a lost byte breaks the TLS session, and the
Pi dials again. Towards the Pi, the driver stops the Pi with XOFF (NextPi's terminal has
`ixon`).

**On the bench (November 2026).** Paired through the ESP, synced at home, and away from
home through the hub's tunnel over the ESP's UDP: a text sent from a phone reached the Pi
through the Mac's hub and `.cbb paste` typed it. The member connection through the tunnel
still reconnects now and then on a read timeout; on a link of 2 KB a second the timeouts
the other members use are short. `cbb next link` starts the service when none runs, since
NextPi starts nothing of ours at boot. Not yet: a phone on a mobile network through the
forwarder to the hub, with the Next behind it.

**Installing.** `.cbb install` (0.5.0) does what was agreed with the owner, except the
signature (apps/zxnext/README.md, "Install"):

- The files for the Next are published on `cbb.tools` over plain HTTP, since NextZXOS's
  `.http` has no TLS: `CBB`, `CBB.DRV`, the Pi's `cbb` for ARMv6, and a list
  with each file's size, CRC-32 and SHA-256 (`packaging/zxnext/site.sh`, the release's
  `cbb-zxnext.tar.gz`). Each `CBB` carries the size and SHA-256 of the driver and the Pi's
  `cbb` built with it (`apps/zxnext/pins.sh`) and installs only those (0.6); the release
  key signs the list as `zxnext.json` (0.6).
- One line fetches `.cbb` into `C:/DOT`: `.http -h cbb.tools -u /zxnext -f CBB`, then `.cbb install` fetches
  the rest through the ESP and keeps them in `/cbb` only. Each file is checked against the
  list before it replaces the old one, a download that broke goes on from where it
  stopped, and a line shows the percentage, the kilobytes, the speed and the time left;
  SPACE stops it.
- The Pi's `cbb` goes from the card to `/NextPi/nextpi` through the UART with the same line,
  and the Pi checks its SHA-256 before it swaps the binary.
- `CBB` itself is as trustworthy as the network `.http` fetched it over; one taken from the
  signed release and copied to the card is not. `.cbb update` (0.6) takes a newer `CBB` and
  its files only from the signed `zxnext.json`, which the `cbb` already on the Pi checks
  against its pinned roots (`cbb next check-list`), so that an update needs no trust in the
  network.
- The Pi's `cbb` is sent at 460800 baud, at 115200 when the Pi's tty does not take it or
  the copy comes damaged; a real Next measured 31 to 32 KB/s, against 9 at 115200. Next
  (0.7): a faster step first, 921600 (the line's limit is about 92 KB/s, but the card's reads
  and the Pi's writes take part of it, so about 50 to 60 KB/s), then 460800 and 115200.
  The Pi Zero's UART has a 16-byte buffer and no flow control here, so a speed it loses
  bytes at fails the SHA-256 check and the next step down sends again.
- `.cbb paste`, `copy` and `text` go over the running network: the driver (0.2) carries
  them to `cbb next link` in frames of their own, as it carries the ESP's bytes, and the
  link runs their `cbb next` as NextPi's shell would. Only `.cbb pair` still stops the
  network for the shell.
- `CBB` lives in `C:/DOT`, so `.cbb` runs from any folder, and its rarer commands are in
  `/cbb/CBB.OVL`, read into a page of their own when they run, so `CBB` stays under the 64K
  a real Next reset at.

**Open questions, for the bench.**

1. The shell. NextPi's shell (`SUP>`) holds the Pi's UART, and `.cbb` and Terminex use it.
   `cbb next link` runs under that shell and gives it back on exit; whether it should
   instead keep the shell inside, on a pseudo-terminal of its own, and hand its bytes
   through unframed while Terminex is open, decides how a text is pasted into the Pi's
   shell. Terminex reads the Pi's UART itself, so the driver must leave that UART alone
   while it runs; how the driver tells (the UART selection it finds, or a key) is to be
   tried.
2. Copying from the Next: a key in the driver that sends the current BASIC line or a marked
   part of the screen, or `.cbb copy` through the driver's API.
3. Whether the driver and the replacement keyboard driver should be one, and how much of the
   key buffer fits in 512 bytes.

Steps: the frames and `cbb next link` on the Pi, tested on Linux against a program that
plays the driver; the driver in assembly, built with z88dk, tried with `.pibridge`'s
counters on the bench; then the keys; then the shell and copying.

## Consent to sync away from home

Planned for 0.6 (item 58, D-82). Today a computer turns sync away from home on only with
`cbb global on` typed on it, so the root phone's "Make it a hub" is refused on a computer
where nobody did that yet (D-45). The owner asked for one consent per device instead, given
when the device is installed or joins, after which the group's root and admins switch it
from their apps, at home or away from home.

**The consent.** A setting of the device, kept in its state, that only its own user changes:

- Given at install: the installers ask, as they ask about updating themselves, and
  `--global on|off` (or `CBB_GLOBAL`) in `get.sh` and `install.sh` on Linux, macOS and
  FreeBSD, and `-Global on|off` in `get.ps1` and `install.ps1`, answer ahead; the lite
  member's installers ask the same, `.cbb install` on the ZX Spectrum Next asks Y or N, and
  the ESP32's console has a setting. The question is `[y/N]`: without an answer it stays off.
- Given or taken back later: `cbb global consent [on|off]` on a computer (with root or as
  administrator, as every change of the group), a switch in the phone apps' settings and on
  their first screen, the tray and Mac apps' settings.
- On a device whose keys sit in a file the consent is given only together with the separate
  warning of D-45 (step 3 of "Sync away from home" in the design): the installer and
  `cbb global consent on` show it and ask for it, and without it the consent counts as not
  given. Rootless installs (D-79) consent the same way and stay clients.
- Taking the consent back does not turn sync away from home off by itself; `cbb global off`
  does. It only stops the root and the admins from turning it on.

**What it allows.**

1. A device with the consent turns sync away from home on by itself once it is in a group
   (after pairing, or at once when the consent comes later): it makes its tunnel key and
   offers it to the group's hubs as `cbb global on` does now. A group with no hub yet only
   keeps the key. This holds for devices that are never a hub or an admin too (keys in a
   file, rootless, a lite member): they go online at once and keep their role, whoever asks.
2. A new signed command `away-on` (protocol section 15) from the root or an admin turns it on
   again on a device that has the consent, for example after an `away-off`; without the
   consent the device refuses it and says so. A watch never signs it.
3. A `hub` command to a device with the consent turns sync away from home on there first,
   then makes it a hub. Who may be a hub does not change: an admin, at the group's key level
   (D-66), never a rootless install (D-79), never a lite member; phones only as D-64 says.
4. A device turned off by `away-off` or by its own `cbb global off` does not turn itself on
   again at the next start; only `away-on`, a `hub` command or its user do.

**What the others see.** The hello gets `away_consent` (`true` from a device whose user
consented, for its kind of keys), shown and never trusted, and the device record carries it too, copied from the hello when an
admin signs the record (at admission and at each renewal), so the apps show "Turn on sync
away from home" and "Make it a hub" only where they will work, and say why elsewhere.
`cbb status` shows the consent on each device.

**The system's limit.** On Linux and Windows the second line of defence outside the program
(the systemd drop-in, the `cbb-home-only` rule) is widened only with root, so it is widened
where root is at hand and nothing of ours runs as root for it later:

- With the consent the installer (with `sudo`, or as administrator) writes the project's
  forwarder and relay at once, `cbb.tools` by the built-in entry points, as
  `cbb global allow` does now; `cbb pair`, which runs with root as well, adds the group's
  hubs, forwarder and relay from the Welcome. A device switched on from an app then reaches
  its hub through the forwarder at once.
- When the group's servers change later (a hub reached at its own address that moves, a
  self-hosted forwarder or relay), the program's limit follows by itself and the system's
  lags behind: `cbb status` and the apps say so and ask for `sudo cbb global allow` (on
  Windows, as administrator), as they do now.
- A `hub` command makes a hub that its clients reach through the group's forwarder, which
  the limit already allows. A hub at its own address needs its UDP port open to everyone (on
  Windows the inbound rule, on Linux a unit that allows every address), so that stays
  `sudo cbb global hub` on the device.
- **"Hub on its own address" in the computers' apps (the owner, 2026-11-04).** The Mac app
  and the tray app on Linux and Windows offer it on their own computer, never on a phone,
  which has no public address. It says plainly what it needs: a public IP address on the
  router (not behind carrier-grade NAT, which many mobile and some home providers use), the
  hub's UDP port forwarded on the router to this computer, and that port open to the whole
  internet, though only the group's devices get an answer. Before it may be turned on, the
  app checks that the address really is public and reachable: the hub asks `cbb.tools` to
  send a packet back to its public address and port, and only when that packet arrives does
  the switch turn on. Otherwise it says why (no public address, or the port not forwarded)
  and suggests a hub through the forwarder, which needs neither. With the user's yes it
  runs `cbb global hub` elevated, as the pair QR button runs `cbb pair` (pkexec, UAC, the
  administrator's password on a Mac), which opens the port in the system's firewall.
- Without the consent the installers write nothing beyond the home network. A Mac keeps the
  program's limit only, as now; the lite member has none of its own.

**Steps.** The protocol (the hello field, `away-on`, the interop vectors) and the Rust
core's checks of the command; the Go service, its control operation and the installers; the
lite member; the phone kits and the apps' screens; then the guide (sync away from home) and
its translations, and design.md in place of this section.

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
  members with their stock firmware, because that TLS gives no access to the exporter the
  member protocol needs; with our firmware on that chip they may be (item 51). Boards
  without a network are not supported.

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

**Looked at again on 2026-11-03, with Android and the user's own VPN.** The finding stands,
and one point weighs more than the rest: today's tunnel (`mobile/cbbtun`) is an app's own
traffic, so it runs beside any VPN the user has on, and CBB's packets simply go inside that
VPN. A packet tunnel on the iPhone or a `VpnService` on Android would take the phone's one
VPN slot: turning on one's own VPN would stop sync away from home, and the other way round.

- **Android needs none of it.** The app's foreground service (`connectedDevice`) already
  keeps its connections and the tunnel in the background, which an iPhone app cannot do.
  `VpnService` would add the VPN key icon, the "allow a VPN connection" prompt and the slot
  conflict, and gain nothing; `addAllowedApplication` narrows what it carries, not the slot.
- **The iPhone without a VPN.** Background app refresh stays (a few seconds now and then,
  docs/apps.md). Push notifications, now that the Apple developer account exists, are the
  real way: a member or the hub asks the project's server to push (the APNs keys stay on
  the server), and a Notification Service Extension, woken by a visible notification for up
  to about 30 seconds with about 24 MiB, opens a small copy sealed to the phone (a push
  carries 4 KiB) or shows that a copy waits. Silent pushes are throttled by iOS and only
  help now and then. This belongs with the notifications work after TestFlight.
- **An optional mode.** A packet tunnel offered only as an opt-in "keep the hub on in the
  background" for people with no VPN of their own still meets guideline 5.4 (an
  organization's account), TN3120 and the memory limit above; it is not planned. Should
  the project register as an organization later, this is the one case to look at again.
