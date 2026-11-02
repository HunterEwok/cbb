# Changelog

All notable changes to clipboardbridge are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- A single-colour glyph for the Mac's menu bar and the tray on Windows and Linux: the app icon's
  clipboard and key, in three states (no group, in a group, another device online). `tools/icon`
  makes the Mac's template images, the symbolic SVGs for Linux and white and black ICOs for
  Windows from the drawings in `apps/design/icon/tray`.
- The phones seal their commands too: a paste, a mode, an action or a hub command to a device
  whose record has a key for sealed messages carries its orders sealed to that key, through
  the core's new `seal_command` (docs/core-api.md). A computer or a lite member sends its key
  in its pairing info, so a phone records it as it admits the device, and keeps it when it
  signs the record again; the core's devices list gives it (`seal`). A receiver whose record
  has a key refuses a paste in the open (docs/protocol.md, section 15, "Sealed commands").
- The phones have keys for sealed messages of their own: a secret in the keychain, or under a
  key of the Android Keystore, whose public key (the core's new `seal_public`) goes in the
  phone's device record when it makes a group or joins one, so the commands for a phone come
  sealed too. The core's `group_command` opens them with the secret, and refuses a paste in the
  open for a device whose record has a key, for the phones as for the members.
- The apps show what stops the group: the phones on Home, the Mac app and the tray app above
  the devices, in a card that says what is stopped, why, and who decides (a claim to take the
  group over with the time left, two admins acting against each other, a key that signed
  two histories, a newer version of the records). On the group's root the card offers the
  way out: cancel a claim by removing its device, remove one of two admins, or void both
  histories (`cbb resolve`). The phone kits read it from the state (`GroupAlerts`).
- A key that signed two histories signs nothing until the group's root resolves them; once
  the root voids both branches, the key goes on from the record below the fork, and what it
  signs counts (docs/protocol.md, section 10, "Going on after two histories").
- `cbb resolve`: on the group's root computer, voids both histories of every key that signed
  two; the admin computer whose key it was signs again by itself what it signed since its
  last backup (`signed.json` in the state directory keeps its log).
- Before a record its user asks for, a computer waits up to 10 seconds for another member's
  records, so that one brought back from a backup does not sign a number it signed already.
- The phone's Send or receive says where a text went or came from and that it is ready to
  paste ("Ready to paste: “…” from Mac.lan", "Sent to Mac.lan"), with a tap in the hand while
  the app is in front; the Shortcuts action (Back Tap) shows its progress while it connects,
  and with Live Activities the Dynamic Island says so.
- `apps/ios/device.sh` installs the iPhone app and its watch app on your own phone and watch,
  signed by a free Personal Team (an Apple ID in Xcode, no developer account), with a bundle
  identifier of its own; CONTRIBUTING.md, "The iPhone app on your own phone".
- The Mac app and the tray app list the device they run on too, first and marked as this
  Mac or this computer, as the phones do, and count it in "N of M online".
- The Apple Watch and Wear OS apps list their phone too, first and marked as the watch's
  phone, as the phone's own list has it.
- The Apple Watch app and the Mac app have the app's icon (`tools/icon` draws them too); before,
  watchOS and macOS showed an empty one.
- The key-level setting's format: the root's `settings` record may carry `key_level`
  (`proven`, `hardware` or `files`; docs/protocol.md, section 10), and the group's state carries it, in
  Go and the Rust core alike. The apps' setting and its checks come later.
- The computers apply the group's stop when its records show a likely thief (docs/protocol.md,
  section 10, "Stopping the exchange"): while two admins act against each other, two claims
  or a disputed claim wait, or a key signed two histories, their connections carry records
  only, or no secret leaves them, until the group's root decides. `cbb status` says what
  stops, why, and what ends it, and shows the claims to take the group over with the time
  left.
- A recovery key for a group whose phones are all lost (docs/records-v2.md, "The recovery
  key"): the root names an offline admin key in a `recovery` record, and that key may only
  claim the group, waiting the delay the root set for admins and cancelled the same ways. The
  state names it in `recovery`; Go and the Rust core agree on shared vectors. The apps make
  the key later.
- The core's entry point reads a remote invitation (`read_invite`, docs/core-api.md): the
  invitation, or the stable reason it is refused, for the phones to use later.
- Sealed commands: a computer seals a command's orders (a paste's text, a hub's keys, a mode
  or an action) to the receiver's key when its device record has one, so that the members
  in between see only who sent it to whom; the receiver opens them with its own secret
  (`v` `2`, docs/protocol.md, section 15, "Sealed commands"), in Go and the Rust core, on
  shared vectors (`testdata/interop/go-sealed-commands.json`). The lite member keeps a key
  too (`seal.json`), offers it in its hello and opens the commands sealed to it.
- Each computer makes a key for sealed messages (`seal.json`, in the TPM where there is one)
  and offers it in its hello; a root computer puts it in the device records, the first step
  to commands sealed for their receiver (docs/protocol.md, section 15).
- The group's main hubs in a table the root signs, or an admin that may be a hub (`cbb hubs`,
  a `hubs` record, docs/records-v2.md, "The hubs table"): they serve first, in the user's
  order, before the hubs the records give, in Go and the Rust core alike.
- `cbb version` of the lite member names the Rust core it was built with: its version, the
  ABI of its entry point and, in a release, the commit it was built from.
- The Rust core evaluates a record set at the limit with about a third of the memory it took
  (1.7 MB instead of 4.7 MB for 1033 records on a 64-bit computer), for the ESP32, and a test
  holds the peak to eight times the records' size.
- The Rust core's entry point answers for a member's record set (`group_add`, `group_view`,
  `group_command` and the other `group_` calls, docs/core-api.md, "The record set"), so the
  phones keep the records file and ask the core instead of applying the group's rules
  themselves.
- Commands, server credentials and release files are read through the Rust core's
  `parse_body` (docs/core-api.md, "Signed bodies") by Go in the release builds and by the
  phone apps, so every program takes exactly the same bodies.
- The Rust core's entry point checks a peer's member certificates (`check_member`, docs/core-api.md),
  for the TLS verify callbacks of the computers and the phones, and gives the same answer as Go's
  crypto/tls on shared vectors (`testdata/interop/member-chains.json`). The lite member now takes
  a peer's admin CA wherever the peer puts it in its chain, as Go does.
- Limits on a group's record set, the same in Go and the Rust core (docs/records-v2.md,
  "Limits"): 1024 records, 1 MiB, 256 devices, 64 admin keys and 16 roots on the path.
  Records past a limit count for nothing, with the reason `limit`; the set is never refused,
  the root's records go first, and the root's checkpoint brings a set back under the limits.
  The Rust core checks a signer's chain in one pass instead of once per record.
- The nightly `cargo fuzz` run covers the Rust core's entry point (`api`), starting from
  requests for each operation built from the interop vectors.
- The remote invitation is read the same way by Go and the Rust core (`cbb_core::invite`),
  checked on shared vectors (`testdata/interop/invites.json`). Its JSON must now be in the
  strict form of signed bodies with exactly the fields of docs/protocol.md section 12. A
  refusal names one reason, the same in both. The obfuscation's ranges are read only as
  `min-max` in plain decimal.
- Encryption of a message for one device, for the sealed commands of 0.6: HPKE with
  X-Wing (ML-KEM-768 and X25519, so it holds against a quantum computer as well),
  HKDF-SHA256 and ChaCha20-Poly1305, in Go (`internal/seal`) and in the Rust core
  (`cbb_core::seal`), checked on shared vectors (`testdata/interop/seal-go.json`,
  `seal-rust.json`). The Rust core needs Rust 1.87.
- Nightly mutation testing of the records' rules (`cargo mutants` on the Rust core,
  `gremlins` on Go's `internal/authority`): every change to the code that no test notices is
  listed in the run (docs/testing.md, "Mutation testing").
- A model of the rules for handing the group over in records v:2, in Quint
  (`docs/model/claims.qnt`): CI's `model` job checks its scenarios and the promises of
  docs/records-v2.md over random runs.
- The Rust core (`cbb_core`) and the phones' bindings (`lite/ffi`) may not panic outside
  their tests: clippy refuses unwrap, expect, indexing that can fail and arithmetic that can
  overflow there, and the core forbids unsafe code; the few places that cannot fail say why.
  Property tests (`lite/core/tests/props.rs`, proptest) feed the parsers random bytes and
  check that the state of a record set does not depend on the records' order or on
  duplicates.
- CI checks the workflows with zizmor (template injection, tokens left to later steps, wide
  permissions, cache poisoning) and the lite member's and the ESP32 firmware's crates with
  cargo-deny: each under a license that fits the AGPL-3.0 (`lite/deny.toml`), from crates.io
  or the pinned esp-hal commit only.
- CI measures the tests' coverage of the Go service (across packages, with the desktop
  clipboards and the e2e), the lite member, the Swift kit and the Kotlin kit, prints it in
  the run's summary, and fails when a part falls below its floor (`tools/coverage`,
  docs/testing.md, "Coverage").
- The bench's desktop suite runs on the Linux member alone too: the primary selection kept
  out of the group (Y26), HTML and a PNG image copied on Linux and arriving with their types
  (O4, O1), the session's kind and a copy from an X11 program under Wayland (H1), the keys
  helper's refusals (T15), the console's tmux on a new virtual terminal (H4), keys in the
  TPM in the hub's device list (K13) and files through the Flatpak portals (O12); with
  `-disruptive` it locks, puts to sleep and restarts the computers through the quick actions
  (Q3, I18, H7) and turns a Mac's application firewall on (H8). CI's OpenWrt job checks the UCI memory limit, procd's
  respawn and sysupgrade's keep list (I23, H9), and its FreeBSD VM the ipfw rules and
  pfSense's refusal to open ports (H10).
- The bench's fleet runs a lite member on another subnet behind a router with avahi, found
  through the mDNS reflector and reached with `-peer` (D9), a member with a router's memory
  passing a 90 MiB copy on (O14), and a soak for `-soak-for` with a fault every hour (E10).
- `release-sign verify` checks SHA256SUMS against the files and the signed manifest and
  prints the manifest's Docker image; the published workflow checks every published release
  with it, each file's build attestation, and the image's digest on ghcr.io (I22).
- The bench's fleet runs the holder's election and handover (D4, D5), dial-back (D11), what a
  stranger learns (S21), the forwarder's hub rule (W30) and fuzzing for `-fuzz-for` (S20).
- The bench's fleet runs the key-file warnings (K11), the join matrix (G41, Y6) and, in a
  systemd container, `cbb update` from a test feed signed by `tools/release-sign`: the install,
  every refusal, a rollback and the update method (I8 to I11), and `get.sh` against the same
  feed, each refusal named (I3), and in a group of two the second member taking the archive
  from the first, with the timer turned on and off (I12).
- The bench's fleet runs install.sh's options against a bare nftables firewall (I2), uninstall
  with and without `--purge` checked against what was there before (I4), an upgrade in a group
  one member at a time (I6) and the previous release installed over the new state (I7).
- The bench's fleet checks the content cache: a part readable only by the service, gone
  10 minutes after its copy is replaced, and none after a restart (O9).
- The bench's fleet runs the lite member (`-cbb-lite FILE`) joined to full members: `cbb watch`
  and `watch -0`, the ZX Next's frames (U9), and a copy of a file giving it only the text that
  goes with it (O6), its `cbb update -check` against a feed signed with test keys (S22), and
  `get.sh --lite` installing it from such a feed (I1).
- The bench's fleet checks the fetch limits of a part's holder with the forge: chunks padded to
  16 KiB, a get over 1 MiB dropped, and too many gets at once closing the connection (O15).
- The bench's fleet plays the phone that scans a computer's QR code: the computer listens only
  during `cbb pair`, and only for the certificate and code in the QR code (G17).
- The bench's fleet relays a join between two TLS sessions with the forge: the join fails, the
  window loses one guess, and the joiner then joins directly (G8).
- The bench's time suite runs the hub's key renewed each credential period, with a client
  away from home taking the next key ahead and one off across the switch (W12).
- The bench's fleet runs install.sh again over an install (I5), the unit's sandbox score and
  TPM device (I20), the ufw rules install.sh adds and removes (S12), `get.sh --lite` over an
  old `cbb-lite` (I26), the hub's addresses allowed only while a join by invitation runs
  (G15), the invitation file as a secret (S7), a removed client reaching no one (S6) and the
  lite member's options (H5).
- The bench's fleet runs the lite member as a client of the hub's tunnel: plain WireGuard
  away from home, and an obfuscated hub's offer refused, so it stays at home (W17); and
  members beside avahi-daemon, which keeps working, ignoring another group's member (D1);
  and what the wire shows: nothing of the group in the clear on the internet's router while
  an away client syncs, and at home only TLS 1.3 with no copied text in the clear (S1, S2), and
  nothing sent anywhere but to the servers once the tunnel breaks (S9); and the forwarder and the relay, with
  `CBB_DEBUG=1`, keeping only their keys, state and log, none of which names the group, a device,
  an address or a copy (S18, but for `systemd-analyze`); and the away client's
  `max-copy-away`, a file within it arriving through the hub and one over it staying at home (O10). The fleet also checks that a
  text sent as a secret stays one when sent again without the mark, and that the sender
  remembers 4096 secrets (Y34); and that a failed step of install.sh or
  uninstall.sh ends them with its exit status and says so, or with `CBB_ERROR_DETAILS=1` shows
  every command (I25, Linux). The forge's invitation to a missing hub names a group, as
  invitations must now.
- The bench's fleet checks the system's limit on a computer that install.sh set up (W2,
  Linux): joined away from home by invitation, its unit lets the service reach exactly the
  hub and the forwarder; once the hub's address changes, `cbb global` and `cbb status` say so
  and nothing goes to the new address until `sudo cbb global allow`. The bench now deletes
  each release feed it builds, close to 1 GiB a run, when the scenario ends. A member
  limited to its home interface (`CBB_INTERFACES`, as on OpenWrt) refuses member TLS from a
  second network with no firewall, even one it takes as its group's (D10).
- The bench has a `desktop` suite for the Macs and Windows PCs with their own clipboards: a
  text the service writes late is not sent back, not even when a clipboard history offers it
  again 10 s later, and `cbb copy` of the text already held is still a copy (Y24, Y25); a
  password manager's mark keeps the text on the computer, also when put back without it
  (Y31); a received secret carries the marks and is gone after its minute (Y32).
  `setup-windows.ps1` registers a third task that runs the bench's scripts in the signed-in
  session, and lets only that user, administrators and the system write to its folder.
- The bench's `desktop` suite pastes and types from the root into a window on Windows: the
  text arrives exactly, 1 MiB pasted and 4 KiB typed, the clipboard's own text comes back and
  nothing is copied to the group (T3, T5); a secret paste is in no log (T11); the log of
  pastes names each one without its text (T12).
- The bench's `desktop` suite also checks each device's log, the Windows and Mac services'
  logs rotated past 1 MiB (I21); `cbb copy` on purpose in every mode (M2); one Linux agent per
  session and a restarted one (H2); tmux's copy and paste keys (H3); and a large copy's
  progress in `cbb status` (O13).
- CI runs the tray app's window in a headless Chrome or Edge against its real Go side: the
  colours and layouts, collections, Russian, error details and the admin actions (A5, A8,
  A9, A15, A16, U12); the bench's coverage counts such CI tests as `ci`. XCUITest drives
  the iPhone app's screens before a group on the simulator and the Mac app's window with no
  service, and Robolectric the Android app's screens (A2, A4, A14).
- The bench's time suite checks certificates near the end of the group CA: a new member's
  certificate ends with the CA, and neither it nor the root's is renewed past it (K5).
- The bench's fleet and time suites take `-coverdir DIR`, where containers running a `cbb` built
  with `-cover` write which code the cases ran (docs/testbench.md, "Code coverage").
- `docs/protocol.md` gives the exact rule for a signed body: each rule of the strict form has
  a name, the order of the checks is written down, and section 10 has a table of every
  record field with its JSON type, the types that need it and its values; section 15 says
  the same for commands. `testdata/interop/strict-generated.json`, which Go's
  `TestStrictGenerated` writes from these tables, holds some 2000 bodies of records, commands
  and manifests with the verdict and the rule each one tests; Go, the lite member and both
  phone kits read it, and the Go test fails when the file is not what the tables give.
- `testdata/interop/strict-files.json`, written by Go's `TestStrictGeneratedFiles` the same
  way, holds some 1500 bodies of server credentials and release files; all four
  implementations read it.
- `testdata/interop/strict-mutants-1.json` and `-2.json` hold 485 record bodies changed byte by
  byte from valid ones, each with the verdict of the tables; all four implementations read
  them.
- Differential fuzzing (`docs/differential.md`): `tools/difffuzz` changes the bodies of the
  interop vectors and their record sets at random from a seed, each of Go, the lite member and
  both phone kits writes its verdict on every case, and the `differential` job of CI fails on
  any case they read differently. A nightly workflow runs it with a fresh seed and more
  cases, and the native fuzz targets of the readers of network input: Go's `FuzzRecordBody`,
  `FuzzCommand`, `FuzzRelayWire` and `FuzzForwardWire`, and the lite core's `cargo fuzz`
  targets.
- The two text diagrams of `docs/design.md` (the system context and the containers) are
  pictures now, drawn by `tools/diagrams` like the others, with a light and a dark theme.
- On the website the pictures of the documentation are drawn in chalk on a board in a walnut
  frame, like every other picture of the site, in every language, and are drawn in once as
  they come into view. The files in `docs/images` are unchanged, so GitHub shows them as before.
- The users' guides (`docs/guide`) in Chinese, Hindi, Spanish, Russian, Arabic, Swahili and
  Hebrew, opening inside the website's own layout with its header and language menu, with
  the text inside their pictures translated; the index's descriptions are translated too.
  Every other page of the documentation stays English and opens on GitHub from the index.
  `site check -strict` and `site docs-sync` keep the translations in step with the pages.
- The website's code signing policy (`/code-signing.html`), which SignPath Foundation asks
  for: who signs the Windows programs and who approves it, linked from the download page and
  from every page's footer. The privacy page now says what the programs send outside the
  group and who is responsible for the policy.
- The project's release root keys: two P-256 keys made on two YubiKeys, with the PIN and a
  touch for every signature, in `internal/release/roots` with Yubico's attestation that
  they were made on the keys. `get.sh`, `get.ps1`, `cbb update`, the lite member's
  `cbb update` and the Android app's own update now check releases against them; a release
  before 0.6 has no signed files, so a new `get.sh` or `get.ps1` installs one only with
  `CBB_VERIFY=skip`.
- `release-sign publish`: one command on the maintainer's Mac signs a release and publishes
  it (the draft's attestations checked, `keys.json` kept or signed again by a root,
  `release.json` and `stable.json` signed, all of it checked under the pinned roots). The
  release workflow now leaves a draft, and the new `published` workflow updates the Homebrew
  tap once the release is published.
- The current `keys.json` and `stable.json` live in the repository's branch `channel`, as a
  published release takes no new files: `get.sh`, `get.ps1`, `cbb update`, the lite member and
  the Android app read them there, and `get.sh` and `get.ps1` install the release
  `stable.json` names. A channel key on cbb.tools (`use` `channel` in `keys.json`, which signs
  channel files only) renews `stable.json` every week (`release-sign extend`), and the daily
  `channel` workflow checks it, commits it to the branch, and opens an issue when
  `keys.json` or `stable.json` is close to its expiry.
- `get.sh` and `get.ps1` take only release keys for `release.json`, no longer every key of
  `keys.json`.
- The release keys on the two YubiKeys (PIV slot 83) with their attestations, in
  `internal/release/roots/release-keys.pem`, checked by `TestReleaseKeysAttested`.
- docs/own-build.md: what ties a build to this project's releases, and how a fork or a
  build of one's own uses its own roots and addresses; `TestProjectAddresses` checks that
  every copy of the project's addresses matches `internal/update`.
- SteamOS: `install.sh` (and so `get.sh`) puts Clipboard Bridge in `/opt/clipboardbridge`
  on a Steam Deck, whose system files each update replaces, and lists its files in `/etc`
  in SteamOS's keep list, so the install and the device's group survive SteamOS updates;
  cbb update keeps its folder in `/opt/clipboardbridge-update` there. Not yet run on a real
  Steam Deck.
- Rootless installs on Linux (D-79): `get.sh --rootless` and `install.sh --rootless`, run
  without `sudo`, install the full member for one user as systemd user units, with its
  files in the user's home. Its hello and device record say `rootless`, and it is never the
  group's root, an admin or a hub, not even after a warning: the service refuses the keys,
  the root and the phones refuse to make it an admin, and `cbb status` and the phones'
  device pages show it. The lite member installs this way too (`get.sh --lite --rootless`),
  without the text console target and the reboot action, which need root.
- The roadmap plans Apple Vision Pro (item 40).
- The model of the device tiles' own order and collections, for the apps' Arrange mode
  that follows: the same rules in the tray app (Go), the Android kit (Kotlin) and the
  Swift kit, checked against shared vectors in `testdata/arrangement`. It is kept on each
  installation and never sent to the group.
- The iPhone and iPad app arranges the devices: Arrange devices in the "…" menu or
  Arrange on a long press, then drag the tiles, drop a device on a collection to put it
  in, or use the same changes in each tile's menu and VoiceOver's actions. A collection
  is a tile with its devices' icons and how many are online, a section in the list, and
  a page of its own. With more than 12 devices Home has a search and the filters Online
  and Needs attention.
- The Android app arranges the devices the same way: Arrange devices in the ⇅ menu or
  Arrange on a long press; in Arrange mode a long press drags a tile to where it is
  dropped, each tile has a ⋮ menu with every change, and TalkBack has the moves as
  actions.
- The tray app arranges the devices too: the ⇅ button turns Arrange mode on, where the
  tiles and rows are dragged, a right click or a tile's ⋮ button opens its menu, and Alt
  with the arrow keys moves the focused tile. A collection opens its own page; the
  arrangement is kept in `desktop.json`.
- The Mac app arranges the devices as well, with the Swift kit's model: Arrange devices
  in the toolbar, drag and drop, the same changes in each tile's right-click menu and
  VoiceOver's actions, and Option with the arrow keys for the focused tile.
- The Apple Watch and the Wear OS watch list their phone's devices in its order: those
  in no collection, then a section for each collection.
- The Android app can act as a Bluetooth keyboard (Settings, Bluetooth keyboard): it types
  the clipboard, or remote pastes when the user sends them there, into a paired TV,
  tablet, console or computer, which needs nothing installed. The user picks the device,
  its layout (English (US) or Russian, the Nano ESP32's key tables) and the speed. A text
  with characters the layout cannot type is refused, and the app names them. A phone whose
  maker left the HID Device profile out says it cannot act as a keyboard.
- `cbb keyboard` makes a Linux computer a Bluetooth LE keyboard (HID over GATT through
  BlueZ) for a TV, tablet or computer near it: `pair` makes it discoverable for two minutes,
  `type` types a text there, and `on -pastes` sends remote pastes there. It uses the same
  layouts as the phone and the Nano.
- `cbb remote` makes a computer the remote of a TV on the home network, so that it types a
  text, or the group's remote pastes when the user sends them there, into the field open
  on the TV. An Android TV or a Google TV pairs once with the code it shows (the Android TV
  Remote v2 protocol of the Google TV app, its certificate pinned); a Roku is taken only
  with `-consent`, as its External Control Protocol is plain HTTP. A TV is reached only on
  the home network, and the errors say which TV failed and why: no text field open, the TV
  reset, or the Roku's "Control by mobile apps" off. Not yet tried on a real TV.
- iPad: keyboard shortcuts (Command-R sends or fetches, Command-N adds a device,
  Command-comma opens Settings, Escape closes a device's details), and CI runs the app's
  tests on an iPad simulator as well as an iPhone one. The iPad's Settings no longer speak
  of a paired Apple Watch.
- The Android app's F-Droid build, `clipboardbridge-fdroid-X.Y.Z.apk` in each release: the
  same app without Google Play services, so without the Wear OS watch, and without its own
  update, which F-Droid does. It builds reproducibly, as F-Droid needs to publish our signed
  APK, and CI checks it; the recipe for fdroiddata and the store texts are in the repository
  (docs/apps.md, "F-Droid"). The Android apps' version is now in
  `apps/android/version.properties`.
- `cbb update` installs the newest signed release on a computer installed with `get.sh`,
  `get.ps1` or a release archive (Linux, OpenWrt, FreeBSD, macOS, Windows): it checks
  `keys.json`, `stable.json` and `release.json`, the archive and the programs in it, runs the
  new release's own installer, and puts the previous programs back when the service does
  not report the new version within a minute; automatic updates then skip that version.
  `-check` only says whether there is one, `-to VERSION` takes a release's `min_from`, and
  a copy from Homebrew, winget, Docker or a package gets its tool's command. Updates come
  from GitHub, else `dl.cbb.tools`, or a mirror set with `cbb update -mirror`; each check
  sends no version, system or group data. On Windows the new programs must carry the
  installed ones' Authenticode signer once they have one.
- Automatic updates: the installers ask once (`--auto-update on|off`, `-AutoUpdate`,
  `CBB_AUTO_UPDATE`), and `cbb update -auto on|off` changes it; a systemd timer, a launchd
  job, a scheduled task as SYSTEM or cron on OpenWrt and FreeBSD checks once a day. The
  installers record how the program was installed, and the uninstallers remove the timer
  and cbb update's folder.
- The group passes the newest signed release around (docs/protocol.md, section 16, "In the
  group"): `cbb update` hands the files it checked to the service, members send them to
  peers whose hello names an older one, and each member checks them as a download is
  checked. `cbb status` says when a newer release is out and lists each device's version,
  marking the older ones; the tray app offers "Update to X", which runs `cbb update` as the
  administrator. The archives pass through the group too: a member keeps the archive it
  installed and serves it, and `cbb update` takes it from the group before downloading.
- The lite member's `cbb update` on Linux and OpenWrt, as the full member's: the signed
  files checked with `lite/core`, the download through the system's curl, wget or
  uclient-fetch, the archive's installer, the rollback, `-check`, `-auto on|off` and
  `-mirror`; its installer now asks about automatic updates too.
- The Android app updates itself when it was installed from a release's APK (docs/apps.md,
  "Updates"): Settings checks for a newer release and installs it through the system's
  installer after checking the signed release files, the APK's hash and its signing
  certificate; "Update automatically" does this once a day. A copy from a store is left to
  the store.
- The Nano ESP32's USB port as a keyboard (`usb keyboard` on its console): a boot keyboard
  and a serial port for the console on the chip's OTG controller, `type TEXT` with the
  layout active on the host (`layout us` or `ru`) at a set rate (only in a build with the
  feature `console-type`, which the default firmware leaves out), and `flash` to restart into
  download mode. A text with characters the layout cannot type is refused, naming them. The
  layouts' key tables are in the protocol core (`cbb_core::keyboard`). Remote paste through
  the keyboard follows the board's sync.
- The Nano ESP32 as a Bluetooth LE keyboard (`ble on` on its console): HID over GATT with
  trouble-host beside Wi-Fi, for TVs, tablets, phones and computers that take BLE
  keyboards. `ble pair` makes it discoverable for two minutes; it keeps up to four paired
  hosts in flash under an address made from its Bluetooth MAC, types only on a paired host
  over an encrypted link, and `ble forget` forgets them. `type` goes to a connected
  Bluetooth host first, else the USB keyboard.
- The Android app on a TV (Android TV, Google TV, Fire OS; docs/apps.md, "Android TV"):
  a launcher banner, every control on the D-pad with a visible focus ring, and no touch
  screen or camera needed. A TV joins a phone's group by the QR code it shows, as a member
  without an admin key, says `tv` in its hello, starts receive only and takes remote
  pastes. A paste that the system's stopped accessibility service could not make says so.
- The `watch` role for a watch's admin key (docs/protocol.md, section 10, rule 8), in Go,
  the lite member and both phone kits, with interop vectors: a watch freezes admin
  computers, removes ordinary devices and signs only the commands that turn things off and
  quick actions; it never admits devices, removes an admin, takes the group over or acts as
  a hub. Any admin can freeze a watch; removing one takes the root or an admin phone.
  The root phone makes its Apple Watch or Wear OS watch an admin in Settings: the watch
  makes the key in its Secure Enclave or Keystore, only with a passcode (and wrist detection
  on the Apple Watch), and the key works only while the watch is unlocked.
- Emergency actions on an admin watch: a device on the watch opens what the watch may do to
  it (freeze an admin computer, remove an ordinary device, turn remote paste, quick actions
  or sync away from home off, run a quick action marked for a watch). The phone builds what
  the watch signs, the watch checks it, asks for a tap and signs it, and the phone carries
  it into the group.
- The `away-off` command turns sync away from home off on a member (`cbb global off -on
  DEVICE` on an admin computer); turning it on stays each device's own decision.
- Quick actions take `watch` in `-by`, for actions a watch may run.
- The bench's catalogue for 0.6 (docs/testbench-catalogue.md): 287 cases in one line each,
  by area, with where each runs (real devices, a fleet of containers, a time-scaled build,
  a test release feed, UI automation, a person) and what it still needs; and every function
  of the product with its cases (docs/testbench-functions.md). `testbench coverage` counts
  how many functions have a case, how many run by themselves and how many the harness runs
  today; `testbench all` runs every suite in turn and ends with that table.
- The bench's `faults` suite: a bad network at the hub, a blocked member port, a hung and a
  stopped service, a damaged `identity.json`, each taken back by a timer on the device;
  every error it expects is checked with `CBB_DEBUG=0` and `1`.
- The bench's devices with `os = "netns"`: a second full member on a Linux host in a network
  namespace of its own, whose only way out is a SOCKS5 proxy through tun2socks, such as a
  VPN's local inbound, so that one server tests sync away from home both directly and
  through the VPN (`tools/bench/setup-netns.sh`).
- The bench's `fleet` suite: full members in containers on the controller, thrown away after
  each run, for the cases that need many devices or would harm the real ones: the pairing
  window, admins and their limits, freezing, removal, a takeover, two groups side by side,
  network splits, the modes, junk on the member port, restarts, remote paste into root's
  tmux with each refusal and its reason, and up to 32 members.
- The bench's time-scaled build (`go build -tags benchtime`, never released): certificates,
  their renewal and the server credentials' periods run 100000 times faster, and
  `CBB_TEST_CLOCK` moves a member's clock. The `time` suite runs it in the fleet: renewal,
  new periods, and a certificate that ends while no admin is on; at the real pace
  (`CBB_TEST_SCALE=1`), members whose clocks are in 1970, hours, days or years ahead.
- The iPhone app asks iOS for background app refresh: now and then iOS runs it for a few
  seconds, and it hears of the group's events then, without being opened. Push
  notifications follow with the Apple developer account.
- Hardened systemd units for the servers, `cbb-forward.service` and `cbb-relay.service`, in
  the Linux archive; docs/admin/self-hosting.md installs them and says what the server
  keeps, what its hosting provider sees, and what a system VPN on a device hides.
- BRAND.md: which builds are official and how to check them, what belongs to the project
  (the icon, `cbb.tools`, the release keys), what anyone may do without asking, and what a
  build with changes should not do; it names the other projects called Clipboard Bridge.
- A commercial license is available without the AGPL's obligations; ask with the new
  **Commercial license** issue form.
- The text of docs/protocol.md is under CC BY 4.0, so anyone may write a compatible
  implementation under any license.

- Signed releases: `keys.json`, `release.json` and `stable.json` describe each release and
  are signed by release keys that two offline root keys certify (docs/protocol.md, section
  16). `tools/release-sign` makes and signs them with a key in a file, on a YubiKey or in
  the Mac's Secure Enclave, and `get.sh` and `get.ps1` check them before they install, once
  the project's root keys are pinned (`CBB_VERIFY=skip` installs unchecked).
- Where a device keeps its keys: hellos say `key_store` and device records `store`, a file
  or hardware, and `cbb status` shows it in a KEYS column (docs/protocol.md, section 17).
- The Android app makes its keys with an attestation challenge, so the Keystore can later
  prove that they live in its hardware.
- The website for cbb.tools (`site/`, built by `tools/site`): the start page, download, and
  security and privacy, in English, Chinese, Hindi, Spanish, Russian, Arabic, Swahili and Hebrew
  (right to left for Arabic and Hebrew). It presents the two kinds of group, with a
  computer at its heart and phones only, and says why it recommends a computer. "/"
  picks the visitor's language by the language they picked before, their country (a local
  DB-IP database on the server, nothing logged) and their browser; English otherwise.
  The start page leads with "One clipboard to rule them all" and what it does, then the
  platforms, a comparison with sending yourself a message and one with Apple's Universal
  Clipboard, Windows clipboard sync, KDE Connect and Pushbullet, platform by platform (from
  their makers' pages, dated), three steps to start with a board each, uses and questions; every page ends with a
  next step, and a phone keeps a "Download" button at the bottom of the screen. A dark and a
  light theme, following the system or the reader's choice in the header; the download page
  puts the reader's system first, and every command has a copy button. Short CSS-only
  motion (the hero's chalk is drawn in on load, every other board's drawing, table or
  commands as it first comes into view; then a little living chalk: a spark runs along the
  main board's wire and back, the steps' arrow, command and camera move, the groups' links and
  our row in the tables are gone over again, a cursor blinks after each command, and the
  chalk's grain shifts as in a hand-drawn film; each movement eases in and out), off for those who ask for less motion; one small
  script of its own, and every page works without it. A link's picture in each language; a
  print style. Error pages (404, 5xx) in the visitor's language, Open Graph, canonical and
  hreflang links, `sitemap.xml`, `robots.txt` and schema.org data for search engines. nginx with its ACME module serves it over
  HTTP/2 and HTTP/1.1 (`site/deploy`), and CI checks every translation. Visits are counted
  by GoatCounter on the same server, without cookies and without storing addresses. Until the
  launch the site is closed: everyone sees "the website opens soon", and a secret link opens
  the whole site in the owner's browsers. CI validates its HTML and runs Lighthouse on it;
  the download page takes the latest version from this changelog; TLS 1.2 and 1.3 only,
  pre-compressed files, a long-cached stylesheet and script, preloaded fonts, `security.txt` and a web manifest.
  The design is art deco: gold lines and glass panes on dark wool felt, like the cloth of a
  billiard table. The pictures (a computer and a phone joined through the key, and each kind
  of group as devices around its heart, a desktop with its system unit among them; the three
  steps: the phone downloading the app, the computer's one command, the phone's camera
  framing the computer's QR code) and the tables are drawn in chalk on black school
  boards with a faint grid, in frames of old walnut; rough.js draws the lines once
  (`site/chalk.js`) and `site/textures.py` makes the wood and the felt. On a phone: a
  sideways menu, the languages in a sheet from the bottom, a docked download button, and the
  servers' table as a list. The download page writes the commands for Linux, Mac and
  Windows on one board, and the whole command for the lite member. The fonts (Forum, Jost, IBM Plex Mono and Caveat, under the OFL)
  are served by the site itself, so nginx allows `font-src 'self'`. The text under the
  centred headings spans the page's width.
- Proven keys: a phone sends the attestation of its member key in an `evidence` message,
  and the group's root checks the Android Key Attestation chain (both Google roots, the
  phone's verified boot) and records the device's keys as `proven`, which `cbb status`
  shows as "proven hardware" (docs/protocol.md, section 17, "Evidence").
- Revoked attestations: a mirror on cbb.tools signs Google's revocation list of Android
  attestation keys every day (`attest-status.json`, with a status key that `keys.json`
  certifies only for it), and the group's root, a computer or a phone, takes it and records a
  phone whose chain was revoked as only in hardware (docs/protocol.md, section 17).
- Keys in the TPM: a Linux computer with a TPM 2.0 makes its member and admin keys in it
  when it joins a group, the identity file keeps only the TPM's blob, and the device counts
  as hardware (`internal/tpmkey`, docs/protocol.md, section 17). The installer lets the
  service reach `/dev/tpmrm0`; `CBB_TPM=off` keeps new keys in a file. The TPM seals the
  WireGuard key of sync away from home too, and a key already in `tunnel.json` moves in.
- Proven TPM keys: a computer whose TPM holds its maker's certificate proves its member key
  to the group's root (`TPM2_Certify` by an attestation key, credential activation), and the
  root records it as proven hardware (docs/protocol.md, section 17, "TPM evidence"). The
  makers' certificates ship in `internal/attest/tpmroots`.
- The guide "Keys and attestation" (docs/guide/keys.md): where each device keeps its keys,
  how Android phones prove it, and the three key levels.
- Remote paste, the protocol and the service (design.md, "Remote paste"): an admin signs a
  `paste` command (`cbb paste -on DEVICE`, from standard input or the clipboard, with
  `-type`, `-enter` and `-secret`), and a member whose user turned it on (`cbb
  paste-receive on`, with `-enter` and `-console` as separate switches) hands the cleaned
  text to a watcher that offers to paste, within one a second and 30 a minute per sender,
  and keeps a log of the last 100 pastes without their texts. Any admin turns it off on a
  member or on all (`cbb paste-receive off -on DEVICE`, `-all`) (docs/protocol.md,
  sections 8 and 15).
- Remote paste targets on Linux: the desktop connector of an X11 session pastes through
  the clipboard and Shift+Insert, or types with XTEST in any layout, and refuses while the
  session is locked or the screen saver is on; in tmux, `cbb paste-helper tmux`, which
  clipboardbridge.conf starts, pastes into the active pane of the client used last, and
  refuses when no one is attached. On Wayland compositors with virtual keyboards (sway,
  Hyprland, labwc), the desktop connector pastes through data-control and Shift+Insert, or
  types any character through a keymap of its own; it also refuses while swaylock or
  another locker runs. On the text console, `cbb paste-helper console`, which `install.sh
  --console` runs as the `clipboardbridge-console` unit with `CAP_SYS_ADMIN` alone, types
  into the active console where a user is logged in. A text with a line break goes to tmux,
  a console or the keys only when the user allowed Enter, since it would run there.
- Remote paste on GNOME and KDE: the desktop connector presses the keys through the
  RemoteDesktop portal (the ei protocol, `internal/ei`). The first paste opens the portal's
  dialog on the device and is refused until the user allows it; the portal's restore token
  keeps the consent. It pastes and presses Enter, and refuses typing, whose keys would follow
  the user's layout. In a Wayland session the X11 connector of XWayland uses it too, since
  XTEST's keys reach only X11 programs there.
- `install.sh --uinput` (and `get.sh --uinput`) adds the uinput helper, `cbb paste-helper
  uinput` in the `clipboardbridge-uinput` unit: a virtual keyboard that presses only
  Shift+Insert and Enter for the desktop connector of the session on the screen, so that
  remote paste works on GNOME and KDE without the portal's dialog. It presses them only for
  a remote paste that the service took under the paste switches and handed to that
  session, asking the service for each, only for the user of the active graphical session,
  and never on a login or lock screen; its socket is open to the service's group only.
- Remote paste on Windows: the clipboard agent pastes into the window with the focus
  through the clipboard and Ctrl+V, or types any character with SendInput's Unicode keys.
  It refuses on the lock screen and under an administrator prompt, and when the window with
  the focus runs as administrator, since Windows drops keys sent to it.
- Remote paste on a Mac, through the Mac app, which macOS lets press keys once its user
  allows it in Accessibility: it pastes through the pasteboard and Cmd+V, marked so the
  agent does not sync it, and gives the pasteboard its items back, or types with Unicode key
  events. It refuses on the lock screen and while Secure Keyboard Entry or a password field
  holds the keyboard. Without the app, a Mac says it needs it. The app's Settings show
  whether it may press keys.
- "Paste on it…" in the iPhone and Android apps: an admin phone puts a text where a
  computer's focus is, pasted or typed, with Enter or as a secret if asked, after Face ID or
  the fingerprint.
- Remote paste onto an Android phone: once its user turns it on in Settings, an admin's paste
  goes into the focused text field of another app through the accessibility service, pasted
  or typed, with Enter from Android 11. It refuses while the phone is locked, keeps a log of
  the last pastes without their text, and names the sender in a notification.
- Remote paste onto the lite member: `sudo cbb paste-receive on` there lets the group's admins
  put a text into the tmux pane in use, and with `-console` into the active text console,
  through `cbb paste-helper tmux|console`, with the full member's rules, limits and log.
  `install.sh --console` now installs the console helper's unit for the lite member too.
- Commands reach a member this one is not connected to: a member connected to it, such as
  the hub, passes a `mode`, `paste`, `paste-off`, `action` or `actions-off` command on and its
  result back.
- Quick actions on the computers (docs/protocol.md, section 15): `cbb action -on DEVICE NAME`
  on an admin runs a preset on another device, `lock`, `sleep`, `reboot`, `shutdown` (both a
  minute later), `cancel-shutdown` or `restart`, and the command carries only its name. Each
  is off until the device's own user runs `sudo cbb action enable NAME`, which says what it
  allows, may limit it to the root, admin phones or admin computers, and on Linux writes the
  polkit rule for logind that it needs, and nothing more. Reboot and shutdown take only admins
  whose keys are in hardware unless the user allows keys in files. Limits per sender and a log
  of the last 100, as for remote paste; `cbb action off -on DEVICE` or `-all` turns them off
  from afar. Linux runs them through logind; a Mac and Windows through the agent of the user
  signed in (`pmset` and loginwindow's Apple events on a Mac, where the minute before a
  reboot is the agent's; `LockWorkStation`, `SetSuspendState` and `InitiateSystemShutdownEx`
  on Windows, which warns the users signed in).
- Quick actions of the user's own: `sudo cbb action add NAME [-by KINDS] -- PROGRAM ARGS`
  on a computer adds an action that runs PROGRAM, by its full path and with those arguments
  only, as the user signed in, through the agent; only its exit status goes back, and it
  must end within 15 s. `cbb action remove NAME` takes it away.
- Quick actions on the phones: a member's hello names the actions that are on there
  (`actions`), and an admin phone shows them on the page of a computer or a lite member, runs
  one at a tap (reboot and shut down ask again) and turns them all off. The Swift and Kotlin
  kits sign and check `action` and `actions-off` commands, with cross test vectors from Go.
- Quick actions on the lite member: `reboot` (a minute later, through `shutdown -r +1` and a
  polkit rule), `cancel-shutdown` and `restart`, each off until `sudo cbb action enable
  NAME` there; its hello names the ones that are on, and `lite/core` checks action commands
  and their signers against Go's vectors.
- Images and files, the first step (design.md, "Images and files"; docs/protocol.md,
  section 4): a `media` event carries a manifest of the copy's parts with their sizes and
  SHA-256, and members fetch the content with `get` from one that serves it, in binary
  chunks padded to 16 KiB that go only while no event waits. The service keeps what it holds
  in a cache in its state directory (the current copy, older ones for 10 minutes, nothing
  after a restart) and fetches a copy its mode takes, from the origin first, up to its limit:
  `cbb config max-copy` (100 MiB) and `max-copy-away` (25 MiB), at most 1 GiB. `cbb copy
  FILE...` sends files and folders (links left out, names made safe for every system), `cbb
  copy -type png FILE` an image, and `cbb paste -o DIR` saves them, never over a file and
  never executable; `cbb status` shows a fetch in progress. Until the desktop connectors
  take images and files, they, the lite member and the phones get only the copy's text, and
  the Swift and Kotlin kits and `lite/core` check manifests against Go's vectors.
- Images in the desktop connectors (design.md, "Images and files", step 2): a PNG or JPEG
  copied on Wayland, X11, a Mac or Windows goes to the group, and a received image is
  written there as the image with its text next to it. Wayland and X11 offer and read
  `image/png` and `image/jpeg` (large ones in INCR pieces on X11); the Mac reads PNG, JPEG
  and TIFF (sent as PNG) and writes the image and a TIFF; Windows reads the registered `PNG`
  format, `CF_DIBV5` and `CF_DIB` (converted to PNG) and writes PNG and `CF_DIBV5`. A
  clipboard with a text and an image is sent as text, and files are left out until the next
  step. On the control socket a watcher asks for images with `images`, gets a `write` of
  kind `media` once the copy is in the cache, and reports its own with `copied-media`
  (docs/protocol.md, section 8).
- Files and folders in the desktop connectors (design.md, "Images and files", step 3):
  files copied in a file manager go to the group, and a received copy is saved in the
  user's cache, a folder for each copy readable only by the user and removed 10 minutes
  after a newer copy, and put into the clipboard as copied files. Wayland and X11 read and
  write `text/uri-list` and `x-special/gnome-copied-files` with the paths as text, and
  offer written files to Flatpak apps through the FileTransfer portal; the Mac reads and
  writes file URLs, as the Finder copies them; Windows reads and writes `CF_HDROP`, with the
  drop effect that makes Explorer copy them. A cut is taken as a copy. Received files carry
  the quarantine mark on a Mac and the Mark of the Web on Windows, also those `cbb paste -o`
  saves, and nothing is made executable. A watch request asks for files with `files`.
- Content in the phones' kits (design.md, "Images and files", step 4): the Swift and Kotlin
  kits speak `get`, `missing` and the binary chunks, serve the parts of the phone's own copies
  from a store, and fetch a received copy's parts from the members that serve them, its
  origin first, checking the hash; their hellos then say `media`. `testdata/interop/content.json`
  holds Go's frames for them, and the Go test that plays the phone sends a picture each way.
- Images and files on the phones (design.md, "Images and files", step 4; apps.md): the button
  sends an image on the clipboard as PNG or JPEG (HEIC and other formats converted) and
  fetches a computer's image, which also comes by itself as a text does (on the iPhone while
  the app runs, to this phone only); the button saves received files in Downloads on Android
  and in the app's folder in Files on the iPhone. Share sends images and files: up to 100 MiB
  on Android, 50 MB from the iPhone's share extension, which stays until a computer fetched
  them.
- Images and files away from home (design.md, "Images and files", step 5): the hub that
  serves fetches each copy of the group within its limit away from home, also in a mode that
  keeps its own clipboard out, and serves it to the members that reach only it, both ways.
  Through its tunnel it serves only copies within that limit (`cbb config max-copy-away`),
  so the hub's limit caps its whole star; a larger copy stays at home and the hub logs it.
- Formatted text in the desktop connectors (design.md, "Images and files", step 6): text
  copied with its formatting in a browser or an office program on Wayland, X11, a Mac or
  Windows (`text/html`, `public.html`, `HTML Format`) is pasted with it on the other
  computers, and as plain text on the phones and the lite member. A secret's formatting is
  never read; formatted text over 8 MiB, or with a text over 256 KiB, goes as its text alone.
  A watch request asks for it with `html` (docs/protocol.md, section 8).
- Server credentials (D-67, D-75, docs/protocol.md, section 18). The group lives in periods
  of about 30 days: a computer that is the group's root signs, inside the group, a fresh tag
  for the servers and a fresh period key, every member signs a fresh server key with its
  member key (both in the TPM where there is one), and the period key signs the hubs' and
  the members' credentials: hashes of the server keys, padded to 4, 8, 16 or more entries,
  with a version and an expiry. A removal or a takeover starts a new period at once. A hub
  registers with its forwarder, and a device with its relay, with these credentials and a
  certificate of its server key, so the servers no longer see the group's records, roots,
  device IDs, names or dates, and cannot link a group or a device from one month to the
  next. The relay knows the devices by pseudonyms, the hashes of their server keys, gets a
  fresh WireGuard key at each registration, and drops a device a newer members' credential
  leaves out; a relay that serves a fixed list of groups also sees the period credential and
  the group's roots. Devices and phones that do not sign credentials yet register as before.
  The lite member's core and the phones' kits read and check the credentials with the same
  vectors. Both phone apps keep them, pass them on, and sign their server keys; a root phone
  signs a new period while the user's last Face ID or fingerprint lasts, and the lists with a
  period key in the Secure Enclave or the Keystore. Once the members' credential lists a
  phone's server key, the phone registers with a relay by the credentials too, under its
  pseudonym (cbbtun's `Relay.SetCredentials`).
- The hub takes a new WireGuard key for its clients with each period of the server
  credentials (docs/protocol.md, section 11, "The hub's key"): its offers give the next key
  three days ahead, then it serves with it and registers again with its forwarder, so the
  forwarder cannot link the group's traffic from one month to the next by the hub's key. Go
  members, the lite member and both phone apps try a hub with its next key too, so one that
  was away when the hub moved on still reaches it.
- The test bench resets a Windows device itself: `uninstall.ps1 -Purge`, a check that it left
  nothing, and `install.ps1` from the build's zip, so a Windows VM needs no snapshot.
- FreeBSD: release archives for amd64 and arm64, `get.sh` and an installer with an rc.d
  script that runs the service through daemon(8), and the firewall rules with consent in a
  pf anchor of their own or an ipfw rule set; a CI job runs the Go tests and the installer
  in a FreeBSD 15.1 virtual machine. FreeBSD's uptime clock and system version show in the
  hello; OPNsense and pfSense say they are routers.
- Routers: `CBB_INTERFACES` limits mDNS, the member port and a listening join to the named
  interfaces, so a router never answers on its internet side, even with a private address
  there or its firewall opened by mistake. On OpenWrt the control socket is in `/var/run`,
  the state in `/etc/clipboardbridge/state` and the device's form is a router. Release
  archives for mips and mipsle (softfloat), whose tests a CI job runs under qemu-mips
  (big-endian).
- OpenWrt 25.12 and later: `get.sh` installs the full member on a router (`uclient-fetch`,
  mips or mipsle by the package architecture) with a procd service that runs as its own
  user without capabilities, only on the devices of the zones in
  `/etc/config/clipboardbridge` (`lan` by default), and starts once NTP has set the clock.
  Its firewall rules are its own procd data, which fw4 loads while it runs, so
  `/etc/config/firewall` is never changed; `cbb global hub` opens the hub's port on `wan`
  this way. sysupgrade keeps the keys and the program. A CI job installs it on OpenWrt
  booted in QEMU.
- OpenWrt package feed: each release can carry `openwrt-feed.tar.gz`, apk packages per Go
  architecture with an index signed by the project's feed key, for
  `cbb.tools/openwrt/<arch>/packages.adb`, so that `apk upgrade` keeps the program current.
- The lite member on OpenWrt (ARM64, ARMv7, x86-64, and MIPS and MIPSel without sync away
  from home, since its WireGuard library needs 64-bit atomics): `get.sh --lite` installs it with the
  same procd service, which runs `cbb run`. The lite member takes `CBB_INTERFACES` too, for
  mDNS, the member port and the QR code's addresses, and its defaults on OpenWrt are
  `/etc/clipboardbridge/state` and `/var/run/clipboardbridge/control.sock`.
- The test bench takes OpenWrt routers and FreeBSD computers as devices under test.
- The desktop connector on FreeBSD: the clipboard of X11 and Wayland desktops, and remote
  paste through XTEST or the virtual keyboard, from `cbb agent`, which XDG autostart starts
  at login. The lock check reads the processes with ps there and knows KDE's lock screen;
  GNOME's takes no keys without logind.
- FreeBSD: the service opens its mDNS sockets as root and then runs as its user
  (`cbb service -user`), so it shares port 5353 with avahi; when another program still
  holds the port, the error names it.
- OPNsense: the installer adds a plugin hook that names the service's pf anchor in
  OPNsense's ruleset and lists the service under System > Diagnostics > Services. pfSense,
  unsupported: the installer prints the rules to add and starts the service through
  `clipboardbridge.sh`.

### Changed

- `cbb global` no longer repeats that the device keeps its keys in files each time it
  shows the status; `cbb global on` says it once, when the user agrees.
- Remote paste on the phones: with the text left empty, Paste sends what the phone's
  clipboard holds, and the button that put the clipboard in the field is gone.
- On a Mac the service and the agent write their own logs, as on Windows:
  `/Library/Logs/clipboardbridge/service.log` and `~/Library/Logs/clipboardbridge/agent.log`,
  each line after the time, each moved to `.1` at 1 MiB, so a log no longer grows without
  end; the agent's log is new.
- The protocol's section 10 now specifies the group records of version 2 (docs/protocol.md,
  from "Records" to "The state", and the records' canonical form in Conventions, "Signed
  bodies"), in place of version 1's rules; docs/records-v2.md keeps why the records changed
  and how the implementations are tested.
- Both phone apps link the Rust core, the group's rules every member shares: the Swift and
  Kotlin kits call its C functions (`lite/ffi/include/cbb_core.h`) instead of generated
  bindings, and building the Android app, F-Droid's build included, needs the Rust of
  `cbb.rust` in `apps/android/gradle.properties` with cargo-ndk.
- One form for each thing on the wire (docs/protocol.md, Conventions), with the next ALPN
  version of every channel: `clipboardbridge/2`, `clipboardbridge-pair/2`,
  `clipboardbridge-forward/2` and `clipboardbridge-relay/2`, so members, forwarders and relays
  of 0.5 and of this version do not connect to each other.
  - One framing: the registrations at a forwarder and a relay and the requests inside a
    relay's tunnel are a 4-byte length and JSON, as the member protocol and pairing are,
    instead of JSON lines (Go's `internal/frame`).
  - One fingerprint: SHA-256 of a key's SubjectPublicKeyInfo in standard base64, as a
    record's key hash, for the join QR code, the confirmation of a joining device, a
    forwarder's or relay's key (`cbb forward` prints it without `sha256:`; set it again on
    the hubs) and a device's pseudonym at a relay.
  - Bytes in standard base64 everywhere: an invitation's text and a relay's call tickets too.
    Identifiers, file digests and the REALITY short ID stay in hex.
- The hello says what a member supports in `features` (now `media`, in place of the `media`
  flag) instead of relying on its version, and the rules for members before 0.6 are gone: a
  tunnel key comes with its preshared key or is ignored.
- The pairing's Welcome carries no CA key any more (`group_ca_key`, `phone_ca` and
  `phone_ca_key` are gone, docs/protocol.md, section 6): no device gets one by joining, in
  Go, the lite member and both phone kits.
- The group's records are of version 2 (docs/records-v2.md) on the computers and the lite
  member: each record names its signer and follows that signer's previous one, the Rust
  core decides what a set says, and the old records are refused. A group of an earlier
  version is not carried over: set it up again. The root decides how long a claim to the
  group waits, 72 hours by default (`cbb takeover-delay`), a new member takes the waits its
  admitting member counted from the Welcome, and `cbb upgrade` is gone. A device whose
  record has not reached a member yet gets a connection that carries records only, until
  the records let it in.
- The iPhone and Android apps keep their group's records of version 2 and ask the Rust core
  what they say (`group_add`, `group_view`, `group_command`), instead of applying the group's
  rules in Swift and Kotlin. Taking a group over is a claim that waits as long as the root
  decided: the app finishes it by itself once the wait is over, with Face ID or the
  fingerprint, and the root's phone may cancel it or change the wait. A new member takes the waits counted so far from the Welcome.
- Remote paste on Linux and FreeBSD takes nothing where the device cannot tell whether its
  session is locked (no logind, `loginctl` failing or saying nothing): earlier it pasted
  there. The device's user may allow pastes without that check with
  `cbb paste-receive on -no-lock-check`, on a computer and on the lite member; `cbb
  paste-receive` shows the switch. A locker that runs still stops a paste either way.
- The Android app's root and admin keys sign for 30 seconds after the fingerprint, the face
  or the screen lock, not five minutes; keys made by earlier versions keep their window,
  and the app asks again after 25 seconds either way.
- A remote paste with a line break needs the device user's leave for Enter on every target
  of a computer and of the lite member, a desktop session too: a shell or console window
  there may take the paste without bracketing it. Without that leave such a paste is
  refused with a reason that says how to send it.
- The documentation's pictures are laid out better: in the forwarder picture the home side
  moves right and the hub's line has room for its label; in the hub picture the hub's neighbours
  hang on one trunk; in the group and without-app pictures the branch stands close to the root.
- On the website the rectangles of the documentation's pictures keep their top corners (the
  site's cut-corner pane style had been applied to them), and the cards of the at-home picture
  no longer overlap in Russian and Swahili: the picture widens to hold them.
- On the website the columns of a documentation table are sized by what is in them, and a
  heading wraps only where it must, not at its middle.

- A member keeps nothing of a peer's cancel of a part it neither queued nor serves for that
  peer (docs/protocol.md, section 4).

- The content cache counts what fetches that stopped short left toward twice the device's
  limit, and deletes it 10 minutes after no copy needs it, as it deletes the parts of
  replaced copies.

- Remote pastes and quick actions go only to a paste target or an agent of the user at the
  screen: the service reads the user at the other end of the control socket from the
  system, gives the console target only to root, the desktop and the actions only to the
  user of an active session, and tmux to a user with a session; where the system does not
  tell who is at the screen, as without logind, it takes no `secret` paste. The same in the
  lite member (docs/protocol.md, section 8).

- Signed release files: a channel file's and `attest-status.json`'s `seq` is compared only
  with the files taken under the same `keys.json`, so a new `keys.json` lets it start again;
  a `seq` more than 65 536 above the one taken, and a file signed more than a day ahead of
  the device's clock, are refused; members pass a release on by its `keys.json` first
  (`release_keys_seq` in the hello), and `release-sign take` refuses a renewed channel file
  more than 16 past the branch's. The same in Go, the lite member and both phone kits
  (docs/protocol.md, section 16).

- The website's chalk is written about 30% faster (a board in about a second) and moves more
  smoothly: the chalk filter is on each table cell and on a drawing's moving parts apart, the
  panes under living boards are tinted rather than blurred, the underline grows by a
  transform, and the chalk's grain holds still while a board is drawn or the page scrolls.

- A member refuses an event more than 7 days ahead of its own wall clock, whatever events it
  took before, in Go, the lite member and both phone kits (docs/protocol.md, section 5).

- A device is an admin, and an admin has its role and store, only by a `device` record a
  root's own key signed, in Go, the lite member and both phone kits; a removed admin's records
  no longer decide the name of a device it admitted (docs/protocol.md, section 10). An admin
  that the root never made one is no longer listed as an admin, a hub or a command's signer.

- The member port holds at most 32 connections to the iPhone endpoints and the profile at a
  time, 4 from one address, and closes one idle for 30 s.

- A device bounds what it reads from a relay's watch: a note's length, the list of devices
  online, the calls it answers at once, and the form of a call's name and ticket
  (docs/protocol.md, section 14).

- The forwarder counts the handshakes that come over VLESS as one network against its
  budget of checks, as it counts any other network's.

- The forwarder checks a hub's registration under the root its member certificate verified
  to, which names the group, not under the first self-signed certificate the hub
  presented.

- Every member reads the bodies of records and commands in one strict form of JSON: exact
  lower-case member names, none twice, valid UTF-8, no null, integers only, the common
  fields required, base64 in its one form (docs/protocol.md, Conventions, "Signed bodies").
  The lite member and both phone kits check a record's fields as the Go member does, and a
  folder in a manifest has no hash, not even an empty one, in every implementation; the
  vectors in `testdata/interop/strict.json` hold them to one verdict.

- The relay bounds the registrations being set up by the address and the network they come
  from (16 and 64 of its 256), and counts the requests inside the tunnels apart from them,
  at most 16 of each device's (docs/protocol.md, section 14).

- The Android app is signed with a new release key from 0.6 on. Android installs an update
  only with the same key, so an APK of 0.3 to 0.5 has to be uninstalled before 0.6 is
  installed (the phone then joins its group again).
- The keys that sign releases (Android, Windows, the OpenWrt feed, the Homebrew tap) are
  secrets of the environment `release`, which only release tags and `main` may use, instead
  of repository secrets that any branch's workflow could read (docs/maintaining.md,
  "Release secrets").
- CI runs only the jobs of the parts a pull request changes (`.github/ci-changes.sh`), so a
  pull request of documentation no longer builds the phone apps, the lite member and the
  firmware, and one brought up to date with main runs again only the jobs of its own parts.
- The documentation is arranged by reader: the guide for users, `docs/admin/` for running
  servers (`self-hosting.md` moved there from `docs/reference/`), the reference, and the
  pages for engineers and maintainers, each part with its own table in `docs/README.md`.
  New reference pages: `config.md`, every settings file and every `CBB_*` variable (moved
  out of `cli.md`, with the ones it lacked: `CBB_TPM`, `CBB_ADMIN_SOCKET`, the installers'
  `CBB_VERIFY` and `CBB_ATTESTATION`, the test variables); `limits.md`, every size, rate,
  timeout and lifetime; `errors.md`, how each part shows errors and the switch that shows
  their details; and `glossary.md`.
  New guide pages for what 0.6 adds: images, files and formatted text; remote paste; quick
  actions; what to do when a device is lost or stolen; keyboards and TVs (the Android app,
  `cbb keyboard`, the Nano ESP32 and `cbb remote`, side by side); and privacy, one table of
  everyone outside the group who sees something, from the home network to the update
  check, and how to avoid it. `docs/admin/routers.md` is for OpenWrt, OPNsense and FreeBSD:
  what the installers set up, the networks the service answers on, the firewall and how to
  check it. `limits.md` has the keyboards' and TVs' limits.
  `devices.md` says what 0.6 devices do: images and files, remote paste, quick actions, keys
  in the TPM, FreeBSD and OpenWrt.
- `tools/repocheck` also checks that every `CBB_*` variable the code, the installers and the
  systemd units read is in `docs/reference/config.md`, that every page below `docs/` is
  reached from `docs/README.md`, that no page calls something "planned for" a version
  that is out already, that every subcommand of `cbb` with flags of its own and each of
  its flags is in `docs/reference/cli.md`, and that every port the code listens on by
  default is in the ports table of `docs/reference/devices.md`. The pages for users and
  administrators may not tell the reader something is easy ("simply", "easily") or call
  the product `clipboardbridge` outside code, links and quotes, and every field of the
  control socket's header must be in section 8 of `docs/protocol.md`. Against a base, it
  also reports a test that skips where it did not, and counts the Swift tests of the Xcode
  projects' test targets too.
- A fresh read of docs/protocol.md against the code fixed the length of CPace's channel
  identifier (88 bytes, not 83), and added what an implementation needs and could not find:
  the forwarder's and relay's framing (JSON lines, at most 1 MiB), the TLS parameters every
  implementation must support (X25519, TLS_AES_128_GCM_SHA256, ECDSA P-256), the records'
  8 KiB limit, encodings and validity, the exact digest of the record IDs, the device
  record's `kind` and `proof`, the attestation challenge's group tag, AmneziaWG's sizes and
  where its header protection is defined, the registration ID's 64 bits, the missing message
  and control header fields, and the hub exception for phones. docs/cryptography.md says
  which keys do leave a device, the member certificates' real lifetime on phones (2 years;
  397 days is the `clipboardbridge.local` certificate's, in limits.md too) and the
  invitation secret; the threat model says which WireGuard keys a hub admits.
- docs/design.md follows arc42: goals and constraints, context, solution strategy, building
  blocks, runtime, deployment, crosscutting concepts, decisions, quality requirements, risks
  and glossary. The decisions D-1 to D-78 have a register with their status
  (`docs/decisions.md`), and the threats a model of their own (`docs/threat-model.md`,
  STRIDE, with the defence and the code for each). The design no longer describes the 0.2
  group, where Linux members held the CA keys, and says what 0.5 and 0.6 built: the Mac as
  a hub, the phones away from home, the server credentials in both phone kits, the project's
  forwarder at `cbb.tools`.
- The designs that are built moved from docs/roadmap.md into docs/design.md: quick
  actions, secure updates, watches, what the servers learn, the phone hub's steps, OpenWrt,
  Docker and FreeBSD. The roadmap keeps what comes next, its items sorted into done, partly
  done and next, under the same numbers.
- docs/protocol.md is normative: BCP 14 keywords (RFC 2119, RFC 8174) mark what an
  implementation must do to interoperate and to keep the group safe, the edition and its
  rule for changes are stated, the registries of every name in use are in section 19
  (ALPN IDs, exporter labels, certificate names, messages, values, addresses), and the
  security considerations in section 20. Stale notes about design.md's line numbers are
  gone.
- The documentation is on the website too, at `cbb.tools/docs/`: `tools/site` renders every
  page of `docs/` and the few it links to with goldmark, keeps GitHub's anchors, sends
  links to the code to GitHub, and lists the pages in the sitemap; the site's "Docs" link
  leads there.
- New pages: docs/cryptography.md (every primitive, library and key, with its size,
  lifetime and storage), docs/testing.md (the test levels, the interop vectors, the cross
  tests, the bench), docs/admin/upgrade-and-backup.md and docs/admin/hardening.md. The
  command reference lists `cbb global move`.
- `cbb forward` keeps no file per group any more, and deletes those earlier versions kept
  (D-75): only `forward-state.json`, which holds, under a keyed hash of each period's tag,
  the version of its newest credential and a hash of its period key (`-state`, `none` for
  memory only). It refuses an older credential or another period key, also after a restart;
  records from older hubs and from phones' groups stay in memory only.
- `cbb forward` and `cbb relay` log no address and no WireGuard key: an error from the network
  or from WireGuard, and with `CBB_DEBUG=1` WireGuard's own messages, are logged without
  them.
- The control socket asks for buffers of 1 MiB each way. On a Mac a Unix socket has 8 KiB,
  so `cbb copy` of large files and the connectors' images woke both sides a hundred times for
  each MiB.
- A computer whose keys sit in a file becomes an admin only when the user allows it: `cbb
  admin -allow-file-key NAME`, and the phones' "Make it an admin" dialog warns what that
  means. `cbb new` warns that the root key is a file.
- `get.ps1` no longer stops in Windows PowerShell 5.1 when `gh` is installed but not signed
  in.
- A copy of files whose names, as a receiver writes the names Windows reserves (`COM0` as
  `COM0_`), would grow past 255 bytes, or whose paths would become one or go through a file,
  is refused by every member when it arrives, instead of failing as it is written.
- When the root signed two own device records at the same time, the phones take the one
  with the greater record ID as its own device, as the computers and the lite member do, so
  every member agrees which device holds the root and whether it is a phone or a computer.

### Removed

- The Rust core's reader of group records of version 1 (`records`): commands now live in
  `command`, and the interop vectors of version 1 (`go-*.json` for records, commands, hubs
  and credentials) give way to the `v2-*.json` vectors of the same cases.

### Fixed

- The phones show where the hub can move while it has no forwarder yet, and ask for the
  forwarder first, instead of hiding the choice.
- A remote paste to a Mac answers in time when the Mac's clipboard holds what Universal
  Clipboard brought from another Apple device: the app no longer reads it to put it back,
  which fetched it from that device first, and it no longer naps while it pastes.
- `cbb global` says "for 1 device", not "1 devices".
- The iPhone app shows why a computer refused a remote paste under the text, where the
  keyboard no longer hides it.
- The Mac app shows "Allowed" for remote paste once Accessibility allows it, without
  a restart, and "Allow…" opens System Settings again after the leave was taken back.
- On Windows the service names the user of the agent, so it gives it remote pastes and quick
  actions: the service's own account could not look up another user's process, and every
  agent was a user the system does not name.
- The iPhone app shows the group's notifications (a device joined, was removed, and the
  others) while it is open too: iOS dropped them there.
- `cbb keyboard` on a computer in no group said it cannot be a Bluetooth keyboard, though
  the keyboard ran: the status left the keyboard out without a group. `cbb keyboard on
  -layout us` works in the usage's order too, with the flags after the verb.
- The tray app's buttons draw their icons in the middle: they were text symbols, which
  Windows takes from fallback fonts that set them off centre.
- A computer takes member connections to its IPv6 link-local address: it closed them at once,
  as from a network it had not met its group on, so a phone that reached it that way (as
  iOS often does) never connected. The log now says when it closes a connection for that.
- The Mac and Windows installers no longer tell a device already in a group to join one
  after an update.
- A watcher the service refuses (a paste target or the quick actions offered by a user the
  system does not name) is logged once in 10 minutes instead of at each try, every 2 seconds;
  on Windows the line says what the system did not tell.
- A computer's log no longer fills with a line each time a phone's system ends the app's
  connection in the background (a reset or a close by the peer); with `CBB_DEBUG=1` the log
  still has them, and a failed handshake is logged as before.
- The phone app finds the computers again when iOS stopped its browsing: on the first launch,
  where it browses before the user allows the local network, and in the background. A browser
  that waits or fails starts again (after 1 s, doubling to 30 s), and the app browses again
  when it comes back to the front without a computer connected.
- The tray app keeps the last of quick changes in its settings: two changes close together
  could leave the earlier one in `desktop.json`.
- The tray app no longer hangs when the service does not answer, and opened while the
  service is not running it says so instead of showing an empty window.
- On Linux the tray item is named Clipboard Bridge instead of Wails.
- The Mac and iPhone apps take ShowErrorDetails given as YES or NO text, as a launch argument gives it;
  before, such a value was ignored.
- A computer that signs two group records in one pass, or at the same moment, gives them
  consecutive numbers: before, both could take one number, which reads as two histories of
  the signer and, for the root, stops the group.
- A member that ends its connections after saying goodbye, as after `cbb global off -on`
  turned sync away from home off there, no longer resets them: it stops sending and reads
  what the other device still sends before it closes. A reset could make the admin lose the
  command's result and report that the device closed the connection before it answered.
- install.sh no longer fails with ufw on a computer whose kernel has no IPv6
  (`ipv6.disable=1`) or whose ufw has `IPV6=no`: the firewall rules it lists, prints and
  adds then name the IPv4 home networks only.
- A relay on Windows told to listen on any free port no longer gives up when
  the ports the system hands out fall in a range Windows reserves for the other protocol; it
  takes turns picking the UDP port first and the TCP port first.
- The pairing window issues a joiner's certificate by the time-scaled build's clock, as the
  renewals do, so the bench can check a join near the end of the group CA (K5); a release
  build is unchanged.
- The lite member no longer stops the download tool after it has finished, so a download
  the tool ends a moment after its output stands.
- A replaced image's or file's parts leave the cache 10 minutes after the copy that replaced
  them even when no further copy comes; the service sweeps the cache every minute instead of
  only on the next copy.
- Uninstalling on Linux also removes what the installer created and nothing else uses
  any more: an `/etc/tmux.conf` left with only blank lines and an empty `/etc/xdg/autostart`.
- A JPEG pasted on Windows stays within the image memory bound: the PNG that goes on the
  clipboard with it is made from the bitmap once the decoded pixels are dropped, in one
  buffer, and the bound counts it.
- The roots a group knows are found from two sides until they settle (docs/protocol.md,
  section 10, rule 2), in every implementation. A root that an admin phone hands the group
  to counts only when no root that may count removes that phone, so a removal by a new root
  holds whichever phone's record made that root known. Where two admin phones hand the
  group to roots that would remove each other's phone, neither root counts and both phones
  are removed. More cases in `testdata/interop/go-removed-admins.json`, which Go checks in
  every order, and the differential corpus gives every record set in other orders too.
- A connection through the hub's tunnel that closes right after it opens no longer stops
  the relay or a hub: the tunnel keeps each connection's addresses from when it was set up,
  on a computer and in the phones' tunnel, and drops one that is gone before it is taken.
- A copy of files may hold the other device names of Windows (`COM0`, `LPT0`, `COM` or `LPT`
  with a superscript digit, `CONIN$`, `CONOUT$`, and these with spaces before the dot): a
  computer writes them with `_` after the name's base, and every program gives its own
  names that form before it sends them. The names Windows reserves are compared alike on
  every member (docs/protocol.md, section 4; `testdata/interop/media-names.json`).
- The lite member's updater asks the next update server when the first one's files are
  out of date, as the full member's does, and stops only at a signature that fails or at
  files older than ones it has seen.
- The open relay and the forwarder count what one IPv6 provider (a /32) holds, as they count
  a wide network: registrations (1024), credential versions (4096), records (16 MiB),
  setups and requests being read, and the setups and record checks paid by the second; the
  forwarder forgets the records of groups that are away from the provider that holds the
  most (docs/relay-budget.md). An IPv4 /16 is its own provider.
- The memory a received JPEG takes on a Windows member is counted as image/jpeg uses it: a
  progressive JPEG's coefficients for every block, the black plane of a four-component one
  and the image an unusual layout or CMYK is converted to, from the frame header before any
  pixel is read, so the 384 MiB bound holds for every JPEG.
- The Kotlin kit reads P-256 keys (in server credentials, release keys and certificates)
  exactly as the other implementations do; `strict-files.json` has vectors for it.
- The forwarder counts only the groups that are away against the 32 MiB it keeps of their
  authority records, and past it forgets from the wide network that holds the most of them
  (docs/relay-budget.md), so the records of a group that is away outlast the groups of other
  networks.
- Release files are read alike by every program that checks them. Go read a file entry
  without `size` as 0; Go, the lite member and `get.sh` took a key whose `use` is empty as a
  release key; the lite member took a key with a compressed point; the Swift kit took a
  channel, a name or a hash with a line break after it. All of these are refused now, and a
  server credential's key with a compressed point too. `get.sh` and `get.ps1` refuse a body
  with a member name in upper case, a `null`, a field written twice or no `time_ms`, as the
  programs do, and `get.sh` no longer takes a status key whose name holds a brace for a
  release key; `get.ps1` compares names and hashes in their case. `release-sign drill
  -fault` makes such files for the installers' tests.
- Server credentials and release files are read in the strict form of signed bodies, as
  records and commands are, in Go, the lite member and both phone kits: a credential before
  its signature is checked. A release file without `time_ms` or another field its table does
  not call optional is refused everywhere; Go and the Android kit read a missing `time_ms` as
  0, and the Android kit took a `time_ms` of any type in `release.json`.
- The lite member and both phone apps check a hub command's order as Go does: a forwarder with an
  address and a key or an address at least, at most 8 addresses and 256 clients, each client
  a device ID once with keys of 32 bytes.
- On Windows the service makes the admin socket's directory before the control socket's, and
  makes it again at each start unless the system, the administrators or the service owns it,
  so no other user can own the directory of the admin socket.
- On Linux a remote paste to the desktop, and a quick action, go only to a user with an
  active graphical session (X11 or Wayland), no longer to one signed in over SSH alone or to a
  user's service manager; tmux still takes a user with any session. The same on the lite
  member.
- After a long outage two members find each other again within seconds both ways: the
  one that lost the other earlier sent its quick browse queries while it was off the
  network and could wait minutes for the next one. A member now announces itself once when
  it finds a member it did not have.
- A pre-release tag (`vX.Y.Z-rc.N`) gets its notes from CHANGELOG's *Unreleased*; it
  failed at the end of the release for want of a section of its own.
- The forwarder bounds what it remembers of the groups that registered with records and are
  gone: 32 MiB in all, the group kept least recently forgotten first and the records of a
  group that is registered now never. It refuses a registration whose authority records
  come to more than 256 KiB, rather than keep part of them; a group that registers again no
  longer costs time in proportion to the square of its records. Hubs see the refusal as an
  ordinary one; nothing else on the wire changes.
- The forwarder keeps what it remembers of a group's credentials until the newest one has
  expired, instead of forgetting the oldest group when its table fills: a period tag new to
  the table is refused when the table, or 256 entries of one network, are full, and the
  table is written to its state file a moment after a change (and when the forwarder
  stops), no longer under the lock of every registration. State files from earlier versions
  are read as before.
- A relay counts the requests being read in its tunnels by group and by the address and
  network the devices registered from, besides by device, waits 5 s instead of 15 s for a
  request line, and charges the registrations an address and a network start by the
  second. An open relay verifies a group's records once and keeps the verified set, keeps
  at most 256 KiB of records for one group and 128 MiB in all, and refuses a registration
  past those rather than keep part of its records. Devices see the new refusals as
  ordinary ones; nothing on the wire changes.
- Every member refuses a command signed at a negative `time_ms`, as it already refused
  such release files; the iPhone app no longer stops on one.
- The phone apps keep the peer's cancels only of the parts they queue or serve, as the
  service does.
- The lite member gives the TLS handshake on its ports 10 s in all, not 10 s for each read.
- A relay that refuses a registration is left as it was: it keeps nothing of the refused
  device's group, period or records, and keeps a period's key and versions while a group's
  devices change under a newer members' credential.
- The open relay and the forwarder keep one budget (docs/relay-budget.md, `internal/budget`):
  what each source starts and holds is charged to its address, its network (/24, /64) and its
  wide network (/16, /48), each with a cap, and what is full refuses the new. Registrations
  are bounded at 256 from one wide network, setups being set up at 128, requests read in a
  relay's tunnels at 64; a forwarder keeps at most 1024 credential versions from one wide
  network, and both servers at most 1 MiB of authority records from one network and 4 MiB
  from one wide network. A client over VLESS reaches only its own group's hub, and a
  client's next handshake from an address that has a session is checked against its group
  first; neither spends the budget for handshakes to unknown groups. The forwarder keeps
  every signer's copy of a record its hub sends, as a group's records do, and a refused
  registration no longer drops the group's earlier one. Hubs and devices see the new
  refusals as ordinary ones; nothing on the wire changes.
- A root record that an admin phone signs counts only while no known root's own key, and no
  other admin phone that is not removed itself, has revoked that admin phone, so a removed
  admin phone hands the group to nobody, whichever root or admin removed it. Known roots
  are found in rounds, and a removal found in one stays, so the result does not depend on
  the order of the records (docs/protocol.md, section 10, rule 2). The same on computers,
  the lite member and both phones, checked against `testdata/interop/go-removed-admins.json`.
- Every member reads a group's records alike in all implementations: a body signed by more
  than one signer is kept under each signer, so what a device makes of the records no longer
  depends on whose copy came first, and the records digest of the hello covers each record's
  signer too (docs/protocol.md, section 10). Until every member of a group runs this
  version, members of both kinds send each other their records at each connection. The lite
  member refuses a body whose `kind` or `proof` is not a string, and the phone kits a body
  over 8 KiB, as the Go member already did.
- A channel or status file may raise its `seq` at most 65 536 on a fresh device or under a
  newer `keys.json` too, as it already could over a `seq` taken, and a signed release file
  with a negative `time_ms` is refused, so a file's lifetime is always measured right. On
  computers, the lite member and both phones; files the project signs are unaffected.
- The control sockets take at most 64 open connections from one user and close one that
  sends no request within 30 seconds, and read a request's payload as it arrives, on computers
  and the lite member.
- The lite member dials at most 64 members found by browsing and remembers at most 64 found
  at home; its tunnel's local port takes only its own user's connections, 32 at most, and it
  refuses a hub offer with a key of zeros or a port 0, as Go does.
- The lite member's tmux helper keeps its log private (0600) and bounded at 1 MiB, and names
  its lock as the Go helper does, so that the two never run for one tmux server.
- On Windows the service moves aside whatever another user put in the place of the admin
  socket's directory, a junction or a file included, instead of removing it, makes the
  directory with its narrow access list from the start, and checks and narrows it through one
  handle. A folder or file in the place of the control socket is moved aside too, so it no
  longer keeps the service from starting.
- The Windows installer moves aside a data folder in ProgramData that is a link or that
  neither the administrators nor the system owns, instead of resetting what is inside it.
- A paste typed on a Bluetooth keyboard or a Roku after its answer stops once remote paste is
  turned off or the sender's command no longer holds, and each takes one text at a time.
- A computer whose member key is in a TPM opens a credential only from the group's root and
  one at a time, so other members cannot keep its TPM busy.
- An EK certificate counts only in the form of TCG's EK profile: no CA, a key for decrypting,
  the EK purpose when it names purposes and the TPM's maker in its alternative name.
- The tray app on Linux runs only a `cbb` that root owns and no one else may change, never
  one found on `PATH`, and on Windows finds Program Files from the system, not from the
  environment. When neither place holds such a `cbb`, it runs nothing as root and says to
  install it again or to use `sudo cbb` in a terminal.
- `CBB_ROOTLESS` set to anything but `1` no longer hides a rootless install from the Go
  commands, and a linked `~/.local` or `~/.local/bin` is resolved as the lite member does.
- `cbb update` takes a release name from the channel file, and a version asked for, only when
  it is a version, before it builds an address from it, on computers and the lite member. The
  lite member's downloads stop after 30 minutes and write no more than their limit to the
  disk with wget and uclient-fetch too, and curl takes the address as it is.
- A hub tells the group's other hubs of a client it admits at once, not only when it starts
  or stops serving, so a client that met only that hub reaches another one once it is off.
- `get.sh` and `get.ps1` install a release only when its `release.json` is one for the
  channel they follow, as `cbb update` already checked, and the Android app's own update
  keeps the highest version it has seen, so its channel never goes back below it.
- The website's `/preview` takes a key of 16 to 128 letters, digits, `-` and `_` only, sets
  no cookie for any other, and answers at most a few requests a minute from one address.
  The site's nginx configuration parses again, and CI's `website` job checks it with
  `nginx -t` in nginx's image (`.github/nginx-check.sh`).
- The lite member keeps a full member's own quick actions when it saves the shared
  `actions.json` and offers only its presets, and counts KDE's lock screen as locked, as
  computers do.
- Both phones answer a command to turn remote paste or quick actions off as done when they
  have none to turn off, and refuse a quick action or a paste they cannot take with the
  right reason, not one about the hub.
- `docs/protocol.md` says which operations the lite member's control socket leaves out, and
  that it gives a desktop watcher no grant for the uinput helper; `docs/design.md` no longer
  lists the Nano ESP32 as a remote paste target, and the limits per sender are named as
  such.
- Both phones admit a joining computer as computers do: its name must be printable (no
  format, private-use or invisible characters), it must send one certificate, and its key
  must be a P-256 key.
- Both phones send their records in messages of about 1 MiB, as computers do, so a large
  set no longer fails to reach a member that is behind.
- The iPhone checks the protocol a TLS handshake agreed on and turns session tickets and
  resumption off, as the other members do.
- Both phones dial at most 64 members found on the network at once, and take a hub's offer
  only with keys that are not all zeros and endpoints with a port, as computers do.
- The iPhone compares the paths of a copied folder byte for byte, so names in NFC and NFD
  are two files, as on the other members; `strict.json` has these manifests now.
- A phone that is the hub shares a client it admits with the group's other hubs at once, as
  a computer does.
- The phone kits run CPace's low-order vectors, as Go and the lite member do.
- Every frame of the member protocol holds only integers written as in signed bodies, members
  a reader does not know included: a frame with `-0`, a fraction or an exponent is no message on
  computers, the lite member and both phones alike, where some took `-0` for 0 before.
- A session counts as at the screen for remote paste and quick actions only on a seat or when
  logind says it is not remote, on computers and the lite member.
- The lock check names logind's own session (`auto`) when `XDG_SESSION_ID` is not set.
- The tray app on Windows doubles every kind of single quote in what it hands PowerShell.
- The lite member takes the key store `rootless` in device records, as the others do.
- A relay goes by a device's whole certificate chain against the group's records, as members
  do: it refuses and drops a device whose admin was removed, unless the removal keeps it.
- A command whose signer's device the receiver's records do not show may not name in `by` a
  device they do show, and the limits on pastes and actions and the logs then count its
  signing key, with the log entry marked unverified. The same on computers, the lite member
  and both phones.
- A command's `by` must be a device ID and, when the receiver's records show which device
  holds the signing key, that device; the limits on pastes and actions from one device and
  the logs then count the device that signed. The same on computers, the lite member and
  both phones. A member from before still takes a command whose `by` names another device;
  no current sender writes one.
- The release workflow run by hand from `main` builds the OpenWrt feed: it named the
  package's version after the branch, which apk refuses.
- A forwarder keeps the handshake budgets of clients that come over VLESS apart for each
  group's VLESS user ID, which its side of VLESS now tells it, so the clients of one group no
  longer use up those of the other groups. Its tables of sources and networks drop the entry
  used least recently when full, instead of refusing new clients. Clients and hubs need no
  change.
- Every member reads a record, a command and a media manifest with a number written `-0`
  alike: all refuse it, as they refuse a fraction or an exponent, where before Go and the
  Android kit took it for 0 and the lite member refused it. The phone kits also refuse such
  numbers in the other messages they read, as the lite member does. A member from before still takes `-0` in a
  body that a current member refuses; no current signer writes one.
- Checking an Android key attestation (Go, the iPhone app's kit and the Android kit) now
  requires every certificate that signs another one in the chain to be a CA that may sign
  certificates, with a path length that fits, and takes the Remote Key Provisioning mark only
  from such a certificate. Real Keystore chains are unchanged; a chain in which a key's own
  leaf certificate signs another certificate now proves nothing. A root running an older
  version keeps accepting such chains until it is updated.
- A command's result is shown with its reason cut to 256 bytes and its control characters
  made spaces, on computers and both phones, so it always shows as plain text.
- A content chunk whose length field is 2^31 or more is refused on the 32-bit builds
  (Raspberry Pi 2 and 3, Pi Zero, mipsle routers, 386) as it already was on 64-bit ones,
  instead of ending the program.
- A received PNG or JPEG is decoded on a Windows member only when it takes at most 384 MiB
  decoded and as the clipboard's bitmap together, which holds a 48-megapixel photo, counted
  from its header (and a PNG's transparency) before any pixel is read; it was 2^28 pixels,
  which a small file could fill with gigabytes. A PNG is also turned into
  the clipboard's bitmap by copying rows, not pixel by pixel. A bitmap on the Windows
  clipboard with a header of 41 to 55 bytes and color masks is refused instead of ending
  the agent.
- The lite member writes its state files through a temporary file with a random name that
  must not exist yet, and removes it when the write fails; `attest-status` gives up on
  Google's list after 30 s instead of waiting for it without end.
- A copied file's name made fit for every system no longer comes out one byte over the
  255-byte limit when it is that long, Windows reserves its base and it ends in a dot; a
  valid name of 255 bytes stays as it is. The same on computers and both phones.
- An admin's command for a device it is not connected to, such as a remote paste, now goes
  only through the group's hubs (the root and the admins), not through every member, on
  computers and both phone apps.
- A device that restarts no longer carries out again a command it took just before the
  restart: computers, phones and the lite member refuse a command signed before they
  started, and the reason asks the sender to send it again.
- A pairing window or an invitation on an admin failed every joiner with "wrong code" once
  the admin's certificates changed while it was open, as when the root sends a new admin
  its admin CA again right after making it an admin; the window now presents the
  certificate it opened with.
- Removing an admin, or taking the group over from a lost root, no longer cuts off the
  devices whose certificates it had only renewed: the revocation keeps every listed device,
  not just those it admitted, on computers, phones and the lite member alike. A member no
  longer takes a renewed certificate from a removed admin or an old root.
- Taking the group over from a lost root no longer cuts off the devices that an admin
  removed earlier had admitted: their certificates hold through that admin's CA, which the
  takeover now keeps under the old root, on computers and phones alike.
- An admin computer made by one root takes the group over from the next root correctly:
  after a takeover the new root gives every other admin computer a new admin CA for the
  same key and records it under itself. Before, the second takeover split the group's roots
  and the records of the root in between, such as a new name, stopped counting. `cbb
  takeover` refuses on an admin that has not met the current root since.
- A member that was off or cut off while an admin took the group over follows the new root
  when it meets only that root afterwards: the new root presents the member certificate it
  had before the takeover, which the member still trusts, until that certificate is due for
  renewal. Before, such a member could not verify the new root and stayed apart.
- Members find each other again soon after one was off the network for a couple of minutes
  without a change to its interfaces, as when a firewall dropped its packets: the member that
  lost another asks for the service again from 1 s, doubling, and no longer lists the lost
  member's PTR record as a known answer, which kept it from answering. Before, they could stay
  apart for up to an hour. The bench's random walk (G40) found it.
- An admin computer that the lost root had frozen, and the new root unfroze, gets its admin
  CA from the new root and can take the group over in turn: an admin CA that comes before
  the records that make it valid is kept and taken once they are in. Before, it was dropped,
  and `cbb takeover` on that admin refused. `cbb status` on a frozen admin says it is
  frozen, not removed.
- `cbb status` on an admin computer, and on a device an admin admitted, no longer says the
  device was removed from the group: it checked the device's certificate without the admin
  CA that issued it.
- `cbb invite` stopped with Ctrl+C deletes its invitation file, as it says it does; it was
  left on the disk. `cbb pair -invite` given up with Ctrl+C takes back its leave to reach
  the hub's addresses.
- A device whose third wrong attempt closes an invitation's window hears so at once; it
  waited minutes, because the hub dropped its guest tunnel before the answer passed.
- A second device using an invitation that was used hears that its pairing window is
  closed, not "tls: internal error".
- The installers and `cbb update` keep a `CBB_INTERFACES` line set by hand in
  `clipboardbridge.env` (Linux, macOS, FreeBSD) or in the service's registry environment
  (Windows); before, the next install or update dropped it, and the service then answered
  on every interface again.
- The forwarder's drop-in for VLESS on port 443 also sets `PrivateUsers=no`: inside the
  unit's own user namespace the capability did not cover the host's network, so the bind
  was refused (docs/admin/self-hosting.md).
- A computer that comes back after its hub moved on to its key for the new period reaches
  the hub at once: it tries the hub's old key and the next one together instead of waiting
  10 seconds for the old key's handshake first, and keeps that link when the hub's new offer
  names the key it already uses, instead of starting it again at once, which the hub refused
  as too soon after the last handshake and cost another 5 seconds. The hub starts its tunnel
  with the new key before its state names it.
- A computer away from home reaches its hub over a slow way, such as VLESS on a busy
  machine: a try goes on while the hub keeps answering, for up to a minute, and ends after
  10 seconds without a word from it, instead of being dropped and started over with a new
  handshake that took as long again.
- An image or file fetched again after a fetch that gave up no longer gives up itself on a
  slow link: the pieces the peer still sends for the first fetch now count as the peer
  sending, so only a peer that sends nothing for 15 seconds ends a fetch.
- The Android app's dependencies take Guava 33.7.2, which fixes GHSA-xxph-c9ww-hj94 in the
  33.3.1 that CameraX and Media3 bring in.
- `cbb revoke`, `takeover`, `freeze`, `unfreeze` and `holder` with `-h` print their usage
  instead of asking the service about a device named `-h`.
- The TV remote's errors name `cbb remote add`, the command that adds a TV, instead of
  `cbb tv add`, which does not exist.
- A device that registers with its relay again, after the group's credentials changed, no
  longer stays off the relay for up to 25 seconds: a dial or an answer it was waiting on
  ends with the old registration instead of at its timeout, and the device says in its log
  that it registers again.
- `cbb status` says when this device's certificate has ended, or ends within 30 days with no
  admin to renew it; before, a member whose certificate ended while no admin was on was
  refused by the group with no word why. When the certificate has ended by this device's
  clock, it names that date too, in case the clock is wrong.
- A root computer that an admin took the group over from while it was away could not undo
  the takeover, as docs/design.md says it does: the others refused its connections, so its
  removal of that admin reached no one, and it gave up its root key when it heard of the
  takeover. Full members now exchange records, and nothing else, with such an old root; it
  keeps its root key and iPhone CA, `cbb status` there names the admin that took over, and
  `cbb revoke` of that admin, before or after it heard, undoes the takeover
  (docs/protocol.md, section 10). Going back to the group's first root no longer crashes
  the service.
- `cbb pair` on a new computer, with two pairing windows open on the network, could try the
  code on whichever window answered first, a wrong code there that counts toward closing it,
  when the other answered a moment later. It now listens two more seconds after finding one
  window and, with two, asks for the address that `cbb pair` showed.
- `cbb paste-receive on -enter` and `on -console`, as the usage and the refusals say, stopped
  with the usage on a full member: the flags were taken only before `on`. Both orders work
  now.
- A device whose clock was more than 7 days ahead, and then set right, had its copies
  refused by the group until real time caught up with the clock it had: its saved clock
  mark kept it ahead. At the next start of the service, a full or lite member now drops
  such a mark and goes by its clock.
- After `cbb takeover` the new root could not admit a computer: the joiner refused the
  member certificate it still had from its admin CA. The new root now issues its own
  certificate from the new root at once. A pairing that fails a certificate check shows
  the check's own words only with `CBB_DEBUG=1`.
- `cbb revoke` names the device it refuses to remove, and `cbb pair -code` asks for the
  code only on a terminal.
- With the service stopped, `cbb` said "not running" followed by the system's error
  (`dial unix …: connect: no such file or directory`) in a release build. It now says how
  to start the service, and shows the system's error under it only with `CBB_DEBUG=1`.
- A fetch of an image or a file could wait for ever when the peer dropped its ranges, as
  after it answered that it did not hold the part yet: a fetch that gets nothing for 15
  seconds now gives up and asks again, a fetch that ends cancels the ranges still asked
  for, and a chunk that comes after its fetch ended no longer blocks the connection.
- A phone's fetch of an image or a file no longer waits for ever on a device that stopped
  sending: after 15 seconds without any of the part it gives up, and on "missing" or a stall
  it cancels what it asked for, as computers now do.
- The iPhone's member key and its certificate are readable while the phone is locked, once
  it was unlocked after starting, so that sync works in the background; the root and admin
  keys still sign only while it is unlocked, after Face ID. Keys made before keep the old
  setting.
- `cbb status` away from home could show a peer at the relay by its pseudonym instead of
  its device, when the credential that names it came after the relay reported it online:
  the names are now mapped each time the status is asked for.

## [0.5.0] - 2026-10-26

### Added

- An open blind relay: `cbb relay -open` serves every group that registers, as the project's
  relay at `cbb.tools` will, within limits that keep groups nobody vouches for from filling
  it: 4096 groups, 16 registrations from one address and 64 from one network, and 1 MiB a
  second of copying for each group. It forgets a group once its last device leaves.
- The blind relay on the phones, Android and the iPhone: under **Blind relay** in Settings,
  the relay's address and key, as `cbb relay` prints them. The app first says what the relay
  learns and asks; then the phone meets the group's devices there while it syncs, dialing
  and answering through `mobile/cbbtun`. A call reaches the phone's member listener only
  when the device's certificate names the device the relay announced for that connection,
  so the relay cannot pose as another member.
- The phone as the group's hub while its app is open, on Android and the iPhone: on from the
  start in a group made on the phone, and a switch in Settings on a root or admin phone. At
  home the other phones, TVs and lite members connect to it; it takes them and publishes
  itself (`r=phone`) only on the home networks it remembers. With a forwarder set in
  Settings (its address and key, as `cbb forward` prints them) it registers there by its
  member key, and devices away from home reach it. On Android it may keep running in the
  foreground service. The computers and the lite member do not dial a phone that publishes
  itself, since it dials them.
- Remote invitations from a phone that is the hub: Settings makes one for an hour while the
  hub is registered with its forwarder, shares its file, and asks whether to admit the
  device that uses it, by its fingerprint, which `cbb pair -invite` shows too
  (docs/protocol.md, section 12).
- Moving the hub to an admin computer: `cbb global move DEVICE` on a computer that is the
  hub, and "Move the hub to a computer" in Settings on a phone that is the hub, which
  suggests a computer that is always on and makes it an admin first if it is not one. The
  old hub hands over its clients' keys in a signed command and passes the new hub's offer to
  its connected clients, so devices far away follow without coming home; the old hub then
  becomes a client. An admin phone that takes the group over from a lost root phone that was
  the hub becomes the hub (docs/protocol.md, section 11).
- Several hubs: the root and every admin with a hub set up are the group's hubs, in an order
  every device takes from the records (phones first, then the root, then by device ID).
  Each device keeps every hub's offer and, away from home, uses the first that answers,
  trying the ones above again every 5 minutes. Each device offers its own preshared key, and
  the hubs share their clients and pass each other's offers on, so any hub can serve any
  device. A computer that is a hub serves only while no hub above it answers and is that
  hub's client otherwise; a phone that is the hub does not yet give way (docs/protocol.md,
  section 11, "Several hubs"). In `cbb`, the lite member and both phone apps.
- A client away from home tries a phone hub at least every 5 s, since it is there only while
  its app is open; a computer hub is still tried up to every 30 s. In `cbb`, the lite member
  and both phone apps.
- Docker: an image of the full service for a NAS or a home server, built from scratch with
  only `cbb` in it, for amd64, arm64 and armv7; it runs as its own user without
  capabilities, on a read-only root file system, with its state in one volume. Compose files
  run it as an always-on member at home or as a forwarder or relay on a server
  (packaging/docker). Each release publishes it as `ghcr.io/hunterewok/clipboardbridge` with a
  build provenance attestation and gives its digest in the release notes.
- Sync modes on the computers: `cbb mode own|shared|receive|send` sets what moves between a
  computer's clipboard and the group. A computer that makes or joins a group from now on
  keeps its own clipboard (own): its copies stay on it and the group's do not come, while
  `cbb copy` and the phones still send to the group and `cbb paste` prints the group's
  text. Computers that joined before keep sharing. `cbb status` shows the mode, and each
  computer's hello reports it for the devices list.
- An admin sets the sync mode of another computer with `cbb mode -on DEVICE MODE`: a
  command signed by the admin's key, which the computer checks against the group's records,
  takes once and only within 30 s (docs/protocol.md, section 15). The phone kits read the
  mode in the hellos and send such commands.
- The apps show each connected computer's sync mode. The Mac app and the tray app set this
  computer's mode in Settings and, on an admin, another computer's from its details; an
  admin iPhone or Android phone sets a computer's mode from its page, after Face ID or the
  fingerprint, and says if the computer refused.
- Sync modes on the phones and the lite member. Each phone sets its own mode on its page in
  the devices list, and an admin phone sets any connected device's; Android's foreground
  service writes the group's copies to the clipboard only in a mode that receives, and its
  accessibility service sends copies by itself only in one that sends. The iPhone, in a mode
  that receives, now writes a group copy from the last 45 s to the pasteboard while the app
  is open; this includes phones that joined before, which share. The lite member keeps its
  mode in the file `mode` (`sudo cbb mode own|shared|receive|send`), starts in own when it
  joins, and `cbb paste` there prints the group's text in a mode that does not receive.
  Phones and the lite member take an admin's `mode` command, checked as the computers check
  it, and refuse `hub` commands. The interop vectors gain `go-commands.json`.
- The phone's side of the phone as the hub (D-64), not yet in the apps: `mobile/cbbtun`
  runs the group's hub in the app's process (`StartHub`), leads the clients' connections to
  the kit's member listener and registers with the forwarder (`Register`). A phone hub
  registers with its member key, without Face ID, when the group's records make that key
  the root's or an admin's; the forwarder now takes such a registration
  (docs/protocol.md, section 13). Both phone kits listen for member connections
  (`MemberListener`) and, as the hub, admit a client by the tunnel key its hello offers and
  answer with the offer (`PhoneHub`).
- The hardware bench takes a member in a container (`os = "docker"` in its inventory),
  reached by `docker exec` on its host. It joins as an ordinary member and never makes the
  group, whose CA keys stay off a container; `full` checks that it runs locked down as
  `compose.home.yaml` sets it, and that a crash, a restart and a new container from the
  same volume keep its group, its mode and its sync (P35 in docs/testbench.md).
  `tools/bench/setup-docker.sh` prepares the container's host and starts a container of the
  build under test.

### Changed

- On a Linux desktop that starts `graphical-session.target` (GNOME, KDE Plasma) the desktop
  agent runs as the user unit `clipboardbridge-agent.service`, which the installer starts
  again in each running session after an update: the clipboard links again without logging
  out and in. Other desktops keep the autostart entry, and a lock keeps it to one agent a
  session.
- A member in the Docker image holds none of the group's keys: `cbb new`, `cbb upgrade` and
  `cbb takeover` refuse there, and it offers no admin key, so the root cannot make it an
  admin and it cannot be the hub, since its keys would be in a file in the volume. The
  refusal says how to allow it anyway: `CBB_KEYS_IN_FILE=yes` in the container's
  environment.
- The home compose file names its container `clipboardbridge`, so `docker exec -it
  clipboardbridge cbb pair` works as the documentation says.

- `cbb global relay` first says what a relay learns (which devices are online and from
  where, which talk, when and how much) and asks you to type yes, or takes `-yes`; the
  service takes a relay only with that consent. Where sync away from home is off, it turns
  it on as well, after the same warning about keys in files as `cbb global on`. The design
  no longer keeps the relay to self-hosting only (D-68).
- The lite member's release archives are `clipboardbridge-lite-linux-amd64.tar.gz`, `-arm64`
  and `-armv6`, holding `clipboardbridge-lite/`, like the full member's `clipboardbridge-*`
  (they were `cbb-lite-linux-*`). `get.sh --lite` takes the new names, and the old ones for
  a release before 0.5 named in `CBB_VERSION`.
- What people read calls the project Clipboard Bridge: the installers' and `cbb`'s messages,
  the Windows service, its firewall rules and its entry in Settings, Apps (an update renames
  the service), the systemd units' and the desktop entry's descriptions, the iPhone profile
  and the release notes. Commands, paths, the service's and the group's names stay
  `clipboardbridge` and `cbb`.
- The documentation for users is rewritten in plain words, under `docs/guide` and
  `docs/reference`: the quick start begins with the phone app as the group's root and then
  suggests making an always-on computer an admin and the hub; "How it works" draws every
  way the devices connect (at home, through the hub, through a forwarder, a blind relay,
  networks that block VPNs), in SVG pictures of one style with a light and a dark theme,
  drawn by `tools/diagrams`; new pages cover installing, sync away from home, AmneziaWG and
  VLESS, the devices, ports and files, and running one's own forwarder or relay. Text for
  readers says Clipboard Bridge; commands, paths and packages keep `clipboardbridge` and
  `cbb`.

### Fixed

- `cbb pair -invite` was always refused: it sent the join, which changes the group, on the
  regular control socket instead of the admin socket, so joining by invitation from away
  did not work at all.
- `cbb status` lists each device's sync mode (`MODE`: both, send or receive).
- The lite member's `cbb join -code` returns only once its service has the group, so a
  command right after it no longer finds the device in no group.
- The Linux and macOS installers wait up to ten seconds for the service to answer before
  their final `cbb status`, which no longer says the service is not running on a clean
  install.
- The Linux `uninstall.sh` stops the desktop agents running in users' sessions too.
- After `cbb pair -invite` the service keeps the invitation's addresses until it knows the
  group's servers; it lost them at once, and could then reach neither the hub nor the
  forwarder. `cbb global on` really waits for the hub's addresses now: it asked again on a
  connection the service had already answered.
- `cbb global off` asks first on a device that reaches its hub only through the tunnel
  (`-yes` for scripts): its new keys reach the hub only on the home network, so it syncs
  again only once it is at home. `cbb global` says so while it waits for the hub.
- A hub that gives way to a hub above it, as an admin computer does when the root is the
  hub again after the hub moved to the admin, first passes the higher hub's offer on to its
  clients and waits for those far from home to leave; they knew only its own offer, and were
  cut off. `cbb global` on a hub that stands by says it is the higher hub's client, not that
  it is the hub with a forwarder it does not run.
- On a Mac, a `cbb` built without cgo, which has no pasteboard, says so in `cbb version` and
  `cbb status`, and the installer refuses it; its agent only exited, over and over.
- The lite member says that a user outside the `clipboardbridge` group must join it, not
  that the service may not be running; its unit keeps the service's memory out of swap
  (`MemorySwapMax=0`), as the full member's does.
- Moving the hub could leave a device far from home without a hub: the old hub stopped its
  tunnel two seconds after it queued the new hub's offer, whether or not the offer had gone
  out. It now says goodbye after the offer on each connection through its tunnel, waits up
  to ten seconds for those connections to end, and only then stops the tunnel.
- A member that got a takeover's root record before the records that make its signer an
  admin kept trusting the old root until it restarted; it now checks the roots after every
  record that can change them. A member admitted by an admin computer no longer logs that
  it was removed from the group when records arrive.
- Security: a forwarder keeps a group's authority records after the group's registration
  ends, and writes the roots, removals and freezes among them (never a device's name) to
  `groups` next to its key (`cbb forward -records`), so an admin the group removed can no
  longer register as its hub with the records from before while the group's own hub is
  away or after the forwarder restarted.
- Privacy: the authority records a hub shows its forwarder, and a device its relay, no
  longer carry the records of devices the root admitted directly, with their names and
  systems; only the root's own device and the devices it made admins (their demotions
  included) are named.
- Security: the lite member on Linux takes crypto-bigint 0.7.6 and ctutils 0.4.5, whose
  arithmetic and comparisons no longer branch on secrets on some compilers and CPUs
  (RUSTSEC-2026-0387, RUSTSEC-2026-0385); the Nano ESP32 firmware had them already. CI now
  checks the lite member's crates, the Android apps' libraries and the tray app's Go module
  against the OSV advisories on every change.
- Android: a certificate with a length field near 2 GiB no longer slips past the DER
  reader's bounds check and throws an unexpected error instead of being refused. Both phone
  kits now test their certificate checks with thousands of randomly damaged certificates.
- iPhone kit: a key whose algorithm identifiers are damaged is refused, as Go and the
  Android kit refuse it; swift-crypto on Linux read the key's point without checking them.

## [0.4.1] - 2026-10-25

### Fixed

- Releases carry `winget-manifest.zip`: the release workflow writes it before it
  publishes the release, since an immutable release takes no files afterwards (0.4.0 went
  out without it).
- The release notes name the Wear OS app's APK, `clipboardbridge-wear-X.Y.Z.apk`, in the
  install steps and the file table.

## [0.4.0] - 2026-10-25

### Added

- Wear OS: an app that shows the group's devices and their live dots, the latest events and
  the switch for sync away from home, through the paired Android phone (the Wearable Data
  Layer of Google Play services); each release carries its signed APK.
- Linux and Windows: a tray app over the cbb service (Wails), the twin of the Mac app: the
  devices as tiles, a list or orbits, a device's details, send and fetch, sync away from
  home, and the group's changes after the administrator's password (pkexec, UAC).
- Mac: an app (SwiftUI) over the cbb service, a window and a menu bar item in the Glass
  design: the devices as tiles, a list or orbits, a device's details beside them, send and
  fetch, sync away from home, and renaming, removing, freezing and making admins after the
  administrator's password.
- Android: notifications of the group's events, as on the iPhone, each with a switch in
  Settings; the background service hears of them at once.
- Android: the Glass design of the iPhone app: ten colours and a Dark, Light or System theme
  (Material You stays a choice), one page with every device as tiles or a list, a device's
  own page with its type, system and version, Clipboard Bridge version, MAC address and
  role, and on tablets and foldables the orbits with the details beside them. The app's
  name on the home screen is CBB.
- iPhone: notifications of the group's events (a device joined or was removed, became an
  admin, was frozen or unfrozen, the group was taken over, the hub does not answer away from
  home), each with a switch in Settings.
- Apple Watch: an app that shows the group's devices and their live dots, the latest events
  and the switch for sync away from home, through the paired iPhone.
- iPad: the app runs on the iPad as a phone of the group. Its Home shows the devices on orbits
  around it (or as tiles or a list), with a device's details in a pane beside them; the
  same layout serves the inner screen of a foldable iPhone, whose strip at the right edge
  takes the toolbar in landscape.
- iPhone: a Live Activity in the Dynamic Island while a device is added and while the phone
  syncs away from home, and the result of a sync for a moment; it never shows what was
  copied.
- A member's hello says what its device is (docs/protocol.md, section 4, "Device"): its form
  (laptop, desktop, phone, tablet, board, console, server and others), its system's version,
  its own version and, on computers and boards, the MAC address of its network card. The
  iPhone app shows them on a device's page and picks its icon by the form; `cbb devices`'s
  socket answer carries them too.
- The Android and iPhone apps keep the home network addresses from the QR code of each
  computer they add, and dial a computer there while mDNS does not find it, so a member in
  another subnet (an IoT VLAN, for example) syncs with the phone too.
- winget: each release writes the manifest of `HunterEwok.clipboardbridge`, and `cbb install`
  installs the service from the copy that winget unpacked. The release signs the Windows
  programs with Authenticode when its secrets hold a certificate.
- ZX Spectrum Next: `.cbb text -s` and `.cbb copy -s` send a secret, through the lite
  member's `cbb next copy -secret`.
- iPhone: Share → Clipboard Bridge sends a text or a link to the computers at once (a share
  extension), and a Control Center control and a home-screen widget "Sync clipboard".
  Android: the home-screen widget "Send clipboard".
- Rename a device: `cbb rename NAME NEW-NAME` on an admin computer, and Rename in the Devices
  list of an admin phone (both apps). An admin signs a new device record with the name.
- Both apps: seven taps on the version in Settings show the switch "Show error details",
  without `adb` or Xcode.
- `cbb status` warns when members at home could not connect to this computer and sync only
  because it dials them back: a firewall here drops the member port.
- `cbb global hub` at the hub's own address lists the firewall rule for its UDP port and asks
  before it opens it (ufw, firewalld, Windows Firewall; the commands for the others);
  `-firewall yes` opens it without asking, `-firewall no` prints the commands. The port
  closes again when the device stops being a hub reached at its own address.
- `--home-cgnat on` for the installers (`-HomeCgnat on` on Windows, `CBB_HOME_CGNAT=1`)
  counts 100.64.0.0/10 as the home network for a home network on the carrier-grade NAT
  range: in the service, the firewall rules, the systemd unit's address limit and the
  Windows outbound rule. By default that range stays outside the home network.

- The Mac installer takes `--port N` like the Linux one, kept in
  `/etc/clipboardbridge/clipboardbridge.env`, and `get.sh` passes it on a Mac too.
- `CBB_ERROR_DETAILS=1` for the Linux and macOS installers, uninstallers and `get.sh`: they
  show every command as it runs. Without it a failure says it failed, with its exit status.
- [docs/parity.md](docs/parity.md): what each computer, phone and lite device can do, the
  gaps between devices of one class and the plan to close them.
- Sync away from home on the lite member: `cbb global on` (with the warning about keys in
  files) offers its tunnel key to the group's hub at home and keeps the hub's offer; away from
  home, or on another subnet, it reaches the hub through the group's WireGuard tunnel, with
  GotaTun's WireGuard and smoltcp's TCP in `cbb`, no TUN device and no root. Plain WireGuard
  only: a hub that hides its tunnel (`-obfuscate`, `-vless`) keeps a lite member at home.
- VLESS with REALITY for networks that block WireGuard and AmneziaWG alike: `cbb forward
  -vless-site www.example.com` also takes VLESS on TCP 443, borrowing that site's TLS, and
  `cbb global hub -forwarder ... -vless` has the hub's clients reach the forwarder only that
  way, inside what looks like HTTPS to the site. The group's WireGuard and member TLS go
  inside it unchanged. Xray-core runs in `cbb` and in the phones' tunnel (`mobile/cbbtun`),
  so both apps take the way over VLESS from the hub's offer too.
- `cbb upgrade`, once on a Linux or Windows member of a group made before this version,
  gives the group a root, that member: the old CA keys are revoked and the other members
  delete their copies when they hear of it, so every device but the root can then be
  removed by a record. No device pairs again; the iPhone CA is replaced, so iPhones that
  use the shortcut pair again. `cbb status` marks the computers that may still hold the old
  keys until they connect.
- `cbb takeover NAME` on an admin computer takes the group over from its lost root
  computer, as an admin phone does in a phone's group: the admin becomes the root, the
  lost root is removed, every other device stays, and the iPhone CA is replaced, so iPhones
  that use the shortcut pair again. After admitting a device, `cbb pair` on a root without
  another admin suggests making one.
- Obfuscation for networks that block WireGuard: `cbb global hub -obfuscate` makes the group's
  tunnel speak AmneziaWG, with junk packets before each handshake, random padding, random
  message types and encrypted headers, so nothing on the wire looks like WireGuard. The hub
  makes the group's settings and gives them to its clients with its offer at home and in
  remote invitations; both phone apps use them too. An obfuscated hub can use a forwarder:
  it gives the forwarder the group's settings when it registers. Not yet on the lite member.
- Sync away from home in the iPhone app, as in the Android app: a switch in Settings, the
  key and the hub's offer in the keychain (this device only), and the same in-process
  tunnel while the app runs. Building the app now needs Go for `Cbbtun.xcframework`.
- Sync away from home in the Android app: a switch in Settings makes the phone's WireGuard
  key, offers it to the group's hub on the next connection at home, and keeps the hub's
  answer. While the hub is not found on the home network, the phone reaches it through the
  tunnel in the app's own process, with the same member TLS as at home, trying the hub's
  addresses in turn; without the tunnel there is no connection. Off by default; turning it
  off forgets the key. Building the app now needs Go for the tunnel.
- The first firmware for the Arduino Nano ESP32 (`lite/esp32`, Rust on the ESP32-S3): a
  console on its USB port sets the Wi-Fi network up, the board joins it and takes an
  address by DHCP, joins a group by the phone (`join` prints the link to paste into the
  app, and the phone pairs with the board over TLS 1.3 as with the lite member's `cbb join`), and keeps
  its settings and identity in flash in two slots, so a power cut while saving keeps the
  last good copy (`cbb_core::store`); its `selftest` makes keys and
  certificates with the chip's true random number generator and runs a TLS 1.3 handshake
  of the protocol core on the chip. CI types on the console and runs the self-test in
  Espressif's QEMU. Syncing comes next; not yet run on a real board.
- The Nano ESP32's network code on Linux: the pairing moved to the crate `lite/embassy`,
  which the firmware and the program `esp32-on-linux` share; `esp32-on-linux` runs it on
  embassy-net over a TAP interface instead of the chip's Wi-Fi, and CI's
  `TestEmbassyJoiner` has a Go member admit it by the phone, as the board joins.
- A forwarder for hubs that the computers cannot reach directly, for example behind
  carrier-grade NAT: `cbb forward` runs it on a server with a public address, and
  `cbb global hub -forwarder ADDRESS:PORT -forwarder-key KEY` registers the hub there with its
  member certificate and its WireGuard key. It holds no keys, passes each encrypted packet
  only to its own group's hub, routes by WireGuard's `mac1` so nothing on the wire tells
  groups apart, limits each group, and writes nothing about the groups, not even to its
  log. `cbb global` on the hub shows the registration.
- A blind relay for a group without a computer to be its hub: `cbb relay -group TAG` runs it
  on a server you run, and `cbb global relay ADDRESS:PORT -key KEY` on each computer meets the
  group's other computers there away from home. It holds none of the group's keys: each
  computer registers with its member certificate and gets its own WireGuard tunnel to the
  relay, which joins two computers' member connections end to end, so it sees who talks
  and when but cannot read the clipboard or pose as a device. It serves only the groups it
  is given and writes nothing about them. `cbb global` shows the link.
- `.cbb`, a dot command for the ZX Spectrum Next (`apps/zxnext`, C for z88dk): with
  the lite member on the Next's own Raspberry Pi it pastes the group's text to the screen or a
  file, sends a file or words, and joins by drawing the QR code for the phone app. Not yet
  run on a real Next.
- iPhone: a new look, "Glass", in ten colours (Terminal, Midnight, Amber, Ocean, Teal,
  Coral, Rose, Lime, Graphite, Ruby), each dark and light. Home shows every device of the
  group as tiles or a list with its icon, system and live dot; a device opens its own page
  with a summary and its actions. The earlier theme carries over.

### Changed

- With `cbb global on`, a computer's service no longer reaches the whole internet: only the
  home network and its group's own hub, forwarder and relay. The program refuses everything
  else on every system, a client's WireGuard socket sends only to its hub, and on Linux and
  Windows the systemd drop-in and the outbound Windows Firewall rule list exactly those
  addresses. `cbb global hub` and `cbb global relay` now run with `sudo` or as administrator
  on those systems, and the new `cbb global allow` follows the hub's addresses when they
  change; `cbb global` and `cbb status` say when it is needed. A hub reached at its own
  address answers its clients anywhere on its UDP port only (on Linux by the program alone).
- The installers no longer open firewall ports without asking. They find the firewall
  (ufw, firewalld, nftables or iptables on Linux, the macOS application firewall, Windows
  Firewall), list each rule clipboardbridge needs with its protocol, port, source and
  purpose, and ask `Add these rules now? [y/N]`. Yes adds them and keeps them current on
  every update; No, the default and the answer when there is no terminal, adds none and
  prints the exact commands. The answer is kept for updates. `--express` (`-Express`,
  `CBB_FIREWALL=express`) adds them without asking and reports what it added;
  `--no-firewall` now also works on a Mac and prints the commands too.
- The lite member and the ESP32 firmware use x25519-dalek 3 (on curve25519-dalek 5) and
  base64 0.23. Dependabot updates the firmware's lock file in the same pull request as the
  lite member's, so the firmware's locked build keeps passing.
- The lite member's stand-in for ring (`lite/ring-shim`) uses chacha20poly1305 0.11, the
  version its TLS uses. smoltcp stays at 0.13, the version embassy-net 0.9 builds on: two
  copies of smoltcp share the `managed` crate's features and do not build together, so
  Dependabot leaves its minor versions alone until embassy-net moves.
- The lite member dials no address outside the home network: `-peer` names a member at
  home, and away from home the device reaches the group only through the tunnel.
- The lite member's command is `cbb`, as on a full member, with the same paths, user and
  service (`/usr/local/bin/cbb`, `/var/lib/clipboardbridge`, `clipboardbridge.service`);
  `cbb version` says which member a device runs, and the commands of a full member answer
  that this is the lite member. Its archive (`cbb-lite-linux-*`) carries the same Linux
  `install.sh` and `uninstall.sh` as a full member's, and `get.sh --lite` installs it.
  The installer moves an install from before the rename to the new names, keeping the
  device in its group, and refuses to put one kind of member over the other.
- `cbb away` is now `cbb global`, with the same subcommands (`on`, `off`, `hub`, `relay`):
  it turns on sync over the internet, beyond the home network.
- A computer that creates a group is now its root, as a phone is in its own group: only it
  and the admins it makes hold CA keys, and the computers that join get only their
  certificates, the Mac, Linux and Windows alike. `cbb admin NAME` on the root makes a
  connected computer an admin, which then admits and removes devices and serves the iPhone
  shortcut with the group's iPhone CA. Any device but the root is removed with
  `cbb revoke` and the group stays; removing an admin replaces the iPhone CA, so the
  iPhones that use the shortcut pair again. A Mac can create a group and be an admin.
  Groups made before keep working as they were until `cbb upgrade`.
- `cbb new` creates a group on a computer, and `cbb pair` does the rest by the device's
  state: in no group it joins one (it shows a QR code for the phone and also takes a
  typed code, `cbb pair -code` reads one from standard input), in a group it admits a
  device. `cbb join` is gone, and `cbb pair` no longer creates a group by itself.
- One `get.sh` installs on Linux and on a Mac: it picks the archive for the system and the
  architecture, checks it against `SHA256SUMS` and runs that system's `install.sh`. On a
  Mac, `install.sh` keeps `uninstall.sh` in `/usr/local/share/clipboardbridge`, as on Linux,
  so every platform has the same three: get, install and uninstall.
- `cbb desktop` is gone: `cbb agent` links the clipboard on every desktop, the Mac's, the
  Windows one and a Linux desktop's (Wayland or X11), and the Linux autostart entry runs it.
- The tunnel for sync away from home now runs on amneziawg-go, the AmneziaWG fork of
  wireguard-go, in `cbb` and in the phones' tunnel. Until a group switches obfuscation on
  it speaks plain WireGuard, the same on the wire as before.
- A hub's hellos to its forwarder are masked, so that they look like random bytes of a
  random length; a forwarder and a hub of this version are needed together.

### Fixed

- Security: a new device trusts only the roots that the group's records lead to. The Welcome
  carries the records of that path, and every member (Go, both phone kits, the lite member)
  refuses a certificate whose chain no root on the path signed, so an admin can no longer
  slip a root of its own into a device it admits and keep access after the group's root
  removes it. The roots a member trusts follow the records by content, not by count.
- Security: an admin can no longer fill the record set to block its own removal. A record
  signed under a root that can never be known (one a computer's admin names in a phone's
  group) is dropped, every signer (admin CAs and roots' own keys alike) is limited to 1024
  records, signatures are checked before the limits, and a full set still takes 1024 more
  records from the own key of a root on the path.
- Security: a device can no longer join twice under one device ID and leave a second key
  behind that removing it misses. The admitting member refuses an ID that the records or a
  connected member already have (new pairing error `taken`), the devices list shows a device
  while any of its keys stands, `cbb revoke`, `cbb takeover` and the apps' Remove revoke
  every key of the device, and a peer counts as the root only with the root's own key.
- Security: the lite member takes a tunnel offer only from the group's root or an admin, by
  its records and the key of its certificate, rather than from any member whose hello says
  `full`. It keeps the first hub until sync away from home is turned off and on again, and
  ignores an offer that does not decode instead of dropping the hub. The phone apps check
  the hub's key the same way.
- Security: the phone apps check each computer's certificate chain against the group's
  records when it connects, and close the connection as soon as new records remove it. A
  removed device is now dropped by its key, not only because its ID left the list.
- Security: a member refuses an event more than 7 days ahead of its clock (Go, the lite
  member and both phone kits), so a device with a wrong date or a removed member can no
  longer hold the group's clocks at the year 9999 and keep every later copy from winning. A
  clock that reads before 2026 refuses nothing, for boards that have not set their time.
- Security: an mDNS announcement of the hub on a foreign network no longer turns off sync
  away from home (Go, the lite member and both apps). A member found by discovery counts as
  on this network for 30 s; after that only a connection to it keeps the tunnel and the
  relay closed.
- Security: the iPhone shortcut's pairing page no longer shows the profile's fingerprint,
  which comes over plain HTTP and could be changed on the way; it sends the user to the
  terminal of `cbb pair -phone`, which now spells out where to compare it.
- Security: a device on the home network can no longer hold a pairing window busy. The
  joiner's first message must come within 10 s (a slow board computes its CPace message
  first), and after 5 attempts from one address that ended before they counted, the window
  answers it `busy`.
- Security (Android): other apps can no longer fetch the group's latest copy by opening the
  app's send activity. The tile, the widget and the notification open one that is not
  exported; Share, the selection menu and "cbb send" open another that asks first unless the
  home screen or the system opened it. "Always allow" now holds for one app only ("Always
  for this app"), and Settings lists those apps; the old switch for every app is gone.
- Security (Android): a secret is cleared from the clipboard after its minute while the
  app is in the background too, unless the app learned of a change since.
- Security: `get.sh` and `get.ps1` check the archive's build provenance attestation with
  `gh attestation verify` when the GitHub CLI is there and signed in, since `SHA256SUMS`
  comes from the same release; `CBB_ATTESTATION=require` refuses to install without it.
- Security: a computer publishes itself by mDNS and takes connections on the member port only
  on networks where it met its group (created or joined it, opened a pairing window, or
  connected to a member there), told by their addresses and the gateway's link-layer
  address. In a café or a hotel it only looks for the members, so its host label and group
  tag no longer follow a laptop around. `cbb status` says where it keeps quiet, and
  `sudo cbb network` takes the current network as known, as at home after a new router. An
  updated computer takes the networks it is on at the update as known.
- Security: only the group's root or an admin can register the group on a forwarder. The hub
  signs the registration with its root or admin CA key, and sends the group's authority
  records with it. The forwarder and the relay keep those records in memory and refuse a hub
  or device that the records remove or freeze, so a removed device can no longer push the
  real hub out or hold a relay slot.
- Security: a forwarder takes at most 16 registrations from one address and 64 from one
  network (/24 or /64), and gives each network a sixteenth of the budget for checking
  handshakes against the groups, so a few hosts can no longer fill it or use up the budget.
- Security: membership in the `clipboardbridge` group gives the clipboard only. The service
  takes what changes the group (`new`, `pair`, `invite`, `revoke`, `rename`, `admin`,
  `takeover`, `upgrade`, `freeze`, `unfreeze`, the holder setting, `global` on, off and hub)
  only on a new admin socket next to the control socket, which only root reaches (on Windows
  administrators): run those commands with `sudo`, or from a terminal opened as
  administrator. The lite member does the same for `cbb global on|off`.
- Security: tmux's paste key no longer types control characters, a second line or a secret
  into the terminal. It runs the new `cbb paste -terminal` (full and lite member), which drops
  the control characters of C0 but tab and line feed, DEL and those of C1, keeps only the
  first line unless `-lines`, leaves out the last line feed, and refuses a secret unless
  `-secret`.
- An update without a terminal over an installation from before the firewall question no
  longer removes the firewall rules it had added: rules that are there without a kept answer
  count as an earlier Yes (Linux, macOS, Windows), and with no terminal and no answer nothing
  is added or removed. `cbb global` returns only once a service it restarted answers again.
- An update no longer leaves an earlier version's limit in place: the Linux drop-in that let a
  member with `cbb global on` reach every address, or a Windows outbound rule written for
  other servers. The installers run `cbb global allow` once the service answers, and
  `cbb status` names such a limit instead of "the home network only". `cbb global on` says
  when the group's servers are not known yet and `sudo cbb global allow` is needed once
  they are. A second `cbb pair` says how to close the window that is still open.
- The phones' one button no longer puts the computers' older text over a clipboard it could
  not read (paste not allowed, or not text): it leaves the clipboard as it is and says so,
  with the details in debug builds.
- The phones' one button waits up to 5 seconds for a computer to connect before it says none
  is: back from the background, the dropped connections take a moment to come back.
- A used remote invitation no longer reaches the hub: its guest tunnel goes as soon as the new
  device's member connection through it ends after the hub answered its tunnel key (at most
  2 minutes after the admission, as before), and the hub refuses a second pairing through it.
- On Linux the service's memory, which holds secrets, never goes to swap (`MemorySwapMax=0`).
- When a device away from home gets no answer through the tunnel, `cbb global` says that the hub
  or the forwarder on the way may be down, not only the hub.
- Security: on Android, a text from Share or the selection menu is sent only after the user
  allows it, with "Allow" or "Always allow"; any app can hand over a text, so without a
  question an app could send whatever it liked to the computers. Settings turns the question
  back on.

- Security: on a Mac with Homebrew, the service, which holds the group's keys, no longer runs
  the binary under Homebrew's prefix, which the user and their programs may replace.
  `install.sh --in-place` copies it to `/Library/Application Support/clipboardbridge/bin`,
  where only root can change it; the agent and `cbb` in PATH still run Homebrew's. Running
  `install.sh` again after `brew upgrade` refreshes the copy, as before.

- Security: any admin, a computer included, can freeze another admin computer, as one that
  was stolen: `cbb freeze <name>`. From then on nothing the frozen admin signs counts beyond
  what it did before, its connections are refused, and it is no admin until the root or an
  admin phone unfreezes it ("Unfreeze" in Devices, `cbb unfreeze` on a root computer) or
  removes it. Nobody freezes the root or an admin phone. Every member (Go, the phone apps,
  the lite member) follows the new `freeze` and `thaw` records; docs/design.md, "Who may
  remove an admin", says why freezing was chosen.

- Security: an admin computer, whose admin key sits in a file, can remove ordinary devices
  but no longer the root or another admin, and cannot hand a phone's group to a new root;
  only the root and admin phones can. `cbb takeover` from a lost root computer still works,
  but counts only while the old root's own records leave that admin standing: a root that
  is still in use undoes it by removing the admin, and a frozen admin does not take over. Nothing an admin signs after it was removed counts,
  and each admin signs at most 1024 records. Every member (Go, the phone apps, the lite
  member) enforces this from the records alone (docs/protocol.md, section 10).

- Security: the iPhone shortcut's token only syncs. `POST /admit` and the shortcut
  "clipboardbridge: add a computer" are gone, so a copied token can no longer add a computer
  (which on Linux got the group's keys); computers join through the phone apps or
  `cbb pair`. `cbb pair -phone -new-token` revokes every shortcut's token and pairs the
  iPhone with a new one.

- Security: only the group's root or an admin can be the hub for sync away from home. A
  member, phone or computer, ignores tunnel offers from any other device, and once it keeps
  a hub's offer it ignores other hubs until sync away from home is turned off and on again,
  so a member cannot point the others' tunnels at itself.

- Security: the lite member makes its control socket in a private directory and narrows it there
  before moving it into place, so nobody can connect in the moment before its mode is set,
  whatever the umask. Dependabot also watches the lite member's crates and the Android
  app's Gradle dependencies.

- Security: handshakes to unknown groups cost the forwarder at most a fixed number of group
  checks a second (`Limits.ScanRate`), whatever their source addresses, so a flood of forged
  handshakes cannot hold up the other groups.

- Security: a member's certificate is checked against the issuer that actually signed it.
  Before, the revocation check and the admin check looked at the second certificate a peer
  presented, so extra certificates in a chain could get a removed admin's devices back in
  and make an ordinary member count as an admin. Fixed in Go, the phone kits and the lite
  member; the member protocol now passes on only the chain the handshake verified.

- A hub on a host without IPv6 could listen on a random UDP port instead of its own and
  then hear no client: wireguard-go's socket reported port 0 there, and the device's next
  rebind, which its own "up" event can cause while it starts, took any free port.

- A data race in the tunnel's WireGuard timers when a peer stops, as when a hub closes: a
  timer that fired at that moment cleared its state outside its lock. clipboardbridge now
  builds with a copy of amneziawg-go that clears it under the lock
  (`internal/third_party/amneziawg-go`).
- Sync away from home works on Linux: the service's unit lets it reach only the home network,
  so a hub could not register with its forwarder and a computer away from home could not reach
  its hub. `sudo cbb global on` (and `sudo cbb pair -invite`) now add a systemd drop-in that lets
  the service reach the internet, and `sudo cbb global off` removes it; until then `cbb global`
  says what is missing.
- Every computer keeps the service on the home network until sync away from home is on: the
  service refuses its own connections outside the home network (`internal/netguard`), as the
  member port already refused connections from there. On Windows the installer adds an
  outbound block rule of Windows Firewall for the service (`clipboardbridge-home-only`) as
  well, which `cbb global on` and `cbb pair -invite`, run as administrator, lift, and `cbb global
  off` puts back, as `sudo` does on Linux. A Mac gets the system's own limit with the Mac
  app's Network Extension later (docs/roadmap.md).
- `cbb global hub -forwarder` and `cbb global relay` take a server's name as well as its address.
- A device whose group file is damaged says so: the service keeps running without its group,
  `cbb status` and every other command explain what is wrong and how to recover (with the
  underlying error in a debug build or with `CBB_DEBUG=1`), and nothing writes over the file.
  Before, the service only restarted every few seconds and `cbb status` said it was not running.
- The service's log no longer says `<nil>` for a member connection that closed in order.
- A removed device learns that it was removed: the member that revokes it sends it the
  revocation before it closes the connection, and `cbb status` on the removed device says so.
  Until now the device never got the record and still showed its group's devices.
- The desktop connectors (the Mac's and Windows's agent, `cbb desktop` on Linux) take the
  first texts soon after the device joins a group. While the service turned them down for
  being in no group, they waited up to 30 seconds between tries, and the texts that came
  meanwhile reached the clipboard late; now they ask again every 2 seconds, and log it once.
- Installing again on Windows no longer fails now and then with "cbbw.exe is being used by
  another process": the installer waits for the old agent to exit, and tries the copy again
  while an agent the last install started is still starting.
- Installing again on a Mac, as after `brew upgrade`, no longer fails now and then with
  "Bootstrap failed: 5: Input/output error": the installer waits for launchd to let the
  old service go before starting it.
- Stopping a tunnel for sync away from home while a packet comes in no longer races in
  WireGuard's network stack, which could crash the service: the peers stop first.

## [0.3.0] - 2026-10-24

### Changed

- The Mac is a full member like the Linux and Windows computers (docs/design.md, D-51): it
  no longer publishes `r=mac`, and of two computers the one with the lower device ID dials;
  when it has not connected for 30 seconds, the other dials too, and of two connections the
  one the lower ID dialed stays. `cbb-lite` dials the Macs as it dials every computer. A Mac
  still does not admit devices.
- Which computer holds `clipboardbridge.local` (D-53): one without a battery comes first and a
  laptop only when no other is on, then the lowest device ID; the computers publish their
  priority in the TXT key `h`. `cbb holder auto|first|fallback|never` changes the guess, and
  `cbb status` says how this computer takes part.
- `cbb away hub` and the quick start say that the hub need not stay on: while it is off,
  nothing syncs away from home, and at home the devices sync without it.
- A device's system is separate from its role (docs/design.md, D-50): device records and
  hellos carry `os` (`linux`, `windows`, `macos`, `ios`, `android`, `none`), and the roles
  are `full`, `phone`, `lite` and `shortcut`. A Windows PC now shows as Windows, not Linux;
  an admin re-signs the record of a full member whose hello names another system. Records
  with the old roles `linux` and `mac` read as `full`, `iphone` as `shortcut`. Not
  compatible with 0.3 members: update every device of a group together.
- `cbb devices` is folded into `cbb status`, which shows this device's system and role and
  then the group's devices with their systems, roles and admins; `cbb-lite devices` the same.
  The apps' Devices screens show each device's system.
- A computer that joins at an address (`cbb join -code ADDRESS`, as through an SSH
  forward or a VPN of your own) now connects to the member that admitted it at that
  address and syncs at once, and so meets the hub to sync away from home, where before it
  synced only once it was on the home network.

- A Mac now takes connections on the member port and publishes itself on mDNS with
  `r=mac`, so phones, other Macs and lite members reach it with no Linux member on; it
  still dials the Linux and lite members itself, so a firewall that blocks incoming
  connections never cuts it off from them. `install.sh` lists the service in the macOS
  application firewall (`CBB_FIREWALL=no` leaves the firewall alone) and `uninstall.sh`
  takes it away. Linux members and `cbb-lite` no longer dial a Mac; update `cbb-lite`
  together with the Macs.

- The lite member's TLS is in its protocol core and needs no operating system, the first
  step to a lite member on the ESP32: rustls without the standard library, with a small
  crypto provider of RustCrypto code (TLS 1.3, ChaCha20-Poly1305 or AES-128-GCM, X25519,
  ECDSA P-256) in place of ring, a TLS session that does no I/O, and the pairing's TLS
  exporter derived from the connection's key log. `cbb-lite` on Linux uses it, so it no
  longer builds C code, and CI builds the core for the ESP32-C6 and the ESP32-S3.

- An event sent from a phone has `via` `phone` (the app, iPhone or Android, or the iPhone
  shortcut), where it had `iphone`; members still take `iphone`. The control socket takes
  and reports `phone` too. Names that belong to the shortcut, for an iPhone without the
  app, keep the word: the iPhone CA, the `iphone` token role, `to_iphone` and `from_iphone`.

- **clipbridge is now clipboardbridge, and its command is `cbb`.** Everything is renamed: the
  repository, the binary (`/usr/local/bin/cbb`), the service (`clipboardbridge.service`, on
  macOS `io.github.hunterewok.clipboardbridge`), the user and group, the directories, the
  environment variables (`CBB_PORT` and the others), and the protocol's names
  (`_clipboardbridge._tcp`, `clipboardbridge.local`, the ALPN protocols, the QR code
  scheme, the signature labels). It does not reach 0.2.0: the installers remove clipbridge,
  with its keys, its user and its firewall rules, and each device pairs again.

- Members accept a group CA with path length 1, the root that the phone app creates for its
  group, so that it can certify admin phones later (docs/protocol.md, sections 9 and 10).
- The phone app logs every error it shows, and a debug build (or the `ShowErrorDetails`
  default) puts the error itself under the message, to find out what failed.
- In the iOS simulator the app keeps its root and admin keys in the keychain, since the
  simulator cannot make a Secure Enclave key that needs Face ID.
- `cbb join` names the app's "Connect a new device" and prints the QR code's text
  as well, to paste into the app on a phone without a camera.
- The Linux installer opens clipboardbridge's ports from the home network on every run, not only
  from `get.sh`, so an update fixes a firewall turned on after the first install: in ufw as
  before, and now in firewalld too (a `clipboardbridge` service and rules for the home network);
  under a bare nftables or iptables setup that drops input it prints the commands.
  `CBB_FIREWALL=no` leaves the firewall alone. `cbb join` names the firewall
  when the phone cannot connect.
- clipboardbridge needs one TCP port, 8764: a listening `cbb join` waits on it (the
  computer is in no group yet), and the iPhone shortcut's HTTPS and the profile moved there
  from 8765 and 8766; the member port tells the connections apart by their first bytes.
  Installed shortcuts stop working: run `cbb pair -phone` and add the new one from
  its page.
- The Linux installer keeps track of the firewall rules it adds and removes them before
  adding new ones, so a changed port leaves nothing open; it never touches other rules.
- The phone app's Start screen says what to do in plain words: "Connect a new device" (a
  computer or another phone) and "I already use clipboardbridge on another phone". Its buttons
  and cards use Liquid Glass from iOS 26, with materials before.

### Added

- `cbb-lite next paste|copy|join` for the ZX Spectrum Next: on the Next's own Raspberry Pi,
  `cbb-lite` answers the Next's `.cbb` dot command over the internal UART in frames its
  Z80 reads (CR lines, the Spectrum character set, length and CRC-32, a QR code as hex
  rows for the phone to scan); see lite/README.md.
- Releases carry the lite member: `cbb-lite-linux-amd64.tar.gz`, `-arm64` and `-armv6`,
  static builds, each with the systemd unit and the licenses of the crates it is built from
  (`THIRD_PARTY_NOTICES`).

- Sync away from home for computers, off by default. `cbb away on` turns it on after a
  warning that the device keeps its keys in files; `cbb away hub address:port` makes an
  always-on computer the group's hub, which takes the others through the group's own
  WireGuard tunnel, in user space inside `cbb`, with member TLS inside it. A member uses the
  tunnel only when the hub is not on its network; `cbb away` and `cbb status` show the
  state and what went wrong (with the underlying error in a development build or with
  `CBB_DEBUG=1`); `cbb away off` forgets the keys.

- The first part of remote invitations: a pairing window can take an invitation's 128-bit
  secret in place of the six-digit code, live up to a day, and ask its admin to confirm the
  device (name, system, key fingerprint) before it admits it; an invited device never gets
  the CA keys.

- Remote invitations for computers: `cbb invite` on the group's hub writes an invitation
  file (`.cbbinvite`, valid for an hour, at most a day, for one device) and asks you to
  confirm the device that uses it; `cbb join -invite FILE` joins from any network through a
  one-time guest key that reaches only the hub's pairing, then syncs through the hub with
  its own tunnel key. The hub's peers now change without resetting the sessions of the
  clients that stay.

- Homebrew, on macOS and Linux (x86-64, ARM64):
  `brew install hunterewok/tap/clipboardbridge`. The formula installs the
  release archive as it is, so it needs no Apple signing, and the release workflow updates
  the tap after each release (`packaging/homebrew/formula.sh`, docs/maintaining.md). On a
  Mac, `install.sh --in-place` runs the service and the agent from Homebrew's binary, so a
  `brew upgrade` followed by the same command updates them.

- `packaging/macos/uninstall.sh` removes clipboardbridge from a Mac, keeping its keys unless
  `--purge`.

- **Windows 10 (1809 or later) and 11, x86-64 and ARM64.** The service runs as a Windows
  service under its own virtual account and listens like a Linux member; the agent
  (`cbbw.exe agent`, started with every sign-in) links the clipboard, skips and writes the
  marks that password managers and the clipboard history use, and turns CR LF into LF.
  `get.ps1` installs a release (`irm .../get.ps1 | iex` as administrator), `install.ps1`
  takes `-Port N` and `-NoFirewall` and allows TCP 8764 and mDNS from the local network in
  Windows Firewall, and Settings, Apps, Uninstall (`uninstall.ps1`, `-Purge` for the keys)
  removes it with exactly those rules. The installers name the step that failed and the
  system's message; `-Details` or `CBB_ERROR_DETAILS=1` adds the full error. The service
  logs to `ProgramData\clipboardbridge\logs`, the agent to
  `LocalAppData\clipboardbridge\agent.log`.
- **The lite member, `cbb-lite`, in Rust** (`lite/`): a small member for weak Linux devices
  (a Raspberry Pi, a router) that joins a phone group by QR code (or a computer group with
  the code from `cbb pair`) and never holds CA keys. It dials the computers, and publishes
  itself in mDNS (TXT `r=lite`) and listens on the member port, so that a phone syncs with it
  directly, with no computer on; Linux members leave it to dial them. `copy`, `paste`,
  `status`, `devices` and `watch` work as in `cbb`. Its errors
  show their details with `-debug` or `CBB_DEBUG=1`, and in a debug build. CI builds it for 64-bit
  Raspberry Pis and, statically, for the ARMv6 Pi Zero W. Its protocol core, `lite/core`,
  needs no operating system (no_std, RustCrypto), for a lite member on the ESP32 later.
- A joiner can say it is a lite member (`"role":"lite"` in its pairing Info): Go members
  send it no CA keys and list it with role `lite`.
- The Android app is started in `apps/android`: a Gradle build with the protocol core in
  Kotlin (`kit`, no Android dependencies) and a Compose app, built and tested in CI. The kit
  has CPace over X25519 (tested with the vectors of RFC 7748 and the CPace draft), the group's
  certificates, the member and pairing messages, the join QR code and the signed records; it
  reads the Go and Swift vectors in `testdata/interop`, and Go checks the records it signs.
  It also has the sync engine, the member node, pairing in both directions and the phone's
  group (making admins, renewals, removal, the takeover); Go checks its renewals, admin CAs
  and `root` records. An Android phone joins with `os` `android` and an admin phone admits it
  as a phone, and both kits record a lite member (`"role":"lite"` in its Info) with role `lite`.
  TLS 1.3 comes from Conscrypt (bundled in the app), with ALPN and the exporter: in CI, Go
  pairs with the Kotlin kit over plain TCP and over TLS, and syncs with it as a member.
  The app keeps its keys in the Android Keystore (StrongBox where the phone has it): the
  member key signs TLS in the background, and the root and admin keys sign only for five
  minutes after the fingerprint, the face or the screen lock.
  It finds the computers with NsdManager and keeps a connection to each (the kit's
  `MemberDialer`), and reads QR codes with CameraX and ZXing, without Google Play services.
  Its screens follow the iPhone app's: Start with the one-time "This phone is ready" note,
  joining another phone's group by showing a QR code, Home with the Send-or-fetch button and
  the computers' live dots, Devices (remove, make a computer an admin, take the group over
  from a lost root phone), Add a device (the camera or pasted text) and Settings; the four
  themes of `apps/design/tokens.json` (`tools/tokens` now writes Kotlin too) and Material
  You, in English and Russian. The app asks for the local network permission Android 17
  needs.
  While there is a group a foreground service keeps the connections, and what a computer
  copies lands on the phone's clipboard by itself. The phone's copies go with one tap: the
  Quick Settings tile "Send clipboard", the notification's Send button, Share and the
  selection menu, and a "cbb send" launcher entry for Quick Tap or a back-tap app; or with
  none, with the accessibility service "Send my copies by themselves", which notices a copy
  and takes the input focus for a moment to read the clipboard (Settings explains it and
  opens the system's page).
  The app has its icon, and a release carries `clipboardbridge-X.Y.Z.apk`, signed with the
  project's release key (docs/apps.md, "Releasing the Android app").

- A new app icon, a clipboard with a key: light, and dark in the system's dark mode
  (iOS 18 and later).
- The phone app's "Sync clipboard" action, in Shortcuts and Spotlight without setting
  anything up: Back Tap or the Action button sends or fetches by the Home button's rule
  without opening the app, and says what it did.
- `install.sh --port N` (and `get.sh --port N`) moves the member port from 8764; it is kept
  in `/etc/clipboardbridge/clipboardbridge.env` as `CBB_PORT` for later updates, and the
  installer says to allow it in other firewalls. The phone app needs no setting.
- `uninstall.sh`, installed to `/usr/local/share/clipboardbridge`, removes clipboardbridge and the
  firewall rules its installer added; `--purge` also deletes the device's keys.
- The phone app's language can be chosen in the app (System, English, Russian), in Settings
  and, when the system's language has no translation, on the Start screen; Settings, with
  the theme, opens from the Start screen too.
- At the first launch the phone app makes its own key and says once that the phone is
  ready and that the next step is to connect a device.
- Groundwork for a second admin phone: members accept a member certificate issued by an
  admin CA under the phone's root, keep that CA with their identity, send it in member
  handshakes and take it from a pairing Welcome; the phone app makes admin CAs, verifies
  such chains and reads and signs records through an admin CA (docs/protocol.md, section 10).
- The phone app asks for Face ID (or the passcode) before it signs with the group's key in
  the Secure Enclave, once per action: adding a computer, removing a device, renewing its
  own certificate. It renews the computers' certificates only while that check lasts.
- The phone app's icon, drawn by `tools/icon` from the design tokens.
- The phone kit lets a second phone join a phone group: it listens and shows a join QR code,
  an admin phone scans it, and the root makes the new phone an admin with an admin CA for
  the admin key it sent. Admin phones admit and renew through their admin CA, and removing
  an admin phone keeps the devices it admitted (docs/protocol.md, sections 6 and 10).
- The phone app joins another phone's group: "Join another phone's group" on the Start
  screen shows a QR code, the other phone scans it with +, and the new phone becomes an
  admin. The Devices screen marks the admin phones and lets only admins remove devices.
- Members accept `root` records, which hand a phone group to a new root when the root phone
  is lost: they trust the new root next to the earlier ones, keep it with their identity,
  take renewals from it and refuse anything the old root's key signs after the handover
  (docs/protocol.md, section 10).
- Any admin phone renews the certificates of the group's devices, also those another admin
  admitted, as after that admin was removed: the `cert` message carries the admin CA that
  issued the new certificate, and members take it as their new issuer (docs/protocol.md,
  section 10).
- The phone app removes a lost phone that made the group: on an admin phone, Remove on that
  phone takes the group over with a new key in the Secure Enclave, and the computers and the
  other phones follow it.
- A computer can be an admin of a phone group: it keeps an admin key and offers it to the
  root phone, which can certify it as an admin CA. An admin computer admits computers with
  `cbb pair`, removes devices with `cbb revoke` and renews certificates from
  its admin CA; it never removes the root phone (docs/protocol.md, section 10, "A computer
  as admin").
- The phone app makes a computer an admin: on the root phone, "Make it an admin" on a
  computer's row in Devices asks for Face ID, sends the computer its admin CA and lists it
  as an admin; a computer that missed it gets it when it connects again.

### Fixed

- The release archives now carry `THIRD_PARTY_NOTICES`, the licenses of the Go modules,
  the copied CPace code and Go itself that `cbb` is built from, as their licenses require.
- A `cbb away` request still running while the service stops no longer starts the hub or
  the tunnel again after the stop.
- `cbb-lite version` and its status show the release's version, taken from the tag; it
  said 0.1.0 whatever the release.
- Adding a device in the phone app no longer hangs when the computer does not answer: a
  connection gives up after 5 s and its TLS handshake after 10 s, the pairing after 30 s,
  IPv4 addresses come first, leaving the sheet cancels it, and the message names the
  computer's firewall as a likely cause.
- The phone app could not sign its TLS handshake with its own key (PRIVATE_KEY_OPERATION_FAILED):
  the keychain kept the key's public half under the same label, and the identity paired
  the certificate with it. Only the private key is stored now, and stale public keys are
  removed. When every address of a device fails, the app reports the most telling failure,
  such as a failed handshake, rather than the last timeout.

## [0.2.0] - 2026-10-21

### Added

- A quick start, [docs/guide/quickstart.md](docs/guide/quickstart.md): install with one command, make
  the group, add the iPhone and the other computers.
- The devices list: `clipbridge devices` shows every device of the group with its role, an
  admin mark and when this member last saw it; `clipbridge revoke <name or ID>` removes a
  Mac, a phone or an iPhone's shortcut from the group. Members keep signed device and
  revocation records, give them to each other, and refuse removed devices at once; a removed
  iPhone's token stops working. A Linux member records the devices it admits, and the
  members of an existing group when it meets them. Removing a Linux member is not supported
  yet. See section 10 of [docs/protocol.md](docs/protocol.md).

### Fixed

- `clipbridge pair` and the installers told the new computer to run `clipbridge join`, which
  now shows a QR code for the phone; for the code they show, it is `clipbridge join -code`.

## [0.1.1] - 2026-10-21

The first release. The tag v0.1.0 was made, but its release build failed on the macOS
archives, so it has no release.

### Added

- Repository scaffolding: license (AGPL-3.0-only), security policy, contributing rules,
  code of conduct, issue forms and repository settings.
- Design document: [docs/design.md](docs/design.md).
- The `clipbridge` command: `service` runs the service; `pair` and `join` admit a computer to
  the group with a six-digit code; `copy` and `paste` use the group's clipboard; `status`
  shows the group and the connected members.
- The service: the group's certificates, pairing, mDNS discovery (publishing on Linux,
  browsing on a Mac), member connections and the sync engine, and a local control socket.
- The connector package, which links a desktop clipboard to the service.
- Linux desktops: `clipbridge desktop` links the session's clipboard, through Wayland
  data-control or X11 (XWayland on GNOME), started by an XDG autostart entry.
- Linux packaging: a hardened systemd unit, the service user, a tmux configuration, an
  optional tmux start on the text console, and `packaging/linux/install.sh`.
- macOS: `clipbridge agent` links the pasteboard (secrets stay on the Mac and carry the
  concealed marker); the service runs as a LaunchDaemon and the agent as a LaunchAgent,
  installed by `packaging/macos/install.sh`.
- iPhone: `clipbridge pair -phone` on the member that holds `clipbridge.local` serves the
  profile with the iPhone CA and a pairing page that issues the shortcut's token; the
  shortcut's `/sync` sends the iPhone's text to the group or brings a recent copy back.
  `pair -phone` shows a QR code of a page that walks through the steps; the shortcut,
  generated from the code and signed on a Mac, asks for the six-digit code on its first run
  and keeps its token.
- The phone as the main device: `clipbridge pair -phone` on a Linux machine in no group
  creates the group, and `clipbridge join` listens and shows a QR code (a `clipbridge://join`
  URL with its code, addresses and certificate fingerprint) that the shortcut "clipbridge:
  add a computer" scans; the Linux member then dials the computer, so no announcement and
  no multicast are needed, and a device that does not know the code learns nothing from a
  try. `clipbridge join -code` keeps the code from `clipbridge pair`.
- Certificate renewal: a Linux member renews its own certificates and, with a new `cert`
  message, those of the members it is connected to, months before they expire.
- The member protocol accepts the roles `phone` (the phone apps) and `lite` (a lite member),
  which connect like a Mac.
- Releases from a version tag: archives for Linux and macOS, `SHA256SUMS` and build
  provenance attestations; `get.sh` installs the latest release on Linux in one command,
  checks it, and opens clipbridge's ports in ufw for the home network only. The member port
  is 8764 and a listening join 8767 when they are free.
- Linux members without the CA keys, for groups whose root will be the phone: a welcome
  without them makes such a member, which syncs but admits nobody and never holds
  `clipbridge.local`.
- The start of the phone app: `apps/ios/ClipbridgeKit`, a Swift package with CPace (checked
  against the draft's test vectors), the pairing frames and the join QR code, tested on
  Linux and macOS against vectors from the Go side in `testdata/interop/`.
- ClipbridgeKit admits a computer as the phone will: it dials, confirms the code first and
  issues the computer's certificate; a Go test runs it against the Go joiner.
- Protocol specification: [docs/protocol.md](docs/protocol.md); the plan for the phone apps:
  [docs/apps.md](docs/apps.md).
- CI: formatting, vet, staticcheck, govulncheck, actionlint and repository rules; tests on Linux and
  macOS; builds for Linux (x86-64, ARM64, ARMv7, ARMv6) and macOS (ARM64, x86-64).

### Fixed

- The release build packs the macOS archives with `packaging/macos`; CI now builds every
  release archive on each pull request with the same script, `packaging/archive.sh`.

[Unreleased]: https://github.com/HunterEwok/clipboardbridge/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/HunterEwok/clipboardbridge/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HunterEwok/clipboardbridge/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/HunterEwok/clipboardbridge/releases/tag/v0.1.1
