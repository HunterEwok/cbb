# clipboardbridge: notes for Claude Code

clipboardbridge syncs the clipboard between Linux computers, Windows PCs, Macs and an iPhone on
the home network. A Go service (`cmd/cbb`, `internal/...`) runs on the computers; the iPhone
app (`apps/ios`) is in development, and in its groups the phone is the root of trust.
Read [README.md](README.md), [docs/design.md](docs/design.md),
[docs/protocol.md](docs/protocol.md) (the wire format, kept in step with the code) and
[docs/apps.md](docs/apps.md) before larger changes; [docs/README.md](docs/README.md) maps every
page by its reader, and CONTRIBUTING's "Documentation" says where a change is written down.

## Working with the owner

- Talk to the owner in **Russian**. Everything in the repository is **English**: code,
  comments, docs, commit messages, PRs. The only exception is the apps' translations
  (`*.xcstrings`, Android `values-xx/strings.xml` later); `tools/repocheck` enforces it.
- Work through a task list in order without stopping to ask; ask only when a decision is
  genuinely the owner's.
- Every change goes to `main` through a pull request: push a branch, open it as a draft,
  mark it ready, and squash-merge it yourself once CI is green (`ci-ok` and the other
  checks; CodeQL's Swift analysis is slow and not required). The Codex review bot often
  fails on usage limits; ignore that.
- After a merge, start the next branch from a fresh `origin/main`.
- Release tags are pushed by the owner from their Mac (`git tag vX.Y.Z && git push origin
  vX.Y.Z`); the release workflow builds and publishes. Move CHANGELOG's *Unreleased* to the
  version in a PR first.
- Apple signing must never block development: CI signs the app ad hoc
  (`CODE_SIGN_IDENTITY=-`, no team), which needs no account and gives the simulator a
  keychain. TestFlight waits for the owner's Apple developer account.
- Commit messages: imperative summary, blank line, details; no model names. The owner's
  personal notes and testing guides stay out of the repository.
- Follow [CONTRIBUTING.md](CONTRIBUTING.md): license headers, CHANGELOG under *Unreleased*,
  copied code under `internal/third_party`.

## Build and test

The commands for every part (Go, the lite member in Rust, the Android app, the phone kit, the
cross tests between Go, Swift and Kotlin, the iPhone app) are in
[CONTRIBUTING.md](CONTRIBUTING.md), "Development"; run the ones for what you changed before
pushing. Cloud sessions: use `$(go env GOROOT)/bin/gofmt`, the `gofmt` on `PATH` may be older.

## Layout

- `internal/group`: identities, certificates (group CA, admin CAs, member certificates),
  member TLS, signed device and revocation records; `keys.go` puts new member and admin keys
  in the TPM (`internal/tpmkey`, go-tpm, tested against swtpm) on Linux.
- `internal/pair`: pairing (CPace inside TLS, the Welcome), both directions.
- `internal/node`: the member protocol and sync, commands passed on to members; `internal/service`: the daemon and CLI.
- Remote paste targets, each a `connector.Target`: `internal/desktop/x11paste.go` (XTEST),
  `waylandpaste.go` (the virtual keyboard), `portal.go` (the RemoteDesktop portal on GNOME and KDE,
  keys through `internal/ei`, the ei protocol, with `ei/eitest` an EIS server for tests), `internal/uinput`
  (`cbb paste-helper uinput`, the opt-in keys helper the desktop connector asks for Shift+Insert), `internal/tmuxpaste` (`cbb paste-helper tmux`),
  `internal/consolepaste` (`cbb paste-helper console`, TIOCSTI); `internal/lockcheck` tells
  them a locked session.
- `internal/keyboard`: the Bluetooth keyboards' layouts (the same as `cbb_core::keyboard` and the
  Android kit's `Keyboard`, all checked against `testdata/interop/keyboard.json`);
  `internal/blekeyboard`: a Linux computer as a BLE keyboard through BlueZ (`cbb keyboard`,
  `internal/service/keyboard.go`; `bluetest` plays BlueZ in tests).
- `internal/tvremote`: a member as a TV's remote (`cbb remote`, `internal/service/tvremote.go`):
  `androidtv` (Android TV Remote v2: pairing, the remote, `wire` its framing, `atvtest` a fake TV),
  `roku` (ECP); only on the home network (`netguard.ControlHome`).
- `internal/actions`: quick actions on a member (the presets, the user's settings, the checks
  on the signer, the log; `system_linux.go` runs them through logind and writes the polkit
  rule, `session_darwin.go` and `session_windows.go` in the agent); `internal/service/actions.go`
  takes `action` and `actions-off` commands and hands the presets to the agent on a Mac and Windows.
- `internal/remotepaste`: remote paste on a member (the user's switches, cleaning the text, the
  limits per sender, the log); `internal/service/paste.go` takes `paste` commands and hands
  them to the watchers that offer a target.
- `internal/tunnel`: WireGuard for sync away from home (amneziawg-go, a wireguard-go fork that is
  plain WireGuard until obfuscation is set, with gVisor netstack in the process): the hub,
  which opens only the member port to its clients, and the client;
  `state.go` and `internal/service/tunnel.go` exchange its keys in the member protocol
  (docs/protocol.md, section 11).
- `internal/vless`: VLESS with REALITY (Xray-core in the process) between a client and the
  forwarder, for networks that block WireGuard: the forwarder's side passes every packet to its
  own UDP port, the client's side is a local UDP port for WireGuard (docs/protocol.md,
  sections 11 and 13).
- `mobile/cbbtun`: the phones' tunnel to the hub, the same WireGuard in the app's process, bound
  by gomobile into an AAR and an xcframework (CI's `phone tunnel` jobs); a loopback port leads
  to the hub's member port, and the kits dial it with their own member TLS.
- Windows: `cmd/cbb/platform_windows.go` (the Windows service, logs),
  `internal/service/control_windows.go` (the socket's access list),
  `internal/pasteboard/pasteboard_windows.go` (the Win32 clipboard), `internal/winpaste` (remote paste:
  Ctrl+V or SendInput's Unicode keys, the secure desktop and integrity checks), `packaging/windows`
  (`install.ps1`, `uninstall.ps1`, `get.ps1`); CI's `windows installer` job runs them.
- `apps/ios/ClipboardBridgeKit`: the phone's protocol core: `Pairing*`, `Member`, `SyncEngine`,
  `MemberNode`, `Records`, `Certificates`, `PhoneGroup`, `Discovery`/`BonjourBrowser`,
  `TLSTransport`, `KeychainIdentity`, `SecKeySigner`, `AwayFromHome` (sync away from home through
  `Cbbtun.xcframework`); `clipboardbridge-interop` plays the phone
  in Go tests.
- `lite/`: the lite member in Rust (its command is `cbb` too): no CA keys, joins by the phone's QR code,
  dials the Linux members and listens for phones and Macs (mDNS TXT `r=lite`). Its protocol core is the crate `lite/core` (`cbb_core`: `certs`,
  `command` (the commands' bodies), `authority` (records `v:2` and their evaluation, docs/protocol.md section 10), `group` (the set of records `v:2` a member keeps), `api` (the one entry point, docs/core-api.md), `clip`, `hlc`, `wire`, `pair`, `identity`, `store`, `keyboard` (the layouts' keys), CPace under `src/third_party`, the
  interop vectors, and with the `tls` feature `tls`: rustls unbuffered with a RustCrypto
  provider, the peer checks, a sans-I/O `Session`, the pairing exporter from the key log):
  no_std with alloc, RustCrypto, no I/O, for the ESP32; CI's `esp32` job builds it for the
  C6 (RISC-V) and the S3 (Xtensa); `lite/src` adds the files, the sockets around the
  core's TLS, mDNS, the control socket, remote paste (`remotepaste.rs`, the tmux and console
  helpers in `pastehelper.rs`) and the tunnel to the hub (`tunnel.rs`, `away.rs`:
  GotaTun's WireGuard and smoltcp's TCP behind a loopback port; GotaTun's AEAD comes from
  `lite/ring-shim`, a stand-in for ring on RustCrypto, patched in by `lite/Cargo.toml`).
- `lite/ffi`: the core's one entry point (`cbb_core::api`, docs/core-api.md) as C functions (`include/cbb_core.h`)
  for Go and the phone kits (`Core.swift` through the module `CCbbCore`, `Core.kt` through JNA); `bind.sh` builds the
  iPhone's and Android's libraries and the host's for `swift test`.
- `lite/esp32`: the firmware for the Arduino Nano ESP32 (ESP32-S3), its own workspace, built
  with the Xtensa toolchain (`cargo +esp`) and rust-lld; esp-hal is pinned to a git commit
  until a release carries its fix for Rust 1.99; `console.rs` (the USB console), `store.rs`
  (settings in the flash partition `cbb` of `partitions.csv`), `net.rs` (Wi-Fi, embassy-net), `pair.rs` (the pairing task around `lite/embassy`), `usb.rs` (the USB port as a keyboard and the console's serial port, on OTG), `ble.rs` (the board as a Bluetooth LE keyboard, trouble-host on esp-radio), `out.rs` (where the console's lines go);
  `qemu-test.sh` types on the console and runs the self-test in Espressif's QEMU (the
  `qemu` feature: console on UART0, no Wi-Fi, without esp-hal's init and with a fixed
  pseudo-random generator, never for a real chip).
- `lite/embassy`: the firmware's network code on embassy-net without the chip (`pair.rs`,
  joining by the phone over TCP), no_std; with the feature `host` the program `esp32-on-linux`
  runs it on Linux over a TAP interface, for `TestEmbassyJoiner` (CI's `lite` job).
- `apps/zxnext`: `.cbb`, the dot command for the ZX Spectrum Next in C for z88dk (`frame.c`
  parses the frames of the lite member's `cbb next`, `link.c` drives the UART to the Next's Pi; `make test`
  runs the parser's tests on the host).
- `apps/macos`: the Mac app (SwiftUI, XcodeGen) over the service's control socket
  (`Control.swift`), admin actions through `cbb` with administrator privileges (`Admin.swift`),
  the Mac's remote paste target (`PasteTarget.swift`: a paste-only watch, Cmd+V or Unicode key
  events), the iPhone app's `Theme` shared; CI's `Mac app` job.
- `testdata/arrangement`: the vectors of the tiles' order and collections (docs/apps.md), read by `apps/desktop/arrange.go`, the Kotlin kit's `Arrangement.kt` and the Swift kit's `Arrangement.swift`.
- `apps/desktop`: the tray app for Linux and Windows (Go module of its own, Wails 3 beta,
  GTK 4/WebKitGTK; `desk.go` over `internal/control`, `admin_*.go` run cbb through pkexec or
  UAC, `frontend/` plain HTML/JS with `tokens.js` from `tools/tokens` and `l10n/ru.json`);
  CI's `tray app` jobs.
- `apps/android/kit`: the phone's protocol core in Kotlin, the Android twin of the Swift kit;
  `apps/android/app`: the Compose app (`WatchLink` tells the Wear OS watch, `BluetoothKeyboard` types
  on a paired device with the kit's `Keyboard` tables), in two flavors: `full` (GitHub, the watch, its own update) and `fdroid` (no Play services; `src/fdroid`, `packaging/fdroid`, reproducible, CI's `fdroid` job);
  `apps/android/wear`: the Wear OS app, through the phone over the Wearable Data Layer;
  `apps/android/shared`: what the two share (`Tokens.kt`, the glyphs, `WatchState`).
- `apps/ios/ClipboardBridge`: the SwiftUI app (`AppModel`, `LiveGroup`, views, theme from
  `apps/design/tokens.json`, String Catalogs in English and Russian; `GroupEvents` notifies of
  the group's events, `WatchLink` talks to the watch); `apps/ios/Watch`: the Apple Watch app,
  which works only through the iPhone over WatchConnectivity (`Shared/WatchState.swift`).

## Status

Done: the Go service (0.2.0 released); the app makes its own group (root key in the Secure
Enclave, Face ID before each signing action), admits computers by QR code, syncs with them,
shows the devices and removes them, renews certificates (any admin renews any device, the
`cert` message carrying its admin CA); admin CAs under the root work in Go and in the kit
(records, chains, Welcome `issuer`); a second phone joins from its Start
screen and the root makes it an admin (`PairingJoiner`, `TLSListener`, `PhoneGroup.joined`);
an admin phone removes a lost root phone by taking the group over with `root` records
(`PhoneGroup.takeOver`, a claim that waits the root's delay, then `finishTakeOver`; both
kits' `RecordSet` asks the Rust core);
a computer of a phone group can be an admin: the root phone's "Make it an admin" certifies
the admin key its hello offers (`PhoneGroup.makeAdmin`, the `admin` message; Go's
`Identity.AdminKey`/`AdminCA`); the lite member for Linux (`lite/`), with
the interop vectors and an e2e test among Go members, not yet run on a real Pi; the
Android app (`apps/android`) does what the iPhone app does, receives copies by itself in a
foreground service and sends them with the accessibility service or one tap, and each
release carries its signed APK (docs/apps.md); Homebrew (`hunterewok/tap`); sync away
from home between computers and for the lite member on Linux, through a hub's WireGuard
tunnel (`cbb global`; `TestLiteMemberAway`).

Next steps, roughly in order:

1. TestFlight (needs the Apple account), a signed macOS `.pkg`, remote invitations on the
   phones (sync away from home works between computers, on both phones and on the lite
   member: docs/protocol.md section 11), the lite member on the ESP32 (see docs/roadmap.md).

Windows (the service, the agent, the installers) passes CI on windows-latest and runs in a
Windows 11 virtual machine (Arm), where the tray app and the agent's clipboard work; not yet
tested on a real PC, nor remote paste and the quick actions there from a phone.

Not yet run on a real Android phone or emulator: the Keystore keys and BiometricPrompt,
`ACCESS_LOCAL_NETWORK` on Android 17, the accessibility overlay getting the focus, the copy
events of each maker's apps, the foreground service across reboots and battery savers.

Verified on a real iPhone, Apple Watch and Mac (apps/ios/device.sh, a free Personal Team):
Secure Enclave key creation with user presence, the Face ID prompt, the keychain identity
for TLS, the admin CA in the TLS chain, making a computer an admin, sync both ways, the
watch's list, remote paste to the Mac at home and away from home (through a Mac hub and
the `cbb.tools` forwarder). Not yet: listening for a joining phone
(`TLSListener`), the takeover (a new Secure Enclave root key signed right after the admin
key) and a run of the background app refresh (the simulator has no BGTaskScheduler); test
these on a device before relying on them.
