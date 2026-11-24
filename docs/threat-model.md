<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Threat model

For engineers and security reviewers: what Connect Beyond Borders protects, which adversaries it
models, where its trust boundaries sit, and which defence and source code address each threat.
Items not yet implemented are marked **open**. For the security audit plan, see
[Security audit](maintainers/security-audit.md); for the normative wire specification, see
[Protocol](protocol.md); for vulnerability reporting, see [SECURITY.md](../SECURITY.md).

## Assets

| Asset | Why it matters |
|---|---|
| Clipboard content | Passwords, codes, private text, images, and files |
| Secrets (marked by a password manager or `-secret`) | Most sensitive copies; must stay in memory only and expire promptly |
| Group authority keys (root key, admin keys, recovery key) | Whoever holds them can admit devices and read future copies |
| Device member and tunnel keys | Whoever holds them can impersonate that device until it is removed |
| Device control (remote paste, quick actions, sync modes) | An admin can type into a device or lock, sleep, or restart it |
| Group metadata (device list, names, activity timing) | Reveals to a server or network which devices exist and when they communicate |
| Distributed binaries and packages | A tampered release executes code on user devices |

## Adversaries

| Adversary | Capabilities | Out-of-scope assumptions |
|---|---|---|
| **Device on the home network** (guest, IoT device) | Observe and inject LAN traffic, spoof mDNS, run a rogue member | Cannot break TLS 1.3 or signatures |
| **Network on the path** (café Wi-Fi, ISP, censor) | Observe, drop, tamper with, or block away-from-home traffic | Cannot break TLS 1.3, WireGuard, or signatures |
| **Server operator** (forwarder or blind relay operator, hosting provider) | Inspect relayed traffic, keep logs, drop or alter packets | Cannot read inside WireGuard, mutual TLS, or end-to-end sealed copies |
| **Thief with a physical device** | Read unencrypted disk contents; access whatever a phone lock permits | Cannot use hardware-gated phone keys without the user's face, fingerprint, passcode, or app PIN |
| **Compromised member** | Perform any member action; read copies sealed to it | Cannot exceed its role, read or alter copies sealed past it, or forge another device's copy |
| **Compromised forwarding-only hub** | Withhold copies; observe sender, time, recipients, and rounded size | Cannot read, modify, or forge copies (none are sealed to it), or act as an admin |
| **Compromised admin** | Sign group records and commands until frozen or removed | Cannot act after another admin freezes it; cannot remove the main device (*root*) |
| **Local user on a shared computer** | Run processes under their own user account | Cannot read service state files or connect to the admin socket |
| **Supply-chain attacker** | Tamper with dependencies or build infrastructure | Cannot sign releases with the project's offline release keys |

**Out of scope:** An attacker with root or administrator privileges on a group device, and the
operating system's local clipboard (readable by any process running under the signed-in user).

## Trust boundaries

1. **The device.** On computers, the service runs under its own unprivileged account; the admin
   socket admits only root or Windows administrators, and the control socket admits only root and
   the `cbb` group (`_cbb` on macOS). On phones, authority keys stay in hardware behind biometrics
   or passcode. On Aurora OS 5, the root or admin key sits in OP-TEE behind the app's own PIN
   (D-94); because Aurora OS provides no trusted input path, the PIN passes through app memory to
   OP-TEE and is wiped immediately, stopping anyone holding an unlocked phone (compromised code
   inside the app or root is out of scope).
2. **The home network.** Every member connection uses mutual TLS 1.3 verifying a peer's member key
   against the group's signed device records. The member port accepts only private, unique-local,
   and link-local addresses (and on routers, only home-zone interfaces).
3. **Intermediary members.** The copying device seals each copy end to end for reading devices only
   and signs it with its member key (D-84). Intermediaries—including hubs—cannot read, alter, or
   forge copies.
4. **The internet.** Away from home, members reach a hub through the group's WireGuard tunnel, with
   member mutual TLS inside it. Forwarders and blind relays sit on this boundary and hold no group
   keys.
5. **The release pipeline.** Binaries build in CI with pinned actions, `SHA256SUMS`, and build
   provenance, and are signed outside CI with the project's offline hybrid keys.

## Threats and defences

STRIDE categories: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure,
**D**enial of service, **E**levation of privilege.

| # | Boundary | STRIDE | Threat | Defence | Where |
|---|---|---|---|---|---|
| 1 | Home network | I | A LAN observer reads traffic | TLS 1.3 on every TCP connection; no plaintext member protocol | `core/src/tls`, `member/src/mesh.rs` |
| 2 | Home network | S | A rogue LAN device impersonates a member (for example via mDNS) | Mutual TLS: members accept a peer only if its key container holds a member key authorized by the group's signed records and not revoked (D-105) | `core/src/tls`, `core/src/records` |
| 3 | Home network | S | An attacker guesses or intercepts a pairing code | CPace inside TLS bound to the TLS exporter: one online guess per attempt, 3 attempts per 5-minute window, no offline guessing; code never passed on the command line | `core/src/join`, `member/src/pair.rs`, `member/src/joining.rs` |
| 4 | Home network | S | Man-in-the-middle attack during phone QR pairing | QR code carries the pairing secret spent in CPace bound to the TLS exporter, as in threat 3 | `core/src/join`, phone kits |
| 5 | Home network | D | Flood of TCP connections or mDNS packets | Global and per-source handshake limits with short first-byte timeouts; refused pairings read one small frame; record-only connections enforce small frame limits; bounded commands per connection; mDNS cache checked 10 times/s (restarts empty with backoff past 1,024 records or overload) and discovered peers capped; mDNS goodbye never stops dialing recorded peers; failed pairing attempts yield to the next; member port drops non-home addresses. Residual (Low): a LAN host using multiple addresses can fill handshake slots and delay pairing temporarily, without learning the code or joining | `member/src/discovery.rs`, `member/src/mesh.rs`, `member/src/join.rs`, `member/src/pair.rs` |
| 6 | Internet | I, T | Path observer reads or alters away-from-home traffic | Mutual TLS inside WireGuard with a per-client preshared key derived from an `X25519MLKEM768` TLS exporter; 16 KiB padded chunk frames and 64 KiB padded blob segments; **open**: padding text frames and cover traffic | `member/src/tunnel.rs`, `member/src/hub.rs`, `internal/tunnel` |
| 7 | Internet | S, D | Unsolicited packets to a hub's UDP port | WireGuard drops packets lacking a peer key from an authenticated hello or an active invitation's guest key | `member/src/hub.rs`, `internal/tunnel` |
| 8 | Internet | I | Censor detects and blocks the tunnel | AmneziaWG header obfuscation and VLESS over XHTTP behind the forwarder's HTTPS web server | `member/src/awg.rs`, `member/src/vless.rs`, `internal/tunnel`, `internal/vless` |
| 9 | Internet | I | Forwarder or relay learns device identities | Short-lived server credentials per 35-day period replace group records: no device ID, name, OS, or role is exposed (D-67, D-75, D-106); a hub sends only its hubs' credential to the forwarder, which routes by `mac1` and stores no group files | `internal/forward`, `internal/blind`, `member/src/relayd`, `core/src/blind/credential.rs` |
| 10 | Internet | I | Blind relay observes communication timing and addresses | **Accepted and disclosed**: the relay sees online pseudonyms, addresses, timing, and volume; `cbb global relay` and the apps warn and require explicit consent before enabling | `member/src/global_cli.rs` |
| 11 | Internet | D | One group or few hosts exhaust a shared server | Multi-level payer caps per address, network, wide network, IPv6 provider, and group ([The servers' budget](relay-budget.md)) | `internal/forward`, `internal/budget`, `member/src/relayd/limits.rs`, `member/src/relayd/budget.rs` |
| 12 | Device | I | Thief copies keys from disk | Hardware key storage where available (phones, Linux and Windows TPM 2.0, Mac Secure Enclave); service-only file permissions otherwise | `internal/tpmkey`, `internal/group/keys.go`, `member/src/keys.rs`, `member/src/sekey.rs` |
| 13 | Device | E | Thief uses a phone's root or admin key | Hardware enforces user verification (face, fingerprint, passcode, or OP-TEE PIN) per signature; Android binds verification via `CryptoObject` | Phone kits (`SecKeySigner`, Android Keystore `Keys`/`Authenticator`, OP-TEE, HUKS) |
| 14 | Group | S | Removed device continues participating | Signed revocation record propagates to all members, which refuse its key; hubs drop its tunnel key and senders stop sealing copies to its keys | `core/src/records` |
| 15 | Group | E | Stolen admin computer signs malicious records | Any admin can freeze it (all later signatures are ignored); only the main device or an admin phone can remove an admin; file-backed admins require explicit key-level consent | `core/src/records`, `member/src/devices_cli.rs` |
| 16 | Group | E | Main device (*root*) is lost | The offline hybrid recovery key (ECDSA P-256 + SLH-DSA-SHA2-128s) moves the group to another member (rule 33, D-117, D-125) while keeping remaining devices | `core/src/records` (`eval.rs`, `pq.rs`), `cbb recovery` |
| 17 | Group | T | Malicious peer pushes group logical clocks far ahead | Timestamps more than 7 days ahead of local time are rejected | `core/src/hlc.rs` |
| 18 | Group | T, R | Replayed or forged admin command (paste, action, mode) | Signed by an admin, expires 30 s after signing, checked against revocations and a replay cache, and logged by sender on the target device | `core/src/commands`, `internal/remotepaste`, `internal/actions` |
| 19 | Device control | E | Admin types into or restarts a device without user consent | Every remote paste target and quick action is off by default until enabled locally by that device's user; Enter, console, and reboot require separate consent; any admin can disable globally; blocked on lock and login screens | `internal/remotepaste`, `internal/actions`, `internal/lockcheck` |
| 20 | Device control | E | Pasted text executes as a shell command | Control characters are stripped; text containing line breaks is rejected unless the user explicitly enabled Enter | `internal/remotepaste` |
| 21 | Device control | E | Custom quick action abused as an arbitrary shell | Runs by full path with fixed arguments and no shell, as the signed-in user, with a 15 s timeout, configured only in that user's `own-actions.json` (unwritable by the service account) | `internal/actions/own.go`, `internal/connector` |
| 22 | Device | I | Another local user reads the clipboard via the service | Control socket restricts access to root and the `cbb` group (`_cbb` on macOS); group changes require the admin socket or interactive confirmation | `internal/control`, `member/src/control.rs`, `member/src/sys/acl_windows.rs` |
| 23 | Device | E | Network parser bug compromises the host | Memory-safe languages (Rust and Go); unprivileged service inside a systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, no capabilities, restricted address families and syscalls) | `packaging/linux/cbb.service` |
| 24 | Device | I | Secret persists past its lifetime | Secrets stay in memory only (never written to disk), skip formatted content, and expire after the group's secret lifetime (60 s default) | `member/src/board.rs` |
| 25 | Device | E | Received file executed as a program | Received files have non-executable permissions, receive macOS quarantine attributes and Windows Mark of the Web, and have path names sanitized | `internal/mediafile`, `member/src/files.rs` (`mark_download`), Mac app `PasteTarget` |
| 26 | Release | T | Tampered release binary reaches users | CI builds with pinned actions, `SHA256SUMS`, and build provenance; offline hybrid signing (ECDSA P-256 + SLH-DSA-SHA2-128s) outside CI with root keys on two YubiKeys (slot 82), release keys on YubiKeys (slot 83) or Mac Secure Enclave, and a channel key on `cbb.tools` renewing only `stable.json` (D-69); installers and updaters verify against pinned roots | `.github/workflows/release.yml`, `internal/release`, `core/src/release.rs`, `packaging/get.sh`, `tools/release-sign` |
| 27 | Release | T | Vulnerable or unauthorized dependency | Minimal dependencies; `govulncheck`, OSV-Scanner (Rust, Android, tray app), and `cargo-deny` (licenses and sources) run in CI | `.github/workflows/ci.yml` |
| 28 | Intermediaries | I, T, S | Hub or relaying member reads, modifies, or forges a copy | Each copy is sealed to reading devices (X-Wing HPKE per reader + ChaCha20-Poly1305 for payload and 64 KiB blob segments) and signed by the origin's member key; relaying members verify origin and signature and reject plaintext copies; forwarding-only hubs receive no key wraps (D-84) | `core/src/copies`, `core/src/seal.rs`, `internal/clip` |
| 29 | Intermediaries | I | Relaying member infers copy contents | Kind, text, file names, and file count travel inside the seal; sizes appear only in rounded steps (attachments in 64 KiB steps); **accepted**: sender, timestamp, and recipient set remain visible for routing | `core/src/copies`, `internal/clip` |
| 30 | Release | T | Network attacker tampers with ZX Spectrum Next files fetched over HTTP | Each `CBB` binary verifies the SHA-256 of the overlay, driver, and Pi `cbb` it installs; `.cbb update` accepts a newer `CBB` only from signed `zxnext.json` verified by the Pi's `cbb` against pinned release roots and rejects downgrades; **accepted**: the initial `.http` bootstrap trusts the network (see Residual risks) | `apps/zxnext/src/cbb.c`, `member/src/next.rs`, `internal/release/zxnext.go` |
| 31 | Internet | I | Push platform (APNs, FCM, UnifiedPush, Push Kit) or `cbb-push` reads wake-up content | Each notification body is sealed under the phone's group push key at a fixed padded size; notification text comes from local app translations; **accepted**: push platforms and `cbb-push` observe notification timing (see Residual risks) | `core/src/push.rs`, `member/src/pushd` |
| 32 | Device | I, E | Bug in the iOS notification service extension leaks signing keys | The extension's dedicated keychain access group holds only decryption and registration state (push keys, send key, active-window sealing secrets, origins, and window), never signing keys (member, admin, root, or recovery keys remain in the main app's keychain group); its app group is separate from the app's group state and server credentials; leaving a group deletes its push keys and secrets; the app updates active epoch secrets on rotation and removes expired epochs | `apps/ios/CBBKit/Sources/CBBKit/PushVault.swift`, `apps/ios/CBB/App/PushSetup.swift`, `apps/ios/NotificationService` |
| 33 | Internet | D, S | Attacker pre-registers a phone's push token to silence or impersonate it | `cbb-push` binds a token to the send key that echoes a stateless HMAC challenge delivered only to the token holder; before confirmation, sends face tight per-group rates and a per-token ceiling past which sends carry only the challenge so the phone can confirm; per-group delivery budgets prevent one group from exhausting a token; replayed, foreign, or stale challenges are rejected | `member/src/pushd/binding.rs`, `member/src/pushd/mod.rs` |

## Residual risks

- **Compromised readers**: Any device with reading rights can read all future group copies, and
  anyone holding the root or an admin key can add a reader. Restrict the group to devices you
  control, keep authority keys in hardware, and use a forwarding-only hub where appropriate.
- **File-backed keys**: Devices without a TPM 2.0 or Secure Enclave (and small devices) store keys
  in files that an attacker with disk access can copy. Use full-disk encryption and remove a lost
  device immediately.
- **Server metadata**: A blind relay and a forwarder observe client IP addresses and activity times
  (threat 10).
- **Push metadata**: Push platforms and `cbb-push` observe when a phone is notified, and push
  platforms know which app and device received the push (threat 31). Disable closed-app push
  notifications in app settings to eliminate this metadata.
- **ZX Spectrum Next initial download**: The first `.http -h cbb.tools -u /zxnext -f CBB` download
  runs over plain HTTP because neither `.http` nor the ESP8266 supports TLS. On an untrusted
  network, download `cbb-zxnext.tar.gz` from the signed release and copy `CBB` to the SD card
  manually (`apps/zxnext/README.md`, "What is checked").
- **Local OS clipboard**: Any process running as the signed-in user can read the local clipboard;
  Connect Beyond Borders cannot isolate copies from other programs on the same desktop.
- **Hardware testing coverage**: Components not yet tested on physical hardware are listed in
  [Status](../README.md#status); Linux and Windows TPM paths in particular are tested against a
  software TPM and a virtual machine.
