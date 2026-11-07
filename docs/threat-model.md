<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Threat model

For engineers and security reviewers: what Copy Beyond Borders protects, from whom, where the
trust boundaries are, and which defence answers each threat, with the code that holds it.
It describes the version in this repository; what is not built yet is marked **open**. The
plan of the security audit is in [security-audit.md](security-audit.md), the wire format in
the [protocol](protocol.md), and how to report a vulnerability in
[SECURITY.md](../SECURITY.md).

## Assets

| Asset | Why it matters |
|---|---|
| The clipboard's content | passwords, codes, private texts, images and files |
| Secrets (marked by a password manager or `-secret`) | the most sensitive copies; they must not outlive their minute |
| The group's keys: the root key, the admin CAs' keys | whoever holds them can add devices and so read every copy |
| A device's member key and tunnel key | whoever holds them can act as that device until it is removed |
| Control of a device: remote paste, quick actions, sync modes | an admin can type into a device or restart it |
| The group's metadata: which devices exist, their names, when they talk | tells a server or a network who owns what and when they are active |
| The programs themselves | a changed release could do anything on every device |

## Adversaries

| Adversary | Can | Cannot, by assumption |
|---|---|---|
| **A device on the home network** (a guest, an IoT device) | see and send any packet on the LAN, answer mDNS, run a rogue member | break TLS 1.3 or the signatures |
| **A network on the way** (a café's Wi-Fi, an ISP, a censor) | see, drop and change every packet away from home, block protocols | the same |
| **A server operator** (a forwarder or relay someone else runs, its hosting provider) | see the traffic it passes, keep logs, change or drop packets | read inside the WireGuard tunnel and the member TLS |
| **A thief with a device** | everything on its disk; on a phone, what its lock allows | unlock a phone's hardware keys without the user's face, fingerprint or passcode |
| **A compromised member** | everything that device may do in the group; read the copies sealed to it | more than its role allows (a member is not an admin); read or change a copy it only passes on, or make one in another device's name |
| **A hub that only passes copies on**, compromised | hold copies back; learn what a member in between learns: which device sent a copy, when, to which devices, its size within a step | read, change or forge a copy (none is sealed to it), or act as an admin |
| **A compromised admin** | sign records and commands until it is frozen or removed | act after another admin freezes it; remove the root |
| **A local user** on a shared computer | run programs as themselves | read the service's files, use the admin socket |
| **A supply-chain attacker** | change a dependency, try to change a release | sign a release with the project's keys |

Out of scope: an attacker with root on a device that is in the group, and the systems' own
clipboards, which any program of the signed-in user may read.

## Trust boundaries

1. **The device.** The service runs as its own user; the admin socket admits only the
   computer's administrators, the control socket root and the `cbb` group. A
   phone's keys are behind its secure hardware and biometrics.
2. **The home network.** Every connection between members is mutual TLS 1.3 under the
   group's certificates, on the member port, which takes only private, unique-local and
   link-local addresses (and on routers only the home zones' interfaces).
3. **The members in between.** A copy is sealed end to end by the device that makes it to
   the devices that read copies, and signed by it (D-84): the members that pass it on, a hub
   among them, cannot read or change it, nor make one in another device's name.
4. **The internet.** Away from home, members reach the group only through its WireGuard
   tunnel to a hub; the member TLS runs inside it. A forwarder or a blind relay sits on this
   boundary and holds no keys of the group.
5. **The release.** Programs come from this repository's CI, with checksums and build
   provenance, and are signed with the project's own keys outside CI.

## Threats and defences

STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial
of service, **E**levation of privilege.

| # | Boundary | STRIDE | Threat | Defence | Where |
|---|---|---|---|---|---|
| 1 | home network | I | someone on the LAN reads the traffic | TLS 1.3 on every connection; no plain-text protocol | `internal/node`, `core/src/tls` |
| 2 | home network | S | a device poses as a member, for example by answering mDNS | mutual TLS: members dial discovered addresses and check the peer's certificate against the group's CAs, the device records and the revocations | `internal/group`, `internal/node` |
| 3 | home network | S | someone guesses or intercepts a pairing code | CPace inside TLS, bound to the TLS exporter: one online guess per attempt, three per window of 5 minutes, no offline attack; the code never on the command line | `internal/pair`, `core/src/pair` |
| 4 | home network | S | a man in the middle during a phone's QR pairing | the QR code carries the pairing code, which the phone spends on CPace inside TLS as in threat 3, so a device in the middle learns nothing it can use | the kits' `Pairing*` |
| 5 | home network | D | a flood of connections or mDNS packets | limits on handshakes, mDNS cache entries and peers; the member port drops other addresses | `internal/service`, `internal/mdns` |
| 6 | internet | I, T | someone on the way reads or changes the traffic away from home | the member TLS inside the group's WireGuard tunnel, a preshared key per client, chunk frames padded to 16 KiB; **open**: padding text frames and cover traffic | `internal/tunnel` |
| 7 | internet | S, D | packets to the hub's port from outside the group | WireGuard drops every packet without a key that a member offered in its authenticated hello, or an invitation's guest key | `internal/tunnel` |
| 8 | internet | I | a censor detects and blocks the tunnel | AmneziaWG's obfuscation, VLESS with REALITY in front of the forwarder | `internal/tunnel`, `internal/vless` |
| 9 | internet | I | a forwarder or relay learns who the devices are | short server credentials per period instead of the group's records: no device ID, name, system or role (D-67, D-75); the forwarder routes by `mac1` and keeps no group files | `internal/forward`, `internal/relay`, `internal/group/credential.go` |
| 10 | internet | I | a relay learns who talks to whom and when | **accepted, told to the user**: the relay sees which devices are online, from where, and how much they send; `cbb global relay` and the apps say so and ask before it is used | `cmd/cbb/global.go` |
| 11 | internet | D | a group, or a few hosts, fill a shared server | limits per group, per address and per network on the forwarder and an open relay | `internal/forward`, `internal/relay/limits.go` |
| 12 | device | I | a thief copies the keys from a disk | keys in hardware where the device has it (phones, Linux with a TPM), the files readable only by the service; **open**: the Secure Enclave on Macs and the TPM on Windows | `internal/tpmkey`, `internal/group/keys.go` |
| 13 | device | E | a thief uses a phone's root or admin key | the key signs only after the user's face, fingerprint or passcode; on Android the Keystore checks it for each signature, through the prompt's CryptoObject | the kits' `SecKeySigner`, Keystore (`Keys`, `Authenticator`) |
| 14 | group | S | a removed device keeps acting | revocation records reach every member, which then refuse its certificate; the hub drops its tunnel key | `internal/group/records.go` |
| 15 | group | E | a stolen admin computer signs records | any admin freezes it (nothing it signs counts from then on); only the root or an admin phone removes an admin; file-key admins need the user's explicit consent (key levels) | `internal/group`, `cmd/cbb/devices.go` |
| 16 | group | E | the root is lost | an admin takes the group over with signed `root` records; the devices stay | `internal/group`, `PhoneGroup.takeOver` |
| 17 | group | T | a device moves the group's clocks for good | received times more than 7 days ahead are refused | `internal/hlc` |
| 18 | group | T, R | a replayed or forged command (paste, action, mode) | commands are signed by an admin, expire 30 s after signing, are checked against the revocations and a replay cache, and each device logs who sent what | `internal/group/command.go`, `internal/remotepaste`, `internal/actions` |
| 19 | device control | E | an admin types into a device or restarts it against its user's will | every remote paste target and quick action is off until the device's own user turns it on there; Enter, the console and reboot are separate consents; any admin turns them off everywhere; never on a lock or login screen | `internal/remotepaste`, `internal/actions`, `internal/lockcheck` |
| 20 | device control | E | a pasted text runs as a command | control characters removed; a text with a line break is refused on every target of a computer unless the user turned Enter on | `internal/remotepaste` |
| 21 | device control | E | a user's own action becomes a shell | the program runs by its full path with fixed arguments, no shell, as the signed-in user, for at most 15 s | `internal/actions` |
| 22 | device | I | another local user reads the clipboard through the service | the control socket admits only root and the `cbb` group; changes to the group only on the admin socket | `internal/control`, `internal/service/control_windows.go` |
| 23 | device | E | a bug in the network code takes over the computer | memory-safe languages; the service unprivileged in a systemd sandbox (`NoNewPrivileges`, `ProtectSystem=strict`, no capabilities, restricted address families and system calls) | `packaging/linux/cbb.service` |
| 24 | device | I | a secret outlives its minute | secrets are kept in memory only, never on disk, and gone 60 s after the copy; their formatting is never read | `internal/clip` |
| 25 | device | E | a received file is opened as a program | received files are never executable, carry the quarantine mark on a Mac and the Mark of the Web on Windows, and names are made safe | `internal/mediafile` |
| 26 | release | T | a changed program reaches users | release builds only in CI, pinned actions, `SHA256SUMS`, build provenance attestations; release files signed outside CI with the project's keys: roots on two YubiKeys, the release key in a Mac's Secure Enclave, a channel key on cbb.tools that only renews `stable.json` (D-69); every installer and updater checks them against the pinned roots | `.github/workflows/release.yml`, `internal/release`, `packaging/get.sh`, `tools/release-sign` |
| 27 | release | T | a vulnerable dependency | few dependencies, `govulncheck` for Go and OSV-Scanner for the Rust crates, the Android libraries and the tray app in CI | `.github/workflows/ci.yml` |
| 28 | members in between | I, T, S | a hub or another member that passes a copy on reads it, changes it, or makes a copy in another device's name | each copy sealed to its readers (X-Wing for each reader's key, ChaCha20-Poly1305 for the copy and its blob in segments) and signed by the origin's member key; every member checks the certificate and the signature before it passes a copy on, and no member takes a copy in the open; a hub may only pass copies on and read none (D-84) | `internal/clip`, `core/src/copy.rs` |
| 29 | members in between | I | a member in between learns what the copies are | the kind, the text, file names and their number travel inside the seal; sizes show only in steps, an attachment only to 64 KiB; **accepted**: which device sent a copy, when and to which devices | `internal/clip` |
| 30 | release | T | someone on the network changes the ZX Spectrum Next's files, which NextZXOS fetches over plain HTTP | each `CBB` installs only the overlay, driver and Pi `cbb` whose SHA-256 it carries; `.cbb update` takes a newer `CBB` only from `zxnext.json`, signed by a release key, which the Pi's `cbb` checks against its pinned roots and refuses for a release older than its own; **accepted**: the first `CBB`, which `.http` fetches, is as trustworthy as the network (residual risks) | `apps/zxnext/src/cbb.c`, `member/src/next.rs`, `internal/release/zxnext.go` |

## Residual risks

- A reader reads the group's clipboard by design: anyone who controls a device that copies
  are sealed to reads every copy from then on, and whoever holds the root's or an admin's key
  can add such a device. Keep the group to devices you control, and the root's and admins'
  keys in hardware; a hub that only passes copies on reads none.
- Keys in a file (Macs, Windows PCs and Linux computers without a TPM, the lite member) can be
  copied by whoever reads the disk; encrypt the disk and remove a lost device at once.
- A blind relay and the project's forwarder see addresses and times of activity (threat 10).
- On the ZX Spectrum Next, the first `.http -h cbb.tools -u /zxnext -f CBB` trusts the
  network it runs over: neither `.http` nor the ESP has TLS, and nothing on the Next can
  check the `CBB` it fetches. Whoever changes that download controls what the Next installs,
  the Pi's `cbb` included, and so the keys the Pi checks updates with from then on. On a
  network you do not trust, take `CBB` from the signed release (`cbb-zxnext.tar.gz`) and
  copy it to the card instead (apps/zxnext/README.md, "What is checked").
- The systems' clipboards are readable by any program of the signed-in user; Copy Beyond
  Borders cannot protect a copy from other programs on the same device.
- What has not run on real devices yet is listed in the [README](../README.md#status); the
  hardware key paths in particular are tested against simulators only.
