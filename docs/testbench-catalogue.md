<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# The bench's test catalogue

Every case the hardware test bench ([testbench.md](testbench.md)) runs for release 0.6 and
later, one line each, grouped by area. It is written for the product as the 0.6 plan
describes it, every phase included, and for a bench that has every device and developer
account it needs: a case whose function, device or account is not there yet is still
listed, says what it needs in its last column, and is reported as skipped with that reason
until it is there.

The functions these cases cover, one line per function of the product, are in
[testbench-functions.md](testbench-functions.md). `testbench coverage` reads both files and
prints how many functions have a case, how many of those cases run by themselves, and how
many the harness runs today, by area, with the list of what is left (section 17).

The step-by-step form of the cases that have one, and the common procedures R1 to R7 (reset,
form the group, end a run, copy and read, "arrives", errors in both modes, capture), are in
[testbench-cases.md](testbench-cases.md). That document keeps its own IDs; the IDs of a case
here that replaces one there are in brackets, such as [C1].

## 0. How the cases run

### 0.1 Where

| Kind | What | Used for |
|---|---|---|
| **real** | the bench's devices (testbench.md, section 3): the Linux desktop, the Windows PC, the Mac, the lite board, the away computer, the router as a device under test, the relay server, the phones, the watches, a TV | everything a user does on a real system: clipboards, desktops, sessions, installers, sleep, the apps |
| **fleet** | containers on the controller, each a member with its own network namespace and state volume: up to 32 full members and 8 lite members, a FreeBSD and an OpenWrt virtual machine in QEMU, and "phones" played by the kits' interop programs (`cbb-interop` in Go, the Kotlin kit on the JVM, the Swift kit on the Mac) | combinations that need many devices, groups made and thrown away by the hundred, faults that must not touch the real devices (netem, port blocks, a full disk, a clock far off, a killed process), several groups on one network |
| **time** | a test build (`-tags benchtime`, never released; `cbb version` says so) in which the long times run 100000 times faster: certificate lives and renewal thresholds (a member certificate lasts about 10 minutes), the 12 h renewal timer (every 5 s), server-credential periods (about 30 s) and the hub key's handover; and `CBB_TEST_CLOCK` (a duration such as `3h`, or an RFC 3339 time; or a file named by `CBB_TEST_CLOCK_FILE`, read when the service starts), which moves one member's wall clock for its service, its hybrid clock, its hellos and its certificate checks. `CBB_TEST_SCALE` sets another scale, such as 1 for cases that only move a clock by hours or days. Short times (pairing windows, invitations, secrets' 60 s, the media cache, replay caches) keep their length and are waited out | expiry, renewal and every rule that waits for time, in minutes |
| **feed** | a release feed on the controller signed with the bench's own test keys, in the format of the real one (protocol.md, section 16) | updates, rollbacks, refused downgrades, tampered and expired manifests, without the real release keys |
| **ui** | UI Automator over adb (Android phone, Wear OS, Android TV), XCUITest (the iPhone app on a simulator and a real iPhone, the Mac app), WebDriver for the tray app | the apps' screens, buttons and notifications |
| **helper** | a small program the `setup-*` scripts put on a device: the Windows clipboard task, a clipboard manager's stand-in, a password manager's marks, a key-event reader | what only code inside the user's session can do |
| **person** | the owner, guided by the report | only what a program cannot press: a disk password at boot, a hardware prompt, moving a device |

### 0.2 How a case checks errors

Every case that expects a refusal or an error also checks it as R6 says, in both modes:
the short message says what to do; with `CBB_DEBUG=0` (in the apps, "Show error details"
off) it carries no internal error text and no detail line; with `CBB_DEBUG=1` (details on)
the cause is under it; the log has the cause in both; nothing says only "Something went
wrong". `tools/bench/errshow.go` does it for the command line.

### 0.3 Combinations

Where a case says **every pair** it runs from each kind of sender to each kind of receiver
the bench has: Linux on Wayland, Linux on X11, Linux without a desktop, Windows, macOS, the
lite member, a container, the router, FreeBSD, the Android app, the iPhone app, Android TV; and over each path: one LAN, across subnets (`-peer`), the hub's
tunnel directly, through the forwarder, with AmneziaWG, over VLESS, through the blind relay.

Where it says **every role**: the root (a computer, a phone), an admin (a computer with a
file key, a computer with a TPM key, a phone, a watch), a member, a lite member,
a frozen admin, a removed device.

### 0.4 The columns

**How** names the kinds of 0.1 the case runs on; several mean the case runs on each.
**Needs** is empty when the bench and the product have everything the case needs; otherwise
it names what is missing: a phase of the 0.6 plan not yet merged (`phase 7` and so on), an
account (`Apple account`, `Google account`, `signing`), or a device (`TV`, `Apple TV`,
`Nano`, `iPad`, `ZX Next`, `smart plug`).

## 1. Installation, updates and the service's life (I)

| ID | Case | How | Needs |
|---|---|---|---|
| I1 | Fresh install with each installer: `install.sh` (Linux, macOS), `get.sh`, `get.sh --lite`, `install.ps1`, `get.ps1`, winget then `cbb install`, Homebrew then `install.sh --in-place`, Docker compose, the OpenWrt apk, FreeBSD's rc.d, the OPNsense plugin; `cbb version` names the build | real, fleet | |
| I2 | Installer options: `--express`, `--no-firewall`, `--port N` and back with `--port 8764`, `--console`, `--uinput`, `--home-cgnat on/off` and `-HomeCgnat`, `CBB_FIREWALL=express/no`, `$env:CBB_PORT`; the kept answers (`firewall.answer`, `cbb.env`, the registry) used by the next run; each firewall (ufw, firewalld, nftables, iptables, Windows Firewall, the macOS application firewall, fw4, pf, ipfw) gets exactly its rules [P6, S12] | real, fleet | |
| I3 | `get.sh` and `get.ps1` check the release: a good build installs; a tampered archive, a wrong signature, an expired manifest, an unknown key and a missing openssl are refused with a clear message; `CBB_VERSION` installs that release | feed | |
| I4 | Uninstall and purge on each system leave nothing: service, agent, units, firewall rules, users and groups, the Apps entry on Windows, the state with `--purge`/`-Purge` and the keys kept without it [L10] | real, fleet | |
| I5 | Install again over an install: the group, mode, settings, quick actions, remote paste switch and keys stay | real | |
| I6 | Upgrade from the previous release one device at a time in a mixed group, copying between old and new after each step; state and keys survive; the agent restarts in every running session [L9] | real, fleet | |
| I7 | Downgrade to the previous release over the new state: it starts or refuses clearly, and no key is lost [P14] | real, fleet | |
| I8 | `cbb update -check` and `cbb update` on Linux, macOS and Windows from the feed: renamed into place (the running exe moved aside on Windows), the health check passes, the new version runs | feed, real | |
| I9 | Updates refused: a tampered file, a bad signature, an expired manifest, an older version (the highest seen is kept), `min_from` not met, a wrong platform; each named in the message | feed | |
| I10 | A new build that never becomes healthy is rolled back and listed as failed; the next check skips it | feed | |
| I11 | Each install method: Homebrew and winget refresh the service's copy; Docker, apk, pkg and FreeBSD print their own command and change nothing | real, fleet | |
| I12 | Automatic updates: the installers' question, the timer, `cbb update -auto on/off`; in a group one member fetches the signed manifest and archives and the others take them from it | feed, time | |
| I13 | The lite member updates itself on Linux; the Nano updates over the air from a member and rolls back after a bad image | feed, helper | Nano |
| I14 | Android updates its sideloaded APK: the signing certificate is checked first, the update needs no tap, a wrong certificate is refused | ui | Google account |
| I15 | The Mac app updates through Sparkle; the tray app and `cbb status` show that an update is ready | ui | Apple account |
| I16 | The service manager restarts a killed service on each system and in the container [F1] | real, fleet | |
| I17 | Reboot each device: it rejoins with no action beyond booting; Windows syncs before anyone signs in [F2] | real, person | smart plug |
| I18 | Sleep and wake (macOS, the Windows VM, the Linux desktop through `rtcwake`): in sync within 30 s, the clock column right [F3] | real, helper | |
| I19 | The service starts with no network and finds the group when it comes; a device without a real-time clock (the lite board, the router) waits for NTP before it checks certificates | fleet, real | |
| I20 | The systemd units' hardening holds (`systemd-analyze security` at or below the recorded score); the TPM reached through `/dev/tpmrm0` only | real, fleet | |
| I21 | Logs: rotated at 1 MiB on Windows and macOS, journald on Linux, syslog on the router; the agent's own log | real | |
| I22 | The release: every archive's `SHA256SUMS`, attestation and signed manifest agree; the Docker image's digest matches the manifest | feed | |
| I23 | Our signed apk feed on OpenWrt: `apk add` from it, its key checked; the mips and mipsle builds boot and sync under QEMU (big-endian) | fleet | |
| I24 | Windows binaries carry a valid Authenticode signature; `cbb update` checks it; SmartScreen lets the installer run | real | signing |
| I25 | The installers' errors: a failed step names its exit status; `CBB_ERROR_DETAILS=1` shows every command and the full Windows error record | real | |

## 2. Groups, pairing and roles (G)

### 2.1 Making a group and joining

| ID | Case | How | Needs |
|---|---|---|---|
| G1 | `cbb new` on Linux, Windows, macOS, the router, FreeBSD; the lite member and a container refuse it; a container with `CBB_KEYS_IN_FILE=yes` may [P35] | real, fleet | |
| G2 | A phone app makes the group: the root key in the Secure Enclave or the Keystore, made with an attestation challenge; the first-launch card | ui | iPhone, Android phone |
| G3 | Each kind of device joins by code to each kind of admitter (root computer, admin computer, root phone, admin phone) [L1] | real, fleet, ui | |
| G4 | Join paths: found by mDNS; by address; across subnets; through an SSH forward to 127.0.0.1; through the user's own VPN with private addresses; a 100.64/10 address refused unless `CBB_HOME_CGNAT=1` | fleet, real | |
| G5 | The pairing window: three wrong codes close it; a code after 5 min is refused; an attempt started just before the end may finish; a used code is refused for a second device; the window counts time the machine slept [L2] | real, fleet, time | |
| G6 | Pairing limits: a second joiner while one pairs hears `busy`; a code already used hears `taken`; five attempts per address before the count; 30 s per attempt; 32 handshakes at once | fleet | |
| G7 | Two windows announced at once: the joiner asks for an address | fleet | |
| G8 | A joiner that only pretends to pair gets one guess; a relay between two TLS sessions fails (CPace's channel binding) | fleet, helper | |
| G9 | `cbb pair` on a member that is no admin names the devices that admit; on a device in a group it keeps its group | real | |
| G10 | A computer joins a phone's group by QR code (the phone dials it; fingerprint and code checked); the lite member and the Nano the same; a QR code of another session is refused | ui, fleet | |
| G11 | A second phone joins from its Start screen and becomes an admin; an iPad joins as a phone | ui | iPhone, iPad |
| G12 | Remote invitation: `cbb invite` on the hub, `cbb pair -invite` away; both show the same fingerprint; `yes` admits; the guest tunnel reaches only the pairing [P11] | real | |
| G13 | Invitation refused: answered `no`; used twice; after its time (1 h by default, `-for 24h`, more than 24 h refused); the hub off; three failed attempts; cancelled; a file of another group; nothing left on the hub after each [P21, S7] | real, time | |
| G14 | An invitation made and served by a phone that is the hub, and used on a phone | ui | |
| G15 | Joining with the hub's addresses only: the service may reach them for the join and a failed join takes them back | real | |
| G16 | The joiner's identity is replaced in one step: the joiner killed at each step (before the welcome, after the certificate, before it confirms) leaves no half-joined device, and the window says whether it was stored | fleet | |
| G17 | The joining computer listens for the phone (QR): only during the join, only for the phone named in the code | fleet | |

### 2.2 Admins, the root and removal

| ID | Case | How | Needs |
|---|---|---|---|
| G20 | `cbb admin NAME` on the root: refused for a file key without `-allow-file-key`, allowed for a TPM key; the target must be connected; refused for a container and a lite member [L5] | real, fleet | |
| G21 | An admin computer admits, renews, removes ordinary devices; it cannot make admins or remove the root or another admin [L5] | real, fleet | |
| G22 | `cbb freeze` from any admin; a frozen admin's records, commands, pastes and connections refused everywhere; `cbb unfreeze` on the root; a mutual freeze keeps both frozen; a frozen admin cannot take over; the root and admin phones cannot be frozen | fleet | |
| G23 | Remove by name and by device ID: a member, an admin (the devices it admitted stay), a phone (both keys), a watch; the removed device's connections close at once and every member, the lite member and the hub refuse it [L3, L7] | real, fleet | |
| G25 | A device that was off during a removal gets the record from the first member it meets; a removed device that was off reaches nobody | fleet | |
| G26 | `cbb takeover` when the root computer is lost; the new root admits and makes admins; the old root comes back and is refused [L6] | real, fleet | |
| G27 | A takeover undone: the old root is still there and removes the admin that took over, before or after it hears of the takeover (its status names that admin); the takeover stops counting | fleet | |
| G28 | A phone's group: an admin phone takes over from a lost root phone (`root` records); no device pairs again; members that were off follow | ui, fleet | |
| G29 | The records `cbb upgrade` gave a group made before 0.4 (version 1) are refused, in Go and in the Rust core the phones and the lite member use: legacy groups and `cbb upgrade` went with records version 2, and such a group is set up again [L9] | fleet | |
| G30 | `cbb rename` on an admin for any device, the root and itself; every device and app shows the new name; 1 and 64 characters taken, 0 and 65 refused, Unicode names | real, fleet | |
| G31 | Records converge in any order: 200 records delivered to 10 members in random orders give one devices list | fleet | |
| G32 | Record limits: 4096 records, 1024 per signer; an admin that floods records cannot push out the root's removal | fleet | |
| G33 | Admins at once: two remove one device; two rename one device; one admits while another removes; two freeze each other; every member ends with the same list | fleet | |
| G34 | Key levels for admins: a file key refused at level 2 (the default), allowed at level 3 after the warning, only proven keys at level 1 | fleet | |
| G35 | A device whose hello names another system than its record gets a new record from an admin | fleet | |
| G36 | A computer of a phone's group becomes an admin: the root phone's "Make it an admin" certifies the key its hello offers, after the warning; the computer then admits and removes with `cbb pair` and `cbb remove` | ui, fleet | |

### 2.3 Watches

| ID | Case | How | Needs |
|---|---|---|---|
| G37 | A watch joins through its phone and gets the `watch` role and key (Secure Enclave on the Apple Watch, a TEE key on Wear OS); a watch without a passcode, or with wrist detection off, is not certified | ui | Apple Watch, Wear OS watch |
| G38 | A watch's limits: it freezes admin computers, removes ordinary devices, turns remote paste and away sync off, and nothing else; every member and kit refuses the rest (shared vectors) | fleet, ui | |
| G39 | Delivery from the watch: a reply through the phone, the fallback when the phone sleeps, the Android foreground service; a record sent twice counts once; the phone out of reach | ui | Apple Watch, Wear OS watch |

### 2.4 Every combination of joining and leaving

| ID | Case | How | Needs |
|---|---|---|---|
| G40 | Random walk: 200 steps chosen at random among join, remove, freeze, unfreeze, make admin, rename, takeover, restart, sleep, network cut and copy; after each step every live member agrees on the devices list and the last text, and every refusal is the one the rules give | fleet | |
| G41 | Every pair of joiner kind, admitter kind and path joins, syncs both ways, is removed and is then refused | fleet, real | |
| G42 | Leave and come back: a device removed, reset and joined again under the same name gets a new device ID, and the old one stays removed | real, fleet | |
| G43 | Groups side by side: two and ten groups on one network; no text, record or device crosses; neither pairs into the other without a code [S13] | fleet | |

## 3. Certificates and keys (K)

| ID | Case | How | Needs |
|---|---|---|---|
| K1 | A member certificate is renewed when less than 240 days remain, by the root, an admin computer and an admin phone (with `issuer`); new connections present it at once [L4] | time | |
| K3 | A member takes a renewal only from a valid admin: a `cert` message for another device or key, ending earlier, not for client and server, or signed by a removed admin is ignored and logged; a frozen admin still renews a listed device (docs/protocol.md, section 10); a device whose certificate a removed admin renewed stays in the group | fleet | |
| K4 | No admin on through the whole renewal window: the certificate expires, connections fail with a clear message, the device pairs again | time | |
| K5 | A certificate already ending with its CA is not renewed; a CA at the end of its 20 years is replaced as after a removal | time | |
| K6 | Clock behind (a board booting in 1970): certificates still accepted; clock ahead by 1 h, 3 h and a year: within the margin it works, beyond it a clear message; `cbb status` shows a skew over 5 s [F8] | fleet, time | |
| K7 | The 12 h renewal timer renews certificates of connections that stay up | time | |
| K8 | Keys at rest: TPM keys on Linux (member, admin, the sealed WireGuard key) and Windows; the Mac's signing key through the agent; phones' keys in hardware; the identity file readable only by the service [S16] | real, helper | |
| K9 | Key levels 1, 2 and 3: who may be root, admin and hub at each; `cbb status` and the devices lists show `file`, `hardware` or `proven (kind)` | fleet, real | |
| K10 | Evidence: a phone's attestation (Android TEE and StrongBox, App Attest), TPM EK chains checked offline, the Intel and AMD fetch only at level 1; a bad chain refused; the revocation list marks a revoked chain `hardware` with the reason | fleet, ui | |
| K11 | Old groups whose root or admins hold file keys are warned and offered a move to a proven root | fleet | |
| K13 | The TPM evidence flow: AK made under the EK, credential activation, the result shown by `cbb status`; Windows through the platform crypto provider | real, helper | |
| K14 | Chains through an admin CA: a device certified by an admin presents the admin CA in TLS; every member, the lite member and both kits accept it, and still accept it once that admin is removed, since the removal keeps the devices it admitted | fleet | |

## 4. Discovery and connections (D)

| ID | Case | How | Needs |
|---|---|---|---|
| D1 | mDNS: every full member and the lite member publish and browse; avahi, systemd-resolved, mDNSResponder and the Windows DNS client keep working beside it; another group's records are ignored | real, fleet | |
| D2 | Who dials: of two full members the lower ID dials; the other dials after 30 s when that is blocked; one connection per pair stays [P4] | fleet, real | |
| D3 | Full members dial lite members; phones dial everyone; a phone that is the hub listens while its app is open | fleet, ui | |
| D6 | Known networks: a member is quiet on a network it does not know; it learns one by making or joining a group, a pairing window or a member connection; `cbb status` names quiet networks; `sudo cbb network` after a new router | fleet | |
| D7 | Only private, unique-local and link-local addresses are published and accepted; a public source address on the member port is refused by the program and by the unit's limits | fleet | |
| D8 | Only IPv6 between two members; link-local addresses tried last [P19] | fleet, real | |
| D9 | Across subnets: `-peer`; the router's mDNS reflector on and off [P18] | real | |
| D10 | The router's member port refuses its WAN side even with the firewall open by mistake | fleet, real | |
| D11 | Dial-back: a member whose firewall drops the member port still syncs because the others dial it, and `cbb status` warns | real, fleet | |
| D12 | Heartbeats: a ping after 5 s of silence; a silent connection closed at 15 s; a large frame gets time at 16 KiB/s | fleet | |
| D13 | At most 32 handshakes or pairing attempts at once, a connection beyond them is closed; running out of file descriptors pauses accepting and recovers | fleet | |
| D14 | A queue of 256 messages: a peer a whole queue behind is disconnected and catches up from its next hello | fleet | |
| D15 | Junk on the member port: random bytes, a wrong ALPN, a TLS client without a certificate, a hello or an event that does not decode, a frame over 7 MiB: each closed or dropped, the service unharmed [S14] | fleet | |
| D16 | Address change: a member's DHCP address changes; an away device moves between networks without a new invitation [F11] | fleet, real | |
| D17 | mDNS answers and records: the TXT fields (`g=`, `r=lite`, `r=phone`), announcements at start, goodbyes at stop, answers to a query, browsing that ignores its own records | fleet | |

## 5. Sync of text (Y)

### 5.1 Content

| ID | Case | How | Needs |
|---|---|---|---|
| Y1 | Short ASCII, every pair [C1] | real, fleet | |
| Y2 | Unicode: Cyrillic, emoji with skin tones, combining marks, right-to-left, CJK, astral planes, a NUL inside (Windows ends at it); invalid UTF-8 refused [C2] | real, fleet | |
| Y3 | Line endings: CR LF, LF, a lone CR, tabs, trailing spaces, no final newline; Windows converts as designed [C3] | real | |
| Y4 | Whitespace only arrives; empty is refused [C4] | real | |
| Y5 | Size: 1 MiB arrives, one byte more is refused with the limit named; 1 MiB through the tunnel and the relay [C5] | real | |
| Y6 | Every pair over every path: one LAN, subnets, the hub directly, the forwarder, AmneziaWG, VLESS, the relay | real, fleet | |

### 5.2 Order and convergence

| ID | Case | How | Needs |
|---|---|---|---|
| Y10 | A burst of 10 in a second, then 100 in 10 s: the last wins everywhere [C7] | real, fleet | |
| Y11 | Two, then all members copy at the same moment: every member ends on the same text [C8] | real, fleet | |
| Y12 | A partition: the group split in two halves that each copy, then joined: one text wins everywhere by the clock's order | fleet | |
| Y13 | A clock far ahead on one member moves the hybrid clock; later copies elsewhere still win in causal order; an event more than 7 days ahead, or past the year 9999, is refused | fleet, time | |
| Y14 | The clock mark: a member killed right after a copy and restarted with its clock set back never issues a lower timestamp | fleet | |
| Y15 | Duplicates: the same event reaching a member by three paths is written once; an event older than the 4096 remembered IDs is not written again; two Macs report one Universal Clipboard item once | fleet, real | |
| Y16 | Forwarding: in a line of five members where each sees only its neighbours, a copy at one end reaches the other | fleet | |

### 5.3 What reaches a member's own clipboard

| ID | Case | How | Needs |
|---|---|---|---|
| Y20 | A live event (under 60 s old) is written; an older one is not | real, fleet | |
| Y21 | After a member was away (service start, wake), for 30 s an older current event is written, unless the member copied before it was back in sync | real, fleet | |
| Y22 | A network drop without sleep does not open those 30 s | fleet | |
| Y23 | A member that only lost its peers keeps its clipboard | fleet | |
| Y24 | No echo: a written text is not sent back, even 10 s late; Windows clipboard history, a GNOME clipboard manager and KDE's Klipper offering it again make no event [P3] | real, helper | |
| Y25 | A clipboard manager putting back an old text makes no event; a deliberate `cbb copy` of the same text does | real | |
| Y26 | Linux's primary selection gets the text; a mouse selection is not sent | real, helper | |
| Y27 | Auto-paste after a phone's event (Shift+Insert through uinput): only for `phone` events, never for Universal Clipboard, never on the lock screen | real, helper | roadmap item 10 |

### 5.4 Secrets

| ID | Case | How | Needs |
|---|---|---|---|
| Y30 | `cbb copy -secret` arrives and is gone everywhere 60 s after the copy; never on disk or in swap [C6, S10] | real | |
| Y31 | Password managers' marks are not synced automatically: macOS ConcealedType, TransientType and AutoGeneratedType; Windows ExcludeClipboardContentFromMonitorProcessing and CanIncludeInClipboardHistory=0; Linux x-kde-passwordManagerHint [P1] | helper | |
| Y32 | A received secret carries the marks on each system, stays out of histories and cloud clipboards, and is given up at its expiry | helper, real | |
| Y33 | A secret in a hello is a mark only: a member that knows only the mark has no text | fleet | |
| Y34 | The memory of skipped secrets: a manager offering one again makes no event for 12 h; it holds 4096 entries | fleet, helper | |
| Y35 | Secrets from the phones; `cbb paste -terminal` refuses a secret without `-secret` | ui, real | |
| Y36 | A device that joins reads copies from the next one on: the copy made before it joined never reaches it in the clear | fleet | |

## 6. Sync on and off (M)

| ID | Case | How | Needs |
|---|---|---|---|
| M1 | Sync on and off on every kind of member (Linux with and without a desktop, Windows, macOS, lite, container, router, phones, TV): with sync on both directions cross, with sync off neither [P34] | real, fleet, ui | |
| M2 | Deliberate actions (`cbb copy`, a phone's button, remote paste) work with sync on and off | real, ui | |
| M3 | `cbb paste` with sync off prints the group's text | real | |
| M4 | Sync off survives a restart, reboot and update; the hello reports it; every devices list shows it | real, fleet | |
| M5 | `cbb sync -on DEVICE` from the root computer, an admin computer, an admin phone: taken; from a member or a frozen admin: refused; to a stopped target: an error within 10 s and nothing changes; to a target not connected to the sender: passed on by a member [P34] | real, fleet | |
| M6 | A new device starts with sync on; a device without `sync.json` syncs | fleet | |
| M7 | The phones' automatic paths follow sync: Android's service writes and its accessibility service sends only while sync is on; the iPhone writes a live copy only while sync is on | ui | |
| M8 | `cbb sync off` on a device: `cbb status` says so; it lasts across a restart; `cbb copy` still sends; `cbb sync on` ends it; `-for` ends it by itself | fleet | |
| M9 | An admin's `cbb mute -on DEVICE`: the device's copies reach no one, every devices list says it is muted, its own user (no admin) cannot end it, another admin can (the last command counts, even a shorter mute after a longer one), `-for` ends it by itself; a mute of a device that cannot be reached is refused with why; a device that is no admin mutes no one | fleet | |
| M10 | `cbb incoming`: the root or an admin sets how long a copy from another device stays live, every member shows it; out of 5s to 1h, or from a device that is no admin, refused; a device cut off for 10 seconds writes the copy made meanwhile with a window of 1m, not with one of 5s | fleet | |

## 7. Images, files and formatted text (O)

| ID | Case | How | Needs |
|---|---|---|---|
| O1 | Images: a PNG screenshot, a 5 MB JPEG, a TIFF on a Mac (sent as PNG), HEIC from an iPhone (sent as JPEG or PNG), between every pair of desktops and phones; JPEG turned into PNG for a receiver that asks [P2] | real, ui | |
| O2 | Files and folders: a folder of 100 files with subfolders and an empty file; 10 000 entries; 10 001 refused; links and special files left out; names made safe (`..`, `/`, control characters, `CON`, `notes.`, 255 bytes); nothing executable; quarantine on macOS, Mark of the Web on Windows [P2] | real | |
| O3 | `cbb copy FILE...`, `-text`, `-type png/jpeg/html`; `cbb paste -o DIR`: never replaces a file, waits for a copy still arriving, in `own` saves the group's copy | real | |
| O4 | Formatted text: HTML from a browser and an office program arrives as HTML where a desktop takes it, as text on phones, the lite member and older connectors; HTML over 8 MiB or text over 256 KiB goes as text alone; never with a secret | real, helper | |
| O5 | Limits: `max-copy` from 1 MiB to 1 GiB, `max-copy-away` up to `max-copy`, others refused; a copy over a receiver's limit is not fetched and is said once in `cbb status` and the log; the sender's own limit [P2] | real | |
| O6 | Text-only devices (lite, Nano, ZX Next) take the text that goes with a copy and never fetch | real, fleet | |
| O7 | Transfer faults: a fetch cut in the middle resumes from its offset; the sender restarts mid-transfer; a newer copy stops the fetch; a corrupted chunk (hash mismatch) is refused and fetched again; a peer that stops answering is cancelled after 15 s | fleet | |
| O8 | Priority: texts keep flowing during a 500 MB transfer | fleet, real | |
| O9 | The cache: older copies deleted 10 min after they are replaced, all at a restart, within twice the limit; the agent's received folder emptied at start; the files readable only by the user | time, real | |
| O10 | Away: through the hub within `max-copy-away`; a copy over the hub's away limit stays at home (logged); the hub fetches and serves whatever its mode; a client that asks too early hears `missing` and tries again [P39] | real | |
| O11 | Phones: the share sheet up to 50 MB on the iPhone and 100 MiB on Android; the button saves files in Files or Downloads; an image already received is nothing new; phones serve their own copies | ui | |
| O12 | Flatpak apps: copied files through the document portal, written files through FileTransfer | helper | |
| O13 | Progress in `cbb status` and the apps' notification | real, ui | |
| O14 | A member with a router's memory (`GOMEMLIMIT` as the OpenWrt package sets it, 64 MiB) passes a 90 MiB copy on to a member that reaches only it, without running out of memory: the parts go through its cache on disk | fleet, real | |
| O15 | Fetch limits: gets of at most 1 MiB, 4 MiB ahead, 64 gets per connection; chunks padded to 16 KiB; a peer that asks for more is refused | fleet | |

## 8. Remote paste (T)

| ID | Case | How | Needs |
|---|---|---|---|
| T1 | Off by default on every target; `paste-receive on`, `on -enter`, `on -console`, `off`; only the device's own user turns it on | real, fleet | |
| T2 | Linux targets paste and type: X11 (XTEST), wlroots' virtual keyboard, GNOME and KDE through the RemoteDesktop portal (the first paste opens the dialog and is refused, after consent it works, the restore token survives a sign-out), the uinput helper, tmux (the user's and root's), the text console helper | real, helper | |
| T3 | Windows (Ctrl+V and SendInput's Unicode keys, an RDP session) and the Mac app (Cmd+V and Unicode key events) paste and type | real, helper | |
| T4 | The Android accessibility target, the lite member (tmux, console) and the Nano's USB keyboard paste and type | ui, helper | Nano |
| T5 | The text arrives exactly: Unicode, another keyboard layout active, 1 MiB pasted and 4 KiB typed, tabs and newlines; the clipboard's old text is put back after 500 ms unless the user copied meanwhile | real, helper | |
| T6 | Refusals with the reason sent back: a locked session (logind, a screensaver, swaylock, macOS, Windows and its secure desktop), an elevated window on Windows, Secure Input on the Mac, no Accessibility permission, a Mac without the app, no tmux client attached, a login prompt on the console, Enter without `-enter`, root's console without `-console`, a newline to tmux or the console without `-enter` | real, helper | |
| T7 | Who may send: the root, an admin computer, an admin phone; a watch may only turn it off; a member, a frozen admin and a removed admin are refused | fleet | |
| T8 | Command checks: expired (over 30 s), `time_ms` more than 60 s ahead, a replayed `id`, a wrong group or target, a target whose clock is not set: each refused with its reason | fleet, time | |
| T9 | Rate limits: one a second and 30 a minute per sender; the 31st is refused | fleet, real | |
| T10 | Control characters, escape sequences and invalid UTF-8 removed before the keys go in (`ESC[201~` cannot end bracketed paste) | real, fleet | |
| T11 | A secret paste: never logged, the clipboard cleared after | real | |
| T12 | The target's notification and log of the last 100 pastes (sender, time, length, result, never the text) | real, ui | |
| T13 | Routing: a target not connected to the sender gets it through a member, away from home through the hub; the result comes back the same way; a failure shows its cause with details on | fleet, real | |
| T14 | `paste-receive off` from afar (one device, every device) takes effect at once; only the device's user turns it on again | fleet | |
| T15 | The uinput helper serves only the active seat0 session's user, never a login screen, and presses only Shift, Insert and Enter | helper | |
| T16 | "Paste on it…" in the phone apps: typed or from the clipboard, with Enter, as a secret, after Face ID or the fingerprint; through a member when the phone is not connected | ui | |
| T17 | Android TV as a target: the TV variant's accessibility target; `cbb remote add` and Android TV Remote v2 (pairing code on the TV, the IME's text) | ui, person | TV |
| T18 | Bluetooth keyboards: the Android phone's HID device, the Nano's BLE keyboard (bonds in flash, erased by a reset), Linux over BlueZ; a phone whose maker left HID out is named | helper, ui | Nano |
| T19 | Other TVs: Apple TV (Companion, or a Bluetooth keyboard), Samsung and LG remotes, Roku (off by default, plain HTTP) | person | TV, Apple TV |
| T20 | The Nano's keyboard layouts, one per target, and its USB console's "reboot to flash" | helper | Nano |

## 9. Quick actions (Q)

| ID | Case | How | Needs |
|---|---|---|---|
| Q1 | `cbb action` lists the presets and who may run each; all off at first | real, fleet | |
| Q2 | `enable` and `disable` with the explanation and `yes`; the polkit rule written and removed on Linux | real, helper | |
| Q3 | Each preset on each system: lock, sleep, reboot (after a minute), shutdown, cancel-shutdown, restart the service; macOS and Windows through the agent, which needs someone signed in; the lite member's reboot and restart | real, helper | |
| Q4 | `-by root,phone,computer` and `-any-key`: reboot and shutdown refused to admins with file keys by default | fleet | |
| Q5 | Own actions: `add NAME -- /full/path args` runs exactly that as the signed-in user, its exit status comes back, it is killed after 15 s; a relative path is refused; `remove` | real | |
| Q6 | `-on DEVICE NAME` from each kind of admin, with the result back; a target where it is off says how to turn it on; a frozen or removed admin is refused | real, fleet | |
| Q7 | `off -on DEVICE` and `off -all` from any admin; only the device's user turns them on again | fleet | |
| Q8 | The phones', watches' and desktop apps' buttons run the same actions; phones ask again before reboot and shutdown; "Turn all off" | ui | |

## 10. Away from home (W)

### 10.1 Turning it on and off

| ID | Case | How | Needs |
|---|---|---|---|
| W1 | `cbb global on` with its warnings (consent for keys in files); `off` forgets the keys and asks first on a device that reaches the hub only through the tunnel; `-yes` [P11, P22] | real | |
| W2 | The system's limit: the systemd drop-in, the Windows rule `cbb-home-only`, the program's own limit on macOS; `cbb global allow` after the hub's addresses change; `cbb global` and `cbb status` say when the limit lags | real | |
| W3 | Fail closed: the service reaches only the home network and the group's servers; with the tunnel broken nothing goes elsewhere [S9] | real, fleet | |
| W4 | `cbb global hub` with addresses, `-port`, `-firewall ask/yes/no` (the port closed again when no longer needed), `-obfuscate`, `-forwarder -forwarder-key`, `-vless`; a name looked up once; the router as the hub through its init script | real, fleet | |
| W5 | `cbb global` and the apps say where it stands: waiting for the hub's offer, at home, connecting, connected through the tunnel, and what went wrong | real, ui | |

### 10.2 Hubs

| ID | Case | How | Needs |
|---|---|---|---|
| W10 | The hub directly by IPv6, by a forwarded IPv4 port, through the forwarder; a client tries them in order [P11, P20] | real, fleet | |
| W11 | The hub's addresses change (a new IPv6 prefix): connected clients learn it through the tunnel; an offline client comes in through the forwarder and moves to the direct path | fleet | |
| W12 | The hub's key changes each credential period; the next key reaches clients 3 days ahead; a client offline across the change still connects | time | |
| W13 | The hub down [F6], hung, rebooting: a client says the hub is unreachable and sends nothing elsewhere | real, fleet | |
| W14 | Several hubs: the root and each admin with a hub; failover within about a minute; back within 5 min; no copy lost [P36] | real, fleet | |
| W15 | `cbb global move` to an admin computer; refused for a lite member and a container; clients follow without coming home [P37] | real, fleet | |
| W16 | The phone as the hub while its app is open: registering, registered, refused with the reason; "This is my home network"; clients retry every 5 s; Android keeps it in the background; moving the hub from the phone to a computer | ui | |
| W17 | The lite member as a client: plain WireGuard, then the hub obfuscated and reached with AmneziaWG (VLESS over XHTTP: `TestLiteMemberAwayXHTTP`) | real | |
| W18 | A client that has not met the hub since its obfuscation changed cannot reach it away until it comes home | fleet | |
| W19 | Client isolation: from a client's tunnel nothing but the hub's member port answers; the hub opens one port [S3, S4] | real, fleet | |
| W20 | A WireGuard key the group does not know gets no answer from the hub or the forwarder [S5] | real, fleet | |
| W21 | A removed away device: the hub drops its key at once; no sync; its old invitation refused [S6] | real | |
| W43 | Two kinds of hub: `cbb global hub -on DEVICE -forward-only` makes a computer that is no admin a hub that only passes the copies on; every device lists it so; the root stops being a hub (`cbb global hub off`) and its client away moves to it | fleet | |

### 10.3 The forwarder and the relay

| ID | Case | How | Needs |
|---|---|---|---|
| W30 | The forwarder: registration with the period's credential; a member that is no hub cannot take the hub's place; an older credential refused after a restart; a removed device's period ends | fleet | |
| W31 | The forwarder down [F7], restarted (the hub registers again by itself), unreachable, a wrong key pinned | real, fleet | |
| W32 | The forwarder's limits: 16 clients per group, packets and bytes per second, registrations per address and network; a busy group slowed alone | fleet | |
| W33 | Two groups on one forwarder cannot reach each other [S8] | fleet | |
| W34 | VLESS: a forwarder with `-vless-site`; anyone who is not a client gets the borrowed site; clients reach the hub only over VLESS; with UDP to the forwarder blocked, VLESS still works [P20] | real, fleet | |
| W35 | AmneziaWG: nothing on the wire starts or is sized like WireGuard, directly and through the forwarder | fleet | |
| W36 | The blind relay: `-group TAG` and `-open`; the consent text and `-yes`; sync both ways; a member and the relay restarted; a wrong key [P12] | real, fleet | |
| W37 | The relay with credentials: pseudonyms only; a device the members' credential does not list is refused; one a newer credential leaves out is dropped | fleet | |
| W38 | The relay's limits: 4096 groups, 64 devices per group, 16 registrations per address and 64 per network, 1 MiB/s per group; a group forgotten when its last device leaves [P38] | fleet | |
| W39 | A new credential period (30 days): new tag, period key and server keys; the servers cannot link two periods; the lists padded | time | |
| W40 | The servers keep nothing: no file or log line with addresses, tags, IDs, names or markers, in either mode; the units' exposure score [S18] | real | |
| W41 | The push sender: an encrypted push reaches the iPhone and wakes it; cbb.tools stores nothing | ui, real | Apple account |
| W42 | Phones away: the tunnel in the app's process (`cbbtun`), the loopback port, the kits' member TLS to the hub; the Android foreground service away; the iPhone while the app runs; the devices list marks the hub, and a computer behind it shows online | ui | |
| W44 | The ways out carry only cbb: a hostile client with a member's keys, sending everything to the hub directly and through the forwarder, reaches neither the internet nor the hub's home network nor its loopback, TCP or UDP, IPv4 or IPv6, and nothing reaches the stand-in for the internet; VLESS, the relay, the phones' hub and the lite member's tunnel in unit tests (roadmap item 61) | fleet | |
| W45 | A hub on a network that lets only HTTPS through: with UDP and the forwarder's TCP port blocked, it registers inside VLESS and its client away syncs both ways | fleet | |
| W46 | A forwarder whose VLESS runs over XHTTP behind its site's web server (`cbb forward -vless-xhttp`): with UDP and the forwarder's TCP port blocked, the hub registers through the web server and its client away syncs both ways through it; anyone else gets the site; in the time-scaled build at the real times, whose VLESS alone trusts the web server's own CA (`CBB_TEST_XHTTP_CA`) | time | |
| W47 | `cbb update` on a client away whose hub uses VLESS asks the mirror on the forwarder's server (`cbb forward -vless-mirror`) only inside VLESS, the mirror's certificate checked on the way; as W46 | time | |
| W48 | The project's relay (`cbb global relay default`) followed from the signed lists: a group without a hub meets at it by its pin in `keys.json`; when it takes a new key, the newer lists bring every member back without the user; when it moves, the members find it at the `endpoints` of the newest `entries.json` and keep that address | fleet | |

## 11. The command line, the control socket and errors (U)

| ID | Case | How | Needs |
|---|---|---|---|
| U1 | `cbb status` matches the real state on every system: devices, systems, roles, root, admin and frozen marks, key store, last seen, clock skew, mode, quiet networks, dial-back warning, away state, transfers [P13] | real, fleet | |
| U2 | `cbb version`, `help`, each command's `-h`; unknown flags and commands print the usage; the lite member's help says it is the lite member and a full member's command there says so | real | |
| U3 | Local access: a user outside the `cbb` group is refused with the group named; a member of it cannot use the admin socket; the Windows socket's access list [S11] | real | |
| U4 | Errors as 0.2 says for every refusal of this catalogue, in both modes; a development build shows details by default | real, fleet | |
| U5 | The service stopped: every command says it is not running and how to start it, the cause only with details on [F14] | real | |
| U6 | The service hung: commands give up within seconds with a clear message [F13] | real | |
| U7 | Damaged state: `identity.json` cut short or garbage, the records, `networks.json`, the mode, the clock mark: the service says which file and what to do, writes nothing over it, and works once it is restored [F10] | real, fleet | |
| U8 | The state directory's disk full: a clear error, and no damaged state once there is room again [F9] | fleet | |
| U9 | `cbb watch` and `watch -0`; `cbb next` frames for the ZX Next | real, fleet | |
| U10 | Logs carry no texts, codes or keys, in either mode [S15] | real | |
| U11 | The control socket's protocol: framing errors, each operation, the watcher protocol (a paste-only watch as the Mac app's), a second agent in one session exits | fleet | |
| U12 | Error details in the apps: off in release builds, on in debug builds; seven taps on the version, the launch argument `ShowErrorDetails` and the tray and Mac apps' switch show the cause under each message | ui | |
| U13 | The lite member's `-state`, `-socket`, `-debug`, `CBB_STATE`, `CBB_SOCKET`; `CBB_SOCKET` for a second instance of a full member | real, fleet | |

## 12. Platforms and their desktops (H)

| ID | Case | How | Needs |
|---|---|---|---|
| H1 | Linux desktops: GNOME (XWayland, native Wayland apps, before XWayland started), KDE (data-control, Klipper), sway, Hyprland, XFCE on X11 [P24] | real, fleet, person | |
| H2 | The Linux agent: one per session, started again after an update in every session, reconnects when the display goes, ends with the session | real | |
| H3 | tmux: copy mode goes to the group; the paste key pastes `-terminal` text [P8] | real | |
| H4 | The text console: the login snippet starts tmux; the console helper [P8] | real | |
| H5 | The lite member's options: `-peer`, `-no-mdns`, `-no-listen`, `-addr`, `-name`, `-port` [P5] | real | |
| H6 | A container: locked down, restarted, recreated, an admin only by choice [P35] | real, fleet | |
| H7 | Windows: before sign-in, fast user switching, lock, sign-out, RDP, ARM and x64, another port [P9, P16] | real, helper | |
| H8 | macOS: Local Network refused and granted, the application firewall on and "block all", Universal Clipboard, the pasteboard privacy alert, Homebrew [P4, P7, P15, P23, P26] | real, helper, person | |
| H9 | OpenWrt: procd, UCI, the NTP wait, `keep.d` across a sysupgrade, fw4 rules that live and die with the service, `GOMEMLIMIT` | fleet, real | |
| H10 | FreeBSD and OPNsense: rc.d, the pf anchor and ipfw, the desktop connector under Xvfb, the mdns-repeater conflict; pfSense's printed rules | fleet | |
| H11 | The lite member on the Nano ESP32: joins by the phone, syncs at home, settings in flash, reset; the QEMU self-test | helper, fleet | Nano |
| H12 | The ZX Spectrum Next's dot command over the UART | person | ZX Next |
| H13 | Android TV: the leanback launcher, the D-pad, joining by the QR code on the TV | ui | TV |
| H14 | The Steam Deck's Game Mode and gamescope [P17] | person | |
| H15 | The iPad build and big screens: the layout of each screen in both orientations and split view | ui | iPad |

## 13. The apps (A)

| ID | Case | How | Needs |
|---|---|---|---|
| A1 | The iPhone app: make a group, add devices (camera and the six digits), Devices, rename, remove, make admin, freeze and unfreeze, takeover, the away switch, send and fetch, settings [P27] | ui | |
| A2 | The Android app: the same, plus the foreground service, sending through accessibility, one tap, the share sheet | ui | |
| A3 | The watches: devices, events, the away switch, the emergency actions, the quick-action buttons, the phone out of reach [P29, P33] | ui, person | Apple Watch, Wear OS watch |
| A4 | The Mac app: window and menu bar, send and fetch, admin actions behind the password, a cancelled prompt changes nothing, a stopped service explained with details on and off, the remote paste target, Accessibility lost after an update shown [P31] | ui | |
| A5 | The tray app on GNOME, KDE and Windows: the same through pkexec and UAC, in Russian too [P32] | ui | |
| A6 | Notifications of the group's events: one per event, the switches respected, never the clipboard; prompt on the iPhone through the push sender [P28] | ui | |
| A7 | The Dynamic Island: the timer, the shield, the result, never the text [P30] | ui, person | iPhone |
| A8 | Collections: make, rename, move devices, the order of tiles, one level, a device in one collection; Arrange mode with drag, the menu, VoiceOver and TalkBack actions, the keyboard; search and filters; the watch shows the phone's arrangement; the paste picker grouped the same; kept per installation, never in a record | ui | |
| A9 | Languages (English, Russian) and the language menu when the system's language has none; right-to-left layout; accessibility labels | ui | |
| A10 | The F-Droid flavour without Wear OS: builds reproducibly, works without Play services [P33] | ui | |
| A11 | The iPhone's background app refresh runs and syncs | person | iPhone |
| A12 | "Sync clipboard" without opening the app: App Intents and App Shortcuts, Back Tap, the Action button, the home-screen widget on both phones, the Control Center control; one line says what it did | ui | |
| A13 | The iPhone's share extension: text and links at once, images and files up to 50 MB, waits until a computer fetched them, at most a minute; a debug build without the app group says there is no group | ui | Apple account |
| A14 | First launch and the Start screen: "This phone is ready", settings before a group, "I already use CBB on another phone" | ui | |
| A15 | Themes: ten colours in System, Dark and Light; tiles and list; every device icon | ui | |
| A16 | Plain-language paths: a lost phone ("remove it on your other phone"), a group with one admin advised to add a second, errors in one line with the next step | ui | |
| A17 | The Aurora OS app: the signed package installs through the store's installer; it joins by its QR code (a computer of the group scans and dials in); the group's copies reach its clipboard while it is in front; a copy goes out when it comes to the front and from the pull-down menu; the main page shows the members and the last copy; "Leave the group" deletes the membership; the key stays in its OP-TEE token across restarts | person | Aurora phone |

## 14. Security (S)

| ID | Case | How | Needs |
|---|---|---|---|
| S1 | The internet path shows nothing: captures on the relay and the away computer find no marker, tag, name or address | real | |
| S2 | The LAN shows nothing: captures on a member find no marker or name; only TLS and mDNS | real | |
| S3 | Clients are isolated: a client's tunnel reaches only the hub's member port | real, fleet | |
| S4 | The hub exposes one port: nmap through the tunnel | real, fleet | |
| S5 | A key outside the group gets no answer | real, fleet | |
| S6 | A removed device away cannot reach anyone | real | |
| S7 | The invitation file: a secret until used, useless after | real | |
| S8 | The relay and the forwarder learn little: two groups cannot reach each other, the servers see no names | real, fleet | |
| S9 | Fail closed: nothing leaves for the internet but to the group's servers | real | |
| S10 | Secrets never reach a disk | real | |
| S11 | Local access to the sockets | real | |
| S12 | The installers' firewall rules are exactly those listed | real | |
| S13 | Two groups on one network stay apart | fleet | |
| S14 | A stranger at home learns nothing and cannot harm a member | fleet | |
| S15 | Logs carry no secrets | real | |
| S16 | Files at rest readable only by the service | real | |
| S17 | Commands: a captured command replayed is refused; one changed in transit is refused | fleet, helper | |
| S18 | The servers keep nothing | real | |
| S20 | Fuzzed member, pairing and control frames for an hour: no crash, no leak | fleet | |
| S21 | A stranger on the LAN learns no names and no tag beyond the TXT `g=` | fleet | |
| S22 | Signed releases: the envelope checks against the shared vectors on the devices themselves (Go, the lite member, both kits) | fleet, ui | |
| S23 | Commands passed on by a member cannot be changed or forged by it | fleet | |
| S24 | A stolen admin computer (its state copied to a fresh container): it acts until frozen; after the freeze nothing it signs counts | fleet | |
| S25 | Copies sealed end to end: through a hub that only passes them on, text and a 20 MB file arrive whole both ways, and neither the hub's memory nor its disk ever holds them in the clear, while a member that reads them does; that hub takes no paste | fleet | |
| S26 | A paste command to a device behind a hub passes through it sealed: the receiver's answer comes back, and the hub never holds the text | fleet | |

## 15. Load, concurrency and faults (E)

| ID | Case | How | Needs |
|---|---|---|---|
| E1 | Latency: 200 copies from different members; p50 and p95 at each receiver (p95 at most 2 s at home, 5 s through the tunnel) | real, fleet | |
| E2 | Throughput: every member copies every 100 ms for 3 minutes; all end on one text; no restarts; memory and descriptors back to where they started | real, fleet | |
| E3 | Many members: 32 full and 8 lite members in one group; all join, a copy reaches all within 5 s, half are removed | fleet | |
| E4 | Big transfers at once: three members send 50 MB files while texts flow; all whole (SHA-256), texts on time | real, fleet | |
| E5 | Many clients on one member: 100 `cbb status` and `paste` at once; 20 joiners with wrong codes at once | fleet | |
| E6 | The hub under load: 16 clients away, each copying; the hub's CPU and memory on the router and a small board | fleet, real | |
| E7 | A bad network [F4]: 30% loss, 300 ms delay and reordering at the hub; 20 copies; the last wins, nothing twice | real, fleet | |
| E8 | The member port blocked both ways for a minute [F5]; the member catches up | real, fleet | |
| E9 | Restarts during everything: members killed at random every 30 s for 10 minutes while copying | fleet | |
| E10 | Soak for 24 h: a copy every 30 s from a random member, a fault every hour, memory and descriptors sampled every 5 minutes; flat, no restarts [Soak] | real, fleet | |
| E11 | The service hung [F13]: SIGSTOP; commands answer within seconds; after SIGCONT it catches up | real | |

## 16. What the bench needs for this

- The controller runs the fleet: Docker with bridge and macvlan networks, QEMU for OpenWrt and
  FreeBSD, a JVM for the Kotlin phone. If the controller is too small for 40 containers and
  two virtual machines, a second controller (any x86 mini PC) takes the fleet.
- The Mac runs the iPhone simulator and XCUITest, the Android emulator (phone, Wear OS, TV)
  and the Swift phone.
- A smart plug for the lite board's power (I17); `rtcwake` on the Linux desktop.
- The router as a device under test, with a timer that takes back every change.
- A test signing key and feed on the controller.
- Real phones and watches for what the simulators cannot do (Secure Enclave, Face ID,
  WatchConnectivity, the Data Layer, wrist detection).
- A TV for T17, T19 and H13 (Android TV starts in the emulator for the rest).

## 17. How it is run

`testbench all BUILD` runs everything the harness has, one suite after another, each after a
reset, and writes one report with the coverage table and the list of what is skipped and
why. `testbench coverage` prints the table alone, from these two documents and the harness's
list of what it runs. A case the harness runs counts as run in full when its suites cover
every kind of section 0.1 it names (either of "real" and "fleet" when it names both, and a
person never); the table counts those apart and lists the others with what they lack. That
compares where a case runs, not each step of its text. Each suite runs alone too (`testbench faults BUILD`), and `-only`
limits the devices.
